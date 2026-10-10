#!/usr/bin/env python3
"""Real socket endpoints and kernel-state assertions for firewall-whitelist.sh."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time

TIMEOUT = 0.7
PORTS = [port for base in range(21000, 21071, 10) for port in (base, base + 1)]


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def family(address):
    return socket.AF_INET6 if ":" in address else socket.AF_INET


def token(label, protocol, port):
    # A fixed service identity, not an echo of the client's request.
    return f"wechatpush-regression/{label}/{protocol}/{port}\n".encode()


def unix_request(path, action, timeout=2):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(path)
        connection.sendall(action.encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = connection.recv(4096)
            if not chunk:
                raise RuntimeError("control connection closed without a response")
            data += chunk
        return json.loads(data)


def control_socket(path):
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.bind(path)
    control.listen()
    return control


def extract(args):
    definitions = []
    names = set()
    for source in (args.runtime, args.service):
        text = Path(source).read_text()
        for opener in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{[^\n]*\n", text, re.M):
            closer = re.search(r"^\}[ \t]*$", text[opener.end():], re.M)
            if closer is None:
                raise RuntimeError(f"no top-level closer for {opener.group(1)}")
            end = opener.end() + closer.end()
            definitions.append(text[opener.start():end] + "\n")
            names.add(opener.group(1))
    if not {"main", "init", "init_ip_white", "clear_blacklist_rules"} <= names:
        raise RuntimeError("required runtime functions were not extracted")
    Path(args.output).write_text("\n".join(definitions))


def serve(args):
    selector = selectors.DefaultSelector()
    sockets = []
    ports = PORTS + [21035, 21500] if args.label == "router" else [23000]
    udp_ports = [21000, 21071, 21500] if args.label == "router" else [23000]
    try:
        for af, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            for protocol, selected in (("tcp", ports), ("udp", udp_ports)):
                for port in selected:
                    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
                    listener = socket.socket(af, kind)
                    sockets.append(listener)
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if af == socket.AF_INET6:
                        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    listener.bind((address, port))
                    if protocol == "tcp":
                        listener.listen()
                    listener.setblocking(False)
                    selector.register(listener, selectors.EVENT_READ, (protocol, port))
        # Readiness is published only after every IPv4/IPv6 listener is bound.
        control = control_socket(args.control)
        sockets.append(control)
        control.setblocking(False)
        selector.register(control, selectors.EVENT_READ, ("control", 0))
        while True:
            for key, events in selector.select():
                connection = key.fileobj
                protocol, value = key.data
                if protocol == "control":
                    client, _ = connection.accept()
                    with client:
                        client.settimeout(2)
                        client.recv(4096)
                        client.sendall(json.dumps({"ready": True, "label": args.label}).encode() + b"\n")
                elif protocol == "tcp":
                    client, _ = connection.accept()
                    client.setblocking(False)
                    sockets.append(client)
                    selector.register(client, selectors.EVENT_READ, ("connection", (value, b"")))
                elif protocol == "udp":
                    _, peer = connection.recvfrom(4096)
                    connection.sendto(token(args.label, "udp", value), peer)
                else:
                    port, pending = value
                    try:
                        if events & selectors.EVENT_READ:
                            data = connection.recv(4096)
                            if not data:
                                selector.unregister(connection)
                                connection.close()
                                continue
                            # Every complete one-byte request has exactly one response,
                            # independent of TCP segmentation or receive coalescing.
                            pending += token(args.label, "tcp", port) * len(data)
                        if pending:
                            try:
                                pending = pending[connection.send(pending):]
                            except BlockingIOError:
                                pass
                        flags = selectors.EVENT_READ | (selectors.EVENT_WRITE if pending else 0)
                        selector.modify(connection, flags, ("connection", (port, pending)))
                    except (ConnectionError, OSError):
                        selector.unregister(connection)
                        connection.close()
    finally:
        selector.close()
        for connection in sockets:
            connection.close()
        Path(args.control).unlink(missing_ok=True)


def wait_ready(args):
    deadline = time.monotonic() + 8
    last_error = None
    while time.monotonic() < deadline:
        try:
            os.kill(args.pid, 0)
            result = unix_request(args.control, "ready", 0.5)
            if result.get("ready"):
                print(json.dumps(result))
                return
        except (OSError, RuntimeError) as error:
            last_error = error
        time.sleep(0.02)
    raise RuntimeError(f"endpoint did not become ready: {last_error}")


def exchange(connection, label, port):
    connection.sendall(b"?")
    response = b""
    while not response.endswith(b"\n"):
        data = connection.recv(4096)
        if not data:
            return False
        response += data
    return response == token(label, "tcp", port)


def hold(args):
    with socket.socket(family(args.source), socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.bind((args.source, 0))
        connection.connect((args.destination, args.port))
        if not exchange(connection, "target", args.port):
            raise RuntimeError("persistent TCP connection reached the wrong endpoint")
        connection.settimeout(TIMEOUT)
        control = control_socket(args.control)
        try:
            with control:
                while True:
                    client, _ = control.accept()
                    with client:
                        client.settimeout(2)
                        action = client.recv(4096).decode().strip()
                        if action == "ready":
                            result = {"ready": True, "port": connection.getsockname()[1]}
                        elif action == "exchange":
                            try:
                                allowed = exchange(connection, "target", args.port)
                            except OSError:
                                allowed = False
                            result = {"allowed": allowed}
                        elif action == "close":
                            client.sendall(b"{}\n")
                            return
                        else:
                            raise RuntimeError(f"unknown control action: {action}")
                        client.sendall(json.dumps(result).encode() + b"\n")
        finally:
            Path(args.control).unlink(missing_ok=True)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def icmp_probe(source, destination):
    af = family(source)
    ipv6 = af == socket.AF_INET6
    protocol = socket.IPPROTO_ICMPV6 if ipv6 else socket.IPPROTO_ICMP
    identifier = os.getpid() & 0xFFFF
    payload = os.urandom(16)
    packet = struct.pack("!BBHHH", 128 if ipv6 else 8, 0, 0, identifier, 1) + payload
    if not ipv6:
        packet = packet[:2] + struct.pack("!H", checksum(packet)) + packet[4:]
    with socket.socket(af, socket.SOCK_RAW, protocol) as connection:
        connection.bind((source, 0))
        connection.settimeout(TIMEOUT)
        # Linux fills the mandatory ICMPv6 checksum on this raw socket.
        connection.sendto(packet, (destination, 0))
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                reply, peer = connection.recvfrom(4096)
            except socket.timeout:
                return False
            if not ipv6:
                reply = reply[(reply[0] & 15) * 4:]
            if len(reply) >= 8 and peer[0] == destination:
                kind, _, _, received_id, sequence = struct.unpack("!BBHHH", reply[:8])
                if kind == (129 if ipv6 else 0) and received_id == identifier and sequence == 1 and reply[8:] == payload:
                    return True
    return False


def probe(args):
    allowed = False
    identity = True
    if args.protocol == "icmp":
        allowed = icmp_probe(args.source, args.destination)
    else:
        kind = socket.SOCK_STREAM if args.protocol == "tcp" else socket.SOCK_DGRAM
        with socket.socket(family(args.source), kind) as connection:
            connection.bind((args.source, 0))
            connection.settimeout(TIMEOUT)
            try:
                connection.connect((args.destination, args.port))
                if args.protocol == "tcp":
                    # A completed handshake already violates an expected denial.
                    allowed = True
                    identity = exchange(connection, args.label, args.reply_port or args.port)
                else:
                    connection.send(b"firewall-regression")
                    response = connection.recv(4096)
                    allowed = True
                    identity = response == token(args.label, "udp", args.reply_port or args.port)
            except OSError:
                if args.expect == "allow":
                    identity = False
    wanted = args.expect == "allow"
    if allowed != wanted or (wanted and not identity):
        raise RuntimeError(f"{args.protocol} {args.source} -> {args.destination}:{args.port}: expected {args.expect}, handshake/reply={allowed}, correct endpoint={identity}")


def grant_state(backend, address, set_kind="login_whitelist"):
    name = "wechatpush_" + set_kind + ("v6" if ":" in address else "")
    wanted = ipaddress.ip_address(address)
    now = time.monotonic()
    if backend == "nft":
        metadata = json.loads(run("nft", "-j", "list", "set", "inet", "fw4", name))
        for item in metadata["nftables"]:
            for entry in item.get("set", {}).get("elem", []):
                element = {"val": entry} if isinstance(entry, str) else entry["elem"]
                if ipaddress.ip_address(element["val"]) == wanted:
                    # nft JSON expires is in seconds, matching monotonic deadlines.
                    remaining = element.get("expires", 0)
                    timed = bool(element.get("timeout", 0) or remaining)
                    return {"permanent": not timed, "deadline": now + remaining if timed else None}
    else:
        for line in run("ipset", "save", name).splitlines():
            fields = line.split()
            if fields[:2] != ["add", name] or ipaddress.ip_address(fields[2]) != wanted:
                continue
            remaining = int(fields[fields.index("timeout") + 1]) if "timeout" in fields else 0
            return {"permanent": remaining == 0, "deadline": now + remaining if remaining else None}
    raise RuntimeError(f"{set_kind} membership disappeared: {address}")


def grant(args):
    state = grant_state(args.backend, args.address, args.set_kind)
    if args.action == "capture":
        Path(args.file).write_text(json.dumps(state))
    elif args.action == "compare":
        old = json.loads(Path(args.file).read_text())
        if old["permanent"] != state["permanent"]:
            raise RuntimeError(f"{args.set_kind} lifetime class changed for {args.address}: {old} -> {state}")
        if not old["permanent"] and abs(old["deadline"] - state["deadline"]) > 2.1:
            raise RuntimeError(f"{args.set_kind} expiry was reset for {args.address}: {old} -> {state}")
    else:
        if state["permanent"]:
            raise RuntimeError(f"cannot age a permanent {args.set_kind} entry")
        start = time.monotonic()
        initial = state["deadline"] - start
        while time.monotonic() - start < 8:
            current = grant_state(args.backend, args.address, args.set_kind)
            if current["permanent"]:
                raise RuntimeError(f"timed {args.set_kind} entry became permanent")
            if current["deadline"] - time.monotonic() <= initial - 5:
                return
            time.sleep(0.05)
        raise RuntimeError(f"kernel {args.set_kind} countdown did not advance")


def conntrack_assert(args):
    af = "ipv6" if ":" in args.source else "ipv4"
    entries = run("conntrack", "-L", "-f", af, "-p", "tcp", "-s", args.source, "--sport", str(args.port)).strip()
    if bool(entries) != (args.expect == "present"):
        raise RuntimeError(f"conntrack {args.source}:{args.port}: expected {args.expect}, got {entries or 'no entries'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("extract")
    for name in ("runtime", "service", "output"):
        command.add_argument(name)
    command.set_defaults(func=extract)
    command = commands.add_parser("serve")
    command.add_argument("label", choices=("router", "target"))
    command.add_argument("control")
    command.set_defaults(func=serve)
    command = commands.add_parser("wait-ready")
    command.add_argument("control")
    command.add_argument("pid", type=int)
    command.set_defaults(func=wait_ready)
    command = commands.add_parser("hold")
    for name in ("control", "source", "destination"):
        command.add_argument(name)
    command.add_argument("port", type=int)
    command.set_defaults(func=hold)
    command = commands.add_parser("request")
    command.add_argument("control")
    command.add_argument("action", choices=("exchange", "close"))
    command.add_argument("expect", nargs="?", choices=("allow", "deny"))
    def request(args):
        response = unix_request(args.control, args.action)
        if args.expect and response.get("allowed") != (args.expect == "allow"):
            raise RuntimeError(f"persistent TCP expected {args.expect}: {response}")
    command.set_defaults(func=request)
    command = commands.add_parser("probe")
    command.add_argument("protocol", choices=("tcp", "udp", "icmp"))
    for name in ("source", "destination"):
        command.add_argument(name)
    command.add_argument("port", type=int)
    command.add_argument("expect", choices=("allow", "deny"))
    command.add_argument("label", choices=("router", "target"))
    command.add_argument("--reply-port", type=int)
    command.set_defaults(func=probe)
    for command_name, set_kind in (("grant", "login_whitelist"), ("blacklist", "blacklist")):
        command = commands.add_parser(command_name)
        command.add_argument("action", choices=("capture", "compare", "age"))
        command.add_argument("backend", choices=("nft", "iptables"))
        command.add_argument("address")
        command.add_argument("file", nargs="?")
        command.set_defaults(func=grant, set_kind=set_kind)
    command = commands.add_parser("conntrack")
    command.add_argument("source")
    command.add_argument("port", type=int)
    command.add_argument("expect", choices=("present", "absent"))
    command.set_defaults(func=conntrack_assert)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        detail = error.stderr if isinstance(error, subprocess.CalledProcessError) else str(error)
        print(f"FAIL: {detail}", file=sys.stderr)
        sys.exit(1)
