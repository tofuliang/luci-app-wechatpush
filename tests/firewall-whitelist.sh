#!/usr/bin/env bash
# Linux root only. Uses real nft/iptables/ipset, sockets and conntrack in fresh namespaces.
# Run: bash tests/firewall-whitelist.sh
# Dependencies: bash, Python 3, nft, iptables, ip6tables, ipset, jq, conntrack,
# iproute2 (ip), util-linux (unshare, mount, flock), and standard core utilities.
# Optional frontend selection: IPTABLES=iptables-legacy IP6TABLES=ip6tables-legacy.
set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)

fail() {
    printf 'not ok - %s / %s: %s\n' "${backend:-setup}" "${case_name:-isolation}" "$*" >&2
    exit 1
}

[[ $(uname -s) == Linux ]] || fail 'requires Linux; no firewall commands were run'
[[ $EUID == 0 ]] || fail 'requires root with network and mount namespace capabilities'
for executable in python3 nft ip ipset jq conntrack unshare mount flock readlink mktemp awk; do
    command -v "$executable" >/dev/null || fail "missing dependency: $executable"
done
IPTABLES_BIN=$(command -v "${IPTABLES:-iptables}") || fail 'missing IPv4 iptables frontend'
IP6TABLES_BIN=$(command -v "${IP6TABLES:-ip6tables}") || fail 'missing IPv6 iptables frontend'
IPTABLES_REAL=$(readlink -f "$IPTABLES_BIN")
IP6TABLES_REAL=$(readlink -f "$IP6TABLES_BIN")
AWK_REAL=$(readlink -f "$(command -v awk)")

if [[ ${1:-} != --isolated ]]; then
    [[ $# == 0 ]] || fail 'usage: bash tests/firewall-whitelist.sh'
    exec {original_net_fd}</proc/self/ns/net
    exec {original_mount_fd}</proc/self/ns/mnt
    exec unshare --net --mount --fork --propagation private "$BASH" "${BASH_SOURCE[0]}" \
        --isolated "$original_net_fd" "$original_mount_fd"
fi
[[ $# == 3 ]] || fail 'invalid namespace handshake'
[[ $2 =~ ^[0-9]+$ && $3 =~ ^[0-9]+$ ]] || fail 'invalid namespace descriptors'
original_net_fd=$2 original_mount_fd=$3
original_net=$(readlink "/proc/self/fd/$original_net_fd") || fail 'missing original network namespace'
original_mount=$(readlink "/proc/self/fd/$original_mount_fd") || fail 'missing original mount namespace'
[[ $original_net == net:\[*\] && $original_mount == mnt:\[*\] ]] || fail 'descriptors are not namespaces'
[[ $(readlink /proc/self/ns/net) != "$original_net" && $(readlink /proc/self/ns/mnt) != "$original_mount" ]] || \
    fail 'refusing to touch a shared network or mount namespace'
exec {original_net_fd}<&-
exec {original_mount_fd}<&-

STATE=''
children=()
namespaces=()
test_cleanup() {
    local status=$? pid namespace
    trap - EXIT ERR INT TERM
    for pid in "${children[@]}"; do
        kill "$pid" 2>/dev/null || :
    done
    for pid in "${children[@]}"; do
        wait "$pid" 2>/dev/null || :
    done
    for namespace in "${namespaces[@]}"; do
        ip netns delete "$namespace" 2>/dev/null || :
    done
    if [[ $status != 0 && -n $STATE ]]; then
        for log in "$STATE"/*.log; do
            [[ -f $log ]] && { printf '\n--- %s ---\n' "${log##*/}" >&2; cat "$log" >&2; }
        done
    fi
    [[ -z $STATE ]] || rm -rf -- "$STATE"
    exit "$status"
}
trap test_cleanup EXIT
trap 'fail "command failed at line $LINENO: $BASH_COMMAND"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM

# Load before masking absolute paths; even checkouts under /tmp or /run keep working.
helper_source=$(cat "$SCRIPT_DIR/firewall-traffic.py")
functions_source=$(python3 "$SCRIPT_DIR/firewall-traffic.py" extract \
    "$REPO_ROOT/root/usr/share/wechatpush/wechatpush" "$REPO_ROOT/root/etc/init.d/wechatpush" /dev/stdout)
mount --make-rprivate /
for directory in /run /tmp /etc /usr/share; do
    mount -t tmpfs -o mode=755 tmpfs "$directory"
done
[[ -d /var/run ]] || fail 'effective /var/run target is missing; refusing to create a host runtime path'
mount --bind /run /var/run
mkdir -p /run/netns /etc/nftables.d /usr/share/wechatpush
STATE=$(mktemp -d /run/wechatpush-firewall.XXXXXX)
printf '%s\n' "$helper_source" >"$STATE/traffic.py"
printf '%s\n' "$functions_source" >"$STATE/functions.sh"
unset helper_source functions_source
# Preserve multicall argv[0] without depending on masked /etc/alternatives symlinks.
ln -s "$IPTABLES_REAL" "$STATE/iptables"
ln -s "$IP6TABLES_REAL" "$STATE/ip6tables"
ln -s "$AWK_REAL" "$STATE/awk"
IPTABLES_BIN="$STATE/iptables" IP6TABLES_BIN="$STATE/ip6tables" AWK_BIN="$STATE/awk"
source "$STATE/functions.sh"
# Sourcing definitions never executes the router's top-level main call.
# All firewall operations use real binaries except a single, explicitly scoped IPv4
# NAT-enumeration failure below. This never changes kernel NAT capability or IPv6.
nat_list_failure=0
iptables() {
    if [[ ${nat_list_failure:-0} == 1 && ${1:-} == -t && ${2:-} == nat && ${3:-} == -S ]]; then
        printf 'simulated IPv4 NAT enumeration failure\n' >>"$STATE/nat-list-failure"
        printf "iptables: can't initialize iptables table 'nat': Table does not exist (do you need to insmod?)\n" >&2
        return 3
    fi
    "$IPTABLES_BIN" "$@"
}
ip6tables() { "$IP6TABLES_BIN" "$@"; }
awk() { "$AWK_BIN" "$@"; }
helper() { python3 "$STATE/traffic.py" "$@"; }

A4=10.66.0.2 B4=10.66.0.3 C4=10.66.0.4 R4=10.66.0.1 T4=10.67.0.2
A6=fd66::2 B6=fd66::3 C6=fd66::4 R6=fd66::1 T6=fd67::2
PORT_CONFIG='21000:21001,21010:21011,21020:21021,21030:21031,21040:21041,21050:21051,21060:21061,21070:21071'

ip link set lo up
printf '1\n' >/proc/sys/net/ipv4/ip_forward
printf '0\n' >/proc/sys/net/ipv6/conf/all/disable_ipv6
printf '0\n' >/proc/sys/net/ipv6/conf/default/disable_ipv6
printf '1\n' >/proc/sys/net/ipv6/conf/all/forwarding
for namespace in client target; do
    ip netns add "$namespace"
    namespaces+=("$namespace")
    ip -n "$namespace" link set lo up
    ip netns exec "$namespace" sh -c 'printf "0\n" >/proc/sys/net/ipv6/conf/all/disable_ipv6; printf "0\n" >/proc/sys/net/ipv6/conf/default/disable_ipv6'
done
for endpoint in client target; do
    ip link add "wp-$endpoint" type veth peer name eth0 netns "$endpoint"
    ip link set "wp-$endpoint" up
    ip -n "$endpoint" link set eth0 up
done
ip address add "$R4/24" dev wp-client
ip -6 address add "$R6/64" dev wp-client nodad
for address in "$A4" "$B4" "$C4"; do ip -n client address add "$address/24" dev eth0; done
for address in "$A6" "$B6" "$C6"; do ip -n client -6 address add "$address/64" dev eth0 nodad; done
ip -n client route add default via "$R4"
ip -n client -6 route add default via "$R6"
ip address add 10.67.0.1/24 dev wp-target
ip -6 address add fd67::1/64 dev wp-target nodad
ip -n target address add "$T4/24" dev eth0
ip -n target -6 address add "$T6/64" dev eth0 nodad
ip -n target route add default via 10.67.0.1
ip -n target -6 route add default via fd67::1
# Static neighbors keep broad source bans from accidentally testing ARP/ND expiry instead.
client_mac=$(ip -n client -j link show eth0 | jq -r '.[0].address')
router_mac=$(ip -j link show wp-client | jq -r '.[0].address')
target_mac=$(ip -n target -j link show eth0 | jq -r '.[0].address')
target_router_mac=$(ip -j link show wp-target | jq -r '.[0].address')
for address in "$A4" "$B4" "$C4" "$A6" "$B6" "$C6"; do
    ip neigh replace "$address" lladdr "$client_mac" dev wp-client nud permanent
done
for address in "$R4" "$R6"; do
    ip -n client neigh replace "$address" lladdr "$router_mac" dev eth0 nud permanent
done
for address in "$T4" "$T6"; do
    ip neigh replace "$address" lladdr "$target_mac" dev wp-target nud permanent
done
for address in 10.67.0.1 fd67::1; do
    ip -n target neigh replace "$address" lladdr "$target_router_mac" dev eth0 nud permanent
done

python3 "$STATE/traffic.py" serve router "$STATE/router.sock" >"$STATE/router.log" 2>&1 &
children+=("$!")
helper wait-ready "$STATE/router.sock" "${children[-1]}" >/dev/null
ip netns exec target python3 "$STATE/traffic.py" serve target "$STATE/target.sock" >"$STATE/target.log" 2>&1 &
children+=("$!")
helper wait-ready "$STATE/target.sock" "${children[-1]}" >/dev/null

# These are only unrelated startup fixtures. Actual init/main/firewall/login helpers run.
# The download helper is an absolute command; Bash permits that name for a function.
function /usr/libexec/wechatpush-call { :; }
enable_detection() { :; }
get_config() { :; }
getinterfacelist() { printf '{}\n'; }
LockFile() { :; }
translate() { printf '%s\n' "$1"; }
read_config() {
    devices_json="$dir/devices.json"
    output_dir="$dir/json_output"
    mkdir -p "$output_dir"
}
monitor_logins() { :; }
first() { :; }
deltemp() { :; }
usage() { :; }
cleanup() { :; }
# Stop after one complete real main-loop iteration, not during firewall initialization.
sleep() { printf 'complete\n' >"$dir/test-loop-complete"; enable=0; }

run_plugin() {
    rm -f /tmp/wechatpush/test-loop-complete
    # The router script itself does not enable nounset; optional UCI variables stay empty.
    if ! (set +u; main; [[ -f /tmp/wechatpush/test-loop-complete ]]) >>"$STATE/plugin.log" 2>&1; then
        fail 'actual init/main orchestration did not complete one iteration'
    fi
}

runtime_helper() {
    # Expected intermediate failures are normal in production (e.g. deleting an absent
    # element). A subshell preserves the test runner's strict options and checks only
    # the real helper's final status, without imposing test-only shell semantics.
    if ! (
        set +e +u
        set +o pipefail
        trap - ERR
        "$@"
    ); then
        fail "production helper failed: $*"
    fi
}

reset_fixture() {
    nat_list_failure=0
    # These destructive operations are permitted only after the namespace handshake.
    # No namespace is inherited from the caller, and no host ruleset is ever touched.
    if nft list table inet fw4 >/dev/null 2>&1; then nft delete table inet fw4; fi
    local command
    for command in iptables ip6tables; do
        "$command" -P INPUT ACCEPT
        "$command" -P FORWARD ACCEPT
        "$command" -P OUTPUT ACCEPT
        "$command" -F
        "$command" -X
        "$command" -t nat -F
        "$command" -t nat -X
    done
    ipset destroy
    conntrack -F >/dev/null 2>&1
    rm -rf /tmp/wechatpush
    dir=/tmp/wechatpush
    : >"$STATE/plugin.log"
    ip_blacklist_path="$STATE/blacklist"
    : >"$ip_blacklist_path"
    nft_blacklist_include_path=/etc/nftables.d/20-wechatpush-blacklist.nft
    rm -f "$nft_blacklist_include_path"
    logfile="$STATE/plugin.log"
    login_ip_white_list='' login_port_white="$PORT_CONFIG" login_port_forward_list=''
    port_knocking_enable=1 login_web_black=1 block_blacklisted_forwarding=1
    login_ip_white_timeout=300 login_ip_black_timeout=0
    enable=1 thread_num=1 get_ipv4_mode=0 get_ipv6_mode=0 sleeptime=1
    if [[ $backend == nft ]]; then
        nftables_version=true
        fw4() { :; } # command-existence selector used by the actual service clear helper
        # /etc is masked; numeric ICMPv6 avoids libc's /etc/protocols lookup.
        nft -f - <<'RULES'
add table inet fw4
add chain inet fw4 input { type filter hook input priority 0; policy drop; }
add chain inet fw4 forward { type filter hook forward priority 0; policy accept; }
add chain inet fw4 output { type filter hook output priority 0; policy accept; }
add rule inet fw4 input iifname "lo" accept
add rule inet fw4 input ct state established,related accept
add rule inet fw4 input tcp dport 21500 accept
add rule inet fw4 input udp dport { 21071, 21500 } accept
add rule inet fw4 input ip protocol icmp accept
add rule inet fw4 input meta l4proto 58 accept
RULES
    else
        nftables_version=''
        unset -f fw4 2>/dev/null || :
        for command in iptables ip6tables; do
            "$command" -P INPUT DROP
            "$command" -A INPUT -i lo -j ACCEPT
            "$command" -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            "$command" -A INPUT -p tcp --dport 21500 -j ACCEPT
            "$command" -A INPUT -p udp -m multiport --dports 21071,21500 -j ACCEPT
        done
        iptables -A INPUT -p icmp -j ACCEPT
        ip6tables -A INPUT -p 58 -j ACCEPT
    fi
}

reload_generated_nft_include() {
    local ports
    ports=$(runtime_helper normalize_login_port_white)
    runtime_helper sync_nft_blacklist_include "$ports"
    # A real atomic nft transaction models a table-preserving include reload;
    # this is not a fw4 command or full OpenWrt integration.
    nft -f - <<RULES
flush table inet fw4
table inet fw4 {
    include "$nft_blacklist_include_path"
    chain input { type filter hook input priority 0; policy drop; iifname "lo" accept; ct state established,related accept; tcp dport 21500 accept; udp dport { 21071, 21500 } accept; ip protocol icmp accept; meta l4proto 58 accept; }
    chain forward { type filter hook forward priority 0; policy accept; }
    chain output { type filter hook output priority 0; policy accept; }
}
RULES
}

setup_legacy_whitelist() {
    local version source old_login router target legacy_set black_set address_family ip_version set_family command destination chain tag
    if [[ $backend == nft ]]; then
        nft add chain inet fw4 wechatpush_dstnat \{ type nat hook prerouting priority -100 \; \}
        nft add chain inet fw4 wechatpush_srcnat \{ type nat hook postrouting priority 100 \; \}
    fi
    for version in 4 6; do
        source="A$version" old_login="C$version" router="R$version" target="T$version"
        source=${!source} old_login=${!old_login} router=${!router} target=${!target}
        legacy_set=wechatpush_whitelist black_set=wechatpush_blacklist
        address_family=ipv4 ip_version=ip set_family=inet
        destination="$target:23000"
        if [[ $version == 6 ]]; then
            legacy_set+=v6 black_set+=v6
            address_family=ipv6 ip_version=ip6 set_family=inet6
            destination="[$target]:23000"
        fi
        command="${ip_version}tables"
        if [[ $backend == nft ]]; then
            nft add set inet fw4 "$legacy_set" \{ type "${address_family}_addr" \; flags timeout \; timeout 0s \; \}
            nft add element inet fw4 "$legacy_set" \{ "$source" \}
            nft add element inet fw4 "$legacy_set" \{ "$old_login" timeout 300s \}
            nft add set inet fw4 "$black_set" \{ type "${address_family}_addr" \; \}
            nft add element inet fw4 "$black_set" \{ "$source" \}
            for chain in input forward; do
                tag='!wechatpush Drop rule'
                [[ $chain == input ]] || tag='!wechatpush Forward Drop rule'
                nft insert rule inet fw4 "$chain" "$ip_version" saddr "@$black_set" "$ip_version" saddr != "@$legacy_set" counter drop comment "\"$tag\""
            done
            nft insert rule inet fw4 input tcp dport 21071 "$ip_version" saddr "@$legacy_set" counter accept comment '"!wechatpush Accept rule"'
            nft add rule inet fw4 wechatpush_dstnat meta nfproto "$address_family" "$ip_version" saddr "@$legacy_set" tcp dport 22000 counter dnat "$ip_version" to "$destination" comment '"!wechatpush DNAT rule"'
            # Old nft SNAT is source-independent and shared with new mappings.
            nft add rule inet fw4 wechatpush_srcnat "$ip_version" daddr "$target" tcp dport 23000 counter snat "$ip_version" to "$router" comment '"!wechatpush SNAT rule"'
        else
            ipset create "$legacy_set" hash:ip family "$set_family" timeout 0
            ipset add "$legacy_set" "$source" timeout 0
            ipset add "$legacy_set" "$old_login" timeout 300
            ipset create "$black_set" hash:ip family "$set_family" timeout 0
            ipset add "$black_set" "$source" timeout 0
            for chain in INPUT FORWARD; do
                "$command" -I "$chain" -m set --match-set "$black_set" src -m set ! --match-set "$legacy_set" src -j DROP
            done
            "$command" -I INPUT -m set --match-set "$legacy_set" src -p tcp -m multiport --dports 21071 -j ACCEPT
            "$command" -t nat -I PREROUTING -m set --match-set "$legacy_set" src -p tcp --dport 22000 -j DNAT --to-destination "$destination"
            "$command" -t nat -I POSTROUTING -m set --match-set "$legacy_set" src -p tcp -d "$target" --dport 23000 -j SNAT --to-source "$router"
        fi
    done
}

set_config_ab() { login_ip_white_list="$A4 $A6 $B4 $B6"; }
set_config_a() { login_ip_white_list="$A4 $A6"; }
set_config_b() { login_ip_white_list="$B4 $B6"; }
restore_a_ban() { printf '%s timeout 0\n' "$A4" "$A6" >"$ip_blacklist_path"; }

member() {
    local set_name="$1" address="$2" wanted="$3" present=0
    [[ $address == *:* ]] && set_name+=v6
    if [[ $backend == nft ]]; then
        if nft get element inet fw4 "$set_name" \{ "$address" \} >/dev/null 2>&1; then present=1; fi
    else
        if ipset test "$set_name" "$address" >/dev/null 2>&1; then present=1; fi
    fi
    [[ $present == "$wanted" ]] || fail "$set_name membership for $address: expected $wanted, got $present"
}

traffic() {
    local protocol="$1" source="$2" destination="$3" port="$4" expected="$5" label="$6"
    shift 6
    if ! ip netns exec client python3 "$STATE/traffic.py" probe "$protocol" "$source" "$destination" \
        "$port" "$expected" "$label" "$@"; then
        fail "$protocol $source -> $destination:$port expected $expected"
    fi
}

login_access() {
    local source="$1" destination="$2" port
    for port in 21001 21011 21021 21031 21041 21051 21061 21071; do
        traffic tcp "$source" "$destination" "$port" allow router
    done
    traffic tcp "$source" "$destination" 21035 deny router
}

configured_access() {
    local version source router target
    for version in 4 6; do
        source="A$version" router="R$version" target="T$version"
        source=${!source} router=${!router} target=${!target}
        member wechatpush_blacklist "$source" 1
        login_access "$source" "$router"
        traffic tcp "$source" "$router" 21500 allow router
        traffic udp "$source" "$router" 21071 allow router
        traffic udp "$source" "$router" 21500 allow router
        traffic icmp "$source" "$router" 0 allow router
        traffic tcp "$source" "$target" 23000 allow target
        traffic udp "$source" "$target" 23000 allow target
    done
}

revoked_access() {
    local version source router target
    for version in 4 6; do
        source="A$version" router="R$version" target="T$version"
        source=${!source} router=${!router} target=${!target}
        member wechatpush_blacklist "$source" 1
        traffic tcp "$source" "$router" 21000 deny router
        traffic tcp "$source" "$router" 21071 deny router
        traffic tcp "$source" "$router" 21500 deny router
        traffic udp "$source" "$router" 21071 deny router
        traffic udp "$source" "$router" 21500 deny router
        traffic icmp "$source" "$router" 0 deny router
        traffic tcp "$source" "$target" 23000 deny target
        traffic udp "$source" "$target" 23000 deny target
    done
}

ok() { printf 'ok - %s / %s\n' "$backend" "$case_name"; }

for backend in nft iptables; do
    case_name='configured startup: blacklist exclusion, TCP login chunks and protocol/forward boundaries'
    reset_fixture
    login_ip_white_timeout=0
    set_config_ab
    restore_a_ban
    run_plugin
    configured_access
    ok

    case_name='normal revoke with B retained: restored live ban and established conntrack cleanup'
    for version in 4 6; do
        source="A$version" target="T$version"
        source=${!source} target=${!target}
        ip netns exec client python3 "$STATE/traffic.py" hold "$STATE/hold$version.sock" "$source" "$target" 23000 \
            >"$STATE/hold$version.log" 2>&1 &
        children+=("$!")
        metadata=$(helper wait-ready "$STATE/hold$version.sock" "${children[-1]}")
        printf '%s\n' "$metadata" >"$STATE/hold$version.json"
        helper conntrack "$source" "$(jq -r .port <<<"$metadata")" present
    done
    set_config_b
    run_plugin
    for version in 4 6; do
        source="A$version"
        source=${!source}
        helper conntrack "$source" "$(jq -r .port "$STATE/hold$version.json")" absent
        helper request "$STATE/hold$version.sock" exchange deny
        helper request "$STATE/hold$version.sock" close
    done
    wait "${children[2]}" "${children[3]}"
    children=("${children[0]}" "${children[1]}")
    revoked_access
    login_access "$B4" "$R4"
    login_access "$B6" "$R6"
    ok

    case_name='normal revoke to an empty config: no independent grant can survive'
    reset_fixture
    set_config_a
    restore_a_ban
    run_plugin
    configured_access
    login_ip_white_list=''
    run_plugin
    revoked_access
    ok

    for ports in '' '21000,not-a-port'; do
        case_name='knocking disabled with empty/invalid ports: all-flow config exclusion and timed-ban expiry survive revoke'
        reset_fixture
        port_knocking_enable=0
        login_port_white="$ports"
        login_ip_black_timeout=300
        set_config_ab
        printf '%s timeout 300\n' "$A4" "$A6" >"$ip_blacklist_path"
        # Ordinary firewall access must not depend on knocking configuration.
        if [[ $backend == nft ]]; then
            nft add rule inet fw4 input tcp dport 21071 accept
        else
            iptables -A INPUT -p tcp --dport 21071 -j ACCEPT
            ip6tables -A INPUT -p tcp --dport 21071 -j ACCEPT
        fi
        run_plugin
        for version in 4 6; do
            source="A$version" router="R$version" target="T$version"
            source=${!source} router=${!router} target=${!target}
            member wechatpush_blacklist "$source" 1
            traffic tcp "$source" "$router" 21071 allow router
            traffic tcp "$source" "$router" 21500 allow router
            traffic udp "$source" "$router" 21071 allow router
            traffic udp "$source" "$router" 21500 allow router
            traffic icmp "$source" "$router" 0 allow router
            traffic tcp "$source" "$target" 23000 allow target
            traffic udp "$source" "$target" 23000 allow target
            helper blacklist capture "$backend" "$source" "$STATE/ban$version.json"
            [[ $(jq -r .permanent "$STATE/ban$version.json") == false ]] || fail 'restored ban is not timed'
        done
        helper blacklist age "$backend" "$A4"
        set_config_b
        run_plugin
        revoked_access
        for version in 4 6; do
            source="A$version"
            source=${!source}
            helper blacklist compare "$backend" "$source" "$STATE/ban$version.json"
        done
        ok
    done

    case_name='legacy mixed whitelist upgrade: fail-closed old grants, retained config and new independent authorization'
    reset_fixture
    setup_legacy_whitelist
    for version in 4 6; do
        router="R$version"
        router=${!router}
        for origin in A C; do
            source="$origin$version"
            source=${!source}
            traffic tcp "$source" "$router" 21071 allow router
            traffic tcp "$source" "$router" 22000 allow target --reply-port 23000
        done
    done
    # Preserve the actual legacy kernel state across the current startup.
    set_config_b
    restore_a_ban
    login_port_forward_list="$R4,22000,$T4,23000"$'\n'"$R6,22000,$T6,23000"
    run_plugin
    for version in 4 6; do
        router="R$version" configured="B$version" source="A$version" independent="C$version"
        router=${!router} configured=${!configured} source=${!source} independent=${!independent}
        member wechatpush_blacklist "$source" 1
        for old_source in "$source" "$independent"; do
            traffic tcp "$old_source" "$router" 21071 deny router
            traffic tcp "$old_source" "$router" 22000 deny target --reply-port 23000
        done
        traffic tcp "$source" "$router" 21500 deny router
        traffic tcp "$configured" "$router" 21071 allow router
        traffic tcp "$configured" "$router" 22000 allow target --reply-port 23000
        runtime_helper add_ip_white "$independent"
        helper grant capture "$backend" "$independent" "$STATE/upgrade-grant$version.json"
    done
    helper grant age "$backend" "$C4"
    login_ip_white_list="$B4 $B6 $C4 $C6"
    run_plugin
    set_config_b
    run_plugin
    if [[ $backend == nft ]]; then
        reload_generated_nft_include
        run_plugin
    fi
    for version in 4 6; do
        source="A$version" independent="C$version" router="R$version"
        source=${!source} independent=${!independent} router=${!router}
        helper grant compare "$backend" "$independent" "$STATE/upgrade-grant$version.json"
        login_access "$independent" "$router"
        traffic tcp "$independent" "$router" 22000 allow target --reply-port 23000
        traffic tcp "$source" "$router" 21071 deny router
        traffic tcp "$source" "$router" 22000 deny target --reply-port 23000
    done
    ok

    case_name='disable, remove config, re-enable with white timeout zero: no leaked config grant'
    reset_fixture
    login_ip_white_timeout=0
    set_config_ab
    restore_a_ban
    run_plugin
    configured_access
    runtime_helper clear_blacklist_rules
    login_ip_white_list=''
    run_plugin
    revoked_access
    ok

    if [[ $backend == iptables ]]; then
        for nat_references in 0 1; do
            case_name="disable with IPv4 NAT enumeration fault (configured NAT references=$nat_references): dual-stack revoke, independent grants retained"
            reset_fixture
            # Default zero makes the IPv6 zero-timeout grant truly permanent;
            # IPv4 below receives an independent explicit timed grant.
            login_ip_white_timeout=0
            set_config_a
            restore_a_ban
            if [[ $nat_references == 1 ]]; then
                login_port_forward_list="$R4,22000,$T4,23000"$'\n'"$R6,22000,$T6,23000"
            fi
            run_plugin
            for version in 4 6; do
                source="A$version" independent="C$version" router="R$version"
                source=${!source} independent=${!independent} router=${!router}
                traffic tcp "$source" "$router" 21071 allow router
                lifetime=300
                [[ $version == 4 ]] || lifetime=0
                login_ip_white_timeout="$lifetime" runtime_helper add_ip_white "$independent"
                login_access "$independent" "$router"
                helper grant capture "$backend" "$independent" "$STATE/cleanup-grant$version.json"
                expected_permanent=false
                [[ $lifetime != 0 ]] || expected_permanent=true
                [[ $(jq -r .permanent "$STATE/cleanup-grant$version.json") == "$expected_permanent" ]] || \
                    fail "cleanup grant does not have the requested $lifetime-second lifetime"
                if [[ $nat_references == 1 ]]; then
                    traffic tcp "$source" "$router" 22000 allow target --reply-port 23000
                    traffic tcp "$independent" "$router" 22000 allow target --reply-port 23000
                fi
            done
            helper grant age "$backend" "$C4"
            rm -f "$STATE/nat-list-failure"
            nat_list_failure=1
            clear_status=0
            # Inspect authorization even if the deliberately failed enumeration is
            # reported to the caller. An early return must not hide the IPv6 leak.
            if (set +e +u; set +o pipefail; trap - ERR; clear_blacklist_rules); then
                :
            else
                clear_status=$?
            fi
            nat_list_failure=0
            for version in 6 4; do
                source="A$version" independent="C$version" router="R$version"
                source=${!source} independent=${!independent} router=${!router}
                traffic tcp "$source" "$router" 21001 deny router
                traffic tcp "$source" "$router" 21071 deny router
                login_access "$independent" "$router"
                helper grant compare "$backend" "$independent" "$STATE/cleanup-grant$version.json"
                if [[ $nat_references == 1 ]]; then
                    traffic tcp "$source" "$router" 22000 deny target --reply-port 23000
                    traffic tcp "$independent" "$router" 22000 allow target --reply-port 23000
                fi
            done
            if ipset list wechatpush_config_whitelistv6 >/dev/null 2>&1; then
                fail 'IPv6 configured set survived successful real IPv6 cleanup'
            fi
            if [[ $nat_references == 0 ]]; then
                if ipset list wechatpush_config_whitelist >/dev/null 2>&1; then
                    fail 'unreferenced IPv4 configured set survived disable'
                fi
                [[ $clear_status == 0 ]] || fail "cleanup without NAT references failed: $clear_status"
            else
                [[ -s $STATE/nat-list-failure ]] || fail 'referenced IPv4 NAT enumeration fault was not exercised'
                [[ $clear_status != 0 ]] || fail 'real referenced-NAT enumeration error was not reported'
                # If real NAT rules still reference this set, destruction is impossible;
                # an empty set must make every remaining configured rule inert.
                if ipset list wechatpush_config_whitelist >/dev/null 2>&1; then
                    [[ $(ipset save wechatpush_config_whitelist | awk '$1 == "add" {count++} END {print count+0}') == 0 ]] || \
                        fail 'failed IPv4 NAT cleanup left configured source permissions active'
                fi
            fi
            ok
        done
    fi

    for lifetime in 0 300; do
        case_name="independent grant ($lifetime seconds): DROP-policy login, config add/remove preservation and chunk ordering"
        reset_fixture
        login_ip_white_timeout=$lifetime
        run_plugin
        for version in 4 6; do
            source="A$version" router="R$version"
            source=${!source} router=${!router}
            # Independent successful-login grants predate config membership.
            runtime_helper add_ip_white "$source"
            member wechatpush_blacklist "$source" 0
            login_access "$source" "$router"
            traffic udp "$source" "$router" 21000 deny router
            helper grant capture "$backend" "$source" "$STATE/grant$version.json"
            expected_permanent=false
            [[ $lifetime != 0 ]] || expected_permanent=true
            [[ $(jq -r .permanent "$STATE/grant$version.json") == "$expected_permanent" ]] || \
                fail "independent grant does not have the requested $lifetime-second lifetime"
        done
        if [[ $lifetime != 0 ]]; then helper grant age "$backend" "$A4"; fi
        set_config_a
        run_plugin
        login_ip_white_list=''
        run_plugin
        for version in 4 6; do
            source="A$version" router="R$version"
            source=${!source} router=${!router}
            helper grant compare "$backend" "$source" "$STATE/grant$version.json"
            member wechatpush_blacklist "$source" 0
            login_access "$source" "$router"
            # An effective ban proves every chunk is before black DROP, not just the first.
            runtime_helper add_ip_black "$source" ''
        done
        run_plugin
        for version in 4 6; do
            source="A$version" router="R$version" target="T$version"
            source=${!source} router=${!router} target=${!target}
            member wechatpush_blacklist "$source" 1
            login_access "$source" "$router"
            traffic tcp "$source" "$router" 21500 deny router
            traffic udp "$source" "$router" 21071 deny router
            traffic icmp "$source" "$router" 0 deny router
            traffic tcp "$source" "$target" 23000 deny target
            traffic udp "$source" "$target" 23000 deny target
        done
        run_plugin
        run_plugin
        for version in 4 6; do
            source="A$version" router="R$version"
            source=${!source} router=${!router}
            helper grant compare "$backend" "$source" "$STATE/grant$version.json"
            login_access "$source" "$router"
        done
        ok
    done

    for ports in "$PORT_CONFIG" '21000,not-a-port'; do
        case_name='configured and independent dynamic DNAT: source restriction, late chunk and repeat stability'
        [[ $ports == "$PORT_CONFIG" ]] || case_name='invalid login port config: independent IPv4/IPv6 DNAT still works'
        reset_fixture
        login_port_white="$ports"
        # Helper-level field-whitespace compatibility; UCI/read_config preprocessing is stubbed.
        login_port_forward_list=" $R4, 22000, $T4, 23000 "$'\n'"$R6,22000,$T6,23000"
        set_config_a
        restore_a_ban
        run_plugin
        for version in 4 6; do
            source="B$version"
            source=${!source}
            runtime_helper add_ip_white "$source"
            helper grant capture "$backend" "$source" "$STATE/nat-grant$version.json"
        done
        for version in 4 6; do
            router="R$version" router=${!router}
            for origin in A B; do
                source="$origin$version" source=${!source}
                traffic tcp "$source" "$router" 22000 allow target --reply-port 23000
                if [[ $ports == "$PORT_CONFIG" ]]; then
                    login_access "$source" "$router"
                else
                    traffic tcp "$source" "$router" 21071 deny router
                fi
            done
            source="C$version" source=${!source}
            traffic tcp "$source" "$router" 22000 deny target --reply-port 23000
        done
        helper grant age "$backend" "$B4"
        run_plugin
        run_plugin
        for version in 4 6; do
            independent="B$version" router="R$version"
            independent=${!independent} router=${!router}
            helper grant compare "$backend" "$independent" "$STATE/nat-grant$version.json"
            for origin in A B; do
                source="$origin$version"
                source=${!source}
                traffic tcp "$source" "$router" 22000 allow target --reply-port 23000
                if [[ $ports == "$PORT_CONFIG" ]]; then
                    login_access "$source" "$router"
                else
                    traffic tcp "$source" "$router" 21071 deny router
                    traffic tcp "$source" "$router" 21035 deny router
                fi
            done
            source="C$version"
            source=${!source}
            traffic tcp "$source" "$router" 22000 deny target --reply-port 23000
        done
        ok
    done

    if [[ $backend == nft ]]; then
        case_name='legacy nft migration: foreign verdict/predicate rules survive while complete owned login rules retire'
        reset_fixture
        setup_legacy_whitelist
        traffic tcp "$C4" "$R4" 21500 allow router
        traffic tcp "$C6" "$R6" 21500 allow router
        # Same old ACCEPT tag, but a different verdict: never plugin-owned.
        nft insert rule inet fw4 input tcp dport 21500 ip saddr @wechatpush_whitelist counter drop comment '"!wechatpush Accept rule"'
        # The IPv6 rule also adds a destination constraint absent from the producer.
        nft insert rule inet fw4 input tcp dport 21500 ip6 saddr @wechatpush_whitelistv6 ip6 daddr "$R6" counter drop comment '"!wechatpush Accept rule"'
        # Correct ACCEPT verdict plus an extra expression independently exercises
        # predicate ownership. Its real gap-port permission must also survive.
        nft insert rule inet fw4 input tcp dport 21035 ip6 saddr @wechatpush_whitelistv6 ip6 daddr "$R6" counter accept comment '"!wechatpush Accept rule"'
        for version in 4 6; do
            independent="C$version" router="R$version"
            independent=${!independent} router=${!router}
            ip_version=ip legacy_set=wechatpush_whitelist
            if [[ $version == 6 ]]; then ip_version=ip6; legacy_set+=v6; fi
            nft insert rule inet fw4 input tcp dport 21001 "$ip_version" saddr "@$legacy_set" counter accept comment '"!wechatpush Accept rule"'
            traffic tcp "$independent" "$router" 21001 allow router
            traffic tcp "$independent" "$router" 21500 deny router
        done
        traffic tcp "$C6" "$R6" 21035 allow router
        set_config_b
        restore_a_ban
        run_plugin
        for version in 4 6; do
            independent="C$version" router="R$version"
            independent=${!independent} router=${!router}
            # Packet denial is the foreign-rule preservation oracle, not its handle.
            traffic tcp "$independent" "$router" 21500 deny router
            traffic tcp "$independent" "$router" 21001 deny router
            member wechatpush_whitelist "$independent" 1
        done
        traffic tcp "$C6" "$R6" 21035 allow router
        for version in 4 6; do
            independent="C$version" router="R$version"
            independent=${!independent} router=${!router}
            runtime_helper add_ip_white "$independent"
            traffic tcp "$independent" "$router" 21001 allow router
            traffic tcp "$independent" "$router" 21500 deny router
        done
        traffic tcp "$C6" "$R6" 21035 allow router
        ok

        case_name='configured nft foreign INPUT/DNAT rules survive main, stop, and re-enable without retaining stopped config grants'
        reset_fixture
        set_config_a
        restore_a_ban
        login_port_forward_list="$R4,22000,$T4,23000"$'\n'"$R6,22000,$T6,23000"
        run_plugin
        for version in 4 6; do
            source="A$version" router="R$version" target="T$version"
            source=${!source} router=${!router} target=${!target}
            traffic tcp "$source" "$router" 21500 allow router
            traffic tcp "$source" "$router" 21001 allow router
            traffic tcp "$source" "$router" 22000 allow target --reply-port 23000
            configured_set=wechatpush_config_whitelist ip_version=ip address_family=ipv4
            destination="$target:23000"
            if [[ $version == 6 ]]; then
                configured_set+=v6 ip_version=ip6 address_family=ipv6
                destination="[$target]:23000"
            fi
            nft insert rule inet fw4 input tcp dport 21500 "$ip_version" saddr "@$configured_set" counter drop comment '"!wechatpush Accept rule"'
            nft insert rule inet fw4 input tcp dport 21035 "$ip_version" saddr "@$configured_set" "$ip_version" daddr "$router" counter accept comment '"!wechatpush Accept rule"'
            nft insert rule inet fw4 wechatpush_dstnat meta nfproto "$address_family" "$ip_version" saddr "@$configured_set" "$ip_version" daddr "$router" tcp dport 22001 counter dnat "$ip_version" to "$destination" comment '"!wechatpush DNAT rule"'
        done
        run_plugin
        for version in 4 6; do
            source="A$version" router="R$version"
            source=${!source} router=${!router}
            traffic tcp "$source" "$router" 21500 deny router
            traffic tcp "$source" "$router" 21035 allow router
            traffic tcp "$source" "$router" 22001 allow target --reply-port 23000
        done
        # Foreign references may make set destruction report failure. Continue to
        # inspect actual stopped authorization rather than letting errexit abort.
        if (set +e +u; set +o pipefail; trap - ERR; clear_blacklist_rules); then
            :
        else
            printf 'Cleanup reported status %s with foreign configured references\n' "$?" >>"$STATE/plugin.log"
        fi
        for version in 4 6; do
            source="A$version" router="R$version"
            source=${!source} router=${!router}
            member wechatpush_config_whitelist "$source" 0
            traffic tcp "$source" "$router" 21001 deny router
            traffic tcp "$source" "$router" 21035 deny router
            traffic tcp "$source" "$router" 22000 deny target --reply-port 23000
            traffic tcp "$source" "$router" 22001 deny target --reply-port 23000
        done
        # Config remains A: repopulation must reactivate the same foreign effects.
        run_plugin
        for version in 4 6; do
            source="A$version" router="R$version"
            source=${!source} router=${!router}
            traffic tcp "$source" "$router" 21500 deny router
            traffic tcp "$source" "$router" 21035 allow router
            traffic tcp "$source" "$router" 22001 allow target --reply-port 23000
            traffic tcp "$source" "$router" 21001 allow router
            traffic tcp "$source" "$router" 22000 allow target --reply-port 23000
        done
        ok

        case_name='generated nft include table reload: live bans and config exclusions before reconciliation, login/DNAT afterward'
        reset_fixture
        set_config_a
        printf '%s timeout 0\n' "$A4" "$A6" "$B4" "$B6" >"$ip_blacklist_path"
        login_port_forward_list="$R4,22000,$T4,23000"$'\n'"$R6,22000,$T6,23000"
        run_plugin
        for version in 4 6; do
            independent="C$version" source="A$version" blocked="B$version" router="R$version" target="T$version"
            independent=${!independent} source=${!source} blocked=${!blocked} router=${!router} target=${!target}
            runtime_helper add_ip_white "$independent"
            helper grant capture "$backend" "$independent" "$STATE/reload-grant$version.json"
            traffic tcp "$source" "$router" 22000 allow target --reply-port 23000
            traffic tcp "$independent" "$router" 22000 allow target --reply-port 23000
            traffic tcp "$source" "$router" 21500 allow router
            traffic tcp "$blocked" "$router" 21500 deny router
        done
        reload_generated_nft_include
        # Deliberately do not run main yet: only generated pre-hooks and ordinary
        # base firewall permissions must enforce this next set of real packets.
        for version in 4 6; do
            source="A$version" blocked="B$version" router="R$version" target="T$version"
            source=${!source} blocked=${!blocked} router=${!router} target=${!target}
            traffic tcp "$source" "$router" 21500 allow router
            traffic udp "$source" "$router" 21071 allow router
            traffic tcp "$source" "$target" 23000 allow target
            traffic udp "$source" "$target" 23000 allow target
            traffic tcp "$blocked" "$router" 21500 deny router
            traffic udp "$blocked" "$router" 21071 deny router
            traffic tcp "$blocked" "$target" 23000 deny target
            traffic udp "$blocked" "$target" 23000 deny target
        done
        run_plugin
        for version in 4 6; do
            source="A$version" independent="C$version" router="R$version"
            source=${!source} independent=${!independent} router=${!router}
            helper grant compare "$backend" "$independent" "$STATE/reload-grant$version.json"
            login_access "$source" "$router"
            login_access "$independent" "$router"
            traffic tcp "$source" "$router" 22000 allow target --reply-port 23000
            traffic tcp "$independent" "$router" 22000 allow target --reply-port 23000
        done
        ok
    fi
done
printf 'All isolated firewall whitelist regressions passed (nft + iptables, IPv4 + IPv6).\n'
