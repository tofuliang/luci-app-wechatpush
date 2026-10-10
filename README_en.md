# Introduction

[![Lastest Release](https://img.shields.io/github/release/tty228/luci-app-wechatpush.svg?style=flat)](https://github.com/tty228/luci-app-wechatpush/releases)
[![GitHub All Releases](https://img.shields.io/github/downloads/tty228/luci-app-wechatpush/total)](https://github.com/tty228/luci-app-wechatpush/releases)

[中文文档](README.md) | [English](README_en.md)

**OpenWrt Notification Plugin – Send Alerts to WeChat or Telegram**

This OpenWrt plugin delivers real-time router notifications to your mobile device via **WeChat** or **Telegram** or **Mail**. Monitor your network with alerts for:

- [x] IP changes (IPv4/IPv6)
- [x] Device connections (online/offline)
- [x] Online client list & traffic usage
- [x] CPU load & temperature (including virtualized hosts like PVE)
- [x] Router status reports
- [x] Security alerts (failed web/SSH logins with auto blacklist)
- [x] Port knocking & automated tasks

Auto-banning blocks blacklisted IPs from accessing the router. With fw4/nftables, its drop rules are persisted in `/etc/nftables.d/20-wechatpush-blacklist.nft`: fw4 preserves set elements and restores the rules in the same transaction on each firewall reload, with no rule gap. After a router reboot, the plugin restores set elements from the blacklist file when it starts. Optionally block all forwarded traffic from blacklisted IPs, including access to port-forwarded downstream devices and Internet access by LAN clients. With forwarded-traffic blocking enabled and conntrack installed, banning also attempts to clear that IP's existing connection-tracking entries to interrupt offloaded flows; without conntrack, this step is skipped while new connections remain blocked by the blacklist rules. Turning the option off, or turning auto-ban off, removes the drop rules and the persisted file on the next detection cycle, and disabling the plugin clears them as well; stopping the service while it stays enabled does not remove the active rules. fw4 timed bans are restored with their last recorded remaining duration. Set the blacklist duration to `0` for permanent bans; remove the IP from the blacklist to lift the ban.

The configured login-alert/auto-ban whitelist takes priority over this plugin's input and forwarding bans, independently of port knocking or the login-port configuration. Blacklist DROP rules match only sources that are blacklisted and not in the configured whitelist; existing bans retain their original lifetime. Removing an entry and reloading the plugin reactivates unexpired bans. With forwarded blocking enabled and conntrack installed, revoking an exemption also clears the affected connection-tracking entries. This ban exemption itself does not bypass unrelated firewall rules.

Configured entries and port-knocking grants acquired through successful logins are managed separately. Adding or removing a configured entry does not change an independent login grant's lifetime, including permanent grants with a release time of `0`. With port knocking enabled, both sources independently authorize the configured TCP login ports and port forwards; login grants do not bypass other-port, other-protocol, or forwarded-traffic blacklist bans. iptables login-port lists are split to fit the multiport capacity. Empty or invalid login-port configuration does not prevent independently configured valid port forwards.

Initialization and shutdown match the complete structure of plugin authorization rules for cleanup; a reused plugin comment alone is not sufficient.

On the first upgrade to the separate login-grant sets, legacy port-knocking entries cannot reliably be attributed to configuration or successful login. They are therefore not migrated; a new successful login is required to obtain a new grant. Configured whitelist entries are restored normally, and subsequent ordinary reloads preserve new independent grants. Legacy sets still referenced by external custom rules are retained for those rules, but this plugin no longer treats their members as login grants.

Supported services:
| Push application | Method | description |
| :-------- | :----- | :----- |
| WeChat | Server Chan | https://sct.ftqq.com/
| WeChat | PushPlus | http://www.pushplus.plus/
| WeChat etc. | WPUSH | https://wpush.cn/
| WeChat | WxPusher | https://wxpusher.zjiecode.com/docs
| WeChat for Enterprise | Application Push | https://work.weixin.qq.com/api/doc/90000/90135/90248
| Telegram | bot | https://t.me/BotFather
| Mail | msmtp | https://marlam.de/msmtp/

Limited resources are available. If you need services such as DingTalk push, Feishu push, Bark push, etc., please try another branch at https://github.com/zzsj0928/luci-app-pushbot, or use **custom API settings**.

## Instructions

**Regarding Installation:**

Basic runtime dependencies are `iputils-arping`, `curl`, `jq`, `bash`, and `luci-lua-runtime`; the package manager installs them as package dependencies. Consider available memory before installing. **Run `opkg update` on opkg-based systems or `apk update` on apk-based systems first, and choose an IPK/APK package matching the firmware version, architecture, and package manager.**

The system must also provide `flock`. Auto-banning and port knocking require `nft` for fw4, or `iptables`/`ip6tables`, `ipset`, and the relevant kernel modules for the iptables backend. `conntrack` is optional and provides the existing-connection cleanup described above; it is not a basic runtime dependency.

The original development baseline was x86 OpenWrt v23.05.0. Current IPK/APK build versions and architectures are defined in the [build workflow](.github/workflows/build.yml); a configured build target does not imply runtime compatibility verification on every firmware or device. Different systems and devices may encounter various issues. **If you encounter errors in temperature information retrieval, display errors, or other issues, please adapt accordingly.**

**Regarding Hostnames:**

For devices that do not declare hostnames, devices connected via optical modem dial-up, OpenWrt used as a bypass gateway, and other scenarios where hostname retrieval fails, you can set the hostname using the following methods:

- Use device name remarks.
- Configure to obtain the hostname from the optical modem in advanced settings.
- Enable MAC device database.
- Install samba*-server or samba*-client to enable the program to query hostnames via NetBIOS.


**Regarding Device Online Status:**

By default, ping/arping is used to actively detect device online status to counter Wi-Fi sleep mechanism. Active detection takes more time but provides more accurate device online status.

- If devices frequently go into sleep mode, please adjust the timeout settings in advanced settings.
- If you don't require highly precise device online information and only need other features, you can disable active detection in advanced settings.


**Regarding Traffic Statistics:**

Traffic statistics rely on `wrtbwmon`, which must be installed or compiled separately for a compatible firewall environment. **wrtbwmon is incompatible with fw4/nftables; installing it alone does not enable traffic statistics on that backend.** Routing/NAT, Flow Offloading, and proxy features can also affect statistics; choose according to your environment.

**About Hard Drive Information:**

When the OpenWrt system or remote host (PVE) does not have lsblk installed, the hard drive capacity information may be inconsistent with the actual capacity.

When the OpenWrt system or remote host (PVE) does not have smartctl installed, information such as hard drive temperature, uptime, and health status will not be available.

**Regarding Bug Submissions:**

When submitting a bug, please provide the following information if possible:

- Device information and plugin version number.
- Prompt information after executing `/usr/share/wechatpush/wechatpush`.
- Log information and file information in the `/tmp/wechatpush/` directory after encountering an error.
- Detailed execution information of `bash -x /usr/share/wechatpush/wechatpush t1`.

## Development verification

Run as root on Linux with network and mount namespace capabilities:

```sh
bash tests/firewall-whitelist.sh
```

To verify the legacy frontends, run the following with the corresponding tools installed:

```sh
IPTABLES=iptables-legacy IP6TABLES=ip6tables-legacy bash tests/firewall-whitelist.sh
```

Dependencies: Bash, Python 3, nftables, iptables/ip6tables, ipset, jq, conntrack, iproute2, util-linux, and standard commands including awk. The suite uses real IPv4/IPv6 TCP, UDP, and ICMP traffic in isolated namespaces to cover revocation, legacy-set upgrades, independent grant preservation, port chunking, port forwards, and foreign-rule preservation without changing host firewall rules. The reload scenario executes a real nft transaction using the generated include, not the fw4 command; it does not replace real OpenWrt procd/fw4 or hardware flow-offload verification.

## DownLoad

| Supported OpenWrt Versions | Download Link |
| :-------- | :----- |
| openwrt-19.07.0 ... latest | [![Lastest Release](https://img.shields.io/github/release/tty228/luci-app-wechatpush.svg?style=flat)](https://github.com/tty228/luci-app-wechatpush/releases)
| openwrt-18.06 | [![Release v2.06.2](https://img.shields.io/badge/release-v2.06.2-lightgrey.svg)](https://github.com/tty228/luci-app-wechatpush/releases/tag/v2.06.2)

## Donate

If you feel that this project is helpful to you, please donate to us so that the project can continue to develop and be more perfect.

![image](https://github.com/tty228/luci-app-wechatpush/blob/master/.github/others/20260303202537_34_664.png)