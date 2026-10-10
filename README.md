## 简介

[![Lastest Release](https://img.shields.io/github/release/tty228/luci-app-wechatpush.svg?style=flat)](https://github.com/tty228/luci-app-wechatpush/releases)
[![GitHub All Releases](https://img.shields.io/github/downloads/tty228/luci-app-wechatpush/total)](https://github.com/tty228/luci-app-wechatpush/releases)

[中文文档](README.md) | [English](README_en.md)

这是一款用于 OpenWRT 路由器上进行 微信、Telegram、邮件 通知的插件。

主要功能：
- [x] 路由 IP、IPv6 变动推送
- [x] 设备 上线、离线 推送
- [x] 设备在线列表及流量使用情况
- [x] CPU 负载、温度监视、PVE 宿主机温度监控
- [x] 路由运行状态定时推送
- [x] 路由 Web、SSH 登录提示，自动拉黑、端口敲门
- [x] 无人值守任务

自动封禁启用后，黑名单默认拦截访问路由器的流量。在 fw4/nftables 环境中，丢弃规则持久化在 `/etc/nftables.d/20-wechatpush-blacklist.nft`。fw4 重载时会保留集合元素，并在同一事务中重新加载丢弃规则，不再出现规则空窗；路由器重启后，插件启动时会从黑名单文件恢复集合元素。可另外开启“阻止黑名单 IP 的转发流量”，拦截经过路由器转发的所有流量（包括访问端口映射的下级设备、局域网客户端访问互联网）。开启转发封禁且已安装 conntrack 时，封禁还会尝试清理该 IP 的连接跟踪记录，以断开已有的流量卸载连接；未安装时跳过该步骤，新连接仍按黑名单规则拦截。关闭该选项或关闭自动封禁后，拦截规则与持久化文件会在下一次检测循环中被移除；停用插件时也会一并清除，停止插件服务（仍启用）不会移除已生效的规则。fw4 定时封禁按最近记录的剩余时长恢复。黑名单时间设置为 `0` 时永久封禁，手动清除黑名单后解除。

配置的登录提醒/自动封禁白名单优先于自动封禁规则：白名单 IP 不受本插件的输入封禁及黑名单转发封禁限制，不依赖端口敲门开关或登录端口配置。黑名单 DROP 规则只匹配“在黑名单且不在配置白名单”的来源地址，已有黑名单记录仍按原期限保留；移除白名单配置并重载插件后，未到期的封禁重新生效。开启转发封禁且已安装 conntrack 时，撤销豁免也会清理相应的连接跟踪记录。该封禁豁免本身不绕过其他独立防火墙规则。

配置白名单与成功登录获得的敲门授权分别管理，配置项增删不会改变独立登录授权的期限（包括释放时间为 `0` 的永久授权）。启用端口敲门时，两种来源分别用于所配置的 TCP 登录端口与端口映射；登录授权不豁免其他端口、协议或黑名单转发封禁。iptables 登录端口列表会按 multiport 容量自动拆分；登录端口为空或无效时，不妨碍独立配置的合法端口映射。

初始化与停用按本插件授权规则的完整结构判定清理归属；仅沿用插件注释不足以将独立规则认定为可清理的规则。

首次升级到独立登录授权集合时，旧版本敲门集合中的配置来源与登录来源无法可靠区分，因此旧敲门授权不迁移，需要重新成功登录以获得新授权；配置白名单照常恢复。后续普通重载保留新的独立授权。若旧集合仍被外部自定义规则引用，会保留该集合供那些规则使用，但本插件不再将其成员作为登录授权。

通知服务支持列表：
| 推送应用 | 方式 | 接口说明 |
| :-------- | :----- | :----- |
| 微信 | Server酱 | https://sct.ftqq.com/
| 微信 | 推送加 | http://www.pushplus.plus/
| 微信等 | WPUSH | https://wpush.cn/
| 微信 | WxPusher | https://wxpusher.zjiecode.com/docs
| 企业微信 | 应用推送 | https://work.weixin.qq.com/api/doc/90000/90135/90248
| Telegram | bot | https://t.me/BotFather
| Mail | msmtp | https://marlam.de/msmtp/

精力有限，如需要钉钉推送、飞书推送、Bark 推送等请尝试另一个分支 https://github.com/zzsj0928/luci-app-pushbot ，或使用自定义 API 设置

v2.06.2 之后的版本不再支持 LuCI 18.06，如需编译，请使用 openwrt-18.06 分支，拉取源码时请使用 `git clone -b openwrt-18.06 https://github.com/tty228/luci-app-wechatpush.git` 命令

## 说明

**关于安装：**

基础运行依赖为 `iputils-arping`、`curl`、`jq`、`bash` 和 `luci-lua-runtime`，安装包会通过包管理器拉取这些依赖。对于内存有限的路由器，请酌情安装。**安装前，使用 opkg 的系统运行 `opkg update`，使用 apk 的系统运行 `apk update`；选择与固件版本、架构及包管理器匹配的 IPK/APK 安装包。**

运行还需要系统提供 `flock`。启用封禁或端口敲门时，fw4 后端需要 `nft`；iptables 后端需要 `iptables`/`ip6tables`、`ipset` 及相应内核模块。`conntrack` 为可选工具，用于前述已有连接清理，不是基础运行依赖。

早期开发基线为 x86 OpenWrt v23.05.0。当前 IPK/APK 自动构建的版本与架构以[构建工作流](.github/workflows/build.yml)为准，构建目标不等同于所有固件和设备都经过运行兼容性验证。不同系统不同设备，可能会遇到各种问题，**如获取到错误的温度信息、页面显示错误、报错等，自行适配**。

**关于主机名：**

对于设备未宣告主机名、光猫拨号上网、OpenWrt 作为旁路网关等各类情况导致的获取主机名失败，可以通过以下方式设置主机名

- 使用设备名备注
- 在高级设置处配置从光猫、小米路由器、ROS 获取
- 开启 MAC 设备数据库
- 安装 samba*-server 或 samba*-client，使程序可以通过 NetBIOS 查询主机名


**关于设备在线状态：**

默认使用 ping/arping 来主动探测设备在线状态，以对抗 Wi-Fi 休眠机制，主动探测较为耗时但可以获得较为精准的设备在线状态

- 如遇设备休眠频繁，请在高级设置处自行调整超时设置
- 如果不需要太过精准的设备在线信息，只需要其余功能，可以在高级设置中关闭主动探测

**关于流量统计信息：**

流量统计依赖 `wrtbwmon`，需在兼容的防火墙环境中自行选装或编译。**wrtbwmon 不兼容 fw4/nftables，单独安装它也不能使该后端的流量统计可用。** Routing/NAT、Flow Offloading、代理上网等功能也可能影响统计结果，请按实际环境选择。

**关于硬盘信息：**

当 OpenWrt 系统或远程主机（PVE）未安装 lsblk 时，硬盘容量信息可能与实际不一致

当 OpenWrt 系统或远程主机（PVE）未安装 smartctl 时，硬盘温度、通电时间、健康度等信息不可用

**关于 bug 提交：**

提交 bug 时请尽量带上以下信息

- 设备信息及插件版本号
- 执行 `/usr/share/wechatpush/wechatpush` 后的提示信息
- 报错后的日志信息、`/tmp/wechatpush/` 目录下的文件信息
- `bash -x /usr/share/wechatpush/wechatpush t1` 的详细运行信息


## 开发验证

在具备网络和挂载命名空间权限的 Linux 环境中，以 root 运行：

```sh
bash tests/firewall-whitelist.sh
```

如需验证 legacy 前端，在已安装相应工具的环境中运行：

```sh
IPTABLES=iptables-legacy IP6TABLES=ip6tables-legacy bash tests/firewall-whitelist.sh
```

依赖 Bash、Python 3、nftables、iptables/ip6tables、ipset、jq、conntrack、iproute2、util-linux，以及 awk 等常用命令。测试在独立命名空间中使用真实 IPv4/IPv6 TCP、UDP、ICMP 流量，覆盖名单撤销、旧集合升级、独立授权保留、端口分片、映射和外部规则保护，不修改宿主防火墙规则。重载场景使用生成的 include 执行真实 nft 事务，并非调用 fw4；它不替代真实 OpenWrt procd/fw4 或硬件流量卸载验收。

## 下载

| 支持的 OpenWrt 版本 | 下载地址 |
| :-------- | :----- |
| openwrt-19.07.0 ... latest | [![Lastest Release](https://img.shields.io/github/release/tty228/luci-app-wechatpush.svg?style=flat)](https://github.com/tty228/luci-app-wechatpush/releases)
| openwrt-18.06 | [![Release v2.06.2](https://img.shields.io/badge/release-v2.06.2-lightgrey.svg)](https://github.com/tty228/luci-app-wechatpush/releases/tag/v2.06.2)


## 捐赠

如果你觉得此项目对你有帮助，请捐助我们，使项目能持续发展和更加完善。

![image](https://github.com/tty228/luci-app-wechatpush/blob/master/.github/others/20260303202537_34_664.png)
