#!/system/bin/sh
# device_dns_fix.sh - 修复设备 DNS（2026-09-12）
# 背景：本环境把设备所有域名解析劫持到 3.3.3.3，导致微信/IM 等「自有协议不走 HTTP 代理」
#       的应用完全无法联网（表现为微信登录「网络繁忙」）。
# 做法：用 root 经 netd 给当前默认网络指定真实 DNS。
set -e
NET=$(dumpsys connectivity 2>/dev/null | grep -m1 'Active default network' | sed 's/.*network: //' | tr -d ' \r')
if [ -z "$NET" ]; then NET=101; fi
echo "netid=$NET"
ndc resolver setnetdns "$NET" '' 223.5.5.5 1.1.1.1
echo "--- getnetdns ---"
ndc resolver getnetdns "$NET"
echo "--- ping IP (无 DNS) ---"
ping -c 1 -W 3 223.5.5.5 | tail -2
echo "--- ping 域名 (走 DNS) ---"
ping -c 1 -W 3 www.baidu.com | head -2
