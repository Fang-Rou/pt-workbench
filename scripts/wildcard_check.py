# -*- coding: utf-8 -*-
"""泛解析(wildcard DNS)体检 —— **可参数化**版（2026-09-22 重写）。

为什么重写：旧版把目标**硬编码**在源码里（只会跑 wanfangdata.com.cn），
传任何参数都被静默忽略、**输出看起来却很正常** ⇒ 典型「假绿灯」。
而 check_lessons_wired.py 只校验文件里含「泛解析」两字，所以接线检查一路 PASS。
（元教训：审计口径必须与查找口径一致，否则指标绿着骗你。）

用法（在 _PT工作台 目录执行）：
    $py scripts/wildcard_check.py --zone sunmi.com
    $py scripts/wildcard_check.py --zone a.com --zone b.com
    $py scripts/wildcard_check.py --hosts state/xxx-hosts.txt      # 自动按 registrable 归并
    $py scripts/wildcard_check.py --zone sunmi.com --json out.json

退出码：0 = 无泛解析；2 = 发现泛解析（供脚本消费）；1 = 用法错误。

判定逻辑与 recon_triage.wildcard_ips 同源（随机名解析出 IP ⇒ 该 zone 泛解析）。
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import string
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
socket.setdefaulttimeout(6)

# 常见多段公共后缀（够用即可；不做完整 PSL 解析）
MULTI_TLD = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "com.hk", "com.tw"}


def rand_label(n: int = 16) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def resolvable(host: str) -> list:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def guessed_zone(host: str) -> str:
    """从主机名猜 registrable zone（hosts 模式用）。"""
    parts = host.strip().lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    last2 = ".".join(parts[-2:])
    if last2 in MULTI_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def check_zone(zone: str, tries: int = 3) -> dict:
    """返回 {zone, wildcard, phantom_ips, samples}。随机名解析出 IP ⇒ 泛解析。"""
    phantom, samples = set(), []
    for _ in range(tries):
        h = rand_label() + "." + zone
        ips = resolvable(h)
        if ips:
            phantom.update(ips)
            samples.append(ips[:2])
    return {"zone": zone, "wildcard": bool(phantom),
            "phantom_ips": sorted(phantom), "samples": samples}


def main() -> int:
    ap = argparse.ArgumentParser(description="泛解析(wildcard DNS)体检（参数化版）")
    ap.add_argument("--zone", action="append", default=[], help="要检查的域，可多次")
    ap.add_argument("--hosts", default="", help="主机清单文件（每行一个），自动归并到 zone")
    ap.add_argument("--tries", type=int, default=3, help="每个 zone 试几个随机名（默认 3）")
    ap.add_argument("--json", default="", help="落盘 JSON")
    a = ap.parse_args()

    zones = list(a.zone)
    if a.hosts:
        p = Path(a.hosts)
        if not p.exists():
            print("[FAIL] --hosts 文件不存在: %s" % p)
            return 1
        hosts = [x.strip() for x in p.read_text(encoding="utf-8").split() if x.strip()]
        seen = {guessed_zone(h) for h in hosts}
        zones += sorted(seen)
        print("# 从 %s 归并出 %d 个 zone（%d 个主机）" % (p.name, len(seen), len(hosts)))

    if not zones:
        print("[FAIL] 必须给 --zone 或 --hosts（旧版就是没有这个参数，才会只跑硬编码目标）")
        return 1

    zones = sorted(set(z.lower() for z in zones))
    print("%-46s %-8s %s" % ("域", "泛解析", "随机名解析结果"))
    results, wild = [], []
    for z in zones:
        r = check_zone(z, a.tries)
        results.append(r)
        if r["wildcard"]:
            wild.append(z)
            print("%-46s %-8s %s" % (z, "YES", r["phantom_ips"][:3]))
        else:
            print("%-46s %-8s -" % (z, "no"))

    print("")
    if wild:
        print("⚠ 泛解析域 %d 个: %s" % (len(wild), ", ".join(wild)))
        print("   ⇒ 这些域下的『存活』子域名**不可信**（随机名也解析），必须先剔幻影再统计")
    else:
        print("无泛解析（全部 %d 个 zone 的随机名均不解析）" % len(zones))

    if a.json:
        p = Path(a.json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"zones": results, "wildcard_zones": wild},
                                ensure_ascii=False, indent=1), encoding="utf-8")
        print("OUT -> %s" % p)
    return 2 if wild else 0


if __name__ == "__main__":
    sys.exit(main())
