# -*- coding: utf-8 -*-
"""recon_triage.py — 把被动情报(CT/Wayback)产出的资产按「业务角色」分诊，挑出先打的。

输入: results/recon-<domain>-<date>/subdomains.json（recon_api.py all 的产物）
      results/scope-registry-<date>.json（厂商范围注册表；无限制 = 全资产授权）
输出: results/recon-triage-<date>/TRIAGE.md + triage.json

分诊只做「按名字排序 + DNS 存活」两件事，**不下结论、不碰目标**。
凡名字无法归类的，一律进 UNSURE 段交回大脑（不静默丢弃）。
用法: python recon_triage.py [--days 1]
"""
from __future__ import annotations

import json
import random
import re
import socket
import string
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "results"

# 角色 → (优先级, 正则)。顺序即优先级，先匹配先定级。
ROLES: list[tuple[int, str, str]] = [
    (1, "认证/身份", r"^(id|ids|sso|auth|login|cas|passport|ucenter|uc|oauth|account|iam|ad|ldap)\.|"
                     r"\.(id|sso|auth|login|ucenter|oauth|iam)\."),
    (1, "支付/资金", r"^(pay|payment|finance|fund|cash|wallet|settle|billing|order)\."),
    (1, "管理后台", r"^(admin|admins|manage|manager|mgmt|console|boss|backend|bg|houtai|cms|dashboard|"
                     r"dispatchadmin|djeoadmin|aftersaleadmin|vadmin|baoliadmin)\."),
    (2, "API/网关", r"^(api|apis|gateway|gw|open|openapi|service|svc|grpc|rest|ws)\."),
    (2, "运维/CI/制品", r"^(jenkins|gitlab|git|gitea|harbor|nexus|grafana|zabbix|kibana|sentry|prometheus|"
                        r"apollo|rancher|minio|oss|s3|nacos|druid|sonar|jumpserver|vpn|bastion|"
                        r"apmserver|monitor|log|elk)\."),
    (2, "测试/预发", r"^(test|testing|dev|uat|staging|stage|pre|sit|demo|beta|sandbox|qa|gray)\."),
    (3, "办公/协作", r"^(oa|mail|smtp|imap|exchange|autodiscover|wiki|confluence|jira|meeting|hr|ehr|"
                     r"crm|erp|finance-oa)\."),
    (3, "客户端/静态", r"^(www|m|mobile|app|h5|static|cdn|img|image|images|file|files|download|apk|"
                       r"resource|assets)\."),
]


def resolve(host: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def rand_label(n: int = 16) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def wildcard_ips(zone: str) -> set:
    """泛解析探测：随机不存在名也能解析 ⇒ 该 zone 泛解析，返回其解析到的 IP 集合。

    2026-09-18 立。教训：§13.2 早把「泛解析」列为三类假阳性之一，但本工具**从没实现它** ——
    实测 wanfangdata.com.cn 有 4 个泛解析域（globe/edu/rd/test），576 个子域里 96.5% 被报「存活」，
    其中 `git.git.git.gitlab...` 这类 CT 日志里的排列组合名之所以"活着"
    只是因为泛解析让任何名字都解析；`*.test.*` 的泛解析甚至指向内网 10.10.192.57。
    沉淀写进文档≠仪器会照做 —— 这次把文档里的纪律落成代码。
    """
    ips: set = set()
    for _ in range(2):
        ips |= set(resolve(rand_label() + "." + zone))
    return ips


def classify(host: str, apex: str) -> tuple[int, str]:
    rest = host[: -len(apex)].rstrip(".") if host.endswith(apex) else host
    for prio, role, rx in ROLES:
        if re.search(rx, rest + "."):
            return prio, role
    return 9, "UNSURE"


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    days = int(sys.argv[sys.argv.index("--days") + 1]) if "--days" in sys.argv else 3
    cutoff = datetime.now() - timedelta(days=days)

    regs = sorted(R.glob("scope-registry-*.json"))
    reg = json.loads(regs[-1].read_text("utf-8")) if regs else {"vendors": {}}
    unlimited = {k for k, v in reg.get("vendors", {}).items() if v.get("scope") == "无限制"}
    print(f"范围注册表: {regs[-1].name if regs else '(缺)'} / 无限制 {len(unlimited)} 家")

    dirs = []
    for d in sorted(R.glob("recon-*-20*")):
        if not d.is_dir():
            continue
        f = d / "subdomains.json"
        if f.exists() and datetime.fromtimestamp(f.stat().st_mtime) >= cutoff:
            dirs.append(d)

    socket.setdefaulttimeout(4)
    buckets: dict[tuple[int, str], list[dict]] = defaultdict(list)
    per_vendor = {}
    for d in dirs:
        data = json.loads((d / "subdomains.json").read_text("utf-8"))
        apex = data["domain"]
        hosts = [h["host"] for h in data.get("hosts", [])]
        with ThreadPoolExecutor(max_workers=24) as ex:
            ips = dict(zip(hosts, ex.map(resolve, hosts)))
        scope = "无限制" if any(apex.endswith(u) or u.endswith(apex) for u in unlimited) else "未核验"
        # 泛解析体检：按"父 zone"归组，只对成员 >= 3 的 zone 做随机名探测（控制 DNS 次数）
        zones: dict = defaultdict(list)
        for h in hosts:
            if "." in h:
                zones[h.split(".", 1)[1]].append(h)
        wc: dict = {}
        for z, members in sorted(zones.items(), key=lambda x: -len(x[1]))[:20]:
            if len(members) >= 3:
                wc[z] = wildcard_ips(z)
        wc_zones = sorted(z for z, s in wc.items() if s)

        # 泛解析是**继承**的：`*.globe.wanfangdata.com.cn` 泛解析会让 `a.b.c.globe...` 也解析，
        # 所以不能只比对直接父 zone（deep 排列名会漏网）—— 对照所有泛解析 IP 的并集。
        wc_all: set = set()
        for _s in wc.values():
            wc_all |= _s

        def _wc(h: str, ip_list: list) -> bool:
            return bool(ip_list) and set(ip_list) <= wc_all

        live_raw = [h for h in hosts if ips[h]]
        live = [h for h in live_raw if not _wc(h, ips[h])]   # 去掉泛解析造成的假存活
        per_vendor[apex] = {"total": len(hosts), "live": len(live), "live_raw": len(live_raw),
                            "wildcard_zones": wc_zones, "scope": scope}
        for h in hosts:
            prio, role = classify(h, apex)
            buckets[(prio, role)].append({"host": h, "apex": apex, "ips": ips[h],
                                          "live": bool(ips[h]) and not _wc(h, ips[h]),
                                          "wc": _wc(h, ips[h]), "scope": scope})
        wenote = ("  ⚠泛解析: " + "/".join(z.split(".")[0] for z in wc_zones)) if wc_zones else ""
        print(f"  {apex:26s} {scope:6s} 子域={len(hosts):>3} 存活={len(live):>3}"
              f" (去泛解析; 原始 {len(live_raw):>3}){wenote}")

    outdir = R / ("recon-triage-" + datetime.now().strftime("%Y-%m-%d"))
    outdir.mkdir(parents=True, exist_ok=True)
    lines = [f"# 被动情报资产分诊 · {datetime.now():%Y-%m-%d %H:%M}", "",
             f"> 源: {len(dirs)} 个 recon 目录（近 {days} 天）｜范围: 无限制厂商=全资产授权",
             "> 本表只做「按业务角色排序 + DNS 存活标注」，不含任何目标请求结论。", ""]
    any_wc = {k: v["wildcard_zones"] for k, v in per_vendor.items() if v.get("wildcard_zones")}
    if any_wc:
        lines += ["## ⚠ 泛解析告警（存活列已剔除泛解析假阳性）", "",
                  "> 随机不存在名也能解析 ⇒ 该 zone 泛解析，落到泛解析 IP 上的主机名**不算真实资产**。",
                  "> 依据：§13.2 三类假阳性之「泛解析」。", ""]
        for k, zs in sorted(any_wc.items()):
            lines.append(f"- `{k}`：{len(zs)} 个泛解析 zone — " + ", ".join(f"`{z}`" for z in zs[:6]))
        lines.append("")
    lines += ["## 厂商概览", "", "| 厂商域 | 范围 | 子域 | 存活(去泛解析) | 原始存活 | 泛解析 zone |",
              "| --- | --- | ---: | ---: | ---: | ---: |"]
    for k, v in sorted(per_vendor.items(), key=lambda x: -x[1]["live"]):
        lines.append(f"| {k} | {v['scope']} | {v['total']} | **{v['live']}** | {v.get('live_raw', '-')} "
                     f"| {len(v.get('wildcard_zones', []))} |")
    lines.append("")

    for (prio, role) in sorted(buckets):
        rows = sorted(buckets[(prio, role)], key=lambda r: (not r["live"], r["host"]))
        title = f"P{prio} · {role}" if prio < 9 else "UNSURE · 名字无法归类（交回大脑）"
        lines += [f"## {title}（{len(rows)} 条，存活 {sum(1 for r in rows if r['live'])}）", ""]
        for r in rows:
            # WC? = 解析到泛解析 IP，**不能当成真实资产**（泛解析下任何名字都"活着"）
            mark = "WC?" if r.get("wc") else ("LIVE" if r["live"] else "dead")
            if prio == 9 and not r["live"] and not r.get("wc"):
                continue
            lines.append(f"- `{r['host']}` — {mark} {','.join(r['ips'][:2])} ({r['apex']}, {r['scope']})")
        lines.append("")

    # 2026-09-17 加：信号 → 手册自动路由（沉淀「会自己触发」，不靠人记得去查）
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from playbook_hint import hints_for
        sig_text = "\n".join(sorted({r["host"] for rows_ in buckets.values() for r in rows_}
                                     | {role for (_p, role) in buckets}))
        hint_lines = hints_for(sig_text)
        if hint_lines:
            lines += ["## 该读的手册（信号自动路由）", "",
                      "> 由 playbook_hint.py 依据上面的主机名/角色生成 —— 动手前按序读，读完回填 lookup --outcome。", ""]
            lines += ["```"] + hint_lines + ["```", ""]
            print("\n[playbook_hint] 命中信号面，已写入 TRIAGE.md：")
            for h in hint_lines:
                if h.startswith("[信号]"):
                    print("   " + h)
    except Exception as e:
        print("[playbook_hint] 跳过: %s" % str(e)[:80])

    (outdir / "TRIAGE.md").write_text("\n".join(lines), "utf-8")
    (outdir / "triage.json").write_text(json.dumps(
        {"generated_at": datetime.now().isoformat(), "vendors": per_vendor,
         "buckets": {f"P{p}-{r}": v for (p, r), v in buckets.items()}},
        ensure_ascii=False, indent=1), "utf-8")
    print(f"\n落盘: {outdir.relative_to(ROOT)}/TRIAGE.md")
    for (p, r) in sorted(buckets):
        n = len(buckets[(p, r)]); lv = sum(1 for x in buckets[(p, r)] if x["live"])
        print(f"  P{p} {r:12s} {n:>4} 条 (存活 {lv})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
