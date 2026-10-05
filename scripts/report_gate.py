#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report_gate.py — 交付前「唯一闸门」：一次跑完全部前置检查，只出一个 VERDICT。

为什么（沿用 2026-09-19 的教训）：提交前要分别记 4-7 个命令 = 必然漏跑。
「知识早就有，却没有一步会拦住交付」是历史上返工的根因。
本闸门**不重写任何规则** —— 它编排已有闸门，让「只跑一个命令」成为默认。

编排的现有闸门（各自仍可单独使用）：
  check_delivery_consistency.py   交付包结构：清单引用 ↔ 包内文件一致；证据四件套完整
  report_format_gate.py           报告形态：客户交付骨架 / 去 AI 味 / 图文配对
  report_evidence_gate.py         证据形式：截图与步骤关联、理论风险措辞
  + 本项目独有：范围一致性（报告里的主机 vs engagement.scope）

用法（在 _PT工作台 目录执行）：
  $py scripts/report_gate.py --deliver "_交付/<slug>"
  $py scripts/report_gate.py --deliver "_交付/<slug>" --slug <engagement> [--report <路径>]

  --skip <步骤名>   跳过某步（应急，汇总里标 SKIP）
退出码 0=PASS 1=FAIL。汇总落 results/report-gate-<时间戳>.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
WS = ROOT.parent
RESULTS = ROOT / "results"
ENG_DIR = ROOT / "state" / "engagements"
ACTIVE = ROOT / "state" / "active-engagement.txt"

STEP_NAMES = ("交付包结构", "报告形态(客户骨架)", "证据形式", "范围一致性")


def pick_report(deliver: Path, explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        if not p.is_absolute():
            p = (WS / p) if (WS / p).exists() else (ROOT / p)
        return p if p.exists() else None
    mds = [p for p in deliver.glob("*.md")
           if not p.name.lower().startswith(("readme", "整改", "复现"))]
    if not mds:
        mds = [p for p in deliver.rglob("*.md")
               if not p.name.lower().startswith(("readme", "整改", "复现"))]
    return max(mds, key=lambda p: p.stat().st_size) if mds else None


def run(name: str, argv: list[str]) -> tuple[str, str]:
    """跑一个子闸门，返回 (VERDICT, 摘要)。"""
    try:
        r = subprocess.run([sys.executable] + argv, capture_output=True, timeout=300)
        out = (r.stdout or b"").decode("utf-8", "ignore") + (r.stderr or b"").decode("utf-8", "ignore")
    except Exception as exc:
        return "ERROR", "执行失败: %s" % str(exc)[:70]
    v = "FAIL"
    if "VERDICT=PASS" in out or "VERDICT: PASS" in out:
        v = "PASS"
    elif "VERDICT=FAIL" in out or "VERDICT: FAIL" in out:
        v = "FAIL"
    elif r.returncode == 0:
        v = "PASS"
    tail = [l for l in out.strip().splitlines() if l.strip()][-1:] or [""]
    detail = ""
    for l in out.splitlines():
        if l.startswith("VERDICT"):
            detail = l.strip()
            break
    return v, detail or tail[0][:110]


def load_engagement(slug: str | None) -> tuple[str, dict]:
    if not ENG_DIR.exists():
        return "", {}
    if slug:
        p = ENG_DIR / (slug if slug.endswith(".json") else slug + ".json")
        if p.exists():
            try:
                return p.stem, json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return "", {}
        return "", {}
    if ACTIVE.exists():
        s = ACTIVE.read_text(encoding="utf-8").strip()
        p = ENG_DIR / (s if s.endswith(".json") else s + ".json")
        if p.exists():
            try:
                return p.stem, json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return "", {}


HOST_RX = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})\b", re.I)
BENIGN_SUFFIX = (".png", ".jpg", ".md", ".json", ".py", ".sh", ".txt", ".csv")


def scope_consistency(report: Path, slug: str | None) -> tuple[str, str, list[str]]:
    """报告里出现的主机 vs 项目登记的 scope。返回 (verdict, 摘要, 越界清单)。"""
    name, eng = load_engagement(slug)
    if not eng:
        return "WARN", "没有 active 项目（--slug 指定 / engagement.py use 切换）⇒ 无法比对范围", []
    sc = eng.get("scope") or {}
    pats = [str(x) for x in (sc.get("hosts") or []) + sc.get("domains") or []]
    cidrs = [str(x) for x in (sc.get("cidrs") or [])]

    txt = report.read_text("utf-8", "ignore")
    seen = set()
    for m in HOST_RX.finditer(txt):
        h = m.group(1).lower()
        if h.endswith(BENIGN_SUFFIX) or h.endswith(".com.cn.example"):
            continue
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", h):
            if h.startswith(("127.", "0.0.0.0", "255.")):
                continue
            if not cidrs:
                seen.add(h)
                continue
            import ipaddress
            try:
                ip = ipaddress.ip_address(h)
            except ValueError:
                continue
            if not any(_in_net(ip, c) for c in cidrs):
                seen.add(h)
            continue
        if not pats:
            seen.add(h)
            continue
        if not any(h == p.lstrip("*.").lower() or h.endswith("." + p.lstrip("*.").lower())
                   for p in pats):
            seen.add(h)

    outside = sorted(seen)
    if outside:
        v = "FAIL" if eng.get("strict_scope") else "WARN"
        return v, "%s：报告里出现 %d 个 scope 表外主机（strict_scope=%s）" % (
            name, len(outside), bool(eng.get("strict_scope"))), outside
    return "PASS", "%s：报告里的主机与 scope 表一致" % name, []


def _in_net(ip, cidr: str) -> bool:
    import ipaddress
    try:
        return ip in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="交付前唯一闸门")
    ap.add_argument("--deliver", required=True, help='如 "_交付/<slug>"（相对工作区根）')
    ap.add_argument("--report", default=None)
    ap.add_argument("--slug", default=None, help="项目 slug（默认取 active）")
    ap.add_argument("--skip", action="append", default=[], help="跳过某步（可重复）")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    deliver = Path(a.deliver)
    if not deliver.is_absolute():
        deliver = (WS / deliver) if (WS / deliver).exists() else (ROOT / deliver)
    if not deliver.exists():
        print("FAIL: 交付目录不存在 %s" % deliver)
        return 1

    report = pick_report(deliver, a.report)
    steps: list[dict] = []

    def add(name: str, verdict: str, detail: str, extra=None):
        steps.append({"step": name, "verdict": verdict, "detail": detail, "extra": extra})

    # ① 交付包结构
    if "交付包结构" in a.skip:
        add("交付包结构", "SKIP", "--skip")
    else:
        v, d = run("交付包结构", [str(SCRIPTS / "check_delivery_consistency.py"), str(deliver)])
        add("交付包结构", v, d)

    # ②③ 报告级闸门
    if not report:
        add("报告形态(客户骨架)", "FAIL", "交付包里没找到报告 .md")
        add("证据形式", "SKIP", "无报告")
    else:
        if "报告形态(客户骨架)" in a.skip:
            add("报告形态(客户骨架)", "SKIP", "--skip")
        else:
            v, d = run("报告形态", [str(SCRIPTS / "report_format_gate.py"), str(report)])
            add("报告形态(客户骨架)", v, d)
        if "证据形式" in a.skip:
            add("证据形式", "SKIP", "--skip")
        else:
            v, d = run("证据形式", [str(SCRIPTS / "report_evidence_gate.py"), str(report)])
            add("证据形式", v, d)

    # ④ 范围一致性
    if "范围一致性" in a.skip:
        add("范围一致性", "SKIP", "--skip")
    elif report:
        v, d, outside = scope_consistency(report, a.slug)
        add("范围一致性", v, d, outside)
    else:
        add("范围一致性", "SKIP", "无报告")

    # ⑤ 整改表 / 发现清单（缺只 WARN —— 小项目可能不需要）
    tracker = list(deliver.glob("整改跟踪表*.md"))
    listing = list(deliver.glob("*发现清单*.csv")) + list(deliver.glob("findings*.csv"))
    notes = []
    if not tracker:
        notes.append("缺 整改跟踪表.md（remediation_tracker.py --init 生成）")
    if not listing:
        notes.append("缺 发现清单 CSV（findings_export.py 生成）")

    verdict = "PASS"
    if any(s["verdict"] == "FAIL" for s in steps):
        verdict = "FAIL"
    if any(s["verdict"] == "WARN" for s in steps) and verdict == "PASS":
        verdict = "WARN"

    payload = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "deliver": str(deliver), "report": str(report) if report else None,
        "engagement": (load_engagement(a.slug)[0] or None),
        "steps": steps, "notes": notes, "verdict": verdict,
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / ("report-gate-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    if a.json:
        print(json.dumps(payload, ensure_ascii=False, indent=1))
    else:
        print("=" * 78)
        print("交付闸门: %s" % deliver)
        print("报告    : %s" % (report.name if report else "(未找到)"))
        print("项目    : %s" % (payload["engagement"] or "(无 active 项目)"))
        print("-" * 78)
        for s in steps:
            print("  [%-4s] %-20s %s" % (s["verdict"], s["step"], s["detail"]))
            if s.get("extra"):
                ex = s["extra"]
                print("         scope 外主机（前 10）: %s%s" % (
                    ", ".join(ex[:10]), " ..." if len(ex) > 10 else ""))
        for n in notes:
            print("  [WARN] %s" % n)
        print("-" * 78)
        print("VERDICT=%s" % verdict)
        print("汇总: %s" % out)
    return 0 if verdict in ("PASS", "WARN") else 1


if __name__ == "__main__":
    sys.exit(main())
