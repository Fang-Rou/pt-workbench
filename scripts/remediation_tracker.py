#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""remediation_tracker.py — 整改跟踪表：交付后客户修没修、复测过没，都落盘。

为什么需要它：渗透测试的价值有一半在**交付后**——客户返修、我们复测、第二轮报告。
没有跟踪表，这些状态只活在邮件和记忆里。口径见
`skills/pt-engagement/references/risk-rating-and-remediation.md`。

状态口径（写死在脚本里，防口径漂移）：
  未修复 / 修复中 / 待验证 / 已修复 / 接受风险
  · `已修复` 只能由**我方复测**写入，且必须附复测证据路径
  · `接受风险` 必须由客户方书面确认（记录确认人与日期）

用法：
  $py scripts/remediation_tracker.py --slug acme-20261001 --init
  $py scripts/remediation_tracker.py --slug acme-20261001                 # 打印
  $py scripts/remediation_tracker.py --slug acme-20261001 --set F-01 \\
        --status 已修复 --note "客户端已加归属校验" --retest-evidence "原始记录/f01-retest.txt"
  $py scripts/remediation_tracker.py --slug acme-20261001 --render        # 重写 md
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT.parent
DB = ROOT / "state" / "workspace.db"
STATE = ROOT / "state" / "remediation"

STATUSES = ("未修复", "修复中", "待验证", "已修复", "接受风险")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}


def _state_file(slug: str) -> Path:
    return STATE / ("%s.json" % slug)


def load_state(slug: str) -> dict:
    f = _state_file(slug)
    if f.exists():
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"slug": slug, "created": datetime.now().isoformat(timespec="seconds"), "items": []}


def save_state(d: dict) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    d["updated"] = datetime.now().isoformat(timespec="seconds")
    _state_file(d["slug"]).write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def db_findings(slug: str) -> list[dict]:
    if not DB.exists():
        return []
    con = sqlite3.connect(str(DB))
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("""
        SELECT f.id, f.title, f.severity, f.category, f.url, f.poc_path, f.status
        FROM findings f JOIN targets t ON t.id = f.target_id
        JOIN projects p ON p.id = t.project_id
        WHERE p.slug = ? ORDER BY f.id""", (slug,))]
    con.close()
    rows.sort(key=lambda r: SEV_ORDER.get((r.get("severity") or "info").lower(), 9))
    return rows


def cmd_init(slug: str, deliver: Path | None, force: bool) -> int:
    d = load_state(slug)
    if d["items"] and not force:
        print("已有 %d 条（要按 DB 重建加 --force）-> %s" % (len(d["items"]), _state_file(slug)))
        return 1
    rows = db_findings(slug)
    if not rows:
        print("WARN: workspace.db 里没有 %s 的 findings；仍会建空表，可手工补条目" % slug)
    items = []
    for i, r in enumerate(rows, 1):
        items.append({
            "id": "F-%02d" % i, "finding_db_id": r["id"],
            "title": r.get("title") or "", "severity": SEV_CN.get((r.get("severity") or "info").lower(),
                                                                  r.get("severity") or "信息"),
            "location": r.get("url") or "",
            "advice": "（见报告对应章节）",
            "owner": "", "status": "未修复", "due": "",
            "verify": "复现报告中的原始请求，确认不再返回敏感数据/不再可越权",
            "retest": "",
        })
    d["items"] = items
    save_state(d)
    print("已建整改跟踪表: %d 条 -> %s" % (len(items), _state_file(slug)))
    out = render(slug, deliver)
    if out:
        print("已渲染: %s" % out)
    return 0


def cmd_set(slug: str, item_id: str, **kw) -> int:
    d = load_state(slug)
    got = next((x for x in d["items"] if x["id"].lower() == item_id.lower()), None)
    if got is None:
        print("UNSURE: 没有条目 %s（现有：%s）" % (item_id, ", ".join(x["id"] for x in d["items"]) or "空"))
        return 2
    if kw.get("status"):
        if kw["status"] not in STATUSES:
            print("UNSURE: status 只能是 %s" % (STATUSES,))
            return 2
        if kw["status"] == "已修复" and not (kw.get("evidence") or got.get("retest")):
            print("FAIL: 「已修复」必须由我方复测写入，并附 --evidence <复测证据路径>")
            return 1
        got["status"] = kw["status"]
    for k in ("owner", "due", "advice", "verify", "title", "severity"):
        if kw.get(k):
            got[k] = kw[k]
    if kw.get("evidence"):
        prev = got.get("retest") or ""
        line = "%s 复测通过 -> %s%s" % (datetime.now().strftime("%Y-%m-%d"), kw["evidence"],
                                       ("；" + kw["note"]) if kw.get("note") else "")
        got["retest"] = (prev + " | " + line) if prev else line
        if kw.get("status") == "待验证":
            got["status"] = "已修复"
    elif kw.get("note"):
        got["note"] = kw["note"]
    save_state(d)
    print("%s [%s] %s" % (got["id"], got["status"], str(got.get("title"))[:50]))
    return 0


def render(slug: str, deliver: Path | None) -> Path | None:
    d = load_state(slug)
    if not d["items"]:
        return None
    lines = ["# 整改跟踪表 — %s" % slug, "",
             "> 由 `scripts/remediation_tracker.py` 维护，更新于 %s" % d.get("updated", "-"),
             "> 状态口径：未修复 / 修复中 / 待验证 / 已修复 / 接受风险；",
             "> **「已修复」只能由我方复测写入**；「接受风险」需客户书面确认（记录确认人+日期）。", "",
             "| 编号 | 名称 | 等级 | 位置 | 修复建议 | 责任方 | 状态 | 期望完成 | 验证方法 | 复测结果 |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for x in d["items"]:
        lines.append("| %s | %s | %s | `%s` | %s | %s | %s | %s | %s | %s |" % (
            x["id"], str(x.get("title"))[:50].replace("|", "/"), x.get("severity", ""),
            str(x.get("location"))[:60], str(x.get("advice", ""))[:40] or "-",
            x.get("owner") or "-", x.get("status", "未修复"), x.get("due") or "-",
            str(x.get("verify", ""))[:50] or "-", str(x.get("retest") or "-")[:60]))
    done = sum(1 for x in d["items"] if x.get("status") in ("已修复", "接受风险"))
    lines += ["", "## 汇总", "",
              "- 共 %d 条；已闭环（已修复/接受风险）%d 条；待处理 %d 条"
              % (len(d["items"]), done, len(d["items"]) - done), ""]
    body = "\n".join(lines) + "\n"

    if deliver:
        deliver.mkdir(parents=True, exist_ok=True)
        p = deliver / "整改跟踪表.md"
    else:
        p = ROOT / "results" / ("整改跟踪表-%s.md" % slug)
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="整改跟踪表")
    ap.add_argument("--slug", required=True)
    ap.add_argument("--init", action="store_true", help="按 workspace.db 的 findings 建表")
    ap.add_argument("--force", action="store_true", help="--init 时覆盖已有条目")
    ap.add_argument("--set", dest="item", default=None, help="条目编号，如 F-01")
    ap.add_argument("--status", default=None)
    ap.add_argument("--owner", default=None)
    ap.add_argument("--due", default=None)
    ap.add_argument("--advice", default=None)
    ap.add_argument("--verify", default=None)
    ap.add_argument("--note", default=None)
    ap.add_argument("--evidence", default=None, help="复测证据路径（写「已修复」必需）")
    ap.add_argument("--deliver", default=None, help='交付目录，如 "_交付/<slug>"')
    ap.add_argument("--render", action="store_true")
    a = ap.parse_args()

    deliver = Path(a.deliver) if a.deliver else None
    if deliver and not deliver.is_absolute():
        deliver = (WS / deliver) if (WS / deliver).exists() else (ROOT / deliver)

    if a.init:
        return cmd_init(a.slug, deliver, a.force)
    if a.item:
        rc = cmd_set(a.slug, a.item, status=a.status, owner=a.owner, due=a.due, advice=a.advice,
                     verify=a.verify, note=a.note, evidence=a.evidence)
        if rc:
            return rc
        out = render(a.slug, deliver)
        if out:
            print("已更新: %s" % out)
        return 0

    d = load_state(a.slug)
    if not d["items"]:
        print("（没有条目；先跑 --init）")
        return 1
    print("%-6s %-8s %-10s %s" % ("编号", "等级", "状态", "名称"))
    print("-" * 90)
    for x in d["items"]:
        print("%-6s %-8s %-10s %s" % (x["id"], x.get("severity", ""), x.get("status", ""),
                                      str(x.get("title"))[:56]))
    if a.render:
        out = render(a.slug, deliver)
        print("")
        print("已渲染: %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
