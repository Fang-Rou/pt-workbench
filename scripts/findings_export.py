#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""findings_export.py — 从 workspace.db 导出发现清单（给客户的 CSV / Markdown）。

改造说明（2026-10-01）：原工作流把发现导去填平台表单；渗透测试里发现清单是**交付物**，
客户会拿它当整改依据，所以导出要含：位置 / 等级 / 描述 / 证据路径 / 修复建议占位。

用法：
  $py scripts/findings_export.py                          # 全部项目
  $py scripts/findings_export.py --slug acme-20261001     # 单个项目
  $py scripts/findings_export.py --slug acme-20261001 --out "_交付/acme-20261001"
  $py scripts/findings_export.py --slug acme-20261001 --json
"""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT.parent
DB = ROOT / "state" / "workspace.db"

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}

SQL = """
SELECT p.slug AS project, p.name AS project_name,
       t.slug AS target, t.name AS target_name, t.host AS host,
       f.id AS fid, f.title, f.severity, f.category, f.url, f.method, f.params,
       f.description, f.poc_path, f.status, f.created_at
FROM findings f
JOIN targets t ON t.id = f.target_id
JOIN projects p ON p.id = t.project_id
{where}
ORDER BY f.id
"""


def fetch(slug: str | None) -> list[dict]:
    con = sqlite3.connect(str(DB))
    con.row_factory = sqlite3.Row
    where, args = "", ()
    if slug:
        where, args = "WHERE p.slug = ?", (slug,)
    rows = [dict(r) for r in con.execute(SQL.format(where=where), args)]
    con.close()
    rows.sort(key=lambda r: (SEV_ORDER.get((r.get("severity") or "info").lower(), 9), r["fid"]))
    return rows


def to_markdown(rows: list[dict], title: str) -> str:
    out = ["# %s" % title, "",
           "> 由 `scripts/findings_export.py` 生成于 %s" % datetime.now().strftime("%Y-%m-%d %H:%M"),
           "> 等级口径见 `skills/pt-engagement/references/risk-rating-and-remediation.md`", ""]
    if not rows:
        out.append("（无记录）")
        return "\n".join(out) + "\n"
    out += ["| 编号 | 名称 | 等级 | 位置 | 状态 | 证据 |",
            "| --- | --- | --- | --- | --- | --- |"]
    for i, r in enumerate(rows, 1):
        sev = SEV_CN.get((r.get("severity") or "info").lower(), r.get("severity") or "-")
        out.append("| F-%02d | %s | %s | `%s` | %s | %s |" % (
            i, str(r.get("title") or "")[:60].replace("|", "/"), sev,
            str(r.get("url") or r.get("host") or "-")[:70], r.get("status") or "-",
            str(r.get("poc_path") or "-")[:50]))
    return "\n".join(out) + "\n"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="导出发现清单")
    ap.add_argument("--slug", default=None, help="项目 slug（默认全部）")
    ap.add_argument("--out", default=None, help='输出目录（如 "_交付/<slug>"）；不给自己挑一个')
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if not DB.exists():
        print("FAIL: workspace.db 不存在 %s" % DB)
        return 1
    rows = fetch(a.slug)

    if a.json:
        print(json.dumps(rows, ensure_ascii=False, indent=1))
        return 0

    tag = a.slug or "all"
    outdir = Path(a.out) if a.out else None
    if outdir and not outdir.is_absolute():
        outdir = (WS / outdir) if (WS / outdir).exists() else (ROOT / outdir)
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
    else:
        outdir = ROOT / "results" / ("findings-%s" % tag)
        outdir.mkdir(parents=True, exist_ok=True)

    csv_p = outdir / ("发现清单-%s.csv" % tag)
    md_p = outdir / ("发现清单-%s.md" % tag)

    with csv_p.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["编号", "项目", "目标", "主机", "名称", "等级", "类型", "位置", "方法",
                    "参数", "描述", "证据路径", "状态", "发现时间"])
        for i, r in enumerate(rows, 1):
            w.writerow(["F-%02d" % i, r.get("project"), r.get("target_name") or r.get("target"),
                        r.get("host"), r.get("title"),
                        SEV_CN.get((r.get("severity") or "info").lower(), r.get("severity")),
                        r.get("category"), r.get("url"), r.get("method"), r.get("params"),
                        (r.get("description") or "")[:500], r.get("poc_path"),
                        r.get("status"), r.get("created_at")])
    md_p.write_text(to_markdown(rows, "发现清单 — %s" % tag), encoding="utf-8")

    print("发现 %d 条" % len(rows))
    by = {}
    for r in rows:
        k = SEV_CN.get((r.get("severity") or "info").lower(), r.get("severity") or "-")
        by[k] = by.get(k, 0) + 1
    print("等级分布: %s" % ("，".join("%s %d" % (k, v) for k, v in
                                  sorted(by.items(), key=lambda x: list(SEV_CN.values()).index(x[0])
                                         if x[0] in SEV_CN.values() else 9)) or "无"))
    print("CSV : %s" % csv_p)
    print("MD  : %s" % md_p)
    print("[done] FINDINGS-EXPORT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
