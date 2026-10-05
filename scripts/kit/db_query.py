# -*- coding: utf-8 -*-
"""kit/db_query.py — 参数化查 workspace.db。别再为查库写临时脚本。

为什么（2026-09-19）：一场会话里为「查 DB」写了两遍临时脚本，每次都经过 TS 字符串转义。

用法（在 _PT工作台 目录执行）：
    $py scripts/kit/db_query.py --tables
    $py scripts/kit/db_query.py --sql "SELECT severity,status,title FROM findings LIMIT 10"
    $py scripts/kit/db_query.py --sql "..." --json --out results/q.json
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DB = ROOT / "state" / "workspace.db"


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="查 workspace.db")
    ap.add_argument("--sql", default="")
    ap.add_argument("--db", default=str(DB))
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--tables", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default="")
    ap.add_argument("--exec", dest="exec_sql", default="",
                    help="执行写语句（UPDATE/DELETE/INSERT），需同时给 --apply")
    ap.add_argument("--apply", action="store_true", help="确认执行 --exec")
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.row_factory = sqlite3.Row
    if a.tables:
        for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            n = con.execute("SELECT COUNT(*) FROM " + r[0]).fetchone()[0]
            print("%-24s %d" % (r[0], n))
        return 0
    if a.exec_sql:
        if not a.apply:
            print("[dry-run] 将执行: %s" % a.exec_sql)
            print("         确认后加 --apply（改前请先 --backup 备份）")
            return 0
        cur = con.execute(a.exec_sql)
        con.commit()
        print("已执行, 影响 %d 行" % cur.rowcount)
        return 0
    if not a.sql:
        print("需要 --sql 或 --tables")
        return 2
    cur = con.execute(a.sql)
    rows = [dict(r) for r in cur.fetchmany(a.limit)]
    if a.json:
        s = json.dumps(rows, ensure_ascii=False, indent=1, default=str)
    else:
        if not rows:
            print("(0 行)")
            return 0
        cols = list(rows[0].keys())
        print(" | ".join(cols))
        print("-" * 60)
        for r in rows:
            print(" | ".join(str(r[c])[:44] for c in cols))
        s = ""
    print("\n(%d 行)" % len(rows))
    if a.out:
        p = Path(a.out)
        if not p.is_absolute():
            p = ROOT / p
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(a.sql + "\n\n" + (s or json.dumps(rows, ensure_ascii=False, indent=1, default=str)),
                     encoding="utf-8")
        print("OUT -> %s" % p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
