# -*- coding: utf-8 -*-
"""kit/db_vocab.py — 字段值域体检 + 安全备份。

为什么（2026-09-19）：platform 字段里混着 butian 与 补天，任何 WHERE platform=?butian?
都会**静默漏掉 23 条**。这类脏数据不报错、只悄悄少结果 —— 比崩溃更危险。

用法（在 _PT工作台 目录执行）：
    $py scripts/kit/db_vocab.py                      # 全库字段值域
    $py scripts/kit/db_vocab.py --table submissions
    $py scripts/kit/db_vocab.py --backup state/workspace.db.bak-20260919
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DB = ROOT / "state" / "workspace.db"


def has_cjk(s: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in s)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="字段值域体检")
    ap.add_argument("--db", default=str(DB))
    ap.add_argument("--table", default="")
    ap.add_argument("--min", type=int, default=2, help="只看不同值个数 >= N 的字段")
    ap.add_argument("--max-vals", type=int, default=12,
                    help="值域超过 N 的字段视为自由文本, 不参与同义告警（默认 12）")
    ap.add_argument("--enum-only", action="store_true", help="只打印值域 <= max-vals 的字段")
    ap.add_argument("--backup", default="", help="先备份到该路径（sqlite backup API，含 WAL）")
    a = ap.parse_args()
    db = Path(a.db)
    if a.backup:
        dst = Path(a.backup)
        if not dst.is_absolute():
            dst = ROOT / dst
        src = sqlite3.connect(str(db))
        out = sqlite3.connect(str(dst))
        src.backup(out)
        out.close()
        src.close()
        print("BACKUP -> %s (%d KB)" % (dst, dst.stat().st_size // 1024))
    con = sqlite3.connect(str(db))
    tabs = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type=?", ("table",))
            if not r[0].startswith("sqlite_")]
    if a.table:
        tabs = [t for t in tabs if t == a.table]
    alerts = []
    for t in tabs:
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % t)]
        for c in cols:
            try:
                rows = list(con.execute(
                    "SELECT %s, COUNT(*) FROM %s GROUP BY %s ORDER BY 2 DESC LIMIT 14" % (c, t, c)))
            except Exception:
                continue
            vals = [(v, n) for v, n in rows if v is not None and str(v).strip() != ""]
            if len(vals) < max(2, a.min):
                continue
            enumish = len(vals) <= a.max_vals
            if a.enum_only and not enumish:
                continue
            # 只有「枚举型字段」中英混用才算同义告警；自由文本(URL/name/command)混用是正常的
            mixed = enumish and any(has_cjk(str(v)) for v, _ in vals) \
                and any(not has_cjk(str(v)) for v, _ in vals)
            flag = "  <<< 枚举字段中英混用, 检查是否同义" if mixed else ""
            print("\n### %s.%s  (%d 种值)%s" % (t, c, len(vals), flag))
            for v, n in vals[:10]:
                print("    %-34s %d" % (str(v)[:34], n))
            if mixed:
                alerts.append("%s.%s" % (t, c))
    print("\n" + "=" * 60)
    if alerts:
        print("疑似同义多写法字段: %s" % ", ".join(alerts))
        print("修法: UPDATE <table> SET <col>=<统一值> WHERE <col>=<旧值>  —— 先备份再改")
    else:
        print("未发现中英混用的字段")
    return 0


if __name__ == "__main__":
    sys.exit(main())
