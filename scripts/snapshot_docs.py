#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""快照技能库文档 -> _archive/docs-snapshots/<ts>/（防再次误删）。"""
import datetime as dt, shutil, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
R = Path(r"D:\渗透工作流")
SRC = R / "_PT工作台" / "skills"
DST = R / "_archive" / "docs-snapshots" / dt.datetime.now().strftime("%Y%m%d-%H%M%S")
n = 0
for p in SRC.rglob("*.md"):
    if "node_modules" in str(p):
        continue
    rel = p.relative_to(R)
    out = DST / rel
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(p, out)
    n += 1
print("已快照 %d 个 .md -> %s" % (n, DST))
