# -*- coding: utf-8 -*-
"""js_ctx.py — 在压缩 JS / 大文件里按正则取「有限上下文」，避免整行灌进模型上下文。

用法:
  $py scripts\\js_ctx.py <文件> <正则> [--radius 300] [--max 8] [--fold 150]

要点: 压缩 JS 常是单行几十万字符, read/grep 都会把整行倒出来 => 用本脚本切片。
"""
import argparse
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("pattern")
    ap.add_argument("--radius", type=int, default=300)
    ap.add_argument("--max", type=int, default=8)
    ap.add_argument("--fold", type=int, default=150)
    a = ap.parse_args()

    p = Path(a.path)
    txt = p.read_text(encoding="utf-8", errors="replace")
    pat = re.compile(a.pattern)
    n = 0
    for m in pat.finditer(txt):
        n += 1
        if n > a.max:
            print("... 命中超过 --max %d, 已截断" % a.max)
            break
        s = max(0, m.start() - a.radius)
        e = min(len(txt), m.end() + a.radius)
        seg = txt[s:e]
        print("=== #%d offset=%d  (字符 %d-%d / 共 %d)" % (n, m.start(), s, e, len(txt)))
        for i in range(0, len(seg), a.fold):
            print("   " + seg[i:i + a.fold])
        print("")
    print("[done] 命中 %d 条 (上限 %d)" % (n if n <= a.max else a.max, a.max))


main()
