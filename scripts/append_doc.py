#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""append_doc.py —— 长文档安全追加器（只追加，绝不重写已有内容）。

背景（2026-09-22 数据事故）：`read` 默认 limit=2000 行会静默截断，
「读→改→整体 write 回写」会把被截断的尾部永久抹掉（hit-case-library-2026.md 1361 行 → 682 行）。
本工具的写入路径是 `open(path, "a")`：**已有的字节一个都不动**，从结构上杜绝该类事故。

用法：
  $py scripts\append_doc.py <目标文件> --text-file <追加内容.md> [--expect-min-lines N] [--dry-run]
  $py scripts\append_doc.py <目标文件> --text "<单行内容>"

校验：
  ① 追加前：目标文件实际行数必须 >= --expect-min-lines（默认 0），否则拒绝（防「读到的被截断」）
  ② 追加后：新行数 == 原行数 + 追加行数，且文件大小 == 原大小 + 追加字节数
  ③ 任一不符 -> 非零退出
"""
import argparse, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
NL = chr(10)

def count_lines(p):
    with open(p, "rb") as f:
        return f.read().count(b"\n")

def main():
    ap = argparse.ArgumentParser(description="长文档安全追加器（只追加，不重写）")
    ap.add_argument("target", help="目标文件")
    ap.add_argument("--text-file", help="追加内容所在文件（推荐，避免引号转义）")
    ap.add_argument("--text", help="直接追加的单行文本")
    ap.add_argument("--expect-min-lines", type=int, default=0,
                    help="追加前目标文件的最小行数；低于此值即拒绝（防截断读）")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    tgt = Path(a.target)
    if not tgt.exists():
        print("FAIL 目标文件不存在: %s" % tgt); return 2
    if bool(a.text_file) == bool(a.text):
        print("FAIL 必须且只能给 --text-file 或 --text 之一"); return 2
    add = Path(a.text_file).read_text(encoding="utf-8") if a.text_file else a.text
    if not add.endswith(NL):
        add = add + NL
    before_lines = count_lines(tgt)
    before_bytes = tgt.stat().st_size
    if before_lines < a.expect_min_lines:
        print("FAIL 拒绝写入：目标只有 %d 行，低于 --expect-min-lines %d"
              % (before_lines, a.expect_min_lines))
        print("     ⇒ 你手上的内容很可能是被 read 截断的（默认 limit=2000），整体回写会抹掉尾部。")
        return 3
    add_bytes = len(add.encode("utf-8"))
    add_lines = add.count(NL)
    print("target=%s  追加前 %d 行 / %d 字节" % (tgt.name, before_lines, before_bytes))
    print("追加 %d 行 / %d 字节" % (add_lines, add_bytes))
    if a.dry_run:
        print("dry-run：未写入"); return 0
    with open(tgt, "a", encoding="utf-8", newline="") as f:
        f.write(add)
    after_lines = count_lines(tgt)
    after_bytes = tgt.stat().st_size
    if after_lines != before_lines + add_lines or after_bytes != before_bytes + add_bytes:
        print("FAIL 追加后校验不符：%d 行 / %d 字节" % (after_lines, after_bytes)); return 4
    print("OK 追加后 %d 行 / %d 字节（原内容未改动）" % (after_lines, after_bytes))
    return 0

if __name__ == "__main__":
    sys.exit(main())