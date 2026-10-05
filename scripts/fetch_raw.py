# -*- coding: utf-8 -*-
"""fetch_raw.py — 取单个 URL 的**原始文本**落盘（不做 JSON 包装、不截断）。

用法:
  $py scripts\\fetch_raw.py <url> <落盘相对路径> [--ref <referer>] [--mobile]

为什么单列一个脚本: probe.py 的 --out 会把 body 包成 JSON 并截断 20000 字符,
分析压缩 JS / 大页面时不够用(js_unpack 那类工具需要原始文件)。
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "kit"))
from probe import fetch, UA_MOBILE  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("out")
    ap.add_argument("--ref", default=None)
    ap.add_argument("--mobile", action="store_true")
    a = ap.parse_args()

    hd = dict(UA_MOBILE) if a.mobile else {}
    if a.ref:
        hd["Referer"] = a.ref
    st, rh, tx = fetch(a.url, headers=hd, timeout=25, read=4_000_000)
    p = ROOT / a.out
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tx, encoding="utf-8", errors="replace")
    print("HTTP %s len=%d ct=%s" % (st, len(tx), rh.get("Content-Type", "-")))
    print("落盘: %s" % p)
    print("头两行: %s" % tx[:200].replace("\n", " ")[:200])
    return 0 if st > 0 else 1


sys.exit(main())
