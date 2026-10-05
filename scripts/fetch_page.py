#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""fetch_page.py — 抓单个 URL 并落盘（自动判编码，只读 GET）。

用途：手工单目标侦察时把页面原文落到 results/，供 read/grep 使用。
纪律：只读；多主机批量请走 scripts/batch_recon.py（有节流与预算）。
请求头带 Referer + Sec-Fetch-* + sec-ch-ua*（2026-09-26 实测：裸 UA 会被 WAF 456 拦）。

用法：
  $py scripts/fetch_page.py --url https://x/ --out results/x.html [--print 2000]
"""
from __future__ import annotations

import argparse, sys
from pathlib import Path

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"


def headers_for(url: str) -> dict:
    import urllib.parse as up
    p = up.urlparse(url)
    origin = "%s://%s/" % (p.scheme, p.netloc)
    return {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": origin,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "sec-ch-ua": '"Chromium";v="128", "Not(A:Brand";v="24", "Google Chrome";v="128"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="")
    ap.add_argument("--print", dest="pr", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=25.0)
    a = ap.parse_args()

    import requests
    try:
        r = requests.get(a.url, headers=headers_for(a.url), timeout=a.timeout, verify=False, allow_redirects=True)
    except Exception as e:
        print("[ERR] 请求失败: %s" % str(e)[:200])
        return 1

    raw = r.content
    enc = None
    ctype = r.headers.get("Content-Type", "")
    if "charset=" in ctype.lower():
        enc = ctype.lower().split("charset=")[-1].split(";")[0].strip()
    if not enc or enc.lower() in ("iso-8859-1", "latin-1"):
        import re
        m = re.search(rb'charset=["\']?([\w-]+)', raw[:4000], re.I)
        if m:
            enc = m.group(1).decode("ascii", "replace")
    if not enc:
        enc = r.apparent_encoding or "utf-8"
    try:
        text = raw.decode(enc, "replace")
    except Exception:
        text = raw.decode("utf-8", "replace")

    print("[HTTP %s] %s  bytes=%d  enc=%s  final=%s" % (r.status_code, a.url, len(raw), enc, r.url))
    print("[title] %s" % (text.split("<title>")[1].split("</title>")[0].strip() if "<title>" in text else "(none)"))
    if a.out:
        p = Path(a.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        print("-> %s" % p)
    if a.pr:
        print("---- head %d ----" % a.pr)
        print(text[: a.pr])
    return 0


if __name__ == "__main__":
    sys.exit(main())
