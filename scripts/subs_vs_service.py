#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""子域名 vs 实际服务：批量核对（回答"厂池子域数据有多少是空壳"）。

判据（只看首页，最小动作）：
  · 去重后逐台 GET /
  · 分类：真应用 / SPA壳 / 默认页 / CNAME兜底 / 403 / 不可达
"""
import concurrent.futures as cf
import hashlib, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path
sys.path.insert(0, r"D:\渗透工作流\_PT工作台\scripts\kit")
from probe import fetch, UA_BROWSER, save_json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
R = Path(r"D:\渗透工作流\_PT工作台")

hosts = set()
for f in R.glob("results/**/subdomains.txt"):
    try:
        for line in f.read_text(encoding="utf-8", errors="replace").split():
            h = line.strip().lower()
            if h and "." in h and not h.replace(".", "").isdigit():
                hosts.add(h)
    except Exception:
        pass
hosts = sorted(hosts)
print("去重后子域总数:", len(hosts))

DEFAULT_SIG = ("welcome to nginx", "welcome to centos", "apache2 ubuntu default",
               "it works", "welcome to openresty", "index of /", "test page for the apache",
               "default web site page", "iis windows server")

def classify(h):
    st, hd, tx = fetch("https://" + h + "/", headers=UA_BROWSER, timeout=8, read=60000, allow_redirect=False)
    if st <= 0:
        st, hd, tx = fetch("http://" + h + "/", headers=UA_BROWSER, timeout=8, read=60000, allow_redirect=False)
    if st <= 0:
        return {"host": h, "kind": "不可达", "status": st}
    low = tx[:3000].lower()
    loc = hd.get("Location", "")
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", tx, re.I | re.S)
    if m:
        title = m.group(1).strip()[:60]
    sig = hashlib.md5(tx[:1200].encode("utf-8", "replace")).hexdigest()[:10]
    kind = "其他"
    if st in (403, 401):
        kind = "拦截(%d)" % st
    elif any(s in low for s in DEFAULT_SIG):
        kind = "默认页"
    elif st in (301, 302) and not tx.strip():
        kind = "CNAME兜底"
    elif st == 200 and len(tx) < 400:
        kind = "极小响应"
    elif st == 200:
        kind = "有内容"
    return {"host": h, "kind": kind, "status": st, "title": title, "len": len(tx), "sig": sig, "loc": loc[:70]}

rows = []
with cf.ThreadPoolExecutor(max_workers=24) as ex:
    for r in ex.map(classify, hosts):
        rows.append(r)
c = Counter(r["kind"] for r in rows)
print("")
print("=== 分类统计 ===")
for k, v in c.most_common():
    print("  %-12s %5d  (%.1f%%)" % (k, v, 100.0 * v / len(rows)))
# 同签名成簇 = SPA 壳/兜底的强信号
sigc = Counter(r.get("sig") for r in rows if r.get("sig"))
dup = sum(1 for r in rows if r.get("sig") and sigc[r["sig"]] >= 10)
print("")
print("⚠ **同一响应签名 >=10 台**的主机数: %d (%.1f%%)  <= SPA壳/CNAME兜底的强信号"
      % (dup, 100.0 * dup / len(rows)))
print("")
print("=== 最常见签名 TOP6（代表壳）===")
for s, n in sigc.most_common(6):
    if n < 5:
        continue
    sample = [r["host"] for r in rows if r.get("sig") == s][:3]
    print("  %-12s x%-5d 例: %s" % (s, n, ", ".join(sample)))
save_json("results/subs-vs-service-20260922.json", {"total": len(rows), "kinds": dict(c),
                                                    "dup_sig_hosts": dup, "rows": rows})
print("")
print("[done] SUBS-VS-SERVICE-END")
