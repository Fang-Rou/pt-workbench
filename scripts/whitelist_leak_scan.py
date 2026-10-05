# -*- coding: utf-8 -*-
"""whitelist_leak_scan.py — 批量找「鉴权白名单漏配」端点（P30 判别法的工具化）。

原理：带全局鉴权拦截器的 API，对**任意路径**都返回统一错误（如「页面超时」/「非法操作认证」）。
      若某个**真实端点**返回的是**业务级**响应（如「参数错误」），说明它的请求穿过了拦截器
      ⇒ 该端点未鉴权可达。再用 `<path>/zz` 与 `<path>X` 变体区分「精确端点放行」与「前缀放行」。
只读：只发 GET/POST，不带任何凭据。
"""
import json, sys, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
B = Path(r"D:\渗透工作流\_PT工作台")
OUT = B / "results" / "kkidc-wlscan"
OUT.mkdir(parents=True, exist_ok=True)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36"
NC = "zz_nonexistent_wl_9k2"
def sig(base, path, method="GET"):
    h = {"User-Agent": UA, "Accept": "application/json, */*", "X-Requested-With": "XMLHttpRequest"}
    d = None
    if method == "POST":
        h["Content-Type"] = "application/json"; d = "{}"
    try:
        r = requests.request(method, base.rstrip("/") + path, headers=h, data=d, timeout=12,
                             verify=False, allow_redirects=False)
        return (r.status_code, len(r.content), r.headers.get("Content-Type", "")[:30], r.text[:200])
    except Exception:
        return None
def scan(base, paths, label):
    ctl = sig(base, "/" + NC)
    if not ctl:
        print("### %-30s 不可达，跳过" % label); return []
    print("### %-30s 负控=%s %s" % (label, ctl[:2], ctl[3][:60]), flush=True)
    def one(pth):
        g = sig(base, pth, "GET")
        if g and g[:3] != ctl[:3]:
            return {"path": pth, "method": "GET", "resp": g}
        q = sig(base, pth, "POST")
        if q and q[:3] != ctl[:3]:
            return {"path": pth, "method": "POST", "resp": q}
        return None
    with ThreadPoolExecutor(max_workers=6) as ex:
        got = [x for x in ex.map(one, paths) if x]
    # 变体判别：精确端点 vs 前缀放行
    out = []
    for x in got:
        v1 = sig(base, x["path"] + "/zz", x["method"])
        v2 = sig(base, x["path"] + "X", "GET")
        exact = bool(v1) and v1[:3] == ctl[:3]
        out.append({"base": base, "path": x["path"], "method": x["method"],
                    "resp": {"status": x["resp"][0], "len": x["resp"][1], "body": x["resp"][3]},
                    "variant_slash_zz": {"status": v1[0], "len": v1[1], "blocked": True} if v1 and v1[:3] == ctl[:3] else ({"status": v1[0], "len": v1[1], "blocked": False} if v1 else None),
                    "whitelist_granularity": "exact-endpoint" if exact else "prefix-or-fuzzy"})
        print("   \u2605 %-4s %-46s %s  [%s]" % (x["method"], x["path"][:46], x["resp"][3][:70].replace(chr(10), " "),
              "精确端点" if exact else "前缀/模糊"))
    return out
def main():
    summ = json.loads((B / "results" / "js-unpack-kkidc" / "summary.json").read_text("utf-8"))
    allhits = []
    for r in summ["results"]:
        host = r.get("host"); eps = r.get("endpoints") or []
        ab = r.get("api_base") or []
        if isinstance(ab, str): ab = [ab]
        api = ""
        for x in ab:
            xs = str(x).strip()
            if xs.startswith("http") and ("api-kws" in xs or "api-yunjiasu" in xs):
                api = xs; break
        if not api or not eps: continue
        paths = [e for e in eps if e.startswith("/") and "/" in e[1:] and "." not in e.rsplit("/", 1)[-1]]
        print("")
        hits = scan(api.rstrip("/"), paths, "%s (%d 路径)" % (host[:26], len(paths)))
        allhits.extend(hits)
    (OUT / "leaks.json").write_text(json.dumps(allhits, ensure_ascii=False, indent=1), encoding="utf-8")
    print("")
    print("=== 白名单漏配端点 %d 个 ===" % len(allhits))
    for h in allhits:
        print("  %-4s %-52s %s" % (h["method"], (h["base"] + h["path"])[:52], h["resp"]["body"][:70].replace(chr(10), " ")))
    print("-> %s" % (OUT / "leaks.json"))
main()