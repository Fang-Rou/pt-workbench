# -*- coding: utf-8 -*-
"""FOFA 反查字段探针：确认哪些 query field 在**我们的账号**上真的可用。

为什么先探针：resume 说要加 name/cert/title/icp 四种反查模式，但 FOFA 的字段可用性
与账号套餐相关（部分字段 VIP 限定）。先花 6 个额度点问清楚，别写完脚本才发现字段报错。
只读 GET，size=1，不碰任何目标。
"""
import base64
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def load_key():
    p = ROOT / "state" / "private" / "fofa.env"
    for line in p.read_text("utf-8", "ignore").splitlines():
        if line.startswith("FOFA_KEY="):
            return line.split("=", 1)[1].strip()
    return ""


def api(key, path, **params):
    params["key"] = key
    url = "https://fofa.info/api/v1/%s?%s" % (path, urllib.parse.urlencode(params))
    req = urllib.request.Request(url, headers={"User-Agent": "recon-api/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"__error__": "%s: %s" % (type(exc).__name__, exc)}


def search(key, q, size=1):
    qb = base64.b64encode(q.encode()).decode()
    return api(key, "search/all", qbase64=urllib.parse.quote(qb), size=size, fields="host,domain,title,icp")


def api_get_raw(url):
    req = urllib.request.Request(url, headers={"User-Agent": "recon-api/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"__error__": "%s: %s" % (type(exc).__name__, exc)}


def round3(key):
    """第三轮：高级语法 + 富字段。

    灵感来自用户提问「FOFA 不是有 60 多个语法吗，高级的用到了没」—— 我们只用了 4 个。
    最被忽略的一条其实是 fields=：返回字段是**免费的信息增量**，多要几个字段不加钱，
    却能让 160 个 apex 域名立刻带上端口/服务/标题，直接决定轰什么。
    """
    print("-- A. 富字段：一次多要字段，看是否额外扣点 --")
    q = 'domain="xfs.com"'
    rich = ("host,domain,port,protocol,server,os,title,icp,header,cert,"
            "banner,base_protocol,status_code,country,region,city,last_updatetime")
    qb = base64.b64encode(q.encode()).decode()
    url = ("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&size=2&fields=%s"
           % (key, urllib.parse.quote(qb), urllib.parse.quote(rich)))
    d = api_get_raw(url)
    print("   consumed=%-6s errmsg=%s" % (d.get("consumed_fpoint"), str(d.get("errmsg"))[:50]))
    for row in (d.get("results") or [])[:2]:
        print("   ROW %s" % json.dumps(row, ensure_ascii=False)[:320])
    time.sleep(3)
    print("")
    print("-- B. 高级运算符（哪些真能用）--")
    adv = [
        ("icon_hash 载体发现", 'icon_hash="-247388890"'),
        ("fid       指纹", 'fid="-247388890"'),
        ("cert.issuer", 'cert.issuer="DigiCert"'),
        ("cert.subject", 'cert.subject="xfs"'),
        ("header    指纹", 'header="Server: nginx" && domain="xfs.com"'),
        ("body      指纹", 'body="Powered by" && domain="xfs.com"'),
        ("port      服务", 'port="9200" && country="CN"'),
        ("protocol  服务", 'protocol="redis" && country="CN"'),
        ("cname     指向", 'cname="xfs.com"'),
        ("status_code", 'status_code="200" && domain="xfs.com"'),
        ("after 时间", 'after="2026-01-01" && domain="xfs.com"'),
        ("server", 'server="nginx" && domain="xfs.com"'),
        ("os", 'os="Windows" && domain="xfs.com"'),
        ("region 中文", 'region="北京" && domain="xfs.com"'),
    ]
    for label, q in adv:
        d = search(key, q)
        time.sleep(3)
        if d.get("__error__"):
            print("  %-18s ERROR %s" % (label, d["__error__"][:70]))
            continue
        if d.get("error"):
            print("  %-18s ERRMSG %s" % (label, str(d.get("errmsg"))[:70]))
            continue
        print("  %-18s OK total=%-8s sample=%s" % (label, d.get("size"),
              json.dumps((d.get("results") or [])[:1], ensure_ascii=False)[:110]))
    return 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description="FOFA 字段/语法可用性探针")
    ap.add_argument("--round", type=int, default=2, choices=[1, 2, 3])
    a = ap.parse_args()
    key = load_key()
    if not key:
        print("NO KEY")
        return 1
    if a.round == 3:
        return round3(key)
    info = api(key, "info/my")
    print("== account ==")
    if info.get("__error__"):
        print("  ERROR", info["__error__"])
    else:
        for k in ("username", "isvip", "vip_level", "fofa_point", "remain_free_point", "expire_at"):
            if k in info:
                print("  %-18s %s" % (k, info[k]))
    print("")
    print("== field probe (size=1) ==")
    queries = [
        # ---- round 1 结论（留档，勿删）：domain/cert/title 可用；name/company 字段不存在(820000) ----
        # ---- round 2：搞清 org / icp / cert 三者的真实语义 ----
        ('org   short', 'org="\u946b\u65b9\u76db"'),
        ('org   ascii', 'org="xfs"'),
        ('cert  company', 'cert="\u946b\u65b9\u76db"'),
        ('cert  full-org', 'cert="\u946b\u65b9\u76db\u6570\u667a\u79d1\u6280\u80a1\u4efd\u6709\u9650\u516c\u53f8"'),
        ('icp   pivot-num', 'icp="\u4eacICP\u590720210253"'),
        ('title+country', 'title="\u946b\u65b9\u76db" && country="CN"'),
        ('body  company', 'body="\u946b\u65b9\u76db"'),
        ('size  limit1000', 'domain="xfs.com"'),
    ]
    for label, q in queries:
        sz = 1000 if label.startswith("size") else 1
        d = search(key, q, size=sz)
        time.sleep(3.0)  # FOFA 有 QPS 限流，实测背靠背立刻 429
        if d.get("__error__"):
            print("  %-18s ERROR %s" % (label, d["__error__"][:90]))
            continue
        if d.get("error"):
            print("  %-18s ERRMSG %s" % (label, str(d.get("errmsg"))[:90]))
            continue
        rows = d.get("results") or []
        print("  %-18s OK returned=%-4d total=%-8s consumed=%-5s sample=%s"
              % (label, len(rows), d.get("size"), d.get("consumed_fpoint"),
                 json.dumps(rows[:1], ensure_ascii=False)[:120]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())