#!/usr/bin/env python3
"""recon_api.py — 被动情报入口（免费源优先，全部第三方数据，**不碰目标**）。

设计原则（对齐 AGENTS.md）：
  1. 只做**被动**收集：本脚本永远不向目标资产发请求，只查第三方公开数据源。
  2. 免费优先：无 key 的源先上（crt.sh / certspotter / Wayback / CommonCrawl / OTX /
     HackerTarget / Anubis / Shodan InternetDB / DoH / RDAP）。FOFA、Quake 等收费源
     留 --fofa-key 插槽，有 key 再填，接口形状不变。
  3. 范围门：从 state/workspace.db 的 projects.scope 读厂商声明范围，命中的资产标
     in_scope=true，越界的**只标注不测试**（红线）。
  4. 证据纪律：全量结果落 results/<slug>/，控制台只打摘要（大文件不整读）。
  5. UNSURE 上行：源挂了 / 返回看不懂 → 打进 errors.json 并在控制台打 UNSURE 行，绝不静默丢。
  6. 免费额度保护：同 (源,查询) 结果带 TTL 缓存，--no-cache 才绕过。

用法（在 _PT工作台 目录执行，$py = bundled python）：
  $py scripts\recon_api.py probe                    # 各源连通性/耗时体检
  $py scripts\recon_api.py all  blacklake.cn        # 一把梭：子域+证书+DNS+WHOIS+历史URL
  $py scripts\recon_api.py subs blacklake.cn        # 仅子域（多源合并 + 范围标注）
  $py scripts\recon_api.py cert blacklake.cn        # 证书关联主机
  $py scripts\recon_api.py urls blacklake.cn --limit 300
  $py scripts\recon_api.py dns  blacklake.cn --types A,CNAME,NS,MX,TXT
  $py scripts\recon_api.py whois blacklake.cn       # RDAP
  $py scripts\recon_api.py ip   1.2.3.4             # InternetDB 端口/CPE/漏洞 + 反查域名
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # _PT工作台
WS = ROOT.parent                                     # 工作区根
DB = ROOT / "state" / "workspace.db"
CACHE_TTL = 6 * 3600
UA = "Mozilla/5.0 (recon_api/1.0; authorized-src-recon)"
TIMEOUT = 25


def _ssl_ctx():
    r"""用 certifi 的 CA 包建 SSL context。

    实测（2026-09-10）：本机 bundled Python 的 openssl_cafile 指向
    C:\Program Files\Common Files\SSL\cert.pem（不存在），退回旧链后对
    hackertarget / commoncrawl 报 "certificate has expired" 假故障 —— 换 certifi
    后两源立刻 200。这是"源不可用"与"环境不可用"的分界线，别再误判。
    """
    import ssl
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


SSL_CTX = _ssl_ctx()

SOURCES = {
    "crt":          "crt.sh 证书透明度（子域；服务端常 502，靠重试+certspotter 兜底）",
    "certspotter":  "Cert Spotter（证书子域）[实测可用]",
    "rapiddns":     "RapidDNS 子域库（HTML 解析）[实测可用]",
    "hackertarget": "HackerTarget hostsearch / reverse IP [实测可用]",
    "commoncrawl":  "Common Crawl 索引（历史 URL）[实测可用]",
    "internetdb":   "Shodan InternetDB（IP 端口/CPE/漏洞，无需 key）[实测可用]",
    "doh":          "DNS over HTTPS：AliDNS / doh.pub 优先（CF/Google 在本机不通）",
    "rdap":         "RDAP：Verisign（com/net）+ rdap.org 兜底（.cn 无 RDAP → 走浏览器 ICP）",
    # --- 本机网络实测不通 / 需 key，保留但 probe 会标出来 ---
    "wayback":      "Wayback CDX —— 本机连不上 web.archive.org（21s 超时），改用 commoncrawl",
    "otx":          "AlienVault OTX —— 无 key 时 HTTP 429，需要免费注册 key 才能用",
    "anubis":       "Anubis jldc —— 301→jonlu.ca 后 403 反爬",
}


# ---------------------------------------------------------------- 基础设施
class Ctx:
    def __init__(self, outdir: Path, use_cache: bool = True, verbose: bool = False):
        self.outdir = outdir
        self.cache = outdir / "cache"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.use_cache = use_cache
        self.verbose = verbose
        self.errors: list[dict] = []
        self.stats: list[dict] = []
        self._last_call: dict[str, float] = {}

    def get(self, source: str, url: str, *, min_interval: float = 1.0,
            headers: dict | None = None, cache_key: str | None = None,
            timeout: int = TIMEOUT) -> str | None:
        """带缓存 / 限速 / 重试的 GET。失败 -> 记 errors 并返回 None（UNSURE 上行）。"""
        key = cache_key or url
        cpath = self.cache / (source + "-" + hashlib.sha1(key.encode()).hexdigest()[:16] + ".txt")
        if self.use_cache and cpath.exists() and time.time() - cpath.stat().st_mtime < CACHE_TTL:
            return cpath.read_text(encoding="utf-8", errors="replace")

        wait = min_interval - (time.time() - self._last_call.get(source, 0.0))
        if wait > 0:
            time.sleep(wait)
        t0 = time.time()
        last_err = ""
        for attempt in (1, 2):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
                with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
                    body = resp.read().decode("utf-8", "replace")
                self._last_call[source] = time.time()
                self.stats.append({"source": source, "url": url, "status": 200,
                                   "bytes": len(body), "secs": round(time.time() - t0, 1)})
                cpath.write_text(body, encoding="utf-8")
                return body
            except urllib.error.HTTPError as exc:
                last_err = "HTTP %s" % exc.code
                if exc.code in (429, 502, 503) and attempt == 1:   # 502: crt.sh 常态过载
                    time.sleep(3)
                    continue
                break
            except Exception as exc:  # 超时 / DNS / TLS ...
                last_err = "%s: %s" % (type(exc).__name__, str(exc)[:120])
                if attempt == 1:
                    time.sleep(2)
                    continue
                break
        self._last_call[source] = time.time()
        self.stats.append({"source": source, "url": url, "status": "ERR",
                           "error": last_err, "secs": round(time.time() - t0, 1)})
        self.errors.append({"source": source, "url": url, "error": last_err})
        return None

    def get_json(self, source: str, url: str, **kw):
        body = self.get(source, url, **kw)
        if body is None:
            return None
        try:
            return json.loads(body)
        except Exception as exc:
            self.errors.append({"source": source, "url": url,
                                "error": "JSON 解析失败: %s" % exc, "snippet": body[:200]})
            return None

    def save(self, name: str, data) -> Path:
        path = self.outdir / name
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return path


# ---------------------------------------------------------------- 范围门
def load_scopes() -> list[dict]:
    """读厂商声明范围 + 该厂商 target 的主机名。

    范围门判定以 **target.host** 为准：scope="无限制" 只是在该厂商**自己的资产**
    内放宽，不等于"任何域名都算在范围内"（2026-09-10 实测踩过：早期版本让
    blacklake.cn 因别的厂商声明无限制而被判 in_scope=true）。
    """
    if not DB.exists():
        return []
    try:
        con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
        con.row_factory = sqlite3.Row
        projects = [dict(r) for r in con.execute(
            "SELECT id, slug, name, scope FROM projects").fetchall()]
        for p in projects:
            p["hosts"] = [str(r["host"]).strip().lower().lstrip("*.")
                          for r in con.execute(
                              "SELECT host FROM targets WHERE project_id=? "
                              "AND host IS NOT NULL AND host<>''", (p["id"],)).fetchall()]
        con.close()
        return projects
    except Exception:
        return []


def scope_of(host: str, projects: list[dict]) -> tuple[bool, str]:
    host = host.lower().strip(".")
    for p in projects:
        scope = (p.get("scope") or "").strip()
        tokens = [t.strip().lower().lstrip("*.") for t in re.split(r"[,，;；\s]+", scope) if t.strip()] if scope else []
        for t in list(p.get("hosts") or []) + [t for t in tokens if "." in t]:
            if t and (host == t or host.endswith("." + t)):
                suffix = "(范围无限制)" if scope in ("无限制", "不限", "unlimited") else ""
                return True, "%s:%s%s" % (p["slug"], t, suffix)
    return False, ""


# ---------------------------------------------------------------- 数据源
def collect_crt(ctx: Ctx, domain: str) -> set:
    out = set()
    data = ctx.get_json("crt", "https://crt.sh/?q=%%25.%s&output=json" % domain,
                        cache_key="crt:%s" % domain, min_interval=2.0)
    if isinstance(data, list):
        for row in data:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    out.add(name)
    return out


def collect_certspotter(ctx: Ctx, domain: str) -> set:
    out = set()
    url = ("https://api.certspotter.com/v1/issuances?domain=%s"
           "&include_subdomains=true&expand=dns_names" % domain)
    data = ctx.get_json("certspotter", url, cache_key="certspotter:%s" % domain)
    if isinstance(data, list):
        for item in data:
            for name in item.get("dns_names", []) or []:
                name = str(name).strip().lower().lstrip("*.")
                if name.endswith(domain):
                    out.add(name)
    return out


def collect_otx(ctx: Ctx, domain: str) -> set:
    out = set()
    url = "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns" % domain
    data = ctx.get_json("otx", url, cache_key="otx:%s" % domain)
    for rec in (data or {}).get("passive_dns", []) or []:
        host = str(rec.get("hostname", "")).strip().lower().lstrip("*.")
        if host.endswith(domain):
            out.add(host)
    return out


def collect_hackertarget(ctx: Ctx, domain: str) -> set:
    out = set()
    body = ctx.get("hackertarget", "https://api.hackertarget.com/hostsearch/?q=%s" % domain,
                   cache_key="ht:%s" % domain)
    if body and "API count exceeded" not in body and not body.lower().startswith("error"):
        for line in body.splitlines():
            host = line.split(",")[0].strip().lower()
            if host.endswith(domain):
                out.add(host)
    elif body:
        ctx.errors.append({"source": "hackertarget", "error": body.strip()[:160]})
    return out


def collect_anubis(ctx: Ctx, domain: str) -> set:
    out = set()
    data = ctx.get_json("anubis", "https://jldc.me/anubis/subdomains/%s" % domain,
                        cache_key="anubis:%s" % domain)
    if isinstance(data, list):
        for name in data:
            name = str(name).strip().lower().lstrip("*.")
            if name.endswith(domain):
                out.add(name)
    return out


def collect_rapiddns(ctx: Ctx, domain: str) -> set:
    """RapidDNS 子域库（HTML 表格，正则抠域名）。实测 200 / 60KB / 14 条。"""
    out = set()
    body = ctx.get("rapiddns", "https://rapiddns.io/subdomain/%s?full=1" % domain,
                   cache_key="rapiddns:%s" % domain, min_interval=2.0)
    if not body:
        return out
    for m in re.finditer(r">([A-Za-z0-9_.\-]+\.%s)<" % re.escape(domain), body):
        name = m.group(1).strip().lower().lstrip("*.")
        if name.endswith(domain):
            out.add(name)
    if not out:
        ctx.errors.append({"source": "rapiddns",
                           "error": "HTML 解析出 0 条（页面结构可能变化）", "snippet": body[:160]})
    return out


def load_fofa_key() -> str:
    """FOFA key 从 state/private/fofa.env 读（不进交付/外协/简报）。"""
    p = ROOT / "state" / "private" / "fofa.env"
    if not p.exists():
        return ""
    for line in p.read_text("utf-8", "ignore").splitlines():
        if line.startswith("FOFA_KEY="):
            return line.split("=", 1)[1].strip()
    return ""


def collect_fofa(ctx: Ctx, domain: str, size: int = 100) -> set:
    """FOFA 资产（收费源，2026-09-20 接入）。额度有限，靠 ctx 的 6h 缓存省。

    返回 host 集合（去 scheme/端口）。实测 domain="xfs.com" 一次 405 条，
    而全部免费源合起来只有 11 条 —— 子域覆盖的瓶颈就卡在这里。
    """
    key = load_fofa_key()
    if not key:
        return set()
    qb = base64.b64encode(("domain=\"%s\"" % domain).encode()).decode()
    url = ("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&size=%d&fields=host"
           % (key, urllib.parse.quote(qb), size))
    data = ctx.get_json("fofa", url, cache_key="fofa:%s:%d" % (domain, size))
    out = set()
    if isinstance(data, dict) and data.get("error"):
        ctx.errors.append({"source": "fofa", "error": str(data.get("errmsg") or data.get("message") or "api error")[:160]})
        return out
    rows = (data or {}).get("results") if isinstance(data, dict) else None
    for row in (rows or []):
        h = row[0] if isinstance(row, (list, tuple)) else str(row)
        h = re.sub(r"^[a-z]+://", "", str(h).strip().lower())
        h = h.split("/")[0].split(":")[0]
        if h.endswith(domain):
            out.add(h)
    return out


def collect_wayback(ctx: Ctx, domain: str, limit: int = 200) -> list:
    url = ("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json"
           "&collapse=urlkey&fl=original&limit=%d" % (domain, limit))
    data = ctx.get_json("wayback", url, cache_key="wayback:%s:%d" % (domain, limit))
    urls = []
    if isinstance(data, list):
        rows = data[1:] if data and isinstance(data[0], list) and data[0][:1] == ["original"] else data
        for row in rows:
            if isinstance(row, list) and row:
                urls.append(str(row[0]))
    return urls


def collect_commoncrawl(ctx: Ctx, domain: str, limit: int = 200) -> list:
    idx = ctx.get_json("commoncrawl", "https://index.commoncrawl.org/collinfo.json",
                       cache_key="cc:collinfo")
    if not isinstance(idx, list) or not idx:
        return []
    api = idx[0].get("cdx-api")
    if not api:
        return []
    body = ctx.get("commoncrawl", "%s?url=*.%s&output=json&limit=%d" % (api, domain, limit),
                   cache_key="cc:%s:%d" % (domain, limit))
    urls = []
    for line in (body or "").splitlines():
        try:
            urls.append(json.loads(line).get("url", ""))
        except Exception:
            continue
    return [u for u in urls if u]


def doh_query(ctx: Ctx, name: str, rtype: str) -> dict:
    # CN 可达优先（实测 AliDNS 315ms / doh.pub 305ms 命中；CF 与 Google 本机超时/被重置）
    providers = [("alidns", "https://dns.alidns.com/resolve?name=%s&type=%s" % (name, rtype)),
                 ("doh.pub", "https://doh.pub/dns-query?name=%s&type=%s" % (name, rtype)),
                 ("cloudflare", "https://cloudflare-dns.com/dns-query?name=%s&type=%s" % (name, rtype)),
                 ("google", "https://dns.google/resolve?name=%s&type=%s" % (name, rtype))]
    for tag, url in providers:
        data = ctx.get_json("doh", url, headers={"accept": "application/dns-json"},
                            cache_key="doh:%s:%s:%s" % (tag, name, rtype), timeout=10)
        if not isinstance(data, dict) or "Status" not in data:
            continue
        # Status=3(NXDOMAIN) 是权威否定答案: 不再串下一个供应商
        # （否则会掉进被墙的 CF/Google 各等 25s，30 主机能拖十几分钟）
        if data.get("Status") == 3:
            return {"provider": tag, "status": 3, "answer": []}
        if "Answer" in data or data.get("Status") == 0:
            return {"provider": tag, "status": data.get("Status"), "answer": data.get("Answer", [])}
    return {}


def rdap_whois(ctx: Ctx, domain: str) -> dict:
    """RDAP：com/net 走 Verisign（权威且本机可达）；其余 TLD 走 rdap.org 兜底。
    .cn 无公开 RDAP -> 返回空，由调用方提示改用浏览器 ICP 备案（那本来也要截图当证据）。"""
    tld = domain.rsplit(".", 1)[-1].lower()
    candidates = []
    if tld in ("com", "net"):
        candidates.append(("verisign", "https://rdap.verisign.com/%s/v1/domain/%s" % (tld, domain)))
    candidates.append(("rdap.org", "https://rdap.org/domain/%s" % domain))
    data = None
    for tag, url in candidates:
        got = ctx.get_json("rdap", url, cache_key="rdap:%s:%s" % (tag, domain))
        if isinstance(got, dict) and got.get("ldhName"):
            data = got
            break
    if not isinstance(data, dict):
        return {}
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) or []}
    return {
        "handle": data.get("handle"),
        "ldhName": data.get("ldhName"),
        "status": data.get("status"),
        "events": events,
        "nameservers": [n.get("ldhName") for n in data.get("nameservers", []) or []],
        "entities": [{"roles": e.get("roles"), "handle": e.get("handle")}
                     for e in data.get("entities", []) or []],
    }


def internetdb(ctx: Ctx, ip: str) -> dict:
    data = ctx.get_json("internetdb", "https://internetdb.shodan.io/%s" % ip,
                        cache_key="idb:%s" % ip)
    return data if isinstance(data, dict) else {}


def reverse_ip(ctx: Ctx, ip: str) -> list:
    body = ctx.get("hackertarget", "https://api.hackertarget.com/reverseiplookup/?q=%s" % ip,
                   cache_key="rev:%s" % ip)
    if not body or "error" in body.lower() or "API count exceeded" in body:
        if body:
            ctx.errors.append({"source": "hackertarget/reverse", "error": body.strip()[:160]})
        return []
    return [h.strip().lower() for h in body.splitlines() if h.strip() and "." in h]


# ---------------------------------------------------------------- 命令
def slug_for(domain: str) -> str:
    return "recon-%s-%s" % (domain.replace("/", "_"), datetime.now().strftime("%Y%m%d"))


def print_scope_note(projects: list, domain: str) -> None:
    def covered(p):
        hosts = p.get("hosts") or []
        if any(domain == t or domain.endswith("." + t) or t.endswith("." + domain) for t in hosts):
            return True
        return bool(p.get("scope")) and domain in p["scope"]

    hit = [p for p in projects if covered(p)]
    if hit:
        for p in hit:
            print("- 范围门: 命中项目 %s（声明范围: %s；target host: %s）"
                  % (p["slug"], p.get("scope") or "-", ", ".join(p.get("hosts") or []) or "-"))
    else:
        print("- 范围门: [!] workspace.db 里没有 %s 的项目/target 记录 —— 结果全部标为待确认；"
              "先登记项目再开打（range 未确认 = 不动手）" % domain)


def cmd_probe(args) -> int:
    print("# recon_api 源体检  %s  target=%s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), args.domain))
    ctx = Ctx(ROOT / "results" / slug_for(args.domain), use_cache=False)
    checks = [
        ("crt", lambda: collect_crt(ctx, args.domain)),
        ("certspotter", lambda: collect_certspotter(ctx, args.domain)),
        ("wayback", lambda: collect_wayback(ctx, args.domain, 20)),
        ("commoncrawl", lambda: collect_commoncrawl(ctx, args.domain, 20)),
        ("otx", lambda: collect_otx(ctx, args.domain)),
        ("hackertarget", lambda: collect_hackertarget(ctx, args.domain)),
        ("rapiddns", lambda: collect_rapiddns(ctx, args.domain)),
        ("anubis", lambda: collect_anubis(ctx, args.domain)),
        ("doh", lambda: doh_query(ctx, args.domain, "A")),
        ("rdap", lambda: rdap_whois(ctx, args.domain)),
        ("internetdb", lambda: internetdb(ctx, args.ip) if args.ip else {"skip": "no --ip"}),
    ]
    for name, fn in checks:
        t0 = time.time()
        try:
            res = fn()
            n = len(res) if hasattr(res, "__len__") else "?"
            ok = (n not in (0,)) or isinstance(res, dict) and res
            print("[%s] %-13s %-10s %5.1fs  %s" % ("OK  " if ok else "EMPTY", name, str(n),
                                                   time.time() - t0, SOURCES.get(name, "")))
        except Exception as exc:
            print("[FAIL] %-13s %s: %s  %5.1fs" % (name, type(exc).__name__, str(exc)[:70],
                                                   time.time() - t0))
    if ctx.errors:
        print("\n## UNSURE / 错误（不静默丢，交回大脑判断）")
        for e in ctx.errors[:12]:
            print("- %s: %s" % (e["source"], str(e.get("error", ""))[:110]))
    return 0


def cmd_subs(args) -> int:
    outdir = Path(args.out) if args.out else ROOT / "results" / slug_for(args.domain)
    outdir.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(outdir, use_cache=not args.no_cache, verbose=args.verbose)
    projects = load_scopes()
    print_scope_note(projects, args.domain)

    found = {}
    for name, fn in (("crt", collect_crt), ("certspotter", collect_certspotter),
                     ("rapiddns", collect_rapiddns), ("hackertarget", collect_hackertarget),
                     ("otx", collect_otx), ("anubis", collect_anubis),
                    ("fofa", collect_fofa)):
        try:
            got = fn(ctx, args.domain)
        except Exception as exc:
            ctx.errors.append({"source": name, "error": "%s: %s" % (type(exc).__name__, exc)})
            got = set()
        found[name] = got
        print("- %-13s %4d 条" % (name, len(got)))
        if args.verbose:
            for h in sorted(got)[:20]:
                print("    " + h)

    hosts = set().union(*found.values()) if found else set()
    rows = []
    for h in sorted(hosts):
        ok, why = scope_of(h, projects)
        rows.append({"host": h, "in_scope": ok, "scope_rule": why,
                     "sources": sorted(s for s, v in found.items() if h in v)})
    ctx.save("subdomains.json", {"domain": args.domain, "count": len(rows), "hosts": rows})
    (outdir / "subdomains.txt").write_text("\n".join(r["host"] for r in rows), encoding="utf-8")
    ins = sum(1 for r in rows if r["in_scope"])
    print("\n合计唯一子域: %d（in_scope=%d / 待确认=%d）" % (len(rows), ins, len(rows) - ins))
    print("落盘: %s , subdomains.txt" % (outdir / "subdomains.json"))
    if ctx.errors:
        ctx.save("errors.json", ctx.errors)
        print("UNSURE/错误 %d 条 -> errors.json（需大脑判断）" % len(ctx.errors))
    return 0


def cmd_cert(args) -> int:
    outdir = Path(args.out) if args.out else ROOT / "results" / slug_for(args.domain)
    outdir.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(outdir, use_cache=not args.no_cache)
    crt = collect_crt(ctx, args.domain)
    cs = collect_certspotter(ctx, args.domain)
    allh = sorted(crt | cs)
    ctx.save("cert-subdomains.json", {"domain": args.domain, "crt": sorted(crt),
                                      "certspotter": sorted(cs), "union": allh})
    print("证书关联主机: crt.sh=%d certspotter=%d 合计=%d" % (len(crt), len(cs), len(allh)))
    for h in allh[:25]:
        print("  " + h)
    if len(allh) > 25:
        print("  ...（全量见 %s）" % (outdir / "cert-subdomains.json"))
    return 0


def cmd_urls(args) -> int:
    outdir = Path(args.out) if args.out else ROOT / "results" / slug_for(args.domain)
    outdir.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(outdir, use_cache=not args.no_cache)
    wb = collect_wayback(ctx, args.domain, args.limit)
    cc = collect_commoncrawl(ctx, args.domain, args.limit)
    urls = sorted(set(u for u in (wb + cc) if u))
    hosts = sorted({urllib.parse.urlparse(u).netloc.lower() for u in urls
                    if urllib.parse.urlparse(u).netloc})
    params = sorted({q.split("=")[0] for u in urls
                     for q in [urllib.parse.urlparse(u).query] if q and "=" in q})
    ctx.save("history-urls.json", {"domain": args.domain, "wayback": len(wb), "commoncrawl": len(cc),
                                   "urls": urls[: args.limit * 3], "hosts": hosts,
                                   "param_names": params[:120]})
    print("历史 URL: wayback=%d commoncrawl=%d 去重=%d 涉及主机=%d" % (len(wb), len(cc), len(urls), len(hosts)))
    print("参数名样本(%d): %s" % (len(params), ", ".join(params[:25])))
    print("落盘: %s" % (outdir / "history-urls.json"))
    return 0


def cmd_dns(args) -> int:
    outdir = Path(args.out) if args.out else ROOT / "results" / slug_for(args.domain)
    outdir.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(outdir, use_cache=not args.no_cache)
    types = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    result = {}
    for t in types:
        r = doh_query(ctx, args.domain, t)
        result[t] = r
        vals = [a.get("data") for a in (r.get("answer") or [])]
        print("- %-6s %2d 条  %s" % (t, len(vals), ", ".join(str(v) for v in vals[:6])))
    ctx.save("dns.json", result)
    print("落盘: %s" % (outdir / "dns.json"))
    return 0


def cmd_whois(args) -> int:
    outdir = Path(args.out) if args.out else ROOT / "results" / slug_for(args.domain)
    outdir.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(outdir, use_cache=not args.no_cache)
    data = rdap_whois(ctx, args.domain)
    if not data:
        print("UNSURE: RDAP 无数据（ccTLD 不支持或网络受限）-> 交回大脑 / 改用浏览器查 ICP 备案")
        return 1
    print(json.dumps(data, ensure_ascii=False, indent=2)[:1200])
    ctx.save("whois-rdap.json", data)
    print("落盘: %s" % (outdir / "whois-rdap.json"))
    return 0


def cmd_ip(args) -> int:
    outdir = Path(args.out) if args.out else ROOT / "results" / slug_for(args.ip)
    outdir.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(outdir, use_cache=not args.no_cache)
    idb = internetdb(ctx, args.ip)
    rev = [] if args.no_reverse else reverse_ip(ctx, args.ip)
    print("InternetDB %s: ports=%s cpes=%s hostnames=%s vulns=%s tags=%s"
          % (args.ip, idb.get("ports"), idb.get("cpes"), idb.get("hostnames"),
             idb.get("vulns"), idb.get("tags")))
    print("反查域名: %d 条 %s" % (len(rev), rev[:8]))
    ctx.save("ip-intel.json", {"ip": args.ip, "internetdb": idb, "reverse_domains": rev})
    print("落盘: %s" % (outdir / "ip-intel.json"))
    return 0


def prior_art(domain: str) -> list:
    """列出该域名**既往**的被动侦察产物（2026-09-18 立，堵一个实测踩了四次的盲区）。

    为什么：slug_for() 按日期命名 ⇒ 重跑永远生成新目录，**永远不会告诉你"上周已经跑过了"**。
    实测代价：2026-09-18 我为萤石 8 个品牌域重跑了一遍，而 09-14 那批（含 126/40/29 个子域）
    早就躺在 results/ 里。同一个坑当天踩了四次（黑湖整轮 / 万方 open / 萤石 v3 BOLA / 这次）。
    这里只**警告不拦截**（改道不拦路），但把既往目录和子域数直接摆出来。
    """
    out = []
    try:
        for p in sorted((ROOT / "results").glob("recon-%s-*" % domain.replace("/", "_"))):
            if not p.is_dir() or p == (ROOT / "results" / slug_for(domain)):
                continue
            subs = p / "subdomains.txt"
            n = 0
            if subs.exists():
                n = sum(1 for ln in subs.read_text("utf-8", "ignore").splitlines() if ln.strip())
            out.append((p.name, n))
    except Exception:
        pass
    return out


def cmd_all(args) -> int:
    outdir = Path(args.out) if args.out else ROOT / "results" / slug_for(args.domain)
    outdir.mkdir(parents=True, exist_ok=True)
    prior = prior_art(args.domain)
    if prior:
        print("=" * 72)
        print("⚠ 该域名**已经有既往侦察产物** —— 先读旧结论，别重复采集：")
        for name, n in prior:
            print("    results/%s   （子域 %d 条）" % (name, n))
        print("  要重跑请确认旧结论确实不适用；否则直接读上面的目录。")
        print("=" * 72)
        print("")
    projects = load_scopes()
    print("# recon_api all  %s  ->  %s\n" % (args.domain, outdir))
    print_scope_note(projects, args.domain)
    print("")
    cmd_subs(args)
    print("")
    cmd_dns(args)
    print("")
    cmd_whois(argparse.Namespace(domain=args.domain, out=str(outdir), no_cache=args.no_cache))
    print("")
    cmd_urls(argparse.Namespace(domain=args.domain, out=str(outdir), limit=args.limit,
                                no_cache=args.no_cache))
    print("\n证据包: %s（子域/证书/DNS/WHOIS/历史URL + cache/ + errors.json）" % outdir)
    print("提醒: 全程被动，未向目标发请求；越界资产只标注不测试。")
    return 0


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="被动情报入口（免费源优先，不碰目标）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, need_domain=True):
        if need_domain:
            p.add_argument("domain")
        p.add_argument("--out", help="输出目录（默认 results/recon-<domain>-<日期>）")
        p.add_argument("--no-cache", action="store_true", help="绕过 6h 缓存")
        p.add_argument("--verbose", action="store_true")
        return p

    common(sub.add_parser("probe")).add_argument("--ip", default="")
    common(sub.add_parser("subs"))
    common(sub.add_parser("cert"))
    common(sub.add_parser("urls")).add_argument("--limit", type=int, default=200)
    common(sub.add_parser("dns")).add_argument("--types", default="A,CNAME,NS,MX,TXT")
    common(sub.add_parser("whois"))
    ip = common(sub.add_parser("ip"), need_domain=False)
    ip.add_argument("ip")
    ip.add_argument("--no-reverse", action="store_true")
    a = common(sub.add_parser("all"))
    a.add_argument("--limit", type=int, default=200)
    a.add_argument("--types", default="A,CNAME,NS,MX,TXT")
    args = ap.parse_args()
    return {"probe": cmd_probe, "subs": cmd_subs, "cert": cmd_cert, "urls": cmd_urls,
            "dns": cmd_dns, "whois": cmd_whois, "ip": cmd_ip, "all": cmd_all}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
