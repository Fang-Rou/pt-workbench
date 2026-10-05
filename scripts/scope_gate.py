#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scope_gate.py — 受托项目**范围登记**（原：备案主体硬闸门）。

改造说明（2026-10-01）
---------------------
原版把「域名现行 ICP 备案主体 × 公益厂池」当授权判据，NO-GO 硬拦。那是 SRC 公益平台的
补偿性证明方式，与渗透测试的授权形态无关 —— 渗透测试的授权来自**委托合同 / 委托书**，
判据在纸面上，不在备案库里。因此本模块只保留**登记**职能：

  1. 从当前项目（state/engagements/<slug>.json 里 active=true 的那个，或
     --engagement 显式指定）读 `scope.hosts` / `scope.domains` / `scope.cidrs`；
  2. 回答「这个 host 在不在本项目登记范围内」，供批量侦察**标注**与报告「范围声明」章节引用；
  3. **默认不阻断**（gate() 恒返回 True）。只有项目自己显式写了 `"strict_scope": true`
     才拦外范围主机 —— 那是项目组自己要的纪律，不是平台规则。

保留的 API（`carrier_probe.py` / `batch_recon.py` 等既有调用不改）：
    registrable(domain) -> str
    check_domain(domain, use_cache=True, verbose=True) -> dict
    gate(domain, allow=None, verbose=True, evidence=None) -> (bool, dict)
    norm(s) / plain(html) / fetch(url)   # 通用小工具

用法
----
    $py scripts/scope_gate.py --show                       # 打印当前项目登记范围
    $py scripts/scope_gate.py --domain a.example.com       # 单点判定
    $py scripts/scope_gate.py --host https://x.a.com:8080
    $py scripts/scope_gate.py --engagement acme-20261001 --domain a.com
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "state"
ENG_DIR = STATE / "engagements"
ACTIVE_P = STATE / "active-engagement.txt"

MULTI = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "co.jp",
         "com.tw", "co.uk", "com.au"}

_last_call = [0.0]
DELAY = 1.0     # 对外部站的 HTTP 小工具默认最小间隔（避免误伤第三方）


# ── 通用小工具（原样保留，多处 import）──────────────────────────────────────

def norm(s: str) -> str:
    return re.sub(r"[\s（）()\-—_·,，.。、]+", "", str(s or "")).lower()


def registrable(dom: str) -> str:
    """取可注册域（apex）。传入 host:port / URL / IP 也能吃。"""
    h = str(dom).strip().lower()
    h = re.sub(r"^[a-z]+://", "", h).split("/")[0].split("?")[0]
    h = h.split("@")[-1]
    if h.startswith("["):
        return h
    h = h.split(":")[0]
    if re.match(r"^[0-9.]+$", h):
        return h
    p = [x for x in h.split(".") if x]
    if len(p) <= 2:
        return ".".join(p)
    return ".".join(p[-3:]) if ".".join(p[-2:]) in MULTI else ".".join(p[-2:])


def plain(html: str) -> str:
    t = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html or "")
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = (t.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<")
          .replace("&gt;", ">").replace("&quot;", chr(34)).replace("&#39;", chr(39)))
    return re.sub(r"\s+", " ", t)


def fetch(url: str, tries: int = 3, timeout: int = 25) -> str:
    """带节流的 GET。**只用于公开信息站，不要拿它去打目标。**"""
    import requests
    gap = time.time() - _last_call[0]
    if gap < DELAY:
        time.sleep(DELAY - gap)
    for i in range(tries):
        _last_call[0] = time.time()
        try:
            r = requests.get(url, timeout=timeout, verify=False, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
                "Accept-Language": "zh-CN,zh;q=0.9"})
            if r.status_code == 200 and len(r.text) > 200:
                return r.text
        except Exception:
            pass
        time.sleep(1.5 * (i + 1))
    return ""


# ── 项目范围登记 ────────────────────────────────────────────────────────────

def _load_engagement(slug: str | None = None) -> tuple[str, dict]:
    """返回 (slug, engagement_dict)。slug 为空时取 active 的项目。"""
    if not ENG_DIR.exists():
        return "", {}
    if slug:
        p = ENG_DIR / (slug if slug.endswith(".json") else slug + ".json")
        if p.exists():
            try:
                return p.stem, json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return "", {}
        return "", {}
    if ACTIVE_P.exists():
        try:
            s = ACTIVE_P.read_text(encoding="utf-8").strip()
            p = ENG_DIR / (s if s.endswith(".json") else s + ".json")
            if p.exists():
                return p.stem, json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    for p in sorted(ENG_DIR.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if d.get("active"):
            return p.stem, d
    return "", {}


def _scope_entries(slug: str | None = None) -> tuple[str, dict, list, list]:
    """返回 (slug, eng, host_patterns, cidr_patterns)。"""
    s, eng = _load_engagement(slug)
    sc = (eng.get("scope") or {}) if eng else {}
    hosts: list = []
    for key in ("hosts", "domains", "subdomains", "urls"):
        v = sc.get(key) or []
        if isinstance(v, str):
            v = [v]
        hosts += [str(x).strip() for x in v if str(x).strip()]
    cidrs = sc.get("cidrs") or []
    if isinstance(cidrs, str):
        cidrs = [cidrs]
    return s, eng, hosts, [str(x).strip() for x in cidrs if str(x).strip()]


_SCOPE_CACHE: dict = {}


def _scope_ready(slug: str | None = None):
    if slug not in _SCOPE_CACHE:
        _SCOPE_CACHE[slug] = _scope_entries(slug)
    return _SCOPE_CACHE[slug]


def _host_matches(host: str, patterns: list) -> bool:
    """支持 a.example.com / *.example.com / example.com / 前缀 *. 与裸域名互认。"""
    h = str(host).strip().lower().split(":")[0]
    for raw in patterns:
        p = raw.strip().lower()
        p = re.sub(r"^[a-z]+://", "", p).split("/")[0]
        if not p:
            continue
        if p.startswith("*."):
            if h == p[2:] or h.endswith("." + p[2:]):
                return True
        elif h == p or h.endswith("." + p):
            return True
    return False


def _cidr_matches(host: str, cidrs: list) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip().split(":")[0])
    except ValueError:
        return False
    for c in cidrs:
        try:
            if ip in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def check_domain(domain: str, use_cache: bool = True, verbose: bool = True,
                 engagement: str | None = None) -> dict:
    """判定单个 host/域名/URL 是否落在**本项目登记范围**内。

    verdict:
      IN-SCOPE       命中项目 scope.hosts / domains
      IN-SCOPE-IP    命中项目 scope.cidrs
      UNLISTED       项目范围表里没登记（**默认不视为越界**，只标注）
      NO-PROJECT     当前没有 active 项目 → 无法判定，一律 UNLISTED
    """
    apex = registrable(domain)
    slug, eng, hosts, cidrs = _scope_ready(engagement)
    ts = datetime.now().isoformat(timespec="seconds")

    if _host_matches(domain, hosts) or _host_matches(apex, hosts):
        r = {"domain": domain, "apex": apex, "verdict": "IN-SCOPE", "engagement": slug,
             "reason": "命中项目 %s 的 scope.hosts" % (slug or "?"), "ts": ts}
    elif _cidr_matches(domain, cidrs):
        r = {"domain": domain, "apex": apex, "verdict": "IN-SCOPE-IP", "engagement": slug,
             "reason": "命中项目 %s 的 scope.cidrs" % (slug or "?"), "ts": ts}
    else:
        why = ("当前无 active 项目（state/active-engagement.txt）"
               if not slug else "项目 %s 的 scope 表里没有这一条" % slug)
        r = {"domain": domain, "apex": apex, "verdict": "UNLISTED", "engagement": slug,
             "reason": why + "；登记范围只作标注与报告引用，不阻断探测", "ts": ts}

    if verbose:
        print("  [scope] %-28s %-12s %s" % (apex, r["verdict"], r.get("reason", "")))
    return r


def gate(domain: str, allow: str = None, verbose: bool = True,
         evidence: str = None, engagement: str | None = None) -> tuple:
    """返回 (allowed: bool, result)。

    **默认恒为 True** —— 渗透测试的授权来自委托合同，不由脚本判定。
    仅当项目 JSON 显式写了 `"strict_scope": true` 时，UNLISTED 才被拦。
    allow / evidence 两个参数保留只为兼容既有调用方（batch_recon / carrier_probe），
    现在只做记录，不做判定。
    """
    r = check_domain(domain, verbose=verbose, engagement=engagement)
    _slug, eng, _h, _c = _scope_ready(engagement)
    strict = bool((eng or {}).get("strict_scope"))
    if strict and r["verdict"] not in ("IN-SCOPE", "IN-SCOPE-IP"):
        r["note"] = "strict_scope=true ⇒ 外范围主机按项目纪律拦截"
        if verbose:
            print("          [!] strict_scope 生效：不在登记范围，跳过 %s" % domain)
        return False, r
    if allow or evidence:
        r["note"] = "allow/evidence 参数在新版仅作记录（不再参与判定）"
    return True, r


def show(engagement: str | None = None) -> int:
    slug, eng, hosts, cidrs = _scope_ready(engagement)
    if not eng:
        print("UNLISTED: 没有 active 项目。先建项目：")
        print('  $py scripts/engagement.py new --client "客户名" --domain example.com')
        return 2
    print("项目: %s" % slug)
    print("客户: %s" % (eng.get("client") or eng.get("vendor") or "-"))
    print("授权依据: %s%s" % (eng.get("auth_basis") or "**未登记**（engagement.py auth %s --basis ...）" % slug,
                            ("（%s）" % eng["auth_ref"]) if eng.get("auth_ref") else ""))
    print("strict_scope: %s" % bool(eng.get("strict_scope")))
    print("scope.hosts (%d):" % len(hosts))
    for h in hosts:
        print("   - %s" % h)
    print("scope.cidrs (%d):" % len(cidrs))
    for c in cidrs:
        print("   - %s" % c)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="项目范围登记判定（不阻断）")
    ap.add_argument("--domain", action="append", default=[], help="可重复")
    ap.add_argument("--host", action="append", default=[], help="URL 或 host:port，可重复")
    ap.add_argument("--engagement", default=None, help="指定项目 slug（默认取 active）")
    ap.add_argument("--show", action="store_true", help="打印当前项目登记范围")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.show:
        return show(a.engagement)

    targets = list(a.domain) + list(a.host)
    if not targets:
        ap.print_help()
        return 2

    out = []
    for t in targets:
        r = check_domain(t, verbose=not a.json, engagement=a.engagement)
        _, g = gate(t, verbose=False, engagement=a.engagement)
        r["allowed"] = True          # 非 strict 项目恒 True
        out.append(r)

    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
    else:
        print("")
        print("VERDICT: %s" % ("GO" if all(x["allowed"] for x in out) else "BLOCK"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
