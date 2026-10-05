#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""api_extract.py — 从 SPA 前端**提取接口表**（2026-09-27 立，第一个「探测原语」）。

为什么它比现有 js 引擎值钱（2026-09-27 实测对照）：
  · 批量 js 引擎（搜特征串）×5 台 = 29 请求 → **0 命中**；
  · 手工拆 1 个 bundle = **1 请求 → 68 条 API**。
  ⇒ SPA 时代该批量化的动作是「**提接口表**」，不是「搜关键词」。

判据内建（治「判据活在文档里、不活在代码里」这个一级根因）：
  1) **负控**：先打一个必然不存在的 JS，确认 404 —— 否则「拉不到 JS」分不清是没引还是被封；
  2) **catch-all 检测**：任意路径返回同一份 HTML ⇒ 标 SPA_CATCHALL，路径判读全部降级；
  3) **scanned_n 门槛**：一个 JS 都没扫到 ⇒ verdict=UNRELIABLE（**不得据此判「没有接口」**）；
  4) **类型校验**：JS 响应必须是 js（不是 HTML 外壳）。

输出（结构化返回）：stdout ≤ 12 行；全量接口表落盘 results/api-extract-<host>-<ts>/；
可选 --memory-slug 自动并入外置工作记忆。

用法：
    $py scripts\api_extract.py --host www.example.com
    $py scripts\api_extract.py --hosts-file state\hosts.txt --max-hosts 10
    $py scripts\api_extract.py --host x.com --memory-slug zjph-butian
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
MAX_JS = 4 * 1024 * 1024


def hdr(host: str) -> dict:
    return {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.9",
            "Referer": "https://%s/" % host,
            "sec-ch-ua": chr(34) + "Chromium" + chr(34) + ";v=" + chr(34) + "128" + chr(34),
            "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": chr(34) + "Windows" + chr(34)}


def get(url: str, timeout: int = 25):
    import requests
    try:
        return requests.get(url, headers=hdr(url.split("/")[2]), timeout=timeout,
                            verify=False, allow_redirects=True)
    except Exception:
        return None


def find_js(html: str, base: str) -> list:
    """从 HTML 提取 JS 引用 —— 覆盖相对路径 ./ 与 type=module（2026-09-27 实测的坑）。"""
    out = []
    for m in re.finditer(r"""<script[^>]*?src=["\x27]?([^"\x27\s>]+)["\x27]?""", html, re.I):
        out.append(m.group(1))
    for m in re.finditer(r"""["\x27]([^"\x27\s>]{1,200}\.js)["\x27]""", html):
        out.append(m.group(1))
    seen, norm = set(), []
    for s in out:
        if s.startswith("//"):
            s = "https:" + s
        elif s.startswith("/"):
            s = base + s
        elif not s.startswith("http"):
            s = base + "/" + s.lstrip("./")
        if ".js" not in s or s in seen:
            continue
        seen.add(s)
        norm.append(s)
    return norm


def extract_from_js(text: str, host: str) -> dict:
    """从单个 JS 提取 base / 路径 / 方法。"""
    bases = {}
    # 2026-09-27 修正：真实压缩代码常是「逗号分隔的多声明」，
    # 例：const y0=new A_(n_),_0="/hospital/v1" —— 只匹配 const\s+name= 会漏掉 _0。
    for m in re.finditer(r"""(?:^|[,;{(]|\bconst\s|\bvar\s|\blet\s)\s*([A-Za-z_$][\w$]*)\s*=\s*["\x27](/[A-Za-z0-9_\-/]{2,60})["\x27]""", text):
        bases[m.group(1)] = m.group(2)
    apis = []
    for m in re.finditer(r"""\.(get|post|put|delete|patch)\(\s*([A-Za-z_$][\w$]*)\s*\+\s*["\x27]([^"\x27]{2,80})["\x27]""", text):
        meth, var, p = m.group(1).upper(), m.group(2), m.group(3)
        apis.append({"method": meth, "path": (bases.get(var, "") + p), "via": var})
    for m in re.finditer(r"""["\x27](/(?:api|v\d|rest|portal|service|open|hospital|admin)/[A-Za-z0-9_\-/\.]{2,80})["\x27]""", text):
        apis.append({"method": "?", "path": m.group(1), "via": "literal"})
    for m in re.finditer(r"https?://([a-z0-9\.\-]+)\.[A-Za-z]{2,6}/[A-Za-z0-9_\-/\.]{0,50}", text):
        if host.split(".")[-2] in m.group(0):
            continue
        apis.append({"method": "?", "path": m.group(0), "via": "absolute"})
    return {"bases": bases, "apis": apis}


def run_host(host: str, verbose: bool = False) -> dict:
    base = "https://" + host
    res = {"host": host, "verdict": "UNSURE", "why": [], "base": None,
           "apis": [], "js_scanned": 0, "js_total": 0, "catchall": None}
    # 判据 1：负控
    neg = get(base + "/__nope_%d__.js" % int(time.time()))
    res["neg_control"] = (neg.status_code if neg is not None else None)
    home = get(base + "/")
    if home is None:
        res["verdict"] = "UNREACHABLE"
        return res
    html = home.text
    res["home_status"] = home.status_code
    # 判据 2：catch-all（拿一个随机路径对比首页）
    rnd = get(base + "/__nope_%d__" % int(time.time()))
    if rnd is not None and rnd.status_code == 200 and abs(len(rnd.text) - len(html)) < 40:
        res["catchall"] = "SPA_CATCHALL"
        res["why"].append("随机路径与首页同构 ⇒ 路径判读全部降级")
    js = find_js(html, base)
    res["js_total"] = len(js)
    host_root = ".".join(host.split(".")[-2:])
    apis, bases = [], {}
    for u in js[:24]:
        if host_root not in u:
            continue
        jr = get(u, timeout=40)
        if jr is None or jr.status_code != 200:
            continue
        if len(jr.content) > MAX_JS:
            res["why"].append("跳过超限 JS: %s" % u.split("/")[-1][:28])
            continue
        ct = (jr.headers.get("Content-Type") or "").lower()
        if "javascript" not in ct and "ecmascript" not in ct and not u.endswith(".js"):
            continue
        res["js_scanned"] += 1
        got = extract_from_js(jr.text, host)
        bases.update(got["bases"])
        apis.extend(got["apis"])
        time.sleep(1.2)
    uniq = {}
    for a in apis:
        uniq[(a["method"], a["path"])] = a
    res["apis"] = [uniq[k] for k in sorted(uniq)]
    res["base"] = sorted(set(bases.values()))[:4]
    # 判据 3：scanned_n 门槛
    if res["js_scanned"] == 0:
        res["verdict"] = "UNRELIABLE"
        res["why"].append("0 个同站 JS 被扫描 ⇒ 不得据此判「没有接口」")
    elif res["apis"]:
        res["verdict"] = "OK"
    else:
        res["verdict"] = "NO_API_FOUND"
        res["why"].append("扫了 %d 个 JS 但未提取到接口（可能是纯静态站或接口在别处）" % res["js_scanned"])
    return res


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="从 SPA 提取接口表（探测原语）")
    ap.add_argument("--host", default="")
    ap.add_argument("--hosts-file", default="")
    ap.add_argument("--max-hosts", type=int, default=5)
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--memory-slug", default="")
    a = ap.parse_args()
    hosts = []
    if a.host:
        hosts.append(a.host)
    if a.hosts_file:
        p = Path(a.hosts_file)
        if not p.is_absolute():
            p = ROOT / p
        hosts += [x.strip().split(",")[0] for x in p.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
    hosts = list(dict.fromkeys(hosts))[: a.max_hosts]
    if not hosts:
        print("UNSURE: 需要 --host 或 --hosts-file")
        return 2
    out = Path(a.out_dir) if a.out_dir else RESULTS / ("api-extract-%s" % datetime.now().strftime("%Y%m%d-%H%M%S"))
    out.mkdir(parents=True, exist_ok=True)
    allres = []
    for h in hosts:
        r = run_host(h)
        allres.append(r)
        (out / ("%s.json" % h)).write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")
        print("%-34s %-14s js %d/%d  接口 %d  %s"
              % (h, r["verdict"], r["js_scanned"], r["js_total"], len(r["apis"]),
                 ("base=" + ",".join(r["base"] or []))[:40]))
    tot = sum(len(r["apis"]) for r in allres)
    print("")
    print("== 汇总：%d 台，接口 %d 条 ==" % (len(allres), tot))
    ver = [r["host"] + ":" + r["verdict"] for r in allres if r["verdict"] != "OK"]
    if ver:
        print("  非 OK 的（**不得据此判无洞**）：" + ", ".join(ver[:6]))
    def rank(a):
        if a["method"] in ("GET", "POST", "PUT", "DELETE", "PATCH") and a["path"].startswith("/"):
            return 0
        if a["path"].startswith("http"):
            return 2
        return 1
    for r in sorted(allres, key=lambda x: -len(x["apis"]))[:2]:
        for x in sorted(r["apis"] or [], key=rank)[:8]:
            print("    %-6s %s" % (x["method"], x["path"][:78]))
    print("  全量: %s" % out)
    if a.memory_slug:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import memory as mem
            for r in allres:
                mem.add_asset(a.memory_slug, r["host"], status="reachable",
                              api_base=",".join(r["base"] or []), apis=[x["path"] for x in r["apis"]][:80])
                if r["verdict"] != "OK":
                    mem.add_simple(a.memory_slug, "leads",
                                   {"ts": mem.now(), "text": "%s api_extract=%s：%s"
                                    % (r["host"], r["verdict"], "; ".join(r["why"])[:90])})
            print("  已并入工作记忆: memory.py brief %s" % a.memory_slug)
        except Exception as e:
            print("  (memory 写入跳过: %s)" % str(e)[:50])
    return 0


if __name__ == "__main__":
    sys.exit(main())