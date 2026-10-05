#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""js_unpack.py — webpack/uni-app 前端逆向流水线（把手工 15 轮压成 1 条命令）。

2026-09-21 立。**为什么**：万章盈科 591adb 那单，我用**手工 15 轮**走完
「找 bundle → 定位请求拦截器 → 抽签名模块 → 抽 chunk 映射表 → 拉懒加载 chunk → 抽 operation 全表」。
每一步都可脚本化 —— 手工做第二遍就是纯浪费。本脚本把这条流水线固定下来。

配套手册（判读与定级红线）：skills/recon-js-analysis/references/uni-app-signed-api.md

用法
----
    $py scripts/js_unpack.py --url https://h5.example.com/
    $py scripts/js_unpack.py --hosts hosts.txt --out results/js-unpack
    $py scripts/js_unpack.py --url https://x/ --max-chunks 30

产出（每主机一目录）
--------------------
    <out>/<host>/index.js              主 bundle 原文
    <out>/<host>/chunks/<name>.<hash>.js
    <out>/<host>/unpack.json           api_base / endpoints / chunk_map / 签名模块源码 / 候选密钥
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent / "kit"))
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        sys.stdout.reconfigure(errors="replace")

from probe import fetch, UA_BROWSER, UA_MOBILE  # noqa: E402

Q, S = chr(34), chr(39)
QQ = Q + S
# HTML 里的属性**经常没有引号**（实测 <script src=static/js/index.xxx.js>）—— 必须容错
RE_SCRIPT = re.compile(r"(?:src|href)=\s*[" + QQ + r"]?([^\s>" + QQ + r"]+\.js)")
# webpack chunk 映射：i.p+"static/js/"+({names}[e]||e)+"."+({hashes}[e])+".js"
RE_NAME_MAP = re.compile(Q + r"([a-zA-Z0-9_\-~]+)" + Q + r"\s*:\s*" + Q + r"([a-zA-Z0-9_\-~]+)" + Q)
RE_HASH_MAP = re.compile(Q + r"([a-zA-Z0-9_\-~]+)" + Q + r"\s*:\s*" + Q + r"([0-9a-f]{6,12})" + Q)
# 2026-09-22 修 umi/ant-design-pro 盲区（品茗 padapi 实证）：
#   umi 的 chunk 名是 {数字id}.{hash}.async.js，与 webpack 的 {name}.{hash}.js 不同，
#   原实现只认 webpack 写法 => umi 应用的**全部业务接口**都抽不到
#   （实测 padapi：73 条全是前端路由，/api/xr/index/* 一个没抽到）。
RE_UMI_MAP = re.compile(
    r"\{(\s*" + Q + r"\d{2,6}" + Q + r"\s*:\s*" + Q + r"[0-9a-f]{4,12}" + Q +
    r"\s*(?:,\s*" + Q + r"\d{2,6}" + Q + r"\s*:\s*" + Q + r"[0-9a-f]{4,12}" + Q +
    r"\s*)*)\}\s*\[[a-zA-Z_$][\w$]*\]")
RE_UMI_ENTRY = re.compile(Q + r"(\d{2,6})" + Q + r"\s*:\s*" + Q + r"([0-9a-f]{4,12})" + Q)
RE_MODULE = re.compile(r"[,{]?\s*" + Q + r"?([0-9a-f]{3,5})" + Q + r"?\s*:\s*function\s*\(")
RE_BASEURL = re.compile(r"(?:baseURL|baseUrl|VUE_APP_[A-Z_]+)\s*[:=]\s*[" + QQ + r"]([^" + QQ + r"]{4,120})[" + QQ + r"]")
RE_ABSURL = re.compile("[" + QQ + r"](https?://[a-zA-Z0-9._\-]+(?::[0-9]+)?(?:/[a-zA-Z0-9._\-/]{0,60})?)[" + QQ + r"]")
RE_CALL = re.compile(r"\$?u?\.?(?:http\.)?(?:get|post|put|delete)\s*\(\s*[" + QQ + r"]([^" + QQ + r"]{2,90})")
RE_URLKEY = re.compile(r"url\s*:\s*[" + QQ + r"]([^" + QQ + r"]{2,90})")
RE_PATHLIT = re.compile("[" + QQ + r"](/[a-z][a-zA-Z0-9_\-/]{3,70})[" + QQ + r"]")
RE_SECRET = re.compile(
    r"(?i)\b(app_?key|app_?secret|secret_?key|sign_?key|access_?key|client_?secret|client_?id|"
    r"aes_?key|api_?key|token_?key)\b\s*[:=]\s*[" + QQ + r"]([A-Za-z0-9+/=_\-]{8,80})[" + QQ + r"]")
RE_SIGNFN = re.compile(r"(signfn|generateSign|getSign|makeSign|createSign|calcSign|sign\()", re.I)

SKIP_PATH_PREFIX = ("/pages", "./", "/static", "/Tpl", "/assets", "/img", "/css", "//")


def js_urls(html: str, page_url: str) -> list:
    """从 HTML 抽 js 链接并补全为绝对 URL。"""
    from urllib.parse import urljoin
    out, seen = [], set()
    for m in RE_SCRIPT.finditer(html):
        u = urljoin(page_url, m.group(1))
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_module(js: str, mid: str):
    """按 webpack 模块 id 抽源码：从 '<id>:function' 到下一个 ',<4位十六进制>:function'。

    这是本脚本的核心动作 —— 手工会漏，因为模块边界只能靠"下一个模块开头"判定。
    """
    m = re.search(r"[,{]?\s*" + Q + r"?" + re.escape(mid) + Q + r"?\s*:\s*function\s*\(", js)
    if not m:
        return None
    seg = js[m.start(): m.start() + 40000]
    nxt = RE_MODULE.search(seg[30:])
    if nxt:
        seg = seg[: 30 + nxt.start()]
    return seg.strip()


def sign_module_ids(js: str) -> list:
    """找请求拦截器里引用的模块 id：interceptors.request.use(... (0,i.signfn)(...))。"""
    ids = []
    for m in re.finditer(r"interceptors\.request\.use", js):
        seg = js[max(0, m.start() - 1500): m.start() + 1500]
        for mm in re.finditer(r"([A-Za-z_$][\w$]*)\s*=\s*[a-zA-Z_$][\w$]*\(\s*" + Q + r"([0-9a-f]{3,5})" + Q + r"\s*\)", seg):
            ids.append(mm.group(2))
    return list(dict.fromkeys(ids))


def chunk_map(js: str) -> dict:
    """抽懒加载 chunk 映射：逻辑名 -> {file, hash}。

    支持两种构建器（2026-09-22 扩展）：
      · webpack / vue-cli : `{name}.{hash}.js`（映射对象 {names}[e] + {hashes}[e]）
      · umi / ant-design-pro : `{数字id}.{hash}.async.js`（映射对象 {ids}[p]）
    umi 的识别结果带 `_umi`: True，供调用方拼正确的 URL 后缀。
    """
    # ---- umi 优先（它的映射对象形态独特，不会与 webpack 混淆）----
    m = RE_UMI_MAP.search(js)
    if m:
        pairs = RE_UMI_ENTRY.findall(m.group(1))
        if len(pairs) >= 3:          # 少于 3 个不像 chunk 映射表，避免误报
            out = {}
            for cid, h in pairs:
                out[cid] = {"file": cid, "hash": h, "_umi": True}
            return out
    # ---- webpack / vue-cli ----
    hashes = dict(RE_HASH_MAP.findall(js))
    # ⚠ 坑：webpack 有两个相邻对象 {names}[e] 和 {hashes}[e]，**两个都匹配 RE_NAME_MAP**，
    # 后写的 hash 会覆盖真文件名 => chunk URL 拼成 "<hash>.<hash>.js" 全 404（实测栽过）。
    # 真文件名映射的特征是 **value 不是 6-12 位十六进制**（即 k==v）。
    names = {k: v for k, v in RE_NAME_MAP.findall(js)
             if not re.fullmatch(r"[0-9a-f]{6,12}", v)}
    out = {}
    for k, h in hashes.items():
        fn = names.get(k, k)
        if re.fullmatch(r"[a-zA-Z0-9_\-~]+", fn or ""):
            out[k] = {"file": fn or k, "hash": h}
    return out
def endpoints_of(js: str) -> set:
    found = set()
    for rx in (RE_CALL, RE_URLKEY, RE_PATHLIT):
        for x in rx.findall(js):
            if x.startswith(SKIP_PATH_PREFIX) or x.endswith((".js", ".css", ".png", ".jpg", ".svg")):
                continue
            found.add(x)
    return found


def analyze(url: str, outdir: Path, max_chunks: int, mobile: bool) -> dict:
    from urllib.parse import urlparse
    host = urlparse(url).netloc
    hd = dict(UA_MOBILE if mobile else UA_BROWSER)
    res = {"url": url, "host": host, "bundles": [], "api_base": [], "abs_urls": [],
           "sign_modules": [], "endpoints": [], "secrets": [], "chunks": {}, "errors": []}
    st, _, html = fetch(url, headers=hd, read=600000)
    res["html_status"] = st
    if st <= 0:
        res["errors"].append("首页取不到: %s" % html[:80])
        return res
    # ⚠ 基线闸门（2026-09-21）：非 200 就不许往下走。
    # 封禁页/挑战页里**当然没有 JS** —— 继续跑会得出「这个站没有前端 bundle」这种假阴性，
    # 和 identity_check 把 418 读成「无注册入口」是同一个坑（kit/verdict.py 有完整说明）。
    if st != 200:
        res["errors"].append("首页返回 %s（非 200，Server=%s）—— 被拦/不可达，**本次解析无效**，"
                             "不得据此判『没有 JS』" % (st, (res.get("server") or "-")))
        return res
    d = outdir / host
    d.mkdir(parents=True, exist_ok=True)

    urls = js_urls(html, url)
    res["bundles"] = urls
    if not urls:
        res["errors"].append("HTML 里没找到 .js（可能是未加引号属性或纯 SPA 注入）")
        return res

    # ⚠ 主包 ≠ 最大的包。chunk-vendors 通常更大，但**拦截器 / 签名 / 路由 / chunk 映射
    # 都在应用包（index.*.js / app.*.js）里**。按"最大"选会选到 vendor 包 —— 实测踩过。
    files, fetched = {}, []
    for u in urls:
        st2, _, body = fetch(u, headers=hd, read=8000000)
        if st2 == 200 and body:
            files[u] = body
            fetched.append(u)
            (d / (u.rsplit("/", 1)[-1] or "bundle.js")).write_text(body, encoding="utf-8")
    if not files:
        res["errors"].append("所有 bundle 都取不到")
        return res
    app_urls = [u for u in fetched if not re.search(r"chunk-vendors|vendor|polyfill|runtime", u, re.I)]
    main_url = (app_urls or fetched)[0]
    main_js = "\n".join(files[u] for u in (app_urls or fetched))
    res["main_bundle"] = main_url
    res["all_bundles"] = fetched

    res["api_base"] = sorted(set(RE_BASEURL.findall(main_js)))
    res["abs_urls"] = sorted(set(x for x in RE_ABSURL.findall(main_js) if "w3.org" not in x))[:20]

    # ① 签名能力：拦截器引用的模块 -> 抽源码
    for mid in sign_module_ids(main_js):
        src = extract_module(main_js, mid)
        if src:
            (d / ("module-%s.js" % mid)).write_text(src, encoding="utf-8")
            res["sign_modules"].append({"module_id": mid, "len": len(src), "src": src[:6000]})

    # ② 懒加载 chunk -> operation 全表
    cm = chunk_map(main_js)
    res["chunk_map"] = cm
    to_fetch = [v for v in cm.values() if v["file"] != "chunk-vendors"][:max_chunks]
    allp = endpoints_of(main_js)
    (d / "chunks").mkdir(exist_ok=True)
    base_dir = main_url.rsplit("/", 1)[0]          # chunk 与应用包同目录
    for item in to_fetch:
        # umi/ant-design-pro: {id}.{hash}.async.js（2026-09-22 加）
        # webpack/vue-cli    : {name}.{hash}.js
        suffix = ".async.js" if item.get("_umi") else ".js"
        cu = "%s/%s.%s%s" % (base_dir, item["file"], item["hash"], suffix)
        st3, _, cjs = fetch(cu, headers=hd, read=4000000)
        res["chunks"][item["file"]] = st3
        if st3 != 200:
            continue
        (d / "chunks" / ("%s.%s%s" % (item["file"], item["hash"], suffix))).write_text(cjs, encoding="utf-8")
        allp |= endpoints_of(cjs)
    res["endpoints"] = sorted(allp)

    # ③ 候选密钥（含弱信号，交由大脑判读，不硬归类）
    for m in RE_SECRET.finditer(main_js):
        res["secrets"].append({"kind": m.group(1), "value": m.group(2),
                               "ctx": " ".join(main_js[max(0, m.start() - 90): m.start() + 110].split())[:200]})
    for f in list(d.glob("chunks/*.js")) + list(d.glob("module-*.js")):
        t = f.read_text("utf-8", "replace")
        for m in RE_SECRET.finditer(t):
            res["secrets"].append({"kind": m.group(1), "value": m.group(2), "file": f.name,
                                   "ctx": " ".join(t[max(0, m.start() - 90): m.start() + 110].split())[:200]})
    res["signfn_present"] = bool(RE_SIGNFN.search(main_js))
    return res


def report(r: dict) -> None:
    print("=" * 78)
    print("%s   [html %s]" % (r["host"], r.get("html_status")))
    if r.get("errors"):
        for e in r["errors"]:
            print("  !! %s" % e)
    print("  bundle %d 个 / 主包 %s" % (len(r.get("bundles") or []), (r.get("main_bundle") or "-")[:70]))
    if r.get("api_base"):
        print("  ★ API base: %s" % " , ".join(r["api_base"][:4]))
    print("  签名函数迹象: %s   签名模块 %d 个" % (r.get("signfn_present"), len(r.get("sign_modules") or [])))
    for sm in (r.get("sign_modules") or [])[:2]:
        print("     [模块 %s, %d 字符] %s" % (sm["module_id"], sm["len"], sm["src"][:200].replace("\n", " ")))
    cm = r.get("chunk_map") or {}
    ch = r.get("chunks") or {}
    print("  chunk 映射 %d 个 / 实拉 %d 个（成功 %d）"
          % (len(cm), len(ch), sum(1 for v in ch.values() if v == 200)))
    if ch and not any(v == 200 for v in ch.values()):
        print("     !! 全部拉取失败，样例: %s" % list(ch.items())[:2])
    eps = r.get("endpoints") or []
    print("  ★ operation/路径 %d 条" % len(eps))
    for x in eps[:24]:
        print("      %s" % x)
    if len(eps) > 24:
        print("      ... 还有 %d 条（见 unpack.json）" % (len(eps) - 24))
    sec = r.get("secrets") or []
    if sec:
        print("  ⚠ 候选密钥 %d 条（UNSURE，交大脑判读，勿硬归类）:" % len(sec))
        for s in sec[:8]:
            print("      %-14s = %s   <- %s" % (s["kind"], s["value"][:40], s.get("ctx", "")[:80]))


def main():
    ap = argparse.ArgumentParser(description="webpack/uni-app 前端逆向流水线")
    ap.add_argument("--url")
    ap.add_argument("--hosts", help="每行一个 URL 或主机名的文件")
    ap.add_argument("--out", default=None, help="产物目录（默认 results/js-unpack-<ts>）")
    ap.add_argument("--max-chunks", type=int, default=40)
    ap.add_argument("--mobile", action="store_true")
    a = ap.parse_args()
    if not a.url and not a.hosts:
        ap.error("要 --url 或 --hosts")

    urls = []
    if a.url:
        urls.append(a.url)
    if a.hosts:
        for line in Path(a.hosts).read_text("utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line if "://" in line else "https://" + line)
    outdir = Path(a.out) if a.out else ROOT / "results" / ("js-unpack-%s" % datetime.now().strftime("%Y%m%d-%H%M%S"))
    outdir.mkdir(parents=True, exist_ok=True)

    results = []
    for u in urls:
        try:
            r = analyze(u, outdir, a.max_chunks, a.mobile)
        except Exception as e:
            r = {"url": u, "host": u, "errors": ["%s: %s" % (type(e).__name__, str(e)[:90])]}
        results.append(r)
        report(r)
    summary = outdir / "summary.json"
    summary.write_text(json.dumps({"ts": datetime.now().isoformat(timespec="seconds"), "results": results},
                                  ensure_ascii=False, indent=1), encoding="utf-8")
    print("\n落盘: %s" % summary)
    print("命中 API base 的主机: %d / %d" % (sum(1 for r in results if r.get("api_base")), len(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
