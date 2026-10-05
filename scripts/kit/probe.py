#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe.py — 一次性探测脚本的四件套（别再手抄第 50 遍）。

2026-09-21 立。**为什么**：一场会话手写了 _wh1.._wh49 共 49 个一次性脚本，
其中同一段签名逻辑抄了 5 遍、fetch 抄了 40 遍，末尾全删 => 零复用。
本模块把反复重写的那几块固定下来：HTTP / 签名 / 错误信息 oracle / 落盘。

两种用法
--------
1) 当库用（推荐，写 5 行就能开工）：

    import sys
    sys.path.insert(0, "scripts/kit")
    from probe import fetch, save_json, sign_sorted_md5, Oracle, UA_MOBILE

    st, hd, body = fetch("https://api.example.com/v1/x", headers=UA_MOBILE)
    save_json("results/xxx/probe.json", {"st": st, "body": body[:500]})

2) 当命令行用（单发探测，不想写文件时）：

    $py scripts/kit/probe.py --url https://x/y --method POST --data a=1 --out results/t.json

铁律（抄自 AGENTS.md，这里做成默认值，免得每次忘）
--------------------------------------------------
* 取证脚本**只** reconfigure(errors="replace")，绝不硬写 encoding="utf-8"（会把中文打成乱码废图）。
* 外部调用先判错：fetch 不抛异常，一律返回 (status, headers, text)，status<0 表示网络层失败。
* 落盘一律带 ts，且打印绝对路径（否则"跑出来的数据没人看得见"）。
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import random
import ssl
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent      # _PT工作台
if hasattr(sys.stdout, "reconfigure"):
    # ⚠ 两类脚本的编码要求**相反**（2026-09-21 踩坑：把取证规则套到分析脚本上，中文全乱码）：
    #   · 分析/探测脚本（本文件）-> 显式设 encoding="utf-8"，否则 chcp 936 控制台里中文全是乱码；
    #   · 取证截图脚本（imou_term_shot.py 等）-> **只**写 errors="replace"，因为截图拍的是
    #     控制台本身，硬写 utf-8 会让**证据图里的中文**变乱码（window.json 有 encoding_ok 告警）。
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        sys.stdout.reconfigure(errors="replace")

UA_BROWSER = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"}
UA_MOBILE = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
                           "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"}
UA_PLAIN = {"User-Agent": "Mozilla/5.0 (compatible; authorized-src-audit)"}
FORM = {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}
JSONCT = {"Content-Type": "application/json"}

_CTX = None


def sslctx():
    """不校验证书的 context（只做可达性/特征判断）。"""
    global _CTX
    if _CTX is None:
        _CTX = ssl.create_default_context()
        _CTX.check_hostname = False
        _CTX.verify_mode = ssl.CERT_NONE
    return _CTX


def fetch(url, method="GET", headers=None, data=None, timeout=15, read=400000, allow_redirect=True):
    """返回 (status, headers, text)。**不抛异常**：网络层失败返回 (-1, {}, "Errno:...")。

    status 语义：>0 = HTTP 码（含 4xx/5xx，服务器答了话）；-1 = 根本没答话。
    可达性判定必须认 HTTPError（405/403 也是活着）—— 这是华律/禾赛两次教训。
    """
    h = dict(UA_PLAIN)
    h.update(headers or {})
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else urllib.parse.urlencode(data).encode()
    rq = urllib.request.Request(url, data=body, headers=h, method=method)
    # ⚠ 2026-09-22 修 bug：原先只 build_opener()，它自带**默认 HTTPSHandler（强制校验证书）**，
    # 于是本模块的 sslctx() 设了 CERT_NONE 却从未生效 —— 所有自签/过期证书的站点
    # 全被记成「不可达」（实测 services-gateway.com / homeofmjr.top 都中招，
    # 而 www.jdy.com 这种正常证书的 200 正常 ⇒ 极具迷惑性）。
    # 修法：显式传 HTTPSHandler(context=sslctx())，让 sslctx 真正生效。
    handler = _NoRedirect if not allow_redirect else urllib.request.HTTPRedirectHandler
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=sslctx()), handler)
    try:
        with opener.open(rq, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(read).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            b = e.read(read)
        except Exception:
            b = b""
        return e.code, dict(e.headers or {}), b.decode("utf-8", "replace")
    except Exception as e:
        return -1, {}, type(e).__name__ + ":" + str(e)[:120]


def _shell_like(text: str, ct: str) -> bool:
    """粗判「这是站点外壳页（SPA catch-all）」：HTML 且无业务特征。"""
    if "html" not in (ct or "").lower():
        return False
    low = (text or "")[:2000].lower()
    return ("<html" in low) or ("<!doctype" in low)


def judged_fetch(url, neg_url=None, headers=None, method="GET", data=None,
                 timeout=15, read=400000, allow_redirect=True, tol=0.03):
    """**带判据的 fetch**（2026-09-27 加）—— 治「判据存在但要靠人记得调用」。

    与 fetch 的区别：fetch 只回答「HTTP 码多少」，本函数回答「**这次探测算不算命中**」。
    它把 2026-09 三次实测损失换来的判据变成**默认动作**：
      · 恒等 catch-all（cwjfpt / authx / 收钱吧 13 条假阳都是它）：任意路径 200 + 同构 HTML；
      · 「一个 200 都没有」不等于目标干净（借 verdict.py 的边界，不许据此判无洞）；
      · 负控失败 ⇒ 报 UNSURE，**不得**顺着往下判命中。

    返回 (verdict, status, body, meta)：
      HIT                —— 与负控明显不同 ⇒ 该路径/接口真实存在（**仍需再看内容**）
      MISS               —— 与负控同构（含 catch-all 情形）⇒ 看不出存在性
      CATCHALL           —— 负控本身 200 且与目标同构 ⇒ 本站是 SPA 外壳，**路径判读全部降级**
      INSTRUMENT_SUSPECT —— 目标与负控都没有 200，且出现拦截码(403/405/456/418) ⇒ 换判据或换网
      UNSURE             —— 判不了（负控不可达等），交回大脑
    meta 里带负控状态/长度等证据，便于写进 notes 与 memory。
    """
    import urllib.parse as _up
    meta = {"url": url, "neg": None}
    if not neg_url:
        p = _up.urlparse(url)
        neg_url = "%s://%s/__nope_%s__" % (p.scheme, p.netloc, rnd_hex(10).lower())
    nst, nhd, ntx = fetch(neg_url, method="GET", headers=headers, timeout=timeout,
                          read=min(read, 20000), allow_redirect=allow_redirect)
    neg_len, neg_ct = len(ntx or ""), (nhd or {}).get("Content-Type", "")
    meta["neg"] = {"url": neg_url, "status": nst, "len": neg_len, "ct": neg_ct[:40]}
    st, hd, tx = fetch(url, method=method, headers=headers, data=data, timeout=timeout,
                       read=read, allow_redirect=allow_redirect)
    ct = (hd or {}).get("Content-Type", "")
    meta["status"], meta["ct"], meta["len"] = st, ct[:40], len(tx or "")
    if nst <= 0:
        return "UNSURE", st, tx, meta          # 负控都打不通 ⇒ 判据无效
    length_close = neg_len > 0 and abs(len(tx or "") - neg_len) <= max(40, int(neg_len * tol))
    if st == 200 and nst == 200 and length_close and _shell_like(tx, ct) == _shell_like(ntx, neg_ct):
        meta["note"] = ("负控也返回外壳页 ⇒ 本站是 catch-all（任意路径同一份 HTML）。"
                        "**路径存在性判读不可靠**；但 Content-Type 为 json 的响应仍可判（它不会是外壳页）。"
                        "若被测 URL 就是根路径 /，这属于「首页即模板源」，不是漏洞。")
        return "CATCHALL", st, tx, meta
    if st > 0 and (st != nst or not length_close):
        return "HIT", st, tx, meta
    if st <= 0 and nst <= 0:
        return "UNSURE", st, tx, meta
    if st in (403, 405, 456, 418, 429):
        return "INSTRUMENT_SUSPECT", st, tx, meta
    return "MISS", st, tx, meta


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch_json(url, **kw):
    """fetch 后尝试 json.loads；失败返回 (status, headers, None, text)。"""
    st, hd, tx = fetch(url, **kw)
    try:
        return st, hd, json.loads(tx), tx
    except Exception:
        return st, hd, None, tx


def sign_sorted_md5(pairs, secret, key_param="key", drop_empty=True):
    """还原实测过的「排序拼串 + md5」签名（591adb / uni-app signfn 那一类）。

    规则：键名 toLowerCase()，拼成 k=v，**对整个 k=v 串排序**，join("&")，
          末尾拼 f"&{key_param}={secret}"，取 md5 hex。
    注意：是对 k=v 串排序，不是按键名排序（这是实测细节，写错了验签必失败）。
    """
    items = [(str(k).lower(), str(v)) for k, v in pairs.items() if not (drop_empty and v in (None, ""))]
    canon = "&".join(sorted("%s=%s" % (k, v) for k, v in items))
    if secret:
        canon = canon + "&%s=%s" % (key_param, secret)
    return hashlib.md5(canon.encode()).hexdigest(), canon


def rnd_hex(n=32):
    return "".join(random.choice(string.hexdigits[:16] + "ABCDE") for _ in range(n))


def rnd_label(n=14):
    """随机不存在标签，用于泛解析探测。"""
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


class Oracle:
    """错误信息 oracle：靠**响应文案变化**反推后端真实字段名 / 操作是否存在。

    为什么需要它（2026-09-21 实测）：前端 JS 写 phoneNumber，后端只认 phone。
    猜字段名靠肉眼是猜不出来的，但"给值后错误文案变了"是硬信号。

    用法：
        o = Oracle(lambda d: fetch(URL, method="POST", data=d, headers=FORM)[2])
        o.baseline({"user_name": "x"})          # 固定已确认的字段
        o.probe("phone", ["13800138000"])       # 变的是这个字段名
        o.report()
    ⚠ 每次请求都真的打到业务逻辑上 —— 只用假数据，且候选表要有界（实测 35 个够用）。
    """

    def __init__(self, call, extract=None):
        self.call = call
        self.extract = extract or (lambda t: t[:160])
        self.base = {}
        self.base_msg = None
        self.rows = []

    def baseline(self, fixed):
        self.base = dict(fixed)
        self.base_msg = self.extract(self.call(dict(fixed)))
        print("基线文案: %s" % self.base_msg)
        return self.base_msg

    def probe(self, field, values):
        for v in values:
            d = dict(self.base)
            d[field] = v
            msg = self.extract(self.call(d))
            changed = msg != self.base_msg
            self.rows.append({"field": field, "value": v, "msg": msg, "changed": changed})
            print("  %-20s %s  %s" % (field, "变了!" if changed else "    ", msg[:110]))
        return [r for r in self.rows if r["changed"]]


def save_json(rel_path, obj):
    """落盘到工作台根下的相对路径，自动加 ts，打印绝对路径。"""
    p = ROOT / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(obj, dict) and "ts" not in obj:
        obj = {"ts": dt.datetime.now().isoformat(timespec="seconds"), **obj}
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
    print("落盘: %s" % p)
    return p


def main():
    ap = argparse.ArgumentParser(description="单发探测（不想写脚本时用）")
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--data", default=None, help="form 串，如 a=1&b=2")
    ap.add_argument("--json", default=None, help="JSON 串，优先于 --data")
    ap.add_argument("--header", action="append", default=[], help="K: V，可多次")
    ap.add_argument("--mobile", action="store_true", help="用移动端 UA")
    ap.add_argument("--out", default=None, help="落盘相对路径")
    ap.add_argument("--read", type=int, default=4000)
    a = ap.parse_args()

    hd = dict(UA_MOBILE if a.mobile else UA_BROWSER)
    for x in a.header:
        k, _, v = x.partition(":")
        hd[k.strip()] = v.strip()
    data = None
    if a.json:
        data = a.json.encode()
        hd.update(JSONCT)
    elif a.data:
        data = a.data.encode()
        hd.update(FORM)
    st, rh, tx = fetch(a.url, method=a.method, headers=hd, data=data, read=a.read)
    print("HTTP %s  len=%d" % (st, len(tx)))
    for k in ("Server", "Content-Type", "Location", "Set-Cookie", "X-Powered-By"):
        if k in rh:
            print("  %s: %s" % (k, str(rh[k])[:120]))
    print(tx[:a.read])
    if a.out:
        save_json(a.out, {"url": a.url, "method": a.method, "status": st,
                          "headers": {k: str(v) for k, v in rh.items()}, "body": tx[:20000]})
    return 0 if st > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
