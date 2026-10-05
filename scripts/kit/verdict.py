#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verdict.py — 判读型脚本的**基线闸门**：仪器坏了，就不许下结论。

2026-09-21 立。起因：一天之内同一个形状失误三次 ——
  ① 泛解析噪声        -> 仪器报出「华律 54/56 可达」这种**正常数字**
  ② §7 编码规则被泛化 -> probe.py 中文全乱码（规则被误用）
  ③ 万华 418 封禁     -> identity_check 报出「无注册入口 => 不可得」这种**正常结论**
共同形状：**仪器坏了，却报出一个看似正常的结论。**

对应案例库 P5「测量层纪律：结论必须能回答『如果我错了，会看到什么』」。
本模块把 P5 从"一条要记得的原则"变成"一个不过就出不去"的**默认动作**（AGENTS §6 的 ③闸门位）。

设计原则
--------
* **宁 UNSURE 不硬归类**（AGENTS §5）：本模块只回答"这次测量可不可信"，不回答业务问题。
* **零依赖**：只用标准库，任何脚本都能 import。
* **可解释**：每个 UNSURE 都带 why 字符串，直接进日志/报告（闸门必须能自我解释）。

用法
----
    import sys; sys.path.insert(0, "scripts/kit")
    from verdict import baseline, appraise, UNSURE, OK

    b = baseline("https://target/")                  # ① 先验仪器
    rows = [(st, body), ...]                          # ② 业务探测结果
    v, why = appraise(rows, b)                        # ③ 闸门
    if v == UNSURE:
        print("判读无效:", why); return 2             # 不许下结论

命令行自检
----------
    $py scripts/kit/verdict.py --url https://target/
"""
from __future__ import annotations

import argparse
import sys

# 分析类脚本：显式 utf-8（否则 chcp 936 控制台里中文全乱码 —— 这个坑 2026-09-21 踩了三次）。
# ⚠ 与"取证截图脚本"相反：那些脚本**只能**写 errors="replace"，见 kit/probe.py 顶部注释。
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        sys.stdout.reconfigure(errors="replace")

UNSURE = "UNSURE"
OK = "OK"

# 这些状态码本身就在说"我没在正常服务你"
BLOCK_CODES = (401, 403, 407, 418, 429, 451, 502, 503, 504)


def _fetch(url, headers=None, timeout=12, read=4000):
    import ssl
    import urllib.error
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    h = {"User-Agent": "Mozilla/5.0 (compatible; authorized-src-audit)"}
    h.update(headers or {})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(read).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            b = e.read(read).decode("utf-8", "replace")
        except Exception:
            b = ""
        return e.code, dict(e.headers or {}), b
    except Exception as e:
        return -1, {}, type(e).__name__ + ":" + str(e)[:100]


def baseline(url, headers=None, expect=(200,), timeout=12):
    """打一个**已知应该有正常反应**的路径，确认仪器还活着。

    返回 dict(ok, status, server, len, why)。ok=False 时**上游必须 UNSURE**。
    默认打站点根；归属/情报类脚本可传自己的"健康路径"（如某源的健康检查 URL）。
    """
    st, hd, bd = _fetch(url, headers=headers, timeout=timeout)
    srv = (hd or {}).get("Server", "") or ""
    ok = st in expect
    why = "" if ok else "基线 %s 返回 %s%s —— 目标不可达/被拦，本次判读无效" % (
        url, st, ("（Server=%s）" % srv) if srv else "")
    return {"ok": ok, "status": st, "server": srv, "len": len(bd or ""), "url": url, "why": why}


def uniform(rows, bucket=120):
    """检测**同构响应**：全部样本长得一样 => catch-all 或封禁页，路径级结论不可靠。

    rows: [(status, body), ...] 返回 (is_uniform, 样本签名, 唯一签名数)
    """
    sigs = []
    for st, body in rows:
        t = " ".join((body or "").split())[:bucket]
        sigs.append((st, t))
    uniq = set(sigs)
    return (len(uniq) == 1 and len(sigs) > 1), (sigs[0] if sigs else None), len(uniq)


def appraise(rows, b=None, min_samples=8, label=""):
    """闸门主函数：rows=[(status, body)]，b=baseline() 的返回值（可省）。

    返回 (verdict, why列表)。verdict ∈ {OK, UNSURE}。
    规则（任一命中即 UNSURE）：
      ① 样本为空
      ② 基线不健康
      ③ 样本数 >= min_samples 且**全部同构**（catch-all / 封禁页）
      ④ 样本里**没有任何一个**非拦截状态码（全是 401/403/418/429/503…）
    """
    why = []
    if not rows:
        return UNSURE, ["样本为空 —— 没有可判读的数据，不得据此下『无』的结论"]
    if b is not None and not b.get("ok"):
        why.append(b.get("why") or "基线不健康")
    is_uni, sig, nuniq = uniform(rows)
    if len(rows) >= min_samples and is_uni:
        why.append("全部 %d 个样本同构（%s）—— catch-all 或封禁页，路径/主机级结论不可靠"
                   % (len(rows), (sig[0] if sig else "?")))
    # ④ 判据要准：**「一个 200 都没有」且「出现明确拦截码」**才算仪器可疑。
    #    纯 404/全员 404 是**正常的否定结果**（服务器在正常答话，只是路径不存在），不该报 UNSURE ——
    #    这条边界写错会让闸门变成"狼来了"，那比没有闸门更糟。
    codes = [st for st, _ in rows]
    if 200 not in codes and any(c in BLOCK_CODES for c in codes):
        why.append("样本里没有任何 200，且出现拦截码 %s —— 疑似被封，不是『目标干净』"
                   % sorted({c for c in codes if c in BLOCK_CODES}))
    if why:
        return UNSURE, (["[%s] %s" % (label, w) for w in why] if label else why)
    return OK, []


def sources_report(results, min_ok=1):
    """情报类专用：results = {源名: True/False/None(未知)}。

    全部源失败 => UNSURE（"查不到" ≠ "没有"）。这是 ICP 源封 IP 那次的教训。
    """
    ok = [k for k, v in results.items() if v is True]
    bad = [k for k, v in results.items() if v is False]
    if len(ok) < min_ok:
        return UNSURE, ["全部 %d 个数据源都失败（%s）—— 『查不到』不等于『没有』，不得下否定结论"
                        % (len(bad), ", ".join(bad[:6]))]
    if bad:
        return OK, ["注意：%d 个源失败（%s），结论仅基于 %d 个成功源"
                    % (len(bad), ", ".join(bad[:4]), len(ok))]
    return OK, []


def main():
    ap = argparse.ArgumentParser(description="基线闸门自检：目标还正常吗？")
    ap.add_argument("--url", required=True)
    ap.add_argument("--expect", default="200", help="期望状态码，逗号分隔")
    a = ap.parse_args()
    exp = tuple(int(x) for x in a.expect.split(",") if x.strip())
    b = baseline(a.url, expect=exp)
    from urllib.parse import urlparse as _up
    print("基线 %s" % b["url"])
    print("  status=%s  Server=%s  len=%s" % (b["status"], b["server"] or "-", b["len"]))
    if b["ok"]:
        print("  判读: %s —— 仪器正常，可以继续" % OK)
        return 0
    print("  判读: %s —— %s" % (UNSURE, b["why"]))
    return 2


if __name__ == "__main__":
    sys.exit(main())
