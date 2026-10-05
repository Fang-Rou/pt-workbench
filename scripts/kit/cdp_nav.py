# -*- coding: utf-8 -*-
"""kit/cdp_nav.py — 参数化 CDP 导航取值。**不要再手写 CDP 脚本。**

为什么（2026-09-19）：手写 CDP 脚本连烧 3 轮 —— 根因是 eval_js 遇到 JS 错误时
返回 {"__error__": ...} 而**不抛异常**，没检查返回值就等于静默吞错。
本模板内置三层失败上报（导航报错 / 导航没生效 / 取值报错）。

2026-09-22 修：原第 118/120 行 JS 字符串写成 ""...:""...""，JS 里提前闭合 =>
凡走导航路径必然 SyntaxError（--no-nav 走另一行所以看不出来）。已改用单引号。

用法（在 _PT工作台 目录执行）：
    $py scripts/kit/cdp_nav.py --url https://www.butian.net/Home/Loo/detail/10969031?n=1 --wait 8
    $py scripts/kit/cdp_nav.py --url X --js "document.title" --out results/x.txt
    $py scripts/kit/cdp_nav.py --url X --match butian.net     # 复用已有标签（登录态在那边）

退出码: 0 成功 / 1 失败（明确打印原因，不再静默）
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import urllib.request
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))
ROOT = SCRIPTS.parent

BODY_JS = "(document.body?document.body.innerText:'').slice(0,4000)"
BODY_JSON = "JSON.stringify((document.body?document.body.innerText:'').slice(0,4000))"


def tabs():
    return json.loads(urllib.request.urlopen("http://127.0.0.1:9223/json/list", timeout=5).read())


def is_err(v):
    return isinstance(v, dict) and "__error__" in v


async def dump(c, sid, a) -> int:
    """只读当前标签内容（不导航）。"""
    info = await c.eval_js(sid, "JSON.stringify({u:location.href,t:document.title})")
    if is_err(info):
        print("[FAIL] 读取失败: %s" % info["__error__"])
        return 1
    d = json.loads(info or "{}")
    print("URL : %s" % d.get("u"))
    print("TITLE: %s" % d.get("t"))
    expr = a.js or "JSON.stringify((document.body?document.body.innerText:'').slice(0,6000))"
    txt = await c.eval_js(sid, expr)
    if is_err(txt):
        print("[FAIL] 取值失败: %s" % txt["__error__"])
        return 1
    s = txt if isinstance(txt, str) else json.dumps(txt, ensure_ascii=False)
    if s.startswith(chr(34)):
        try:
            s = json.loads(s)
        except Exception:
            pass
    print("---- BODY ----")
    print(s[:2500])
    if a.out:
        p = Path(a.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(s, encoding="utf-8")
        print("OUT -> %s" % p)
    return 0


async def run(a) -> int:
    from cdp import CDP
    c = await CDP.connect()
    try:
        sid = None
        if a.match:
            for t in tabs():
                if a.match in t.get("url", ""):
                    sid = (await c.cmd("Target.attachToTarget",
                                       {"targetId": t["id"], "flatten": True}))["sessionId"]
                    print("attached -> %s" % t.get("url"))
                    break
        if not sid:
            for t in tabs():
                if t.get("url") == "about:blank":
                    sid = (await c.cmd("Target.attachToTarget",
                                       {"targetId": t["id"], "flatten": True}))["sessionId"]
                    print("reuse existing about:blank tab")
                    break
        if not sid:
            tid, sid = await c.new_page("about:blank")
            print("new tab -> about:blank")
        if a.no_nav:
            print("no-nav: 直接读当前标签内容")
            return await dump(c, sid, a)
        try:
            await c.cmd("Page.enable", {}, session_id=sid)
        except Exception:
            pass
        nav = await c.cmd("Page.navigate", {"url": a.url}, session_id=sid)
        if isinstance(nav, dict) and nav.get("errorText"):
            print("[FAIL] Page.navigate 报错: %s" % nav["errorText"])
            return 1
        await asyncio.sleep(a.wait)
        info = await c.eval_js(sid, "JSON.stringify({u:location.href,t:document.title,"
                                   "n:(document.body?document.body.innerText.length:0)})")
        if is_err(info):
            print("[FAIL] 读取页面信息失败: %s" % info["__error__"])
            return 1
        d = json.loads(info or "{}")
        print("URL : %s" % d.get("u"))
        print("TITLE: %s" % d.get("t"))
        print("TEXTLEN: %s" % d.get("n"))
        if a.expect and a.expect not in (d.get("u") or ""):
            print("[FAIL] 导航没生效（URL 里没有 %s）" % a.expect)
            print("       修法: 用 --match <域名片段> 复用已登录标签，或确认 Chrome 9223 在跑")
            return 1
        if not d.get("n"):
            print("[WARN] 页面正文为空 —— 可能是登录态失效/跳转/需要渲染时间（加大 --wait）")
        expr = a.js or BODY_JS
        txt = await c.eval_js(sid, expr) if a.js else await c.eval_js(sid, BODY_JSON)
        if is_err(txt):
            print("[FAIL] 取值失败: %s" % txt["__error__"])
            return 1
        s = txt if isinstance(txt, str) else json.dumps(txt, ensure_ascii=False)
        if a.js:
            print("JS RESULT: %s" % s[:800])
        else:
            body = json.loads(s) if s.startswith(chr(34)) else s
            print("---- BODY (前 1200) ----")
            print(body[:1200])
            s = body
        if a.out:
            p = Path(a.out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(s, encoding="utf-8")
            print("OUT -> %s" % p)
        return 0
    finally:
        await c.close()


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="参数化 CDP 导航取值")
    ap.add_argument("--url", default="", help="要导航到的 URL（--no-nav 时可不给）")
    ap.add_argument("--no-nav", action="store_true", help="只读当前匹配标签，不导航")
    ap.add_argument("--wait", type=float, default=7)
    ap.add_argument("--js", default="", help="自定义 JS 表达式（默认取 body.innerText）")
    ap.add_argument("--out", default="", help="落盘路径")
    ap.add_argument("--match", default="", help="复用 URL 含该片段的已有标签")
    ap.add_argument("--expect", default="", help="URL 里应包含的片段（校验导航生效）")
    return asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
