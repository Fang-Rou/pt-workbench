# -*- coding: utf-8 -*-
"""cdp_read.py - 读 CDP 浏览器里的页面（优先复用已打开的标签，并把窗口带到前台）

用法:
  python scripts/cdp_read.py <url或url子串> [--new] [--out FILE] [--links] [--text-limit N] [--wait N]

说明:
  不带 --new 时: 先在已打开标签里找 URL 含该串的；找到就复用（**不会丢你的登录态/滚动位置**）；
  找不到才新建并导航。--new 强制新建。
"""
from __future__ import annotations
import argparse, asyncio, json, sys, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from cdp import CDP, WS_URL  # noqa: E402


def list_tabs():
    with urllib.request.urlopen(WS_URL + "/json/list", timeout=8) as r:
        return json.loads(r.read())


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--new", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--links", action="store_true")
    ap.add_argument("--text-limit", type=int, default=4000)
    ap.add_argument("--wait", type=int, default=6)
    ap.add_argument("--eval", dest="js", default=None, help="在该页执行任意 JS 并打印返回值")
    ap.add_argument("--eval-file", dest="jsfile", default=None, help="同 --eval，但从文件读 JS（躲开 PowerShell 引号）")
    a = ap.parse_args()

    c = await CDP.connect()
    tgt = a.target
    url = tgt if tgt.startswith("http") else "https://" + tgt
    key = tgt.split("//")[-1].rstrip("/")
    sid = tid = None
    if not a.new:
        for t in list_tabs():
            if t.get("type") == "page" and key in (t.get("url") or ""):
                tid, sid = t["id"], None
                att = await c.cmd("Target.attachToTarget", {"targetId": tid, "flatten": True})
                sid = att["sessionId"]
                break
    if sid is None:
        tid, sid = await c.new_page(url)
        await asyncio.sleep(a.wait)
    try:
        await c.cmd("Target.activateTarget", {"targetId": tid})
    except Exception:
        pass
    if a.jsfile:
        a.js = Path(a.jsfile).read_text(encoding="utf-8")
    if a.js:
        res = await c.eval_js(sid, a.js)
        print(json.dumps(res, ensure_ascii=False, indent=1)[:4000])
        return

    info = await c.eval_js(sid, """(function(){
      var t = document.body ? document.body.innerText : '';
      var out = {url: location.href, title: document.title, len: t.length, text: t.slice(0, %d)};
      out.links = [].map.call(document.querySelectorAll('a'), function(a){
        return ((a.innerText||'').trim().replace(/\s+/g,' ').slice(0,26)) + ' -> ' + a.href; })
        .filter(function(s){ return s.length > 8; }).slice(0, 80);
      return out; })()""" % a.text_limit)
    print("URL:", (info or {}).get("url"))
    print("标题:", (info or {}).get("title"), "| 正文", (info or {}).get("len"), "字节")
    print("--- 正文前段 ---")
    print(((info or {}).get("text") or "")[:a.text_limit])
    if a.links:
        print("--- 链接 ---")
        for l in (info or {}).get("links", []):
            print("   ", l[:150])
    if a.out:
        Path(a.out).write_text("URL: %s\n标题: %s\n\n%s" % ((info or {}).get("url"), (info or {}).get("title"),
                                                             (info or {}).get("text") or ""), encoding="utf-8")
        print("SAVED:", a.out)


asyncio.run(main())
