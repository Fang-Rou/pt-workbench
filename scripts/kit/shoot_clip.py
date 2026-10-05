# -*- coding: utf-8 -*-
"""shoot_clip.py - CDP 精确裁剪截图：把含关键词的元素连同上下文裁出来（证据图定稿用）。

用法: python scripts/kit/shoot_clip.py <url> <keyword> <out.png> [--pad-top N] [--pad-bottom N] [--max-w N]

为什么不用整视口图：视口里常混入广告/推荐位/不相关内容（2026-09-28 递易归属补图实测），
clip 只取证据区块本身，审核员一眼能读。
"""
from __future__ import annotations
import asyncio, base64, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from cdp import CDP  # noqa: E402


async def main():
    url, kw, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    pad_top, pad_bottom, max_w, max_h = 300, 180, 1200, 0
    args = sys.argv[4:]
    for i, a in enumerate(args):
        if a == "--pad-top" and i + 1 < len(args): pad_top = int(args[i + 1])
        if a == "--pad-bottom" and i + 1 < len(args): pad_bottom = int(args[i + 1])
        if a == "--max-w" and i + 1 < len(args): max_w = int(args[i + 1])
        if a == "--max-h" and i + 1 < len(args): max_h = int(args[i + 1])

    c = await CDP.connect()
    tid, sid = await c.new_page(url)
    await asyncio.sleep(14)
    js = "(function(){var kw=" + json.dumps(kw) + ";"
    js += "var els=[].slice.call(document.querySelectorAll('*'));"
    js += "var hit=els.filter(function(x){return (x.textContent||'').indexOf(kw)>=0 && x.children.length===0;});"
    js += "if(!hit.length)return {found:false};var e=hit[0];"
    js += "e.scrollIntoView({block:'center'});"
    js += "var rc=e.getBoundingClientRect();"
    js += "return {found:true,text:(e.textContent||'').slice(0,80),top:Math.round(rc.top+window.scrollY),bottom:Math.round(rc.bottom+window.scrollY),vw:innerWidth,vh:innerHeight,dh:document.documentElement.scrollHeight};})()"
    r = await c.eval_js(sid, js)
    await asyncio.sleep(3)  # 等滚动稳定 + 懒加载完成后再量一次
    r2 = await c.eval_js(sid, js)
    if r2.get("found"):
        r = r2
    print("locate:", json.dumps(r, ensure_ascii=False))
    if not r.get("found"):
        print("ERR: keyword not found on page")
        return
    y0 = max(0, r["top"] - pad_top)
    y1 = min(r["dh"], r["bottom"] + pad_bottom)
    w = min(max_w, r["vw"])
    h = max(120, y1 - y0)
    if max_h > 0:
        h = min(h, max_h)   # JSON 类页面整块很大时，只取前 N 像素（2026-09-28 递易实测）
    clip = {"x": 0, "y": y0, "width": w, "height": h, "scale": 1}
    print("clip:", json.dumps(clip))
    shot = await c.cmd("Page.captureScreenshot",
                       {"format": "png", "captureBeyondViewport": True, "clip": clip},
                       session_id=sid)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(base64.b64decode(shot["data"]))
    print("SAVED:", out, out.stat().st_size)


asyncio.run(main())