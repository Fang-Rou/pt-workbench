# -*- coding: utf-8 -*-
"""浏览器 XHR 侦察：用真 Chrome 打开目标（穿 WAF/执行 JS），抓它自己发出的 XHR/Fetch 接口。只读。"""
import asyncio, json, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
sys.path.insert(0, r"D:\渗透工作流\_PT工作台\scripts")
from cdp import CDP


async def probe(c, url, wait=18):
    tid, sid = await c.new_page(url)
    await c.cmd("Network.enable", {}, session_id=sid)
    await asyncio.sleep(wait)
    evs = c.take_events("Network.")
    reqs, seen = [], set()
    for e in evs:
        if e.get("method") != "Network.requestWillBeSent":
            continue
        p = e.get("params") or {}
        r = p.get("request") or {}
        u = r.get("url") or ""
        if p.get("type") not in ("XHR", "Fetch"):
            continue
        k = (r.get("method"), u.split("?")[0])
        if k in seen:
            continue
        seen.add(k)
        reqs.append("%-5s %s" % (r.get("method"), u[:150]))
    st = await c.eval_js(sid, "({url:location.href,title:document.title,len:(document.body?document.body.innerText:'').length})") or {}
    print("=" * 74, flush=True)
    print("%s\n  落点=%s 标题=%s 正文=%s" % (url, str(st.get("url"))[:80], str(st.get("title"))[:40], st.get("len")), flush=True)
    print("  XHR/Fetch %d 条:" % len(reqs), flush=True)
    for x in reqs[:14]:
        print("    " + x, flush=True)
    try:
        await c.cmd("Target.closeTarget", {"targetId": tid})
    except Exception:
        pass


async def main():
    c = await CDP.connect()
    for url in sys.argv[1:]:
        try:
            await probe(c, url)
        except Exception as e:
            print("%s ERR %s" % (url, str(e)[:80]), flush=True)
    await c.close()


asyncio.run(main())
