# -*- coding: utf-8 -*-
"""抓某页面的全部 XHR/Fetch（URL/方法/状态/请求体摘要）落盘，供接口面分析。只读。"""
import asyncio, json, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
sys.path.insert(0, r"D:\渗透工作流\_PT工作台\scripts")
from cdp import CDP
OUT = Path(r"D:\渗透工作流\_PT工作台\results\ghzq-xhr-20260929")
OUT.mkdir(parents=True, exist_ok=True)


async def one(c, url, wait=20):
    tid, sid = await c.new_page(url)
    await c.cmd("Network.enable", {}, session_id=sid)
    await asyncio.sleep(wait)
    evs = c.take_events("Network.")
    safe = {}
    for e in evs:
        p = e.get("params") or {}
        if e.get("method") == "Network.responseReceived":
            rid = p.get("requestId")
            safe[rid] = (p.get("response") or {}).get("status")
    rows, seen = [], set()
    for e in evs:
        if e.get("method") != "Network.requestWillBeSent":
            continue
        p = e.get("params") or {}
        if p.get("type") not in ("XHR", "Fetch"):
            continue
        r = p.get("request") or {}
        u = r.get("url") or ""
        k = (r.get("method"), u.split("?")[0])
        if k in seen:
            continue
        seen.add(k)
        rows.append({"method": r.get("method"), "url": u[:220], "status": safe.get(p.get("requestId")),
                     "post": (r.get("postData") or "")[:160]})
    st = await c.eval_js(sid, "({url:location.href,title:document.title})") or {}
    try:
        await c.cmd("Target.closeTarget", {"targetId": tid})
    except Exception:
        pass
    return st, rows


async def main():
    c = await CDP.connect()
    allout = {}
    for url in sys.argv[1:]:
        st, rows = await one(c, url)
        print("=" * 74, flush=True)
        print("%s  ->  %s | %s | XHR %d" % (url, st.get("url"), st.get("title"), len(rows)), flush=True)
        for x in rows:
            print("  %-5s %-4s %s" % (x["method"], x["status"], x["url"][:130]), flush=True)
        allout[url] = {"final": st, "xhr": rows}
    (OUT / "xhr-dump.json").write_text(json.dumps(allout, ensure_ascii=False, indent=1), encoding="utf-8")
    await c.close()


asyncio.run(main())
