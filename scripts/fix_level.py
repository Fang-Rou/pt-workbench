# -*- coding: utf-8 -*-
"""修正提交表单 level=2(高危) 并回读全字段。用法: fix_level.py
"""
from __future__ import annotations

import asyncio
import json
import sys
import urllib.request

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from cdp import CDP  # noqa: E402


async def main() -> int:
    tabs = json.loads(urllib.request.urlopen("http://127.0.0.1:9223/json/list", timeout=5).read())
    tgt = next((t for t in tabs if "/Loo/submit" in t.get("url", "")), None)
    if not tgt:
        print("NO_SUBMIT_TAB")
        return 1
    cdp = await CDP.connect()
    sid = (await cdp.cmd("Target.attachToTarget", {"targetId": tgt["id"], "flatten": True}))["sessionId"]
    st = await cdp.eval_js(sid, """(function(){
      const sel = document.querySelector('select[name="level"]');
      if (!sel) return 'MISS';
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
      setter.call(sel, '2');
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      return 'set-to-' + sel.value;
    })()""")
    print("level fix:", st, flush=True)
    await asyncio.sleep(2)
    v = await cdp.eval_js(sid, """(function(){
      const g = s => { const el = document.querySelector(s); return el ? el.value : null; };
      return {
        company: g('input[name="company_name"]'),
        host: g('input[name="host"]'),
        title: g('#title'),
        level: g('select[name="level"]'),
        type: g('select[name="type"]'),
        attr: g('select[name="attribute"]'),
        detailLen: g('textarea[name="detail"]') ? g('textarea[name="detail"]').length : -1,
        repairLen: g('textarea[name="repair_suggest"]') ? g('textarea[name="repair_suggest"]').length : -1,
        anon: (function(){const a=document.querySelector('input[name="anonymous"]');return a?a.checked:null;})(),
        agree: (function(){const a=document.querySelector('input[name="agree"]');return a?a.checked:null;})()
      };
    })()""")
    print("verify:", json.dumps(v, ensure_ascii=False), flush=True)
    await cdp.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
