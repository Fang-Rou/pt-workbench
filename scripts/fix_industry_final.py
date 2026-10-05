# -*- coding: utf-8 -*-
"""修正行业字段为 制造业（医药包装公司），并做提交前最终确认。"""
from __future__ import annotations

import asyncio
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cdp import CDP  # noqa: E402


async def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cdp = await CDP.connect()
    tabs = json.loads(urllib.request.urlopen("http://127.0.0.1:9223/json/list", timeout=5).read())
    tgt = next((t for t in tabs if "/Loo/submit" in t.get("url", "")), None)
    if not tgt:
        print("NO_SUBMIT_TAB"); return 1
    sid = (await cdp.cmd("Target.attachToTarget", {"targetId": tgt["id"], "flatten": True}))["sessionId"]

    # 行业改为 制造业（医药包装 → 制造业）
    r = await cdp.eval_js(sid, r"""
    (function(){
      const sel = document.querySelector('select[name="industryLoo1"]');
      if (!sel) return 'MISS';
      let opt = Array.from(sel.options).find(o => o.text.trim() === '制造业')
             || Array.from(sel.options).find(o => /医药|制药|包装/.test(o.text.trim()));
      if (!opt) return 'NO_OPT: ' + Array.from(sel.options).map(o=>o.text.trim()).join('|');
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
      setter.call(sel, opt.value);
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      return 'set -> ' + opt.text.trim() + ' (value=' + opt.value + ')';
    })()
    """)
    print("行业修正:", r, flush=True)
    await asyncio.sleep(1)

    # 最终确认
    v = await cdp.eval_js(sid, r"""
    (function() {
      const g = s => { const el = document.querySelector(s); return el ? el.value : null; };
      let ue0Imgs = -1;
      try { const ue = UE.instants && UE.instants['ueditorInstant0']; if (ue) ue0Imgs = (ue.getContent().match(/<img[^>]+src=/g)||[]).length; } catch(e){}
      return {
        attribute: (function(){const a=document.querySelector('select[name="attribute"]'); return a?a.options[a.selectedIndex].text.trim():null;})(),
        industry: (function(){const i=document.querySelector('select[name="industryLoo1"]'); return i&&i.selectedIndex>=0?i.options[i.selectedIndex].text.trim():null;})(),
        level: (function(){const a=document.querySelector('select[name="level"]'); return a?a.options[a.selectedIndex].text.trim():null;})(),
        type: (function(){const a=document.querySelector('select[name="type"]'); return a?a.options[a.selectedIndex].text.trim():null;})(),
        detailLen: (g('textarea[name="detail"]')||'').length,
        ue0Imgs: ue0Imgs,
        anon: (function(){const a=document.querySelector('input[name="anonymous"]'); return a?a.checked:null;})(),
        agree: (function(){const a=document.querySelector('input[name="agree"]'); return a?a.checked:null;})(),
      };
    })()
    """)
    print("最终确认:", json.dumps(v, ensure_ascii=False), flush=True)
    await cdp.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))