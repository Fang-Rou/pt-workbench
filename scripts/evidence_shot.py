# -*- coding: utf-8 -*-
"""通用证据截图工具：挖到关键漏洞后【立即】留证，提交时无需返工。

用法（在 _PT工作台 下）:
  python scripts/evidence_shot.py --url "https://target/api/leak" ^
      --token "eyJ..." --cookie "session=xxx" --label shops-leak

行为：
  1. CDP 新开标签页，地址栏 = 真实攻击 URL（浏览器直连）
  2. 页面内 fetch 携带真实 Authorization/Cookie 重新请求并渲染
     （HTTP 状态码 + 完整响应体，纯真实服务器数据）
  3. Page.captureScreenshot 截图 PNG（真实攻击页面）
  4. 响应体/页面文本落盘 .txt/.json
  5. 可选 --ocr：自动调用 ocr_image.ps1 做 Windows OCR 自验证
  6. 关闭标签页，打印产物路径（供 OCR 二次核验）

产物目录：results/<label>-<date>/shot.png + shot.txt + shot.json + ocr.txt(可选)
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import subprocess
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cdp import CDP  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", required=True, help="真实攻击 URL（地址栏将显示它）")
    ap.add_argument("--token", default="", help="Bearer token（可选）")
    ap.add_argument("--cookie", default="", help="Cookie（可选）")
    ap.add_argument("--headers", default="{}", help='附加请求头 JSON，如 {"X-Id":"1"}')
    ap.add_argument("--method", default="GET", help="HTTP 方法（默认 GET；POST 需配 --body）")
    ap.add_argument("--body", default="", help="请求体字符串（POST 时作为 fetch body）")
    ap.add_argument("--body-file", dest="body_file", default="", help="请求体文件路径（优先于 --body，规避 shell 引号问题）")
    ap.add_argument("--ctype", default="application/json", help="POST 时的 Content-Type")
    ap.add_argument("--label", default="evidence", help="产物标签（目录名/文件名）")
    ap.add_argument("--out", default="", help="输出目录（默认 results/<label>-<date>/）")
    ap.add_argument("--wait", type=float, default=3.0, help="fetch 后等待秒数")
    ap.add_argument("--ocr", action="store_true", help="截图后自动跑 Windows OCR 自验证")
    return ap.parse_args()


async def main() -> int:
    args = parse_args()
    if args.body_file:
        args.body = Path(args.body_file).read_text("utf-8")
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out) if args.out else ROOT / "results" / f"{args.label}-{stamp[:10]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    label = args.label
    shot_png = out_dir / f"{label}.png"
    shot_txt = out_dir / f"{label}.txt"
    shot_json = out_dir / f"{label}.json"

    try:
        extra_headers = json.loads(args.headers)
    except json.JSONDecodeError:
        print("ERROR: --headers 不是合法 JSON")
        return 2

    cdp = await CDP.connect()
    tid, sid = await cdp.new_page(args.url)
    await asyncio.sleep(3)

    headers = dict(extra_headers)
    headers.setdefault("Accept", "application/json")
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.method.upper() != "GET" and args.body:
        headers.setdefault("Content-Type", args.ctype)

    # 页面内 fetch：浏览器真实发出，服务器真实响应（支持 GET/POST）
    _init = {"method": args.method.upper(), "headers": dict(headers)}
    if args.method.upper() != "GET" and args.body:
        _init["body"] = args.body
    st = await cdp.eval_js(sid, f"""
    (async function(){{
      const resp = await fetch({json.dumps(args.url)}, {json.dumps(_init)});
      const text = await resp.text();
      const esc = text.replace(/&/g,'&amp;').replace(/</g,'&lt;');
      document.body.innerHTML =
        '<pre style="font:12px monospace;white-space:pre-wrap;padding:16px;background:#fff;color:#000;margin:0">' +
        'URL: {json.dumps(args.url)}\\nHTTP: ' + resp.status + ' ' + resp.statusText + '\\n\\n' + esc +
        '</pre>';
      return {{ status: resp.status, len: text.length, head: text.slice(0, 500) }};
    }})()
    """)
    if isinstance(st, dict) and "__error__" in st:
        print("FETCH ERROR:", st["__error__"])
        await cdp.cmd("Target.closeTarget", {"targetId": tid})
        await cdp.close()
        return 3
    print("fetch:", json.dumps(st, ensure_ascii=False)[:400])
    await asyncio.sleep(args.wait)

    st2 = await cdp.eval_js(sid, r"""
    (function(){ return { url: location.href, body: (document.body ? document.body.innerText : '').slice(0, 6000) }; })()
    """)
    st2 = st2 or {}
    print("url:", (st2.get("url") or "")[:130])
    print("body head:", ((st2.get("body") or "")[:260]).replace("\n", " "))

    res = await cdp.cmd("Page.captureScreenshot", {"format": "png"}, session_id=sid, timeout=60)
    shot_png.write_bytes(base64.b64decode(res["data"]))
    shot_txt.write_text(f"url: {st2.get('url','')}\n\n{st2.get('body','')}", "utf-8")
    shot_json.write_text(json.dumps({
        "label": label, "url": args.url, "status": (st or {}).get("status"),
        "resp_len": (st or {}).get("len"), "headers": headers,
        "captured_at": datetime.now().isoformat(timespec="seconds"),
    }, ensure_ascii=False, indent=2), "utf-8")
    print(f"saved: {shot_png} ({shot_png.stat().st_size} bytes)")
    print(f"saved: {shot_txt}")

    await cdp.cmd("Target.closeTarget", {"targetId": tid})
    await cdp.close()

    if args.ocr:
        ocr_ps1 = ROOT / "scripts" / "ocr_image.ps1"
        try:
            p = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(ocr_ps1), "-ImagePath", str(shot_png)],
                capture_output=True, timeout=120)
            ocr_txt = p.stdout.decode("utf-8", errors="replace")
            (out_dir / f"{label}-ocr.txt").write_text(ocr_txt, "utf-8")
            print("OCR saved:", out_dir / f"{label}-ocr.txt")
            print(ocr_txt[:800])
        except Exception as e:
            print("OCR auto-run failed (可手动跑 ocr_image.ps1):", e)

    print("DONE dir=", out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
