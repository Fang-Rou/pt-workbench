# -*- coding: utf-8 -*-
"""窗口级证据截图：OS 级整屏截图，含浏览器地址栏 + 任务栏时钟。

背景（2026-09-01 修正）：CDP Page.captureScreenshot 只截视口、无地址栏；
旧方案"页面内注入 URL 横幅"是自注入内容，伪造成本为零、证明力为零。
本工具的证明来自浏览器渲染层（页面 JS 无法伪造）：

  1. 纯导航模式：浏览器真实导航到攻击 URL，地址栏由浏览器渲染
  2. OS 级 CopyFromScreen 整屏截图：地址栏 + 页面响应 + 任务栏时钟（时间戳）
  3. sidecar JSON 记录浏览器侧 target URL（/json/list 报告，非页面注入）
  4. --pdf：printToPDF 带浏览器渲染的 URL 页眉（第二证明层）
  5. --ocr：OCR 自验地址栏含目标 host，不含 = 截图无效（FAIL）

用法（在 _PT工作台 下）:
  # 纯导航（GET 型漏洞首选，零注入）
  python scripts/evidence_shot_window.py --url "https://t/api/leak" --label api-leak --ocr
  # 附加到已有标签页（如 evidence_shot.py 渲染完响应后补窗口截图）
  python scripts/evidence_shot_window.py --url-substr "zxaimall" --label openapi-window --ocr
  # 需要带 token/POST 的请求：先 evidence_shot.py 渲染，再 attach 本工具

产物: results/<label>-<date>/window-<stamp>.png + window.json (+ url-header.pdf + ocr.txt)
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
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cdp import CDP  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

PS_BODY = r"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$b = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap($b.Width, $b.Height)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($b.X, $b.Y, 0, 0, $bmp.Size)
$g.Dispose()
$bmp.Save('__OUT__', [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output ('CAPTURED ' + $b.Width + 'x' + $b.Height)
"""


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="窗口级证据截图（含地址栏）")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--url", help="纯导航模式：新开标签页直接访问该 URL（零注入）")
    mode.add_argument("--url-substr", help="附加模式：匹配已开标签页 URL 子串")
    mode.add_argument("--tab", type=int, help="附加模式：第 N 个标签页")
    ap.add_argument("--label", default="evidence-window", help="产物标签")
    ap.add_argument("--wait", type=float, default=3.0, help="导航后等待秒数")
    ap.add_argument("--pdf", action="store_true", help="另存 printToPDF（浏览器渲染 URL 页眉）")
    ap.add_argument("--ocr", action="store_true", help="OCR 自验地址栏含目标 host")
    ap.add_argument("--scroll-bottom", action="store_true", help="截图前滚到底部（页脚场景）")
    ap.add_argument("--scroll-to", help="滚动到含该关键词的元素再截图（如 主办单位）")
    ap.add_argument("--keep", action="store_true", help="导航模式结束后保留标签页")
    return ap.parse_args()


def browser_tabs() -> list[dict]:
    with urllib.request.urlopen("http://127.0.0.1:9223/json/list", timeout=5) as r:
        return [t for t in json.loads(r.read()) if t.get("type") == "page"]


PS_FOREGROUND = r"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class FG {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
}
'@
$procs = Get-CimInstance Win32_Process -Filter "name='chrome.exe'" |
  Where-Object { $_.CommandLine -match 'chrome-cdp-profile|chrome-profile' -and $_.CommandLine -match 'remote-debugging-port' }
$wsh = New-Object -ComObject WScript.Shell
$done = $false
foreach ($p in $procs) {
  $gp = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
  if ($gp -and $gp.MainWindowHandle -ne 0) {
    for ($i = 0; $i -lt 5; $i++) {
      $wsh.AppActivate($p.ProcessId) | Out-Null
      [FG]::ShowWindow($gp.MainWindowHandle, 3) | Out-Null       # 3 = SW_MAXIMIZE
      [FG]::SetForegroundWindow($gp.MainWindowHandle) | Out-Null
      Start-Sleep -Milliseconds 800
      $fg = [FG]::GetForegroundWindow()
      $fpid = [uint32]0
      [FG]::GetWindowThreadProcessId($fg, [ref]$fpid) | Out-Null
      if ([int]$fpid -eq [int]$p.ProcessId) {
        Write-Output ('FG-OK pid=' + $p.ProcessId + ' try=' + $i + ' title=' + $gp.MainWindowTitle)
        $done = $true
        break
      }
    }
  }
  if ($done) { break }
}
if (-not $done) { Write-Output 'FG-FAILED-NOT-FOREGROUND' }
"""


def force_chrome_foreground() -> None:
    p = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", PS_FOREGROUND],
        capture_output=True, timeout=30)
    print("foreground:", p.stdout.decode("utf-8", errors="replace").strip())


def os_capture(out_png: Path) -> bool:
    ps = ("$ErrorActionPreference='Stop';" + PS_BODY).replace(
        "__OUT__", str(out_png).replace("'", "''")
    )
    p = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        capture_output=True, timeout=60,
    )
    ok = out_png.exists() and out_png.stat().st_size > 20_000
    print("capture:", p.stdout.decode("utf-8", errors="replace").strip(),
          "OK" if ok else f"FAIL({p.returncode})")
    if not ok and p.stderr:
        print("stderr:", p.stderr.decode("utf-8", errors="replace")[:300])
    return ok


def _norm_ocr(s: str) -> str:
    """OCR 混淆字符归一化：i/l/1、o/0、s/5、b/6 等常见误读统一。"""
    s = s.lower()
    table = str.maketrans({"l": "i", "1": "i", "0": "o", "5": "s", "6": "b", "2": "z", "：": ":", "．": "."})
    s = s.translate(table)
    return "".join(ch for ch in s if ch.isalnum())


def run_ocr(png: Path, expect_host: str) -> bool:
    ps1 = ROOT / "scripts" / "ocr_image.ps1"
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", str(ps1), "-ImagePath", str(png)],
            capture_output=True, timeout=120)
        text = p.stdout.decode("utf-8", errors="replace")
        (png.parent / (png.stem + "-ocr.txt")).write_text(text, "utf-8")
        hit = _norm_ocr(expect_host) in _norm_ocr(text) or _norm_ocr(expect_host.replace("www.", "")) in _norm_ocr(text)
        print(f"OCR 地址栏校验: {'PASS' if hit else 'FAIL'} (期望含 {expect_host})")
        print("ocr head:", text[:200].replace("\n", " "))
        return hit
    except Exception as e:
        print("OCR 失败（人工核对地址栏）:", e)
        return False


async def dismiss_cert_warning(cdp, sid) -> bool:
    """穿越 Chrome 证书警告页（net::ERR_CERT_*）。

    2026-09-12 新增：目标证书不被信任时（如 am-982-cab.aimatech.com），
    Chrome 会停在「您的连接不是私密连接」 interstitial，窗口级截图截到的就是这张警告页，
    证据等于废掉。这里点「高级」→「继续前往」把真页面放出来。
    """
    probe = ("(function(){var t=(document.body?document.body.innerText:'')||'';"
             "var w=(location.href.indexOf('chrome-error://')===0)||/不是私密连接|不是私密|NET::ERR_CERT|Privacy error|not private/i.test(t);"
             "return w?'WARN':'OK';})()")
    try:
        state = await cdp.eval_js(sid, probe)
    except Exception:
        return False
    if state != 'WARN':
        return False
    print('cert-warning: 检测到证书警告页，尝试穿越')
    try:
        await cdp.eval_js(sid, "(function(){var d=document.querySelector('#details-button');if(d)d.click();return 1;})()")
        await asyncio.sleep(1.2)
        r = await cdp.eval_js(sid, ("(function(){var p=document.querySelector('#proceed-link');"
                                 "if(p){p.click();return 'PROCEED';}"
                                 "var a=Array.prototype.slice.call(document.querySelectorAll('a,button')).find(function(e){return /继续前往|Proceed|Advanced|高级/.test(e.innerText||'');});"
                                 "if(a){a.click();return 'ALT';}return 'NO_BTN';})()"))
        print('cert-warning: 点击结果 =', r)
        await asyncio.sleep(4.5)
        return True
    except Exception as e:
        print('cert-warning: 穿越失败', str(e)[:80])
        return False

async def main() -> int:
    args = parse_args()
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = ROOT / "results" / f"{args.label}-{stamp[:8]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    shot_png = out_dir / f"window-{stamp}.png"

    cdp = await CDP.connect()
    close_after = False
    if args.url:
        tid, sid = await cdp.new_page(args.url)
        close_after = not args.keep
        await asyncio.sleep(args.wait)
        await dismiss_cert_warning(cdp, sid)   # 证书警告页会把证据截图毁掉，先穿越
    else:
        tabs = browser_tabs()
        if not tabs:
            print("FAIL: 无可用标签页")
            return 2
        if args.url_substr:
            hits = [t for t in tabs if args.url_substr.lower() in t.get("url", "").lower()]
            if not hits:
                print("FAIL: 无匹配标签页:", [t.get("url", "")[:60] for t in tabs][:5])
                return 2
            tab = hits[0]
        else:
            if args.tab > len(tabs):
                print(f"FAIL: --tab {args.tab} 越界（共 {len(tabs)} 个）")
                return 2
            tab = tabs[args.tab - 1]
        tid, tab_url, tab_title = tab["id"], tab.get("url", ""), tab.get("title", "")
        att = await cdp.cmd("Target.attachToTarget", {"targetId": tid, "flatten": True})
        sid = att["sessionId"]

    # 浏览器侧 target 信息（非页面注入）
    info = {"url": "", "title": ""}
    try:
        ti = await cdp.cmd("Target.getTargetInfo", {"targetId": tid})
        info = {"url": ti["targetInfo"].get("url", ""), "title": ti["targetInfo"].get("title", "")}
    except Exception:
        if not args.url:
            info = {"url": tab_url, "title": tab_title}

    if args.scroll_bottom:
        await cdp.eval_js(sid, "(function(){window.scrollTo(0, document.body.scrollHeight);return document.body.scrollHeight;})()")
        await asyncio.sleep(1.5)
    if args.scroll_to:
        st = await cdp.eval_js(sid, """
        (function(){
          var kw = %s;
          var els = Array.from(document.querySelectorAll('td,th,div,span,li,p,h1,h2,h3,a,label,em,strong,b,small'));
          var e = els.find(function(x){ return x.textContent.indexOf(kw) >= 0 && x.children.length === 0; });
          if (e) { e.scrollIntoView({block:'center'}); return 'OK'; }
          return 'NOT-FOUND';
        })()
        """ % json.dumps(args.scroll_to))
        print("scroll-to:", st)
        await asyncio.sleep(1.0)

    # 页面全文落盘（机器核验内容：主办单位等关键字段）
    try:
        txt = await cdp.eval_js(sid, "(function(){return (document.body?document.body.innerText:'').slice(0,8000);})()")
        if txt:
            (out_dir / f"window-{stamp}.txt").write_text(str(txt), "utf-8")
    except Exception:
        pass

    # 激活到前台再 OS 截屏（地址栏 + 任务栏时钟入镜）
    await cdp.cmd("Target.activateTarget", {"targetId": tid})
    await asyncio.sleep(1.0)
    force_chrome_foreground()
    await asyncio.sleep(0.8)
    ok = os_capture(shot_png)

    pdf_path = None
    if args.pdf:
        try:
            res = await cdp.cmd(
                "Page.printToPDF",
                {"displayHeaderFooter": True,
                 "headerTemplate": '<div style="font-size:9px;width:100%;text-align:center;"><span class="url"></span></div>',
                 "footerTemplate": "<span></span>", "printBackground": True},
                session_id=sid, timeout=60)
            pdf_path = out_dir / f"url-header-{stamp}.pdf"
            pdf_path.write_bytes(base64.b64decode(res["data"]))
            print("pdf saved:", pdf_path.name)
        except Exception as e:
            print("pdf 失败（不影响 PNG）:", str(e)[:200])

    sidecar = {
        "tool": "evidence_shot_window.py",
        "method": "os-copyfromscreen(virtual-screen)",
        "browser_reported_url": info["url"],
        "browser_reported_title": info["title"],
        "proof_layers": ["L2: 地址栏(浏览器渲染)", "L3: sidecar(浏览器侧target信息)"],
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "png": shot_png.name, "pdf": pdf_path.name if pdf_path else None,
        "note": "URL 证明来自浏览器地址栏(页面JS不可伪造)；时钟提供时间戳。横幅/标注不作为证明。",
    }
    (out_dir / "window.json").write_text(json.dumps(sidecar, ensure_ascii=False, indent=2), "utf-8")
    print("url(browser):", info["url"][:130])

    if close_after:
        await cdp.cmd("Target.closeTarget", {"targetId": tid})
    await cdp.close()

    ocr_ok = True
    if args.ocr and ok and info["url"].startswith("http"):
        host = urlparse(info["url"]).netloc
        ocr_ok = run_ocr(shot_png, host)

    if not ok:
        print("RESULT: FAIL（截屏失败或过小；确认 Chrome 在前台）")
        return 3
    if not ocr_ok:
        print("RESULT: FAIL（OCR 未见目标 host，截图可能没对准前台窗口）")
        return 4
    print("DONE dir=", out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
