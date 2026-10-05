# -*- coding: utf-8 -*-
r"""health_check.py - 工作区运行时体检（重装/换 Python 后必跑一次）。

查六项：
  1. 全部 scripts/*.py 语法编译（换 Python 版本最易炸的地方）
  2. 共享模块可导入性（cdp / net_helper / workspace_db / vision_qa / submit_common …）
  3. 第三方依赖可用性（requests/urllib3/websockets/pymysql/Crypto/redis/cryptography/PIL/bs4/certifi）
  4. CDP 浏览器链路（9223 端口 → Target.getTargets → 新建页 → eval_js）
  5. 外部运行时（node/npm/git/chrome 可执行文件定位）
  6. 关键闸门脚本可运行性（preflight / sync_skills / check_lessons_wired / maintain）

退出码：0=全绿，1=有 FAIL。WARN 不影响退出码。
用法: python scripts\health_check.py [--json out.json]
"""
from __future__ import annotations

import asyncio
import importlib
import json
import py_compile
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
RESULTS = {"ts": None, "sections": {}}
FAILS: list[str] = []
WARNS: list[str] = []


def sec(name: str, data):
    RESULTS["sections"][name] = data
    return data


def ok(msg): print("  [PASS] %s" % msg)
def bad(msg): print("  [FAIL] %s" % msg); FAILS.append(msg)
def warn(msg): print("  [WARN] %s" % msg); WARNS.append(msg)


print("=" * 74)
print("1) 语法编译：scripts/*.py")
bad_files = []
all_py = sorted(SCRIPTS.glob("*.py"))
for p in all_py:
    try:
        py_compile.compile(str(p), cfile=str(Path(tempfile.gettempdir()) / "hc.pyc"),
                           doraise=True, optimize=0)
    except py_compile.PyCompileError as e:
        bad_files.append({"file": p.name, "err": str(e).splitlines()[-1][:160]})
    except Exception as e:
        bad_files.append({"file": p.name, "err": "%s: %s" % (type(e).__name__, str(e)[:140])})
sec("compile", {"total": len(all_py), "failed": bad_files})
if bad_files:
    for b in bad_files[:20]:
        bad("编译失败 %s :: %s" % (b["file"], b["err"]))
    if len(bad_files) > 20:
        bad("… 共 %d 个编译失败" % len(bad_files))
else:
    ok("全部 %d 个脚本编译通过" % len(all_py))

print()
print("2) 共享模块导入")
sys.path.insert(0, str(SCRIPTS))
for m in ("cdp", "net_helper", "workspace_db", "vision_qa", "engagement", "recon_api"):
    try:
        importlib.import_module(m)
        ok("import %s" % m)
    except Exception as e:
        bad("import %s :: %s: %s" % (m, type(e).__name__, str(e)[:130]))
sec("modules", {"checked": ["cdp", "net_helper", "workspace_db", "vision_qa", "engagement", "recon_api"]})

print()
print("3) 第三方依赖")
dep_status = {}
for m in ("requests", "urllib3", "websockets", "pymysql", "Crypto", "redis", "cryptography",
          "PIL", "bs4", "certifi", "yaml", "dns", "playwright", "mitmproxy"):
    try:
        importlib.import_module(m)
        dep_status[m] = "OK"
    except Exception:
        dep_status[m] = "MISSING"
for m, s in dep_status.items():
    core = m in ("requests", "urllib3", "websockets", "pymysql", "Crypto", "redis", "cryptography",
                 "PIL", "bs4", "certifi")
    if s == "OK":
        ok("%-14s %s" % (m, s))
    elif core:
        bad("%-14s %s（工作流核心依赖）" % (m, s))
    else:
        warn("%-14s %s（按需再装）" % (m, s))
sec("deps", dep_status)

print()
print("4) CDP 浏览器链路 (127.0.0.1:9223)")
try:
    with socket.create_connection(("127.0.0.1", 9223), timeout=3):
        ok("9223 端口可连")
    sys.path.insert(0, str(SCRIPTS))
    from cdp import CDP  # noqa: E402

    async def cdp_probe():
        cdp = await CDP.connect()
        ver = await cdp.cmd("Browser.getVersion", {})
        tid, sid = await cdp.new_page("about:blank")
        r = await cdp.eval_js(sid, "1+1")
        await cdp.cmd("Target.closeTarget", {"targetId": tid})
        await cdp.close()
        return ver, r
    ver, r = asyncio.run(cdp_probe())
    ok("Browser.getVersion: %s" % (ver or {}).get("product", "?"))
    ok("eval_js('1+1') -> %s" % r)
    sec("cdp", {"port": True, "product": (ver or {}).get("product"), "eval": r})
except Exception as e:
    bad("CDP 链路失败 :: %s: %s" % (type(e).__name__, str(e)[:150]))
    sec("cdp", {"error": str(e)[:200]})

print()
print("5) 外部运行时")
extern = {}
for c in ("node", "npm", "git", "chrome", "powershell"):
    path = shutil.which(c)
    extern[c] = path or "MISSING"
    (ok if path else warn)("%-11s %s" % (c, path or "未在 PATH（Chrome 由 chrome-profile 启动亦可）"))
# Chrome 实际二进制（CDP 在用）
cands = [Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
         Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
         Path.home() / r"AppData\Local\Google\Chrome\Application\chrome.exe"]
found = next((str(p) for p in cands if p.exists()), None)
(ok if found else warn)("chrome.exe 实体 %s" % (found or "未找到（但 9223 已在跑，说明别处启动）"))
extern["chrome_exe"] = found
sec("extern", extern)

# 2026-09-18 加：**工具链事实**（一次告知，别再用一轮工具调用去踩）
# 动机：当天为了反编译一个 APK，连踩三次环境坑 —— ① pwsh 不存在（要用 powershell）
# ② 默认 java 是 JRE 8（jadx 1.5.1 要 11+）③ .cmd/.ps1 不能带非 ASCII。
# 这些事实本该开场就知道，而不是在需要的时候一个个试出来。
print()
print("5b) 工具链事实（脚本/反编译常用）")
tc = {}
ps7 = shutil.which("pwsh")
tc["pwsh"] = ps7 or "MISSING"
(ok if ps7 else warn)("%-14s %s" % ("pwsh(PS7)", ps7 or "未装 —— **脚本里要用 powershell(5.1)**，且 .ps1 必须纯 ASCII 或带 BOM"))
javas = []
for j in (r"C:\Program Files\Java\jdk-17\bin\java.exe",
          r"C:\Program Files\Java\jdk-19\bin\java.exe",
          r"C:\Program Files\Java\jre1.8.0_491\bin\java.exe"):
    if Path(j).exists():
        javas.append(j)
tc["jdk11+"] = javas[0] if javas and "jre" not in javas[0].lower() else "MISSING"
(ok if tc["jdk11+"] != "MISSING" else warn)("%-14s %s" % ("jdk11+", tc["jdk11+"] or "未找到（jadx 需要）"))
tc["java_default"] = shutil.which("java") or "MISSING"
(ok if tc["java_default"] != "MISSING" else warn)("%-14s %s（注意可能只是 JRE 8）" % ("java(default)", tc["java_default"]))
jadx = Path(r"D:\tool\mobile\jadx\bin\jadx.bat")
tc["jadx"] = str(jadx) if jadx.exists() else "MISSING"
(ok if jadx.exists() else warn)("%-14s %s" % ("jadx", tc["jadx"]))
sec("toolchain", tc)

print()
print("6) 关键闸门脚本可运行性")
gates = ["scope_gate.py", "engagement.py", "sync_skills.py", "check_lessons_wired.py",
         "maintain.py", "check_delivery_consistency.py", "report_gate.py",
         "resume.py", "next.py", "job.py", "checkpoint.py"]
# 每个闸门给"最轻且无副作用"的探针参数：
#   手写 argv 的脚本不认 --help（会把它当目标目录 → FAIL/rc=2），必须无参跑；
#   sync_skills 无参会真的做同步，故用 --check。
GATE_ARGS = {
    "scope_gate.py": ["--show"],
    "engagement.py": ["list"],
    "sync_skills.py": ["--check"],
    "check_lessons_wired.py": [],
    "maintain.py": [],
    "check_delivery_consistency.py": [],
    "report_gate.py": ["--help"],
    "resume.py": [],
    "next.py": [],
    "job.py": [],
    "checkpoint.py": ["--help"],
}
gate_res = {}
for g in gates:
    p = SCRIPTS / g
    if not p.exists():
        bad("%-34s 文件缺失" % g); gate_res[g] = "MISSING"; continue
    try:
        r = subprocess.run([sys.executable, str(p)] + GATE_ARGS.get(g, ["--help"]), cwd=str(ROOT),
                           capture_output=True, timeout=90)
        txt = ((r.stderr or b"") + b"\n" + (r.stdout or b"")).decode("utf-8", "replace")
        # 判据：**有没有崩栈**。返回码 1/2 往往是"缺参数/条件不满足"，属正常业务码。
        crashed = "Traceback (most recent call last)" in txt or r.returncode is None
        gate_res[g] = ("CRASH rc=%s" % r.returncode) if crashed else "OK rc=%s" % r.returncode
        (bad if crashed else ok)("%-34s %s" % (g, gate_res[g]))
        if crashed:
            print("        %s" % txt.strip().splitlines()[-1][:160])
    except Exception as e:
        gate_res[g] = "ERR " + type(e).__name__
        bad("%-34s %s" % (g, gate_res[g]))
sec("gates", gate_res)

print()
print("=" * 74)
print("VERDICT: %s   (FAIL=%d, WARN=%d)" % ("PASS" if not FAILS else "FAIL", len(FAILS), len(WARNS)))
if WARNS:
    print("WARN 明细:")
    for w in WARNS:
        print("  -", w)
RESULTS["fails"] = FAILS
RESULTS["warns"] = WARNS
RESULTS["verdict"] = "PASS" if not FAILS else "FAIL"
import datetime  # noqa: E402
RESULTS["ts"] = datetime.datetime.now().isoformat(timespec="seconds")
out = ROOT / "state" / "health-check.json"
out.write_text(json.dumps(RESULTS, ensure_ascii=False, indent=1), "utf-8")
print("落盘:", out)
sys.exit(0 if not FAILS else 1)
