#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量第一跳驱动：对 state/jdy-next-hosts.txt 全量跑多条 path 引擎手法。"""
import subprocess, sys, time
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(r"D:\渗透工作流\_PT工作台")
PY = ROOT / ".venv" / "Scripts" / "python.exe"
HOSTS_FILE = ROOT / "state" / "jdy-next-hosts.txt"
hosts = [h.strip() for h in HOSTS_FILE.read_text(encoding="utf-8").split() if h.strip()]
print("主机数:", len(hosts), flush=True)
WEAPONS = [("F", "Actuator 三级跳"), ("H", ".git 源码泄露"), ("O", "未授权运维面板"), ("P", "OpenAPI/Swagger 公开"), ("A", "匿名制品仓")]
for wp, name in WEAPONS:
    print("", flush=True)
    print("=" * 72, flush=True)
    print("### 手法 %s — %s  (%d 台)" % (wp, name, len(hosts)), flush=True)
    t0 = time.time()
    try:
        p = subprocess.run([str(PY), str(ROOT / "scripts" / "arsenal.py"), "scan",
                            "--weapon", wp, "--hosts"] + hosts + ["--apply"],
                           cwd=str(ROOT), timeout=5400,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode("utf-8", "replace")
        print(out[-4000:], flush=True)
        print("(exit=%d, %.0fs)" % (p.returncode, time.time() - t0), flush=True)
    except Exception as e:
        print("ERR", str(e)[:150], flush=True)
    time.sleep(3)
print("", flush=True)
print("[done] BATCH-SCAN-ALL-END", flush=True)
