# -*- coding: utf-8 -*-
"""把 FineCMS SQLi 完整复现材料组装到以漏洞命名的交付文件夹。"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "xfdyb-nday-2026-08-20"
DELIV = ROOT.parent / "_交付" / "finecms-cve-2018-6893-checktitle-sqli"

# (源, 目标相对路径)
FILES = [
    (ROOT / "pocs" / "finecms-cve-2018-6893-sqli-README.md", "README-审核员复现指南.md"),
    (ROOT / "pocs" / "finecms-cve-2018-6893-sqli-v2.md", "报告-finecms-cve-2018-6893-sqli.md"),
    (ROOT / "pocs" / "finecms_cve_2018_6893_poc.py", "复现脚本/finecms_cve_2018_6893_poc.py"),
    (ROOT / "scripts" / "xfdyb_blind_dump.py", "攻击脚本/xfdyb_blind_dump.py"),
    # 复现过程（真实请求 + 实测耗时）
    (OUT / "repro-1-baseline.png", "真实截图/复现-①基线-0.26s.png"),
    (OUT / "repro-2-sleep4.png", "真实截图/复现-②sleep4-实测4.27s.png"),
    (OUT / "repro-3-if-true.png", "真实截图/复现-③if(1=1)-实测2.27s.png"),
    (OUT / "repro-4-if-false.png", "真实截图/复现-④if(1=2)-实测0.26s.png"),
    # 爆破过程（真实提取日志）
    (OUT / "extract-1-dbname.png", "真实截图/爆破-①数据库名.png"),
    (OUT / "extract-2-tables.png", "真实截图/爆破-②表名.png"),
    (OUT / "extract-3-columns.png", "真实截图/爆破-③字段名.png"),
    (OUT / "extract-4-member.png", "真实截图/爆破-④会员凭据.png"),
    (OUT / "extract-5-news.png", "真实截图/爆破-⑤文章标题.png"),
    # 厂商归属
    (OUT / "vendor-1-home.png", "真实截图/厂商-①首页.png"),
    (OUT / "vendor-2-about.png", "真实截图/厂商-②关于鑫富达.png"),
    (OUT / "vendor-3-contact.png", "真实截图/厂商-③联系我们.png"),
    # 原始记录
    (OUT / "blind-dump.json", "原始记录/blind-dump.json"),
    (OUT / "blind-extract-v2.log", "原始记录/blind-extract-v2.log"),
    (OUT / "excerpts.json", "原始记录/excerpts.json"),
    (OUT / "channel-probe-2026-08-20.json", "原始记录/channel-probe-WAF探测.json"),
]


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if DELIV.exists():
        # 容错清理（Explorer/杀软可能占用文件夹句柄，rmtree 会失败；逐文件删除并忽略锁定）
        for p in sorted(DELIV.rglob("*"), key=lambda x: -len(str(x))):
            try:
                if p.is_dir():
                    p.rmdir()
                else:
                    p.unlink()
            except (PermissionError, OSError):
                pass
    DELIV.mkdir(parents=True, exist_ok=True)
    ok, miss = 0, 0
    for src, rel in FILES:
        dst = DELIV / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.exists():
            shutil.copy2(src, dst)
            ok += 1
        else:
            print("MISSING:", src)
            miss += 1
    print(f"组装完成: {DELIV}  ({ok} 个文件, {miss} 缺失)")
    return 0 if miss == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
