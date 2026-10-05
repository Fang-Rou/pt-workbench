#!/usr/bin/env python3
"""Print a compact resume card for an interrupted or archived thread.

Run this first in a new thread, before next.py, whenever state/resume.md exists.
"""

from __future__ import annotations

import sys
from pathlib import Path

import workspace_db


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    resume_path = workspace_db.STATE_DIR / "resume.md"
    if resume_path.exists():
        print(resume_path.read_text(encoding="utf-8"))
    else:
        print("# RESUME")
        print("")
        print("- 未找到 state/resume.md；先执行 checkpoint 生成续接卡：")
        print(f"- {sys.executable} scripts/checkpoint.py --next \"<下一步动作>\"")
        print("")

    conn = workspace_db.connect()
    active = [
        j
        for j in workspace_db.list_jobs(conn, limit=20)
        if j["status"] in ("pending", "running")
    ]
    conn.close()
    print("## 实时后台作业")
    if active:
        for j in active:
            print(
                f"- [{j['status']}] #{j['id']} {j['name']} "
                f"log={j['log_path'] or '-'}"
            )
    else:
        print("- (none)")
    print("")
    print("## 新线程开场白（可直接粘贴）")
    print(
        f"> 只读 `state/BRIEF.md` 和 `state/resume.md`；执行 `{sys.executable} scripts/resume.py`、"
        f"`{sys.executable} scripts/next.py`；按 `state/WORKFLOW.md` 的防中断规则继续。"
        f"禁止整读 raw/ 大文件；长任务用 `{sys.executable} scripts/job.py start` 后台运行。"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
