#!/usr/bin/env python3
"""Checkpoint: write a compact BRIEF, optionally archive raw outputs, and print handoff.

Run this before closing a thread or switching targets. A new thread should start by
reading the generated BRIEF only, then use next.py for the immediate action list.

**长文本走 --next-file，不要塞进命令行**（2026-09-21 实测：一天之内被同一个坑咬了三次）:

    $py scripts/checkpoint.py --next-file state/next.txt

原因：`--next "……含 "内层引号" 的文本……"` 在 PowerShell 里会被**内层引号截断** ——
吵的时候表现成 argparse 报 usage，不吵的时候写进 resume.md 的是**半截话**（更坏，没人会发现）。
--next 仍可用，但一旦检测到内层 ASCII 双引号会**直接拒绝**并指路到 --next-file。
中文引号请用「」，它不会触发这个问题。
"""

from __future__ import annotations

import argparse
import shutil
import sys
import zipfile
from datetime import datetime
from pathlib import Path

import workspace_db


def project_targets(conn, project_slug: str | None):
    projects = workspace_db.list_projects(conn)
    if project_slug:
        projects = [p for p in projects if p["slug"] == project_slug]
    for project in projects:
        yield project, workspace_db.list_targets(conn, project_slug=project["slug"])


def raw_paths_for_target(conn, target) -> list[Path]:
    paths: list[Path] = []
    rows = conn.execute(
        "SELECT path FROM raw_artifacts WHERE target_id = ?", (target["id"],)
    ).fetchall()
    for row in rows:
        p = workspace_db.ROOT / row["path"]
        if p.exists():
            paths.append(p)
    conventional = workspace_db.ROOT / "results" / target["slug"]
    if conventional.exists() and conventional not in paths:
        paths.append(conventional)
    return paths


def zip_paths(zip_path: Path, sources: list[Path]) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for src in sources:
            if src.is_dir():
                for file in sorted(src.rglob("*")):
                    if file.is_file():
                        zf.write(file, file.relative_to(src.parent))
            else:
                zf.write(src, src.name)


def build_resume(conn, next_action: str | None) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    active_jobs = [
        j
        for j in workspace_db.list_jobs(conn, limit=10)
        if j["status"] in ("pending", "running")
    ]
    lines = [
        "# RESUME",
        "",
        f"- updated: {stamp}",
        f"- next_action: {next_action or '(see next.py)'}",
        "",
        "## 后台作业",
    ]
    if active_jobs:
        for j in active_jobs:
            lines.append(
                f"- [{j['status']}] #{j['id']} {j['name']} log={j['log_path'] or '-'}"
            )
    else:
        lines.append("- (none)")
    lines += [
        "",
        "## 续接命令",
        f"1. {sys.executable} scripts/resume.py",
        f"2. {sys.executable} scripts/next.py",
        f"3. {sys.executable} scripts/job.py status",
        "",
        "## 新线程开场白",
        f"> 只读 `state/BRIEF.md` 和 `state/resume.md`；执行 `{sys.executable} scripts/resume.py`、`{sys.executable} scripts/next.py`；",
        "> 按 `state/WORKFLOW.md` 的防中断规则继续。禁止整读 raw/ 大文件。",
        "> 指纹命中产品家族先读 `skills/product-playbooks/references/` 对应手册；**新目标动手前先读命中案例库速查表 `skills/pt-engagement/references/hit-case-library-2026.md`**；提交前必过 L0 去重 `scripts/submission_dedupe_check.py`。",
        "> **技能已接线**（21 个已进会话 skill 目录）：命中信号先加载对应技能（见 AGENTS.md「技能库调度」表），别凭记忆硬编；接线是否漂移跑 `scripts/sync_skills.py --check`。",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", help="only checkpoint one project slug")
    parser.add_argument("--archive", action="store_true", help="zip raw outputs")
    parser.add_argument(
        "--clean",
        action="store_true",
        help="delete zipped originals after archiving (requires --archive)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="show archive plan without changes"
    )
    parser.add_argument(
        "--next",
        help="one-line description of the immediate next action for resume.md"
             "（含内层 ASCII 双引号会被拒；长文本请用 --next-file）",
    )
    parser.add_argument(
        "--next-file",
        help="从文件读 next_action —— **长文本首选**，绕开命令行引号地狱",
    )
    parser.add_argument(
        "--out",
        default=str(
            Path(__file__).resolve().parents[1] / "state" / "BRIEF.md"
        ),
    )
    args = parser.parse_args()

    # 2026-09-21 加（一天被咬三次的同一个坑）：长文本一律走 --next-file。
    # 内层 ASCII 双引号会截断 PowerShell 命令行：吵的时候是 argparse usage，
    # 不吵的时候写进 resume.md 的是**半截话** —— 后者更坏，因为没人会发现。
    if args.next_file:
        nf = Path(args.next_file)
        if not nf.exists():
            print("--next-file 不存在: %s" % nf)
            return 2
        # utf-8-sig + lstrip(﻿)：PowerShell 的 Set-Content -Encoding UTF8 会加 BOM，
        # 不剥掉的话 resume.md 的 next_action 会以一个不可见字符开头（今天已被 BOM 咬过一次：
        # 普查清单的 BOM 污染了首个主机名）。
        next_action = (" ".join(nf.read_text("utf-8-sig", errors="replace").split())
                       .lstrip("﻿"))
    else:
        next_action = args.next
        # 守卫**只对命令行这条路生效**：文件里的引号是正常内容，不是截断征兆。
        # （2026-09-21 实测：初版两条路都查，一小时内就把自己的 --next-file 拒了 ——
        #   把守卫架在安全路径上，等于把人推回危险路径。判据要窄，见 verdict.py 同款教训。）
        if next_action and '"' in next_action:
            print("拒绝写入：next_action 中含有 ASCII 双引号 —— 这正是命令行被截断的元凶。")
            print("  改用文件（推荐）：把文本写进 state/next.txt，然后")
            print("    %s scripts/checkpoint.py --next-file state/next.txt" % sys.executable)
            print("  或把文本里的 ASCII 双引号改成中文引号「」。")
            return 2

    conn = workspace_db.connect()
    brief = workspace_db.brief_markdown(conn, project_slug=args.project)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not args.dry_run:
        out.write_text(brief, encoding="utf-8")
    print(f"BRIEF -> {out}")

    if not args.dry_run:
        resume = build_resume(conn, next_action)
        resume_path = workspace_db.STATE_DIR / "resume.md"
        resume_path.write_text(resume, encoding="utf-8")
        print(f"RESUME -> {resume_path}")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    archive_root = Path(__file__).resolve().parents[2] / "_archive"
    planned: list[str] = []
    if args.archive:
        for project, targets in project_targets(conn, args.project):
            for target in targets:
                sources = raw_paths_for_target(conn, target)
                if not sources:
                    continue
                dest_dir = archive_root / project["slug"] / stamp
                dest = dest_dir / f"{target['slug']}.zip"
                planned.append(f"{dest} <- {', '.join(str(s) for s in sources)}")
                if args.dry_run:
                    continue
                zip_paths(dest, sources)
                if args.clean:
                    for src in sources:
                        if src.is_dir():
                            shutil.rmtree(src, ignore_errors=True)
                        else:
                            src.unlink(missing_ok=True)
                workspace_db.add_artifact(
                    conn,
                    target_slug=target["slug"],
                    path=str(dest.relative_to(workspace_db.ROOT.parent)),
                    kind="archive",
                    note=f"checkpoint {stamp}",
                )

    if planned:
        print("ARCHIVE_PLAN:")
        for line in planned:
            print("  " + line)
    elif args.archive:
        print("ARCHIVE_PLAN: (nothing to archive)")

    print("")
    print("## HANDOFF")
    print(
        "新线程先读 BRIEF + state/resume.md；执行: "
        f"{sys.executable} scripts/resume.py ; {sys.executable} scripts/next.py"
    )
    print("需要原始产物时再打开具体 zip/路径，禁止整读 raw 目录。")
    print("沉淀自检: 这次什么 delta 进了哪个产品手册？(skills/product-playbooks/references/)")
    print("技能库自检: " + f"{sys.executable} scripts/sync_skills.py --check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
