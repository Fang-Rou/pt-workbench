#!/usr/bin/env python3
"""sync_skills.py — 工作区技能接线体检 / 自动注册（Windows junction）。

背景：DSH 只扫描 <工作区根>/.dsh/skills/<name>/SKILL.md（rank 100，深度 1）。
工作区技能源在 _PT工作台/skills/<name>/，必须挂成 junction 才会进会话
skill 目录（可被 skill 工具按名加载）。手工挂容易漏 → 本脚本做幂等同步。

用法（在 _PT工作台 目录执行）：
  python scripts/sync_skills.py            # 同步：补齐缺失 junction + 修复断链
  python scripts/sync_skills.py --check    # 只体检不改动（有问题的返回码 1）
  python scripts/sync_skills.py --verbose  # 逐条打印（默认只打印异常 + 汇总）

纪律：只建 junction，**不复制正文**（副本会漂移）。--check 是给 checkpoint /
maintain 用的体检位；VERDICT=PASS 才说明"技能真的接上了"。
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

WORKBENCH = Path(__file__).resolve().parents[1]          # _PT工作台
WORKSPACE = WORKBENCH.parent                              # 工作区根（含 .dsh）
SRC = WORKBENCH / "skills"
DST = WORKSPACE / ".dsh" / "skills"
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def parse_frontmatter(path: Path) -> dict:
    """返回 frontmatter 的顶层 key:value（只认 SKILL.md 开头的 --- 块）。"""
    try:
        # utf-8-sig: 容忍 BOM（旧文件带 BOM 时普通 utf-8 会让 frontmatter 判定失败）
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return {}
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    fm: dict[str, str] = {}
    key: str | None = None
    for line in text[3:end].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1] not in (" ", "\t") and ":" in line:
            key, val = line.split(":", 1)
            key, val = key.strip(), val.strip()
            fm[key] = "" if val in (">", "|", ">-", "|-", ">+", "|+") else val
        elif key and line[:1] in (" ", "\t"):   # 块标量/折行的续行
            fm[key] = (fm.get(key, "") + " " + line.strip()).strip()
    return fm


def is_junction(path: Path) -> bool:
    try:
        return os.path.isdir(path) and bool(os.readlink(str(path)).startswith("\\\\?\\"))
    except (OSError, ValueError):
        pass
    try:  # 非 Windows 或其他 reparse：能 readlink 出来就算链接
        os.readlink(str(path))
        return True
    except OSError:
        return False


def link_target(path: Path) -> str | None:
    try:
        t = os.readlink(str(path))
    except OSError:
        return None
    return t[4:] if t.startswith("\\\\?\\") else t


def make_junction(link: Path, target: Path) -> str:
    if os.name != "nt":
        os.symlink(str(target), str(link), target_is_directory=True)
        return "symlink"
    res = subprocess.run(
        f'cmd /c mklink /J "{link}" "{target}"',
        shell=True, capture_output=True, text=True, errors="replace",
    )
    if res.returncode != 0:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"New-Item -ItemType Junction -Path '{link}' -Target '{target}' | Out-Null"],
            capture_output=True, text=True, errors="replace", check=True,
        )
        return "junction(pwsh)"
    return "junction"


def run(check: bool = False, verbose: bool = False, dsh_skills: str | None = None) -> int:
    """体检/同步主体（供 CLI 与 maintain.py 复用）。返回 0=PASS，1=有待处理项。"""
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    dst = Path(dsh_skills or DST)
    if not check:
        dst.mkdir(parents=True, exist_ok=True)

    print(f"# 技能接线体检  {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"- 技能源: {SRC}")
    print(f"- 会话根: {dst}")
    print("")

    src_skills = sorted([d for d in SRC.iterdir() if d.is_dir()]) if SRC.is_dir() else []
    ok, problems, fixed = [], [], []
    seen: set[str] = set()

    for src in src_skills:
        name = src.name
        seen.add(name)
        skill_md = src / "SKILL.md"
        if not skill_md.is_file():
            problems.append(f"[NO-SKILL.md] {name}: 源目录没有 SKILL.md（按契约不会被发现，需补 frontmatter 正文）")
            continue
        fm = parse_frontmatter(skill_md)
        if not fm.get("name") or not fm.get("description"):
            problems.append(f"[BAD-FRONTMATTER] {name}: SKILL.md 缺 name/description")
            continue
        if fm["name"] != name:
            problems.append(f"[NAME-MISMATCH] {name}: frontmatter name={fm['name']} 与目录名不一致")
        if not NAME_RE.match(fm["name"]):
            problems.append(f"[BAD-NAME] {name}: name 必须是 kebab-case")

        link = dst / name
        if link.exists() or link.is_symlink():
            if is_junction(link):
                tgt = link_target(link)
                if tgt and Path(tgt) != src:
                    problems.append(f"[WRONG-TARGET] {name}: junction 指向 {tgt}，应为 {src}")
                else:
                    ok.append(name)
            else:
                problems.append(f"[COPY] {name}: 会话根里是**目录副本**（非 junction）→ 会与源漂移，建议改成 junction")
        else:
            if check:
                problems.append(f"[MISSING] {name}: 源存在但未注册到会话 skill 根")
            else:
                how = make_junction(link, src)
                fixed.append(f"{name} ({how})")
                ok.append(name)

    # 反向检查：会话根里的孤儿 / 断链
    if dst.is_dir():
        for entry in sorted(dst.iterdir()):
            if entry.name in seen:
                continue
            if is_junction(entry):
                tgt = link_target(entry)
                if tgt and not Path(tgt).exists():
                    if check:
                        problems.append(f"[STALE] {entry.name}: junction 指向已不存在的源 {tgt}")
                    else:
                        entry.unlink()
                        fixed.append(f"{entry.name} (清理断链)")
                else:
                    ok.append(entry.name)
            elif entry.is_dir():
                problems.append(f"[ORPHAN] {entry.name}: 会话根里的目录在 skills/ 没有对应源（副本？确认后处理）")

    if verbose:
        for name in sorted(set(ok)):
            print(f"[OK] {name}")
    for line in problems:
        print(line)
    for line in fixed:
        print(f"[FIXED] {line}")

    total = len(src_skills)
    print("")
    if problems:
        print(f"VERDICT=FAIL  已接线 {len(set(ok))}/{total}，{len(problems)} 处待处理"
              + ("" if check else "（部分已修，重跑一次确认）"))
        return 1
    print(f"VERDICT=PASS  已接线 {len(set(ok))}/{total}，无漂移、无断链"
          + (f"，本次修复 {len(fixed)} 项" if fixed else ""))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只体检，不改动")
    ap.add_argument("--verbose", action="store_true", help="逐条打印全部技能")
    ap.add_argument("--dsh-skills", default=str(DST), help="会话 skill 根（默认 <工作区根>/.dsh/skills）")
    args = ap.parse_args()
    return run(check=args.check, verbose=args.verbose, dsh_skills=args.dsh_skills)


if __name__ == "__main__":
    raise SystemExit(main())
