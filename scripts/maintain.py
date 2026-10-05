#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工作台维护工具：体检 / 清理缓存与垃圾文件。

用法（在 _PT工作台 目录执行）：
    $py scripts/maintain.py report                # 体积体检 + 可清理项清单
    $py scripts/maintain.py clean --dry-run       # 预览将要删除的内容（默认）
    $py scripts/maintain.py clean --apply         # 实际执行清理

清理范围（只删可再生数据，绝不碰登录态/证据/技能）：
  - scripts/ 下的 __pycache__
  - chrome-profile 的纯缓存目录（Cache/Code Cache/GPU/Shader/模型/组件缓存等，
    保留 Cookies、Login Data、Local Storage、IndexedDB、Preferences、扩展本体）
  - results/ 下 0 字节文件和空目录
  - _archive 之外不存在任何白名单外的删除
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # _PT工作台
CHROME = ROOT / "chrome-profile"

# chrome-profile 里可安全删除的纯缓存目录（Chrome 会在需要时重建/重下载）
CHROME_CACHE_DIRS = [
    "component_crx_cache",
    "extensions_crx_cache",
    "optimization_guide_model_store",
    "Safe Browsing",
    "WasmTtsEngine",
    "WidevineCdm",
    "hyphen-data",
    "ZxcvbnData",
    "GrShaderCache",
    "ShaderCache",
    "GraphiteDawnCache",
    "Crashpad",
    "BrowserMetrics",
    "CertificateRevocation",
    "ActorSafetyLists",
    "Default/Cache",
    "Default/Code Cache",
    "Default/GPUCache",
    "Default/Service Worker/CacheStorage",
    "Default/Service Worker/ScriptCache",
]

# 递归遍历时永远跳过的大目录
SKIP_DIRS = {".venv-mitmproxy", ".git", "node_modules", "_archive", "chrome-profile"}


def _size(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())


def _fmt(mb: float) -> str:
    return f"{mb:9.1f} MB"


def cmd_report() -> int:
    print("# 工作台体检\n")
    for d in sorted(ROOT.iterdir(), key=lambda x: x.name.lower()):
        if d.is_dir() and not d.name.startswith("."):
            print(f"{_fmt(_size(d) / 1e6)}  {d.name}/")
    print(f"{_fmt(_size(CHROME) / 1e6)}  chrome-profile/（登录态已保留，只清缓存）\n")

    print("## 可清理项\n")
    pycache, empty, zero, caches = _collect()
    for rel in CHROME_CACHE_DIRS:
        p = CHROME / rel
        if p.exists():
            caches.append((rel, _size(p) / 1e6))
    print(f"- __pycache__: {len(pycache)} 个目录（{_fmt(sum(_size(p) for p in pycache) / 1e6)}）")
    print(f"- chrome-profile 缓存: {len(caches)} 个目录")
    for rel, mb in sorted(caches, key=lambda x: -x[1]):
        print(f"    {_fmt(mb)}  {rel}")
    print(f"- results/ 0 字节文件: {len(zero)} 个")
    print(f"- 空目录: {len(empty)} 个（_archive 除外）")
    print("\n执行清理: python scripts/maintain.py clean --apply")

    print("\n## 技能接线体检（会话 skill 目录 → 见下方详细）\n")
    try:
        import sync_skills

        rc = sync_skills.run(check=True, verbose=False)
        print(f"- 结论: {'PASS' if rc == 0 else 'FAIL —— 跑 python scripts/sync_skills.py 修复'}")
    except Exception as exc:  # 体检失败不该拖垮整个体检
        print(f"- 技能体检失败: {exc}")

    print("\n## 沉淀接线体检（每条经验是否都有'会自己触发'的路径）\n")
    try:
        import check_lessons_wired

        rc2 = check_lessons_wired.main()
        print(f"- 结论: {'PASS' if rc2 == 0 else 'FAIL —— 跑 python scripts/check_lessons_wired.py 看缺哪条'}")
    except Exception as exc:  # 体检失败不该拖垮整个体检
        print(f"- 沉淀体检失败: {exc}")

    print("\n## 沉淀利用体检（经验是在被用，还是只在吃灰）\n")
    try:
        import audit_sediment
        audit_sediment.main()
    except Exception as exc:  # 体检失败不该拖垮整个体检
        print(f"- 利用体检失败: {exc}")
    return 0


def _collect() -> tuple[list[Path], list[Path], list[Path], list[tuple[str, float]]]:
    pycache = [p for p in ROOT.rglob("__pycache__") if not any(s in SKIP_DIRS for s in p.parts)]
    empty = [
        d
        for d in ROOT.rglob("*")
        if d.is_dir()
        and not any(s in SKIP_DIRS for s in d.parts)
        and not any(d.iterdir())
    ]
    zero = [
        f
        for f in (ROOT / "results").rglob("*")
        if f.is_file() and f.stat().st_size == 0
    ]
    caches = []
    for rel in CHROME_CACHE_DIRS:
        p = CHROME / rel
        if p.exists():
            caches.append((rel, _size(p) / 1e6))
    return pycache, empty, zero, caches


def cmd_clean(args) -> int:
    pycache, empty, zero, caches = _collect()
    total_mb = sum(mb for _, mb in caches) + _size(ROOT / "scripts") / 1e6 * 0  # pycache 计入下方
    pycache_mb = sum(_size(p) for p in pycache) / 1e6
    if args.dry_run:
        print("# 清理预览（--apply 才会真正删除）\n")
        for p in pycache:
            print(f"  __pycache__  {p.relative_to(ROOT)}")
        for rel, mb in caches:
            print(f"  chrome缓存  {_fmt(mb)}  {rel}")
        for f in zero:
            print(f"  0字节文件   {f.relative_to(ROOT)}")
        for d in empty:
            print(f"  空目录      {d.relative_to(ROOT)}")
        print(f"\n预计释放: {_fmt((pycache_mb + sum(mb for _, mb in caches)) / 1e6)}")
        return 0

    freed = 0.0
    for p in pycache:
        try:
            shutil.rmtree(p)
            print(f"del __pycache__ {p.relative_to(ROOT)}")
        except OSError as e:
            print(f"SKIP {p.relative_to(ROOT)}: {e}")
    for rel, mb in caches:
        p = CHROME / rel
        try:
            shutil.rmtree(p)
            freed += mb
            print(f"del chrome缓存 {_fmt(mb)}  {rel}")
        except OSError as e:
            print(f"SKIP {rel}: {e}")
    for f in zero:
        try:
            f.unlink()
            print(f"del 0字节文件  {f.relative_to(ROOT)}")
        except OSError as e:
            print(f"SKIP {f.relative_to(ROOT)}: {e}")
    for d in empty:
        try:
            d.rmdir()
            print(f"del 空目录     {d.relative_to(ROOT)}")
        except OSError:
            pass
    print(f"\n本次释放约 {_fmt(freed)}")
    return 0


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="工作台维护：体检与清理")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("report", help="体积体检 + 可清理项清单")
    c = sub.add_parser("clean", help="清理缓存与垃圾文件")
    c.add_argument("--dry-run", action="store_true", default=True, help="只预览不删除（默认）")
    c.add_argument("--apply", dest="dry_run", action="store_false", help="真正执行删除")
    args = ap.parse_args()
    if args.cmd == "report":
        return cmd_report()
    return cmd_clean(args)


if __name__ == "__main__":
    sys.exit(main())
