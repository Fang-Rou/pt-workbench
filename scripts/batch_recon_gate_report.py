# -*- coding: utf-8 -*-
"""batch_recon_gate_report.py — 入口形态判读的阈值体检（2026-09-23 加）。

为什么：entry_form 的阈值（开口 >=50% / 升格 UNSURE >=80% 且 >=5 台）是拍的。
要调它只能靠**真实跑过的批次**，不能靠感觉 —— 本脚本把每个 run 的簇数据摆出来，
并模拟「换一组阈值会多/少判几个 run」，供人拍板。

只读本地产物（results/batch-recon-*/run.json），不发任何请求。

用法: python scripts/batch_recon_gate_report.py [--results results]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(results: Path) -> list:
    rows = []
    for d in sorted(results.glob("batch-recon-*")):
        rp = d / "run.json"
        if not rp.exists():
            continue
        try:
            run = json.loads(rp.read_text("utf-8"))
        except Exception:
            continue
        live = run.get("live") or []
        ef = run.get("entry_form") or {}
        if not ef and run.get("engine") == "path" and live:
            # 2026-09-23：entry_form 是后加的 —— 老批次 run.json 里没有这个字段，
            # 但 raw/ 里的探针响应都在，可以**离线重算**（不发请求），否则样本永远攒不起来。
            try:
                sys.path.insert(0, str(ROOT / "scripts"))
                import batch_recon as _br
                raw = {}
                for f in (d / "raw").glob("*.json"):
                    try:
                        j = json.loads(f.read_text("utf-8"))
                        raw[j["host"]] = j
                    except Exception:
                        pass
                ef = _br.entry_form(live, raw, run.get("reach") or {})
                ef["_recomputed"] = True
            except Exception as exc:
                ef = {"_error": str(exc)[:80]}
        groups = ef.get("groups") or []
        n = len(live)
        top = len(groups[0]["hosts"]) if groups else 0
        rows.append({"dir": d.name, "weapon": run.get("weapon"), "engine": run.get("engine"),
                     "n": n, "hits": len(run.get("hits") or []), "top": top,
                     "share": (top / n) if n else 0.0, "blind": bool(ef.get("blind")),
                     "gate": (run.get("gate") or {}).get("verdict"),
                     "groups": len(groups), "scope_ok": True})
    return rows


def simulate(rows: list, open_share: float, open_min: int, blind_share: float, blind_min: int) -> tuple:
    notes = blinds = 0
    for r in rows:
        if r["engine"] != "path" or not r["top"]:
            continue
        if r["top"] >= max(open_min, -(-r["n"] // 2)) and r["share"] >= open_share:
            notes += 1
            if not r["hits"] and r["share"] >= blind_share and r["n"] >= blind_min:
                blinds += 1
    return notes, blinds


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(ROOT / "results"))
    a = ap.parse_args()
    rows = load(Path(a.results))
    path_rows = [r for r in rows if r["engine"] == "path"]
    print("# 入口形态判读 · 阈值体检（本地 %d 个批次，其中 path 引擎 %d 个）" % (len(rows), len(path_rows)))
    print("")
    print("## 每个批次的簇数据（share = 最大同构簇 / 存活台）")
    for r in rows:
        if r["engine"] != "path":
            continue
        print("  %-24s %-3s n=%-3d top=%-3d share=%.2f groups=%-2d hits=%d gate=%-7s blind=%s"
              % (r["dir"][-6:], r["weapon"], r["n"], r["top"], r["share"], r["groups"], r["hits"],
                 r["gate"], r["blind"]))
    print("")
    print("## 换阈值会怎样（当前: 开口 >=50% & >=max(3,半数)；升格 UNSURE >=80% & >=5 台）")
    print("  %-28s %-8s %-10s %s" % ("开口条件", "给事实note", "升格UNSURE", "与当前差异"))
    cur = simulate(rows, 0.5, 3, 0.8, 5)
    for open_share, open_min, bs, bm in [(0.4, 3, 0.8, 5), (0.5, 3, 0.8, 5), (0.6, 3, 0.8, 5),
                                         (0.5, 5, 0.8, 5), (0.5, 3, 0.9, 5), (0.6, 5, 0.9, 5),
                                         (0.5, 3, 1.0, 5)]:
        got = simulate(rows, open_share, open_min, bs, bm)
        tag = "<= 当前" if (open_share, open_min, bs, bm) == (0.5, 3, 0.8, 5) else ""
        print("  >=%.0f%% & >=%-3d台%s %-8d %-10d %s" % (open_share * 100, open_min,
              " " * 8, got[0], got[1], tag + ("（%+d/%+d）" % (got[0] - cur[0], got[1] - cur[1]) if tag == "" else "")))
    print("")
    print("读法：note 多了会把正常环境也点一遍；UNSURE 多了会让『0 命中』普遍失去结论。")
    print("      样本还小（path 批次 %d 个），先按当前阈值跑，攒够 20+ 个批次再回来调。" % len(path_rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())