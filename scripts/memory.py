#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""memory.py — Agent 的**外置工作记忆**（2026-09-27 立，治「上下文是唯一工作记忆」这个一级根因）。

为什么必须存在（2026-09-27 实测痛点）：
  会话上下文**只增不减、不可寻址、不可回读**。150+ 轮实战里，我在后期明显忘了早期细节
  （判据、已否决结论、未结线索）⇒ 重复劳动 + 重踩坑。DB/NOTES 存在，但**要我手工写、不自动回读**
  ⇒ 等于没有工作记忆。

与 DB 的分工：
  workspace.db  = 结果库（findings/submissions）—— 我「得到了什么」
  memory-*.json = 过程记忆（试过什么/学到什么/还欠什么）—— 我「做过什么、还欠什么」

两条硬要求（否则又变成负担）：
  ① 自动落：batch_recon 跑完用 ingest-run 并入，不依赖我记得调用；
  ② 自动注入：下一轮开场 brief <slug> 一屏看清，不靠我回忆。

用法：
    $py scripts\memory.py brief zjph-butian
    $py scripts\memory.py show  zjph-butian
    $py scripts\memory.py asset <slug> --host H --tech "Vue SPA" --status reachable
    $py scripts\memory.py tried <slug> --host H --weapon K4 --verdict miss --evidence PATH
    $py scripts\memory.py lead  <slug> --text "..."
    $py scripts\memory.py criterion <slug> --text "..."
    $py scripts\memory.py rejected <slug> --what "..." --why "..."
    $py scripts\memory.py ingest-run <slug> --run results/batch-recon-XXX/run.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MEM = ROOT / "state"


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def path_of(slug: str) -> Path:
    return MEM / ("memory-%s.json" % slug)


def load(slug: str) -> dict:
    p = path_of(slug)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"slug": slug, "created": now(), "updated": now(), "assets": [],
            "tried": [], "criteria": [], "leads": [], "rejected": []}


def save(slug: str, d: dict) -> None:
    d["updated"] = now()
    MEM.mkdir(parents=True, exist_ok=True)
    path_of(slug).write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def add_asset(slug, host, tech="", status="", note="", api_base="", apis=None):
    d = load(slug)
    hit = [a for a in d["assets"] if a.get("host") == host]
    a = hit[0] if hit else {"host": host, "tried": [], "first_seen": now()}
    if tech:
        a["tech"] = tech
    if status:
        a["status"] = status
    if note:
        a["note"] = note
    if api_base:
        a["api_base"] = api_base
    if apis:
        a["apis"] = sorted(set((a.get("apis") or []) + list(apis)))
    a["last_seen"] = now()
    if not hit:
        d["assets"].append(a)
    save(slug, d)
    return a


def add_tried(slug, host, weapon, verdict, evidence="", note=""):
    d = load(slug)
    d["tried"].append({"ts": now(), "host": host, "weapon": weapon,
                       "verdict": verdict, "evidence": evidence, "note": note})
    for a in d["assets"]:
        if a.get("host") == host:
            w = a.setdefault("tried", [])
            if weapon not in w:
                w.append(weapon)
    save(slug, d)


def add_simple(slug, field, payload):
    """追加一条；按文本去重（重复 ingest 同一结论时不再堆同一条）。"""
    d = load(slug)
    rows = d.setdefault(field, [])
    key = (payload.get("text") or payload.get("what") or "") if isinstance(payload, dict) else str(payload)
    for old in rows:
        okey = (old.get("text") or old.get("what") or "") if isinstance(old, dict) else str(old)
        if okey and okey == key:
            return d
    rows.append(payload)
    save(slug, d)
    return d


def ingest_run(slug, run_path):
    """把 batch_recon 的 run.json 自动并进记忆（自动落的关键一环）。"""
    p = Path(run_path)
    if not p.is_absolute():
        p = ROOT / run_path
    if not p.exists():
        print("UNSURE: 找不到 %s" % p)
        return 2
    r = json.loads(p.read_text(encoding="utf-8"))
    weapon = r.get("weapon")
    for h in r.get("live") or []:
        add_asset(slug, h, status="reachable")
    for h in r.get("unreachable") or []:
        add_asset(slug, h, status="unreachable")
    for h in r.get("blocked") or []:
        add_tried(slug, h.get("host", "?"), weapon, "blocked",
                  evidence=str(p.relative_to(ROOT)),
                  note=(str(h.get("verdict")) + ":" + str(h.get("reason"))[:40]))
    n_hit = len(r.get("hits") or [])
    for h in (r.get("live") or []):
        add_tried(slug, h, weapon, ("hit" if n_hit else "miss"),
                  evidence=str(p.relative_to(ROOT)),
                  note=("命中 %d 条" % n_hit) if n_hit else "0 命中")
    aud = r.get("js_audit") or {}
    blind = [h for h, a in aud.items() if (a or {}).get("scanned_n") == 0]
    if blind:
        add_simple(slug, "leads", {"ts": now(), "text":
                                   ("js 引擎对 %d 台是仪器盲区（scanned_n=0），其 0 命中不可信：%s"
                                    % (len(blind), ", ".join(blind[:5])))})
    print("已并入记忆：可达 %d / 不可达 %d / 拦截 %d / 命中 %d"
          % (len(r.get("live") or []), len(r.get("unreachable") or []),
             len(r.get("blocked") or []), n_hit))
    return 0


def brief(slug) -> int:
    d = load(slug)
    a = d.get("assets") or []
    reach = [x for x in a if x.get("status") == "reachable"]
    tried = d.get("tried") or []
    byw = {}
    for t in tried:
        byw[t.get("weapon")] = byw.get(t.get("weapon"), 0) + 1
    print("## 工作记忆 · %s（更新 %s）" % (slug, d.get("updated")))
    print("  资产 %d 台（可达 %d / 不可达 %d）" % (len(a), len(reach), len(a) - len(reach)))
    for x in reach[:6]:
        bits = [x.get("host", ""), x.get("tech") or "", x.get("api_base") or ""]
        extra = ("已试 " + ",".join(x.get("tried") or [])) if x.get("tried") else ""
        print("    - %s  %s" % (" ".join([b for b in bits if b]), extra))
    if byw:
        print("  已试手法：%s" % ", ".join("%s x%d" % (k, v) for k, v in sorted(byw.items())))
    for label, key, lim in (("判据", "criteria", 4), ("未结线索", "leads", 5), ("已否决", "rejected", 5)):
        rows = d.get(key) or []
        if not rows:
            continue
        print("  %s %d 条：" % (label, len(rows)))
        for r in rows[-lim:]:
            if isinstance(r, str):
                print("    - %s" % r[:120])
            elif isinstance(r, dict):
                txt = r.get("text") or ("%s —— %s" % (r.get("what", ""), r.get("why", "")))
                print("    - %s" % str(txt)[:120])
    print("  ⚠ 本屏是**外部记忆**：不要凭回忆行事，有疑问看 memory.py show。")
    return 0


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Agent 外置工作记忆")
    sub = ap.add_subparsers(dest="cmd")
    for name in ("brief", "show"):
        s = sub.add_parser(name)
        s.add_argument("slug")
    s = sub.add_parser("asset")
    s.add_argument("slug")
    s.add_argument("--host", required=True)
    s.add_argument("--tech", default="")
    s.add_argument("--status", default="")
    s.add_argument("--note", default="")
    s.add_argument("--api-base", default="", dest="api_base")
    s = sub.add_parser("tried")
    s.add_argument("slug")
    s.add_argument("--host", required=True)
    s.add_argument("--weapon", required=True)
    s.add_argument("--verdict", required=True)
    s.add_argument("--evidence", default="")
    s.add_argument("--note", default="")
    s = sub.add_parser("lead")
    s.add_argument("slug")
    s.add_argument("--text", required=True)
    s = sub.add_parser("criterion")
    s.add_argument("slug")
    s.add_argument("--text", required=True)
    s = sub.add_parser("rejected")
    s.add_argument("slug")
    s.add_argument("--what", required=True)
    s.add_argument("--why", required=True)
    s = sub.add_parser("ingest-run")
    s.add_argument("slug")
    s.add_argument("--run", required=True)
    a = ap.parse_args()
    if not a.cmd:
        print(__doc__)
        return 0
    if a.cmd == "brief":
        return brief(a.slug)
    if a.cmd == "show":
        print(json.dumps(load(a.slug), ensure_ascii=False, indent=1))
        return 0
    if a.cmd == "asset":
        add_asset(a.slug, a.host, a.tech, a.status, a.note, a.api_base)
        print("ok asset %s" % a.host)
    elif a.cmd == "tried":
        add_tried(a.slug, a.host, a.weapon, a.verdict, a.evidence, a.note)
        print("ok tried %s %s %s" % (a.host, a.weapon, a.verdict))
    elif a.cmd == "lead":
        add_simple(a.slug, "leads", {"ts": now(), "text": a.text})
        print("ok lead")
    elif a.cmd == "criterion":
        add_simple(a.slug, "criteria", {"ts": now(), "text": a.text})
        print("ok criterion")
    elif a.cmd == "rejected":
        add_simple(a.slug, "rejected", {"ts": now(), "what": a.what, "why": a.why})
        print("ok rejected")
    elif a.cmd == "ingest-run":
        return ingest_run(a.slug, a.run)
    return 0


if __name__ == "__main__":
    sys.exit(main())