# -*- coding: utf-8 -*-
r"""audit_sediment.py — 沉淀利用率体检：经验是在被用，还是只在吃灰？

改造说明（2026-10-01）：原版绑 SRC 平台（提交记录 / 受理口径库 / 决策点回看），
那些随平台层一起移除。保留的是**通用**的沉淀体检——渗透测试同样会「积累越来越多、
用得越来越少」，这几个指标跟平台无关。

指标（全部来自 state/lesson-usage.jsonl 账本 + 文档实际章节）：
  ① 账本量：查询 / 结果回填 / 回填率（回填率低 = 用了没闭环）
  ② 手册利用率：每本 references/*.md 被查询命中过几次（0 = 落灰）
  ③ 章节覆盖率：hit-case-library 各节是否曾被任何查询命中（未被命中 = 查不到 = 等于没沉淀）
  ④ 使用趋势：近 N 天每天查询数
  ⑤ 模式库退休体检：§32 的 P<n> 模式「被应用次数」（--used 回填）为 0 ⇒ 退休候选
判定：覆盖率 ≥80% 且回填率 ≥70% ⇒ PASS；否则 WARN 并列出该补的地方。

用法: python scripts/audit_sediment.py [--json] [--days 7] [--strict]
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "state" / "lesson-usage.jsonl"
HCL = ROOT / "skills" / "pt-engagement" / "references" / "hit-case-library-2026.md"
PB = ROOT / "skills" / "product-playbooks" / "references"


def reference_docs() -> list:
    """所有技能 references/ 下的 .md（排除单独按章节处理的 HCL 与报告模板）。"""
    hard = {HCL.resolve()}
    out = []
    for p in sorted((ROOT / "skills").glob("*/references/*.md")):
        if p.resolve() in hard or p.name in ("pt-report-template.md", "remediation-tracker.md"):
            continue
        out.append(p)
    return out


def load_rows() -> list:
    if not LEDGER.exists():
        return []
    return [json.loads(l) for l in LEDGER.read_text("utf-8").splitlines() if l.strip()]


def sections(text: str) -> list:
    return [p.splitlines()[0].strip() for p in re.split(r"^##\s+", text, flags=re.M)[1:]]


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    as_json = "--json" in sys.argv
    days = 7
    if "--days" in sys.argv:
        days = int(sys.argv[sys.argv.index("--days") + 1])
    rows = load_rows()
    lookups = [r for r in rows if r.get("event") == "lookup"]
    outs = [r for r in rows if r.get("event") == "outcome"]
    backfill = (100.0 * len(outs) / len(lookups)) if lookups else 0.0

    manual_hits = collections.Counter()
    sec_hits = collections.Counter()
    for l in lookups:
        for m in l.get("matched", []):
            lb = m.get("label", "")
            mm = re.search(r"→\s*([\w\-\.]+\.md)", lb)
            if mm:
                manual_hits[mm.group(1)] += 1
            sm = re.search(r"hit-case-library §([0-9]+(?:\.[0-9]+[a-z]?)?)", lb)
            if sm:
                sec_hits[sm.group(1)] += 1
    manuals = sorted(set(p.name for p in PB.glob("*.md")) | set(p.name for p in reference_docs()))
    used_manuals = [m for m in manuals if manual_hits.get(m)]
    dust_manuals = [m for m in manuals if not manual_hits.get(m)]

    hcl_secs = sections(HCL.read_text("utf-8", "ignore")) if HCL.exists() else []
    hcl_keys = []
    for s in hcl_secs:
        km = re.match(r"([0-9]+(?:\.[0-9]+)?)", s)
        if km:
            hcl_keys.append((km.group(1), s))
    dust_secs = [(k, s) for k, s in hcl_keys if sec_hits.get(k, 0) == 0]
    coverage = (100.0 * (len(hcl_keys) - len(dust_secs)) / len(hcl_keys)) if hcl_keys else 0.0

    byday = collections.Counter((r.get("ts") or "")[:10] for r in lookups)
    days_sorted = sorted(byday)
    recent = days_sorted[-days:] if days_sorted else []

    out_ts = sorted(r["ts"] for r in outs)
    pending = [l for l in lookups if not any(o > l["ts"] for o in out_ts)]

    # ⑤ §32 模式「应用计数」退休体检
    #    为什么要有它：§32 的模式库**只增不减** ⇒ 信噪比单调下降。没有退休机制的积累必然是负债。
    #    两个口径（都不靠"感觉"）：
    #      - **被应用** = outcome 记录里显式写了 --used P<n> 的次数（人真的用了它）
    #      - **可命中** = 把账本里每次查询的关键词**回放**一遍，看这条模式会不会被捞到
    #        （口径复用 playbook_lookup.score / MIN_SCORE；0 = 连查都查不到 = 等于没写）
    #    退休候选 = 被应用 0 **且** 可命中 0 ⇒ 补触发词，或合并进别的模式 / 降级成案例注解。
    pat_rows, pat_retire, pat_note = [], [], ""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import playbook_lookup as _pl
        _hcl = HCL.read_text("utf-8", "ignore")
        _m32 = re.search(r"^## 32\..*?(?=^## 33\.)", _hcl, re.S | re.M)
        if _m32:
            _sec = _m32.group(0)
            _applied = collections.Counter()
            for _r in outs:
                for _u in (_r.get("used") or []):
                    _applied[str(_u).strip().upper()] += 1
            _kwsets = [l.get("keywords") or [] for l in lookups]
            _min = getattr(_pl, "MIN_SCORE", 3)
            for _pm in re.finditer(r"^### (P\d+)\s+(.+)$", _sec, re.M):
                _pid, _pt = _pm.group(1), _pm.group(2).strip()
                _rest = _sec[_pm.end():]
                _nx = re.search(r"^### P\d+", _rest, re.M)
                _body = _rest[: _nx.start() if _nx else len(_rest)]
                _hitn = sum(1 for _k in _kwsets if _pl.score(_pid + " " + _pt + " " + _body, _k) >= _min)
                pat_rows.append((_pid, _pt, _applied.get(_pid, 0), _hitn))
            # 判定门槛（很重要）：机制 2026-09-18 才上线，样本不足时**明确暂缓**——
            # 绝不"第一天就报 12 条退休候选"（那是假红；假红报几次，真红就没人看了）。
            # 另外：「可被查询捞到」**不是**退休判据 —— §32 是整节阅读，不靠关键词命中；
            # 它只作参考列，提示哪些模式连 lookup 都捞不到。
            _samples = [r for r in outs if (r.get("ts") or "")[:10] >= "2026-09-18"]
            if len(_samples) >= 10:
                pat_retire = ["%s %s" % (p_, t_) for p_, t_, a_, _h in pat_rows if a_ == 0]
            else:
                pat_note = ("判定暂缓：--used 计数自 2026-09-18 起，当前可用样本仅 %d 次实战回填"
                            "（≥10 次才开始报退休候选）" % len(_samples))
    except Exception as _exc:
        pat_rows = [("ERR", str(_exc)[:60], -1, -1)]

    verdict = "PASS" if (coverage >= 80.0 and backfill >= 70.0) else "WARN"
    if as_json:
        print(json.dumps({
            "lookups": len(lookups), "outcomes": len(outs), "backfill_pct": round(backfill, 1),
            "manuals_used": len(used_manuals), "manuals_total": len(manuals),
            "dust_manuals": dust_manuals, "coverage_pct": round(coverage, 1),
            "dust_sections": [s for _, s in dust_secs], "pending_outcomes": len(pending),
            "by_day": {d: byday[d] for d in recent},
            "patterns_total": len(pat_rows),
            "patterns_applied": sum(1 for _x in pat_rows if _x[2] > 0),
            "patterns_reachable": sum(1 for _x in pat_rows if _x[3] > 0),
            "pattern_retire": pat_retire, "verdict": verdict,
        }, ensure_ascii=False, indent=1))
    else:
        print("# 沉淀利用率体检")
        print("  账本：%d 条（查询 %d / 回填 %d，回填率 %.0f%%）" % (len(rows), len(lookups), len(outs), backfill))
        print("  手册：%d/%d 用过%s" % (len(used_manuals), len(manuals),
                                    ("；落灰：" + " ".join(dust_manuals)) if dust_manuals else ""))
        print("  章节覆盖率：%d/%d 节被查询命中过（%.0f%%）" % (len(hcl_keys) - len(dust_secs), len(hcl_keys), coverage))
        if dust_secs:
            print("  落灰节（从没被任何查询命中 ⇒ 下次也读不到，建议补『触发词』行）：")
            for k, s in dust_secs:
                print("    [ ] §%s %s" % (k, s[:(56 - len(k))]))
        if pending:
            print("  未回填查询 %d 条（用了没闭环）最近 3 条：" % len(pending))
            for l in pending[-3:]:
                print("    %s  %s" % (l["ts"][:16], "/".join(l["keywords"])[:44]))
        if pat_rows:
            print("  §32 模式库退休体检：%d 条模式，被应用 %d 条 / 历史查询可命中 %d 条" % (
                len(pat_rows), sum(1 for _x in pat_rows if _x[2] > 0), sum(1 for _x in pat_rows if _x[3] > 0)))
            if pat_note:
                print("    " + pat_note)
            if pat_retire:
                print("    退休候选 %d 条（样本充足仍 0 次被应用 ⇒ 合并进别的模式，或降级成案例注解）："
                      % len(pat_retire))
                for _x in pat_retire[:8]:
                    print("      [ ] " + _x[:72])
                if len(pat_retire) > 8:
                    print("      ... 另有 %d 条" % (len(pat_retire) - 8))
        print("  近 %d 天查询趋势：%s" % (days, " ".join("%s=%d" % (d[5:], byday[d]) for d in recent) or "无"))
        print("\nVERDICT=%s%s" % (verdict, "（有落灰节或回填率低，见上）" if verdict == "WARN" else ""))
    if "--strict" in sys.argv:
        return 0 if verdict == "PASS" else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
