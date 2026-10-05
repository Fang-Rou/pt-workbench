# -*- coding: utf-8 -*-
r"""playbook_lookup.py — **沉淀利用侧**：动手前查该读哪份手册/案例，并留下"被使用过"的记录。

为什么要有它（2026-09-12 用户明示："滚雪球不能只沉淀不利用"）：
  `check_lessons_wired.py` 只验"经验是否放在会被读到的位置"（接线），
  **不验"是否真的被读到、被用上"**。没有使用记录时，"沉淀"无法证明在滚。
  本脚本把利用侧变成可度量：**每次动手前的查询动作本身就是使用证据**（append-only 账本），
  实战结束再用 --outcome 回填结果，形成「沉淀 → 使用 → 结果 → 回写」的闭环账。

用法:
  python scripts\playbook_lookup.py YApi 接口管理 越权        # 查该读什么 + 自动记一条 usage
  python scripts\playbook_lookup.py --outcome hit --detail "YApi 越权命中，交付包已备"
  python scripts\playbook_lookup.py --report                   # 利用率报表（沉淀 N 条 / 被用到 M 条）
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
PB = SKILLS / "product-playbooks" / "references"
HCL = SKILLS / "pt-engagement" / "references" / "hit-case-library-2026.md"
BATTLE = SKILLS / "pt-engagement" / "references" / "evidence-escalation.md"
LEDGER = ROOT / "state" / "lesson-usage.jsonl"
# 匹配阈值：'未授权'/'漏洞' 这类通用词几乎每份手册都有，会让"用过"失真。
# 只有同类词累计命中 >= MIN_SCORE 才算真相关（2026-09-12 首跑报表发现该失真并修正）。
MIN_SCORE = 3


def load(p: Path) -> str:
    try:
        return p.read_text("utf-8", "ignore")
    except Exception:
        return ""


def fm_desc(text: str) -> str:
    m = re.search(r"^---\s*\n(.*?)\n---", text, re.S)
    if not m:
        return ""
    d = re.search(r"description:\s*(.+)", m.group(1))
    return (d.group(1) if d else "").strip()[:400]


def sections(text: str) -> list[tuple[str, str]]:
    """把 markdown 按 '## ' 切段，返回 [(标题, 正文)]。"""
    out = []
    parts = re.split(r"^##\s+", text, flags=re.M)
    for p in parts[1:]:
        title = p.splitlines()[0].strip()
        out.append((title, p))
    return out


def score(text: str, kws: list[str]) -> int:
    t = text.lower()
    return sum(t.count(k.lower()) for k in kws)


def reference_docs() -> list:
    """所有技能 references/ 下的 .md（排除已单独按章节处理的 HCL / BATTLE）。

    2026-09-17 修：此前只索引 product-playbooks/*.md 与两个硬编码文件，
    任何写在 skills/*/references/ 下的手册/清单对查找**完全不可见**（死文件）。
    """
    hard = {HCL.resolve(), BATTLE.resolve()}
    pb_root = PB.resolve()
    out = []
    for p in sorted(SKILLS.glob("*/references/*.md")):
        rp = p.resolve()
        if rp in hard:
            continue
        if pb_root in rp.parents:   # product-playbooks 已由 PB 分支处理，避免重复
            continue
        out.append(p)
    return out


def best_excerpt(text: str, kws: list[str], width: int = 900) -> str:
    """从文本里挑与关键词最密的一段（段落级）—— RAG 用。"""
    paras = [x.strip() for x in re.split(r"\n\s*\n", text) if len(x.strip()) > 30]
    best, bs = "", 0
    for x in paras:
        s = score(x, kws)
        if s > bs:
            bs, best = s, x
    if not best:
        best = paras[0] if paras else text[:width]
    return best[:width]


def cmd_lookup(kws: list[str], note: str, rag: bool = False,
               rag_chars: int = 900, top: int = 3, level: str = "full") -> int:
    """hits 元素 = (kind, path, score, label, excerpt)。

    rag=True 时**直接打印命中内容的正文片段**（2026-09-27 加，学 redteam-agent 的 RAG 注入）：
    此前只列文件名，读它要再花 2-3 次工具调用 ⇒ 实战里基本没人读 ⇒「沉淀被读 ≠ 被用」。
    """
    hits = []
    for p in sorted(PB.glob("*.md")):
        t = load(p)
        s = score(t, kws)
        if s >= MIN_SCORE:
            hits.append(("手册", p, s, "product-playbooks → %s" % p.name, best_excerpt(t, kws, rag_chars)))
    for p in reference_docs():
        t = load(p)
        s = score(t, kws)
        if s >= MIN_SCORE:
            hits.append(("手册", p, s, "%s → %s" % (p.parent.parent.name, p.name), best_excerpt(t, kws, rag_chars)))
    for p in sorted(SKILLS.glob("*/SKILL.md")):
        t = load(p)
        s = score(t, kws)
        if s >= MIN_SCORE:
            hits.append(("技能", p, s, "skill: %s" % p.parent.name, best_excerpt(t, kws, rag_chars)))
    hcl = load(HCL)
    for title, body in sections(hcl):
        s = score(body, kws)
        if s >= MIN_SCORE:
            hits.append(("案例库", HCL, s, "hit-case-library §%s" % title[:60], body.strip()[:rag_chars]))
    b = load(BATTLE)
    for title, body in sections(b):
        s = score(body, kws)
        if s >= MIN_SCORE:
            hits.append(("提交坑", BATTLE, s, "submission-battle-notes §%s" % title[:60], body.strip()[:rag_chars]))

    hits.sort(key=lambda x: -x[2])
    print("# 动手前该读（关键词: %s）" % " / ".join(kws))
    if not hits:
        print("  （无匹配 —— 可能是新面，也可能只是关键词太少/太泛被 MIN_SCORE=%d 挡掉）" % MIN_SCORE)
        if len(kws) < 3:
            print("  ⚠ 本次只给了 %d 个关键词：请用 3 个以上具体词再查一次"
                  "（例：诗路云 OSS 判重 / 签名密钥 网关 鉴权绕过），别急着当新面。" % len(kws))
        print("  命中后（无论是新面还是漏检）请回写手册/案例库。")
    shown = hits[: max(3, top)] if rag else hits[:12]
    for kind, p, s, label, excerpt in shown:
        print("  [%s] %-58s 匹配%d 次  <- %s" % (kind, p.relative_to(ROOT) if p.is_relative_to(ROOT) else p, s, label))
    if rag and level == "brief":
        # 2026-09-27 Context Engineering 分层：brief 只给「标题 + 首行摘要」，
        # 省 token；确认要哪条后再 --level full 展开（治「一次塞 900 字×3 把窗口占满」）。
        print()
        print("## RAG 摘要（brief 档：只给首行；要细节加 --level full）")
        def _key_lines(path, kws, n: int = 3):
            """brief 档：直接从文件里挑**含关键词的行**（比"最密段落"更适合表格/列表型文档）。"""
            try:
                t = load(path)
            except Exception:
                return []
            out = []
            for x in t.splitlines():
                y = x.strip()
                if len(y) < 15 or y.startswith(("#", "```", "|", "---")):
                    continue
                if any(k.lower() in y.lower() for k in kws):
                    out.append(y)
                    if len(out) >= n:
                        break
            return out
        for i, (kind, p, s, label, excerpt) in enumerate(shown, 1):
            print("  [%d] %s（%s，匹配 %d）" % (i, label, kind, s))
            for ln in _key_lines(p, kws, 3) or ["(该文件无含关键词的行，用 --level full 看正文)"]:
                print("      %s" % ln[:130])
    elif rag:
        print()
        print("=" * 72)
        print("## RAG 注入（full 档：前 %d 条正文，直接当上下文用，不必再 read 文件）" % len(shown))
        for i, (kind, p, s, label, excerpt) in enumerate(shown, 1):
            print()
            print("### [%d] %s  （%s，匹配 %d）" % (i, label, kind, s))
            print(excerpt)
        print("=" * 72)
    else:
        print()
        print("  ⚠ 加上 --rag 可直接看到命中正文（省掉再 read 文件的两三次调用）")

    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "event": "lookup", "keywords": kws,
           "note": note, "rag": bool(rag),
           "matched": [{"kind": k, "file": str(p), "score": s, "label": lb} for k, p, s, lb, _ex in hits[:12]]}
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print("\n  已记一条 usage -> %s" % LEDGER.relative_to(ROOT))
    return 0 if hits else 0


def read_ledger() -> list[dict]:
    if not LEDGER.exists():
        return []
    out = []
    for line in LEDGER.read_text("utf-8", "ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def cmd_record(event: str, detail: str, used=None, outcome: str = "", target: str = "") -> int:
    # 2026-09-18 沉淀改造④：outcome 记录新增 used 字段 = 这条经验**被应用**的结构化证据
    # （§32 的 P<n> 列表）。audit_sediment 的「退休机制」只认这个字段，不认自由文本。
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "event": event, "detail": detail}
    if outcome:
        rec["outcome"] = outcome
    if used:
        rec["used"] = used
    # 2026-09-21 加：回填必须能**绑定目标**。不加 target 时一条回填会解锁 24h 内所有目标，
    # 实测造成过假 PASS（万华被万章盈科的回填"洗白"）。
    if target:
        rec["target"] = target
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print("已记: %s | %s" % (event, detail))
    return 0


def cmd_report() -> int:
    rows = read_ledger()
    lookups = [r for r in rows if r.get("event") == "lookup"]
    outcomes = [r for r in rows if r.get("event") == "outcome"]
    matched_files = set()
    for r in lookups:
        for m in r.get("matched", []):
            # 报表也按阈值过滤：旧账本里可能残留宽松匹配（阈值是后加的）
            if m.get("score", 0) >= MIN_SCORE:
                matched_files.add(m.get("file"))
    pb_all = sorted(p.name for p in PB.glob("*.md"))
    pb_used = sorted({Path(f).name for f in matched_files if str(f).endswith(".md") and "product-playbooks" in str(f).replace("\\", "/")})
    ref_all = [p for p in reference_docs() if "src-report-template" not in p.name]
    ref_names = {p.name for p in ref_all}
    pb_used = sorted(set(pb_used) | {Path(str(f)).name for f in matched_files if Path(str(f)).name in ref_names})
    hcl = load(HCL)
    secs = [t for t, _ in sections(hcl)]

    print("# 沉淀利用报表")
    print("  账本: %s" % (LEDGER.relative_to(ROOT) if LEDGER.exists() else "(尚无)"))
    print("  查询(使用)记录 %d 条 / 结果回填 %d 条" % (len(lookups), len(outcomes)))
    print()
    print("  == 产品手册 %d 本 ==" % len(pb_all))
    for n in pb_all:
        print("     [%s] %s" % ("用过" if n in pb_used else "未用", n))
    if ref_all:
        print("  == 技能内手册/清单 %d 本 ==" % len(ref_all))
        for p in ref_all:
            print("     [%s] %s/%s" % ("用过" if p.name in pb_used else "未用", p.parent.parent.name, p.name))
    print("  == 案例库章节 %d 节（是否被查过需人工看正文引用）==" % len(secs))
    # 2026-09-15 修：原来用「历史所有查询关键词是否是标题子串」判定，会把 §5 误标成已用
    # （被 §20.5 之类的标题/别的查询词捎带），覆盖率虚高。改为：只有该节真的出现在某次查询的
    # matched 列表里（score ≥ MIN_SCORE）才算「查到过」——与 audit_sediment.py 口径一致。
    seen_nums = set()
    for r in lookups:
        for m in r.get("matched", []):
            if m.get("score", 0) < MIN_SCORE:
                continue
            sm = re.search(r"hit-case-library §([0-9]+(?:\.[0-9]+[a-z]?)?)", m.get("label") or "")
            if sm:
                seen_nums.add(sm.group(1))
    for t in secs:
        nm = re.match(r"([0-9]+(?:\.[0-9]+)?)", t)
        used = bool(nm and nm.group(1) in seen_nums)
        print("     [%s] §%s" % ("查到过" if used else "   ", t[:64]))
    print()
    if outcomes:
        print("  == 最近结果回填 ==")
        for r in outcomes[-8:]:
            print("     %s  %s" % (r.get("ts"), str(r.get("detail"))[:150]))
    else:
        print("  ⚠ **尚无任何 --outcome 回填** —— 说明只记了「查」，没记「结果」，闭环未合上。")
    print()
    print("  判据提醒：**手册被写出来但从未出现在任何 lookup 的 matched 里 = 只沉淀不利用**。")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("keywords", nargs="*", help="目标指纹/攻击面关键词")
    ap.add_argument("--outcome", choices=["hit", "miss", "partial"], help="实战结果回填")
    ap.add_argument("--detail", default="", help="结果明细")
    ap.add_argument("--target", default="",
                    help="本次回填针对的资产（域名/IP）。**强烈建议填** —— 不填则回填是会话级的，\n"
                         "会让窗口内任意目标都判定为已交代（曾造成假 PASS）")
    ap.add_argument("--rag", action="store_true",
                    help="直接打印命中内容的**正文片段**（RAG 注入，省掉再 read 文件的 2-3 次调用）")
    ap.add_argument("--rag-chars", type=int, default=900, dest="rag_chars",
                    help="每条命中注入的正文长度上限（默认 900 字）")
    ap.add_argument("--top", type=int, default=3, help="RAG 模式下注入前 N 条（默认 3）")
    ap.add_argument("--level", choices=["brief", "full"], default="full",
                    help="RAG 分层：brief 只给标题+首行摘要（省 token），full 给正文片段")
    ap.add_argument("--report", action="store_true", help="利用率报表")
    ap.add_argument("--used", default="",
                    help="本条实战**实际用到**了哪些 §32 模式（逗号分隔，如 P7,P23）——"
                         "退休机制的计数来源；不填就只算『被查询过』，不算『被应用过』")
    a = ap.parse_args()
    if a.report:
        return cmd_report()
    if a.outcome:
        used = [x.strip().upper() for x in a.used.split(",") if x.strip()]
        return cmd_record("outcome", "%s | %s" % (a.outcome, a.detail), used=used, outcome=a.outcome,
                           target=a.target)
    if not a.keywords:
        print(__doc__)
        return 0
    return cmd_lookup(a.keywords, a.detail, rag=a.rag, rag_chars=a.rag_chars, top=a.top, level=a.level)


if __name__ == "__main__":
    sys.exit(main())
