# -*- coding: utf-8 -*-
"""report_evidence_gate.py — 报告「形式证据」闸门（2026-09-18 立，源自补天 28 条驳回原话统计）。

为什么要有它：全量统计显示，**图片缺失占驳回的 43%**，是头号杀手，且 100% 可控。
补天审核员原话（QTVA-2026-10895402）：
    「报告完整性、可复现性和规范性均良好……**但按 Skill 规则，报告全文无 img 图片标签，直接判定不通过**」
⇒ 文字与请求响应证据再齐全，**只要正文没有 img 标签就是必驳**。

同时扫「理论风险」措辞（占 39%）：平台原话反复用
    「所述影响仅为……的**理论风险**，未形成实际安全影响」
其中三种措辞几乎必驳：**降低攻击门槛 / 配合其他漏洞 / 可进一步利用**。

用法：python scripts/report_evidence_gate.py <报告.md|.html> [--min-img 1]
退出码：0=PASS，1=FAIL
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.stdout.isatty():
    sys.stdout.reconfigure(errors="replace")
else:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 平台明说「直接判定不通过」的硬拦措辞（出自 28 条驳回原话）
HARD_PHRASES = ["降低攻击门槛", "配合其他漏洞", "可进一步利用", "进一步利用可"]
SOFT_PHRASES = ["理论风险", "理论可能", "理论推断", "假设攻击者", "若攻击者"]
IMG_HTML = re.compile(r"<img\b", re.I)
IMG_MD = re.compile(r"!\[[^\]]*\]\([^)]+\)")

# 2026-09-24 加（用户明示，规范化为交付标准）：**图文关联 —— 具体截图放在每一步的步骤下**。
# 触发场景：补天历史驳回原话「报告可读性太差，图文请关联起来，具体的截图放在每一步的步骤下」；
# 同月 QTVA-2026-10986140 又被判「还需要完善」⇒ 把「图堆在文末」从看不顺眼变成机器可拦的 FAIL。
STEP_H = re.compile(r"^\s{0,3}(?:#{1,6}\s*)?(?:\*\*)?\s*(?:步骤|第\s*[0-9一二三四五六七八九十]+\s*步|Step\s*\d+)", re.I)
HEAD_H = re.compile(r"^\s{0,3}#{1,6}\s+\S")


def image_layout(text: str):
    """图文关联检查 -> (problems, warns, total)。

    判据一：图片不得堆在文末（>=2 张且过半落在全文最后 20% 行内 = FAIL）。
    判据二：图数 >= 步骤小节数时，每个步骤小节都必须有图（图不够则只 WARN）。
    """
    lines = text.splitlines()
    n = len(lines)
    heads = [i for i, l in enumerate(lines) if HEAD_H.match(l)]
    pos = []
    for i, l in enumerate(lines):
        pos += [i] * (len(IMG_HTML.findall(l)) + len(IMG_MD.findall(l)))
    total = len(pos)
    if total == 0:
        return [], [], 0
    problems, warns = [], []
    tail_start = int(n * 0.8)
    in_tail = sum(1 for i in pos if i >= tail_start)
    if total >= 2 and in_tail * 2 >= total:
        problems.append("图片堆在文末：%d/%d 张落在全文最后 20%% 行内 → 违反「图文关联，具体的截图放在每一步的步骤下」"
                        "（补天驳回原话）；每张图应移到对应步骤的正下方" % (in_tail, total))
    import bisect

    def blk(i):
        return bisect.bisect_right(heads, i) - 1

    steps = [h for h in heads if STEP_H.match(lines[h])]
    if len(steps) >= 2 and total >= 2:
        per = {}
        for i in pos:
            per[blk(i)] = per.get(blk(i), 0) + 1
        missing = [h for h in steps if per.get(blk(h), 0) == 0]
        if missing and total >= len(steps):
            problems.append("步骤缺图：图 %d 张 >= 步骤 %d 个，却有 %d 个步骤小节没有图片 → %s"
                            % (total, len(steps), len(missing),
                               "; ".join(lines[h].strip()[:30] for h in missing[:4])))
        elif missing:
            warns.append("步骤缺图 %d 个（图数少于步骤数，暂只提醒）" % len(missing))
    return problems, warns, total


def count_images(text: str) -> tuple[int, int]:
    return len(IMG_HTML.findall(text)), len(IMG_MD.findall(text))


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("用法: report_evidence_gate.py <报告.md|.html> [--min-img N]")
        return 2
    p = Path(args[0])
    if not p.exists():
        print("找不到文件: %s" % p)
        return 2
    min_img = 1
    if "--min-img" in sys.argv:
        min_img = int(sys.argv[sys.argv.index("--min-img") + 1])
    text = p.read_text("utf-8", "ignore")
    html_n, md_n = count_images(text)
    total = html_n + md_n
    hard = [(ph, len(re.findall(ph, text))) for ph in HARD_PHRASES]
    hard = [(ph, n) for ph, n in hard if n]
    soft = [(ph, len(re.findall(ph, text))) for ph in SOFT_PHRASES]
    soft = [(ph, n) for ph, n in soft if n]

    lay_p, lay_w, _ = image_layout(text)
    print("# 报告形式证据闸门: %s" % p.name)
    print("  图片标签: <img> x%d + ![]() x%d = **%d**（要求 >= %d）" % (html_n, md_n, total, min_img))
    if total < min_img:
        print("  [FAIL] 图片不足。平台原话（QTVA-2026-10895402）：")
        print("         「报告完整性、可复现性和规范性均良好……但按 Skill 规则，")
        print("           报告全文无 img 图片标签，直接判定不通过」")
        print("         高频伴随句（10 条）：『且详细细节中图片缺失或不完整』")
    if hard:
        print("  [FAIL] 命中平台『几乎必驳』措辞:")
        for ph, n in hard:
            print("         '%s' x%d —— 平台原话：『所述影响仅为降低攻击门槛和配合其他漏洞利用的理论风险，"
                  "未获取非公开敏感数据，未形成实际安全影响』（QTVA-2026-10908770）" % (ph, n))
    if soft:
        print("  [WARN] 命中『理论风险』类措辞 %d 处（占驳回 39%）:" % sum(n for _, n in soft))
        for ph, n in soft:
            print("         '%s' x%d" % (ph, n))
        print("         修法：把主张换成**已发生**的实际影响（真实数据读取／真实状态改变／真实资源消耗／有效凭据实证）。")

    for pr in lay_p:
        print("  [FAIL] " + pr)
    for wn in lay_w:
        print("  [WARN] " + wn)

    ok = total >= min_img and not hard and not lay_p
    print("\nVERDICT=%s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
