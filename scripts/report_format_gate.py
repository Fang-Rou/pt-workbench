# -*- coding: utf-8 -*-
"""report_format_gate.py —— 报告形态闸门（通用渗透报告骨架）。

改造说明（2026-10-01）：原版判的是**补天审核员 5 条硬要求**（标题【产品名+版本号】等），
那套随 SRC 层移除。现在判的是**客户交付报告**的骨架，口径来自
`skills/pt-engagement/references/pt-report-template.md`。

保留的两条通用经验（与平台无关，同样会毁掉报告）：
  · **去 AI 味**：解析性套话命中 >= 3 个即 FAIL（词表见 AI_CLICHES）
  · **图文配对**：数据包/步骤后要紧跟对应截图，别把图堆文末

用法: python scripts/report_format_gate.py <报告.md>
退出码 0=PASS 1=FAIL
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# 解析性套话（AI 味）。按实际出现过、读起来最"生成感"的措辞收的，命中 >=3 个直接 FAIL。
AI_CLICHES = ("首先", "其次，", "再次，", "综上所述", "值得注意的是", "旨在", "需要指出的是", "总的来说",
              "总而言之", "也就是说", "换句话说", "本质上是", "想做的事", "现实一点的场景",
              "这里的关键", "不难看出", "由此可见", "更重要的是", "顺带一提", "我们可以看到",
              "值得一提的是", "毋庸置疑", "不可估量")

# 必需章节（标题里含其一即可）
REQUIRED_SECTIONS = {
    "执行摘要": ("执行摘要", "管理层摘要", "摘要"),
    "测试范围与方法": ("测试范围", "范围与方法", "测试方法"),
    "风险总览": ("风险总览", "风险汇总", "发现汇总"),
    "发现详情": ("发现详情", "漏洞详情", "详细发现", "技术发现"),
    "修复优先级": ("修复优先级", "修复建议汇总", "整改优先级"),
    "附录": ("附录",),
}

# 每条发现应含的要素（全文层面判，缺 2 个以上即 FAIL）
FINDING_ELEMENTS = {
    "位置": ("位置", "URL", "接口", "主机"),
    "复现": ("复现", "重现", "验证步骤"),
    "证据": ("证据", "请求", "响应", "报文"),
    "实际影响": ("实际影响", "影响", "危害"),
    "修复建议": ("修复建议", "修复方案", "整改建议"),
    "验证方法": ("验证方法", "复测", "验证方式"),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    a = ap.parse_args()
    p = Path(a.report)
    if not p.is_absolute() and not p.is_file():
        base = Path(__file__).resolve().parent.parent
        for cand in (base / p, base.parent / p):
            if cand.is_file():
                p = cand
                break
    if not p.is_file():
        print("FAIL: 报告不存在 %s" % p)
        return 1

    txt = p.read_text("utf-8", "ignore")
    print("# 报告形态闸门（客户交付骨架）: %s" % p.name)
    bad: list[str] = []

    # ① 必需章节
    miss = [k for k, alts in REQUIRED_SECTIONS.items() if not any(x in txt for x in alts)]
    ok1 = not miss
    print("  [%s] ① 必需章节 : 缺 %s" % ("PASS" if ok1 else "FAIL", miss or "无"))
    if not ok1:
        bad.append("补上缺的章节 %s（骨架：skills/pt-engagement/references/pt-report-template.md）" % miss)

    # ② 范围声明（客户第一个看的章节）
    seg = ""
    m = re.search(r"##[^\n]*范围[^\n]*\n(.{0,3000})", txt, re.S)
    if m:
        seg = m.group(1)
    ok2 = bool(seg.strip()) and ("不在范围" in txt or "排除" in txt or "限制" in txt)
    print("  [%s] ② 范围与方法（含「不在范围」声明） : %s"
          % ("PASS" if ok2 else "FAIL", "有" if ok2 else "缺范围节或没写不在范围"))
    if not ok2:
        bad.append("「测试范围与方法」要写明范围内资产**和明确不在范围的部分**（客户会拿它比对）")

    # ③ 发现要素齐全
    miss3 = [k for k, alts in FINDING_ELEMENTS.items() if not any(x in txt for x in alts)]
    ok3 = len(miss3) <= 1
    print("  [%s] ③ 发现要素（位置/复现/证据/影响/修复/验证） : 缺 %s"
          % ("PASS" if ok3 else "FAIL", miss3 or "无"))
    if not ok3:
        bad.append("每条发现要含 %s —— 缺的补上，别只写复现步骤" % miss3)

    # ④ 影响要指到证据（禁止纯"理论上"）
    soft = [w for w in ("理论上", "可能被", "如果攻击者", "假设") if w in txt]
    ok4 = len(soft) < 6
    print("  [%s] ④ 不写「理论危害」 : 推测性措辞 %d 处 %s"
          % ("PASS" if ok4 else "FAIL", len(soft), soft or "无"))
    if not ok4:
        bad.append("删掉推测性措辞（%s），把「已发生」的证据（读到什么/拿到什么权限）写进去" % soft)

    # ⑤ 图文配对（截图不要堆文末）
    steps = len(re.findall(r"^###+ .*?(步骤|复现|验证)", txt, re.M))
    imgs = len(re.findall(r"!\[[^\]]*\]\([^\n]*?\.(?:png|jpg|jpeg)\)", txt, re.I))
    ok5 = (imgs == 0) or (steps == 0) or (imgs >= steps)
    print("  [%s] ⑤ 图文配对 : 步骤节 %d / 截图 %d（图数应 >= 步骤数）"
          % ("PASS" if ok5 else "WARN", steps, imgs))
    if not ok5:
        print("      提示：把图放到对应步骤下面；文末堆图在多条发现时读者对不上号")

    # ⑥ AI 味
    hits = [w for w in AI_CLICHES if w in txt]
    ok6 = len(hits) < 3
    print("  [%s] ⑥ 去 AI 味 : 解析性套话 %d 个 %s"
          % ("PASS" if ok6 else "FAIL", len(hits), hits or "无"))
    if not ok6:
        bad.append("删掉这些解析性套话 %s —— 只留事实、步骤与报文" % hits)

    # ⑦ 未覆盖面诚实声明
    ok7 = ("未覆盖" in txt) or ("遗留" in txt) or ("本次未测试" in txt)
    print("  [%s] ⑦ 未覆盖面声明 : %s" % ("PASS" if ok7 else "WARN", "有" if ok7 else "缺"))
    if not ok7:
        print("      提示：附录写明没测到的面，别让客户误以为全测过了")

    if bad:
        print("VERDICT=FAIL - 报告形态不合客户交付口径")
        for b in bad:
            print("  修法：%s" % b)
        return 1
    print("VERDICT=PASS - 报告形态符合客户交付骨架")
    return 0


if __name__ == "__main__":
    sys.exit(main())
