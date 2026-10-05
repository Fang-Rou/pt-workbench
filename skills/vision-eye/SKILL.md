---
name: vision-eye
description: 视觉眼睛钩子（按需调用）。当会话模型无原生读图(read_image 不可用)，又需要"看"图——用户发图/点名某张图要判断或对比、截图质检(空屏/黑屏/地址栏/构图)、表单回读存疑、判断哪张图不对——调用本钩子：用 vision 模型(deepseek-v4-flash-vision-exp)经工作区 scripts/vision_qa.py 看图作答。命中场景：看图说话、图内容判断、截图粗检。反触发：不需要看图的任务不调；已有机器记录(page.txt/raw/window.json)可回答时不调；vision 输出只当粗检辅助，精确内容一律以机器记录为准。
---

# vision-eye — 视觉眼睛钩子

> 形态：**钩子** = 需要时自主调用，不设"拍完图必须先跑/见图必先看"式硬触发义务。
> 何时拉这个钩子由执行者按任务需要判断；拉不拉都不违规。

## 环境

- 执行目录：`D:\渗透工作流\_PT工作台`（工作区约定：命令都在此目录跑，`$py` = 下方 Python）
- Python：`D:\渗透工作流\_PT工作台\.venv\Scripts\python.exe`（Python 3.13.5；2026-09-12 起，原 bundled Python 被删已不可用）
- 脚本：`scripts\vision_qa.py`（绝对路径 `D:\渗透工作流\_PT工作台\scripts\vision_qa.py`）
- 密钥：`state/private/vision.env`（BASE_URL/API_KEY/MODEL，不外传、不进交付/外协/简报）
- 模型：deepseek-v4-flash-vision-exp（主会话模型 deepseek-v4-flash 无图像输入，故走此通道）

## 调用

```text
$py scripts\vision_qa.py <图片路径> [图片路径...] --q "<问题>"
$py scripts\vision_qa.py <目录> --each --q "<问题>"     # 目录内全部 png 逐张 QA
$py scripts\vision_qa.py <图> --think --q "<问题>"       # 复杂推演才开思考（默认关）
```

- **默认关思考（2026-09-10 接线）**：脚本写死 `thinking={"type":"disabled"}`（AGENTS.md 云端调用规范：
  机械判读省时省 token），`--think` 才开。实测同图 3 次（毫秒）：OFF 1456/1244/1586，ON 1756/2114/1479
  ——简单图上差距不大，但 OFF 从不更慢且合规，故为默认。
- **UNSURE 上行（别将就模糊回答）**：回答含糊（"看不清/无法确定/不确定"）时按 ①换更明确的问法 →
  ②`--think` 重问 → ③回退机器记录 的顺序升级；仍不确定就如实报给用户，**不把模糊结论当证据**。
- 默认问题即窗口截图四要素粗检：地址栏 URL / 内容清晰 / 空黑屏 / 是否像真窗口
- 产物（--each）：`results/vision-qa/<图片名>.qa.txt`

## 值得拉钩子的场景

1. 用户发来一张图、点名某张图（"这张对吗/你看下/哪张不对"）——先看图再回应，不许空口猜。
2. 拍完证据图后想快速粗检空屏/黑屏/地址栏/构图（FAIL 即重拍）。
3. 涉及"地址栏清晰不清晰 / 内容可见不可见 / 两张图差异"类判断。
4. 表单回读、页面截图内容存疑，需要第二双眼睛核验。

## 不必拉的场景（避免无谓开销）

- 已有等价机器记录（`*.page.txt`、`*.cmdlog.txt`、`window.json`、原始响应落盘）能回答——机器记录优先且更准。
- 纯文本/纯 JSON 数据核对（直接读文件，别绕一圈 vision）。
- 当前模型有原生 read_image 时（直接用原生，不经过本钩子）。

## 边界（实测教训，必须遵守）

- vision 只做**粗检**：空屏/黑屏/地址栏可见与 URL 主机/内容类型/构图/是否像真窗口。
- **vision 逐字读取会幻觉**（实测把凭据与文件名单读错）——严禁用 vision 输出当字节级证据；
  精确内容一律以机器记录为准（CDP innerText `*.page.txt`、printToPDF 页眉 PDF、`window.json`、原始抓包）。
- vision 说"是/否"由执行者结合机器记录裁断，不盲信单张结论；FAIL（空白/黑屏/地址栏不可见）才触发重拍。

## 接线与维护

- 本技能通过 **junction** 注册进会话 skill 目录：
  `D:\渗透工作流\.dsh\skills\vision-eye` → `_PT工作台\skills\vision-eye`
  （改本文件即时生效；**不要再另存一份副本**——2026-09-10 前的 `.dsh` 手改副本已合并回本文件并删除）。
- 体检/修复全部技能接线：`$py scripts\sync_skills.py`（`--check` 只体检不改动）；新增技能同法建 junction。
