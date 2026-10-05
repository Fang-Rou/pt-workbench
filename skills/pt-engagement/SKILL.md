---
name: pt-engagement
description: 当开始一个渗透测试项目（客户委托 / 内网评估 / 攻防演练 / 红队任务）、需要确定范围与交战规则、规划 kill-chain 阶段、推进多跳攻击链、把控取证标准、写客户交付报告、做风险定级与整改跟踪时调用。命中场景：接到新委托不知道从哪下手 / 忘了上一步打到哪 / 链条断了要续 / 不确定啥算「打成了」/ 报告要写哪些章节 / 漏洞怎么定级 / 客户要整改清单 / 实战结束不知道沉淀什么。
---

# 渗透测试项目规范（pt-engagement）

> 本技能是**项目层**规范：怎么开一个项目、怎么推进、怎么收尾。
> 具体漏洞类的手法在各专项技能里（`injection-vulns` / `auth-access-control` / …）；
> 20 条成熟攻击链在 `references/attack-arsenal.md`；模式库在
> `references/hit-case-library-2026.md` §32（**动脑前先读 §32**）。

## 0. 与 SRC 流程的根本差别（改造说明）

以前这套工作流是给**公益 SRC 平台**用的：授权来自平台页面声明、判据是备案主体、终点是「提交漏洞」。
渗透测试不是这样：

| 维度 | SRC | 渗透测试（本工作流） |
| --- | --- | --- |
| 授权来源 | 平台项目页声明 | **委托合同 / 授权书**（纸面，不在库里） |
| 范围判据 | ICP 备案主体 × 厂池 | 委托书写的资产清单（登记进 `engagement.scope`） |
| 终点 | 提交单个漏洞拿赏金 | **完整报告 + 整改跟踪**，覆盖约定周期 |
| 深度 | 单点 PoC 闭环即可 | 允许并要求**横向 / 提权 / 后渗透**，看整体风险 |
| 证据 | 够审核员认就行 | 够客户复现 + 够复盘（可复跑、可对账） |
| 平台耦合 | 表单字段 / 级别 / 公告口径 | 无 |

⇒ 因此本工作区删掉了补天/漏洞盒子提交链、厂池、公告与受理口径、备案归属闸门。
保留并强化的是：侦察引擎、20 条攻击链、多阶段链状态、取证与截图流水线、技能库。

## 1. 开工三步（顺序不能反）

```bash
# ① 建项目（把委托书里的范围登记进来）—— 这是唯一的「项目身份」
$py scripts/engagement.py new --client "客户全称" --domain example.com \
      --scope-host example.com --scope-host "*.example.com" --scope-cidr 10.0.0.0/24 \
      --window 2026-10-01..2026-10-15 --roe "禁止DoS；生产库只读；不得触碰 10.0.0.9" \
      --auth-basis "委托合同" --auth-ref "合同号 XX-2026-101 / 授权书扫描件在 原始记录/"
# 没走合同的项目：--auth-basis 换成 "平台项目声明" / "自有资产" / "靶场或比赛"，
# 并把依据出处写进 --auth-ref（平台项目页 URL、靶场说明链接…）。
# 后期补/改：engagement.py auth <slug> --basis "平台项目声明" --ref "<URL>"

# ② 看范围：谁在册、授权依据、有没有 strict_scope
$py scripts/scope_gate.py --show

# ③ 拿目标（从公司名反查资产 / 或直接给域名）
$py scripts/recon_api.py all example.com            # 被动测绘，不碰目标
$py scripts/fofa_reverse.py --vendor "某某科技有限公司"
```

**再说一遍**：`scope_gate.py` 只在项目显式写了 `"strict_scope": true` 时才拦外范围主机。
默认它只**标注**——授权判定在委托书里，不该由脚本替你判。但**报告里的「测试范围」章节
必须与登记一致**，客户会拿它比对。

## 2. Kill-chain 阶段机（`engagement.py` 的 phase）

```
recon → enum → foothold → escalate → lateral → exfil → report → archived
```

| phase | 含什么 | 出门判据（说不清就别往下走） |
| --- | --- | --- |
| `recon` | 被动测绘、子域、证书、历史 URL、指纹、供应链 | 资产清单落盘 + 指纹矩阵，能说出"主要入口有几个" |
| `enum` | 端口/服务、接口枚举、JS 抽接口与密钥、登录面 | 每个入口有「能打的面」清单，或明确的负结论 |
| `foothold` | 首个可用立足点（RCE / 上传落地 / 有效凭据 / 越权读数据） | **有可复现的实证**（不是"理论上能"） |
| `escalate` | 本地提权（内核 / SUID / 服务 / 令牌 / 配置） | 拿到了更高权限的**实际命令输出** |
| `lateral` | 凭据复用、隧道、横向 SMB/WMI/WinRM/SSH、域内路径 | 第二台主机上的实际立足证据 + 横向路径图 |
| `exfil` | 数据访问范围证明（只取样本）、影响面确认 | **样本 + 条数 + 只读证明**，不拖库 |
| `report` | 报告 + 复现附录 + 整改清单 | 闸门 PASS（见 §4） |
| `archived` | 复盘、沉淀、环境回收 | delta 已写进手册 |

推进怎么写：

```bash
$py scripts/engagement.py hop <slug> --action "对 gw 跑 actuator 探测" --result "2 个端点未授权"
$py scripts/engagement.py lead <slug> --id L3 --what "heapdump 里可能有凭据" --status open
$py scripts/engagement.py phase <slug> --set lateral --reason "已拿到第二跳立足点"
$py scripts/engagement.py graph <slug>          # 落盘攻击图（hosts / edges / creds）
```

**铁律：链状态只认 `state/engagements/<slug>.json`，不认我的上下文。** 会话断了就 `engagement.py show`。

## 3. 取证标准（渗透测试要能复现，不只是"能提"）

| 漏洞类 | 取证下限 | 常见不合格 |
| --- | --- | --- |
| 命令执行 / RCE | 真实命令输出（`id` / `hostname` / 文件落地） | 只贴 payload 和 200 |
| 注入 | 库→表→字段→内容四连（只取 3 行样本）+ 延时对照（基线 / 4s / 1=1 / 1=2） | 只证明"能注" |
| 越权 / IDOR | **双账号互测**：A 的凭据读到 B 的真实数据，字段级展示 + 前后对照 | 只说明"参数可改" |
| 未授权接口 | 返回**真实非公开数据样本**（字段 + 条数 + 时间） | 返回的是前端本来可见的数据 |
| 凭据 / 密钥泄露 | **有效性实证**（可登录 / 可 clone / 可调用 / 可上传后删除验证） | "假设管理员勾选" |
| 文件上传 / 读取 | 真实落地 + 可访问（200）+ 下载回验 + 类型判别 | 只返回附件标识 |
| SSRF | 真实请求到内网/元数据 + 响应内容片段；盲 SSRF 走带外回连日志 | 只证明"服务端发起了请求" |
| 内网横向 | 目标机上的实际命令输出 + 来源主机标识 + 时间戳 | 只有"能连上"的截图 |
| 提权 | `id`/`whoami /priv` 前后对照 + 提权路径每一步命令 | 只有本地脚本跑出了 EXP |
| XSS / CSRF | 影响**其他**用户（双账号受控演示），不是测自己 | 只有自己弹窗 |

**取证文字纪律**：任何"实际影响"都要能指到**原始记录**（`results/` 与交付包 `原始记录/`）。
报告里的每句话，都要能在原始记录里找到出处——客户和复盘的你会来对账。

截图与窗口级证据沿用原流水线：`scripts/evidence_shot_window.py` / `imou_term_shot.py`，
要求见 `references/evidence-shot-runbook.md`（真实窗口实拍；本机渲染页 `127.0.0.1`/`file://` 不算证据）。

## 4. 交付与闸门

```bash
$py scripts/assemble_deliver.py --slug <slug>            # 组交付包到 _交付/<slug>/
$py scripts/report_gate.py --deliver "_交付/<slug>"      # 唯一闸门：PASS 才算报告可用
$py scripts/findings_export.py --slug <slug>             # 导出发现清单（CSV 给客户）
$py scripts/remediation_tracker.py --slug <slug> --init  # 整改跟踪表
```

交付包结构（`_交付/<slug>/`）：

```
报告-<slug>.md                  客户主报告（章节见 references/pt-report-template.md）
README-复现指南.md              客户方复跑的步骤，每条命令都本机跑通过
复现脚本/                       最小可复现 PoC
原始记录/                       请求响应、dump、探测记录、时间线
窗口级截图/                     真实窗口实拍 + page.txt / cmdlog.txt / window.json
整改跟踪表.md                   逐条发现的状态与验证方式
```

**报告写作要点**：客户报告 ≠ 漏洞提交单。
① 先给**管理层摘要**（风险总体判断、Top 风险、不改会怎样）；
② 再给**技术发现**（每条：位置 / 复现 / 证据 / 影响 / 修复 / 验证方法）；
③ 最后给**附录**（范围与方法、工具、时间线、遗留问题）。
模板：`references/pt-report-template.md`；定级与整改表：`references/risk-rating-and-remediation.md`。

## 5. 数据与操作纪律

- **只读取证优先**：不为"证明危害"去改、删、加密客户数据。要写时只写**随机命名标记**，
  取证后立即清理并留清理记录。
- **数据最小化**：只取证明所需的样本（3 行 / 3 条），脱敏后写进报告，原始值只留在交付包原始记录里。
- **不做与范围无关的事**：不给无关方写文件、不扫范围外 IP、不用客户环境做演练以外的用途。
- **生产环境优先"最小动作"**：需要重启 / 停服 / 改配置时走客户确认（写进 `engagement.roe`）。
- **凭据卫生**：实战中拿到的凭据只用于本次范围；不落进 git、不进公开笔记；报告里脱敏。

## 6. 收尾（做完不沉淀 = 白做）

1. `engagement.py phase <slug> --set archived`，把 hop/lead 结局写全（含死胡同）。
2. 新手法 → 写进 `references/attack-arsenal.md` 或对应专项技能，**五段式**（信号 / 思路 / 动作 / 闭环判据 / 死法）。
3. 新案例 → 追加进 `references/hit-case-library-2026.md`，只在 §32 补**模式**，案例作出处。
4. 跑 `$py scripts/audit_sediment.py` 看这次沉淀有没有落进「会被读到」的位置。
5. `report_gate.py` 必须 PASS；整改表状态与发现一致。

## 红线清单

```text
- 范围外资产（scope 表外的 host / IP 段）
- 拖库、批量导出客户数据（只取证明所需样本）
- 破坏性操作：删数据、改密、加密、停服（除非 ROE 明写且客户确认）
- 命令执行后写 shell / 留后门（演练要求例外，且须在报告与 ROE 里声明）
- 大规模扫描器怼生产（走 batch_recon.py 的节流与预算）
- 把客户凭据 / 数据带出范围或用于本次之外
```

## 交接

- 资产问题 → `recon-info-collection`
- JS/接口 → `recon-js-analysis`
- 中间件 Nday → `middleware-framework-nday`
- 登录/越权 → `auth-access-control`
- 横向移动 → `lateral-movement`
- 提权 / 持久化 / C2 → `post-exploitation`
- 注入/文件/SSRF/XSS → 对应专项技能

## 手册索引（先读，方法复用）

- 20 条攻击链（信号 / 第一跳 / 闭环判据 / 取证 / 迁移 / 死法）: `references/attack-arsenal.md`
- 实战案例与方法提炼（含 §32 模式库 P1–P28）: `references/hit-case-library-2026.md`
- 手法覆盖度矩阵（这一轮该练哪族）: `references/method-coverage-matrix.md`
- 取证与截图手册: `references/evidence-shot-runbook.md`
- 证据不足怎么补（"理论危害"被质疑时）: `references/evidence-escalation.md`
- 客户报告模板: `references/pt-report-template.md`
- 定级与整改: `references/risk-rating-and-remediation.md`
