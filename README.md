# pt-workbench

授权渗透测试的**会话外脑**：让一个多阶段攻击链活过 LLM 会话重启。

> ⚠️ 本项目仅用于**已获得书面授权**的渗透测试、授权漏洞评估、安全研究。
> 未授权扫描、入侵、利用任何系统均属违法。作者不对滥用负责。

## 解决什么问题

跟 LLM 一起做渗透时，最痛的不是"想不到下一步"，而是：

1. **链断了**——同一条利用链在同一场对话里被找回来三四次，换个会话直接归零；
2. **状态漂移**——做了什么、发现了什么、下一步去哪，全在上下文里，窗口一满就丢；
3. **交付撞车**——报告拼到一半发现截图缺关键帧、PoC 没复现步骤、范围外主机被打了；
4. **长任务阻塞**——前台跑个 5 分钟的扫描，会话就卡死，中途断了不知道跑到哪。

pt-workbench 把这些状态**全部落盘到 JSON / SQLite**，LLM 每次新会话只读摘要和链状态，不读原始数据。

## 核心设计

```
┌─────────────────────────────────────────────────────┐
│  engagement.py  = 项目档案 + kill-chain 阶段机      │
│                   状态只认磁盘 JSON，不认上下文       │
├─────────────────────────────────────────────────────┤
│  scope_gate.py  = 范围登记（默认不阻断，             │
│                   授权在委托书里，不在脚本里）        │
├─────────────────────────────────────────────────────┤
│  report_gate.py = 交付前唯一闸门：                   │
│                   证据齐不齐 / 报告形态 / 范围一致    │
├─────────────────────────────────────────────────────┤
│  job.py         = 长任务后台托管，禁止前台阻塞        │
├─────────────────────────────────────────────────────┤
│  next.py        = 新会话第一句话：续接在哪、干嘛     │
├─────────────────────────────────────────────────────┤
│  skills/        = 24 个方法论库（漏洞类型 / 阶段）    │
└─────────────────────────────────────────────────────┘
```

## 目录结构

```
pt-workbench/
├── AGENTS.md            # LLM 会话运行规则（新会话必读）
├── README.md
├── scripts/             # 框架引擎（70+ 个）
│   ├── engagement.py    #   项目档案 + kill-chain 状态机
│   ├── next.py          #   新会话续接
│   ├── checkpoint.py    #   里程碑快照
│   ├── job.py           #   后台任务托管
│   ├── scope_gate.py    #   范围登记
│   ├── report_gate.py   #   交付闸门
│   ├── arsenal.py       #   攻击链作战板
│   ├── batch_recon.py   #   批量侦察预算账本
│   ├── recon_api.py     #   被动测绘
│   ├── fofa_reverse.py  #   公司名 → 资产候选
│   ├── findings_export.py / remediation_tracker.py
│   ├── maintain.py / health_check.py / workspace_db.py
│   └── kit/             #   可复用零件（cdp 导航、截图、判定）
├── skills/              # 24 个方法论库
│   ├── injection-vulns/           auth-access-control/
│   ├── xss-frontend-security/     ssrf-internal-network/
│   ├── deserialization-xxe/       file-handling/
│   ├── api-protocol-security/     middleware-framework-nday/
│   ├── recon-info-collection/     recon-js-analysis/
│   ├── lateral-movement/          post-exploitation/
│   ├── mobile-iot-device-security/ cloud-infra-supply-chain/
│   ├── waf-bypass-techniques/    source-code-audit/
│   ├── business-logic-race/      pt-engagement/
│   ├── pentest-batch/            tool-orchestration/
│   ├── product-playbooks/        vision-eye/
│   ├── ruoyi-audit/              ai-llm-agent-security/
└── config/
    ├── agents.json          # 主流渗透 Agent 调研清单
    └── tool-registry.json  # 按阶段分类的工具清单
```

## 快速上手

```bash
# 1. 新建一个授权项目
python scripts/engagement.py new \
  --client "Acme Corp" \
  --domain example.com \
  --scope-host "example.com" --scope-host "*.example.com" \
  --scope-cidr "10.0.0.0/24" \
  --window "2026-10-01..2026-10-15" \
  --roe "禁止DoS" --roe "生产库只读" \
  --auth-basis "Signed contract #ACME-2026-1001"

python scripts/engagement.py use acme-20261001

# 2. 看范围
python scripts/scope_gate.py --show

# 3. 被动侦察（不碰目标）
python scripts/recon_api.py all example.com

# 4. 打一条链，记账
python scripts/engagement.py hop acme-20261001 \
  --action "JS 解包 15 个控制台" --result "8/15 暴露 API base"

# 5. 碎片利用点入库
python scripts/engagement.py lead acme-20261001 --id L1 \
  --what "/admin/* 白名单漏配" --status open

# 6. 长任务后台跑
python scripts/job.py start --name scan-1 --cmd "python scripts/batch_scan_next.py ..."

# 7. 交付前过闸门
python scripts/report_gate.py --deliver deliverables/acme-20261001

# 8. 新会话续接
python scripts/next.py
```

## 设计原则（踩过的坑）

1. **状态落盘，不依赖上下文**。链状态、利用点、证据路径全在 JSON/SQLite 里；LLM 换了就 `engagement.py show`。
2. **单轮只做一个有界单元**。前台命令 >2 分钟就拆后台；连做 5 次以上工具调用就先 checkpoint。
3. **复杂字符串走文件**。不在命令行里塞多行 Python/markdown；脚本写文件再跑。
4. **授权在委托书里，不在脚本里**。`scope_gate.py` 默认登记不阻断；只有项目显式 `strict_scope: true` 才拦外范围。
5. **交付前唯一闸门**。`report_gate.py` 一次跑完只出一个 VERDICT，子闸门可单独排障。
6. **客户数据不进仓库**。`state/`、`evidence/`、`pocs/`、`results/`、`deliverables/` 全部 gitignore。

## 不包含什么

- ❌ 真实客户项目、证据截图、PoC、报告
- ❌ 针对具体厂商的一次性脚本（已在 `_archive/` 本地保留，不开源）
- ❌ API key、cookie、授权文件
- ❌ 任何未授权目标的扫描规则

## License
MIT。但请遵守：仅用于授权测试；引用第三方工具时遵循其各自许可证。
