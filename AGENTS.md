# AGENTS.md — LLM 会话运行规则

本工作区是**授权渗透测试工作台**。新会话开始时读这一份，其余按需查。

> 红线：只在书面授权范围内测试。没有 ROE / 委托书的目标，一律不动手。

## 0. 四个默认入口

| 时机 | 命令 |
|---|---|
| 开新项目 | `python scripts/engagement.py new ...` 然后 `engagement.py use <slug>` |
| 看范围 | `python scripts/scope_gate.py --show` |
| 交付前 | `python scripts/report_gate.py --deliver <dir>` |
| 续接会话 | `python scripts/next.py` |

## 1. 防中断（最高优先）

1. 单轮只做一个有界单元：预计前台 >2 分钟、或还要连做 5 次以上工具调用，先拆分。
2. 长任务一律后台托管：`python scripts/job.py start --name <n> --cmd "<cmd>"`。
3. 里程碑、浏览器自动化、交付组装前：`python scripts/checkpoint.py --next-file state/next.txt`。
4. 续接只跑 `next.py`，不要重读旧对话。
5. 大文件只落盘不整读，输出限 20–50 行。复杂字符串一律走文件，禁止 `python -c "..."`。
6. 外部调用先判退出码，不检查 = 吞错。

## 2. 状态约定

- 项目档案：`state/engagements/<slug>.json`
- 链状态只认磁盘 JSON，不认上下文
- 碎片利用点 `leads[]` 带 status 和 blocked_by
- 攻击图 `graph`：hosts / edges / creds / c2
- 产物路径写在 `artifacts`，证据不许只留在对话里

## 3. 范围与授权

- `scope_gate.py` 默认登记不阻断（授权在委托书里）
- 只有项目显式 `strict_scope: true` 才拦外范围
- 外范围主机**只标注不测试**
- 报告引用 ROE 原文

## 4. 交付

- 唯一闸门：`report_gate.py`
- 检查：证据齐 / 报告形态 / 范围一致 / PoC 可复现
- 一次跑完只出一个 VERDICT

## 5. 目录红线

不进 git 的目录：
- `state/` `evidence/` `pocs/` `results/` `deliverables/`
- `chrome-profile/` `.venv*/` `__pycache__/`
- 任何含真实客户名、域名、IP、凭据的文件
