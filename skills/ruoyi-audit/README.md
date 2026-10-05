# ruoyi-audit — RuoYi 系审计资产

> 研究线 `reports/ruoyi-research-track.md` 的沉淀层；手册 `skills/product-playbooks/references/ruoyi.md`
> 负责打法与案例，本目录负责可复用资产（规则/映射/目录/清单）。

## 资产

| 文件 | 内容 | 状态 |
| --- | --- | --- |
| `fingerprints.json` | 指纹规则 v1（强/弱信号、探针集、误报模式） | 2026-09-02 首轮实测 |
| `version-map.json` | 页面/JS 特征 → 上游版本映射 | 起步（csifs: ry-ui.js?v=4.8.1） |
| `vuln-catalog.json` | 公开漏洞目录（CVE/GHSA + 影响 + 修复） | 种子级，需逐条核验 |
| `audit-checklist.md` | 二开审计 checklist（六条候选链 → 可执行步骤） | 骨架 |

## 用法

- 指纹扫描器：`scripts/ruoyi_fp_scan.py`（主域池）/ `scripts/ruoyi_fp_subs.py`（子域池，纯 stdlib）
- 命中 → 读 `references/ruoyi.md` 候选链 → 按 checklist 定向验证
- 新经验回写三处：本目录资产 + ruoyi.md + research-track
