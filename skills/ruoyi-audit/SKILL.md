---
name: ruoyi-audit
description: 当侦察指纹命中 RuoYi / RuoYi-Cloud / 若依二开（ry-ui.js、/prod-api、/dev-api、druid、swagger、captcha 等信号）时调用。提供 RuoYi 系可复用审计资产：指纹规则（强/弱信号+误报模式）、页面特征到上游版本映射、公开漏洞目录（CVE/GHSA 种子，含平台收录状态）、二开审计 checklist（权限/数据范围/匿名白名单/文件存储/定时任务/Cloud 信任边界六类候选链）。命中场景：指纹疑似若依、需要把指纹转成可利用候选链、二开去特征后做归属确认、提交前查 N-day 是否已收录。配套打法见 product-playbooks/references/ruoyi.md。
---

# ruoyi-audit — RuoYi 系审计资产

> 分层：`product-playbooks/references/ruoyi.md` 负责**打法与案例**，本技能负责**可复用资产**（规则/映射/目录/清单）。
> 上游研究线：`reports/ruoyi-research-track.md`。

## 资产

| 文件 | 内容 | 状态 |
| --- | --- | --- |
| `fingerprints.json` | 指纹规则 v1（强/弱信号、探针集、误报模式） | 2026-09-02 首轮实测 |
| `version-map.json` | 页面/JS 特征 → 上游版本映射 | 起步（如 csifs: ry-ui.js?v=4.8.1） |
| `vuln-catalog.json` | 公开漏洞目录（CVE/GHSA + 影响 + 修复） | 种子级，**必须逐条核验** |
| `audit-checklist.md` | 二开审计 checklist（六类候选链 → 可执行步骤） | 骨架 |

## 用法（固定顺序）

1. **指纹**：`scripts/ruoyi_fp_scan.py`（主域池）/ `scripts/ruoyi_fp_subs.py`（子域池，纯 stdlib）；
   命中后对照 `fingerprints.json` 判强/弱信号，别被二开去特征骗过（`version-map.json` 定版本）。
2. **选链**：读 `product-playbooks/references/ruoyi.md` 的候选链 → 按 `audit-checklist.md` 六类（A 权限角色 / B 数据范围租户 / C 匿名白名单 / D 文件与对象存储 / E 定时任务监控 / F Cloud 信任边界）定向验证。
3. **查重**：候选若对应公开 CVE，先查 `vuln-catalog.json` 的 `platform_status` + 跑
   `scripts/submission_dedupe_check.py`；**种子表不是"新洞"，未核验不得提交**。
4. **证据**：按 `audit-checklist.md` 收尾段（原始请求响应落盘 + 窗口级截图 + L0 去重 + 报告落 `_交付/<slug>/`）。

## 边界（红线）

- 不爆破、不遍历越权数据、不碰真实用户数据；命中即停手取证（只读优先）。
- 仅对授权范围目标执行；二开去特征时先做归属确认再动手。
- `vuln-catalog.json` 条目 `verified:false` 的，一律先回源核验公告/修复 commit 再做判断。

## 回写（实战结束必做，含驳回）

三处同时更新：本目录资产（`fingerprints.json` / `version-map.json` / `vuln-catalog.json` / `audit-checklist.md`）
+ `product-playbooks/references/ruoyi.md` 案例索引 + `reports/ruoyi-research-track.md`。
新命中的通用教训同步进 `skills/pt-engagement/references/hit-case-library-2026.md`。
