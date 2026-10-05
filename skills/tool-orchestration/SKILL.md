---
name: tool-orchestration
description: 当需要选择、安装、校验或调度渗透测试工具，按渗透阶段组织工具调用链，或把工具输出交给专项分析时调用。命中场景：不知道用什么工具、批量资产扫描、工具缺失、需要浏览器 GUI 操作登录/SPA/表单/DOM XSS 验证、需要把扫描结果衔接给 recon/injection/ssrf 等技能。
---

# tool-orchestration — 工具链编排与调度

## 何时调用（触发条件）

- 目标已确认，需要生成“信息收集 -> 扫描 -> 利用 -> 后渗透”工具调用链
- 多个工具需要串联输入输出，例如子域列表传给 httpx，存活列表传给 nuclei
- 需要判断某个工具是否安装、版本是否可用、参数是否写对
- 需要将工具输出结构化，交给对应专项 Skill 分析
- 需要登录、点击 SPA、填写表单、验证 DOM XSS/CSRF、截图留证，或保持登录态供后续测试

## 工具注册表

优先读取 `config/tool-registry.json`，字段含义：

```json
{
  "name": "工具名",
  "repo": "GitHub 仓库",
  "url": "仓库地址",
  "stars": "星标参考",
  "phase": "recon/scan/exploit/post/mobile/cloud/audit/support",
  "category": "功能分类",
  "description": "用途",
  "agent_hint": "调用建议"
}
```

完整 SecurityProduct 解析在 `D:\渗透工作流\_提取\GitHub-Agent工具提取\securityproduct-tools.json`，其中的 `phase_label` 用于判断防御类、蜜罐类和攻击类。

## 本地工具优先

机器上已有现成工具时直接调用，不自研扫描器。已知路径：

```text
D:\security tools\OneForAll-0.4.5
D:\security tools\EHole
D:\security tools\enscan
D:\security tools\goby
D:\security tools\dirsearch-0.4.3
D:\security tools\JSFinder
D:\security tools\GitHack-master
D:\security tools\ds_store_exp-master
D:\security tools\subDomainsBrute-1.4
D:\渗透工作流\_工具研究\bin\nuclei
```

先 `Get-Command <tool>`；不在 `PATH` 时检查上述目录，再决定安装或使用 `recon-info-collection` 的基线脚本兜底。

## 浏览器 GUI 控制

> **先看 harness 给不给浏览器工具，再选路线（2026-09-12 补）**：
> 本工作区在 **DSH harness** 下运行时，会话工具表里**没有** `browser_*` 系列（Playwright MCP 不存在），
> 此时**一律走工作区自带的 CDP 路线**（已实测可用，是当前主力）。
> 只有 harness 真的暴露了 `browser_navigate`/`browser_snapshot` 等工具时，才用下面第二小节。

### A) CDP 路线（DSH 下默认，工作区自带）

- **前置**：Chrome 以 `--remote-debugging-port=9223` + `--user-data-dir=state/chrome-cdp-profile`（或 `chrome-profile`）启动；
  登录态靠该 profile 保持。体检：`scripts/health_check.py` 第 4 项会直接验 9223 + `Browser.getVersion` + `eval_js`。
- **主力模块**：`scripts/cdp.py` —— `await CDP.connect()` → `new_page(url)` / `eval_js(sid, js)` / `cmd(...)`，
  连不上或多标签页调度都靠它；照 `dump_scope.py` / `scope_check_many.py` 的写法抄。
- **不能用 `--help` 的坑**：工作区多数脚本是**手写 argv 解析**，`--help` 会被当成目标参数
  （如 `check_delivery_consistency.py --help` → `FAIL: 目录不存在 --help`）。给脚本传参前先看一眼它的 `sys.argv` 用法。
- **截图/留证**：`scripts/evidence_shot_window.py --url <URL> --label <名> --wait 6 --pdf --ocr [--scroll-to <文本>]`
  —— 前台窗口截图 + 地址栏 OCR 校验 + PDF，产物落 `results/<label>-<日期>/`。
- **页面正文优先取 machine record**：`eval_js(sid, "document.body.innerText")` 比截图 OCR 可靠；
  OCR 只作粗检（AGENTS.md「截图 Vision-QA 分层」）。
- **渲染型页面必须走浏览器**：SPA（如 chinaz 的 `/icp/`）纯 HTTP 拿到的只是空壳，
  备案号/主办单位这类数据要么浏览器渲染后取 innerText，要么换非 SPA 的源。

#### A2) 在同一个 Chrome 上叠 Playwright（2026-09-12 实测可行，**推荐混用**）

`pip install playwright` 后**不需要** `playwright install` 下载浏览器——用
`connect_over_cdp` 直接接管 9223 那个长跑 Chrome，**登录态/profile/page 全部复用**：

```python
pw = await async_playwright().start()
browser = await pw.chromium.connect_over_cdp("http://127.0.0.1:9223", timeout=120000)
print(len(browser.contexts), [p.url for p in browser.contexts[0].pages])  # 复用现有标签
ctx = await browser.new_context()          # 用**独立临时上下文**干活，不污染用户标签
page = await ctx.new_page(); await page.goto(url)
h1 = await page.locator("h1").inner_text() # 自动等待，不用手写轮询
await page.screenshot(path=..., full_page=True)
await ctx.close(); await pw.stop()          # 只关自己的 ctx；**不要 browser.close()**
```

**怎么分工（实测取舍）**：

| 场景 | 用哪个 |
| --- | --- |
| 单发取数（读一页 innerText / 抓一次响应） | **CDP 脚本**（启动 ~0.3s，比 Playwright ~2-4s 快；131 个现成脚本都在） |
| 多步交互（登录→跳转→填表→点击→校验→截图） | **Playwright**（locator 自动等待，免手写元素查找+轮询） |
| 改请求头 / 改响应体喂回浏览器 | **Playwright** `route.continue_` / `route.fulfill`（CDP 要手写 `Fetch.enable`+`Fetch.fulfillRequest`） |
| 元素级截图 / 整页截图 / PDF | **Playwright** 一行 |
| 已有脚本 / 批量探测 | 别改，继续用 CDP |

**坑（实测）**：
- **首次 `connect_over_cdp` 会一次性 attach 到 profile 里所有历史标签页**（本案 14 个），冷启动慢；
  超时给 `120000`，别用默认短超时；profile 攒太多陈标签会拖慢它，定期清理。
- `pw.stop()` 是断开连接，**Chrome 继续跑**；`browser.close()` 在 CDP 连接下可能**杀掉浏览器**，别用。
- 别在同一个标签页上同时用 `cdp.py` 和 Playwright 操作（两套 session/object 模型会打架）。
- **Playwright MCP ≠ Playwright 库**：MCP 是 harness 提供的工具（DSH 下没有，且它另起 context
  → **丢掉 chrome-profile 登录态与"用户能看见并接管"的人机协作**）；库是本工作区自己可控的，
  走 `connect_over_cdp` 才两全。**能用库就别指望 MCP**。
- 冒烟脚本：`scripts/pw_cdp_smoke.py`（四步自证：连接/复用登录态/高层 API/不碰用户标签）。

### B) Playwright MCP（仅当 harness 提供 browser_* 工具时）

可用工具：

| 工具 | 用途 |
|---|---|
| `browser_tabs` | 新建/切换/关闭标签页 |
| `browser_navigate` | 打开 URL |
| `browser_snapshot` | 获取可操作 DOM 快照，点击前必须先用它定位元素 |
| `browser_click` | 点击按钮/链接/复选框 |
| `browser_take_screenshot` | 截图留证，保存到 `evidence/` |
| `browser_resize` | 切换桌面/移动视口 |

浏览器 GUI 执行纪律：

1. 点击前先 `browser_snapshot` 拿元素引用，不要凭坐标盲点。
2. 登录态用浏览器上下文保持；需要给 CLI 工具使用时，把 Cookie/localStorage 导出到 `data/`。
3. 截图统一存 `evidence/`，命名包含目标和阶段。
4. 浏览器看到的请求/响应优先用 `browser_snapshot` 或页面内脚本提取，再交给 CLI 工具深挖。
5. 涉及支付、删除、批量操作等业务动作时，先暂停并请求确认。

### 实战记录（XSS-Labs 2026-08）

- 弹窗统一用 `page.on('dialog', d => d.accept())`，alert/confirm 都会被接管，不要用 MCP 手工点。
- 反射型 XSS 的 payload 要按过滤规则校准：`on*` 被改写时改用 `javascript:` 链接并自动点击；`script`/`on` 被删除时用 `scrscriptipt` 双写还原；`javascript:` 被过滤时用 `java&#x73;cript:` 实体。
- `Referer` 这类受限头用 Playwright `route.continue` 或 `setExtraHTTPHeaders` 都发不进去时，改用 Node 原生 HTTP 带恶意头取回 HTML，再用 `route.fulfill` 喂给浏览器页面。
- Angular `ng-include` 注入 `<script>` 不执行，用 `<img src=x onerror=alert(1)>` 可以稳定触发。
- `<embed>` 的 `onclick` 用 Playwright `.click()` 不触发时，改用 `onmouseover` 后 `.click()`，或 `dispatchEvent('click')`。

## 阶段工具路由

| 阶段 | 首选工具 | 说明 |
|---|---|---|
| 综合信息收集 | `SearchMap`, `SiteScan`, `Vxscan`, `Nemo`, `ShuiZe` | 先跑综合工具出全貌，再按缺口补专项 |
| 资产与子域 | 先读 `recon-info-collection`；再选 `subfinder`, `amass`, `OneForAll`, `ksubdomain`, `assetfinder`, `Sylas`, `domain_hunter` | 输出统一为一行一个域名 |
| 旁站 / C 段 | `BingC`, `ip2domain`, `fofa_viewer`, `ones`, `webscan.cc` | 先反查同 IP，再展开 `/24` |
| CDN 绕过 | `Frog-checkCDN`, `CloudFlair`, `w8fuckcdn`, `Bypass_cdn`, `f5_cookieLeaks`, `Vxscan`, 历史 DNS | 必须按 `recon-info-collection/references/cdn-bypass-playbook.md` 验证 |
| WAF 识别 | `wafw00f`, `identYwaf`, nmap WAF 脚本 | 识别后切换 `waf-bypass-techniques` |
| HOST 碰撞 | `hostscan`, `Hosts_scan`, `host_scan` | 真实 IP 无法直接访问时发现隐形资产 |
| 端口与服务 | `nmap`, `naabu`, `fscan` | 内网目标优先 `fscan` |
| HTTP 存活与指纹 | `httpx`, `WhatWeb`, `wafw00f`, `dismap`, `EHole`, `FingerprintHub`, `EyeWitness`, `AlliN` | 生成存活 URL 与技术栈清单 |
| 爬虫与历史 URL | `katana`, `gau`, `waybackurls` | 合并去重后保存为 URL 清单 |
| 目录/参数/JS | `ffuf`, `dirsearch`, `feroxbuster`, `Arjun`, `URLFinder`, `JSINFO-SCAN`, `LinkFinder`, `SecretFinder`, `Packer-InfoFinder` | JS 分析结果交给 `recon-js-analysis` |
| 漏洞扫描 | `nuclei`, `nuclei-templates`, `xray`, `yakit`, `zaproxy`, `wpscan` | 先扫指纹再选模板集 |
| 中间件/Nday | 先读 `middleware-framework-nday`；再选 `scaninfo`, `fscan`, `shiro_attack`, `JNDIExploit`, `ysoserial` | 指纹转 CVE，验证后交接专项 |
| 利用与口令 | `sqlmap`, `metasploit-framework`, `hydra`, `hashcat`, `PayloadsAllTheThings` | 高风险动作执行前必须确认 |
| 登录/口令爆破 | `hydra`, Burp Intruder/Turbo Intruder, `pkav` | 按 `auth-access-control/references/login-page-playbook.md` 执行 |
| 后渗透与 AD | `impacket`, `BloodHound`, `mimikatz` | 仅授权环境，结果存 evidence |
| 移动端 | `AppInfoScanner`, `jadx`, `frida`, `objection` | 先提取 APP 域名/接口/密钥，输出交给 `mobile-iot-device-security` |
| 云安全 | `prowler`, `pacu`, `ScoutSuite` | 云凭证必须来自授权测试 |
| 源码审计 | `Kunlun-M`, `Cobra` | 结果交给 `source-code-audit` |
| 辅助 | `SecLists`, `interactsh` | OOB 结果回填 SSRF/XXE 验证 |
| 浏览器 GUI | Playwright MCP：`browser_navigate` / `browser_snapshot` / `browser_click` / `browser_take_screenshot` | 登录态、SPA、表单、DOM XSS/CSRF、业务流截图 |

## 执行纪律

1. 只对用户明确提供、且已获得授权的目标执行。
2. 调用工具前先确认命令存在：`which` / `Get-Command`，不存在则先给出安装方案。
3. 批量扫描前先小样本验证参数和输出格式，再放大范围。
4. 爆破、命令执行、文件上传、横向移动、删除数据等高风险动作必须暂停并请求确认。
5. 所有输出按阶段写入 `results/`，关键证据写入 `evidence/`，便于后续写报告。
6. 工具被 WAF/拦截时，不硬刚，切换 `waf-bypass-techniques` 并按 Level 1-7 升级。
7. 扫描结果不能直接下结论，必须交给对应专项 Skill 做差异验证与可利用性评估。

## 输出与交接

完成后输出：

```text
[工具链]
阶段：recon
工具：subfinder -> httpx -> nuclei
命令：...
输出文件：results/recon/...

[结果摘要]
存活资产：N
指纹：...
风险点：...

[交接]
SRC范围/证据/报告 -> pt-engagement
资产/旁站/C段/CDN源站 -> recon-info-collection
接口/参数问题 -> api-protocol-security / auth-access-control
注入点 -> injection-vulns
URL 抓取类 -> ssrf-internal-network
上传/文件类 -> file-handling
中间件/框架 Nday -> middleware-framework-nday
```
