---
name: middleware-framework-nday
description: 当指纹识别出 Nginx/Apache/IIS/Tomcat/WebLogic/JBoss/Spring/Struts2/Shiro/Fastjson/Log4j/OA/CMS 等中间件、框架或业务组件，需要匹配已知 CVE/Nday、验证漏洞、快速打点时调用。命中场景：端口 7001/8080/8443、console/manager/jmx-console/wls-wsat/actuator 等特征、shiro rememberMe、fastjson 报错、OA 系统、需要把指纹转成可利用的 Nday 清单。
---

# 中间件 / 框架 Nday 专项

## 工作流

1. 指纹识别：用 EHole、dismap、httpx、WhatWeb、Wappalyzer、FingerprintHub 确认组件和版本。
2. 版本定级：从响应头、错误页、默认路径、Cookie、静态资源哈希确认精确版本。
3. 查 Nday：优先本地 `nuclei -update-templates`，再查官方 CVE、漏洞库、GitHub POC。
4. 小样本验证：先选 1 个目标跑低风险 POC，确认指纹和利用条件，再批量。
5. 利用与留证：命令执行用 `id`、`echo` 等无副作用命令；写入文件/反弹 shell 前必须确认授权。
6. 清理与报告：删除测试文件、保存原始请求和响应、按影响面写报告。

## 指纹 -> Nday 快速映射

| 组件 | 特征路径/Header | 优先验证项 |
|---|---|---|
| Nginx | `server: nginx`、alias 配置、CRLF | CRLF 注入、alias 目录穿越、解析漏洞、CVE-2021-23017 |
| Apache | `server: Apache`、多后缀解析 | 多后缀解析、CVE-2021-41773/42013 路径穿越 RCE |
| Tomcat | `/manager`、`/host-manager`、`8009` | 弱口令、PUT 上传、AJP Ghostcat CVE-2020-1938 |
| WebLogic | `7001`、`/console`、`/wls-wsat` | 弱口令、XMLDecoder、任意上传、未授权 RCE |
| JBoss | `/jmx-console`、`/web-console`、`/invoker` | 未授权控制台、反序列化 |
| Spring | `/actuator`、`/env`、`/jolokia` | Actuator 泄露、Spring4Shell、SpEL |
| Struts2 | `.action`、`struts` 错误页 | OGNL 注入系列 S2-xxx |
| Shiro | `rememberMe=deleteMe` | AES 弱密钥反序列化 |
| Fastjson | 报错 `com.alibaba.fastjson` | autoType 绕过 RCE |
| Log4j | 存在日志/搜索/反序列化入口 | JNDI 注入 |

详细 CVE、POC 路径和验证命令见 `references/nday-matrix.md`。

## 工具链

```bash
# 指纹批量识别
EHole_windows_amd64.exe finger -l urls.txt -o ehole.xlsx
dismap -f urls.txt
httpx -l urls.txt -tech-detect -json -o tech.json

# Nday 模板扫描
nuclei -update-templates
nuclei -l urls.txt -t http/cves -o nuclei-http.txt

# 中间件专项
scaninfo -host <ip> -p 7001,8009,8080,8443
fscan -h <ip> -p 7001,8009,8080,8443
```

验证工具：

- WebLogic：`CVE-2023-21839`、`JNDIExploit`、`Decrypt_Weblogic_Password`
- Shiro：`BurpShiroPassiveScan`、`shiro_attack`
- Java 反序列化：`ysoserial`、`JNDIExploit`
- 综合：`xray`、`yakit`、`nuclei`、`vulhub`/`vulfocus` 复现环境

## 验证纪律

1. 只对授权目标执行；Nday 扫描也受 SRC 公告约束。
2. 先确认版本匹配，再执行 POC；版本不对直接跳过，不要硬打。
3. 命令执行优先 `id`/`echo`/`whoami` 等无副作用命令，不写 shell、不改配置。
4. 使用 `-it` 交互式或 `--timeout` 限制，避免扫描器把目标打崩。
5. 每个验证保留：指纹证据、POC 请求、响应、影响面说明。

## 输出与交接

```text
[Nday 报告]
目标：...
组件/版本：...
指纹证据：...
命中 CVE：...
验证请求：...
验证结果：...
影响面：...
修复建议：...
```

漏洞确认后交接：

- 反序列化/RCE → `deserialization-xxe`
- 注入点 → `injection-vulns`
- 上传点 → `file-handling`
- 未授权/弱口令 → `auth-access-control`
- 中间件在内网/云上 → `ssrf-internal-network` / `cloud-infra-supply-chain`

## 详细参考

- `references/nday-matrix.md`：常见中间件、框架、OA 的 Nday 矩阵。
