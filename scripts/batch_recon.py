#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""batch_recon.py — 批量侦察的**唯一脚本入口**（只读第一跳）。

为什么必须存在（2026-09-23）
----------------------------
persona 写着「批量侦察必须经脚本入口执行（只读第一跳、单主机节流、全局并发与每日请求预算上限）」，
但实测 arsenal.py scan **既无节流也无预算**：ThreadPoolExecutor 默认 8 并发直发，
一次铺开几十上百台主机时既可能压垮对方，也可能把自己的出口 IP 打进黑名单（禾赛 / 黑湖都出现过被限）。
本脚本把三件事做成**传输层强制**，不靠自觉：

  1. 范围登记：每个 apex 过 scope_gate.check_domain，**只作标注**（默认不阻断）；
     仅当项目 JSON 写了 "strict_scope": true 才拦外范围主机 —— 那是项目组自己的纪律。
  2. 节流：monkeypatch requests.get，**单主机相邻请求 >= 2s、全局在飞 <= 4**（传更大值会被夹回并解释）。
  3. 预算：state/recon-budget.json 按日计数，默认 3000/日；不足即**拒绝启动**（不是跑一半才停）。

判据（每目标留痕，可回放）
--------------------------
  · 负控A：该主机瞎编路径的 (状态码, 字节数, 摘要md5) —— 命中与之同字节即判 catch-all 假阳。
  · 负控B：命中后再发 1 次**同形**瞎编路径（同目录同扩展名）—— 它也同状态码且回显请求串 ⇒ 判假阳。
    治的是「路径即输入」站点（SSL 评估/Whois/测速/缩略图）：负控A 路径不含点，与 /x.php 不同构，必漏。
  · 可达性：不可达主机单独列出，**不**计入「目标干净」。
  · 基线闸门：0 命中时跑 scripts/kit/verdict.appraise，仪器存疑报 UNSURE（AGENTS 5）。
  · 落盘：raw/<host>.json + candidates.json/csv + criteria.md + run.json（可 --replay）。

不做的事（边界写死）
--------------------
  · **产出只到候选表**：本脚本不写报告、不碰目标状态；交付走 report_gate.py + assemble_deliver.py。
  · 只发只读 GET；不写、不删、不爆破、不带凭据。
  · 越界资产只标注不测试。

用法
----
    $py scripts/batch_recon.py --status
    $py scripts/batch_recon.py --weapon F --hosts a.example b.example
    $py scripts/batch_recon.py --weapon F --hosts a.example --apply
    $py scripts/batch_recon.py --weapon G --hosts-file state/hosts.txt --apply --max-hosts 20
    $py scripts/batch_recon.py --replay results/batch-recon-20260923-120000/run.json --apply

真批量**必须走后台作业**（前台单次工具调用有 30s 上限，会被掐断）：
    $py scripts/job.py start --name recon-F --cmd "python scripts/batch_recon.py --weapon F --hosts-file state/hosts.txt --apply"
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import posixpath
import sys
import threading
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        # line_buffering：后台作业里若不开，job_output 会长时间空白（看起来像卡死）
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass

try:
    import urllib3
    urllib3.disable_warnings()          # 只读探测常用自签证书，告警刷屏会淹掉结论
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
STATE = ROOT / "state"
RESULTS = ROOT / "results"
BUDGET_P = STATE / "recon-budget.json"
sys.path.insert(0, str(SCRIPTS))

# 日预算上限。默认 3000（纪律值）；需要临时提额时用环境变量**显式**覆盖：
#   $env:RECON_DAY_CAP='4500'; $py scripts\batch_recon.py ...
# （2026-09-24 用户授权的一次性提额即走此处，默认值不变以免纪律被悄悄放宽）
DAY_CAP = int(os.environ.get("RECON_DAY_CAP", "3000"))

# 2026-09-25 立：**项目明示「禁止自动化工具/只允许手工测试」的域名黑名单**。
# 为什么必须存在（当天事故）：朴朴《漏洞定级与安全测试规范 V2.7》第 6 条明文
# 「禁止使用扫描器或其他自动化工具，只允许手工测试」，我仍跑了 batch_recon 24 台 × 6 武器（599 请求）
# ⇒ 违反项目规则。根因三条：① 规则在**图片附件**里（长图），闸门读不到；
# ② 我按「补天厂池」思路假设了授权，没意识到 vulbox 企业SRC 的规则口径完全不同；
# ③ 该目标既有工作目录叫 pupu-20260917（品牌名），preflight 的既往产物检查按域名匹配，漏报了它。
# ⇒ **vulbox 企业SRC 开靶前必须先读项目页「漏洞规则 / 资产范围」**；命中禁止自动化或「范围不含网站」
# 即写入本表，batch_recon 与 arsenal 一律拒跑（不看归属是否 GO —— 归属 GO 只说明资产是谁的，不代表允许扫码）。
NO_AUTO_P = STATE / "no-auto-scan.json"


def _load_no_auto() -> dict:
    if not NO_AUTO_P.exists():
        return {}
    try:
        d = json.loads(NO_AUTO_P.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}
MIN_GAP = 2.0
MAX_WORKERS = 4
CTRL_PATH = "/zz_nonexistent_batchrecon_9k2"
# 2026-09-26 修：原 UA = "Mozilla/5.0" 是 WAF 最典型的爬虫指纹 ——
# 实测 cacp.org.cn 对裸 UA / 仅换 UA 均回 HTTP 456（WAF 拦截），补齐全套浏览器头后放行。
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
# 通用浏览器头（导航 + 子资源都兼容；Sec-Fetch-Dest 因请求类型而异故不写死）
BROWSER_HEADERS = {
    "User-Agent": UA,
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "sec-ch-ua": '"Chromium";v="147", "Not?A_Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "no-cors",
    "Connection": "keep-alive",
}


def now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def norm_host(h) -> str:
    s = str(h or "").strip().strip(",").strip()
    s = s.lstrip(chr(65279))
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?")[0].split("@")[-1]
    if s.startswith("["):
        return s.split("]")[0] + "]"
    return s.split(":")[0].lower()


def host_of_url(url) -> str:
    return norm_host(url)


# ── 预算 ────────────────────────────────────────────────────────────────────

class Budget:
    """按日请求预算账本。先记**估算值**，收尾再校正为实测值。

    过记是安全方向：进程被杀也不会漏账。"""

    def __init__(self, cap: int = DAY_CAP, path: Path = BUDGET_P, platform: str = "unknown"):
        self.cap = int(cap)
        self.cap_source = "默认值 %d" % self.cap
        self.path = Path(path)
        self.platform = (platform or "unknown").strip().lower()
        self._lk = threading.Lock()
        env_cap = os.environ.get("RECON_DAY_CAP")
        if env_cap:
            self.cap_source = "环境变量 RECON_DAY_CAP"
        d = {}
        if self.path.exists():
            try:
                d = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                d = {}
        fresh = not isinstance(d, dict) or d.get("date") != dt.date.today().isoformat()
        # 账本里的 cap 字段代表「当日已授权的额度」；回读它，否则会出现
        # 「文件写 4500、跑起来按 3000 卡」的自相矛盾（2026-09-24 实测踩到）。
        # 显式环境变量 > 账本已授权额度 > 默认纪律值。
        if not fresh and not env_cap and d.get("cap"):
            self.cap = int(d["cap"])
            self.cap_source = "账本 cap 字段（当日已授权）"
        if fresh:
            d = {"date": dt.date.today().isoformat(), "used": 0, "cap": self.cap, "runs": []}
        d.setdefault("runs", [])
        d["cap"] = self.cap
        self.d = d
        self.reclaim_dead()

    @property
    def used(self) -> int:
        return int(self.d.get("used", 0))

    @property
    def by_platform(self) -> dict:
        d = self.d.get("by_platform")
        if not isinstance(d, dict):
            d = {}
            self.d["by_platform"] = d
        return d

    def charged(self) -> int:
        """计入当日额度的请求数。**补天线不占额度**（用户明示 2026-09-27：补天都是中小厂商、
        很难触发 WAF）—— 补天的请求照样记账（可见），只是不参与 cap 判定。"""
        return max(0, self.used - int(self.by_platform.get("butian", 0) or 0))

    def _bump(self, n: int) -> None:
        """本平台 +n：同时写「总数」与「分平台」两处，保证 charged() 可反推补天用量。"""
        n = int(n)
        self.d["used"] = max(0, self.used + n)
        bp = self.by_platform
        bp[self.platform] = max(0, int(bp.get(self.platform, 0) or 0) + n)

    def left(self) -> int:
        return max(0, self.cap - self.charged())

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except Exception:
            return False

    def reserve(self, n: int, note: str = "") -> None:
        """开工前先记 估算值：进程被杀也不漏账（过记是安全方向）。"""
        with self._lk:
            n = int(n)
            self._bump(n)
            res = self.d.setdefault("reservations", {})
            key = str(os.getpid())
            res[key] = int(res.get(key, 0)) + n
            self.d["runs"].append({"ts": now_iso(), "delta": n, "note": "reserve " + note})
            self.flush()

    def settle(self, actual: int, note: str = "") -> None:
        """预留 -> 实测；只在收尾调一次。

        2026-09-23 修双记 bug：原设计是 reserve(估算) + 每请求 add(1) + 收尾 add(实际-估算)，
        三者叠加等于 2 倍实际请求数，试跑一眼看出账本虚高。现在每请求只计数、不记账。
        """
        with self._lk:
            res = self.d.setdefault("reservations", {})
            held = int(res.pop(str(os.getpid()), 0) or 0)
            self._bump(int(actual) - held)
            self.d["runs"].append({"ts": now_iso(), "delta": int(actual) - held,
                                   "note": "settle " + note})
            self.flush()

    def add_manual(self, n: int, note: str = "") -> None:
        """手工 / 浏览器发出的请求也入账（2026-09-23 加）。

        动机：账本原来只被 batch_recon 记账 ⇒ 手工探针与 CDP 浏览器请求**不进账**，
        账面的「今日剩 N」会高于真实出口量（实测一天手工约 70 个请求没记）。
        手工请求是实测值，不进预留池，直接记 delta。调用方：scripts/budget_note.py。
        """
        with self._lk:
            n = int(n)
            if n <= 0:
                return
            self._bump(n)
            self.d["runs"].append({"ts": now_iso(), "delta": n, "note": "manual " + note})
            self.flush()

    def reclaim_dead(self) -> int:
        """回收 已死进程 留下的预留。

        预留是为了不漏账；但被 kill 的 run 会把预留永久留在账上，反复 kill 会白吃预算
        （2026-09-23 实测：一次 kill 加重发，账上 84/3000，两笔预留都在）。
        """
        with self._lk:
            res = self.d.get("reservations")
            if not isinstance(res, dict):
                return 0
            gone, total = [], 0
            for k, v in list(res.items()):
                try:
                    pid = int(k)
                except Exception:
                    gone.append(k)
                    total += int(v or 0)
                    continue
                if pid != os.getpid() and not self._pid_alive(pid):
                    gone.append(k)
                    total += int(v or 0)
            for k in gone:
                res.pop(k, None)
            if total:
                self._bump(-total)
                self.d["runs"].append({"ts": now_iso(), "delta": -total,
                                       "note": "reclaim dead reservations"})
                self.flush()
            return total

    def flush(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.d, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception:
            pass

    def render(self) -> str:
        s = "预算 总%d/%d（计入额度 %d，今日剩 %d）" % (self.used, self.cap, self.charged(), self.left())
        bp = {k: int(v or 0) for k, v in (self.d.get("by_platform") or {}).items() if int(v or 0)}
        if bp:
            s += " 分平台 " + " ".join("%s=%d" % (k, v) for k, v in sorted(bp.items()))
        return s


# ── 节流：传输层强制 ────────────────────────────────────────────────────────

class Throttle:
    """单主机最小间隔 + 全局在飞上限；每个真实请求扣 1 预算。"""

    def __init__(self, gap: float = MIN_GAP, workers: int = MAX_WORKERS, budget: Budget = None):
        self.gap = float(gap)
        self.workers = int(workers)
        self.budget = budget
        self._sem = threading.Semaphore(self.workers)
        self._guard = threading.Lock()
        self._locks = {}
        self._lasts = {}
        self.count = 0
        self.waited = 0.0

    def _lock(self, host: str):
        with self._guard:
            lk = self._locks.get(host)
            if lk is None:
                lk = threading.Lock()
                self._locks[host] = lk
            return lk

    def run(self, url: str, fn):
        host = host_of_url(url)
        with self._sem:
            with self._lock(host):
                gap = time.time() - self._lasts.get(host, 0.0)
                if gap < self.gap:
                    w = self.gap - gap
                    self.waited += w
                    time.sleep(w)
                self._lasts[host] = time.time()
                self.count += 1   # 只计数；记账走 reserve/settle，避免双记
                return fn()


def patch_requests(throttle: Throttle):
    """把节流与预算挂在 requests.get 上 —— arsenal / scope_gate 的既有代码自动受管。"""
    import requests
    orig = requests.get

    def wrapped(url, *a, **kw):
        return throttle.run(str(url), lambda: orig(url, *a, **kw))

    requests.get = wrapped
    return orig


# ── 范围预检 ────────────────────────────────────────────────────────────────

def preflight(hosts, allow=None, verbose=True, evidence=None):
    """返回 {apex: {"ok": bool, "result": dict}}；同一 apex 只查一次。

    evidence：2026-09-27 加。UNSURE（我方备案源没查出来，不是确认越界）时，
    由 --evidence 提供客观第二证据即可降级放行（scope_gate 会写审计日志）。
    背景：icplishi 限流会让整批假 UNSURE，此前 UNSURE 也 BLOCK ⇒ 批量施工被第三方站点卡死。
    """
    import scope_gate
    out = {}
    for h in hosts:
        apex = scope_gate.registrable(h)
        if apex in out:
            continue
        ok, r = scope_gate.gate(apex, allow, verbose=verbose, evidence=evidence)
        out[apex] = {"ok": bool(ok), "result": r}
    return out


# ── 第一跳 ──────────────────────────────────────────────────────────────────

def reachable(host: str):
    import requests
    for sch in ("https", "http"):
        try:
            r = requests.get("%s://%s/" % (sch, host), timeout=6, verify=False,
                             allow_redirects=False, headers=BROWSER_HEADERS)
        except Exception:
            continue
        b = r.content[:600]
        return True, [sch, r.status_code, r.headers.get("Server") or "", hashlib.md5(b).hexdigest()[:12]]
    return False, None


def ctrl_of(host: str):
    """同主机 catch-all 指纹：瞎编路径的 (状态码, 字节数, 摘要md5)。"""
    import requests
    first = None
    for sch in ("https", "http"):
        try:
            r = requests.get("%s://%s%s" % (sch, host, CTRL_PATH), timeout=8, verify=False,
                             allow_redirects=False, headers=BROWSER_HEADERS)
        except Exception:
            continue
        body = r.text[:300000]
        sig = [r.status_code, len(r.content),
               hashlib.md5(" ".join(body.split())[:220].encode("utf-8", "ignore")).hexdigest()[:10]]
        if r.status_code == 200:
            return sig
        if first is None:
            first = sig
    return first


def shape_ctrl_path(p: str) -> str:
    """与探针 p **同形**的瞎编路径：同目录、同扩展名，只换主干。
    2026-09-25 加：原负控 CTRL_PATH 不含点，与 /zabbix.php 这类含点路径**不同构**，
    遇上「路径即输入」的站点（SSL 评估 / Whois / 测速 / 截图缩略图 / 短链预览）必然漏判假阳
    （实测 myssl.com：/zabbix.php 与 /zz_fake_xxx.com 都返回 200 + 评估报告页）。
    """
    p = "/" + str(p).lstrip("/")
    d, base = posixpath.split(p)
    _stem, ext = posixpath.splitext(base)
    h = hashlib.md5(str(p).encode("utf-8")).hexdigest()[:8]
    d = d.rstrip("/")
    return (d + "/" if d else "/") + "zz_noauth_" + h + (ext or "")


def shape_ctrl_of(host: str, path: str):
    """形状负控：同形瞎编路径的 {status, len, echo}。
    echo = 响应正文里出现了**我请求的那个文件主干** ⇒ 该站在按输入生成页面（路径即输入）。
    判据：同形瞎编路径**也**返回与命中相同的状态码、且回显请求串 ⇒ 假阳。
    与旧判据互补：旧判据抓「同字节的 catch-all」，本判据抓「同形但逐字不同的输入回显」。
    """
    import requests
    cp = shape_ctrl_path(path)
    needle = posixpath.basename(cp).lower()
    first = None
    for sch in ("https", "http"):
        try:
            r = requests.get("%s://%s%s" % (sch, host, cp), timeout=8, verify=False,
                             allow_redirects=False, headers=BROWSER_HEADERS)
        except Exception:
            continue
        body = r.text[:300000].lower()
        sig = {"path": cp, "status": r.status_code, "len": len(r.content),
               "echo": needle in body}
        if r.status_code == 200:
            return sig
        if first is None:
            first = sig
    return first


# ── 判据特异性闸门（2026-09-26）────────────────────────────────────────
# 起因：probe_one 的判据是「任一子串命中」(any)，所以 ["enabled"] / ["pageSize"] 这类
# 通用词会让**任何页面**都判 hit —— 实测 R 出 8 条假阳、J 出 3 条（Element UI 分页语言包）。
# 本闸门在**发请求之前**把「过松判据」显式打出来，别让假阳靠人记得去查。
_LOOSE_COMMON = {
    "enabled", "version", "true", "false", "ok", "index", "error", "name", "type", "data",
    "status", "success", "result", "code", "id", "key", "value", "list", "total", "{}", "[]",
    "<a href", "<html", "login", "admin", "user", "password", "welcome", "forbidden",
    "repositories", "edition", "components", "project_id", "pagesize", "getlist", "imageurl",
    "token", "session", "email", "phone", "components", "uri",
}

# 中文产品名虽短但**够特异**（反而比英文通用词准），不进「太短」告警。
_LOOSE_OK = {"若依", "致远", "泛微", "用友", "金蝶", "通达", "蓝凌"}

def _warn_loose_probes(wk: str) -> None:
    """发请求前告警：本手法的探针里有没有「过松判据」。"""
    import arsenal
    probes = arsenal.PROBES.get(wk)
    if not probes:
        return
    bad = []
    for p in probes:
        if not isinstance(p, (list, tuple)) or len(p) < 3:
            continue
        name, sigs = str(p[0]), p[2]
        for sg in (sigs if isinstance(sigs, (list, tuple)) else [sigs]):
            s = str(sg).strip().lower()
            if s in _LOOSE_OK:
                continue
            if len(s) < 5:
                bad.append((name, sg, "太短(<5)"))
            elif s in _LOOSE_COMMON:
                bad.append((name, sg, "通用词"))
    if not bad:
        return
    print("  [判据闸门] ⚠ 手法%s 有 %d 条过松判据（probe_one 是 any 匹配 ⇒ 易假阳）："
          % (wk, len(bad)))
    for name, sg, why in bad[:6]:
        print("      %-24s sig=%r  <- %s" % (name[:24], sg, why))
    if len(bad) > 6:
        print("      ... 另有 %d 条" % (len(bad) - 6))
    print("      收紧：换成「只有该产品才有的长串」，或删掉无区分度的探针。")

def path_pass(host: str, probes: list, ctrl):
    """path 引擎：逐探针只读 GET。"""
    import arsenal
    rows = []
    for name, path, expect in probes:
        try:
            hit, status, sig = arsenal.probe_one(host, path, expect)
        except Exception as e:
            hit, status, sig = None, -1, "exception: %s" % e
        row = {"probe": name, "path": path, "status": status, "hit": bool(hit),
               "sig": str(sig)[:120]}
        if hit:
            row.update({"url": hit["url"], "len": hit["len"], "snippet": hit["snippet"]})
            cc = bool(ctrl) and ctrl[0] == hit["status"] and ctrl[1] == hit["len"]
            row["catchall_same"] = cc
            if cc:
                row["verdict"] = "catchall-false-positive"
            else:
                # 2026-09-25：形状负控（只在命中时才发这 1 次请求，命中稀少 ⇒ 预算影响可忽略）
                sc = shape_ctrl_of(host, path)
                row["shape_ctrl"] = sc
                if sc and sc["status"] == hit["status"] and sc["echo"]:
                    row["verdict"] = "echo-false-positive"
                    print("  [FP-ECHO] %-32s %-14s 同形瞎编 %s 也 %s 且回显请求串 => 站点按输入生成页面"
                          % (host, name, sc["path"], sc["status"]))
                else:
                    row["verdict"] = "hit"
        rows.append(row)
    # 2026-09-26 加：**多探针同构**判据（catch-all 的第二种形态，本次实测踩到）。
    # 场景：站点把所有未知路径都渲染成同一个 SPA/登录页（HTTP 200、内容逐字相同），
    # 而单个负控 CTRL_PATH 恰好被规则重定向成 302 ⇒ 原判据（status+len 与负控一致）失效
    # ⇒ 假阳混进候选。实测 auth.gopay.com.cn：21 个探针全部返回同一登录页，
    # 却因为 HTML 里含 "ry-ui" 子串，有 1 条被报成 hit（差点当成若依站点去深挖）。
    # 判据：同一主机上 **>=3 个不同路径** 的响应 (status, sig) 完全一致且 status==200 ⇒ 整体判 catch-all。
    try:
        from collections import Counter as _Ctr
        _sigs = _Ctr((r0["status"], r0["sig"]) for r0 in rows
                     if r0.get("status") == 200 and r0.get("sig"))
        if _sigs:
            (_st, _sg), _cnt = _sigs.most_common(1)[0]
            if _st == 200 and _cnt >= 3:
                for r0 in rows:
                    if r0.get("status") == 200 and r0.get("sig") == _sg and r0.get("verdict") != "catchall-false-positive":
                        r0["hit"] = False
                        r0["verdict"] = "catchall-false-positive"
                        r0["catchall_same"] = True
                        r0["catchall_reason"] = "多探针同构：%d 个不同路径返回同一响应" % _cnt
    except Exception:
        pass
    return rows


def js_pass(host: str, keywords: list, evidence: str):
    """返回 (rows, audit)。audit = 仪器台账（扫了/跳过了哪些同站 JS），写进 raw 与 run.json。"""
    import arsenal
    audit: dict = {}
    try:
        rs = arsenal.js_probe(host, keywords, 6, 8, evidence, audit) or []
    except Exception as e:
        rs = [{"error": str(e)}]
        audit["error"] = str(e)[:140]
    rows = []
    for x in rs:
        row = {"probe": x.get("kw") or "js", "src": x.get("src"), "ctx": (x.get("ctx") or "")[:200]}
        if x.get("error"):
            row["verdict"] = "error"
        elif x.get("note"):
            # 2026-09-23 改：note 以前一律标 third-party-js —— 把「跳过大包」「仪器盲区」也混成三方 JS 了。
            row["verdict"] = "js-note"
            row["kind"] = x.get("kind") or "note"
        else:
            row["verdict"] = "hit"
        rows.append(row)
    return rows, audit


def entry_form(live: list, raw_map: dict, reach_map: dict = None) -> dict:
    """入口形态判读（2026-09-23 加）：只读本批**既有响应**，不发一个请求。

    为什么需要：新特能源那批 20 台里 17 台对任意路径（含负控）返回逐字相同的
    {"error_msg":"404 Route Not Found"}（APISIX 未注册路由）。工具**没报假阳**（这是对的），
    但也没告诉人「这些台等于没测」—— 于是 0 命中被读成「目标干净」。

    判据分三层，**每层只说证据支撑得住的话**（自动判读假阳的根源就是越层下结论）：
      事实① 单台同构：该台所有探针的 (状态码, 响应指纹) 一致且无一命中
             ⇒ 「定长路径第一跳在这台上没有区分度」—— 定义层面成立，不依赖推断
      事实② 跨台成簇：同一 (状态码, 指纹) 出现在 ≥max(3, 50% 存活台) 台 ⇒ 「这些台响应同构」
      推断（**必须 Server 头也同名**才给，且标 UNVERIFIED）：可能是同一入口/网关 ——
             反例：多家同款部署（清一色 nginx 默认 404 页）也会同构，所以不单独下这个结论。
    用途：0 命中时回答「本批到底测到东西没有」；覆盖率 ≥80% 且 ≥5 台 ⇒ 不构成『目标干净』。
    """
    n = len(live)
    groups: dict = {}
    for h in live:
        rows = (raw_map.get(h) or {}).get("probes") or []
        if not rows:
            continue
        keys = {(r.get("status"), str(r.get("sig"))[:60]) for r in rows if r.get("status") != -1}
        if len(keys) != 1 or any(r.get("hit") for r in rows):
            continue
        st, sig = next(iter(keys))
        if st == 200 or st in (401, 403, 404, 405, 406, 410, 418, 502, 503):
            groups.setdefault((st, sig), []).append(h)
    out = {"groups": [], "wall_hosts": [], "shell_hosts": [], "notes": [], "blind": False}
    if not groups:
        return out
    thr = max(3, -(-n // 2))          # ceil(n/2)，且不低于 3（样本太小不下判读）
    (st, sig), hosts = max(groups.items(), key=lambda kv: len(kv[1]))
    kind = "shell" if st == 200 else "wall"
    frac = (len(hosts) / n) if n else 0.0
    out["wall_hosts"] = sorted(hosts) if kind == "wall" else []
    out["shell_hosts"] = sorted(hosts) if kind == "shell" else []
    out["groups"] = [{"status": k[0], "sig": k[1], "hosts": sorted(v)} for k, v in
                     sorted(groups.items(), key=lambda kv: -len(kv[1]))]
    out["top_share"] = round(frac, 2)
    if len(hosts) >= thr:
        # 2026-09-23 实操补充：**拦截类（403/406/418/429）与不存在类（404/405/410）必须分开说** ——
        # 景安那批 H 手法在 13/15 台上拿到同一张 403 拦截页（.git 被 WAF 规则挡），
        # 这与「路径不存在」的下一步动作完全不同：前者要升绕过等级，后者要换路径表。
        if kind == "shell":
            label = "同一 200 壳（SPA catch-all）"
            advice = "换 js 引擎拉前端包 / 浏览器手工看"
        elif st in (401, 403, 406, 418, 429):
            label = "同一 %s 拦截页" % st
            advice = "**疑似 WAF/权限网关**（推断，UNVERIFIED）：按 waf-bypass L1–L7 升绕过等级或换手法"
        elif st in (502, 503, 504):
            label = "同一 %s 服务异常页" % st
            advice = "目标侧服务异常 ⇒ 本轮探针没测到东西，先确认服务再复测"
        else:
            label = "同构 %s" % st
            advice = "路径在该系统不存在 ⇒ 换手法或换路径表"
        note = ("%d/%d 台对**全部探针**返回%s（指纹 %s）⇒ 这些台上定长路径第一跳**没有区分度**，"
                "不得计入『目标干净』；%s" % (len(hosts), n, label, str(sig)[:48], advice))
        servers = {(((reach_map or {}).get(h) or [None, None, ""]) + ["", ""])[2] for h in hosts}
        servers = {s for s in servers if s}
        if len(servers) == 1:
            note += "；Server 同名 `%s`（**推断**：可能同一入口/网关，UNVERIFIED）" % list(servers)[0]
        out["notes"].append(note)
        if frac >= 0.8 and n >= 5:
            out["blind"] = True
            out["blind_reason"] = ("%d/%d 台同构 ⇒ 本批 0 命中**不构成『目标干净』**："
                                   "换 js 引擎 / 浏览器手工看 / 枚举网关已注册路由" % (len(hosts), n))
    # 未过阈值 = 保持沉默（自动判读只在证据够下判读时才说话；低于阈值的簇进 raw/groups 供人查，不进结论）
    return out


# ── 主流程 ──────────────────────────────────────────────────────────────────

def load_hosts(a) -> list:
    raw = []
    for h in (a.hosts or []):
        raw.append(h)
    for src in (a.hosts_file or []):
        p = Path(src)
        if not p.exists():
            print("  ! 找不到主机文件 %s" % src)
            continue
        for line in p.read_text("utf-8", "ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                raw.append(line)
    if a.from_json:
        p = Path(a.from_json)
        if p.exists():
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                print("  ! 读 %s 失败: %s" % (p, e))
                d = None
            if isinstance(d, list):
                for it in d:
                    if isinstance(it, dict):
                        v = it.get(a.from_json_field)
                        if v:
                            raw.append(v)
                    elif isinstance(it, str):
                        raw.append(it)
            elif isinstance(d, dict):
                v = d.get(a.from_json_field)
                if isinstance(v, list):
                    for it in v:
                        raw.append(it.get(a.from_json_field) if isinstance(it, dict) else it)
    seen = []
    for h in raw:
        n = norm_host(h)
        if n and n not in seen:
            seen.append(n)
    return seen


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="批量侦察唯一入口（范围预检 + 节流 + 预算 + 只读第一跳）")
    ap.add_argument("--weapon", default="", help="手法字母（path 引擎 A/B/E/F/H/O/P/X，js 引擎 C/G/I/J/L/N/Q/T）")
    ap.add_argument("--weapons", default="", help="一次跑一队手法（逗号/空格分隔，如 P,F,H,O）—— 省掉每个手法一次作业往返")
    ap.add_argument("--hosts", nargs="+", default=[])
    ap.add_argument("--hosts-file", action="append", default=[])
    ap.add_argument("--from-json", default="")
    ap.add_argument("--from-json-field", default="host")
    ap.add_argument("--allow", default=None, help="显式放行的厂池厂商名（NO-GO/UNSURE 时，风险自担）")
    ap.add_argument("--memory-slug", default="", dest="memory_slug",
                    help="本轮结果自动并入该 slug 的工作记忆（memory-<slug>.json）")
    ap.add_argument("--evidence", default=None,
                    help="UNSURE 降级证据（客观第二证据，如官网页脚自述/项目页范围声明）；会写审计日志")
    ap.add_argument("--max-hosts", type=int, default=20)
    ap.add_argument("--gap", type=float, default=MIN_GAP, help="单主机最小间隔秒（下限 2.0，传更小会被夹回）")
    ap.add_argument("--workers", type=int, default=MAX_WORKERS, help="全局在飞上限（上限 4，传更大会被夹回）")
    ap.add_argument("--cap", type=int, default=DAY_CAP, help="今日请求预算（只能调低）")
    ap.add_argument("--platform", default="unknown", choices=["unknown", "butian", "vulbox"],
                    help="本批目标属于哪个平台；butian 不占日额度"
                         "（补天都是中小厂商，很难触发 WAF；用户明示 2026-09-27）")
    ap.add_argument("--apply", action="store_true", help="真发请求；不加则只打印计划")
    ap.add_argument("--skip-reach", action="store_true", help="跳过可达性采样（不推荐）")
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--replay", default="", help="按 run.json 的原参数重跑")
    ap.add_argument("--status", action="store_true", help="只看预算账本")
    a = ap.parse_args(argv)

    # 2026-09-23 加：`--weapons P,F,H,O` 一次把一队手法跑完。
    # 动机（用户点名的性能损耗 #1）：单次工具调用 30s 上限 ⇒ 每换一个手法都要「启动作业 + 轮询」，
    # 4 个手法 = 4 次往返。这里在**同一进程内**按序再调 main()：每个手法仍各自 reserve/settle
    # （预算语义不变、产物目录与回放入口都不变），范围预检从第二个手法起命中 scope-cache。
    if a.weapons and not a.replay:
        base = list(argv if argv is not None else sys.argv[1:])
        cleaned, skip = [], False
        for tok in base:
            if skip:
                skip = False
                continue
            if tok == "--weapons":
                skip = True
                continue
            if tok.startswith("--weapons="):
                continue
            cleaned.append(tok)
        wl = [w.strip().upper() for w in a.weapons.replace(",", " ").split() if w.strip()]
        rcs = []
        for i, wk in enumerate(wl, 1):
            print("")
            print("#" * 70)
            print("## 队列 %d/%d：手法 %s" % (i, len(wl), wk))
            print("#" * 70)
            rcs.append(main(cleaned + ["--weapon", wk]))
        print("")
        print("== 队列收尾：%d 个手法，返回码 %s ==" % (len(wl), rcs))
        return max(rcs) if rcs else 0

    if a.status:
        b = Budget(platform=getattr(a, "platform", "unknown"))
        print("== 批量侦察预算 ==")
        print("  " + b.render())
        for r in b.d.get("runs", [])[-10:]:
            print("    %s  +%-6s %s" % (r.get("ts"), r.get("delta"), r.get("note")))
        return 0

    if a.replay:
        p = Path(a.replay)
        if not p.exists():
            print("找不到 %s" % p)
            return 2
        cfg = json.loads(p.read_text(encoding="utf-8"))
        pr = cfg.get("params", {})
        a.weapon = cfg.get("weapon", a.weapon)
        a.hosts = [norm_host(x) for x in cfg.get("hosts", a.hosts)]
        a.gap = pr.get("gap", a.gap)
        a.workers = pr.get("workers", a.workers)
        a.cap = pr.get("cap", a.cap)
        a.max_hosts = pr.get("max_hosts", a.max_hosts)
        a.skip_reach = pr.get("skip_reach", a.skip_reach)
        print("== 回放 %s（手法%s，%d 台）==" % (p, a.weapon, len(a.hosts)))
    else:
        a.hosts = load_hosts(a)

    if a.gap < MIN_GAP:
        print("  [闸门] --gap %.1f 低于下限，夹回 %.1f 秒/主机" % (a.gap, MIN_GAP))
        a.gap = MIN_GAP
    if a.workers > MAX_WORKERS:
        print("  [闸门] --workers %d 高于上限，夹回 %d" % (a.workers, MAX_WORKERS))
        a.workers = MAX_WORKERS
    if a.cap > DAY_CAP or a.cap <= 0:
        print("  [闸门] --cap %d 非法或高于日上限，夹回 %d" % (a.cap, DAY_CAP))
        a.cap = DAY_CAP
    budget = Budget(cap=a.cap, platform=a.platform)

    if not a.hosts:
        print("没有目标。用 --hosts / --hosts-file / --from-json / --replay")
        return 2
    hosts = a.hosts[:max(1, a.max_hosts)]
    if len(a.hosts) > len(hosts):
        print("  [闸门] 目标 %d 台超过 --max-hosts %d，本轮只做前 %d 台"
              % (len(a.hosts), a.max_hosts, len(hosts)))

    import arsenal
    wk = a.weapon.upper()
    _warn_loose_probes(wk)
    engine = "path" if wk in arsenal.PROBES else ("js" if wk in arsenal.JS_KEYWORDS else None)
    if not engine:
        print("手法%s 没有可批量引擎。path: %s / js: %s"
              % (wk or "?", ", ".join(sorted(arsenal.PROBES)), ", ".join(sorted(arsenal.JS_KEYWORDS))))
        return 2
    probes = arsenal.PROBES.get(wk) if engine == "path" else arsenal.JS_KEYWORDS.get(wk)
    # 2026-09-26 校准：原 (len(probes)+3) / js=8 严重低估 —— K4(13 探针) 估 320、实耗 600（2.5x），
    # 因为每台还叠加 可达性采样 + catch-all 负控(CTRL_PATH) + 同域重定向跟随 的开销；
    # 低估会让 --cap 形同虚设（实测 5005/5000 超支）。改为按实测比取上界，宁高勿低。
    # js 引擎实测：20 台约 113 次（含可达性+负控）⇒ per_host≈6，取 8 留余量
    per_host = (len(probes) * 2 + 8) if engine == "path" else 8
    estimate = len(hosts) * per_host

    print("== 批量第一跳 ==")
    print("  手法 %s  引擎 %s  目标 %d 台" % (wk, engine, len(hosts)))
    print("  节流 单主机 >= %.1fs / 全局在飞 <= %d / %s" % (a.gap, a.workers, budget.render()))
    print("  估算请求 ~%d 次（含可达性 + 负控），今日剩 %d" % (estimate, budget.left()))
    _charge = 0 if a.platform == "butian" else estimate   # 补天线不占额度
    if budget.charged() + _charge > budget.cap:
        print("  **拒绝启动**：估算 %d 超出今日剩余 %d。缩小 --max-hosts 或明天再来。"
              % (estimate, budget.left()))
        return 4

    if not a.apply:
        for h in hosts[:20]:
            print("    would-scan %s" % h)
        print("")
        print("(dry-run：不发任何目标请求。确认这批目标都在本项目范围内后加 --apply)")
        print("[done] BATCH-RECON-DRYRUN")
        return 0

    print("")
    print("== 范围预检（备案主体 x 厂池）==")
    scope = preflight(hosts, a.allow, verbose=True, evidence=a.evidence)
    import scope_gate
    noauto = _load_no_auto()
    if noauto:
        print("  禁自动化名单已载入：%d 条（来源 state/no-auto-scan.json）" % len(noauto))
    allowed, blocked = [], []
    for h in hosts:
        apex = scope_gate.registrable(h)
        na = noauto.get(apex)
        if na:
            blocked.append({"host": h, "apex": apex, "verdict": "NO-AUTO",
                            "reason": "%s：%s" % (na.get("project", ""), na.get("reason", ""))})
            continue
        info = scope.get(apex) or {"ok": False, "result": {"verdict": "UNSURE", "reason": "未查询"}}
        if info["ok"]:
            allowed.append(h)
        else:
            blocked.append({"host": h, "apex": apex,
                            "verdict": info["result"].get("verdict"),
                            "reason": info["result"].get("reason") or info["result"].get("org")})
    # 2026-09-27 结构化返回（用户批准）：拦截明细**按 (原因) 聚合**，同因只打一行 + 台数。
    # 动机：此前 BLOCK 时逐台刷屏（13 台 = 13 行）⇒ 吃掉上下文。逐台明细仍在 run.json。
    agg = {}
    for b in blocked:
        key = (str(b.get("verdict")), str(b.get("reason"))[:60])
        agg.setdefault(key, []).append(b["host"])
    for (v, rs), hs in sorted(agg.items(), key=lambda x: -len(x[1])):
        print("  [BLOCK] %-8s %2d 台  %s" % (v, len(hs), rs))
        if len(hs) <= 4:
            print("           %s" % ", ".join(hs))
    print("  放行 %d 台 / 拦截 %d 台（**越界资产只标注不测试**；逐台明细见 run.json）" % (len(allowed), len(blocked)))
    if not allowed:
        print("  没有可施工目标，退出。")
        print("[done] BATCH-RECON-END")
        return 3

    out_dir = Path(a.out_dir) if a.out_dir else RESULTS / ("batch-recon-%s" % dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    (out_dir / "raw").mkdir(parents=True, exist_ok=True)

    throttle = Throttle(gap=a.gap, workers=a.workers, budget=budget)
    budget.reserve(estimate, note="%s x%d" % (wk, len(allowed)))
    patch_requests(throttle)

    live, dead, reach_map = allowed, [], {}
    if not a.skip_reach:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=a.workers) as ex:
            got = dict(zip(allowed, ex.map(reachable, allowed)))
        live = [h for h in allowed if got[h][0]]
        dead = [h for h in allowed if not got[h][0]]
        # 2026-09-23：可达性采样本来带回了 (scheme, 状态码, Server, 首页指纹)，却当场丢掉 ——
        # 入口形态判读要用它当「跨台同构」的第二独立信号（见 entry_form）。
        reach_map = {h: (got[h][1] or []) for h in allowed}
        print("  可达性采样: 可达 %d / 不可达 %d（不可达**不**计入『目标干净』）" % (len(live), len(dead)))
        for h in dead[:8]:
            print("    不可达 %s" % h)

    def scan_host(h):
        """单主机：负控 -> 探针（主机内部串行；跨主机并行，节流由 Throttle 强制）。"""
        ctrl = ctrl_of(h) if engine == "path" else None
        audit: dict = {}
        if engine == "path":
            rows = path_pass(h, probes, ctrl)
        else:
            rows, audit = js_pass(h, probes, arsenal.EVIDENCE.get(wk))
        raw = {"host": h, "engine": engine, "weapon": wk, "ctrl": ctrl, "probes": rows,
               "js_audit": audit}   # 2026-09-23：js 引擎的仪器台账，判读「0 命中」时必须有它
        (out_dir / "raw" / (h + ".json")).write_text(
            json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
        return raw

    # 2026-09-23 修：原先是**按主机串行**的 for 循环，--workers 形同虚设（吞吐 0.5 req/s，
    # 一台台等 2s）。批量要的是效率，故跨主机并行 —— 单主机仍被 gap 串行化，
    # 全局在飞仍被 Throttle 信号量锁在 --workers。
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        raws = list(ex.map(scan_host, live))

    hits, false_pos, raw_map = [], [], {}
    for raw in raws:
        h = raw["host"]
        raw_map[h] = raw
        for r in raw["probes"]:
            if r.get("verdict") == "hit":
                hits.append({"host": h, "weapon": wk, **r})
                print("  [HIT] %-38s %-16s %s" % (h, r.get("probe"), str(r.get("url") or r.get("src"))[:44]))
                if r.get("snippet") or r.get("ctx"):
                    print("        %s" % str(r.get("snippet") or r.get("ctx"))[:120])
            elif r.get("verdict") in ("catchall-false-positive", "echo-false-positive"):
                false_pos.append({"host": h, "weapon": wk, **r})

    actual = throttle.count
    budget.settle(actual, note="%s actual=%d" % (wk, actual))

    gate_verdict, gate_why = "OK", []
    ef = entry_form(live, raw_map, reach_map) if engine == "path" else {}
    if not hits and engine == "path":
        rows_all = []
        for h in live:
            for r in raw_map[h]["probes"]:
                rows_all.append((r.get("status", -1), r.get("sig", "")))
        if rows_all:
            try:
                sys.path.insert(0, str(SCRIPTS / "kit"))
                from verdict import appraise
                gate_verdict, gate_why = appraise(rows_all, label="批量第一跳基线")
            except Exception as e:
                gate_verdict, gate_why = "UNSURE", ["基线闸门不可用: %s" % e]
        # 2026-09-23：入口形态判读（只读既有响应）。措辞分两层——
        #   note = 事实（这些台没区分度）；blind = 覆盖 ≥80% 才允许升格为 UNSURE。
        if ef.get("notes"):
            gate_why = list(gate_why) + list(ef["notes"])
        if ef.get("blind") and gate_verdict == "OK":
            gate_verdict = "UNSURE"
            gate_why = list(gate_why) + [ef["blind_reason"]]
    elif not hits and engine == "js":
        # 2026-09-23 加：js 引擎此前**从不进基线闸门** —— 0 命中直接报 gate=OK。
        # 实测代价：portal 的主包 5.99MB（含 getSign）被 4MB 上限静默吞掉，整批仍报 OK。
        # 现按「有没有真的扫到同站 JS」判：一台都没扫到 = 仪器盲区 ⇒ UNSURE 上交。
        _scanned = [h for h in live if (raw_map[h].get("js_audit") or {}).get("scanned")]
        _skipped = {h: ((raw_map[h].get("js_audit") or {}).get("skipped") or []) for h in live}
        _skipped = {h: v for h, v in _skipped.items() if v}
        if not _scanned:
            gate_verdict, gate_why = "UNSURE", [
                "js 引擎 %d 台里没有一台扫到同站 JS（首页无 JS / 抓取失败 / 体积超限）"
                " —— 仪器盲区，不得据此判『无漏洞』" % len(live)]
        else:
            _nohome = [h for h in live if not (raw_map[h].get("js_audit") or {}).get("scanned")
                       and (raw_map[h].get("js_audit") or {}).get("home") == "unreachable"]
            gate_why = ["js 引擎扫到同站 JS 的主机 %d/%d 台" % (len(_scanned), len(live))]
            if len(_nohome) >= max(3, len(live) // 2):
                gate_why.append("%d/%d 台根路径无 HTML（404/跳转）—— 这些台上 js 引擎**不适用**，"\
                                "不得计入『无此特征』；要覆盖得换 path 引擎或浏览器手工看" % (len(_nohome), len(live)))
            if _skipped:
                gate_why.append("有 JS 被跳过的主机 %d 台（多为体积超限 ⇒ 命中面未覆盖）: %s"
                                % (len(_skipped),
                                   "; ".join("%s:%s" % (h, ",".join(v[:2])) for h, v in list(_skipped.items())[:3])))
            # 2026-09-26 加：**WAF 指纹拦截**必须单独报 —— 它不是「这台干净」，而是「这台没扫到」。
            # 触发场景：目标按请求头指纹拦子资源（HTTP 456 / 403 / 空体），此时 js 引擎的 0 命中是假阴性。
            # 实测 cacp.org.cn：6 个 JS 全 456、scanned_n=0；补 Referer+Sec-Fetch-Dest 后 scanned_n=6。
            _waf = {}
            for _h, _v in _skipped.items():
                _w = [s for s in _v if "456" in str(s) or "403" in str(s)]
                if _w:
                    _waf[_h] = _w
            if _waf:
                gate_verdict = "UNSURE"
                gate_why = list(gate_why) + [
                    "**WAF 指纹拦截**：%d 台主机的 JS 被抓成 456/403 ⇒ 这些台**未被覆盖**，其「0 命中」是假阴性；"
                    "修头后重跑（见 pentest-batch「WAF 按请求头指纹拦截」）: %s"
                    % (len(_waf),
                       "; ".join("%s:%s" % (h, ",".join(w[:2])) for h, w in list(_waf.items())[:3]))]

    run = {"ts": now_iso(), "weapon": wk, "engine": engine,
           "params": {"gap": a.gap, "workers": a.workers, "cap": a.cap, "max_hosts": a.max_hosts,
                      "skip_reach": bool(a.skip_reach)},
           "hosts": a.hosts, "scope": {k: v["result"] for k, v in scope.items()},
           "blocked": blocked, "live": live, "unreachable": dead,
           "hits": hits, "catchall_false_positives": false_pos,
           "requests_actual": actual, "budget_after": {"used": budget.used, "cap": budget.cap},
           "entry_form": ef, "reach": reach_map,
           "js_audit": {h: (raw_map[h].get("js_audit") or {}) for h in live} if engine == "js" else {},
           "gate": {"verdict": gate_verdict, "why": gate_why},
           "artifacts": {"candidates": "candidates.json", "raw": "raw/", "criteria": "criteria.md"}}
    (out_dir / "run.json").write_text(json.dumps(run, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "candidates.json").write_text(
        json.dumps({"weapon": wk, "engine": engine, "ts": run["ts"], "hits": hits,
                    "catchall_false_positives": false_pos, "blocked": blocked,
                    "unreachable": dead}, ensure_ascii=False, indent=2), encoding="utf-8")
    with (out_dir / "candidates.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "probe", "url/src", "status", "len", "verdict"])
        for r in hits:
            w.writerow([r.get("host"), r.get("probe"), r.get("url") or r.get("src"),
                        r.get("status", ""), r.get("len", ""), "hit"])
        for r in false_pos:
            w.writerow([r.get("host"), r.get("probe"), r.get("url") or r.get("src"),
                        r.get("status", ""), r.get("len", ""), r.get("verdict", "false-positive")])

    crit = []
    crit.append("# 批量第一跳判据 — 手法 %s（引擎 %s）" % (wk, engine))
    crit.append("")
    crit.append("- 时间: %s" % run["ts"])
    crit.append("- 目标: %d 台（放行 %d / 拦截 %d / 不可达 %d）" % (len(a.hosts), len(live), len(blocked), len(dead)))
    crit.append("- 节流: 单主机 >= %.1fs，全局在飞 <= %d" % (a.gap, a.workers))
    crit.append("- 请求: 估算 %d，实测 %d；%s" % (estimate, actual, budget.render()))
    crit.append("- 引擎: %s" % ("arsenal.PROBES path 表（直连固定路径，只读 GET）" if engine == "path"
                                else "arsenal.JS_KEYWORDS（拉前端 JS 搜特征串 + 赋值证据正则）"))
    crit.append("- 负控A(catch-all): 同主机 %s 的 (状态码, 字节数, 摘要md5) —— 同字节即假阳" % CTRL_PATH)
    crit.append("- 负控B(形状/回显): 对每个**命中**再发 1 次同目录同扩展名的瞎编路径"
                "（如 /zz_noauth_<md5>.php）；它与命中同状态码、且页面回显我请求的文件名"
                " ⇒ 站点按输入生成页面 = 假阳（2026-09-25 加，myssl 类）")
    crit.append("- 可达性: 先采样，不可达主机单列，**不**计入『目标干净』")
    crit.append("- 基线闸门: %s" % ("0 命中时必须过 scripts/kit/verdict.appraise，否则报 UNSURE（仪器存疑）"
                                  if engine == "path" else
                                  "js 引擎按仪器台账判：一台都没扫到同站 JS = 盲区 ⇒ UNSURE（2026-09-23 加）"))
    if engine == "path" and ef.get("groups"):
        crit.append("- 入口形态(advisory): 同构簇 %d 组；最大簇 %d 台（阈值 %d）；明细见 run.json 的 entry_form"
                    % (len(ef["groups"]), len(ef["groups"][0]["hosts"]),
                       max(3, -(-len(live) // 2))))
    if engine == "js":
        _sc = [h for h in live if (raw_map[h].get("js_audit") or {}).get("scanned")]
        _sk = [h for h in live if (raw_map[h].get("js_audit") or {}).get("skipped")]
        crit.append("- 仪器台账(js): 扫到同站 JS %d 台 / 有 JS 被跳过 %d 台（明细见 raw/<host>.json 的 js_audit）"
                    % (len(_sc), len(_sk)))
    crit.append("")
    crit.append("## 结论")
    crit.append("")
    crit.append("- 候选命中 **%d** 条；catch-all 假阳 **%d** 条" % (len(hits), len(false_pos)))
    crit.append("- 基线判读: **%s** %s" % (gate_verdict, "; ".join(gate_why)))
    crit.append("")
    crit.append("## 边界")
    crit.append("")
    crit.append("- 本脚本产出只到候选表；报告交付走 report_gate.py，不在此处发生。")
    crit.append("- 只发只读 GET；不写、不删、不爆破、不带凭据。")
    crit.append("- 拦截清单里的越界资产**只标注不测试**。")
    (out_dir / "criteria.md").write_text(chr(10).join(crit), encoding="utf-8")

    print("")
    print("== 结果 ==")
    print("  候选命中 %d 条 / catch-all 假阳 %d 条 / 目标 %d 台 / 实测请求 %d 次"
          % (len(hits), len(false_pos), len(live), actual))
    for _nt in (ef.get("notes") or []):
        if _nt not in gate_why:
            print("  · 入口形态: %s" % _nt)
    if gate_verdict == "UNSURE":
        for why in gate_why:
            print("  ! 判读存疑: %s" % why)
        print("  => **0 命中不可作为『目标干净』的依据**（AGENTS 5：仪器存疑必须 UNSURE 上交）")
    print("  " + budget.render())
    print("  落盘: %s" % out_dir)
    print("  回放: $py scripts/batch_recon.py --replay %s --apply" % (out_dir / "run.json"))
    # 2026-09-27 自动落：本轮结果并入外置工作记忆（治「上下文是唯一工作记忆」）。
    try:
        if a.memory_slug:
            import subprocess as _sp
            _sp.run([sys.executable, str(SCRIPTS / "memory.py"), "ingest-run", a.memory_slug,
                     "--run", str(out_dir / "run.json")], timeout=60, check=False)
            print("  已并入工作记忆: memory.py brief %s" % a.memory_slug)
    except Exception as _exc:
        print("  (memory ingest 跳过: %s)" % str(_exc)[:50])
    print("  下一步: 候选表进 engagement.py hop 记账；命中项按闭合链打到底，再走 report_gate.py。")
    print("[done] BATCH-RECON-END")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
