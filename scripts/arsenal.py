#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""arsenal.py — 武器库：手法 x 目标 的登记、选路、批量。

两条腿（2026-09-19 用户定案：**手法没有高低贵贱**）：
  · batch（轰炸线）: 第一跳是单请求/固定路径 -> 能写成探针批量跑。
    **手法越多，整个厂池一次能覆盖的面越多 => 效率指数级提高。这是效率引擎。**
  · manual（精细线）: 需注册/抓包/反编译/理解业务 -> 逐家人工，慢工出细活。

一条公司可以有**多个特征** => 同一家公司可以套**多种手法**分别打（手法 x 公司是矩阵, 不是一对一）。
一个手法打不通**不代表这家公司没漏洞** —— 换手法继续。

records 里那些 QTVA 编号 = **别人也用了同一手法**的成熟度证据, **不是红灯**。

用法（在 _PT工作台 目录执行）：
    $py scripts/arsenal.py board                   # 作战板: 两条线 + 探针缺口
    $py scripts/arsenal.py check --target <host>   # 这家公司能套哪些手法（矩阵）
    $py scripts/arsenal.py check --weapon D        # 这条手法的第一跳/闭环/记录
    $py scripts/arsenal.py hunt [--limit N]        # 从厂池（补天 5974 + 漏洞盒子 47）猎没打过的目标
    $py scripts/arsenal.py scan --weapon F --hosts <列表> --apply   # 批量第一跳（只读 GET）
    $py scripts/arsenal.py log --weapon D --target <host> --verdict dup|hit|miss

数据: state/arsenal.json    文档: skills/pt-engagement/references/attack-arsenal.md
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REG = ROOT / "state" / "arsenal.json"
POOL = ROOT / "state" / "pt-targets.json"
DB = ROOT / "state" / "workspace.db"
MULTI = ("com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "co.jp", "co.uk")


def load() -> dict:
    return json.loads(REG.read_text("utf-8"))


def save(d: dict) -> None:
    d["updated"] = dt.date.today().isoformat()
    REG.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")


def host_of(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    return s.split("/")[0].split("?")[0].split(":")[0]


def base_domain(h: str) -> str:
    parts = host_of(h).split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def score_match(target_host: str, recorded: str) -> int:
    th, ch = host_of(target_host), host_of(recorded)
    if not th or not ch:
        return 0
    if th == ch:
        return 3
    if th in ch or ch in th:
        return 2
    if base_domain(th) == base_domain(ch):
        return 2
    return 0


def mode_cn(w: dict) -> str:
    return "轰炸线" if w.get("mode") == "batch" else "精细线"


def cmd_board(d: dict) -> int:
    ws = d["weapons"]
    batch = {k: w for k, w in ws.items() if w.get("mode") == "batch"}
    manual = {k: w for k, w in ws.items() if w.get("mode") != "batch"}
    pool = d.get("pool", {})
    eng = {}
    for k, w in batch.items():
        eng.setdefault(w.get("engine", "path"), []).append(k)
    print("== 作战板 ==（无先后，两条腿并行）")
    # 2026-10-01 改造：厂池（补天/漏洞盒子）随 SRC 层移除，
    # 现在读**本项目目标清单** state/pt-targets.json：每项 {"name": "..."} 或纯字符串。
    tgt = load_pool()
    if tgt:
        print("  目标清单: %d 项（state/pt-targets.json）" % len(tgt))
    else:
        print("  目标清单: 空 —— 把本次委托的资产写进 state/pt-targets.json，或直接用 --hosts 传目标。")
    print("\n-- 轰炸线（batch）%d 条 --" % len(batch))
    for e, label, table in (("path", "path 引擎（直连固定路径）", PROBES),
                            ("js", "js 引擎（前端 JS 搜特征串）", JS_KEYWORDS)):
        ks = sorted(eng.get(e, []))
        if not ks:
            continue
        have = [k for k in ks if k in table]
        lack = [k for k in ks if k not in table]
        print("   %s: 共 %d 条, 已定义 %d" % (label, len(ks), len(have)))
        for k in ks:
            mark = "OK " if k in table else "缺 "
            print("      [%s] %s %s" % (mark, k, batch[k]["name"][:52]))
        if lack:
            print("      **缺 %s —— 补一张表即多覆盖一个面**" % " ".join(lack))
    print("\n-- 精细线（manual）%d 条 -- 逐家人工, 慢工出细活" % len(manual))
    for k in sorted(manual):
        w = manual[k]
        print("      %s %-46s  %d 条记录" % (k, w["name"][:46], len(w.get("records", []))))
    print("\n读法: 轰炸线挣**广度**（同一套探针套 242 家），精细线挣**深度**（每家链子都不同）。")
    print("      手法越多能批量的面 => 效率越高。**没有该主攻哪条这回事。**")
    return 0


def cmd_check_target(d: dict, target: str) -> int:
    th = host_of(target)
    print("== 目标矩阵: %s ==" % target)
    self_hit = []
    for k, w in sorted(d["weapons"].items()):
        for o in w.get("records", []):
            if score_match(th, o.get("t", "")) >= 2:
                self_hit.append((k, w, o))
    if self_hit:
        for k, w, o in self_hit:
            print("  [已交] 手法%s「%s」已有该目标的记录 %s (%s)"
                  % (k, w["name"], o.get("r"), o.get("d")))
        print("         同一目标同一个面重交必驳；**但这家公司的其他面照样可以打**（见下）。")
    # 2026-09-21 加：**把判死记录读回来**。判死举证只有被"下次开荒"读到才有价值
    # （AGENTS §8「写了没人读 = 白干」）。位置有意放在"已交"之后、推荐之前：
    # 先告诉你这个面**以前怎么死的**，再谈还能套哪些手法。
    miss_hit = []
    for k, w in sorted(d["weapons"].items()):
        for o in w.get("records", []):
            if o.get("v") == "miss" and score_match(th, o.get("t", "")) >= 2:
                miss_hit.append((k, w, o))
    if miss_hit:
        print("\n  [已判死] 该目标/同域此前判过打不通（**别原地重来**）:")
        for k, w, o in miss_hit[-4:]:
            print("    手法%s「%s」 %s" % (k, w["name"], o.get("d")))
            if o.get("tried"):
                print("      试过: %s" % o["tried"])
            if o.get("why"):
                print("      原因: %s" % o["why"])
        print("    ⇒ 要么**升级到更高 Level**（L5 换入口 / L6 组合 / L7 时间维度），")
        print("      要么换手法 —— 同一层重来一次不会有不同结果。")
    rec = recommend(d, th)
    if rec:
        print("\n  这家公司可套的手法（%d 条）:" % len(rec))
        for k, w, sig in sorted(rec, key=lambda x: (x[1].get("mode") != "batch", x[0])):
            print("    [%s] %s「%s」" % (mode_cn(w), k, w["name"]))
            print("        命中特征: %s" % sig)
            print("        第一跳: %s" % w["first_hop"])
            print("        闭环: %s" % w["closed_loop"])
    else:
        print("\n  域名特征没直接命中任何手法 —— 但那只是**按名字猜**，不代表没戏。")
        print("  下一步: recon_api.py all <domain> 拿资产清单，再人工过一遍 19 条手法的适用画像。")
    print("\n提示: 一家公司多特征 => 多手法并行；一条打不通不等于没漏洞。")
    return 1 if self_hit else 0


def recommend(d: dict, host: str):
    out = []
    for k, w in sorted(d["weapons"].items()):
        hit = [s for s in w.get("signal", []) if s in host]
        if hit:
            out.append((k, w, "/".join(hit[:4])))
    return out


def cmd_check_weapon(d: dict, wk: str) -> int:
    w = d["weapons"].get(wk.upper())
    if not w:
        print("没有手法 %s；可选: %s" % (wk, ", ".join(sorted(d["weapons"]))))
        return 2
    probe = ""
    if w.get("mode") == "batch":
        probe = "  探针: %s" % ("已就绪" if w.get("probe_ready") else "**缺**（补 PROBES 即可批量）")
    print("== 手法%s: %s  <%s>%s" % (wk.upper(), w["name"], mode_cn(w), probe))
    print("  信号: %s" % " / ".join(w.get("signal", [])))
    print("  第一跳: %s" % w["first_hop"])
    print("  闭环判据: %s" % w["closed_loop"])
    print("  取证清单:")
    for e in w.get("evidence", []):
        print("    - %s" % e)
    print("  记录（别人也用过 = 手法成熟度证据, 不是红灯）:")
    for o in w.get("records", []) or [{"t": "(无)", "r": "", "d": "", "v": ""}]:
        print("    - %-46s %s %s [%s]" % (o.get("t", ""), o.get("r", ""), o.get("d", ""), o.get("v", "")))
    print("  适用画像: %s" % w.get("targets", ""))
    return 0


def load_pool() -> list:
    """厂池：优先用重建后的两池（pool_loader），旧池仅作回退。"""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import pool_loader
        got = pool_loader.load_all()
        if got:
            return [{"cid": r["cid"], "name": r["name"], "tag": r["tag"],
                     "scope": r.get("scope") or "", "platform": r.get("platform"),
                     "tier": r.get("tier"), "in_scope": r.get("in_scope")} for r in got]
    except Exception:
        pass
    if not POOL.exists():
        return []
    raw = json.loads(POOL.read_text("utf-8", "ignore"))
    out = []
    if isinstance(raw, dict):
        for cid, v in raw.items():
            if isinstance(v, dict) and v.get("name"):
                out.append({"cid": str(cid), "name": v["name"], "tag": v.get("tag", ""),
                            "scope": v.get("scope", "")})
    elif isinstance(raw, list):
        for v in raw:
            if isinstance(v, dict) and (v.get("company_name") or v.get("name")):
                out.append({"cid": str(v.get("company_id", "")),
                            "name": v.get("company_name") or v.get("name"),
                            "tag": v.get("tag", ""), "scope": ""})
    return out


def recon_ids() -> set:
    """「侦察过」= 跑过 FOFA 反查、手里已有资产清单。**这不等于打过。**"""
    did = set()
    for art in (ROOT / "state").glob("fofa-reverse-*.json"):
        try:
            for c in json.loads(art.read_text("utf-8")).get("companies", []):
                cid = str(c.get("company_id") or "")
                if cid:
                    did.add(cid)
        except Exception:
            continue
    return did


def tested_ids() -> set:
    """「打击过」= DB 里有 project 行（真开过项目动过手）。"""
    did = set()
    try:
        con = sqlite3.connect(str(DB))
        did |= {str(r[0]) for r in con.execute("SELECT company_id FROM projects")
                if r[0] not in (None, "")}
    except Exception:
        pass
    return did


def touched() -> set:
    """侦察过 ∪ 打击过（兼容旧调用）。

    ⚠ 2026-09-21 修：**不要拿这个函数决定「还有什么可打」**。
    当天给 touched() 加了「跑过 FOFA 反查也算接触过」之后，fofa_reverse 覆盖全池，
    家家都"接触过" => hunt 输出「还没碰过 0 家」，与 AGENTS §3 的「230 家空白」直接矛盾。
    根因：把**侦察**和**打击**合并成了一个集合。判"可打"请用 tested_ids()，见 cmd_hunt。
    """
    return recon_ids() | tested_ids()


def cmd_hunt(d: dict, a) -> int:
    """从**本项目目标清单**里挑还没打过的目标。

    改造说明（2026-10-01）：原版在「242 家公益厂池」里挑；厂池已随 SRC 层移除，
    现在目标清单 = state/pt-targets.json（本次委托要覆盖的资产/单位）。
    「打没打过」仍按 DB 里有没有 project 行判定（真实开工的痕迹），不用记忆。
    """
    tgt = load_pool()
    if not tgt:
        print("目标清单为空（%s）" % POOL)
        print('  写法: [{"name": "某某科技有限公司"}, {"name": "某某医院"}]')
        print('      或纯字符串数组 ["某某科技", "某某医院"]')
        return 2
    recon, tested = recon_ids(), tested_ids()
    fresh = [p for p in tgt if p["cid"] not in tested]
    ready = [p for p in fresh if p["cid"] in recon]
    need_recon = [p for p in fresh if p["cid"] not in recon]
    fresh = ready + need_recon
    print("== 猎目标：本项目目标清单 ==")
    print("  清单 %d 项 | 打击过 %d | 待打 %d（其中 %d 已有资产清单=就绪，%d 需先侦察）"
          % (len(tgt), len(tgt) - len(fresh), len(fresh), len(ready), len(need_recon)))
    if a.filter:
        fresh = [p for p in fresh if a.filter in p["name"]]
        print("  按关键词「%s」过滤后 %d 项" % (a.filter, len(fresh)))
    print("")
    print("  待打清单（前 %d 项）:" % a.limit)
    for i, p in enumerate(fresh[:a.limit], 1):
        print("   %3d. [%s] %-30s %s" % (i, p["cid"] or "-", p["name"][:30],
                                          "就绪" if p["cid"] in recon else "需先侦察"))
    print("")
    print("  下一步: recon_api.py all <域名> 拿资产 -> 用 check --target <host> 看能套哪些手法")
    print("          -> 定范围（scope_gate --show）-> engagement.py new 挂项目 -> 才动手。")
    return 0


# JS 关键词引擎：很多手法的第一跳其实是「前端 JS 里搜特征串」，这天然可批量。
# 与 PROBES（直连固定路径）并列，二者构成 scan 的两个引擎。
JS_KEYWORDS = {
    "C": ["uploadToken", "uptoken", "up-token", "getSts", "sts/token", "AssumeRole"],
    "G": ["generateSign", "signKey", "X-Sign", "x-timestamp", "x-nonce", "getSign"],
    "L": ["client_secret", "client_id", "grant_type", "oauth/token"],
    "I": ["/api/register", "/api/signup", "/api/user/reg", "自助注册", "register.html"],  # 2026-09-27 删裸 /register（命中备案链接 registerSystemInfo 假阳）
    "N": ["forgotPassword", "resetPwd", "resetPassword", "sendCode", "找回密码"],
    "Q": ["sendCode", "sendSms", "sms/send", "smsCode", "验证码"],
    "J": ["/api/user/list", "/api/v1/users", "getUserList", "listUsers", "getAllUser"],  # 2026-09-27 删裸 userList（实测命中 Vue CSS 类名 Userlist 假阳）; 2026-09-26 原 pageSize/getList 太泛
    "T": ["downloadUrl", "fileUrl", "previewUrl", "remoteUrl", "callbackUrl", "targetUrl", "fetchUrl", "proxyUrl", "webhookUrl", "redirect_uri"]  # 删 imageUrl（太泛）；补 proxy/webhook/redirect_uri,
}

SQ = chr(39)
DQ = chr(34)


MAX_JS_BYTES = 12_000_000   # 2026-09-23: 原上限 4MB 会**静默跳过** SPA 主包 ——
                            # 实测 portal.xinteenergy.com/static/js/index-*.js = 5.99MB 且含 getSign，
                            # 却什么都没留下 ⇒「无命中」与「主包被吞」长得一模一样（假阴性无法识别）。


def js_probe(host: str, keywords: list, max_js: int = 6, timeout: int = 8, evidence: str = None,
             audit: dict = None):
    """拉首页 + 前 N 个 JS, 搜关键词。只读 GET, 不碰业务接口。

    audit（可选 dict）：回填仪器台账（扫到哪些同站 JS / 跳过了什么 / 首页可达性），
    由 batch_recon 写进 run.json 与 criteria.md —— 判读必须有仪器记录，见技能 pentest-batch。
    """
    import requests
    import urllib3
    urllib3.disable_warnings()
    ua = BROWSER_HEADERS
    base = html = None
    for scheme in ("https", "http"):
        try:
            r = requests.get("%s://%s/" % (scheme, host), timeout=timeout, verify=False,
                             headers=ua, allow_redirects=True)
            if r.status_code < 400 and r.text:
                base, html = "%s://%s" % (scheme, host), r.text
                break
        except Exception:
            continue
    if not html:
        if audit is not None:
            audit["home"] = "unreachable"
        # 2026-09-23：根路径无 HTML 也要留一行 —— 否则 raw 里是空数组，
        # 读的人分不清「这台没应用」和「引擎没跑」。
        return [{"note": True, "kind": "no-home", "kw": "home-not-html", "src": "根路径无 HTML",
                 "ctx": "首页 GET 失败或状态码 >=400 —— js 引擎在这台**不适用**（不等于无漏洞）"}]
    if audit is not None:
        audit["home"] = "ok"
    low = html.lower()
    hits = []
    bare_home = 0
    for kw in keywords:
        if kw.lower() not in low:
            continue
        # 首页侧同样要赋值证据：实测 mail.shouqianba.com 首页里的 client_id=legacy_webmail
        # 是**阿里邮箱**的 OAuth 客户端 ID，不是厂商自己的（同类：腾讯企业邮）。
        if evidence and not re.search(evidence, html, re.I):
            bare_home += 1
            continue
        i = low.find(kw.lower())
        hits.append({"src": base + "/", "kw": kw, "ctx": " ".join(html[max(0, i - 60):i + 90].split())})
    if bare_home:
        hits.append({"note": True, "kind": "bare-keyword", "kw": "bare-keyword-home",
                     "src": "%d 处首页裸关键词" % bare_home,
                     "ctx": "首页关键词无赋值证据（多为他方 SaaS 客户端 ID），不计命中"})
    # 用 split 提 script src（避免在源码里写引号字面量, 免遭转义地狱）
    srcs = []
    for part in html.split("src=")[1:]:
        if not part:
            continue
        q = part[0]
        if q == DQ or q == SQ:
            s = part[1:].split(q)[0]
        else:
            # 2026-09-27 实测：**压缩 HTML 用无引号属性**（<script src=/static/js/app.js>）。
            # 旧逻辑对无引号直接 continue ⇒ srcs_total=0 ⇒ 假报「首页无 JS / 仪器盲区」。
            # 实证：en.hospitalstar.com 首字节流为 <script src=/vendors/underscore/js/...>，
            # 旧引擎报 0，实际有 6 个 JS（含 Vue CLI 的 app.f56c160d.js 与 chunk-vendors）。
            s = re.split(r"[\s>]", part, 1)[0]
        if ".js" in s and s not in srcs:
            srcs.append(s)
    # ⚠ 2026-09-21 实测修正：**必须只看同站 JS**。
    # 起因：wave2 手法 G 一次报 9 个命中，8 个是 mail.* 主机命中 `getSign` in `all7e1bf3.js`，
    # 抓下来一看全站都引用 `rescdn.qqmail.com/bizmail/...` ——**那是腾讯企业邮箱的客户端代码**，
    # 不是厂商自己的。任何用腾讯/网易企业邮箱的公司都会假命中。
    # 判据：JS 的 host 与目标同 registrable domain 才算目标的代码；公共 CDN 一律不计入（只记数）。
    third = 0
    bare = 0
    scanned = 0
    _ = None   # bare_home 已在首页段计数
    for s in srcs[:max_js]:
        url = s if s.startswith("http") else (base + ("/" if not s.startswith("/") else "") + s)
        if not _same_site(url, host):
            third += 1
            if audit is not None:
                audit.setdefault("third", []).append(url.split("/")[-1][:32])
            continue
        try:
            # 2026-09-26：JS 请求补 Referer + Sec-Fetch-Dest —— 实测 WAF(HTTP 456) 对
            # 「带 Referer 的同源子资源」放行；仅换 UA / 补 sec-ch-ua 仍会被拦。
            _h = dict(ua)
            _h["Referer"] = base + "/"
            _h["Sec-Fetch-Dest"] = "script"
            _h["Sec-Fetch-Mode"] = "no-cors"
            jr = requests.get(url, timeout=timeout, verify=False, headers=_h)
        except Exception as exc:
            if audit is not None:
                audit.setdefault("skipped", []).append("%s 抓取失败:%s"
                                                       % (url.split("/")[-1][:24], str(exc)[:24]))
            continue
        if jr.status_code != 200:
            if audit is not None:
                audit.setdefault("skipped", []).append("%s HTTP %s" % (url.split("/")[-1][:30], jr.status_code))
            continue
        if len(jr.content) > MAX_JS_BYTES:
            # 2026-09-23：**跳过必须留痕**，否则整批的「0 命中」里混着没扫过的主包。
            if audit is not None:
                audit.setdefault("skipped", []).append("%s %.1fMB>%.0fMB"
                                                       % (url.split("/")[-1][:22], len(jr.content) / 1e6,
                                                          MAX_JS_BYTES / 1e6))
            hits.append({"note": True, "kind": "js-skipped", "kw": "js-too-big",
                         "src": url.split("/")[-1][:40],
                         "ctx": "%.1fMB 超过 %.0fMB 上限，**未扫描**（不得据此判『无此特征』）"
                                % (len(jr.content) / 1e6, MAX_JS_BYTES / 1e6)})
            continue
        scanned += 1
        if audit is not None:
            audit.setdefault("scanned", []).append("%s %.0fKB" % (url.split("/")[-1][:30], len(jr.content) / 1024))
        t = jr.text
        tl = t.lower()
        for kw in keywords:
            if kw.lower() not in tl:
                continue
            if evidence and not re.search(evidence, t, re.I):
                bare += 1        # 只有 API 名、没有赋值 => 不算密钥（留痕）
                continue
            i = tl.find(kw.lower())
            hits.append({"src": url.split("/")[-1][:40], "kw": kw,
                         "ctx": " ".join(t[max(0, i - 60):i + 90].split())})
    if bare:
        hits.append({"note": True, "kind": "bare-keyword", "kw": "bare-keyword", "src": "%d 处裸关键词" % bare,
                     "ctx": "关键词无赋值证据（多为他方库/API 名），不计命中"})
    if third:
        hits.append({"note": True, "kind": "3rd-party", "kw": "3rd-party-js",
                     "src": "%d 个第三方 CDN JS" % third,
                     "ctx": "同站 JS 才算目标代码；公共库/企业邮箱客户端不计入命中"})
    if not scanned:
        # 一台都没扫到 = 仪器盲区，必须显式上报（此前直接返回空列表，与「扫过但没特征」同形）
        hits.append({"note": True, "kind": "no-js", "kw": "no-same-site-js",
                     "src": "0 个同站 JS 被扫描",
                     "ctx": "首页共 %d 个 JS（第三方 %d / 跳过 %d）—— **仪器盲区**，不得据此判『无漏洞』"
                            % (len(srcs), third, len((audit or {}).get("skipped") or []))})
    if audit is not None:
        audit["srcs_total"] = len(srcs)
        audit["scanned_n"] = scanned
    return hits


def _ssl_ctx():
    """不可信证书的 SSL context（扫描器只做可达性/特征判断，不做证书校验）。"""
    try:
        import ssl as _ssl
        c = _ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = _ssl.CERT_NONE
        return c
    except Exception:
        return None


def _same_site(js_url: str, target_host: str) -> bool:
    """JS 与目标是否同站（同 registrable domain）。公共 CDN ⇒ False。"""
    try:
        from urllib.parse import urlparse
        jh = (urlparse(js_url).hostname or "").lower()
    except Exception:
        return True
    if not jh:
        return True
    return _apex(jh) == _apex(target_host.split(":")[0].lower())


def _apex(h: str) -> str:
    p = [x for x in h.split(".") if x]
    if len(p) <= 2:
        return ".".join(p)
    multi = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "co.jp"}
    return ".".join(p[-3:]) if ".".join(p[-2:]) in multi else ".".join(p[-2:])


# 可批量第一跳（只读 GET）。batch 手法应尽量补齐到这里 —— 每补一条, 242 家就多覆盖一个面。
# 「以 200 包装的拒绝页」标志词 —— 命中即判该探针未命中
# ⚠ 2026-09-21 实测修正之二：**裸关键词不算命中，必须伴随赋值证据**。
# 起因：同站过滤后再验 `czton.cn` 唯一的 G 命中，发现 `signKey` 出自 `getQQBrowserSignKey`
# —— 那是打包进本地播放器文件的**腾讯 QQ 浏览器库 API 名**，不是站点的签名密钥。
# 判据：关键词附近必须出现「键 = 值」形态的赋值，否则只是 API 名/文档词。
EVIDENCE = {
    "G": r"""(signkey|secretkey|appsecret|sign_key|apikey)\s*[:=]\s*["'\x60][A-Za-z0-9+/=_-]{8,}["'\x60]""",
    "L": r"""client_secret\s*[:=]\s*["'\x60][A-Za-z0-9+/=_-]{8,}["'\x60]""",
    "C": r"""(accesskeyid|accesskeysecret|securitytoken|ststoken)\s*[:=]\s*["'\x60][A-Za-z0-9+/=_-]{8,}["'\x60]""",
}
NEG_MARKERS = ("无权限", "没有权限", "无权访问", "access denied", "403 forbidden",
               "please login", "请登录", "登录后", "unauthorized", "not authorized")

# 2026-09-26 修：裸 UA "Mozilla/5.0" 触发 WAF 456（同 batch_recon.py 修复）
UA_FULL = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
BROWSER_HEADERS = {
    "User-Agent": UA_FULL,
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "sec-ch-ua": '"Chromium";v="147", "Not?A_Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "no-cors",
    "Connection": "keep-alive",
}

PROBES = {
    "A": [("Harbor", "/api/v2.0/projects?page_size=5", ["repo_count", "creation_time"]),
          ("Nexus", "/service/rest/v1/repositories", ["format", "repositoryName"]),
          ("GitLab", "/api/v4/projects", ["path_with_namespace"]),
          ("Jenkins", "/api/json", ["\"jobs\":[", "hudson.model.Hudson", "_class"]),
          ("SonarQube", "/api/projects/search", ["qualifier", "pageIndex"])],
    "B": [("OSS/COS-list", "/?max-keys=3", ["ListBucketResult"]),
          ("OSS-versioning", "/?versioning", ["VersioningConfiguration"])],
    "E": [("FineCMS", "/index.php?s=admin&c=login", ["FineCMS", "finecms"]),
          ("ThinkPHP", "/?s=/index/\\think\\app/invokefunction", ["ThinkPHP"]),
          ("SeeyonOA", "/seeyon/index.jsp", ["seeyon", "致远"]),
          ("RuoYi", "/prod-api/captchaImage", ["captchaEnabled", "\"img\":"])],
    "F": [("Actuator-root", "/actuator", ["_links"]),
          ("Actuator-health", "/actuator/health", ['"status":"UP"']),
          ("Actuator-env", "/actuator/env", ["propertySources"]),
          ("Actuator-mappings", "/actuator/mappings", ["contexts"])],
    "H": [("git-config", "/.git/config", ["[core]", "repositoryformatversion"]),
          ("git-HEAD", "/.git/HEAD", ["ref:"])],
    "O": [("Kibana", "/app/kibana", ["kibana"]),
          ("Grafana", "/api/health", ["\"database\"", "\"version\""]),
          ("Zabbix", "/zabbix.php", ["zabbix"]),
          ("Jenkins-login", "/login", ["Jenkins"])],
    "P": [("api-docs-v2", "/v2/api-docs", ["swagger", "paths"]),
          ("api-docs-v3", "/v3/api-docs", ["openapi", "paths"]),
          ("knife4j", "/doc.html", ["knife4j"])],
    # 2026-09-23 加（新高危链第一跳，详见 skills/pt-engagement/references/attack-arsenal.md 武器 J ④）：
    # SSO/IAM「给登录页用的配置接口」常把**租户认证配置**匿名返回；更狠的一跳是把
    # **服务端登录脚本全文**（login_steps[].code_content，含内网集成端点/常量/内网 IP）也一起给。
    # 判据串只取该产品独有字段名（auth_method_code / idp_config_code / login_steps / code_content），
    # 避免打到普通接口造成假阳；要拿脚本那一跳需 appId，用 scripts/iam_config_probe.py 两跳深挖。
    "X": [("iam-auth-configs-t1", "/api/v1/idp/auth-configs?tenant_id=1&prefix=login",
           ["auth_method_code", "idp_config_code"]),
          ("iam-auth-configs-t2000", "/api/v1/idp/auth-configs?tenant_id=2000&prefix=login",
           ["auth_method_code", "idp_config_code"]),
          ("iam-auth-configs-t1000", "/api/v1/idp/auth-configs?tenant_id=1000&prefix=login",
           ["auth_method_code", "idp_config_code"]),
          ("iam-pubinfo", "/interactive/login/pub-info", ["login_steps", "auth_method_code"]),
           # 2026-09-26 加（idmesh 手册 §62 的**未测**面）：比 auth-configs（只枚举登录方式、
           # 得力线已实证「中危封顶、归档不投」）更有价值 —— idp/configs 可能回完整 IDP 配置。
           # 判据坚持用产品特有长串，避免重蹈「any 匹配 + 通用词」假阳。
           ("iam-idp-configs-t1", "/api/v1/idp/configs?tenant_id=1",
            ["clientSecret", "idpConfigCode", "ssoUrl"]),
           ("iam-idp-configs-t2000", "/api/v1/idp/configs?tenant_id=2000",
            ["clientSecret", "idpConfigCode", "ssoUrl"]),
           ("iam-login-steps", "/api/v1/applications/1/login-steps",
            ["loginSteps", "authMethodCode"])],
     # 2026-09-25 加：补 method-coverage-matrix 的「API 协议层」空白（只读 GET 可测）。
     # GraphQL introspection 与 Socket.IO 握手都能用 GET 发；POST-only 的 GraphQL 测不到（已知盲区）。
     # 判据串只取 GraphQL 特有词，避免打到普通 JSON 造成假阳。
     # R（2026-09-26 补，probe_ready: false -> true）：制品仓/私服「匿名可写」的**只读前置探测**。
     # 判据：Nexus anonymous 配置 / npm ping / PyPI simple / JFrog ping —— 全部 GET，不改任何数据。
     # 真正的 PUT 验证属闭环阶段：仅限声明「无限制」厂商 + 随机包名 + 立即 DELETE。
     # 2026-09-26 收紧：原判据 ["enabled"]/["{}"]/["<a href"]/["OK"] 是「任一子串命中」就判 hit
     # （probe_one 用 any），任何页面都会中 —— 实测 8 条假阳全出自这里。现改为**产品特有长串**。
     "R": [("Nexus-anon-config", "/service/rest/v1/security/anonymous",
            ["anonymousAccessEnabled", "NexusAuthorizingRealm"]),
           ("Nexus-anon-settings", "/service/rest/v1/security/anonymous/settings",
            ["anonymousAccessEnabled"]),
           ("Nexus-rest-status", "/service/rest/v1/status", ["Nexus Repository Manager"]),
           ("PyPI-simple", "/simple/", ["Simple Index", "PEP 503"]),
           ("JFrog-ping", "/artifactory/api/system/ping", ["Artifactory"]),
           ("JFrog-repos", "/artifactory/api/repositories", ["packageType", "repoKey"]),
           ("Maven-index", "/repository/maven-public/", ["Nexus Repository Manager"])],
     "U": [("graphql-get", "/graphql?query=%7B__typename%7D", ["__typename"]),
           ("graphql-schema", "/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D", ["queryType"]),
           ("graphql-v1", "/v1/graphql?query=%7B__typename%7D", ["__typename"]),
           ("graphql-api", "/api/graphql?query=%7B__typename%7D", ["__typename"]),
           ("graphql-gql", "/gql?query=%7B__typename%7D", ["__typename"]),
           ("socketio-eio4", "/socket.io/?EIO=4&transport=polling", ["\"sid\""]),
           ("socketio-eio3", "/socket.io/?EIO=3&transport=polling", ["\"sid\""])],
}


# ---- nuclei 探针包（2026-09-26）：从 state/nuclei-probes.json 动态加载 -------------------
# 来源：projectdiscovery/nuclei-templates 的 http 模板，经 scripts/nuclei_to_probes.py 严格过滤
# （只保留 GET + 单请求 + {{BaseURL}} 字面路径 + word matcher）=> 2458 条探针 / 393 个分类。
# 这里只挂 4 个常用包，每条包限 20 条以内，避免单主机请求量爆炸（20 探针 x 45 主机 = 900 请求）。
_NUCLEI_PROBES = Path(__file__).resolve().parents[1] / "state" / "nuclei-probes.json"
if _NUCLEI_PROBES.exists():
    try:
        _NPD = json.loads(_NUCLEI_PROBES.read_text("utf-8"))

        def _nuc(cat: str, limit: int) -> list:
            return [(r["id"], r["path"], r["expect"]) for r in (_NPD.get(cat) or [])[:limit]]

        PROBES["K1"] = _nuc("panel", 20)
        PROBES["K2"] = _nuc("exposure", 20)
        PROBES["K3"] = _nuc("misconfig", 20)
        PROBES["K4"] = _nuc("unauth", 13)
    except Exception:
        pass


# ---- 国产产品指纹包 CN1（2026-09-26）：来自 product-playbooks 的**实测指纹**，非猜测 ----
# 每条探针都能回溯到具体手册（state/cn-probes.json 的 source 字段）。
# 与 nuclei 包的区别：nuclei 以国外产品为主，CN1 打的是国内中小厂商/政企的真实部署面
# （若依 / YApi / 永中FcsCloud / Nexus / 百胜E3+ / WTS PLUS / IDMesh / FineCMS / 金蝶 / Actuator）。
_CN_PROBES = Path(__file__).resolve().parents[1] / "state" / "cn-probes.json"
if _CN_PROBES.exists():
    try:
        _CD = json.loads(_CN_PROBES.read_text("utf-8"))
        PROBES["CN1"] = [(r["name"], r["path"], r["expect"]) for r in (_CD.get("CN1") or [])]
    except Exception:
        pass


# ---- 判据收紧覆盖（2026-09-26）------------------------------------------------
# 起因：probe_one 是「任一子串命中」(any) ⇒ ["version"]/["name"]/["uri"] 这类通用词
# 会让任何页面都判 hit（实测 R 出 8 条、J 出 3 条假阳皆因此）。
# 下面把已审计出的过松判据就地换成**产品特有长串**。
# 审计：scripts/_audit_probes.py；批量入口发请求前自动告警（batch_recon._warn_loose_probes）。
_TIGHTEN_SIG = {
    "nexus-status": ["Nexus Repository Manager"],
    "actuator-gateway-routes": ["predicates", "gatewayFilters"],
    "kingdee-erp-sso": ["erp-sso", "landing"],
    "tolgee-api": ["tolgee", "translationProvider"],
    "mlflow-unauth": ["experiment_id", "run_id"],
    "easycvr-info-leak": ['"Password":', '"userName"'],
}
for _k in ("K1", "K2", "K3", "K4", "CN1"):
    _rows = PROBES.get(_k) or []
    if not _rows:
        continue
    PROBES[_k] = [
        (p[0], p[1], _TIGHTEN_SIG.get(p[0], p[2]))
        if isinstance(p, (list, tuple)) and len(p) >= 3 else p
        for p in _rows
    ]


def probe_one(host: str, path: str, expect: list, timeout: int = 8):
    """返回 (hit, status, sig)。

    ⚠ 2026-09-21 改：原来只返回 hit/None，**非 200 的响应被直接丢掉** ——
    于是"全部被 WAF 拦成 418"和"目标确实没有这个面"在结果上**完全一样**，都表现为「0 命中」。
    现在把状态码与响应指纹一并带回，交给 verdict 基线闸门判读
    （「仪器坏了却报出看似正常的结论」是今天栽过三次的同一个形状）。
    """
    import requests
    import urllib3
    urllib3.disable_warnings()
    last = (None, -1, "")
    for scheme in ("https", "http"):
        url = "%s://%s%s" % (scheme, host, path)
        try:
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=False,
                             headers=BROWSER_HEADERS)
        except Exception:
            continue
        # 2026-09-26 加：跟进**同主机**重定向（最多 3 跳）。
        # 为什么：本批 45 台里 301 占了 97 个探测（HTTP→HTTPS / CDN 跳转），
        # 原实现 allow_redirects=False + 只认 200 ⇒ 这些站点**全部判不了内容**，
        # 0 命中里有一大半是假阴性（真问题被工具吃掉）。
        # 跨主机一律不跟（合规：只碰授权域）。
        import urllib.parse as _up
        for _hop in range(3):
            if r.status_code not in (301, 302, 303, 307, 308):
                break
            _loc = r.headers.get("Location") or ""
            if not _loc:
                break
            _u2 = _up.urljoin(url, _loc)
            # 判据放宽到**同一注册域下的子域**（2026-09-26 实测：ab-inbev.cn -> www.ab-inbev.cn
            # 是极常见的跳转，按「严格同主机」会把它拒掉，等于没修）。
            _h2 = (_up.urlparse(_u2).hostname or "").lower()
            _h1 = (host or "").lower()
            if not (_h2 == _h1 or _h2.endswith("." + _h1) or _h1.endswith("." + _h2)):
                break
            try:
                r = requests.get(_u2, timeout=timeout, verify=False, allow_redirects=False,
                                 headers=BROWSER_HEADERS)
                url = _u2
            except Exception:
                break
        body = r.text[:300000]
        sig = " ".join(body.split())[:120]
        # ⚠ 首个有效响应为准：若写成 last = (...) 会被后一个 scheme 覆盖 ——
        # https 返 418 后循环继续试 http（可能返 301/400），闸门看到的就不是 418 了（实测栽过）。
        if last[1] == -1:
            last = (None, r.status_code, sig)
        if r.status_code != 200:
            continue
        # 假阳性防护（2026-09-19 实测教训）：403/登录页常以 HTTP 200 包装，其 HTML 属性
        # （如 description=""）会误命中判据 —— 差点让我去深挖一个不存在的 Jenkins。
        head = body[:2500].lower()
        if "<html" in head and any(n in head for n in NEG_MARKERS):
            return (None, r.status_code, sig)
        if not expect or any(e in body for e in expect):
            return ({"url": url, "status": r.status_code, "len": len(r.content),
                     "snippet": " ".join(body.split())[:220]}, r.status_code, sig)
        return (None, r.status_code, sig)
    return last


def cmd_scan(d: dict, a) -> int:
    wk = a.weapon.upper()
    engine = "path" if wk in PROBES else ("js" if wk in JS_KEYWORDS else None)
    if not engine:
        print("手法%s 还没有可批量引擎。" % wk)
        print("  path 引擎（直连固定路径）: %s" % ", ".join(sorted(PROBES)))
        print("  js   引擎（前端 JS 搜特征）: %s" % ", ".join(sorted(JS_KEYWORDS)))
        print("补一张路径表或关键词表即可 —— 每补一条, 242 家就多覆盖一个面。")
        return 2
    hosts = []
    for src in a.hosts:
        p = Path(src)
        if p.exists():
            hosts += [l.strip() for l in p.read_text("utf-8", "ignore").splitlines()
                      if l.strip() and not l.startswith("#")]
        else:
            hosts.append(src.strip())
    hosts = list(dict.fromkeys(host_of(h.lstrip("\ufeff")) for h in hosts if h.strip()))
    # ⚠️ 2026-09-21 加（**禾赛教训**）：FOFA/测绘产物里大量 sit/uat/test 主机是**内网系统，外部不可达**。
    # 不先筛就扫，会得到"0 命中"并误判「这家很干净」—— 实际是在扫一堆扫不到的主机。
    # 故 --apply 时先做**可达性采样**：活的才扫，死的单独列出来（并写进产物 JSON）。
    # 2026-09-23：批量的 --apply 收口到 scripts/batch_recon.py（纪律见技能 pentest-batch）。
    # 本命令有负控，但**没有范围预检、没有节流、没有请求预算** —— 拿它跑几十上百台，
    # 既可能打到无授权资产上，也可能把出口 IP 打进黑名单（禾赛/黑湖都已被限过）。
    # 闸门必须能自我解释：这里直说要改用什么，而不是默默拦下。
    if a.apply and not getattr(a, "unthrottled", False):
        print("  **止损**：批量第一跳请改走 scripts/batch_recon.py ——")
        print("           范围预检(GO 才施工) + 单主机 >=2s 节流 + 全局在飞 <=4 + 日请求预算，本命令三者皆无。")
        print("           改用: $py scripts/batch_recon.py --weapon %s --hosts-file <列表> --apply" % wk)
        print("           只做单点/排障、确要绕开时，显式加 --unthrottled。")
        return 3
    dead = []
    wildcard_phantom = []
    if a.apply and not getattr(a, "scan_dead", False):
        from concurrent.futures import ThreadPoolExecutor as _TPE
        import hashlib as _hl
        import random as _rnd
        import string as _str
        import urllib.error as _ue
        import urllib.request as _u

        def _sig_of(h):
            """(alive, sig)。sig 用于泛解析同构判定：scheme/code/server/正文摘要
            全同 => 同一个默认 vhost，不是独立资产。"""
            for sch in ("https", "http"):
                try:
                    rq = _u.Request("%s://%s/" % (sch, h), headers=BROWSER_HEADERS)
                    with _u.urlopen(rq, timeout=6, context=_ssl_ctx()) as rp:
                        b = rp.read(600)
                        return True, (sch, rp.status, rp.headers.get("Server") or "", _hl.md5(b).hexdigest()[:12])
                except _ue.HTTPError as e:
                    try:
                        b = e.read(600)
                    except Exception:
                        b = b""
                    return True, (sch, e.code, e.headers.get("Server") or "", _hl.md5(b).hexdigest()[:12])
                except Exception:
                    continue
            return False, None

        with _TPE(max_workers=max(8, a.threads)) as ex:
            probed = dict(zip(hosts, ex.map(_sig_of, hosts)))

        # 泛解析剔除（2026-09-21 华律教训）：测绘产物里混着大量泛解析噪声子域
        #（证书透明日志 + 字典生成的垃圾名，形如 free-cccam.<apex>）。它们齐刷刷
        # 解析到同一个默认 vhost、返回同一个错误页 => 被当"存活"，于是"54/56 可达"
        # 里 44 台是幻影，整轮扫描白做。先按 base_domain 分组打一个随机不存在名，
        # 取该 zone 的泛解析签名，再把与签名完全同构的主机剔为幻影（可审计）。
        zs = sorted({base_domain(h) for h, (ok, _s) in probed.items() if ok})
        rnd_hosts = ["%s.%s" % ("".join(_rnd.choice(_str.ascii_lowercase + _str.digits) for _ in range(14)), z)
                     for z in zs]
        wc_sig = {}
        with _TPE(max_workers=max(8, a.threads)) as ex:
            for z, (ok, sig) in zip(zs, ex.map(_sig_of, rnd_hosts)):
                if ok:
                    wc_sig[z] = sig
        for h, (ok, sig) in probed.items():
            if ok and h not in wc_sig and wc_sig.get(base_domain(h)) == sig:
                wildcard_phantom.append(h)
        ph = set(wildcard_phantom)
        dead = [h for h, (ok, _s) in probed.items() if not ok]
        hosts = [h for h, (ok, _s) in probed.items() if ok and h not in ph]
        print("  可达性采样: 真实可达 %d / 不可达 %d / 泛解析幻影剔除 %d（幻影不扫，避免 0 命中被误读）"
              % (len(hosts), len(dead), len(wildcard_phantom)))
        if wildcard_phantom:
            print("    泛解析 zone: %s" % ", ".join(sorted(wc_sig)[:5]))
            print("    幻影样例: %s" % ", ".join(wildcard_phantom[:5]))
        if dead:
            print("    不可达样例: %s" % ", ".join(dead[:5]))
    print("== 批量第一跳: 手法%s「%s」  引擎=%s ==" % (wk, d["weapons"][wk]["name"], engine))
    if engine == "path":
        print("  目标 %d x 探测 %d = %d 次只读 GET" % (len(hosts), len(PROBES[wk]), len(hosts) * len(PROBES[wk])))
    else:
        print("  目标 %d x 关键词 %d（拉首页 + 前 6 个 JS, 只读 GET）" % (len(hosts), len(JS_KEYWORDS[wk])))
    if not a.apply:
        for h in hosts[:10]:
            print("    would-probe %s" % h)
        print("\n(dry-run；确认目标全部在授权范围内后加 --apply)")
        return 0
    from concurrent.futures import ThreadPoolExecutor
    hits = []
    catchall = []         # 同主机 catch-all 假阳（2026-09-22 收钱吧教训）
    gate_rows = []        # (status, sig) —— 供 verdict 基线闸门判读「仪器是否可信」
    notes = []            # 第三方 CDN JS 等「不计入命中但要留痕」的记录（AGENTS §5 不许静默丢）
    # ==== 同主机 catch-all 对照（2026-09-22 收钱吧教训，P27 的批量化落地）====
    # 症状：SPA 站点对**任意路径**都返回同一个 HTML 壳（例：收钱吧 s.shouqianba.com
    # 对 /actuator/health、/actuator/mappings、瞎编路径全部返回同一个 18356 字节页）。
    # 于是 Nexus/SonarQube/Actuator 的固定路径被批量判成"200 命中"——实测 14 条命中**全是假阳**。
    # 判据：先取该主机瞎编路径的 (status, 字节数)，命中响应与之**完全相同**即判 catch-all。
    ctrl = {}
    if engine == "path":
        def _ctrl_of(h):
            """取该主机 catch-all 指纹。

            ⚠ 2026-09-22 修（fir.blacklake.cn 假阳）：**必须与 probe_one 用同一套协议选择逻辑**。
            probe_one 会跳过非 200 落到下一个 scheme；若这里只试到 https 的 403 就返回，
            指纹就是 (403,548)，而命中是 http 的 (200,56261) —— 对不上，假阳漏网。
            故这里也**优先取 200**，没有 200 才退回首个响应。
            """
            import hashlib as _h2
            import requests as _rq2
            import urllib3 as _u32
            _u32.disable_warnings()
            first = None
            for sch in ("https", "http"):
                try:
                    rr = _rq2.get("%s://%s/zz_nonexistent_arsenal_9k2" % (sch, h), timeout=8,
                                  verify=False, allow_redirects=False, headers=BROWSER_HEADERS)
                except Exception:
                    continue
                body = rr.text[:300000]
                sig = (rr.status_code, len(rr.content),
                       _h2.md5(" ".join(body.split())[:220].encode("utf-8", "ignore")).hexdigest()[:10])
                if rr.status_code == 200:
                    return sig
                if first is None:
                    first = sig
            return first
        with ThreadPoolExecutor(max_workers=a.threads) as ex:
            ctrl = dict(zip(hosts, ex.map(_ctrl_of, hosts)))
        n_cc = sum(1 for v in ctrl.values() if v)
        print("  负控采样: %d/%d 台取到 catch-all 指纹（命中与之同构即判假）" % (n_cc, len(hosts)))
    if engine == "path":
        jobs = [(h, name, path, exp) for h in hosts for name, path, exp in PROBES[wk]]
        with ThreadPoolExecutor(max_workers=a.threads) as ex:
            futs = {ex.submit(probe_one, h, p, e): (h, n) for h, n, p, e in jobs}
            for f, (h, n) in futs.items():
                try:
                    r, _st, _sig = f.result()
                except Exception:
                    r, _st, _sig = None, -1, ""
                gate_rows.append((_st, _sig))
                if r:
                    _c = ctrl.get(h)
                    if _c and _c[0] == r["status"] and _c[1] == r["len"]:
                        catchall.append({"host": h, "probe": n, **r})
                        continue
                    hits.append({"host": h, "probe": n, **r})
                    print("  [HIT] %-42s %-16s %s" % (h, n, r["url"]))
                    print("        %s" % r["snippet"][:150])
        total = len(jobs)
        if catchall:
            print("  [假阳] %d 条与同主机瞎编路径**字节数完全相同** => catch-all 兜底，不计命中" % len(catchall))
    else:
        kws = JS_KEYWORDS[wk]
        with ThreadPoolExecutor(max_workers=a.threads) as ex:
            futs = {ex.submit(js_probe, h, kws, 6, 8, EVIDENCE.get(wk)): h for h in hosts}
            for f, h in futs.items():
                try:
                    rs = f.result() or []
                except Exception:
                    rs = []
                for x in rs:
                    if x.get("note"):          # 3rd-party JS 只记数，不算命中
                        notes.append({"host": h, **x})
                        continue
                    hits.append({"host": h, **x})
                    print("  [HIT] %-40s %-16s %s" % (h, x.get("kw"), (x.get("src") or "")[:40]))
                    print("        %s" % (x.get("ctx") or "")[:150])
        total = len(hosts)
    if notes:
        print("\n⚠ 未计入命中 %d 条（第三方 CDN JS —— 公共库/企业邮箱客户端，不是目标自己的代码）" % len(notes))
        for n in notes[:5]:
            print("    - %-38s %s" % (n["host"], str(n.get("ctx"))[:70]))
    # ⚠ 2026-09-21 加：**0 命中不得直接下「目标干净」的结论** —— 先过基线闸门。
    # 「仪器坏了（被封 / 全站 418 / 全 catch-all）报出的 0 命中」和「真的没有」长得一模一样。
    gate_verdict, gate_why = "OK", []
    if not hits and gate_rows:
        try:
            import sys as _s
            _s.path.insert(0, str(ROOT / "scripts" / "kit"))
            from verdict import appraise
            gate_verdict, gate_why = appraise(gate_rows, label="扫描基线")
        except Exception as _e:
            gate_verdict, gate_why = "UNSURE", ["基线闸门不可用: %s" % _e]
    print("\n命中 %d / 目标 %d 台 / 探测 %d 次" % (len(hits), len(hosts), total))
    if gate_verdict == "UNSURE":
        for w in gate_why:
            print("  ⚠ 判读存疑: %s" % w)
        print("  ⇒ **0 命中不可作为『目标干净』的依据**（AGENTS §5：仪器存疑必须 UNSURE 上交）")
    out = ROOT / "results" / ("arsenal-scan-%s.json" % dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"weapon": wk, "engine": engine, "hits": hits,
                               "unreachable": dead,
                               "wildcard_phantom": wildcard_phantom,
                               "notes_third_party_js": notes},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    print("落盘: %s" % out)
    if hits:
        print("\n下一步: check --target <host> 看这家还能套哪些手法; 未被交过的按闭环走到底。")
    return 0


def cmd_log(d: dict, a) -> int:
    wk = a.weapon.upper()
    w = d["weapons"].get(wk)
    if not w:
        print("没有手法 %s" % wk)
        return 2
    # 2026-09-21 加：**判死要举证**（用户最早提的「遇到 WAF 就走了」的根因修法）。
    # 在此之前 `--verdict miss` 只要一个词就登记完事 —— 判死是**零成本**的，
    # 而 waf-bypass-techniques 里那条「至少尝试到 Level 4 才能下『无漏洞』结论」
    # 写了却**没有任何东西核验**（散文规则的战绩：当天 0 胜 3 负）。
    tried = (a.tried or "").strip()
    why = (a.why or "").strip()
    if a.verdict == "miss":
        lack = []
        if len(tried) < 6:
            lack.append("--tried（试过哪些）")
        if len(why) < 6:
            lack.append("--why（为什么打不通）")
        if lack:
            print("拒绝登记：**判死必须举证**，缺 %s。" % "、".join(lack))
            print("  例：--tried \"A/B/E/F/H/O/P/X 全跑 0 命中；手测 403 绕过头 3 种\"")
            print("      --why \"全站 nginx 统一 403，无应用层响应差异\"")
            print("  WAF 场景：--tried 必须写明试到 L 几（skills/waf-bypass-techniques 的 L1–L7），")
            print("           该技能规定**至少到 L4** 才允许下「无漏洞」结论。")
            return 2
        _lv = [int(x) for x in re.findall(r"[Ll](\d)", tried)]
        if _lv and max(_lv) < 4:
            print("拒绝登记：--tried 只到 L%d —— waf-bypass-techniques 规定**至少 L4** 才允许判死。"
                  % max(_lv))
            print("  还欠：L1 编码 / L2 变形 / L3 逻辑（换方法·换 Content-Type·换参数位置）/ L4 协议层。")
            return 2
    entry = {"t": a.target, "r": a.record or "-", "d": dt.date.today().isoformat(),
             "v": {"dup": "dup", "hit": "open", "miss": "miss"}.get(a.verdict, a.verdict),
             "note": a.note or ""}
    if tried:
        entry["tried"] = tried
    if why:
        entry["why"] = why
    w.setdefault("records", []).append(entry)
    save(d)
    print("已登记: 手法%s %s %s -> %s" % (wk, a.target, a.verdict, REG))
    if tried:
        print("  举证 tried: %s" % tried)
    if why:
        print("  举证 why  : %s" % why)
    return 0


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="武器库：手法x目标 登记/选路/批量")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("board")
    c1 = sub.add_parser("check")
    c1.add_argument("--target", default="")
    c1.add_argument("--weapon", default="")
    c4 = sub.add_parser("hunt")
    c4.add_argument("--limit", type=int, default=25)
    c4.add_argument("--filter", default="")
    c3 = sub.add_parser("scan")
    c3.add_argument("--weapon", required=True)
    c3.add_argument("--hosts", nargs="+", required=True)
    c3.add_argument("--apply", action="store_true")
    c3.add_argument("--scan-dead", action="store_true",
                    help="跳过可达性采样，连不可达主机也扫（默认会先采样并跳过，避免 0 命中被误读）")
    c3.add_argument("--threads", type=int, default=8)
    c3.add_argument("--unthrottled", action="store_true",
                    help="绕开 batch_recon 收口（无节流/无预算/无范围预检，只给单点排障用）")
    c2 = sub.add_parser("log")
    c2.add_argument("--weapon", required=True)
    c2.add_argument("--target", required=True)
    c2.add_argument("--verdict", required=True, choices=["dup", "hit", "miss"])
    c2.add_argument("--record", default="")
    c2.add_argument("--note", default="")
    c2.add_argument("--tried", default="",
                    help="【--verdict miss 必填】试过哪些：具体路径/手法/绕过级别。"
                         "WAF 场景要写明试到 L 几（见 waf-bypass-techniques 的 L1–L7）")
    c2.add_argument("--why", default="",
                    help="【--verdict miss 必填】为什么判定打不通（要具体到证据，不是感觉）")
    a = ap.parse_args()
    d = load()
    if a.cmd in ("board", "next"):
        return cmd_board(d)
    if a.cmd == "hunt":
        return cmd_hunt(d, a)
    if a.cmd == "scan":
        return cmd_scan(d, a)
    if a.cmd == "check":
        if a.target:
            return cmd_check_target(d, a.target)
        if a.weapon:
            return cmd_check_weapon(d, a.weapon)
        print("check 需要 --target 或 --weapon")
        return 2
    return cmd_log(d, a)


if __name__ == "__main__":
    sys.exit(main())
