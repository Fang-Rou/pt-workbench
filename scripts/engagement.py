#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""engagement.py — 项目作战档案：让多阶段攻击链**活过会话**。

为什么需要它（2026-09-22 立）：
  链子状态**只活在上下文里，会话一结束就没了**。实测症状：同一条链在同一场里数次
  重新找回；换新会话就彻底断线。业界（AIxVuln 的 exploitIdea → exploitChain）也是
  把碎片利用点汇聚成链，但**状态必须落盘**，否则模型换代 / 会话重启就归零。

改造（2026-10-01）：从「SRC 目标档案」升级为「渗透项目档案」。
  - 身份从 `--vendor/--platform/--project`（平台登记）改为 `--client + scope + ROE`（委托登记）
  - phase 从 recon→enum→exploit→evidence→submit 改为渗透 kill-chain：
      recon → enum → foothold → escalate → lateral → exfil → report → archived
  - 新增 `use`（切换 active 项目，scope_gate.py 读它）、`graph`（攻击图落盘）

设计：一个项目一个 JSON，落在 state/engagements/<slug>.json。
   - scope    : {"hosts": [...], "cidrs": [...]}  ← 委托书里的资产清单（登记用，非阻断）
   - roe      : [ "禁止DoS", "生产库只读", ... ]   ← 交战规则，写报告要引用
   - hops[]   : 逐跳流水（做了什么、得到什么、何时）—— 取代「靠记忆续接」
   - leads[]  : **碎片化利用点**（exploitIdea），带 status 与 blocked_by
   - graph    : {hosts[], edges[], creds[], c2[]} —— 攻击图（报告「路径复盘」的素材）
   - artifacts: 产物路径（原始证据不许只留在对话里）

用法：
  $py scripts/engagement.py list
  $py scripts/engagement.py use acme-20261001
  $py scripts/engagement.py show acme-20261001
  $py scripts/engagement.py new --client "某某科技有限公司" --domain example.com \\
        --scope-host example.com --scope-host "*.example.com" --scope-cidr 10.0.0.0/24 \\
        --window 2026-10-01..2026-10-15 --roe "禁止DoS" --roe "生产库只读"
  $py scripts/engagement.py hop acme-20261001 --action "js_unpack 15 台控制台" --result "8/15 暴露 API base"
  $py scripts/engagement.py lead acme-20261001 --id L1 --what "/AnnualReport/* 白名单漏配" --status open
  $py scripts/engagement.py phase acme-20261001 --set lateral --reason "已拿到第二跳立足点"
  $py scripts/engagement.py graph acme-20261001 --add-host "10.0.0.5" --role db --access root
  $py scripts/engagement.py graph acme-20261001 --add-edge 10.0.0.5 --from 10.0.0.1 --via smb --cred "svc-***"
  $py scripts/engagement.py graph acme-20261001 --c2 "https://cdn-x.example.net/beacon"
  $py scripts/engagement.py graph acme-20261001 --md
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIR = ROOT / "state" / "engagements"
ACTIVE = ROOT / "state" / "active-engagement.txt"

PHASES = ("recon", "enum", "foothold", "escalate", "lateral", "exfil", "report", "archived")
PHASE_HELP = {
    "recon": "被动测绘 / 子域 / 指纹（不碰目标）",
    "enum": "端口服务 / 接口枚举 / JS 抽密钥 / 登录面",
    "foothold": "首个可用立足点（RCE / 上传 / 有效凭据 / 越权读数据）",
    "escalate": "本地提权（内核 / SUID / 服务 / 令牌 / 配置）",
    "lateral": "横向：凭据复用 / 隧道 / SMB-WMI-WinRM / 域内路径",
    "exfil": "数据与影响面确认（只取样本，不拖库）",
    "report": "报告 + 复现附录 + 整改清单（过 report_gate）",
    "archived": "复盘沉淀 / 环境回收完毕",
}
LEAD_STATUS = ("open", "blocked", "dead", "confirmed", "delivered")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _p(slug: str) -> Path:
    return DIR / (("%s.json" % slug) if not slug.endswith(".json") else slug)


def active_slug() -> str:
    try:
        return ACTIVE.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def load(slug: str) -> dict:
    f = _p(slug)
    if not f.exists():
        print("UNSURE: 没有这个项目档案: %s（用 list 看现有）" % slug)
        sys.exit(2)
    return json.loads(f.read_text(encoding="utf-8"))


def save(d: dict) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    d["updated"] = _now()
    _p(d["slug"]).write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def _scope_list(d: dict) -> list:
    sc = d.get("scope") or {}
    out = []
    for k in ("hosts", "domains", "cidrs"):
        v = sc.get(k) or []
        if isinstance(v, str):
            v = [v]
        out += [str(x) for x in v]
    return out


def cmd_list(a) -> int:
    if not DIR.exists():
        print("（还没有项目档案）")
        return 0
    rows = []
    for f in sorted(DIR.glob("*.json")):
        try:
            rows.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    if a.json:
        print(json.dumps(rows, ensure_ascii=False, indent=1))
        return 0
    cur = active_slug()
    print("%-1s %-24s %-9s %-10s %-6s %-7s %s" % ("", "slug", "phase", "client", "hops", "leads", "next"))
    print("-" * 122)
    for r in rows:
        leads = r.get("leads") or []
        openl = sum(1 for x in leads if x.get("status") in ("open", "blocked"))
        mark = "*" if r.get("slug") == cur else " "
        print("%-1s %-24s %-9s %-10s %-6d %-7s %s" % (
            mark, str(r.get("slug", "?"))[:24], r.get("phase", "-"),
            str(r.get("client") or r.get("vendor") or "-")[:10],
            len(r.get("hops") or []), "%d/%d" % (openl, len(leads)),
            str(r.get("next") or "-")[:42]))
    print("")
    print("共 %d 个项目（* = active，scope_gate.py 按它判定）-> %s" % (len(rows), DIR))
    return 0


def cmd_use(a) -> int:
    d = load(a.slug)
    ACTIVE.parent.mkdir(parents=True, exist_ok=True)
    ACTIVE.write_text(d["slug"], encoding="utf-8")
    print("active 项目 = %s（%s / phase=%s）" % (d["slug"], d.get("client") or "-", d.get("phase")))
    return 0


def cmd_show(a) -> int:
    d = load(a.slug or active_slug())
    print("=" * 78)
    print("%s   [%s]   %s" % (d.get("slug"), d.get("phase"),
                              "**ACTIVE**" if d.get("slug") == active_slug() else ""))
    print("客户  : %s" % (d.get("client") or d.get("vendor") or "-"))
    print("授权  : %s%s" % (d.get("auth_basis") or "**未登记**（用 engagement.py auth <slug> --basis 补）",
                          ("（%s）" % d["auth_ref"]) if d.get("auth_ref") else ""))
    print("窗口  : %s" % (d.get("window") or "-"))
    print("域名  : %s" % ", ".join(d.get("domains") or []))
    sc = d.get("scope") or {}
    if sc:
        print("范围  : hosts=%d cidrs=%d  strict_scope=%s" % (
            len(sc.get("hosts") or []), len(sc.get("cidrs") or []), bool(d.get("strict_scope"))))
        for h in (sc.get("hosts") or [])[:12]:
            print("         - %s" % h)
        for c in (sc.get("cidrs") or [])[:8]:
            print("         - %s" % c)
    if d.get("roe"):
        print("交战规则:")
        for r in d["roe"]:
            print("         - %s" % r)
    print("")
    print("--- 逐跳（%d）---" % len(d.get("hops") or []))
    for h in (d.get("hops") or []):
        print("  #%-3s %-22s %s" % (h.get("n"), str(h.get("ts"))[5:16], str(h.get("action"))[:60]))
        if h.get("result"):
            print("        -> %s" % str(h["result"])[:100])
    leads = d.get("leads") or []
    print("")
    print("--- 碎片化利用点（%d）---" % len(leads))
    for l in leads:
        mark = {"open": "[ ]", "blocked": "[!]", "dead": "[x]",
                "confirmed": "[+]", "delivered": "[$]"}.get(l.get("status"), "[?]")
        print("  %s %-6s %-44s %s" % (mark, l.get("id"), str(l.get("what"))[:44],
                                      ("卡在: " + str(l.get("blocked_by"))) if l.get("blocked_by") else ""))
        if l.get("evidence"):
            print("        证据: %s" % str(l["evidence"])[:90])
    g = d.get("graph") or {}
    if g:
        print("")
        print("--- 攻击图 ---")
        print("  主机 %d / 边 %d / 凭据 %d / C2 %d" % (len(g.get("hosts") or []), len(g.get("edges") or []),
                                                    len(g.get("creds") or []), len(g.get("c2") or [])))
        print("  渲染: $py scripts/engagement.py graph %s --md" % d["slug"])
    ch = d.get("chain") or {}
    print("")
    print("--- 当前链 ---")
    print("  正在推 : %s" % ch.get("current", "-"))
    print("  已组装 : %s" % (", ".join(ch.get("assembled") or []) or "-"))
    print("")
    print("下一步 : %s" % (d.get("next") or "-"))
    arts = d.get("artifacts") or []
    if arts:
        print("产物   : %s" % ", ".join(str(x)[:40] for x in arts[:5]))
    return 0


def cmd_new(a) -> int:
    dom = a.domain or ""
    if a.slug:
        slug = a.slug
    elif dom:
        slug = dom.split(".")[0].replace("-", "") + "-" + datetime.now().strftime("%Y%m%d")
    else:
        base = "".join(ch for ch in (a.client or "pt") if ch.isalnum())[:12].lower() or "pt"
        slug = base + "-" + datetime.now().strftime("%Y%m%d")
    f = _p(slug)
    if f.exists() and not a.force:
        print("已存在: %s（要覆盖加 --force）" % f)
        return 1
    scope_extra = getattr(a, "scope_extra", None) or {}
    d = {
        "slug": slug, "created": _now(), "phase": a.phase,
        "client": a.client or a.vendor or "",
        "auth_basis": a.auth_basis or "",
        "auth_ref": a.auth_ref or "",
        "window": a.window or "",
        "domains": [dom] if dom else [],
        "scope": {"hosts": list(a.scope_host or []), "cidrs": list(a.scope_cidr or [])},
        "strict_scope": bool(a.strict_scope),
        "roe": list(a.roe or []),
        "hops": [], "leads": [], "chain": {"current": "", "assembled": []},
        "graph": {"hosts": [], "edges": [], "creds": [], "c2": []},
        "artifacts": [], "next": a.next or "recon_api.py all <域名> 拿资产 -> 定范围 -> 动手",
    }
    for k, v in scope_extra.items():
        d[k] = v
    if a.vendor and not a.client:
        d["legacy_vendor"] = a.vendor
    save(d)
    print("已建项目档案: %s -> %s" % (slug, f))
    print("  切为 active: $py scripts/engagement.py use %s" % slug)
    if not d.get("auth_basis"):
        print("  ⚠ 未登记授权依据（--auth-basis）：报告「测试范围」章节没有出处。")
        print("     四种合法形态: " + " / ".join(AUTH_FORMS))
    if not d["scope"]["hosts"] and not d["scope"]["cidrs"]:
        print("  ⚠ scope 为空：scope_gate.py 只会把所有目标标 UNLISTED（不阻断，但报告「范围」章节没依据）")
    return 0


AUTH_FORMS = (
    "委托合同",       # 客户委托 / 授权书 / 测试协议 —— 最常见
    "平台项目声明",   # SRC / 众测平台项目页声明的资产范围（原 SRC 线的替代承载方式）
    "自有资产",       # 你是所有者：自有 VPS / 域名 / 云账号（练手最优解）
    "靶场或比赛",     # 靶场说明 / CTF 规则 / 开源项目安全政策
)


def cmd_auth(a) -> int:
    """登记/更新授权依据。为什么单列一条：改造后平台层没了，
    「这活凭什么能干」必须有地方写下来，否则报告「测试范围」章节没有出处。"""
    d = load(a.slug or active_slug())
    if a.basis is not None:
        d["auth_basis"] = a.basis
    if a.ref:
        d["auth_ref"] = a.ref
    save(d)
    print("%s 授权依据: %s" % (d["slug"], d.get("auth_basis") or "(空)"))
    if d.get("auth_ref"):
        print("  凭证/出处: %s" % d["auth_ref"])
    if not d.get("auth_basis"):
        print("  ⚠ 空授权依据 = 这份报告不能在报告闸门里通过「范围一致性」以外的审阅口径")
    return 0


def cmd_hop(a) -> int:
    d = load(a.slug)
    hops = d.setdefault("hops", [])
    hops.append({"n": len(hops) + 1, "ts": _now(), "action": a.action, "result": a.result or ""})
    if a.artifact:
        arts = d.setdefault("artifacts", [])
        if a.artifact not in arts:
            arts.append(a.artifact)
    save(d)
    print("第 %d 跳已记: %s" % (len(hops), a.action[:60]))
    return 0


def cmd_lead(a) -> int:
    d = load(a.slug)
    leads = d.setdefault("leads", [])
    got = None
    for l in leads:
        if l.get("id") == a.id:
            got = l
            break
    if got is None:
        got = {"id": a.id, "created": _now()}
        leads.append(got)
    if a.what:
        got["what"] = a.what
    if a.status:
        if a.status not in LEAD_STATUS:
            print("UNSURE: status 只能是 %s" % (LEAD_STATUS,))
            return 2
        got["status"] = a.status
    if a.blocked_by is not None:
        got["blocked_by"] = a.blocked_by
    if a.evidence:
        got["evidence"] = a.evidence
    if a.what and not got.get("status"):
        got["status"] = "open"
    save(d)
    print("利用点 %s: %s [%s]" % (a.id, str(got.get("what"))[:60], got.get("status")))
    return 0


def cmd_phase(a) -> int:
    d = load(a.slug)
    if a.set not in PHASES:
        print("UNSURE: phase 只能是 %s" % (PHASES,))
        print("  说明: " + " | ".join("%s=%s" % (k, v) for k, v in PHASE_HELP.items()))
        return 2
    old = d.get("phase")
    d["phase"] = a.set
    d.setdefault("phase_log", []).append({"ts": _now(), "from": old, "to": a.set,
                                          "reason": a.reason or ""})
    save(d)
    print("%s: phase %s -> %s" % (a.slug, old, a.set))
    if a.reason:
        print("  理由: %s" % a.reason)
    nxt = list(PHASES)
    try:
        print("  下一步提示: %s" % PHASE_HELP[nxt[nxt.index(a.set) + 1]])
    except Exception:
        pass
    return 0


def cmd_next(a) -> int:
    d = load(a.slug)
    txt = a.text
    if a.file:
        txt = Path(a.file).read_text(encoding="utf-8").strip()
    d["next"] = txt
    if a.current is not None:
        d.setdefault("chain", {})["current"] = a.current
    save(d)
    print("%s 下一步已记: %s" % (a.slug, str(txt)[:70]))
    return 0


def _graph(d: dict) -> dict:
    g = d.setdefault("graph", {})
    for k in ("hosts", "edges", "creds", "c2"):
        g.setdefault(k, [])
    return g


def cmd_graph(a) -> int:
    d = load(a.slug or active_slug())
    g = _graph(d)
    touched = False

    if a.add_host:
        for h in a.add_host:
            ent = {"host": h, "role": a.role or "", "access": a.access or "", "ts": _now()}
            old = next((x for x in g["hosts"] if x.get("host") == h), None)
            if old:
                if a.role:
                    old["role"] = a.role
                if a.access:
                    old["access"] = a.access
            else:
                g["hosts"].append(ent)
            touched = True

    if a.add_edge:
        if not a.frm:
            print("UNSURE: --add-edge 必须配 --from（来源主机）")
            return 2
        g["edges"].append({"from": a.frm, "to": a.add_edge, "via": a.via or "",
                           "cred": a.cred or "", "ts": _now()})
        touched = True

    if a.add_cred:
        g["creds"].append({"label": a.add_cred, "kind": a.kind or "", "ts": _now()})
        touched = True

    if a.c2:
        if a.c2 not in g["c2"]:
            g["c2"].append(a.c2)
        touched = True

    if touched:
        save(d)

    g = _graph(d)
    print("== 攻击图: %s ==" % d["slug"])
    print("主机（%d）:" % len(g["hosts"]))
    for h in g["hosts"]:
        print("   - %-22s %-10s %s" % (h.get("host"), h.get("role", ""), h.get("access", "")))
    print("边（%d）:" % len(g["edges"]))
    for e in g["edges"]:
        print("   %s -> %s   via=%s  cred=%s" % (e.get("from"), e.get("to"), e.get("via", ""), e.get("cred", "")))
    if g["creds"]:
        print("凭据（%d，脱敏登记）:" % len(g["creds"]))
        for c in g["creds"]:
            print("   - %s %s" % (c.get("label"), c.get("kind", "")))
    if g["c2"]:
        print("C2 / 回连（%d，收尾要按这些清理）:" % len(g["c2"]))
        for c in g["c2"]:
            print("   - %s" % c)

    if a.md:
        out = ROOT / "results" / ("attack-graph-%s.md" % d["slug"])
        out.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# 攻击路径图 — %s" % (d.get("client") or d["slug"]), "",
                 "项目: `%s`   窗口: %s   生成: %s" % (d["slug"], d.get("window") or "-", _now()), "",
                 "## 主机", "", "| 主机 | 角色 | 权限 |", "| --- | --- | --- |"]
        for h in g["hosts"]:
            lines.append("| %s | %s | %s |" % (h.get("host"), h.get("role", ""), h.get("access", "")))
        lines += ["", "## 攻击路径（边）", "", "```text"]
        for e in g["edges"]:
            lines.append("%s  ->  %s   [via=%s%s]" % (
                e.get("from"), e.get("to"), e.get("via", ""),
                (", cred=%s" % e.get("cred")) if e.get("cred") else ""))
        lines += ["```", "", "## 凭据来源（脱敏）", ""]
        for c in g["creds"]:
            lines.append("- %s（%s）" % (c.get("label"), c.get("kind", "")))
        if g["c2"]:
            lines += ["", "## 演练遗留通道（收尾按此清理）", ""]
            for c in g["c2"]:
                lines.append("- %s" % c)
        lines += ["", "## 逐跳时间线", ""]
        for h in (d.get("hops") or []):
            lines.append("%d. `%s` %s -> %s" % (h.get("n"), str(h.get("ts"))[:16], h.get("action"), h.get("result") or ""))
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("")
        print("已渲染: %s" % out)
    return 0


def cmd_summary(a) -> int:
    """给 next.py / 会话续接用：只打印「还活着的」项目。"""
    if not DIR.exists():
        return 0
    live = []
    for f in sorted(DIR.glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if d.get("phase") in ("archived",):
            continue
        live.append(d)
    if not live:
        return 0
    cur = active_slug()
    print("== 项目档案（活着的）==")
    for d in live:
        opens = [l for l in (d.get("leads") or []) if l.get("status") in ("open", "blocked")]
        tag = " *active*" if d.get("slug") == cur else ""
        print("  [%s] %-22s 未结利用点 %d  下一步: %s%s" % (
            d.get("phase"), d.get("slug"), len(opens), str(d.get("next") or "-")[:48], tag))
        for l in opens[:3]:
            print("      - %s %s %s" % (l.get("id"), str(l.get("what"))[:44],
                                        ("(卡在:%s)" % l.get("blocked_by")) if l.get("blocked_by") else ""))
    return 0


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="项目作战档案（多阶段链子跨会话续跑）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list", help="列全部项目（* = active）")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_list)

    s = sub.add_parser("use", help="把某个项目设为 active（scope_gate.py 按它判定）")
    s.add_argument("slug")
    s.set_defaults(fn=cmd_use)

    s = sub.add_parser("show", help="看项目全貌（不给 slug 看 active）")
    s.add_argument("slug", nargs="?")
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("summary", help="只列活着的项目（next.py 用）")
    s.set_defaults(fn=cmd_summary)

    s = sub.add_parser("new", help="建项目档案")
    s.add_argument("--slug")
    s.add_argument("--client", default="", help="客户/委托方全称")
    s.add_argument("--vendor", default="", help="（兼容旧写法）等同 --client")
    s.add_argument("--domain", default="", help="主域名（用于生成 slug）")
    s.add_argument("--scope-host", dest="scope_host", action="append", default=[],
                   help="委托范围里的主机/域名，可重复；支持 *.example.com")
    s.add_argument("--scope-cidr", dest="scope_cidr", action="append", default=[],
                   help="委托范围里的网段，可重复；如 10.0.0.0/24")
    s.add_argument("--window", default="", help="测试窗口，如 2026-10-01..2026-10-15")
    s.add_argument("--roe", action="append", default=[], help="交战规则一条一次，可重复")
    s.add_argument("--auth-basis", dest="auth_basis", default="",
                   help="授权依据：" + " / ".join(AUTH_FORMS) + "  （无授权依据就不要建项目）")
    s.add_argument("--auth-ref", dest="auth_ref", default="",
                   help="凭证/出处：合同编号 / 平台项目页 URL / 靶场说明链接")
    s.add_argument("--strict-scope", dest="strict_scope", action="store_true",
                   help="打开范围硬拦（默认关：scope_gate 只标注不阻断）")
    s.add_argument("--phase", default="recon")
    s.add_argument("--next", default="")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_new)

    s = sub.add_parser("auth", help="登记/更新授权依据（合同编号 / 平台项目页 / 自有资产 / 靶场）")
    s.add_argument("slug", nargs="?")
    s.add_argument("--basis", default=None, help="授权依据：" + " / ".join(AUTH_FORMS))
    s.add_argument("--ref", default=None, help="凭证/出处：合同编号 / 项目页 URL / 靶场链接")
    s.set_defaults(fn=cmd_auth)

    s = sub.add_parser("hop", help="记一跳（做了什么 -> 得到什么）")
    s.add_argument("slug")
    s.add_argument("--action", required=True)
    s.add_argument("--result", default="")
    s.add_argument("--artifact", default="")
    s.set_defaults(fn=cmd_hop)

    s = sub.add_parser("lead", help="记一个碎片化利用点")
    s.add_argument("slug")
    s.add_argument("--id", required=True)
    s.add_argument("--what", default="")
    s.add_argument("--status", default="")
    s.add_argument("--blocked-by", dest="blocked_by", default=None)
    s.add_argument("--evidence", default="")
    s.set_defaults(fn=cmd_lead)

    s = sub.add_parser("phase", help="推进 kill-chain 阶段")
    s.add_argument("slug")
    s.add_argument("--set", required=True, choices=PHASES)
    s.add_argument("--reason", default="")
    s.set_defaults(fn=cmd_phase)

    s = sub.add_parser("next", help="写下一步动作")
    s.add_argument("slug")
    s.add_argument("--text", default="")
    s.add_argument("--file", default="")
    s.add_argument("--current", default=None)
    s.set_defaults(fn=cmd_next)

    s = sub.add_parser("graph", help="攻击图：登记主机/边/凭据/C2，可渲染 md")
    s.add_argument("slug", nargs="?")
    s.add_argument("--add-host", dest="add_host", action="append", default=[])
    s.add_argument("--role", default="")
    s.add_argument("--access", default="")
    s.add_argument("--add-edge", dest="add_edge", default="", help="目标主机")
    s.add_argument("--from", dest="frm", default="", help="来源主机")
    s.add_argument("--via", default="", help="协议/手法，如 smb / winrm / ssh -D")
    s.add_argument("--cred", default="", help="用的凭据（**脱敏**写法：svc-***）")
    s.add_argument("--add-cred", dest="add_cred", default="")
    s.add_argument("--kind", default="", help="凭据类型：plaintext / nthash / ticket / key")
    s.add_argument("--c2", default="", help="演练遗留回连地址（收尾按此清理）")
    s.add_argument("--md", action="store_true", help="渲染攻击图到 results/attack-graph-<slug>.md")
    s.set_defaults(fn=cmd_graph)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
