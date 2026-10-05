#!/usr/bin/env python3
"""Print the compact next-action list for a fresh Codex thread."""

from __future__ import annotations

import json
import re
import sys

import workspace_db

# AGENTS.md §2（用户明示）：同时在审上限 5 条 —— 占满就交不进新发现。
REVIEW_SLOTS = 5


def _age_days(ts) -> float | None:
    """ISO 时间戳 → 距今多少天（解析不了返回 None）。"""
    from datetime import datetime

    try:
        t = datetime.fromisoformat(str(ts))
    except Exception:
        return None
    if t.tzinfo is not None:
        t = t.astimezone().replace(tzinfo=None)
    return max(0.0, (datetime.now() - t).total_seconds() / 86400.0)


def _ago(ts) -> str:
    d = _age_days(ts)
    if d is None:
        return "?"
    return ("%.1f 天前" % d) if d < 10 else ("%d 天前" % d)


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    conn = workspace_db.connect()

    print("# NEXT")
    print("")

    # 2026-09-23 加：两个稀缺资源此前只活在 resume.md 的手写句子里（「还剩 1 槽」）—— 手写的会漂。
    #   · 审核槽位（AGENTS.md §2：同时在审上限 5 条）
    #   · 今日批次预算（batch_recon 的日 3000 请求）
    # 旁证：scripts/archive/_status_board.py 早就专门做过「槽位占用」看板，归档后无人调用 ⇒ 开场看不见。
    # 只放一行：明细在下面的「在审待回访 / 未关闭漏洞」块里，不重复。
    _bits: list[str] = []
    try:
        import sqlite3 as _sq_dash
        _cx_dash = _sq_dash.connect(workspace_db.ROOT / "state" / "workspace.db")
        # 2026-10-01 改造：不再有「审核槽位」概念（平台层已移除），
        # 改成报「在跑的项目数」——那才是渗透测试线真正稀缺的东西。
        _slots_used = _cx_dash.execute(
            "select count(*) from projects where status = 'active'"
        ).fetchone()[0]
        _cx_dash.close()
        _bits.append("在跑项目 %d 个（engagement.py list 看明细，* = active）" % _slots_used)
    except Exception as exc:
        _bits.append("项目数读取失败(%s)" % str(exc)[:30])
    try:
        _b = json.loads((workspace_db.STATE_DIR / "recon-budget.json").read_text("utf-8", "ignore"))
        if isinstance(_b.get("used"), int) and isinstance(_b.get("cap"), int):
            # 2026-10-01 改造：不再按平台分账（补天/漏洞盒子已移除），只报总额度。
            _bits.append("今日批量预算 %d/%d" % (_b["used"], _b["cap"]))
    except Exception:
        pass
    print("- 稀缺资源: " + " · ".join(_bits))
    print("")
    # 2026-09-27 自动注入外置工作记忆：上次做到哪、试过什么、还欠什么（不靠回忆）。
    try:
        _mems = sorted(workspace_db.STATE_DIR.glob("memory-*.json"), key=lambda p: -p.stat().st_mtime)[:3]
        if _mems:
            print("## 工作记忆（最近 %d 个目标）" % len(_mems))
            for _p in _mems:
                _d = json.loads(_p.read_text("utf-8", "ignore"))
                _a = _d.get("assets") or []
                _reach = len([x for x in _a if x.get("status") == "reachable"])
                _w = {}
                for _t in (_d.get("tried") or []):
                    _w[_t.get("weapon")] = _w.get(_t.get("weapon"), 0) + 1
                _line = "  - %s：资产 %d（可达 %d）｜已试 %s｜线索 %d｜已否决 %d"
                print(_line % (_p.stem.replace("memory-", ""), len(_a), _reach,
                               ",".join(sorted(_w)) or "-", len(_d.get("leads") or []),
                               len(_d.get("rejected") or [])))
            print("    详情: memory.py brief <slug>")
            print("")
    except Exception:
        pass

    resume_path = workspace_db.STATE_DIR / "resume.md"
    if resume_path.exists():
        print("## RESUME")
        print(f"- 检测到 state/resume.md，先执行: {sys.executable} scripts/resume.py")
        # 2026-09-23 加：AGENTS.md §1.4 说「续接只跑 next.py」—— 那就不能只丢一个指针。
        # 实测 resume.md 的 next_action 是一整篇（本轮 3534 字），几条待决策全在里面；
        # 只打印一行指针 ⇒ 谁跳过 resume.py，整篇就丢了（决策丢失 = 白跑一轮）。
        try:
            _rtext = resume_path.read_text("utf-8", "ignore")
            for _line in _rtext.splitlines():
                if _line.startswith("- next_action:"):
                    _one = re.sub(r"\s*\|\s*", " / ", _line.split(":", 1)[1].strip())
                    print(f"- next_action 摘要: {_one[:240]}{'…' if len(_one) > 240 else ''}")
                    break
            if "待用户决策" in _rtext:
                print("- ⚠ resume.md 里有「待用户决策」小节 —— 先让用户拍板，不要自己替他定")
        except Exception as exc:
            print(f"- (resume.md 摘要读取失败: {str(exc)[:60]})")
        print("")

    active = [p for p in workspace_db.list_projects(conn) if p["status"] == "active"]
    if active:
        # 2026-09-23：原来最多 24 行、一个日期都没有 —— 分不出哪家是这两周在打的，纯噪音。
        # 现在带「最后活动」并截断到 10 家，其余折一行。
        print("## 活跃项目（按最后活动排序）")
        for p in active[:10]:
            print(f"- {_ago(p['updated_at'])} · {p['name']} ({p['slug']})")
        if len(active) > 10:
            print(f"- …另 {len(active) - 10} 家活跃（共 {len(active)} 家；全量查 workspace.db 的 projects 表）")
        print("")

    tasks = workspace_db.list_tasks(conn, limit=30)
    open_tasks = [
        t for t in tasks if t["status"] in ("pending", "running")
    ][:10]
    if open_tasks:
        print("## 待办/进行中")
        for t in open_tasks:
            print(
                f"- [{t['status']}] {t['kind']} {t['title'] or ''} "
                f"`{t['target_slug']}` {t['output_path'] or ''}"
            )
        print("")

    findings = workspace_db.list_findings(conn, limit=100)
    open_findings = [
        f for f in findings if f["status"].lower() in ("open", "validating")
    ]
    # 2026-09-23 加：这些命中里哪些「从未提交过」—— 它决定要不要占审核槽位（AGENTS.md §2）。
    try:
        import sqlite3 as _sq_f
        _cx_f = _sq_f.connect(workspace_db.ROOT / "state" / "workspace.db")
        _has_sub = {r[0] for r in _cx_f.execute("select distinct finding_id from submissions")}
        _cx_f.close()
    except Exception:
        _has_sub = set()
    ranked = sorted(
        open_findings,
        key=lambda f: {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }.get(f["severity"], 5),
    )[:10]
    if ranked:
        print("## 未关闭漏洞（按等级；⚑未提交 = 台账里没有任何提交记录）")
        for f in ranked:
            tag = "" if f["id"] in _has_sub else " ⚑未提交"
            print(
                f"- [{f['severity']}] {f['title']} ({f['status']}){tag} "
                f"`{f['target_slug']}` {f['poc_path'] or ''}"
            )
        print("")

    playbook_dir = workspace_db.ROOT / "skills" / "product-playbooks" / "references"
    if playbook_dir.exists():
        pb_rows = []
        for pb in sorted(playbook_dir.glob("*.md")):
            try:
                head = pb.read_text("utf-8").splitlines()[:12]
            except Exception:
                continue
            title = pb.stem
            status = "?"
            for line in head:
                if line.startswith("# ") and title == pb.stem:
                    title = line[2:].strip()
                if "验证状态" in line:
                    status = line.split("：", 1)[-1]
                    m = re.search(r"\*\*(.+?)\*\*", status)
                    if m:
                        status = m.group(1)
                    else:
                        status = status.split("。")[0]
                    status = status.strip()
                    break
            rel = pb.relative_to(workspace_db.ROOT)
            pb_rows.append(f"- {title} [{status}] → `{rel}`")
        if pb_rows:
            print("## 产品攻击手册（指纹命中先读；实战结束回写 delta）")
            for r in pb_rows:
                print(r)
            print("")

    # 2026-09-15 加（审计发现"在审回访"没人做：IMOU 有一条在审被误判成"封盘"）：
    # 开场就把在审清单摆出来——这是替代"会话开始钩子"的最省事做法。
    try:
        import sqlite3
        dbf = workspace_db.ROOT / "state" / "workspace.db"
        con = sqlite3.connect(dbf)
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            select s.submission_id, s.submitted_at, p.platform, p.slug, f.title
            from submissions s left join findings f on f.id = s.finding_id
            left join targets t on t.id = f.target_id left join projects p on p.id = t.project_id
            where s.status = 'submitted' order by s.submitted_at""").fetchall()
        if rows:
            print("## 在审待回访（提交后平台状态会变，别让台账漂移）")
            for r in rows:
                _ag = _ago(r["submitted_at"])
                print("- %s [%s] %s（%s%s）" % (
                    r["submission_id"], r["platform"] or "?", (r["title"] or "")[:40],
                    (r["submitted_at"] or "")[:10],
                    ("，已交 %s" % _ag) if _ag != "?" else ""))
            # 2026-09-23 加：revisit_check 只在状态「变了」时写库 ⇒「查过但没变」零痕迹，
            # 开场分不清「昨天刚回访过」和「从没回访」⇒ 台账漂移没人负责。
            # 现在它每次跑都落 state/revisit-last.json，这里读它。
            _mk = workspace_db.STATE_DIR / "revisit-last.json"
            if not _mk.exists():
                print("- ⚠ 从无回访记录（state/revisit-last.json 不存在）⇒ 先跑一次 revisit_check.py")
            else:
                try:
                    _mj = json.loads(_mk.read_text("utf-8", "ignore"))
                    _h = _age_days(_mj.get("ts"))
                    _hrs = "?" if _h is None else (("%.1f 小时前" % (_h * 24)) if _h < 1 else ("%.1f 天前" % _h))
                    _warn = " ⚠ 超 48h，该回访了" if (_h is not None and _h > 2) else ""
                    _dryw = " ⚠ 那次是 dry-run 且有 %s 条变更没写回库" % _mj.get("changed") if (_mj.get("dry") and _mj.get("changed")) else ""
                    print("- 上次回访: %s（查 %s 条，写回 %s 条%s）%s%s" % (
                        _hrs, _mj.get("checked", "?"), _mj.get("changed", "?"),
                        "，dry-run" if _mj.get("dry") else "", _warn, _dryw))
                except Exception as exc:
                    print("- (revisit-last.json 读不出来: %s)" % str(exc)[:60])
            print("- 回访命令: python scripts/revisit_check.py（--dry-run 只看不写库）")
            print("")
    except Exception as exc:
        print("## 在审待回访（读取失败: %s）\n" % str(exc)[:60])

    # 2026-09-22 加（用户拍板）：**作战档案** —— 多阶段链子的状态必须活过会话。
    # 实测教训：青矩/kkidc 那些链子此前只活在模型的上下文里，换会话就归零；
    # 这正是《A Survey of LLM-Driven Penetration Testing: Taxonomy》点名的头号开放难题
    #   「limited performance on multi-stage attack scenarios」。
    # 开场就摆出来 —— 与「在审待回访」同理：这是唯一能保证它被看到的时机。
    try:
        import subprocess as _sp2
        from pathlib import Path as _P2
        _sc2 = _P2(__file__).resolve().parent / "engagement.py"
        _r2 = _sp2.run([sys.executable, "-W", "ignore", str(_sc2), "summary"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
        _out2 = (_r2.stdout or "").strip()
        if _out2:
            print(_out2)
            print("- 续跑/更新: python scripts/engagement.py show <slug> | hop | lead | next")
            print("")
    except Exception as exc:
        print("## 作战档案（读取失败: %s）\n" % str(exc)[:60])

    # 2026-09-18 加（能力型瘦身）：results/ 有近 18000 个文件，**整轮的结论会烂在里面**——
    # 实测：萤石 09-14 那轮开荒（评分口径 / 129 子域 / APK 反编译 / 卡点全在里面）DB 里一个字都没有；
    # 黑湖那份 FINDING-NOTES 也躺了 6 天没人知道，差点重走三天前的路。
    # 开场就把「未入库的轮次结论」摆出来 —— 这是唯一能保证它被看到的时机。
    try:
        import contextlib, io, time as _t
        cache = workspace_db.STATE_DIR / "orphan-findings.txt"
        fresh = cache.exists() and (_t.time() - cache.stat().st_mtime) < 24 * 3600
        if not fresh:
            # 进程内调用（不要 subprocess 管道：harness 下管道解码会炸，2026-09-18 实测）
            sys.path.insert(0, str(workspace_db.ROOT / "scripts"))
            import orphan_findings
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                orphan_findings.main()
            cache.write_text(buf.getvalue(), encoding="utf-8")
        body = cache.read_text("utf-8", "ignore").strip()
        if body:
            print("## 未入库的轮次结论（results/ 里写了、DB 不知道 —— 动手前先读，别重走）")
            for line in body.splitlines()[:16]:
                print(line[:160])
            print("")
    except Exception as exc:
        print("## 未入库的轮次结论（扫描失败: %s）\n" % str(exc)[:60])

    # 2026-09-19 加（用户指出"跑到很多数据没及时更新，不然池里不止这些"）：
    # 缺口不在结论（那是 orphan_findings 管的），而在**中间数据集**：state/*.json 既不进 DB、
    # 也不在任何扫描范围里 —— 实测 247 家的全量池 vs 242 家的已跑范围，差 5 家没人看得见。
    # 这里只做两件不需要人维护的事：报事实（条数/时间）+ 检出"断点比数据还旧"。
    try:
        import json as _json, time as _time
        sd = workspace_db.STATE_DIR
        rows = []
        for p in sorted(sd.glob("*.json")):
            if p.name.startswith("_"):
                continue  # 旧的临时/中间文件, 不是工作数据集
            try:
                raw = _json.loads(p.read_text("utf-8", "ignore"))
            except Exception:
                continue
            meta = raw.get("_meta") if isinstance(raw, dict) else None
            # 条数: _meta.count > 列表长度 > 常见容器键 > 全 dict 值记录集 > 第一个容器值
            # 2026-09-23 实测：15 个数据集里 8 个渲染成 "?"（等于没有信息）——其中就有
            # carrier-triage.json（apexes 287 条）和 recon-budget.json（132/3000 请求，批量唯一闸门）。
            # 顶层键数确实没有意义，但「第一个容器值」有意义：这类文件顶层就是单集合。
            n = None
            disp = ""
            if isinstance(meta, dict) and isinstance(meta.get("count"), int):
                n = meta["count"]
            elif isinstance(raw, list):
                n = len(raw)
            elif isinstance(raw, dict):
                if isinstance(raw.get("used"), int) and isinstance(raw.get("cap"), int):
                    disp = "%d/%d 请求" % (raw["used"], raw["cap"])   # 预算型：used/cap 才是那个数
                else:
                    for key in ("weapons", "vendors", "rules", "items", "entries", "projects",
                                "apexes", "candidates", "hosts", "results", "rows", "records"):
                        if isinstance(raw.get(key), (list, dict)):
                            n = len(raw[key])
                            break
                    else:
                        # {id: {...}} 这类记录集, 顶层键数就是条数（gongyi-scope-batch 就是这种）
                        vals = [v for k, v in raw.items() if not k.startswith("_")]
                        if vals and all(isinstance(v, dict) for v in vals):
                            n = len(vals)
                        else:
                            for k, v in raw.items():   # 兜底：第一个容器值，顺带把键名带上
                                if k.startswith("_"):
                                    continue
                                if not isinstance(v, (list, dict)):
                                    continue
                                n = len(v)
                                disp = "%d(%s) 条" % (n, k)
                                # 记录集再往下一层找一个「量」字段（fofa 反查就是 1 companies · 10 hosts）
                                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                                    for kk in ("hosts", "apexes", "domains", "items", "results",
                                               "candidates", "rows", "records", "urls", "subs"):
                                        tot = sum(len(x.get(kk) or []) for x in v
                                                  if isinstance(x.get(kk), (list, dict)))
                                        if tot:
                                            disp = "%d(%s) · %d(%s) 条" % (n, k, tot, kk)
                                            break
                                break
            if n is None and not disp and not isinstance(raw, (list, dict)):
                continue
            if not disp:
                disp = "?" if n is None else "%d 条" % n   # 真读不出来才报 ?
            rows.append((p.stat().st_mtime, p.name, disp,
                         (meta or {}).get("how", "") if isinstance(meta, dict) else ""))
        now = _time.time()
        if rows:
            print("## 工作数据集（state/*.json，自动扫描 —— 中间数据集不进 DB，只在这里可见）")
            _w = max(len(str(r[2])) for r in rows)
            for mt, name, ns, how in sorted(rows, reverse=True)[:14]:
                age = (now - mt) / 86400.0
                flag = "   ⚠ %d 天未更新" % int(age) if age > 7 else ""
                hint = ("   重跑: %s" % how) if how else ""
                print("- %-32s %*s   %4.1f 天前%s%s" % (name, _w, ns, age, flag, hint))
            print("- 陈旧不等于没用：先看条数对不对（如「全集 247 / 已跑 242」= 还差 5 家没跑完）")
            print("")
        rp = sd / "resume.md"
        if rp.exists() and rows:
            rt = rp.stat().st_mtime
            newer = [name for mt, name, ns, how in rows if mt > rt + 60]
            if newer:
                print("## ⚠ 断点已过期（resume.md 比数据集旧）")
                print("- 这些数据集在断点生成之后又变过: %s" % ", ".join(newer[:6]))
                print("- 收工前补跑一次 checkpoint，否则下次开场看不见这轮产出：")
                print("  `$py scripts\\checkpoint.py --next \"<下一步一句话>\"`")
                print("")
    except Exception as exc:
        print("## 工作数据集（扫描失败: %s）\n" % str(exc)[:60])

    # 2026-09-18 瘦身：删掉原来的「## 规则」块 —— 它和 AGENTS.md 常驻段逐条重复，
    # 每次开场等于把同样的话读两遍。规则只在 AGENTS.md 里维护一份。
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
