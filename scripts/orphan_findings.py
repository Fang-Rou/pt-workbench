# -*- coding: utf-8 -*-
"""orphan_findings.py —— 找回「写出来但没入库」的命中（能力型瘦身，2026-09-18）。

为什么：results/ 有近 18000 个文件，结论散落其中。黑湖那份 FINDING-NOTES.md 是靠
「碰巧列了个目录」才被发现的 —— 而它已经躺了 6 天。**过去的产出对 AI 不可见 = 白干**。
本脚本扫 results/ 下的结论类文件，抽出「提到高危/严重」但 DB 里查无对应的，列出来。

用法: python scripts/orphan_findings.py [--all]
"""
from __future__ import annotations
import re, sqlite3, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
DB = ROOT / "state" / "workspace.db"
NAME_RX = re.compile(r"(FINDING|finding|结论|SUMMARY|summary|NOTES|notes|RESULT|result)", re.I)
HIGH_RX = re.compile(r"(高危|严重|critical|high severity|\bhigh\b)", re.I)
EXT = (".md", ".txt")


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    show_all = '--all' in sys.argv
    con = sqlite3.connect(DB)
    known = set()
    for (p,) in con.execute('select coalesce(poc_path, \'\') from findings'):
        if p:
            known.add(p.replace('\\', '/').lower())
    # 2026-09-18 补：项目/目标备注里提到过的轮次目录也算「已归位」（把结论写进台账 = 目的达成）
    for tbl, col in (('projects', 'notes'), ('targets', 'notes'), ('findings', 'description')):
        try:
            for (d,) in con.execute('select coalesce(%s, \'\') from %s' % (col, tbl)):
                for m in re.findall(r'results[/\\][A-Za-z0-9_\-./]+', d or ''):
                    known.add(m.replace('\\', '/').lower())
        except Exception:
            pass
    for (d,) in con.execute('select coalesce(description, \'\') from findings'):
        for m in re.findall(r'results[/\\][A-Za-z0-9_\-./]+', d or ''):
            known.add(m.replace('\\', '/').lower())
    known_blob = ' | '.join(sorted(known))
    cands = [p for p in RES.rglob('*') if p.is_file() and p.suffix.lower() in EXT and NAME_RX.search(p.name)]
    print('结论类文件: %d 个；DB 已知路径: %d 条' % (len(cands), len(known)))
    rows, no_tldr = [], []
    for p in cands:
        rel = str(p.relative_to(ROOT)).replace('\\', '/')
        low = rel.lower()
        # 匹配口径（2026-09-18 修）：DB 里的 poc_path 写法五花八门（目录/文件/带\不带 results 前缀），
        # 只看整串包含会把已入库的也报成孤儿（假红）。改成**父目录名**或文件名命中即算已知。
        keys = {p.parent.name.lower(), p.name.lower()}
        _already = any(k and (k in known_blob) for k in keys)
        try:
            t = p.read_text('utf-8', 'ignore')[:6000]
        except Exception:
            continue
        if not t.strip():
            continue
        mt = p.stat().st_mtime
        first = next((ln.strip('# ').strip() for ln in t.splitlines() if ln.strip().startswith('#')), p.parent.name)
        _head = "\n".join(t.splitlines()[:25])
        if not any(k in _head for k in ("结论", "CONCLUSION", "Conclusion")):
            no_tldr.append((mt, rel))
        if _already:
            continue
        hi = bool(HIGH_RX.search(t[:3000]))
        if not hi and not show_all:
            continue
        # 2026-09-18 加：**结论先行**体检。
        # 教训：我为萤石那轮只读了笔记的头和尾，漏掉中间 §6.2（v3 BOLA 负结果就写在那里），
        # 于是准备重做一遍。根因不是"文件找不到"，是**结论没写在开头**。
        # 规范：结论类文件前 25 行内必须出现「结论」字样（## 结论 / 结论先行 / 结论：）。
        rows.append((mt, rel, first[:70], hi))
    rows.sort(reverse=True)
    print('未入库且提到高危/严重: %d 个%s' % (len(rows), '' if rows else '（--all 看全部未入库）'))
    for mt, rel, title, hi in rows[:25]:
        print('  %s [%s] %s' % (time.strftime('%m-%d', time.localtime(mt)), 'H' if hi else ' ', rel[:64]))
        print('        %s' % title)
    if no_tldr:
        # 2026-09-23 改：这份清单从 09-16 起每天逐字重现（50 份，全是 08 月前后的老文件）——
        # 静态噪音会把上面真正要看的「未入库命中」挤掉。只列最近 14 天新增的；没有就一句话带过。
        _recent = [x for x in no_tldr if (time.time() - x[0]) < 14 * 86400]
        print('')
        if _recent:
            print('  ⚠ 结论没写在开头的 %d 份（**下次会被读漏** —— 2026-09-18 萤石就这么漏掉 v3 BOLA 负结果）；最近 14 天新增 %d 份：'
                  % (len(no_tldr), len(_recent)))
            for _mt, x in sorted(_recent, reverse=True)[:8]:
                print('      %s %s' % (time.strftime('%m-%d', time.localtime(_mt)), x[:72]))
        else:
            print('  ⚠ 结论没写在开头的 %d 份：最近 14 天无新增（老文件，逐条列只是噪音；真要用去 results/ 里按轮次找）'
                  % len(no_tldr))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
