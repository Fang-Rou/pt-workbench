# -*- coding: utf-8 -*-
"""交付包一致性校验 v2.1。
行级语义: 仅清单式行(bullet)参与; 该行若含至少一个与包内实际文件匹配(或通配)的引用则整行视为合法清单行,
描述性杂音(URL/中文粘连/chunk 名)不再误报; 整行引用全部悬空=FAIL。
另查证据四件套完整性与截图非空。用法: python scripts/check_delivery_consistency.py <交付包目录>
"""
from __future__ import annotations
import io, json, re, sys
from pathlib import Path
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

EXT_OK = ('json', 'png', 'pdf', 'txt', 'py', 'html', 'zip', 'bin', 'log', 'csv', 'xlsx')
TOKEN = '[A-Za-z0-9_\u4e00-\u9fff\\-]+'
# 2026-09-11 修: 文件名可含内部点(如 归属-ICP备案-qrange.cn.png), 并加左界防从中间截断(旧版会把 cn.png 当引用)
SEG = TOKEN + r'(?:\.' + TOKEN + r')*'
PATHSEP = '(?:' + TOKEN + '[/\\\\])*'
REF_RE = re.compile(r'(?<![\w\u4e00-\u9fff.\-])' + PATHSEP + '(' + SEG + r'\.(?:' + '|'.join(EXT_OK) + r'))')

def refs_of_line(line: str):
    out = set()
    for m in REF_RE.finditer(line):
        out.add(m.group(1))
    return out

def main() -> int:
    if len(sys.argv) < 2:
        print('usage: python scripts/check_delivery_consistency.py <交付包目录>')
        return 2
    root = Path(sys.argv[1])
    if not root.is_dir():
        print('FAIL: 目录不存在', root)
        return 2
    actual = {f.name for f in root.rglob('*') if f.is_file()}
    dangling = []
    for f in root.rglob('*'):
        if not (f.is_file() and f.suffix.lower() in ('.md', '.txt')):
            continue
        for line in f.read_text(encoding='utf-8', errors='replace').splitlines():
            ls = line.lstrip()
            if not (ls.startswith('-') or ls.startswith('*') or ls.startswith('•')):
                continue
            if 'curl' in ls or 'http://' in ls or 'https://' in ls:
                continue
            toks = {t for t in refs_of_line(ls) if not t.startswith('-')}
            if not toks:
                continue
            matched = toks & actual
            has_wild = any('*' in t or '?' in t for t in toks)
            if not matched and not has_wild:
                dangling.append((f.name, ls[:80], sorted(toks)[:6]))
    print('实际文件:', len(actual))
    if dangling:
        for fn, ln, toks in dangling:
            print('DANGLING 清单行 @' + fn + ': ' + ln)
            print('   引用了包内不存在的文件:', toks)
        print('VERDICT: FAIL - 存在悬空引用(文档写了但包内没有), 严禁带不一致包验收/提交')
        return 1
    shot_dirs = [d for d in root.rglob('*') if d.is_dir() and d.name in ('证据截图', '窗口级截图')]
    problems = []
    for d in shot_dirs:
        for png in d.glob('*.png'):
            base = png.name[:-4]
            if (d / (base + '.cmdlog.txt')).exists():
                # 终端证据组: png + cmdlog.txt + window.json
                for need in (base + '.cmdlog.txt', base + '.window.json'):
                    if not (d / need).exists():
                        problems.append(d.name + '/' + need + ' 缺失(终端三件套不完整)')
            else:
                # 浏览器证据组四件套
                for need in (base + '-urlheader.pdf', base + '.page.txt', base + '.window.json'):
                    if not (d / need).exists():
                        problems.append(d.name + '/' + need + ' 缺失(四件套不完整)')
            sz = png.stat().st_size
            if sz < 8192:
                problems.append(d.name + '/' + png.name + ' 仅 ' + str(sz) + 'B, 疑似空白/失败渲染, 人工复核')
            # 2026-09-13 加：证据必须是"真实窗口实拍"，禁止把本机渲染页(127.0.0.1/file://)当证据（厂家不认）
            wj = d / (base + '.window.json')
            if wj.exists():
                try:
                    meta = json.loads(wj.read_text('utf-8'))
                    tgt = str(meta.get('target_url') or meta.get('url') or '')
                    mode = str(meta.get('mode') or meta.get('capture') or '')
                    if '127.0.0.1' in tgt or 'localhost' in tgt or 'file://' in tgt or 'local-render' in mode:
                        problems.append(d.name + '/' + png.name + ': 目标为本机渲染页(' + (tgt or mode)[:60] + ')，不是真实窗口实拍 → 重拍')
                except Exception:
                    pass
    # 2026-09-14 加（用户："以后不要有这种漏截图的"）：终端截图若「内容行数 > 可见行数」即为漏行图
    # （顶部命令行被挤出画面）。imou_term_shot.py 现在会把 fits 写进 window.json。
    for wj in root.rglob('*.window.json'):
        try:
            meta = json.loads(wj.read_text('utf-8'))
        except Exception:
            continue
        if meta.get('fits') is False:
            problems.append(wj.name + ': 内容 ' + str(meta.get('content_lines')) + ' 行 > 可见 '
                            + str(meta.get('visible_rows')) + ' 行 → 顶部丢行的漏行图, 必须重拍')
        # 2026-09-14 加：日志中文编码错乱（脚本硬写 utf-8 打 GBK 控制台）→ 图里中文是乱码，同样作废
        if meta.get('encoding_ok') is False:
            problems.append(wj.name + ': 日志中文编码错乱（乱码图），必须重拍（脚本输出编码要跟随环境）')
    # 2026-09-18 加：形式证据闸门（补天 28 条驳回原话时间切片后的结论见 hit-case-library §30）
    # 审核员原话：「报告完整性、可复现性和规范性均良好……但按 Skill 规则，报告全文无 img 图片标签，直接判定不通过」
    # 覆盖范围：交付包内的**报告正文**（文件名含「报告」或 report）。README 等不强制配图。
    try:
        import report_evidence_gate as reg
        n_rep = 0
        for rp in root.rglob("*.md"):
            nm = rp.name.lower()
            if "报告" not in rp.name and "report" not in nm:
                continue
            n_rep += 1
            txt = rp.read_text("utf-8", "ignore")
            n_img = len(reg.IMG_HTML.findall(txt)) + len(reg.IMG_MD.findall(txt))
            if n_img == 0:
                problems.append(rp.name + ": 报告正文 0 张图片标签 → 平台原话「报告全文无 img 图片标签，直接判定不通过」")
            # 2026-09-24 加：图文关联（截图放在每一步步骤下），用户明示规范化为交付标准
            for _pr in reg.image_layout(txt)[0]:
                problems.append(rp.name + ": " + _pr)
            for ph in reg.HARD_PHRASES:
                if ph in txt:
                    problems.append(rp.name + ": 命中必驳措辞「" + ph + "」→ 平台原话「所述影响仅为降低攻击门槛和配合其他漏洞利用的理论风险，未形成实际安全影响」")
        if n_rep:
            print("  形式证据闸门: 检查报告 %d 份" % n_rep)
    except Exception as e:
        print("  [WARN] 形式证据闸门未接入: %s" % str(e)[:70])
    if problems:
        for p in problems:
            print('  !', p)
        print('VERDICT: FAIL - 证据集有问题')
        return 1
    print('VERDICT: PASS - 清单引用与包内文件一致, 证据四件套完整')
    return 0

if __name__ == '__main__':
    sys.exit(main())