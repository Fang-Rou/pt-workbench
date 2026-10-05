# -*- coding: utf-8 -*-
"""前置追加断点到 state/next.txt —— 禁止整体覆盖（2026-09-27 事故防护）。

用法:
  $py scripts\prepend_next.py --text-file new.md
  $py scripts\prepend_next.py --text "短句"
  $py scripts\prepend_next.py --text-file new.md --dry-run

判据（任一不满足即回滚并退出 1）:
  1. 写后文件必须**完整包含**写入前的旧全文（防覆盖事故）
  2. 写后文件必须包含本次新内容
  3. 旧文件自动备份为 next.txt.bak-<时间戳>
"""
import argparse, os, shutil, sys, datetime

NL = chr(10)
HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.normpath(os.path.join(HERE, "..", "state", "next.txt"))
SEP = NL + NL + "---------- 以下为历史断点（原样保留，勿删）----------" + NL + NL


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--text")
    ap.add_argument("--text-file")
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if not a.text and not a.text_file:
        print("need --text or --text-file")
        return 2
    new = a.text if a.text else open(a.text_file, encoding="utf-8").read()
    new = new.strip()
    if not new:
        print("empty new text; refuse")
        return 2
    if not os.path.exists(a.target):
        print("target missing: " + a.target)
        return 2
    old = open(a.target, encoding="utf-8").read()
    composed = new + SEP + old.strip() + NL
    if a.dry_run:
        print("dry-run: would write %d bytes (old %d bytes, new %d bytes)" % (
            len(composed.encode("utf-8")), len(old.encode("utf-8")), len(new.encode("utf-8"))))
        print("dry-run: old would be preserved = %s" % (old.strip() in composed))
        return 0
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = a.target + ".bak-" + stamp
    shutil.copy2(a.target, bak)
    with open(a.target, "w", encoding="utf-8", newline=NL) as f:
        f.write(composed)
    back = open(a.target, encoding="utf-8").read()
    ok_old, ok_new = old.strip() in back, new in back
    if not (ok_old and ok_new):
        shutil.copy2(bak, a.target)
        print("FAIL verify (old=%s new=%s) -> rolled back from %s" % (ok_old, ok_new, bak))
        return 1
    print("OK appended. bytes=%d lines=%d backup=%s" % (
        len(back.encode("utf-8")), back.count(NL) + 1, os.path.basename(bak)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
