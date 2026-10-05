# -*- coding: utf-8 -*-
"""batch_recon.entry_form 自测（2026-09-23 加）：自动判读最怕假阳，先把边界钉死。

跑: python scripts/batch_recon_selftest.py      # 期望 7/7 PASS

覆盖的边界：
  1 各台指纹互不相同          -> 不报（正常的多应用环境）
  2 同构台数未过阈值          -> 不报（3/10，低于 max(3, 50%)）
  3 同构 6/10（过阈值未到 80%）-> 只给事实 note，**不**升格 UNSURE
  4 同构 8/10（>=80%）        -> note + blind=True（gate 记 UNSURE）
  5 有命中的台                -> 该台被排除，不参与同构簇
  6 探针全 -1（超时/无响应）  -> 不报（那不是"同构响应"）
  7 3/3 全同构但样本 <5 台     -> 只给 note（小样本不下判读）
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import batch_recon as br


def mk(spec):
    """spec: {host: (status, sig, hit?)} -> raw_map"""
    out = {}
    for h, (st, sg, hit) in spec.items():
        out[h] = {"host": h, "probes": [
            {"probe": "p1", "path": "/a", "status": st, "sig": sg, "hit": hit},
            {"probe": "p2", "path": "/b", "status": st, "sig": sg, "hit": hit},
            {"probe": "p3", "path": "/c", "status": st, "sig": sg, "hit": hit}]}
    return out


CASES = []


def case(name, spec, want_note, want_blind, reach=None):
    CASES.append((name, spec, want_note, want_blind, reach or {}))


case("1 各台指纹不同（正常环境）",
     {"h%d" % i: (404, "404 body %d" % i, False) for i in range(10)}, False, False)
case("2 同构 3/10（未过阈值 ⇒ 沉默）",
     dict({"h%d" % i: (404, "same", False) for i in range(3)},
          **{"x%d" % i: (404, "uniq %d" % i, False) for i in range(7)}), False, False)
case("3 同构 6/10（过阈值未到 80%）",
     dict({"h%d" % i: (404, "same", False) for i in range(6)},
          **{"x%d" % i: (404, "uniq %d" % i, False) for i in range(4)}), True, False)
case("4 同构 8/10（>=80%）",
     dict({"h%d" % i: (404, "same", False) for i in range(8)},
          **{"x%d" % i: (404, "uniq %d" % i, False) for i in range(2)}), True, True,
     reach={"h%d" % i: ["https", 404, "APISIX/3.5.0", "abcdef"] for i in range(8)})
case("5 有命中的台被排除出簇",
     dict({"h%d" % i: (404, "same", False) for i in range(10)},
          **{"hit1": (200, "swagger here", True)}), True, True)
case("6 探针全 -1（无响应）",
     {"h%d" % i: (-1, "", False) for i in range(10)}, False, False)
case("7 3/3 全同构但样本太小",
     {"h%d" % i: (404, "same", False) for i in range(3)}, True, False)

fails = 0
for name, spec, want_note, want_blind, reach in CASES:
    raw = mk(spec)
    ef = br.entry_form(list(spec.keys()), raw, reach)
    got_note, got_blind = bool(ef.get("notes")), bool(ef.get("blind"))
    ok = (got_note == want_note) and (got_blind == want_blind)
    fails += 0 if ok else 1
    print("%s %-30s note=%-5s blind=%-5s (want note=%-5s blind=%s)"
          % ("PASS" if ok else "FAIL", name, got_note, got_blind, want_note, want_blind))
    if ef.get("notes"):
        print("      %s" % ef["notes"][0][:150])
print("")
print("VERDICT=%s (%d/%d)" % ("PASS" if fails == 0 else "FAIL", len(CASES) - fails, len(CASES)))
raise SystemExit(1 if fails else 0)