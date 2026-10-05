# -*- coding: utf-8 -*-
"""oss_verify.py — OSS 狩猎阶段2: 对候选桶做【只读】验证并分级。

只读动作: 匿名列目录(list-type=2 / prefix) + 根响应 + 已知对象 HEAD。
绝不 PUT/POST/DELETE —— 写权限候选只登记到 write_candidates.json, 等用户批量批准后再测。
输出: verified.json + report.md（含候选桶来源主机, 便于做归属证明）
"""
from __future__ import annotations

import argparse, io, json, re, sys, time
from datetime import datetime
from pathlib import Path
import urllib.error, urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recon_api import SSL_CTX  # noqa: E402
from oss_hunt import DELAY, UA  # noqa: E402


def probe(url: str, method: str = "GET", timeout: int = 10) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
            body = r.read(8000).decode("utf-8", "replace")
            return {"status": r.status, "len": int(r.headers.get("Content-Length") or len(body)),
                    "ctype": (r.headers.get("Content-Type") or "")[:40],
                    "snippet": re.sub(r"\s+", " ", body)[:300]}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(1500).decode("utf-8", "replace")
        except Exception:
            body = ""
        code = re.search(r"<Code>([^<]+)</Code>", body)
        return {"status": e.code, "err_code": (code.group(1) if code else ""),
                "snippet": re.sub(r"\s+", " ", body)[:200]}
    except Exception as e:
        return {"status": None, "err": "%s: %s" % (type(e).__name__, str(e)[:70])}


def classify(v: dict) -> tuple[str, str]:
    root, lv2, lv1 = v.get("root", {}), v.get("list_v2", {}), v.get("list_v1", {})
    if lv2.get("status") == 200 and "<ListBucketResult" in (lv2.get("snippet") or ""):
        return "LISTABLE", "匿名可列目录(高危候选: 可枚举全部对象)"
    if lv1.get("status") == 200 and "<ListBucketResult" in (lv1.get("snippet") or ""):
        return "LISTABLE_V1", "匿名可列目录(v1 语法)"
    if root.get("status") == 200:
        return "PUBLIC_ROOT", "根可读(可能公开读桶)"
    code = root.get("err_code") or lv2.get("err_code") or ""
    if code == "AccessDenied":
        return "PRIVATE", "拒绝匿名(桶存在, 权限正常)"
    if code == "NoSuchBucket":
        return "NO_BUCKET", "桶不存在(可能是误报/CNAME)"
    return "UNKNOWN", (root.get("err") or code or "?")


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--buckets", required=True, help="阶段1 buckets.json")
    ap.add_argument("--out", default="")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    buckets = json.loads(Path(args.buckets).read_text(encoding="utf-8"))
    items = list(buckets.items())
    if args.limit:
        items = items[: args.limit]
    outdir = Path(args.out) if args.out else Path(args.buckets).parent
    print("# oss_verify: %d 个候选桶(只读验证)" % len(items), flush=True)

    results, write_candidates = {}, []
    for b, srcs in items:
        v = {}
        for label, path in (("root", "/"), ("list_v2", "/?list-type=2&max-keys=5"), ("list_v1", "/?prefix=&max-keys=5")):
            v[label] = probe("https://" + b + path)
            time.sleep(DELAY)
        verdict, why = classify(v)
        v["verdict"] = verdict
        v["why"] = why
        v["sources"] = srcs
        results[b] = v
        print("  %-58s %-12s %s" % (b[:56], verdict, why), flush=True)
        if verdict in ("LISTABLE", "LISTABLE_V1", "PUBLIC_ROOT"):
            write_candidates.append({"bucket": b, "verdict": verdict, "sources": srcs,
                                     "note": "公开读; 写权限未测(需用户批准)"})

    (outdir / "verified.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    (outdir / "write_candidates.json").write_text(
        json.dumps({"generated": datetime.now().isoformat(timespec="seconds"),
                    "candidates": write_candidates}, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\n有信号 %d 个; 写测试候选 %d 个" % (
        sum(1 for v in results.values() if v["verdict"] not in ("PRIVATE", "NO_BUCKET")), len(write_candidates)))
    print("落盘: %s" % (outdir / "verified.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
