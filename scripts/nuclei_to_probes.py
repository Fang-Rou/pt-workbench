# -*- coding: utf-8 -*-
"""nuclei 模板 -> 探针库转换器。

严格过滤（宁可少、不可假）：只保留
  ① method=GET（batch_recon 的只读硬约束）
  ② 只有 1 个 path（多请求链/工作流一律不要）
  ③ path 以 {{BaseURL}} 开头且去掉后**不含任何 {{变量}}**（否则需要交互或额外输入）
  ④ 有 word 类型 matcher 且 words 非空（我们的 PROBES 用关键字判定）
输出：state/nuclei-probes.json（按 tag 分类）+ 统计。
"""
import json, sys
from collections import Counter, defaultdict
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import yaml
ROOT = Path(r"D:\渗透工作流\_PT工作台")
REPO = Path(r"D:\gh-nuclei\nuclei-templates-main\http")
OUT = ROOT / "state" / "nuclei-probes.json"
def parse(p):
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    tid = str(doc.get("id") or p.stem)
    info = doc.get("info") or {}
    sev = str(info.get("severity") or "")
    tags = info.get("tags")
    if isinstance(tags, list):
        tags = ",".join(str(t) for t in tags)
    tags = str(tags or "")
    reqs = doc.get("http") or doc.get("requests") or []
    out = []
    for req in reqs:
        if not isinstance(req, dict):
            continue
        if str(req.get("method") or "GET").upper() != "GET":
            continue
        paths = req.get("path")
        if not isinstance(paths, list) or len(paths) != 1:
            continue
        raw = str(paths[0])
        if not raw.startswith("{{BaseURL}}"):
            continue
        rel = raw.replace("{{BaseURL}}", "")
        if "{{" in rel or "}}" in rel:
            continue
        if not rel.startswith("/"):
            continue
        words = []
        for m in (req.get("matchers") or []):
            if not isinstance(m, dict):
                continue
            if m.get("type") == "word":
                ws = m.get("words")
                if isinstance(ws, list):
                    words += [str(w) for w in ws if str(w).strip()]
        if not words:
            continue
        words = sorted(set(words), key=lambda x: -len(x))[:3]
        out.append({"id": tid, "path": rel, "expect": words, "severity": sev, "tags": tags})
    return out
def main():
    if not REPO.exists():
        print("模板目录不存在:", REPO); return
    files = sorted(list(REPO.rglob("*.yaml")) + list(REPO.rglob("*.yml")))
    print("http 模板文件: %d" % len(files))
    rows = []
    for f in files:
        rows += parse(f)
    print("通过严格过滤的探针: %d（来自 %d 个模板）" % (len(rows), len({r["id"] for r in rows})))
    by_tag = defaultdict(list)
    for r in rows:
        first = (r["tags"].split(",")[0] or "untagged").strip()
        by_tag[first].append(r)
    print("")
    print("按首个 tag 分类 TOP 20:")
    for t, v in sorted(by_tag.items(), key=lambda x: -len(x[1]))[:20]:
        print("   %-26s %d" % (t, len(v)))
    OUT.write_text(json.dumps(dict(by_tag), ensure_ascii=False, indent=1), "utf-8")
    print("")
    print("-> %s" % OUT)
    sev = Counter(r["severity"] for r in rows)
    print("严重度分布:", dict(sev))
main()