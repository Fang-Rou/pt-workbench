#!/usr/bin/env python3
"""fofa_carrier.py — 载体发现：一个产品的图标指纹 → 全世界的部署实例。

为什么需要它（2026-09-20 用户点破「FOFA 有 60 多个语法，高级的用到了没」）：
  我们原先只用 domain/cert/title/icp 四个字段。而 `icon_hash=` 是**载体级**的杠杆 ——
  AGENTS.md §3 定死「载体 = 产品/框架/组件，一处摸清、处处可套」，icon_hash 正是
  找「同一个载体还被谁部署了」的那把钥匙。

实测口径（fofa_probe.py --round 3，2026-09-21，勿凭记忆改）：
  ✅ `icon_hash="<h>"` 作为**查询条件**可用（实测 total=55）
  ❌ icon_hash 作为 **fields 返回字段**不可用：[820001] 没有权限搜索icon_hash字段
  ⇒ 所以必须自己算：mmh3.hash(base64.encodebytes(favicon_bytes))（FOFA 官方口径）

图标来源用**官方仓库/镜像**（raw.githubusercontent / jsdelivr），**不碰任何目标**。

用法（在 _PT工作台 目录执行）：
  $py scripts\fofa_carrier.py                       # 默认几个载体
  $py scripts\fofa_carrier.py --carriers harbor,ruoyi --size 500
  $py scripts\fofa_carrier.py --targets state/bombard-wave2.txt   # 顺带做本地交集
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recon_api import load_fofa_key  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "results" / "fofa-carrier"
FIELDS = "host,domain,title,icp"

# 载体登记表：name -> (图标 URL, 说明, 关联手法)
# 只放**官方仓库/镜像**的默认图标 —— 部署实例多数保留默认图标，故可指纹化。
CARRIERS = {
    "harbor": ("https://cdn.jsdelivr.net/gh/goharbor/harbor@main/src/portal/src/favicon.ico",
               "Harbor 制品仓", "A"),
    "ruoyi": ("https://cdn.jsdelivr.net/gh/yangzongzhuan/RuoYi@master/ruoyi-admin/src/main/resources/static/favicon.ico",
              "RuoYi 若依", "E/I"),
    "jenkins": ("https://cdn.jsdelivr.net/gh/jenkinsci/jenkins@master/war/src/main/webapp/favicon.ico",
                "Jenkins", "O"),
    "grafana": ("https://cdn.jsdelivr.net/gh/grafana/grafana@main/public/img/fav32.png",
                "Grafana", "O"),
    "yapi": ("https://cdn.jsdelivr.net/gh/YMFE/yapi@master/static/favicon.ico",
             "YApi 接口管理平台", "P/J"),
    "gitlab": ("https://cdn.jsdelivr.net/gh/gitlabhq/gitlabhq@master/app/assets/images/favicon.ico",
               "GitLab", "O"),
}

MULTI = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "co.jp"}


def out(s=""):
    print(s, flush=True)


def log(m):
    out("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), m))


def ssl_ctx():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def apex_of(host):
    h = str(host).split(":")[0]
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
        return ""
    p = h.split(".")
    if len(p) <= 2:
        return h
    return ".".join(p[-3:]) if ".".join(p[-2:]) in MULTI else ".".join(p[-2:])


def icon_hash(favicon_bytes):
    """FOFA 官方口径：mmh3.hash(base64.encodebytes(icon))。"""
    import mmh3
    return mmh3.hash(base64.encodebytes(favicon_bytes))


def fetch_icon(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (carrier/1.0)"})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx()) as r:
        return r.read()


def fofa(key, q, size, sleep_s=3.0):
    # P29：默认加「蜜罐/裸IP/新鲜度」三件套（见 hit-case-library §32 P29）
    from fofa_reverse import harden_query
    q = harden_query(q)
    qb = base64.b64encode(q.encode()).decode()
    url = ("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&size=%d&fields=%s"
           % (key, urllib.parse.quote(qb), size, FIELDS))
    req = urllib.request.Request(url, headers={"User-Agent": "carrier/1.0"})
    delay = 5.0
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:
                log("  429 限流，退避 %.0fs" % delay)
                time.sleep(delay)
                delay *= 2
                continue
            return None, "HTTP %s" % e.code
        except Exception as e:
            return None, "%s: %s" % (type(e).__name__, e)
    else:
        return None, "429 退避失败"
    if d.get("error"):
        return None, str(d.get("errmsg"))[:100]
    time.sleep(sleep_s)
    return d, ""


def main():
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="FOFA 载体发现（icon_hash 指纹）")
    ap.add_argument("--carriers", default="harbor,ruoyi,jenkins,grafana",
                    help="逗号分隔；可用: %s" % ",".join(CARRIERS))
    ap.add_argument("--size", type=int, default=500)
    ap.add_argument("--targets", default="state/bombard-wave2.txt",
                    help="本地目标清单，用于做交集（只标注不测试）")
    ap.add_argument("--intersect", action="store_true",
                    help="按目标**批量反查**（icon_hash X && (domain=a || domain=b ...)）—— "
                         "抽样式交集漏检率高（全球4万实例只抽486个），批量反查才是结论性的")
    ap.add_argument("--batch", type=int, default=20, help="每个 OR 查询塞几个域名")
    a = ap.parse_args()

    key = load_fofa_key()
    if not key:
        out("UNSURE: 没读到 FOFA key")
        return 2

    targets = set()
    tp = ROOT / a.targets
    if tp.exists():
        for ln in tp.read_text("utf-8", "ignore").splitlines():
            if ln.strip():
                targets.add(apex_of(ln.strip()))
    log("本地目标 apex 数: %d" % len(targets))

    result = {"generated": datetime.now().isoformat(timespec="seconds"), "carriers": {}}
    for name in [x.strip() for x in a.carriers.split(",") if x.strip()]:
        if name not in CARRIERS:
            out("UNSURE: 未登记的载体 %r（可用: %s）" % (name, ",".join(CARRIERS)))
            continue
        url, desc, weapon = CARRIERS[name]
        log("== %s（%s，关联手法 %s）==" % (name, desc, weapon))
        try:
            icon = fetch_icon(url)
        except Exception as e:
            out("  UNSURE: 图标取不到 %s: %s" % (type(e).__name__, str(e)[:70]))
            result["carriers"][name] = {"error": "icon fetch failed", "desc": desc}
            continue
        h = icon_hash(icon)
        log("  icon %d bytes -> icon_hash=%d" % (len(icon), h))
        q = 'icon_hash="%d"' % h
        d, err = fofa(key, q, a.size)
        if err:
            out("  UNSURE: 查询失败 %s" % err)
            result["carriers"][name] = {"error": err, "icon_hash": h, "desc": desc}
            continue
        rows = d.get("results") or []
        total = d.get("size")
        hosts, hits = [], []
        for r in rows:
            r = list(r) + [""] * (4 - len(r))
            host = re.sub(r"^[a-z]+://", "", str(r[0])).split("/")[0]
            if host and host not in hosts:
                hosts.append(host)
            apx = apex_of(host.split(":")[0])
            if apx and apx in targets and host not in hits:
                hits.append(host)
        log("  全世界该载体实例 total=%s（取回 %d），其中**落在我们目标清单里** %d 个"
            % (total, len(hosts), len(hits)))
        for x in hits[:15]:
            out("     ★ 交集 %s" % x)
        result["carriers"][name] = {"desc": desc, "weapon": weapon, "icon_hash": h,
                                    "total": total, "returned": len(hosts),
                                    "hosts": hosts[:200], "target_hits": hits}
        if a.intersect and targets:
            tl = sorted(targets)
            found = []
            for i in range(0, len(tl), a.batch):
                grp = tl[i:i + a.batch]
                q2 = 'icon_hash="%d" && (%s)' % (h, " || ".join('domain="%s"' % x for x in grp))
                d2, e2 = fofa(key, q2, 100)
                if e2:
                    out("      UNSURE: 批量反查失败 %s" % e2)
                    break
                for r2 in (d2.get("results") or []):
                    r2 = list(r2) + [""] * (4 - len(r2))
                    hh = re.sub(r"^[a-z]+://", "", str(r2[0])).split("/")[0]
                    found.append({"host": hh, "title": str(r2[2])[:60]})
            result["carriers"][name]["intersect_hits"] = found
            out("     【批量反查】我们 %d 个 apex 里命中该载体: %d 个" % (len(tl), len(found)))
            for f in found[:15]:
                out("        ★ %-38s %s" % (f["host"], f["title"]))

    CACHE.mkdir(parents=True, exist_ok=True)
    p = CACHE / ("carrier-%s.json" % datetime.now().strftime("%Y%m%d-%H%M"))
    p.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    out("")
    out("产物: %s" % p)
    out("提醒: 交集只是**候选**；是否属于委托范围由项目 scope 表决定，落地前人工过一眼。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())