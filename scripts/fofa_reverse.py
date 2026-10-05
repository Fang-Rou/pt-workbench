#!/usr/bin/env python3
"""fofa_reverse.py — 目标入口：把「单位/公司名」变成「资产」（FOFA 反查，全程被动）。

为什么需要它：
  渗透测试开工时手里常常**只有委托方给的公司名**，不知道域名是什么。
  recon_api 的 collect_fofa 只支持 domain= 查询，所以要先有域名才能查，**鸡生蛋**。
  本脚本就是打破这个死循环的那一环。

实测事实（scripts/fofa_probe.py 探针，2026-09-20，勿凭记忆改）：
  ✅ cert="<公司名>"  可用，且**最肥**：鑫方盛 → 381 条，还挖出全新域名 xinfangsheng.com
  ✅ title="<公司名>" 可用但弱：同一家只有 47 条
  ✅ icp="京ICP备20210253" 可用（**按备案号**，不是按公司名）
  ❌ name= / company=      字段不存在（820000 查询语法错误）
  ❌ org="<公司名>"        合法但恒 0 命中；icp="<公司名>" 同样恒 0
  ⇒ 所以「按公司名反查」只有 cert / title 两条路；icp 只能拿**备案号**去查（见 --pivot-icp）。

⚠ 精度纪律：
  反查是**候选**，不是结论。同一张证书 / 同一句 title 可能属于别的主体（集成商、代运营）。
  本脚本只输出候选主机清单，**绝不向候选发请求**；是否纳入范围由项目 scope 表决定。

用法（在 _PT工作台 目录执行，$py = bundled python）：
  $py scripts\fofa_reverse.py --vendor "某某科技有限公司"
  $py scripts\fofa_reverse.py --from state/pt-targets.json --limit 20
  $py scripts\fofa_reverse.py --vendor "某某科技有限公司" --pivot-icp   # 顺备案号扩线
  $py scripts\fofa_reverse.py --report state/fofa-reverse-<日期>.json  # 复读，不耗额度
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recon_api import load_fofa_key  # noqa: E402  （复用密钥加载，位置唯一）

ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = ROOT / "results" / "fofa-reverse" / "cache"
FIELDS = "host,domain,title,icp"
UA = "Mozilla/5.0 (fofa_reverse/1.0; authorized-src-recon)"
CACHE_TTL = 30 * 24 * 3600          # 公司↔证书映射变化很慢，而额度很贵
FIELD_ORDER = ["cert", "title"]     # 按实测产量排序（cert 381 vs title 47）

# 多段后缀：取 apex 时不能简单取最后两段（否则 x.com.cn 会退化成 com.cn）
MULTI_SUFFIX = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "com.hk",
                "com.tw", "co.jp", "co.kr", "co.uk", "com.au", "com.sg"}

# 噪声 apex（**实测出来的**，不是猜的）：
# ① 动态域名/内网穿透：证书里出现的是隧道临时域名。实测 至臻云 cert 命中
#    x296481q17.zicp.vip —— 那是花生壳隧道，跟厂商无关。
# ② B2B 企业名录站：页面把「公司名」写进 <title>，于是被 title= 命中，站点却属于名录站。
#    实测 淳中科技 title 命中「北京淳中科技股份有限公司-高端装备网」→ zhuangbei.cn。
# 不删只标：命中的主机仍留在 hosts，但记进 noise_hosts，且不计入 apex_domains。
NOISE_APEX = {
    "zicp.vip", "vicp.hk", "iok.la", "ngrok.io", "ngrok-free.app", "natappfree.cc",
    "ddns.net", "myqcloud.com", "3322.org", "f3322.net", "noip.com", "dynv6.net",
    "goho.co", "ngrok.cc", "oray.net", "xicp.net", "tcp6.cn", "ngrok.app",
    "zhuangbei.cn", "dav01.com", "qcc.com", "tianyancha.com", "11467.com", "b2b168.com",
    "china.cn", "hc360.com", "made-in-china.com", "1688.com", "zhaopin.com", "liepin.com",
    "shunqi.com", "cn5135.com", "globalbuy.cc", "huangye88.com", "cn.china.cn",
    # ③ 文档/博客托管：别人在语雀/飞书写了一篇提到该公司的文档，域名不是厂商的。
    #    实测 上海伯俊 的 title 命中里混进 yuque.com。
    "yuque.com", "feishu.cn", "notion.site", "wixsite.com", "blogspot.com",
    "wordpress.com", "github.io", "gitee.io", "jianshu.com", "wjx.cn", "docs.qq.com",
}

# SEO 垃圾站特征：把**真实公司全称**塞进 <title> 吃搜索流量（多为赌博/推广站）。
# 实测：title="福建天马科技集团股份有限公司" 命中
#   「澳亚国际777糖果派对官网登录在线平台入口（2025已更新）—福建天马科技集团股份有限公司」
# ⇒ 这类**整行丢弃**（不是标噪声），否则赌博站会被当成「厂商资产」写进报告。
# ⚠ 实测补充（shiyicd.com）：色情/盗版站会把标题写成 HTML 实体躲过滤，故匹配前先 html.unescape；
#   且关键词表要含流媒体盗版话术（免费观看/全集/在线观看），否则仍会漏。
SPAM_TITLE_PAT = re.compile(
    r"糖果派对|官网登录|在线平台入口|已更新|澳门|威尼斯|新葡京|棋牌|娱乐城|博彩|彩票|"
    r"开户|试玩|优惠活动|真人荷官|返水|投注|现金网|六合|时时彩|体育下注|"
    r"办证|代开发票|约炮|楼凤|迷药|赌场|"
    r"免费观看|在线观看|全集|完整版|午夜|福利视频|成人视频|情色|自慰|爆乳|"
    r"金瓶|肉蒲团|国产自拍|偷拍")

# 公司名 → 品牌名 的剥离规则（用于 UNSURE 兜底；**推断成分**，故弱查询结果一律标 weak）
REGION_PREFIX = ("中国", "北京", "上海", "广州", "深圳", "杭州", "南京", "苏州", "成都", "重庆",
                 "武汉", "西安", "天津", "厦门", "福州", "合肥", "郑州", "长沙", "济南", "青岛",
                 "大连", "沈阳", "哈尔滨", "昆明", "贵阳", "南宁", "宁波", "无锡", "珠海", "东莞",
                 "佛山", "南昌", "太原", "石家庄", "乌鲁木齐", "呼和浩特", "银川", "兰州", "西宁",
                 "海口", "三亚", "长春", "广东", "浙江", "江苏", "福建", "山东", "四川", "河南")
CORP_SUFFIX = ("股份有限公司", "有限责任公司", "有限公司", "集团有限公司", "集团", "公司",
               "合伙企业", "有限合伙", "合伙")
INDUSTRY = ("人力资源科技", "网络科技", "信息技术", "信息科技", "智能科技", "数字科技", "教育科技",
            "文化传播", "企业管理", "电子商务", "科技", "信息", "网络", "技术", "数字", "智能",
            "教育", "文化", "传媒", "实业", "发展", "软件", "数据", "电子", "通信", "服务")
# 剥到这些词就停：它们单独拿去做反查会命中半个互联网（实测口径，不是推测）
GENERIC = {"科技", "信息", "网络", "技术", "数字", "智能", "实业", "集团", "发展", "文化",
           "教育", "服务", "数据", "电子", "通信", "公司", "中国", "管理", "咨询"}


def variants(name):
    """公司名 → [(变体, 强度), ...]。强度 strong=全称 / mid=去地域后缀 / weak=品牌词。

    实测依据（2026-09-20 十六家批次）：cert=全称 只命中 3/16，而全称 title 命中 11/16，
    剩 5 家两家皆 0 —— 它们要么没有 OV 证书，要么站名不含公司全称。品牌词是唯一兜底，
    代价是精度下降 ⇒ 所以 weak 命中的主机只当**候选**，动手前仍须走 preflight 归属预检。
    """
    out = [(name, "strong")]
    core = name
    for _ in range(3):
        for pre in REGION_PREFIX:
            if core.startswith(pre) and len(core) > len(pre) + 1:
                core = core[len(pre):]
                break
        else:
            break
    core = re.sub(r"[（(][^）)]*[）)]", "", core)      # 去括号里的地域/备注
    for _ in range(4):                                # 循环剥：近付科技合伙企业 → 近付科技
        for suf in CORP_SUFFIX:
            if core.endswith(suf) and len(core) > len(suf) + 1:
                core = core[: -len(suf)]
                break
        else:
            break
    core = core.strip()
    if core and core != name and len(core) >= 3:
        out.append((core, "mid"))
    brand = core
    for _ in range(4):
        for tok in INDUSTRY:
            if brand.endswith(tok) and len(brand) > len(tok) + 1:
                brand = brand[: -len(tok)]
                break
        else:
            break
    brand = brand.strip()
    if len(brand) >= 2 and brand not in GENERIC and all(b[0] != brand for b in out):
        out.append((brand, "weak"))
    return out


def out(s=""):
    print(s, flush=True)


def log(msg):
    out("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg))


def api_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


# P29（2026-09-22 实测）：FOFA 索引约 **96% 是陈旧记录**（domain=greetec.com 共 432 条，
# 加 after=近30天 只剩 16 条），且混有蜜罐与裸 IP。故猎杀查询**默认**加三件套。
# 注意：这三件套解决的是「数据新鲜度」，**不解决归属** ——
# cert= / title= 只是内容匹配，归属仍须 scope_gate.py 验证（见 §32 P28/P29）。
def _fresh_since(days: int = 30) -> str:
    import os
    if os.environ.get("DXMW_FOFA_NO_FRESH"):
        return ""
    from datetime import datetime, timedelta
    return (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")


def harden_query(q: str) -> str:
    """给 FOFA 查询加 P29 三件套；幂等（已含则不重复加）。"""
    out = q
    if "is_honeypot=" not in out:
        out += " && is_honeypot=false"
    if "is_domain=" not in out:
        out += " && is_domain=true"
    since = _fresh_since()
    if since and "after=" not in out:
        out += " && after=" + chr(34) + since + chr(34)
    return out

def fofa_search(key, query, size, sleep_s, no_cache, min_points):
    """一次 FOFA 查询。返回 (rows, meta)。带磁盘缓存 + 429 退避 + 额度护栏。

    缓存的意义：额度是稀缺资源，重跑一轮 247 家 × 2 模式 = 494 次调用，
    没有缓存的话调试一次就烧掉一轮。命中缓存不消耗任何额度。
    """
    query = harden_query(query)
    ck = hashlib.md5(("%s|%d" % (query, size)).encode("utf-8")).hexdigest()[:20]
    cp = CACHE_DIR / ("%s.json" % ck)
    if not no_cache and cp.exists() and (time.time() - cp.stat().st_mtime) < CACHE_TTL:
        try:
            d = json.loads(cp.read_text("utf-8"))
            d.setdefault("meta", {})["cached"] = True
            return d.get("rows", []), d.get("meta", {})
        except Exception:
            pass
    qb = base64.b64encode(query.encode("utf-8")).decode()
    url = ("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&size=%d&fields=%s"
           % (key, urllib.parse.quote(qb), size, FIELDS))
    delay = 5.0
    meta = {}
    for attempt in range(4):
        try:
            d = api_get(url)
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < 3:
                log("  429 限流，退避 %.0fs 后重试 (%d/3)" % (delay, attempt + 1))
                time.sleep(delay)
                delay *= 2
                continue
            return [], {"error": "HTTP %s" % exc.code}
        except Exception as exc:
            return [], {"error": "%s: %s" % (type(exc).__name__, exc)}
    else:
        return [], {"error": "429 退避 4 次仍失败"}
    if d.get("error"):
        return [], {"error": str(d.get("errmsg") or "api error")[:120]}
    rows = d.get("results") or []
    meta = {"total": d.get("size"), "returned": len(rows),
            "consumed": d.get("consumed_fpoint"), "cached": False}
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        cp.write_text(json.dumps({"query": query, "rows": rows, "meta": meta},
                                 ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    time.sleep(sleep_s)          # 背靠背必 429，实测
    return rows, meta


def norm_host(h):
    h = str(h or "").strip().lower()
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)
    h = h.split("/")[0]
    if h.startswith("["):                      # IPv6
        return h
    return h.split(":")[0]


def apex_of(host):
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) or ":" in host:
        return ""                              # IP 没有 apex，别硬造
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def load_names(args):
    """支持几种目标清单文件形状：
    - ["公司名", ...]                        纯字符串数组
    - [{"name": "公司名"}, ...]              对象数组（state/pt-targets.json 用这种）
    - [[id, name], ...]                      带 id 的数组
    - {"yes": [[id, name], ...], ...}        dict 时用 --key 取键
    """
    if args.vendor:
        return [{"id": "", "name": args.vendor.strip()}]
    p = Path(args.from_file)
    if not p.is_absolute():
        p = ROOT / p if (ROOT / p).exists() else Path(p)
    data = json.loads(p.read_text("utf-8"))
    if isinstance(data, dict):
        key = args.key or "yes"
        if key not in data:
            raise SystemExit("UNSURE: %s 里没有键 %r，现有键: %s" % (p.name, key, list(data)[:8]))
        data = data[key]
    items = []
    for it in data:
        if isinstance(it, (list, tuple)) and len(it) >= 2:
            items.append({"id": str(it[0]), "name": str(it[1]).strip()})
        elif isinstance(it, dict):
            nm = it.get("company_name") or it.get("name") or it.get("vendor")
            if nm:
                items.append({"id": str(it.get("company_id") or it.get("id") or ""),
                              "name": str(nm).strip()})
        elif isinstance(it, str):
            items.append({"id": "", "name": it.strip()})
    return [i for i in items if i["name"]]


def collect(rows):
    """把 FOFA rows 收成 hosts / apex / titles / icp。"""
    hosts, titles, icps = [], [], []
    for r in rows:
        r = list(r) + [""] * (4 - len(r))
        host = norm_host(r[0]) or norm_host(r[1])
        if host and host not in hosts:
            hosts.append(host)
        if r[2] and r[2] not in titles:
            titles.append(r[2])
        if r[3] and r[3] not in icps:
            icps.append(r[3])
    apexes = []
    for h in hosts:
        a = apex_of(h)
        if a and a not in apexes:
            apexes.append(a)
    return hosts, apexes, titles, icps


def run_query(key, rec, q, tag, strength, args, acc):
    """跑一条查询，结果并进 acc[strength]。返回命中主机数。"""
    rows, meta = fofa_search(key, q, args.size, args.sleep, args.no_cache, args.min_points)
    total = meta.get("total", 0) or 0
    rec["queries"].append({"mode": tag, "q": q, "strength": strength, "total": total,
                           "returned": meta.get("returned", 0),
                           "cached": meta.get("cached", False), "error": meta.get("error", "")})
    if meta.get("error"):
        log("  %-22s ERROR %s" % (tag, meta["error"]))
        return 0
    if strength != "strong" and total > args.max_weak_total:
        # 品牌词过宽 = 撞名（例如「顺帮」可能命中一堆无关公司）。宁可不要，也不能污染归属。
        rec["queries"][-1]["suppressed"] = "total %d > --max-weak-total %d" % (total, args.max_weak_total)
        log("  %-22s total=%-6s ⚠ 过宽，按撞名丢弃" % (tag, total))
        return 0
    log("  %-22s total=%-6s returned=%-4d%s" % (tag, total, meta.get("returned", 0),
                                                " (cache)" if meta.get("cached") else ""))
    kept, spam = [], []                       # SEO 垃圾行整行丢弃（留痕，不静默）
    for r in rows:
        rr = list(r) + [""] * (4 - len(r))
        # ⚠ 必须先解 HTML 实体：实测 shiyicd.com 的色情站标题写成
        #   &#x91D1;&#x74F6;...（金瓶双艳…），不 unescape 就绕过中文关键词过滤。
        rr[2] = html.unescape(str(rr[2] or ""))
        if rr[2] and SPAM_TITLE_PAT.search(rr[2]):
            spam.append(str(rr[2])[:70])
        else:
            kept.append(r)
    if spam:
        rec["spam_rows_dropped_count"] = rec.get("spam_rows_dropped_count", 0) + len(spam)
        rec.setdefault("spam_rows_dropped", [])
        rec["spam_rows_dropped"].extend(spam[:3])   # 样本只留 3 条，计数才是真值
        log("  %-22s 丢弃 SEO 垃圾行 %d 条（标题含赌博/推广词）" % (tag, len(spam)))
    rows = kept
    hosts, apexes, titles, icps = collect(rows)
    a = acc[strength]
    a["hosts"].update(hosts)
    a["apexes"].update(apexes)
    for t in titles:
        if t not in a["titles"]:
            a["titles"].append(t)
    for i in icps:
        if i not in a["icp"]:
            a["icp"].append(i)
    return len(hosts)


def reverse_one(key, comp, args):
    rec = {"company_id": comp["id"], "company_name": comp["name"], "queries": [],
           "hosts": [], "apex_domains": [], "titles": [], "icp": [], "verdict": "UNSURE"}
    acc = {s: {"hosts": set(), "apexes": set(), "titles": [], "icp": []}
           for s in ("strong", "mid", "weak")}
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    vs = variants(comp["name"])
    rec["variants"] = [{"name": v, "strength": s} for v, s in vs]
    full = vs[0][0]
    for mode in modes:                       # 第一跳永远用全称（精度最高）
        run_query(key, rec, '%s="%s"' % (mode, full), "%s(full)" % mode, "strong", args, acc)
    if not acc["strong"]["hosts"] and not args.no_deep:
        for var, strength in vs[1:]:         # 只在全称 0 命中时才降级，省额度
            log("  全称 0 命中 → 降级试 %s「%s」" % (strength, var))
            for mode in modes:
                run_query(key, rec, '%s="%s"' % (mode, var), "%s(%s)" % (mode, strength),
                          strength, args, acc)
            if acc[strength]["hosts"]:
                break
    for s in ("strong", "mid", "weak"):
        for h in sorted(acc[s]["hosts"]):
            if h not in rec["hosts"]:
                rec["hosts"].append(h)
                if s != "strong":
                    rec.setdefault("weak_hosts", []).append(h)
        for a in sorted(acc[s]["apexes"]):
            if s == "strong":
                if a not in rec["apex_domains"]:
                    rec["apex_domains"].append(a)
            else:
                rec.setdefault("weak_apex_domains", [])
                if a not in rec["weak_apex_domains"]:
                    rec["weak_apex_domains"].append(a)
        for t in acc[s]["titles"]:
            if t not in rec["titles"]:
                rec["titles"].append(t)
        for i in acc[s]["icp"]:
            if i not in rec["icp"]:
                rec["icp"].append(i)
    # 噪声分流：不删只标（AGENTS.md §5 禁止静默丢弃）
    noise = [a for a in rec["apex_domains"] + rec.get("weak_apex_domains", []) if a in NOISE_APEX]
    if noise:
        rec["noise_apex"] = noise
        rec["apex_domains"] = [a for a in rec["apex_domains"] if a not in NOISE_APEX]
        rec["weak_apex_domains"] = [a for a in rec.get("weak_apex_domains", [])
                                    if a not in NOISE_APEX]
    rec["strong_icp"] = sorted(acc["strong"]["icp"])   # 只认强证据的备案号（见 pivot_icp 说明）
    if rec["apex_domains"]:
        rec["verdict"] = "HIT"
    elif rec.get("weak_apex_domains"):
        rec["verdict"] = "CANDIDATE"
        rec["must_verify"] = ("仅简称/品牌词命中 ⇒ 有撞名风险，动手前必须走 "
                              "人工看一眼站点归属，并决定是否纳入项目 scope")
    else:
        rec["unsure_reason"] = ("cert/title 对全称及简称均 0 命中 —— 可能无 OV 证书、"
                                " 或站名不含公司名。需改走 ICP 备案反查 / 工商信息人工补。")
    rec["hosts"] = rec["hosts"][: args.max_hosts]
    return rec


def cmd_report(args):
    p = Path(args.report)
    if not p.is_absolute():
        p = ROOT.parent / p if (ROOT.parent / p).exists() else (ROOT / p)
    data = json.loads(p.read_text("utf-8"))
    recs = data.get("companies", data if isinstance(data, list) else [])
    print_summary(recs, str(p))
    return 0


def print_summary(recs, path):
    hit = [r for r in recs if r.get("verdict") == "HIT"]
    cand = [r for r in recs if r.get("verdict") == "CANDIDATE"]
    unsure = [r for r in recs if r.get("verdict") not in ("HIT", "CANDIDATE")]
    all_apex, weak_apex = [], []
    for r in hit:
        for a in r.get("apex_domains", []):
            if a not in all_apex:
                all_apex.append(a)
    for r in hit + cand:
        for a in r.get("weak_apex_domains", []):
            if a not in weak_apex:
                weak_apex.append(a)
    out("")
    out("=" * 74)
    out("## 反查结果：HIT %d / CANDIDATE %d / UNSURE %d 家；apex 域名 确定 %d + 候选 %d"
        % (len(hit), len(cand), len(unsure), len(all_apex), len(weak_apex)))
    out("=" * 74)
    for r in hit:
        out("- %-30s %3d 主机  %s" % (r["company_name"][:30], len(r.get("hosts", [])),
                                     ", ".join(r.get("apex_domains", [])[:6])))
    if cand:
        out("")
        out("## CANDIDATE（**只是候选**：简称/品牌词命中，有撞名风险 ⇒ 必须先过归属预检）")
        for r in cand:
            out("- %-30s %3d 主机  %s" % (r["company_name"][:30], len(r.get("hosts", [])),
                                          ", ".join(r.get("weak_apex_domains", [])[:6])))
    if unsure:
        out("")
        out("## UNSURE（**没结果不等于没资产**，别静默丢 —— 需人工/ICP 兜底）")
        for r in unsure:
            errs = [q.get("error") for q in r.get("queries", []) if q.get("error")]
            why = ("查询报错: %s" % errs[0]) if errs else "全称+简称+品牌词均 0 命中"
            out("- %-30s %s" % (r["company_name"][:30], why))
    noise = sorted({a for r in recs for a in r.get("noise_apex", [])})
    if noise:
        out("")
        out("## 已标噪声 apex（隧道域名/企业名录站；**未删除**，只是不计入域名）: %s" % ", ".join(noise[:10]))
    out("")
    out("产物: %s" % path)
    if all_apex or weak_apex:
        out("下一步（**动手前必过归属预检**）：")
        out("  纳入范围后写进 state/pt-targets.json，并在 engagement.py 里登记")
    return 0


def pivot_icp(key, recs, args):
    """第二跳：拿第一跳里看到的**备案号**去查同备案主体的兄弟站。
    实测 icp="京ICP备20210253" → 50 条（同一备案主体下的其它域名）= 免费扩线。
    """
    pairs = []
    for r in recs:
        # 默认**只吃强证据**（全称命中那批）里的备案号：实测用弱命中（品牌词）的备案号扩线会炸 ——
        # 例：浙江顺帮 title(顺帮网络科技) 命中的页面带着「浙ICP备20210071」，一 pivot 出 774 条，
        # 那显然不是一家小公司的备案号（页面只是提到了它）。弱证据扩线 = 把噪声放大 100 倍。
        vals = r.get("icp", []) if args.pivot_weak else (r.get("strong_icp") or [])
        for v in vals:
            if v and (v, r["company_name"]) not in pairs:
                pairs.append((v, r["company_name"]))
    if not pairs:
        log("--pivot-icp: 第一跳没收到备案号，跳过")
        return {}
    log("--pivot-icp: %d 个备案号待扩线" % len(pairs))
    piv = {}
    for v, name in pairs[: args.max_pivot]:
        q = 'icp="%s"' % v
        rows, meta = fofa_search(key, q, args.size, args.sleep, args.no_cache, args.min_points)
        log("  %s (%s) -> total=%s" % (v, name[:12], meta.get("total")))
        hosts, apexes, _t, _i = collect(rows)
        piv[v] = {"query": q, "company": name, "total": meta.get("total", 0), "hosts": hosts}
        for r in recs:
            if r["company_name"] == name:
                for a in apexes:
                    if a not in r["apex_domains"]:
                        r["apex_domains"].append(a)
                        r.setdefault("pivot_domains", []).append(a)
    return piv


def main():
    # 与 recon_api.py 保持一致：本工具是**流水线工具**（输出给 job.py tail / 大脑读），
    # 不是取证截图脚本 —— 后者按 AGENTS.md §7 只加 errors="replace" 跟随控制台编码。
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="FOFA 反查：公司名 -> 资产（被动，不碰目标）")
    ap.add_argument("--from", dest="from_file", default="state/pt-targets.json",
                    help="目标清单文件（默认 state/pt-targets.json）")
    ap.add_argument("--key", default="yes", help="清单文件是 dict 时取哪个键")
    ap.add_argument("--vendor", help="只查一家（公司全称），与 --from 二选一")
    ap.add_argument("--modes", default=",".join(FIELD_ORDER),
                    help="反查模式，逗号分隔。默认 cert,title（实测只有这两个对公司名有效）")
    ap.add_argument("--size", type=int, default=200, help="每次查询取回条数上限")
    ap.add_argument("--limit", type=int, default=0, help="只处理前 N 家（0=全部）")
    ap.add_argument("--max-hosts", type=int, default=60, help="每家保留主机数上限（报告用）")
    ap.add_argument("--sleep", type=float, default=3.0, help="调用间隔秒（背靠背必 429）")
    ap.add_argument("--pivot-icp", action="store_true", help="第二跳：按备案号扩线")
    ap.add_argument("--max-pivot", type=int, default=20, help="pivot 备案号个数上限")
    ap.add_argument("--pivot-weak", action="store_true",
                    help="pivot 也吃弱命中的备案号（默认不吃：实测会把噪声放大百倍）")
    ap.add_argument("--min-points", type=int, default=50, help="免费额度低于此值就停")
    ap.add_argument("--no-deep", action="store_true", help="只用公司全称，不做简称/品牌词降级")
    ap.add_argument("--max-weak-total", type=int, default=300,
                    help="弱查询命中数超过此值视为撞名，丢弃该查询结果（默认 300）")
    ap.add_argument("--retry-unsure", help="复跑某份产物里非 HIT 的厂商（可与 --pivot-icp 合用）")
    ap.add_argument("--no-cache", action="store_true", help="绕过 30 天缓存（会烧额度）")
    ap.add_argument("--out", help="产物 json 路径")
    ap.add_argument("--report", help="复读已有产物，不发任何请求")
    args = ap.parse_args()

    if args.report:
        return cmd_report(args)

    key = load_fofa_key()
    if not key:
        out("UNSURE: 没读到 FOFA key（state/private/fofa.env 的 FOFA_KEY）—— 交回大脑处理")
        return 2

    if args.retry_unsure:
        prev = json.loads(Path(args.retry_unsure).read_text("utf-8"))
        comps = [{"id": r.get("company_id", ""), "name": r["company_name"]}
                 for r in prev.get("companies", []) if r.get("verdict") != "HIT"]
        log("--retry-unsure: 上一份产物里非 HIT 共 %d 家" % len(comps))
    else:
        comps = load_names(args)
    if args.limit:
        comps = comps[: args.limit]
    if not comps:
        out("UNSURE: 清单里没读到公司名 —— 交回大脑")
        return 2
    log("待反查 %d 家；模式=%s；间隔=%.1fs" % (len(comps), args.modes, args.sleep))

    recs = []
    for i, comp in enumerate(comps, 1):
        log("[%d/%d] %s" % (i, len(comps), comp["name"]))
        try:
            recs.append(reverse_one(key, comp, args))
        except Exception as exc:
            recs.append({"company_id": comp["id"], "company_name": comp["name"],
                         "verdict": "UNSURE", "queries": [],
                         "unsure_reason": "%s: %s" % (type(exc).__name__, exc)})
            log("  ! 异常，记 UNSURE：%s" % exc)

    pivots = {}
    if args.pivot_icp:
        pivots = pivot_icp(key, recs, args)

    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    outp = Path(args.out) if args.out else (ROOT / "state" / ("fofa-reverse-%s.json" % stamp))
    payload = {"generated": datetime.now().isoformat(timespec="seconds"),
               "source": args.from_file if not args.vendor else args.vendor,
               "modes": args.modes, "companies": recs, "icp_pivots": pivots}
    outp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    rdir = ROOT / "results" / ("fofa-reverse-%s" % datetime.now().strftime("%Y%m%d"))
    rdir.mkdir(parents=True, exist_ok=True)
    apex = []
    for r in recs:
        for a in r.get("apex_domains", []):
            if a not in apex:
                apex.append(a)
    (rdir / "apex-domains.txt").write_text("\n".join(apex), encoding="utf-8")
    (rdir / "hosts.txt").write_text("\n".join(h for r in recs for h in r.get("hosts", [])),
                                    encoding="utf-8")
    print_summary(recs, str(outp))
    out("旁路产物: %s  (apex-domains.txt / hosts.txt)" % rdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())