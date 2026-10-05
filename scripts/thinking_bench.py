# -*- coding: utf-8 -*-
"""实证: deepseek-v4-flash thinking enabled vs disabled
同一任务同一输入, 只切 thinking 开关, 对照:
- prompt_tokens / completion_tokens(含 reasoning) / total
- 耗时 / 输出长度 / 端点提取质量(GT命中)
"""
import io, json, os, re, sys, time, urllib.request, urllib.error

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
ROOT = r"D:\渗透工作流\_PT工作台"
OUT = os.path.join(ROOT, "results", "thinking-bench-2026-09-08")
os.makedirs(OUT, exist_ok=True)

def ds_key():
    for ln in open(os.path.join(ROOT, "state", "private", "vision.env"), encoding="utf-8"):
        if ln.startswith("API_KEY="):
            return ln.split("=", 1)[1].strip()

PROMPT = """你是安全代码分析器。从代码中机械提取 API 路径(形如 xxx/yyy)，跳过 https:// 完整 URL 与静态资源。
只输出 JSON: {"endpoints": ["users/login", "orders/cancel"]}，无其他文字。"""

# 样本: 真实 JS 段 (8KB, 含 40+ 真实端点)
raw = open(os.path.join(ROOT, "results", "lanxiniu-main-recon-2026-09-06", "h5-index.6cb3b114.js"),
           encoding="utf-8", errors="replace").read()
i = raw.find('driver:"drivers/info"')
chunk = raw[max(0, i - 4000): i + 4000]

# ground truth 关键端点
GT = {"users/verify","users/code","users/login","users/logout","users/destruct","drivers/info",
      "orders/cancel","orders/serving","orders/driver-pickup-loc","orders/contacts-worker",
      "orders/cancel-win","orders/update-order-time","orders/update-car-type","orders/update-order-address",
      "comments/conf","comments/label","collections/drivers","configs/list","configs/all-list",
      "complaint/list","complaint/save","feedbacks/add","feedbacks/detail","feedbacks/reply",
      "instructions/rates","instructions/common_problems","activity/list","coupons/cancel",
      "coupons/convert","coupons/valid","overflow/policy","prices/evaluate-price","gis/reverse",
      "gis/routes","auths/loginbyautotoken"}

def run(label, extra):
    payload = {"model": "deepseek-v4-flash", "temperature": 0.1, "max_tokens": 4000,
               "messages": [{"role": "user", "content": PROMPT + "\n---CODE---\n" + chunk}]}
    payload.update(extra)
    req = urllib.request.Request("https://api.deepseek.com/v1/chat/completions",
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + ds_key()})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=300) as r:
        out = json.loads(r.read().decode())
    dt = round(time.time() - t0, 2)
    ch = out["choices"][0]["message"]
    content = ch.get("content") or ""
    use = out.get("usage", {})
    eps = set(re.findall(r'(?<![a-z0-9_/])([a-z][a-z0-9_]{1,30}/[a-z0-9_/]{1,50})(?![a-z0-9_/])', content))
    hit = eps & GT
    rec = {
        "label": label, "secs": dt, "finish": out["choices"][0].get("finish_reason"),
        "content_len": len(content), "eps_found": len(eps), "gt_hit": len(hit), "gt_miss": sorted(GT - hit),
        "usage": {"prompt": use.get("prompt_tokens"), "completion": use.get("completion_tokens"),
                  "total": use.get("total_tokens"),
                  "reasoning": use.get("completion_tokens_details", {}).get("reasoning_tokens"),
                  "cache_hit": use.get("prompt_tokens_details", {}).get("cached_tokens")},
        "content_head": content[:120],
    }
    print(f"[{label}] {dt}s total={rec['usage']['total']} reasoning={rec['usage']['reasoning']} "
          f"eps={len(eps)} gt_hit={len(hit)}/{len(GT)}", flush=True)
    return rec

results = []
# 每种跑 2 次取稳
for round_i in range(1, 3):
    results.append(run(f"thinking-ON-{round_i}", {}))
    results.append(run(f"thinking-OFF-{round_i}", {"thinking": {"type": "disabled"}}))
    time.sleep(1)

json.dump(results, open(os.path.join(OUT, "bench.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)

# 汇总均值
def avg(rows, key):
    vals = [r[key] for r in rows if isinstance(r.get(key), (int, float))]
    return round(sum(vals) / len(vals), 1) if vals else 0
on = [r for r in results if "ON" in r["label"]]
off = [r for r in results if "OFF" in r["label"]]
print("\n=== 汇总(2次均值) ===")
print(f"{'指标':<16}{'thinking ON':>14}{'thinking OFF':>14}{'节省':>10}")
for k, disp in [("secs","耗时s"), ("usage.total","总token"), ("usage.completion","输出token"),
                ("usage.reasoning","其中思考token")]:
    a, b = avg(on, k), avg(off, k)
    pct = round((1 - b / a) * 100) if a else 0
    print(f"{disp:<16}{a:>14.1f}{b:>14.1f}{str(pct)+'%':>10}")
ga, gb = avg(on, "gt_hit"), avg(off, "gt_hit")
print(f"{'GT命中数':<16}{ga:>14.1f}{gb:>14.1f}")
print("\n[*] DONE -> thinking-bench-2026-09-08/bench.json")
