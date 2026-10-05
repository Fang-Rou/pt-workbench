# -*- coding: utf-8 -*-
"""高价值前缀 DNS 扫描 v2 —— 剔除泛解析（wildcard DNS）噪声。

方法：每个域名先采**一组**随机前缀，收成「泛解析 IP 池」；
命名前缀解析出的地址若**全部**落在池内，判为噪声；只要有一个在池外才算真实主机。

2026-09-11 修（重要）：v2 早期版本每个域名只解析**一个**随机前缀当基线，
而泛解析可以配多条 A 记录（round-robin）—— 命名前缀返回池里**另一个**成员时，
与单样本基线不相等，就被误判成「真实主机」。
实测代价：66law.cn / bkwgc.com / ce-inv.com / cread.com / haust.edu.cn 五个域名
报出 46 条「真实主机」，**100% 是这种误报，真实候选为 0**。
所以基线必须多采样（WILD_SAMPLES），且解析要用 getaddrinfo 取全量 A 记录，
不能用 gethostbyname（只返回一条，天然采不全池）。

注意：DNS 相同 != 没东西 —— 泛解析常指向**按 Host 路由的反向代理**。
本脚本只做 DNS 层粗筛，命中与否都要再用 HTTP 响应对比（随机 Host 做基线）确认，
见 scripts/hotprefix_http_check.py。
"""
import json, pathlib, sys, socket, ipaddress, concurrent.futures as cf, collections, secrets
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = pathlib.Path('results/hotprefix-dns-20260911'); OUT.mkdir(parents=True, exist_ok=True)
rows = json.loads((pathlib.Path('results')/'gongyi-domains-2026-08-19.json').read_text('utf-8'))
def apex(h):
    h = h.strip().lower()
    return h[4:] if h.startswith('www.') else h
DOMS = sorted({apex(r['host']) for r in rows if r.get('host') and '.' in r.get('host')})
PREFIX = ['harbor','git','gitlab','jenkins','nexus','registry','rancher','grafana','kibana','zabbix',
          'nacos','minio','jira','sonar','argocd','drone','yapi','apollo','skywalking','sentry']
socket.setdefaulttimeout(3)
WILD_SAMPLES = 6   # 每域名随机采样次数; 见 docstring「2026-09-11 修」

def geth_all(h):
    """返回该名字解析出的**全部** A 记录。gethostbyname 只给一条, 采不全泛解析池。"""
    try:
        return {i[4][0] for i in socket.getaddrinfo(h, None)}
    except Exception:
        return set()
print('域名 %d 个, 前缀 %d 个' % (len(DOMS), len(PREFIX)), flush=True)
# 1) 泛解析基准 —— 多采样收池（单样本会漏掉 round-robin 的其余成员）
wild = {}
def wild_pool(d):
    pool = set()
    for _ in range(WILD_SAMPLES):
        pool |= geth_all('%s-%s.%s' % (secrets.token_hex(4), secrets.token_hex(3), d))
    return pool
with cf.ThreadPoolExecutor(max_workers=60) as ex:
    futs = {ex.submit(wild_pool, d): d for d in DOMS}
    for f in cf.as_completed(futs):
        wild[futs[f]] = f.result()
nwild = sum(1 for v in wild.values() if v)
print('存在泛解析的域名 %d / %d (每域名采样 %d 次)' % (nwild, len(DOMS), WILD_SAMPLES), flush=True)
# 2) 真实前缀探测
tasks = [(p, d) for d in DOMS for p in PREFIX]
def probe(t):
    p, d = t
    ips = geth_all('%s.%s' % (p, d))
    if not ips: return None
    pool = wild.get(d) or set()
    extra = ips - pool
    if not extra: return None            # 全部落在泛解析池内 -> 噪声
    return (p, d, '|'.join(sorted(extra)), '|'.join(sorted(pool)) if pool else 'NXDOMAIN')
found = []
with cf.ThreadPoolExecutor(max_workers=80) as ex:
    for r in ex.map(probe, tasks):
        if r: found.append(r)
(OUT/'resolved-real.json').write_text(json.dumps(found, ensure_ascii=False, indent=1), encoding='utf-8')
# 3) 私网地址单列 —— 2026-09-11 补: 公网 DNS 解析到 10.x/192.168.x 时该主机**公网不可达**,
#    是「内网服务名泄露」而不是可测主机。早期版本把它并进「真实命中」,
#    输出 51 台里其实有 15 台根本连不上 —— 属测量层误导, 与泛解析误报同类。
def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)
    except Exception:
        return False

pub = [r for r in found if any(_is_public(x) for x in r[2].split('|'))]
priv = [r for r in found if r not in pub]
print(); print('=== 剔除泛解析后的真实命中 %d (公网可达 %d / 仅私网不可达 %d) ==='
             % (len(found), len(pub), len(priv)))
if priv:
    print('  [仅私网, 不可测, 属内网服务名泄露]')
    for p, d, ip, ws in sorted(priv, key=lambda x: x[1]):
        print('     %-12s %-40s %-16s' % (p, d, ip))
KEY = ('harbor','git','gitlab','jenkins','nexus','registry','rancher','grafana','kibana','zabbix','nacos','minio','jira','sonar','argocd','drone','yapi','apollo','skywalking','sentry')
for p, d, ip, ws in sorted(found, key=lambda x: (KEY.index(x[0]) if x[0] in KEY else 99, x[1])):
    print('   %-12s %-40s %-16s (泛解析=%s)' % (p, d, ip, ws))