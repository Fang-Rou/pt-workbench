
# -*- coding: utf-8 -*-
"""制品仓库前缀专项 DNS 扫描（2026-09-11）。
补齐 hotprefix_dns2 前缀表的空白：那轮没有 artifactory/maven/repo/npm/docker/jfrog 等制品仓库词。
基线沿用修正版：多样本收泛解析 IP 池 + getaddrinfo 取全量 A 记录 + 私网单列。
"""
import json, pathlib, sys, socket, ipaddress, secrets, concurrent.futures as cf
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = pathlib.Path('results/artifactrepo-dns-20260911'); OUT.mkdir(parents=True, exist_ok=True)
rows = json.loads((pathlib.Path('results')/'gongyi-domains-2026-08-19.json').read_text('utf-8'))
def apex(h):
    h = h.strip().lower()
    return h[4:] if h.startswith('www.') else h
DOMS = sorted({apex(r['host']) for r in rows if r.get('host') and '.' in r.get('host')})
PREFIX = ['artifactory','maven','repo','repos','repository','npm','pypi','docker','jfrog','gitea',
          'bitbucket','gogs','gitlab','git','svn','mirrors','mirror','cache','registry','nexus',
          'harbor','package','packages','libs','library','binary','binaries','download','downloads',
          'static','files','file','oss','storage','minio','s3','cdn']
socket.setdefaulttimeout(3)
WILD_SAMPLES = 6
def geth_all(h):
    try: return {i[4][0] for i in socket.getaddrinfo(h, None)}
    except Exception: return set()
def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)
    except Exception: return False
print('域名 %d, 前缀 %d' % (len(DOMS), len(PREFIX)), flush=True)
wild = {}
def pool_of(d):
    p = set()
    for _ in range(WILD_SAMPLES):
        p |= geth_all('%s-%s.%s' % (secrets.token_hex(4), secrets.token_hex(3), d))
    return p
with cf.ThreadPoolExecutor(max_workers=60) as ex:
    futs = {ex.submit(pool_of, d): d for d in DOMS}
    for f in cf.as_completed(futs): wild[futs[f]] = f.result()
print('有泛解析的域名 %d' % sum(1 for v in wild.values() if v), flush=True)
def probe(t):
    p, d = t
    ips = geth_all('%s.%s' % (p, d))
    if not ips: return None
    extra = ips - (wild.get(d) or set())
    if not extra: return None
    pub = sorted(x for x in extra if is_public(x))
    priv = sorted(x for x in extra if not is_public(x))
    return (p, d, '|'.join(pub) if pub else '', '|'.join(priv) if priv else '')
tasks = [(p, d) for d in DOMS for p in PREFIX]
found = []
with cf.ThreadPoolExecutor(max_workers=80) as ex:
    for r in ex.map(probe, tasks):
        if r: found.append(r)
pub = [r for r in found if r[2]]
priv = [r for r in found if not r[2]]
(OUT/'resolved.json').write_text(json.dumps(found, ensure_ascii=False, indent=1), encoding='utf-8')
print(); print('=== 命中 %d (公网可达 %d / 仅私网 %d) ===' % (len(found), len(pub), len(priv)))
for p, d, pu, pr in sorted(pub, key=lambda x: x[0]):
    print('   %-14s %-32s %s' % (p, d, pu))
if priv:
    print('  [仅私网, 不可测]')
    for p, d, pu, pr in priv[:15]: print('   %-14s %-32s %s' % (p, d, pr))
