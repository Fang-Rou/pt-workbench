
# -*- coding: utf-8 -*-
"""泛解析主机 HTTP 层甄别（2026-09-11）。

背景: hotprefix_dns2 的 DNS 基线只采了**一次**随机样本, 而泛解析可能有多条 A 记录,
命名前缀返回池里另一个成员就被误判成「真主机」—— 实测 46 条"真实主机" 100% 是误报。
但 DNS 相同 != 没东西: 泛解析常指向**按 Host 路由的反向代理**, harbor.66law.cn 可能真在跑 Harbor。
所以判据要下沉到 HTTP 层: 拿随机前缀 Host 的响应做基线, 比对命名前缀 Host 的响应。
  与基线一致 -> 兜底页(CATCHALL), 无价值
  与基线不同 -> 真实业务(REAL), 进下一步
只读探测: 每台最多 2 个请求(GET 首页), 不猜路径、不爆破。
"""
import sys, json, random, string, pathlib, ssl, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, 'scripts')
import urllib.request, urllib.error
from net_helper import UA_BROWSER

OUT = pathlib.Path('results/hotprefix-http-20260911'); OUT.mkdir(parents=True, exist_ok=True)
j = json.loads(pathlib.Path('results/hotprefix-dns-20260911/resolved-real.json').read_text(encoding='utf-8'))
live = [r for r in j if r[3] != 'NXDOMAIN']

def rnd(n=12):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def fetch(host, scheme='https', timeout=12):
    url = '%s://%s/' % (scheme, host)
    req = urllib.request.Request(url, headers={'User-Agent': UA_BROWSER, 'Accept': '*/*'})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            b = r.read(60000)
            return {'code': r.status, 'len': len(b),
                    'title': (b.decode('utf-8', 'ignore').split('<title>')[-1].split('</title>')[0][:60] if b'<title>' in b[:20000] else ''),
                    'srv': r.headers.get('Server', ''), 'scheme': scheme}
    except urllib.error.HTTPError as e:
        return {'code': e.code, 'len': 0, 'title': '', 'srv': e.headers.get('Server', '') if e.headers else '', 'scheme': scheme}
    except Exception as e:
        return {'code': None, 'err': type(e).__name__, 'scheme': scheme}

random.seed(20260911)
doms = sorted({r[1] for r in live})
base = {}
for dom in doms:
    for s in ('https', 'http'):
        base[(dom, s)] = fetch('%s.%s' % (rnd(), dom), s)
    print('基线 %-14s https=%s http=%s' % (dom, base[(dom,'https')], base[(dom,'http')]), flush=True)

rep = []
for pre, dom, _b, ip in live:
    host = '%s.%s' % (pre, dom)
    row = {'host': host, 'ip': ip, 'prefix': pre, 'domain': dom}
    for s in ('https', 'http'):
        r = fetch(host, s)
        row[s] = r
        if r.get('code') and r.get('code') not in (502, 503, 504):
            b = base.get((dom, s), {})
            same = (r.get('code') == b.get('code') and abs((r.get('len') or 0) - (b.get('len') or 0)) <= 64)
            row['verdict'] = 'CATCHALL' if same else 'REAL'
            row['baseline'] = b
            break
    else:
        row['verdict'] = 'DEAD'
    rep.append(row)
    print('  %-28s %s' % (host, row.get('verdict')), flush=True)
    time.sleep(0.3)

(OUT/'http-classify.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8')
import collections
c = collections.Counter(r['verdict'] for r in rep)
print('\n分类统计:', dict(c))
for r in rep:
    if r['verdict'] == 'REAL':
        print('  REAL %-28s %s' % (r['host'], json.dumps({k: r.get(k) for k in ('https','http')}, ensure_ascii=False)[:200]))
