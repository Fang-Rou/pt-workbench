# -*- coding: utf-8 -*-
"""vision_qa.py - 调用 DeepSeek vision 模型给截图做 QA（AI 的眼睛）。
用法:
  python scripts/vision_qa.py <图片路径> [图片路径...] --q "问题"
  python scripts/vision_qa.py <dir> --q "问题"        # 目录内全部 png
密钥: state/private/vision.env (BASE_URL/API_KEY/MODEL), 不落日志不打印。
"""
from __future__ import annotations
import argparse, base64, io, json, sys
from pathlib import Path
import urllib.request

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / 'state' / 'private' / 'vision.env'

def load_env():
    d = {}
    for ln in ENV.read_text(encoding='utf-8').splitlines():
        if '=' in ln:
            k, v = ln.split('=', 1)
            d[k.strip()] = v.strip()
    return d

def img_data_uri(p: Path) -> str:
    return 'data:image/png;base64,' + base64.b64encode(p.read_bytes()).decode()

def ask(base_url, key, model, content_parts, question, think=False):
    payload = {
        'model': model,
        'messages': [{'role': 'user', 'content': [
            {'type': 'text', 'text': question},
        ] + content_parts}],
        'temperature': 0.1,
        'max_tokens': 2000,
        'stream': False,
    }
    # AGENTS.md 云端调用规范: 机械判读类默认关思考(实证省 92% 耗时/91% 输出 token);
    # 仅复杂推理/多跳分析才 --think 打开。UNSURE: vision 回答含糊时改用 --think 重问。
    if not think:
        payload['thinking'] = {'type': 'disabled'}
    req = urllib.request.Request(base_url.rstrip('/') + '/chat/completions',
                                 data=json.dumps(payload).encode('utf-8'),
                                 headers={'Content-Type': 'application/json',
                                          'Authorization': 'Bearer ' + key})
    with urllib.request.urlopen(req, timeout=120) as resp:
        out = json.loads(resp.read().decode('utf-8'))
    return out['choices'][0]['message']['content']

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--each', action='store_true', help='多图逐张单独QA')
    ap.add_argument('--think', action='store_true', help='开思考(默认关: 机械判读快且省token; 复杂推演/含糊回答才开)')
    ap.add_argument('--q', default='检查这张窗口截图的准确性：1)浏览器地址栏是否可见且完整显示目标URL？2)页面关键内容（若有凭据行/命令输出/错误码等）是否清晰可见？3)画面是否空白、黑屏或模糊？4)整体是否像真实浏览器窗口截图？逐条回答 是/否+一句话理由。')
    args = ap.parse_args()
    env = load_env()
    base_url = env.get('BASE_URL'); key = env.get('API_KEY'); model = env.get('MODEL')
    if not (base_url and key and model):
        print('FAIL: vision.env 缺字段'); return 2
    imgs = []
    for p in args.paths:
        p = Path(p)
        if p.is_dir():
            imgs += sorted(p.glob('*.png'))
        elif p.is_file() and p.suffix.lower() in ('.png', '.jpg', '.jpeg', '.webp'):
            imgs.append(p)
    if not imgs:
        print('FAIL: 无图片'); return 2
    parts = []
    for im in imgs:
        parts.append({'type': 'image_url', 'image_url': {'url': img_data_uri(im)}})
    q = args.q + '\n图片文件名: ' + ', '.join(i.name for i in imgs)
    outdir = ROOT / 'results' / 'vision-qa'
    outdir.mkdir(parents=True, exist_ok=True)
    try:
        if args.each and len(imgs) > 1:
            for im in imgs:
                one_q = args.q + '\n图片文件名: ' + im.name
                ans = ask(base_url, key, model, [{'type': 'image_url', 'image_url': {'url': img_data_uri(im)}}], one_q, args.think)
                (outdir / (im.stem + '.qa.txt')).write_text(ans, 'utf-8')
                print('==', im.name, '::', ans.replace('\n', ' | ')[:400], flush=True)
        else:
            ans = ask(base_url, key, model, parts, q, args.think)
            print(ans, flush=True)
    except urllib.error.HTTPError as e:
        print('API HTTP', e.code, e.read(500).decode('utf-8', 'replace')[:500]); return 1
    except Exception as e:
        print('API ERR', str(e)[:300]); return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())