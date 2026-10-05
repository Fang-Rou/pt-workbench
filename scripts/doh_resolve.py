# -*- coding: utf-8 -*-
"""doh_resolve.py - 本地 DNS 不可靠时的 DoH 解析补丁（可复用）。

背景（2026-09-12 爱玛实测）：`socket.getaddrinfo` 对多 A 轮询的 *.aimatech.com **间歇性**
返回 `[Errno 11001] getaddrinfo failed`，而同一时刻 DoH（dns.alidns.com / doh.pub）解析正常、
PowerShell 也正常 —— 属**本地解析器侧**问题，不是目标不可达。若不处理，会误判成"主机死了"。

用法：
    import doh_resolve
    doh_resolve.install()      # 之后所有 urllib/requests/socket 连接都走 DoH 解析
    ...
    doh_resolve.install(fallback=True)   # DoH 失败时回退系统解析（默认 True）

机制：monkeypatch `socket.getaddrinfo`，先查 DoH 缓存，命中即返回 A 记录，否则回退原函数。
纪律：只解析、不改 TLS 校验策略；不落任何目标数据。
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import sys
import urllib.request

_CACHE: dict[str, list[str]] = {}
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
_ENDPOINTS = ("https://dns.alidns.com/resolve?name=%s&type=A",
              "https://doh.pub/dns-query?name=%s&type=A")
_RX_IP = re.compile(r'"data"\s*:\s*"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"')
_INSTALLED = False
_IN_RESOLVE = False   # 防重入：DoH 请求自身的解析必须走系统解析，否则无限递归


def resolve(host: str, timeout: float = 8.0) -> list[str]:
    """DoH 解析域名 -> IPv4 列表（带进程内缓存）。失败返回 []。

    ⚠ 重入保护：本函数内部用 urlopen 访问 DoH 端点，而 urlopen 又会调 getaddrinfo。
    安装补丁后若不拦，就会「解析 -> 请求 DoH -> 解析 DoH 域名 -> 再请求 DoH」无限递归，
    最终表现为目标域名 `getaddrinfo failed`（2026-09-12 实测踩坑）。
    """
    global _IN_RESOLVE
    if host in _CACHE:
        return _CACHE[host]
    if _IN_RESOLVE:
        return []          # 交给上层 fallback 走系统解析
    _IN_RESOLVE = True
    ips: list[str] = []
    try:
        ips = _resolve_uncached(host, timeout)
    finally:
        _IN_RESOLVE = False
    if ips:
        _CACHE[host] = ips
    return ips


def _resolve_uncached(host: str, timeout: float) -> list[str]:
    ips: list[str] = []
    for tpl in _ENDPOINTS:
        try:
            req = urllib.request.Request(tpl % host, headers={"User-Agent": "curl/8",
                                                              "Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
                body = r.read(20000).decode("utf-8", "ignore")
            ips = list(dict.fromkeys(_RX_IP.findall(body)))
            if ips:
                break
        except Exception:
            continue
    return ips


def install(fallback: bool = True) -> None:
    """monkeypatch socket.getaddrinfo：优先 DoH，失败回退系统解析。"""
    global _INSTALLED
    if _INSTALLED:
        return
    real = socket.getaddrinfo

    def patched(host, port, family=0, type=0, proto=0, flags=0, *a, **kw):
        h = host if isinstance(host, str) else None
        if h and not h.replace(".", "").isdigit() and ":" not in h:
            ips = resolve(h)
            if ips:
                out = []
                for ip in ips:
                    try:
                        out.append((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)))
                    except Exception:
                        pass
                if out:
                    return out
        if fallback:
            return real(host, port, family, type, proto, flags, *a, **kw)
        raise socket.gaierror(11001, "DoH 解析失败且未启用系统回退")

    socket.getaddrinfo = patched  # type: ignore[assignment]
    _INSTALLED = True


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    for h in sys.argv[1:] or ["am-982-ops.aimatech.com", "eam.aimatech.com"]:
        import time
        t0 = time.time()
        ips = resolve(h)
        print("%-32s -> %-46s (%.2fs)" % (h, ips[:4] or "FAIL", time.time() - t0))
