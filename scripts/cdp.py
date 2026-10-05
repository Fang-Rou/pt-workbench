# -*- coding: utf-8 -*-
"""CDP 客户端工具库：连 9223，创建/操作页面，执行 JS，上传文件。"""
from __future__ import annotations

import asyncio
import json
import sys
import urllib.request

import websockets

WS_URL = "http://127.0.0.1:9223"


def browser_ws_url() -> str:
    with urllib.request.urlopen(f"{WS_URL}/json/version", timeout=5) as r:
        return json.loads(r.read())["webSocketDebuggerUrl"]


class CDP:
    def __init__(self, ws):
        self.ws = ws
        self._id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self.session_ids: dict[str, str] = {}
        self.events: list[dict] = []   # 2026-09-12 加：收集 CDP 事件（如 Network.*），供抓真实请求用

    def take_events(self, method_prefix: str = "") -> list[dict]:
        """取出并清空事件（可按方法名前缀过滤）。"""
        got = [e for e in self.events if e.get("method", "").startswith(method_prefix)]
        self.events = [e for e in self.events if not e.get("method", "").startswith(method_prefix)]
        return got

    @classmethod
    async def connect(cls):
        ws = await websockets.connect(browser_ws_url(), subprotocols=["chrome-devtools"],
                                      max_size=None, open_timeout=10)
        c = cls(ws)
        asyncio.create_task(c._reader())
        return c

    async def _reader(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg and msg["id"] in self._pending:
                    fut = self._pending.pop(msg["id"])
                    if not fut.done():
                        fut.set_result(msg)
                elif "method" in msg:
                    self.events.append(msg)
        except Exception:
            pass

    async def cmd(self, method: str, params: dict | None = None, session_id: str | None = None,
                  timeout: float = 30) -> dict:
        self._id += 1
        mid = self._id
        fut = asyncio.get_event_loop().create_future()
        self._pending[mid] = fut
        msg = {"id": mid, "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        await self.ws.send(json.dumps(msg))
        try:
            resp = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(mid, None)
            raise TimeoutError(f"CDP timeout: {method}")
        if "error" in resp:
            raise RuntimeError(f"CDP error {method}: {resp['error']}")
        return resp.get("result", {})

    async def new_page(self, url: str = "about:blank") -> tuple[str, str]:
        """创建 tab，返回 (targetId, sessionId)。"""
        res = await self.cmd("Target.createTarget", {"url": url})
        tid = res["targetId"]
        att = await self.cmd("Target.attachToTarget", {"targetId": tid, "flatten": True})
        sid = att["sessionId"]
        self.session_ids[tid] = sid
        return tid, sid

    async def eval_js(self, sid: str, expr: str, await_promise: bool = True) -> dict:
        """Runtime.evaluate，返回 result.value 或异常文本。"""
        res = await self.cmd("Runtime.evaluate",
                             {"expression": expr, "returnByValue": True,
                              "awaitPromise": await_promise},
                             session_id=sid, timeout=40)
        if "exceptionDetails" in res:
            return {"__error__": json.dumps(res["exceptionDetails"], ensure_ascii=False)[:300]}
        return res.get("result", {}).get("value")

    async def set_file_input(self, sid: str, selector: str, file_path: str) -> bool:
        """DOM.setFileInputFiles 上传文件。"""
        doc = await self.cmd("DOM.getDocument", {"depth": -1}, session_id=sid)
        root = doc["root"]["nodeId"]
        q = await self.cmd("DOM.querySelector",
                           {"nodeId": root, "selector": selector}, session_id=sid)
        nid = q.get("nodeId")
        if not nid or nid == 0:
            return False
        await self.cmd("DOM.setFileInputFiles",
                       {"nodeId": nid, "files": [file_path]}, session_id=sid)
        return True

    async def close(self):
        try:
            await self.ws.close()
        except Exception:
            pass
