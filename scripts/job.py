#!/usr/bin/env python3
"""Detached job runner with SQLite state, heartbeat, logs, and fast resume.

Long commands never block a conversation.  Start a job, then poll it with
`status` / `tail`; the job keeps running even if the chat thread is closed.

Usage (run from _PT工作台):
  $py scripts/job.py start --name jxnu-recon --cmd "$py scripts/probe.py --target X"
  $py scripts/job.py status
  $py scripts/job.py tail 1 --lines 30
  $py scripts/job.py kill 1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
from collections import deque
from datetime import datetime
from pathlib import Path

import workspace_db

ROOT = workspace_db.ROOT
JOBS_DIR = ROOT / "state" / "jobs"
HEARTBEAT_INTERVAL = 5.0
STALE_AFTER_SECONDS = 30.0


def _slugify(name: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-").lower()
    return text[:48] or "job"


def _log_rel(job_id: int, name: str) -> str:
    return f"state/jobs/{job_id}-{_slugify(name)}.log"


def _read_tail(path: Path, lines: int = 5) -> list[str]:
    if not path.exists():
        return []
    raw_lines = deque(maxlen=lines)
    with path.open("rb") as fh:
        for raw in fh:
            raw_lines.append(raw)
    return [_decode_bytes(raw).rstrip("\r\n") for raw in raw_lines]


def _decode_bytes(raw: bytes) -> str:
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _last_line_summary(path: Path) -> str:
    for line in reversed(_read_tail(path, 10)):
        line = line.strip()
        if line:
            return line[:300]
    return ""


def _spawn_monitor(job_id: int) -> str:
    """派生 monitor 进程，返回所用方式标签。

    2026-09-12 教训（DSH harness）：harness 在每次 shell 工具调用结束时清理该调用的
    整棵进程树，因此 subprocess.Popen(DETACHED_PROCESS) 派生的 monitor **活不过一次
    工具调用**——症状是 job 永远停在 pending、连日志文件都不生成（pid 为 null）。
    Windows 下改用 WMI 的 Win32_Process.Create 派生：新进程挂在 WMI provider 服务下，
    不在调用方的 Job Object 里，实测可存活并正常回报心跳。非 Windows 保留原路径。

    2026-09-12 晚修（用户反馈「老是弹命令框」）：WMI 默认会给新进程一个**可见控制台窗口**
    （CREATE_NO_WINDOW 那个兜底路径是隐藏的，但 WMI 走的是 WMI provider，不继承我们的
    creationflags），于是每起一个后台作业就弹一个黑框、作业不死框不关。
    修法：传 ProcessStartupInformation（Win32_ProcessStartup 实例）并把 ShowWindow=0。
    """
    script = Path(__file__).resolve()
    argv = [sys.executable, str(script), "monitor", str(job_id)]
    if os.name == "nt":
        # 注意：**不要**用 Invoke-CimMethod 传 ProcessStartupInformation ——
        # 实测报「无法从提供的 .NET 对象推断 CimType」（CimType 推断不了 startupinfo 实例），
        # 会静默回落到 popen（于是又被 harness 杀）。必须走 [wmiclass].Create(cmd, cwd, si)。
        ps = (
            "$si = ([wmiclass]'Win32_ProcessStartup').CreateInstance(); "
            "$si.ShowWindow = 0; "
            "$r = ([wmiclass]'Win32_Process').Create($env:JOBPY_CMDLINE, $env:JOBPY_CWD, $si); "
            "if ($r.ReturnValue -ne 0) { exit 9 }; Write-Output $r.ProcessId"
        )
        env = os.environ.copy()
        env["JOBPY_CMDLINE"] = subprocess.list2cmdline(argv)
        env["JOBPY_CWD"] = str(ROOT)
        try:
            p = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                env=env, capture_output=True, text=True, timeout=90,
            )
            if p.returncode == 0 and p.stdout.strip().isdigit():
                return "wmi(pid=%s)" % p.stdout.strip()
        except Exception:
            pass  # 落到下面的兜底路径
        kwargs: dict = {
            "creationflags": (
                subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NO_WINDOW
            )
        }
    else:
        kwargs = {"start_new_session": True}
    subprocess.Popen(
        argv, cwd=str(ROOT), stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True, **kwargs,
    )
    return "popen(可能被 harness 清理)"


def _kill_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def _heartbeat_loop(job_id: int, stop: threading.Event) -> None:
    conn = workspace_db.connect()
    try:
        while not stop.wait(HEARTBEAT_INTERVAL):
            workspace_db.touch_job_heartbeat(conn, job_id)
    finally:
        conn.close()


def _reap_stale(conn) -> int:
    count = 0
    now_dt = datetime.now()
    for row in workspace_db.list_jobs(conn, status="running", limit=200):
        hb = row["heartbeat_at"]
        age = 9999.0
        if hb:
            try:
                age = (now_dt - datetime.strptime(hb, "%Y-%m-%d %H:%M:%S")).total_seconds()
            except ValueError:
                age = 9999.0
        if age > STALE_AFTER_SECONDS:
            workspace_db.finish_job(
                conn,
                row["id"],
                "failed",
                exit_code=-1,
                summary="stale heartbeat: monitor process died",
            )
            count += 1
    return count


def cmd_start(args: argparse.Namespace) -> int:
    if not args.name or not args.cmd:
        raise SystemExit("start requires --name and --cmd")
    conn = workspace_db.connect()
    job_id = workspace_db.add_job(
        conn,
        args.name,
        args.cmd,
        cwd=args.cwd,
        timeout_minutes=args.timeout_minutes,
        env=args.env,
    )
    log_rel = _log_rel(job_id, args.name)
    (ROOT / log_rel).parent.mkdir(parents=True, exist_ok=True)
    conn.execute(
        "UPDATE jobs SET log_path = ? WHERE id = ?", (log_rel, job_id)
    )
    conn.commit()
    conn.close()

    mode = _spawn_monitor(job_id)
    print(f"job id={job_id} name={args.name} status=pending spawn={mode}")
    print(f"log={log_rel}")
    print(f"watch: {sys.executable} scripts/job.py status ; {sys.executable} scripts/job.py tail {job_id}")
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    conn = workspace_db.connect()
    row = workspace_db.get_job(conn, args.id)
    if not row:
        conn.close()
        raise SystemExit(f"unknown job {args.id}")
    if row["status"] == "running":
        conn.close()
        print(f"job {args.id} already running pid={row['pid']}")
        return 0
    if row["status"] in ("done", "failed", "aborted"):
        conn.close()
        print(f"job {args.id} already {row['status']}")
        return 0

    workspace_db.mark_job_running(conn, args.id, os.getpid())

    log_rel = row["log_path"] or _log_rel(row["id"], row["name"])
    log_path = ROOT / log_rel
    log_path.parent.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    heartbeat = threading.Thread(
        target=_heartbeat_loop, args=(row["id"], stop), daemon=True
    )
    heartbeat.start()

    cwd = ROOT / row["cwd"] if row["cwd"] else ROOT
    env = os.environ.copy()
    if row["env_json"]:
        for item in json.loads(row["env_json"]):
            key, _, value = item.partition("=")
            if key:
                env[key] = value
    try:
        with log_path.open("ab") as log_fh:
            proc = subprocess.Popen(
                row["command"],
                shell=True,
                cwd=str(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
            )
            try:
                if row["timeout_minutes"]:
                    proc.wait(timeout=float(row["timeout_minutes"]) * 60)
                else:
                    proc.wait()
            except subprocess.TimeoutExpired:
                _kill_tree(proc.pid)
                proc.wait()
                workspace_db.finish_job(
                    conn,
                    row["id"],
                    "failed",
                    exit_code=-1,
                    summary=f"timeout after {row['timeout_minutes']} minutes",
                )
                conn.close()
                return 1
    except Exception as exc:  # launch failure
        workspace_db.finish_job(
            conn, row["id"], "failed", exit_code=-1, summary=f"launch failed: {exc}"
        )
        conn.close()
        print(f"job {row['id']} launch failed: {exc}")
        return 1
    finally:
        stop.set()

    status = "done" if proc.returncode == 0 else "failed"
    summary = _last_line_summary(log_path)
    workspace_db.finish_job(
        conn,
        row["id"],
        status,
        exit_code=proc.returncode,
        summary=summary or None,
    )
    conn.close()
    print(f"job {row['id']} -> {status} exit={proc.returncode}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    conn = workspace_db.connect()
    reaped = _reap_stale(conn)
    rows = workspace_db.list_jobs(conn, status=args.status, limit=args.limit)
    now_dt = datetime.now()
    data = []
    for row in rows:
        age = ""
        elapsed = ""
        if row["status"] == "running":
            if row["heartbeat_at"]:
                try:
                    age = round(
                        (now_dt - datetime.strptime(row["heartbeat_at"], "%Y-%m-%d %H:%M:%S")).total_seconds(),
                        1,
                    )
                except ValueError:
                    age = "?"
            if row["started_at"]:
                try:
                    elapsed = round(
                        (now_dt - datetime.strptime(row["started_at"], "%Y-%m-%d %H:%M:%S")).total_seconds(),
                        1,
                    )
                except ValueError:
                    elapsed = "?"
        item = {
            "id": row["id"],
            "name": row["name"],
            "status": row["status"],
            "pid": row["pid"],
            "heartbeat_age_s": age,
            "elapsed_s": elapsed,
            "exit_code": row["exit_code"],
            "log": row["log_path"],
            "summary": row["summary"],
        }
        data.append(item)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        for item in data:
            print(
                f"{item['id']}\t{item['name']}\t{item['status']}\tpid={item['pid'] or '-'}\t"
                f"hb={item['heartbeat_age_s'] or '-'}\t{item['elapsed_s'] or ''}s\t"
                f"exit={item['exit_code'] if item['exit_code'] is not None else '-'}\t{item['log'] or ''}"
            )
            if item["summary"]:
                print(f"  summary: {item['summary']}")
    if reaped:
        print(f"reaped_stale={reaped}")
    conn.close()
    return 0


def cmd_tail(args: argparse.Namespace) -> int:
    conn = workspace_db.connect()
    row = workspace_db.get_job(conn, args.id)
    conn.close()
    if not row:
        raise SystemExit(f"unknown job {args.id}")
    log_path = ROOT / (row["log_path"] or _log_rel(row["id"], row["name"]))
    for line in _read_tail(log_path, args.lines):
        print(line.rstrip("\r\n"))
    return 0


def cmd_kill(args: argparse.Namespace) -> int:
    conn = workspace_db.connect()
    row = workspace_db.get_job(conn, args.id)
    if not row:
        conn.close()
        raise SystemExit(f"unknown job {args.id}")
    if row["status"] == "running" and row["pid"]:
        _kill_tree(row["pid"])
    workspace_db.finish_job(
        conn, row["id"], "aborted", exit_code=-1, summary="killed by user"
    )
    conn.close()
    print(f"job {row['id']} -> aborted")
    return 0


def cmd_cleanup(args: argparse.Namespace) -> int:
    conn = workspace_db.connect()
    count = _reap_stale(conn)
    conn.close()
    print(f"reaped_stale={count}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detached background jobs")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("start", help="start a detached background job")
    p.add_argument("--name", required=True)
    p.add_argument("--cmd", required=True)
    p.add_argument(
        "--env",
        action="append",
        metavar="KEY=VALUE",
        help="environment variable to set for the command; repeatable",
    )
    p.add_argument("--cwd")
    p.add_argument("--timeout-minutes", type=int)
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("monitor", help="internal: run and supervise a job")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_monitor)

    p = sub.add_parser("status", help="list jobs with heartbeat/exit info")
    p.add_argument("--status", choices=["pending", "running", "done", "failed", "aborted"])
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("tail", help="show the tail of a job log")
    p.add_argument("id", type=int)
    p.add_argument("--lines", type=int, default=20)
    p.set_defaults(func=cmd_tail)

    p = sub.add_parser("kill", help="abort a running job")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_kill)

    p = sub.add_parser("cleanup", help="mark stale running jobs as failed")
    p.set_defaults(func=cmd_cleanup)

    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
