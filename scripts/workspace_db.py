#!/usr/bin/env python3
"""SQLite-backed workspace state for long-term SRC projects.

The conversation should stay thin: scripts write raw output to disk and only
compact summaries/findings go into this database. New Codex sessions should
start with `make_brief.py` output instead of re-reading raw captures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "state"
DB_PATH = STATE_DIR / "workspace.db"

CLOSED_FINDING_STATUSES = {"closed", "fixed", "accepted", "rejected", "duplicate"}

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  platform TEXT,
  company_id TEXT,
  scope TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  notes TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  host TEXT,
  status TEXT NOT NULL DEFAULT 'new',
  tech_stack TEXT,
  notes TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  title TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  summary TEXT,
  output_path TEXT,
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  dedupe_key TEXT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  category TEXT,
  url TEXT,
  method TEXT,
  params TEXT,
  description TEXT,
  poc_path TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(target_id, dedupe_key)
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  platform TEXT,
  submission_id TEXT,
  status TEXT NOT NULL DEFAULT 'submitted',
  submitted_at TEXT,
  notes TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  kind TEXT NOT NULL DEFAULT 'other',
  path TEXT NOT NULL,
  caption TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL DEFAULT 'raw',
  path TEXT NOT NULL,
  size_bytes INTEGER,
  sha256 TEXT,
  note TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  command TEXT NOT NULL,
  cwd TEXT,
  env_json TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  pid INTEGER,
  log_path TEXT,
  timeout_minutes INTEGER,
  exit_code INTEGER,
  summary TEXT,
  heartbeat_at TEXT,
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
CREATE INDEX IF NOT EXISTS idx_tasks_target ON tasks(target_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_submissions_finding ON submissions(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_raw_target ON raw_artifacts(target_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
"""


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)
    cols = [row[1] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()]
    if cols and "env_json" not in cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN env_json TEXT")
    return conn


def rel_path(value: str | None) -> str | None:
    if not value:
        return value
    p = Path(value)
    try:
        return str(p.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(p)


def add_project(
    conn: sqlite3.Connection,
    slug: str,
    name: str,
    platform: str | None = None,
    company_id: str | None = None,
    scope: str | None = None,
    status: str = "active",
    notes: str | None = None,
) -> int:
    ts = now()
    conn.execute(
        """
        INSERT INTO projects (slug, name, platform, company_id, scope, status, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
          name=excluded.name, platform=excluded.platform, company_id=excluded.company_id,
          scope=excluded.scope, status=excluded.status, notes=excluded.notes, updated_at=excluded.updated_at
        """,
        (slug, name, platform, company_id, scope, status, notes, ts, ts),
    )
    row = conn.execute("SELECT id FROM projects WHERE slug = ?", (slug,)).fetchone()
    conn.commit()
    return int(row["id"])


def get_project(conn: sqlite3.Connection, slug: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM projects WHERE slug = ?", (slug,)).fetchone()


def list_projects(
    conn: sqlite3.Connection, status: str | None = None
) -> list[sqlite3.Row]:
    sql = "SELECT * FROM projects"
    params: tuple = ()
    if status:
        sql += " WHERE status = ?"
        params = (status,)
    sql += " ORDER BY updated_at DESC, id DESC"
    return conn.execute(sql, params).fetchall()


def add_target(
    conn: sqlite3.Connection,
    project_slug: str,
    slug: str,
    name: str,
    host: str | None = None,
    status: str = "new",
    tech_stack: str | None = None,
    notes: str | None = None,
) -> int:
    project = get_project(conn, project_slug)
    if not project:
        raise ValueError(f"unknown project slug: {project_slug}")
    ts = now()
    conn.execute(
        """
        INSERT INTO targets (project_id, slug, name, host, status, tech_stack, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
          project_id=excluded.project_id, name=excluded.name, host=excluded.host,
          status=excluded.status, tech_stack=excluded.tech_stack, notes=excluded.notes,
          updated_at=excluded.updated_at
        """,
        (project["id"], slug, name, host, status, tech_stack, notes, ts, ts),
    )
    row = conn.execute("SELECT id FROM targets WHERE slug = ?", (slug,)).fetchone()
    conn.commit()
    return int(row["id"])


def get_target(conn: sqlite3.Connection, slug: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM targets WHERE slug = ?", (slug,)).fetchone()


def list_targets(
    conn: sqlite3.Connection, project_slug: str | None = None
) -> list[sqlite3.Row]:
    sql = (
        "SELECT t.*, p.slug AS project_slug, p.name AS project_name "
        "FROM targets t JOIN projects p ON p.id = t.project_id"
    )
    params: tuple = ()
    if project_slug:
        sql += " WHERE p.slug = ?"
        params = (project_slug,)
    sql += " ORDER BY t.updated_at DESC, t.id DESC"
    return conn.execute(sql, params).fetchall()


def add_task(
    conn: sqlite3.Connection,
    target_slug: str,
    kind: str,
    title: str | None = None,
    status: str = "pending",
    summary: str | None = None,
    output_path: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
) -> int:
    target = get_target(conn, target_slug)
    if not target:
        raise ValueError(f"unknown target slug: {target_slug}")
    ts = now()
    cur = conn.execute(
        """
        INSERT INTO tasks (target_id, kind, title, status, summary, output_path, started_at, finished_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target["id"],
            kind,
            title or kind,
            status,
            summary,
            rel_path(output_path),
            started_at or (ts if status == "running" else None),
            finished_at or (ts if status in ("done", "failed", "skipped") else None),
            ts,
            ts,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def finish_task(
    conn: sqlite3.Connection,
    task_id: int,
    status: str,
    summary: str | None = None,
    output_path: str | None = None,
) -> None:
    ts = now()
    fields = ["status = ?", "updated_at = ?"]
    params: list = [status, ts]
    if summary is not None:
        fields.append("summary = ?")
        params.append(summary)
    if output_path is not None:
        fields.append("output_path = ?")
        params.append(rel_path(output_path))
    if status in ("done", "failed", "skipped"):
        fields.append("finished_at = ?")
        params.append(ts)
    params.append(task_id)
    conn.execute(f"UPDATE tasks SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()


def list_tasks(
    conn: sqlite3.Connection,
    target_slug: str | None = None,
    status: str | None = None,
    limit: int = 20,
) -> list[sqlite3.Row]:
    sql = (
        "SELECT t.*, tg.slug AS target_slug, tg.name AS target_name, "
        "p.slug AS project_slug "
        "FROM tasks t "
        "JOIN targets tg ON tg.id = t.target_id "
        "JOIN projects p ON p.id = tg.project_id"
    )
    where: list[str] = []
    params: list = []
    if target_slug:
        where.append("tg.slug = ?")
        params.append(target_slug)
    if status:
        where.append("t.status = ?")
        params.append(status)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY t.created_at DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def default_dedupe_key(target_id: int, title: str, url: str | None) -> str:
    raw = f"{target_id}|{title}|{url or ''}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def add_finding(
    conn: sqlite3.Connection,
    target_slug: str,
    title: str,
    severity: str = "info",
    category: str | None = None,
    url: str | None = None,
    method: str | None = None,
    params: str | None = None,
    description: str | None = None,
    poc_path: str | None = None,
    status: str = "open",
    dedupe_key: str | None = None,
) -> tuple[int, bool]:
    target = get_target(conn, target_slug)
    if not target:
        raise ValueError(f"unknown target slug: {target_slug}")
    key = dedupe_key or default_dedupe_key(int(target["id"]), title, url)
    ts = now()
    existing = conn.execute(
        "SELECT id FROM findings WHERE target_id = ? AND dedupe_key = ?",
        (target["id"], key),
    ).fetchone()
    if existing:
        conn.execute(
            """
            UPDATE findings
            SET title=?, severity=?, category=?, url=?, method=?, params=?,
                description=?, poc_path=?, status=?, updated_at=?
            WHERE id=?
            """,
            (
                title,
                severity,
                category,
                url,
                method,
                params,
                description,
                rel_path(poc_path),
                status,
                ts,
                existing["id"],
            ),
        )
        conn.commit()
        return int(existing["id"]), False
    cur = conn.execute(
        """
        INSERT INTO findings
          (target_id, dedupe_key, title, severity, category, url, method, params,
           description, poc_path, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target["id"],
            key,
            title,
            severity,
            category,
            url,
            method,
            params,
            description,
            rel_path(poc_path),
            status,
            ts,
            ts,
        ),
    )
    conn.commit()
    return int(cur.lastrowid), True


def set_finding_status(
    conn: sqlite3.Connection, finding_id: int, status: str
) -> None:
    conn.execute(
        "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
        (status, now(), finding_id),
    )
    conn.commit()


def list_findings(
    conn: sqlite3.Connection,
    project_slug: str | None = None,
    target_slug: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
) -> list[sqlite3.Row]:
    sql = (
        "SELECT f.*, t.slug AS target_slug, t.name AS target_name, p.slug AS project_slug "
        "FROM findings f "
        "JOIN targets t ON t.id = f.target_id "
        "JOIN projects p ON p.id = t.project_id"
    )
    where: list[str] = []
    params: list = []
    if project_slug:
        where.append("p.slug = ?")
        params.append(project_slug)
    if target_slug:
        where.append("t.slug = ?")
        params.append(target_slug)
    if status:
        where.append("f.status = ?")
        params.append(status)
    if severity:
        where.append("f.severity = ?")
        params.append(severity)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY f.updated_at DESC, f.id DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def add_submission(
    conn: sqlite3.Connection,
    finding_id: int,
    platform: str,
    submission_id: str | None = None,
    status: str = "submitted",
    submitted_at: str | None = None,
    notes: str | None = None,
) -> int:
    existing = conn.execute(
        "SELECT id FROM submissions WHERE finding_id = ? AND submission_id = ?",
        (finding_id, submission_id),
    ).fetchone()
    finding_status = status if status in CLOSED_FINDING_STATUSES else "submitted"
    if existing:
        conn.execute(
            """
            UPDATE submissions
            SET platform=?, status=?, submitted_at=COALESCE(?, submitted_at), notes=?
            WHERE id=?
            """,
            (platform, status, submitted_at, notes, existing["id"]),
        )
        set_finding_status(conn, finding_id, finding_status)
        conn.commit()
        return int(existing["id"])
    cur = conn.execute(
        """
        INSERT INTO submissions (finding_id, platform, submission_id, status, submitted_at, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding_id,
            platform,
            submission_id,
            status,
            submitted_at or now(),
            notes,
            now(),
        ),
    )
    set_finding_status(conn, finding_id, finding_status)
    conn.commit()
    return int(cur.lastrowid)


def list_submissions(
    conn: sqlite3.Connection, finding_id: int | None = None, limit: int = 50
) -> list[sqlite3.Row]:
    sql = (
        "SELECT s.*, f.title AS finding_title, t.slug AS target_slug "
        "FROM submissions s JOIN findings f ON f.id = s.finding_id "
        "JOIN targets t ON t.id = f.target_id"
    )
    params: list = []
    if finding_id is not None:
        sql += " WHERE s.finding_id = ?"
        params.append(finding_id)
    sql += " ORDER BY s.created_at DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def add_evidence(
    conn: sqlite3.Connection,
    finding_id: int,
    path: str,
    kind: str = "other",
    caption: str | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO evidence (finding_id, kind, path, caption, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (finding_id, kind, rel_path(path), caption, now()),
    )
    conn.commit()
    return int(cur.lastrowid)


def add_artifact(
    conn: sqlite3.Connection,
    target_slug: str,
    path: str,
    kind: str = "raw",
    size_bytes: int | None = None,
    sha256: str | None = None,
    note: str | None = None,
) -> int:
    target = get_target(conn, target_slug)
    if not target:
        raise ValueError(f"unknown target slug: {target_slug}")
    cur = conn.execute(
        """
        INSERT INTO raw_artifacts (target_id, kind, path, size_bytes, sha256, note, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (target["id"], kind, rel_path(path), size_bytes, sha256, note, now()),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_artifacts(
    conn: sqlite3.Connection, target_slug: str | None = None, limit: int = 20
) -> list[sqlite3.Row]:
    sql = (
        "SELECT a.*, t.slug AS target_slug FROM raw_artifacts a "
        "JOIN targets t ON t.id = a.target_id"
    )
    params: list = []
    if target_slug:
        sql += " WHERE t.slug = ?"
        params.append(target_slug)
    sql += " ORDER BY a.created_at DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def add_job(
    conn: sqlite3.Connection,
    name: str,
    command: str,
    cwd: str | None = None,
    timeout_minutes: int | None = None,
    env: list[str] | None = None,
) -> int:
    ts = now()
    cur = conn.execute(
        """
        INSERT INTO jobs (name, command, cwd, env_json, status, timeout_minutes, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
        """,
        (
            name,
            command,
            rel_path(cwd) if cwd else None,
            json.dumps(env or [], ensure_ascii=False),
            timeout_minutes,
            ts,
            ts,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def get_job(conn: sqlite3.Connection, job_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()


def mark_job_running(
    conn: sqlite3.Connection, job_id: int, pid: int
) -> None:
    ts = now()
    conn.execute(
        """
        UPDATE jobs
        SET status = 'running', pid = ?, heartbeat_at = ?, started_at = ?, updated_at = ?
        WHERE id = ?
        """,
        (pid, ts, ts, ts, job_id),
    )
    conn.commit()


def touch_job_heartbeat(conn: sqlite3.Connection, job_id: int) -> None:
    conn.execute(
        "UPDATE jobs SET heartbeat_at = ?, updated_at = ? WHERE id = ?",
        (now(), now(), job_id),
    )
    conn.commit()


def finish_job(
    conn: sqlite3.Connection,
    job_id: int,
    status: str,
    exit_code: int | None = None,
    summary: str | None = None,
) -> None:
    ts = now()
    fields = ["status = ?", "finished_at = ?", "updated_at = ?"]
    params: list = [status, ts, ts]
    if exit_code is not None:
        fields.append("exit_code = ?")
        params.append(exit_code)
    if summary is not None:
        fields.append("summary = ?")
        params.append(summary[:400])
    params.append(job_id)
    conn.execute(f"UPDATE jobs SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()


def list_jobs(
    conn: sqlite3.Connection,
    status: str | None = None,
    limit: int = 20,
) -> list[sqlite3.Row]:
    sql = "SELECT * FROM jobs"
    params: list = []
    if status:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def stats(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT p.slug AS project_slug, p.name AS project_name, p.status AS project_status,
               COUNT(DISTINCT t.id) AS targets,
               COUNT(DISTINCT f.id) AS findings,
               SUM(CASE WHEN f.status IN ('open','validating','submitted','under_review')
                        THEN 1 ELSE 0 END) AS active_findings,
               COUNT(DISTINCT CASE WHEN t.status NOT IN ('done','dead','archived') THEN t.id END) AS active_targets,
               (SELECT COUNT(*) FROM submissions s
                JOIN findings f2 ON f2.id = s.finding_id
                JOIN targets t2 ON t2.id = f2.target_id
                WHERE t2.project_id = p.id) AS submissions
        FROM projects p
        LEFT JOIN targets t ON t.project_id = p.id
        LEFT JOIN findings f ON f.target_id = t.id
        GROUP BY p.id
        ORDER BY p.updated_at DESC
        """
    ).fetchall()


def brief_markdown(conn: sqlite3.Connection, project_slug: str | None = None) -> str:
    lines: list[str] = []
    lines.append("# 渗透测试工作台简报")
    lines.append("")
    lines.append(f"生成时间：{now()}")
    lines.append("")
    lines.append("> 会话规则：只读本文件；按需打开指定路径；不要整读 raw/ 下的大文件。")
    lines.append("> 本工作区由原「公益 SRC 工作流」改造为**渗透测试工作流**（2026-10-01）：")
    lines.append("> 授权来自委托合同，平台提交链/厂池/备案归属预检已移除。")
    lines.append("")
    lines.append("## 开工入口（AGENTS.md §0）")
    lines.append("")
    lines.append("```text")
    lines.append("新建项目: python scripts/engagement.py new --client \"<客户>\" --domain <域名> \\")
    lines.append("            --scope-host <资产> --scope-cidr <网段> --window <起..止> --roe \"<规则>\"")
    lines.append("切为 active: python scripts/engagement.py use <slug>")
    lines.append("看范围:     python scripts/scope_gate.py --show")
    lines.append("交付闸门:   python scripts/report_gate.py --deliver \"_交付/<slug>\"")
    lines.append("续接会话:   python scripts/next.py")
    lines.append("```")
    lines.append("")
    lines.append("## 总览（`workspace.db` 台账）")
    lines.append("")
    lines.append("> ⚠ 下表含 SRC 期的历史项目（状态 `archived`/`paused`/`done`）——它们是**知识库**，")
    lines.append("> 不是待办。渗透线的在跑项目看 `python scripts/engagement.py list`（`*` = active）。")
    lines.append("")
    lines.append("| 项目 | 状态 | 目标数 | 未关闭漏洞 | 提交数 |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for row in stats(conn):
        if project_slug and row["project_slug"] != project_slug:
            continue
        lines.append(
            f"| {row['project_name']} (`{row['project_slug']}`) | "
            f"{row['project_status']} | {row['targets']} | "
            f"{row['active_findings'] or 0} | {row['submissions'] or 0} |"
        )
    lines.append("")
    projects = list_projects(conn, status="active")
    if project_slug:
        projects = [p for p in projects if p["slug"] == project_slug]
    for project in projects:
        lines.append(f"## {project['name']} ({project['slug']})")
        lines.append("")
        if project["platform"]:
            lines.append(f"- 平台：{project['platform']}")
        if project["company_id"]:
            lines.append(f"- company_id：{project['company_id']}")
        if project["scope"]:
            lines.append(f"- 范围：{project['scope']}")
        if project["notes"]:
            lines.append(f"- 备注：{project['notes']}")
        lines.append("")
        targets = list_targets(conn, project_slug=project["slug"])
        if targets:
            lines.append("### 目标")
            lines.append("")
            for t in targets:
                lines.append(
                    f"- `{t['host'] or t['slug']}` [{t['status']}] {t['name']}"
                )
            lines.append("")
        findings = list_findings(conn, project_slug=project["slug"], limit=200)
        open_findings = [
            f
            for f in findings
            if f["status"].lower() not in CLOSED_FINDING_STATUSES
        ]
        if open_findings:
            lines.append("### 未关闭漏洞")
            lines.append("")
            for f in open_findings:
                lines.append(
                    f"- [{f['severity']}] {f['title']} "
                    f"({f['status']}) `{f['url'] or ''}` {f['poc_path'] or ''}"
                )
            lines.append("")
        tasks = list_tasks(
            conn, status="pending", limit=20
        ) + list_tasks(conn, status="running", limit=20)
        project_tasks = [
            t for t in tasks if t["project_slug"] == project["slug"]
        ][:10]
        if project_tasks:
            lines.append("### 待办/进行中任务")
            lines.append("")
            for t in project_tasks:
                lines.append(
                    f"- [{t['status']}] {t['kind']} {t['title'] or ''} "
                    f"`{t['target_slug']}` {t['output_path'] or ''}"
                )
            lines.append("")
    lines.append("## 常用命令")
    lines.append("")
    lines.append("```text")
    lines.append("python scripts/engagement.py list              # 渗透项目清单（* = active）")
    lines.append("python scripts/engagement.py show <slug>       # 链状态 / 利用点 / 攻击图")
    lines.append("python scripts/arsenal.py board                # 20 条攻击链作战板")
    lines.append("python scripts/batch_recon.py --status         # 批量侦察预算账本")
    lines.append("python scripts/recon_api.py all <domain>       # 被动测绘（不碰目标）")
    lines.append("python scripts/findings_export.py --slug <s>   # 导出发现清单")
    lines.append("python scripts/remediation_tracker.py --slug <s> --init   # 整改跟踪表")
    lines.append("python scripts/health_check.py                 # 运行时体检")
    lines.append("python scripts/maintain.py report              # 体积 + 接线 + 沉淀体检")
    lines.append("python scripts/sync_skills.py --check          # 技能接线")
    lines.append("python scripts/workspace_db.py finding list --limit 20")
    lines.append("python scripts/job.py status                   # 后台作业")
    lines.append("python scripts/resume.py                       # 续接")
    lines.append("```")
    lines.append("")
    lines.append("## 新线程启动")
    lines.append("")
    lines.append("1. 只读本文件，不读 raw/ 目录。")
    lines.append("2. 若有 `state/resume.md`，先执行 `python scripts/resume.py` 续接。")
    lines.append("3. 运行 `python scripts/next.py` 获取下一步；长任务用 `python scripts/job.py start` 后台跑。")
    lines.append("4. 不确定该用哪些技能/手法时，先跑 `python scripts/playbook_lookup.py <词1> <词2> <词3>`。")
    lines.append("5. 里程碑或风险步骤前运行 `python scripts/checkpoint.py --next-file state/next.txt`。")
    lines.append("")
    return "\n".join(lines)


def load_seed(conn: sqlite3.Connection, seed_path: Path) -> None:
    data = json.loads(seed_path.read_text(encoding="utf-8"))
    for project in data.get("projects", []):
        project_id = add_project(
            conn,
            slug=project["slug"],
            name=project["name"],
            platform=project.get("platform"),
            company_id=project.get("company_id"),
            scope=project.get("scope"),
            status=project.get("status", "active"),
            notes=project.get("notes"),
        )
        for target in project.get("targets", []):
            target_id = add_target(
                conn,
                project_slug=project["slug"],
                slug=target["slug"],
                name=target["name"],
                host=target.get("host"),
                status=target.get("status", "new"),
                tech_stack=target.get("tech_stack"),
                notes=target.get("notes"),
            )
            _ = project_id, target_id
            for task in target.get("tasks", []):
                add_task(
                    conn,
                    target_slug=target["slug"],
                    kind=task.get("kind", "task"),
                    title=task.get("title"),
                    status=task.get("status", "pending"),
                    summary=task.get("summary"),
                    output_path=task.get("output_path"),
                )
            for finding in target.get("findings", []):
                fid, _ = add_finding(
                    conn,
                    target_slug=target["slug"],
                    title=finding["title"],
                    severity=finding.get("severity", "info"),
                    category=finding.get("category"),
                    url=finding.get("url"),
                    method=finding.get("method"),
                    params=finding.get("params"),
                    description=finding.get("description"),
                    poc_path=finding.get("poc_path"),
                    status=finding.get("status", "open"),
                    dedupe_key=finding.get("dedupe_key"),
                )
                submission = finding.get("submission")
                if submission:
                    add_submission(
                        conn,
                        finding_id=fid,
                        platform=submission.get("platform", "butian"),
                        submission_id=submission.get("submission_id"),
                        status=submission.get("status", "submitted"),
                        submitted_at=submission.get("submitted_at"),
                        notes=submission.get("notes"),
                    )
                for ev in finding.get("evidence", []):
                    add_evidence(
                        conn,
                        finding_id=fid,
                        path=ev["path"],
                        kind=ev.get("kind", "other"),
                        caption=ev.get("caption"),
                    )
            for artifact in target.get("artifacts", []):
                add_artifact(
                    conn,
                    target_slug=target["slug"],
                    path=artifact["path"],
                    kind=artifact.get("kind", "raw"),
                    size_bytes=artifact.get("size_bytes"),
                    sha256=artifact.get("sha256"),
                    note=artifact.get("note"),
                )
    conn.commit()


def print_rows(rows: list[sqlite3.Row], fields: list[str]) -> None:
    if not rows:
        print("(empty)")
        return
    print("\t".join(fields))
    for row in rows:
        print("\t".join(str(row[f] if f in row.keys() else "") for f in fields))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Workspace SQLite state")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="initialize the database")

    p = sub.add_parser("project", help="project operations")
    p.add_argument("action", choices=["add", "list"])
    p.add_argument("--slug")
    p.add_argument("--name")
    p.add_argument("--platform")
    p.add_argument("--company-id")
    p.add_argument("--scope")
    p.add_argument("--status")
    p.add_argument("--notes")

    p = sub.add_parser("target", help="target operations")
    p.add_argument("action", choices=["add", "list"])
    p.add_argument("--project")
    p.add_argument("--slug")
    p.add_argument("--name")
    p.add_argument("--host")
    p.add_argument("--status", default="new")
    p.add_argument("--tech")
    p.add_argument("--notes")

    p = sub.add_parser("task", help="task operations")
    p.add_argument("action", choices=["add", "done", "list"])
    p.add_argument("--id", type=int)
    p.add_argument("--target")
    p.add_argument("--kind", default="task")
    p.add_argument("--title")
    p.add_argument("--status")
    p.add_argument("--summary")
    p.add_argument("--output")
    p.add_argument("--limit", type=int, default=20)

    p = sub.add_parser("finding", help="finding operations")
    p.add_argument("action", choices=["add", "list", "status"])
    p.add_argument("--id", type=int)
    p.add_argument("--target")
    p.add_argument("--project")
    p.add_argument("--title")
    p.add_argument("--severity")
    p.add_argument("--category")
    p.add_argument("--url")
    p.add_argument("--method")
    p.add_argument("--params")
    p.add_argument("--description")
    p.add_argument("--poc")
    p.add_argument("--status")
    p.add_argument("--dedupe-key")
    p.add_argument("--limit", type=int, default=100)

    p = sub.add_parser("submit", help="交付/上报登记（finding -> 客户报告或厂商）")
    p.add_argument("action", choices=["add", "list"])
    p.add_argument("--finding", type=int)
    p.add_argument("--platform", default="report",
                   help="交付对象：report=客户报告 / 厂商名 / 跟踪单号系统")
    p.add_argument("--submission-id")
    p.add_argument("--status", default="submitted")
    p.add_argument("--notes")

    p = sub.add_parser("evidence", help="attach evidence to a finding")
    p.add_argument("--finding", type=int, required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--kind", default="other")
    p.add_argument("--caption")

    p = sub.add_parser("artifact", help="record a raw artifact")
    p.add_argument("action", choices=["add", "list"])
    p.add_argument("--target")
    p.add_argument("--path")
    p.add_argument("--kind", default="raw")
    p.add_argument("--size", type=int)
    p.add_argument("--sha256")
    p.add_argument("--note")
    p.add_argument("--limit", type=int, default=20)

    p = sub.add_parser("brief", help="print compact brief markdown")
    p.add_argument("--project")

    sub.add_parser("stats", help="show project statistics")

    p = sub.add_parser("seed", help="load seed JSON")
    p.add_argument("--file", default=str(STATE_DIR / "seed.json"))

    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    conn = connect()
    if args.command == "init":
        print(f"DB ready: {DB_PATH}")
    elif args.command == "project":
        if args.action == "add":
            if not args.slug or not args.name:
                raise SystemExit("project add requires --slug and --name")
            pid = add_project(
                conn,
                args.slug,
                args.name,
                platform=args.platform,
                company_id=args.company_id,
                scope=args.scope,
                status=args.status or "active",
                notes=args.notes,
            )
            print(f"project id={pid} slug={args.slug}")
        else:
            print_rows(
                list_projects(conn, status=args.status),
                ["id", "slug", "name", "platform", "status", "updated_at"],
            )
    elif args.command == "target":
        if args.action == "add":
            if not args.project or not args.slug or not args.name:
                raise SystemExit("target add requires --project --slug --name")
            tid = add_target(
                conn,
                args.project,
                args.slug,
                args.name,
                host=args.host,
                status=args.status,
                tech_stack=args.tech,
                notes=args.notes,
            )
            print(f"target id={tid} slug={args.slug}")
        else:
            print_rows(
                list_targets(conn, project_slug=args.project),
                ["id", "slug", "name", "host", "status", "project_slug"],
            )
    elif args.command == "task":
        if args.action == "add":
            if not args.target:
                raise SystemExit("task add requires --target")
            tid = add_task(
                conn,
                args.target,
                args.kind,
                title=args.title,
                status=args.status or "pending",
                summary=args.summary,
                output_path=args.output,
            )
            print(f"task id={tid}")
        elif args.action == "done":
            if not args.id:
                raise SystemExit("task done requires --id")
            finish_task(
                conn,
                args.id,
                args.status or "done",
                summary=args.summary,
                output_path=args.output,
            )
            print(f"task id={args.id} -> {args.status or 'done'}")
        else:
            print_rows(
                list_tasks(
                    conn,
                    target_slug=args.target,
                    status=args.status,
                    limit=args.limit,
                ),
                ["id", "target_slug", "kind", "status", "title", "output_path"],
            )
    elif args.command == "finding":
        if args.action == "add":
            if not args.target or not args.title:
                raise SystemExit("finding add requires --target and --title")
            fid, created = add_finding(
                conn,
                args.target,
                args.title,
                severity=args.severity or "info",
                category=args.category,
                url=args.url,
                method=args.method,
                params=args.params,
                description=args.description,
                poc_path=args.poc,
                status=args.status or "open",
                dedupe_key=args.dedupe_key,
            )
            print(f"finding id={fid} {'inserted' if created else 'updated'}")
        elif args.action == "status":
            if not args.id or not args.status:
                raise SystemExit("finding status requires --id and --status")
            set_finding_status(conn, args.id, args.status)
            print(f"finding id={args.id} -> {args.status}")
        else:
            print_rows(
                list_findings(
                    conn,
                    project_slug=args.project,
                    target_slug=args.target,
                    status=args.status,
                    severity=args.severity,
                    limit=args.limit,
                ),
                [
                    "id",
                    "project_slug",
                    "target_slug",
                    "severity",
                    "status",
                    "title",
                    "url",
                    "poc_path",
                ],
            )
    elif args.command == "submit":
        if args.action == "add":
            if not args.finding:
                raise SystemExit("submit add requires --finding")
            sid = add_submission(
                conn,
                args.finding,
                args.platform,
                submission_id=args.submission_id,
                status=args.status,
                notes=args.notes,
            )
            print(f"submission id={sid}")
        else:
            print_rows(
                list_submissions(conn, finding_id=args.finding),
                ["id", "finding_id", "platform", "submission_id", "status"],
            )
    elif args.command == "evidence":
        eid = add_evidence(
            conn, args.finding, args.path, kind=args.kind, caption=args.caption
        )
        print(f"evidence id={eid}")
    elif args.command == "artifact":
        if args.action == "add":
            if not args.target or not args.path:
                raise SystemExit("artifact add requires --target and --path")
            aid = add_artifact(
                conn,
                args.target,
                args.path,
                kind=args.kind,
                size_bytes=args.size,
                sha256=args.sha256,
                note=args.note,
            )
            print(f"artifact id={aid}")
        else:
            print_rows(
                list_artifacts(conn, target_slug=args.target, limit=args.limit),
                ["id", "target_slug", "kind", "path", "size_bytes", "created_at"],
            )
    elif args.command == "brief":
        print(brief_markdown(conn, project_slug=args.project))
    elif args.command == "stats":
        print_rows(
            stats(conn),
            [
                "project_slug",
                "targets",
                "active_targets",
                "findings",
                "active_findings",
                "submissions",
            ],
        )
    elif args.command == "seed":
        load_seed(conn, Path(args.file))
        print(f"seed loaded from {args.file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
