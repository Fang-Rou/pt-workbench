#!/usr/bin/env python3
"""Ingest findings from JSONL into the workspace database.

Each line is one finding:
{"target_slug": "lib-jnu-edu-cn", "title": "...", "severity": "low",
 "category": "...", "url": "...", "method": "GET", "description": "...",
 "poc_path": "...", "status": "open", "dedupe_key": "optional"}
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import workspace_db


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", default="-", help="JSONL path or -")
    parser.add_argument("--default-status", default="open")
    args = parser.parse_args()

    conn = workspace_db.connect()
    if args.input == "-":
        stream = sys.stdin
    else:
        stream = Path(args.input).open(encoding="utf-8")

    inserted = 0
    updated = 0
    failed = 0
    with stream:
        for lineno, raw in enumerate(stream, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                item = json.loads(line)
                target_slug = item.get("target_slug")
                title = item.get("title")
                if not target_slug or not title:
                    raise ValueError("missing target_slug or title")
                _, created = workspace_db.add_finding(
                    conn,
                    target_slug=target_slug,
                    title=title,
                    severity=item.get("severity", "info"),
                    category=item.get("category"),
                    url=item.get("url"),
                    method=item.get("method"),
                    params=item.get("params"),
                    description=item.get("description"),
                    poc_path=item.get("poc_path"),
                    status=item.get("status", args.default_status),
                    dedupe_key=item.get("dedupe_key"),
                )
                if created:
                    inserted += 1
                else:
                    updated += 1
            except Exception as exc:
                failed += 1
                print(f"FAIL line {lineno}: {exc}", file=sys.stderr)
    print(f"inserted={inserted} updated={updated} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
