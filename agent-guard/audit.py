"""Audit sinks: where decisions go.

A sink is anything with an ``append(record)`` method, where ``record`` is
a dict with ``agent``, ``tool``, ``decision`` and ``reason`` keys.

That is the whole plug-in contract. It is deliberately tiny so a user
can point logs at whatever they already run, without this project
needing a driver for every database:

- ``AuditLog`` — JSONL file, the default. Human-readable, grep-able,
  no server needed. Good for local use.
- ``SqliteAuditLog`` — SQLite file, stdlib only. Good when you want
  real SQL queries over decisions (``SELECT decision, COUNT(*) ...``)
  without running a database server.
- Your own sink — implement ``append(record)`` and pass it to
  ``Guard(audit_sink=...)``. The README shows a Postgres example
  (insert one row per decision) that needs no change to the guard.

``stats()`` is implemented for the built-in sinks. Custom sinks may
implement it too, or omit it — the guard never calls ``stats()``.
"""
import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    """JSONL audit log. Default sink."""

    def __init__(self, path="audit.jsonl"):
        self.path = Path(path)

    def append(self, record: dict):
        with self.path.open("a") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")

    def stats(self):
        counts = Counter()
        by_reason = Counter()
        if not self.path.exists():
            return {"total": 0, "by_decision": {}, "by_reason": {}}
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            counts[r.get("decision", "?")] += 1
            by_reason[r.get("reason", "?")] += 1
        return {"total": sum(counts.values()), "by_decision": dict(counts), "by_reason": dict(by_reason)}


class SqliteAuditLog:
    """SQLite audit log. Stdlib only, queryable with SQL."""

    def __init__(self, path="audit.db"):
        self.path = Path(path)
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS audit ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "created_at TEXT NOT NULL, agent TEXT, tool TEXT, "
                "decision TEXT, reason TEXT)"
            )
            conn.commit()
        finally:
            conn.close()

    def append(self, record: dict):
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "INSERT INTO audit (created_at, agent, tool, decision, reason) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    record.get("agent"),
                    record.get("tool"),
                    record.get("decision"),
                    record.get("reason"),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def stats(self):
        conn = sqlite3.connect(self.path)
        try:
            total = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            by_decision = dict(conn.execute(
                "SELECT decision, COUNT(*) FROM audit GROUP BY decision").fetchall())
            by_reason = dict(conn.execute(
                "SELECT reason, COUNT(*) FROM audit GROUP BY reason").fetchall())
        finally:
            conn.close()
        return {"total": total, "by_decision": by_decision, "by_reason": by_reason}


def make_audit_sink(backend: str, path: str):
    """Build a built-in sink by name: ``jsonl`` (default) or ``sqlite``."""
    backend = (backend or "jsonl").lower()
    if backend == "sqlite":
        return SqliteAuditLog(path)
    if backend == "jsonl":
        return AuditLog(path)
    raise ValueError(f"unknown audit backend: {backend!r} (want 'jsonl' or 'sqlite')")
