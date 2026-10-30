"""Real executor for Agent Guard — the V2 answer to "the tools are mocks".

This is deliberately boring and narrow, not a general shell:
  - read_file: opens a real file, but only inside the policy sandbox
    (resolved path must be inside the resolved sandbox root, symlinks
    included), max 100 KB, UTF-8 with errors replaced.
  - run_command: only `ls` and `echo`, run with subprocess and NO shell
    (argv list, never shell=True). `ls` arguments must already have
    passed the guard's sandbox check; this module re-checks them.
  - query_db: a real SQLite database (demo.db next to this file's
    project root, created on first use with two tables). A single
    statement is executed, with a 5-second timeout, and the guard's
    table allowlist is re-checked here too.
    IMPORTANT: this executor does NOT re-enforce read-only. The
    guard does that for auto-execution (handle() blocks or routes
    writes to approval before the executor ever sees them), and
    approve() is the human gate that allows a write through. Do not
    call real_execute() directly with untrusted input — go through
    Guard.handle() / Guard.approve().
  - call_api: still mocked. A real HTTP client to an allowed host
    would need redirect / DNS-rebinding handling that this module
    does not claim to provide, so it stays a mock rather than a
    half-safe real client. Say so, don't fake it.

Usage:
    from agent_guard.guard import Guard
    from agent_guard.real_tools import execute as real_execute
    g = Guard(executor=real_execute)
    # or, for the server:
    REAL_TOOLS=1 python3 -m agent_guard.server

The mock executor remains the default, so existing tests, the
pentest harness, and the fuzzer keep running against the mock
unless you opt into real tools explicitly.
"""
import sqlite3
import subprocess
from pathlib import Path

MAX_FILE_BYTES = 100_000

# Demo database lives in the project root's data/ folder, next to the
# sandbox files, so a demo stays self-contained and deletable.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_DB = PROJECT_ROOT / "data" / "demo.db"


def _sandbox_root(policy) -> Path:
    return (PROJECT_ROOT / policy.sandbox_root).resolve()


def _inside_sandbox(path: str, policy) -> Path | None:
    """Resolve a path the guard already approved, or None if it escapes.

    The guard's canonical paths are project-relative ("data/report.txt"),
    while a bare filename is sandbox-relative ("report.txt"). Accept
    both forms, but in both cases the resolved path must be inside the
    resolved sandbox root.
    """
    root = _sandbox_root(policy)
    if path == policy.sandbox_root.rstrip("/") or path.startswith(policy.sandbox_root):
        candidate = (PROJECT_ROOT / path).resolve()
    else:
        candidate = (root / path).resolve()
    if not candidate.is_relative_to(root):
        return None
    return candidate


def _ensure_demo_db() -> Path:
    DEMO_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DEMO_DB)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS findings ("
            "id INTEGER PRIMARY KEY, title TEXT, severity TEXT, status TEXT)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY, email TEXT, role TEXT)")
        if conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO findings (title, severity, status) VALUES (?, ?, ?)",
                [("CWE-787 in parser", "high", "open"),
                 ("CWE-416 in cache", "medium", "fixed"),
                 ("CWE-404 in cleanup", "low", "open")])
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO users (email, role) VALUES (?, ?)",
                [("jane@example.com", "admin"), ("sam@example.com", "user")])
        conn.commit()
    finally:
        conn.close()
    return DEMO_DB


def execute(tool: str, args: dict, policy) -> str:
    if tool == "read_file":
        path = args.get("path", "")
        # Guard already canonicalised this, but re-check here: the
        # executor must not trust the caller, only the resolved path.
        from .guard import _canonical_sandbox_path
        if _canonical_sandbox_path(path, policy.sandbox_root) is None:
            raise ValueError("path outside sandbox")
        candidate = _inside_sandbox(path, policy)
        if candidate is None or not candidate.is_file():
            return f"file not found in sandbox: {path}"
        raw_bytes = candidate.read_bytes()
        truncated = len(raw_bytes) > MAX_FILE_BYTES
        data = raw_bytes[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
        return data + ("\n[truncated at 100 KB]" if truncated else "")

    if tool == "run_command":
        cmd = args.get("command", "")
        parts = cmd.split()
        if not parts or parts[0] not in ("ls", "echo"):
            raise ValueError("command not allowed")
        if parts[0] == "echo":
            return " ".join(parts[1:])
        # ls: map sandbox-relative args to real paths, flags pass through
        argv = ["ls"]
        for arg in parts[1:]:
            if arg.startswith("-"):
                argv.append(arg)
            else:
                candidate = _inside_sandbox(arg, policy)
                if candidate is None:
                    raise ValueError("ls argument outside sandbox")
                argv.append(str(candidate))
        if len(argv) == 1:
            argv.append(str(_sandbox_root(policy)))
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        return (result.stdout + result.stderr).strip()

    if tool == "query_db":
        query = args.get("query", "")
        # Single statement only (sqlite3.execute enforces this too).
        statements = [s.strip() for s in query.split(";") if s.strip()]
        if len(statements) != 1:
            raise ValueError("only a single statement allowed")
        # Table allowlist, re-checked at execution time (guard checks
        # it too; defence in depth, not trust in the caller). For a
        # write, the table named after INTO / UPDATE / TABLE is
        # checked as well, so an approved DROP of a non-allowed table
        # still does not run.
        if policy.allowed_tables:
            from .guard import _query_tables
            import re as _re
            names = set(_query_tables(query))
            for m in _re.finditer(r"\b(?:INTO|UPDATE|TABLE)\s+([A-Za-z_][A-Za-z0-9_]*)",
                                  query, _re.IGNORECASE):
                names.add(m.group(1).lower())
            bad = [t for t in names if t not in policy.allowed_tables]
            if bad:
                raise ValueError(f"table not allowed: {bad[0]}")
        db = _ensure_demo_db()
        conn = sqlite3.connect(db, timeout=5)
        try:
            cur = conn.execute(query)
            if cur.description is not None:
                rows = cur.fetchall()
                cols = [d[0] for d in cur.description]
                lines = [", ".join(cols)]
                lines += [", ".join(str(v) for v in row) for row in rows]
                return "\n".join(lines) if lines else "(no rows)"
            conn.commit()
            return f"ok, {cur.rowcount} row(s) affected"
        finally:
            conn.close()

    if tool == "call_api":
        # See module docstring: intentionally still mocked.
        from . import tools as mock_tools
        return mock_tools.execute(tool, args, policy)

    raise ValueError(f"unknown tool: {tool}")
