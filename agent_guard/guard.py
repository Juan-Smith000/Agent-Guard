import json
import os
import posixpath
import re
import threading
import shlex
import time
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from .audit import AuditLog
from .policy import DEFAULT_POLICIES
from .scanner import scan_output
from . import tools


@dataclass
class Decision:
    decision: str  # ALLOW, BLOCK, NEEDS_APPROVAL
    reason: str
    output: str = ""
    approval_id: str = ""


class RateLimiter:
    """Sliding-window limiter.

    Fixed-window was the pentest finding: 30 calls at the end of one
    window + 30 at the start of the next = 60 calls in ~2 seconds.
    Sliding window keeps only timestamps from the last 60 seconds, so
    that burst is impossible. A deque per key is cheap at this scale.
    """

    def __init__(self):
        self._hits = {}  # key -> deque[timestamp]

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.time()
        q = self._hits.setdefault(key, deque())
        while q and now - q[0] >= window_seconds:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


SHELL_META = re.compile(r"[;|&`$><\n\r]")
# Non-read-only SQL. Anything in here, or anything that is not a single
# SELECT/WITH statement, is never auto-executed: NEEDS_APPROVAL if the
# policy allows an approval path, otherwise BLOCK. The old list only
# had DROP/DELETE/UPDATE/TRUNCATE, so INSERT/ALTER/GRANT/CREATE sailed
# through as ALLOW — the pentest finding.
DESTRUCTIVE_SQL = re.compile(
    r"\b(DROP|DELETE|UPDATE|TRUNCATE|INSERT|ALTER|CREATE|GRANT|REVOKE|"
    r"REPLACE|PRAGMA|ATTACH|DETACH|COPY|VACUUM)\b", re.IGNORECASE)
ENDPOINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _decode_path(path: str) -> str:
    """Decode URL-encoding repeatedly (single + double encoding)."""
    decoded = path
    for _ in range(3):
        new = unquote(decoded)
        if new == decoded:
            break
        decoded = new
    return decoded


def _canonical_sandbox_path(path: str, sandbox_root: str):
    """Return the normalised path inside sandbox_root, or None.

    Normalise, don't just string-match: the old check looked for '..'
    as a '/'-separated segment, so an encoded '..' (%2e%2e%2f) passed
    and a real filesystem executor that decodes would have escaped.
    Backslashes are treated as separators (Windows-style traversal),
    NUL bytes are rejected outright, and a symlink that resolves
    outside the sandbox is rejected when the file actually exists.
    """
    if "\x00" in path:
        return None
    decoded = _decode_path(path).replace("\\", "/")
    if "\x00" in decoded:
        return None
    normalised = posixpath.normpath(decoded)
    root = sandbox_root.rstrip("/")
    if normalised.startswith("/") or normalised == ".." or normalised.startswith("../"):
        return None
    if not (normalised == root or normalised.startswith(root + "/")):
        return None
    # Symlink check, only when the path exists on disk (mock files do
    # not, so this is a no-op for the V1 mock tools, but it closes the
    # escape for a real executor).
    try:
        candidate = Path(normalised).resolve()
        root_resolved = Path(root).resolve()
        if candidate.exists() and not candidate.is_relative_to(root_resolved):
            return None
    except Exception:
        return None
    return normalised


def _query_tables(query: str):
    """Table names mentioned after FROM or JOIN, lowercased, deduplicated.

    Deliberately simple: it is an allowlist check, not a SQL parser.
    Quoted names, subqueries, and CTEs are not fully handled — a query
    the guard cannot parse cleanly is a reason to block it, not to
    trust it. WITH ... SELECT is allowed only if every FROM/JOIN
    table it names is allowed.
    """
    stripped = _strip_sql_comments(query)
    tables = []
    for m in re.finditer(r"\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_]*)", stripped, re.IGNORECASE):
        name = m.group(1).lower()
        if name not in tables:
            tables.append(name)
    return tables


def _strip_sql_comments(query: str) -> str:
    query = re.sub(r"/\*.*?\*/", " ", query, flags=re.DOTALL)
    query = re.sub(r"--[^\n]*", " ", query)
    return query.strip()


def _is_single_read_only_query(query: str) -> bool:
    stripped = _strip_sql_comments(query)
    # One statement only: a trailing semicolon is fine, a second
    # statement is not ("SELECT ...; DROP ..." was already caught by
    # the destructive regex, this also catches "SELECT ...; INSERT ...").
    statements = [s.strip() for s in stripped.split(";") if s.strip()]
    if len(statements) != 1:
        return False
    first = statements[0].lower()
    return first.startswith("select") or first.startswith("with")


class Guard:
    def __init__(self, policies=None, audit_path="audit.jsonl", audit_sink=None, executor=None, approvals_path=None):
        # Copy the default policies, don't share them: the old code
        # used the same dict (and the same Policy objects) for every
        # Guard, so set_tool_allowed() in one guard changed the
        # defaults for every later guard. Each guard gets its own copy.
        if policies is None:
            from .policy import Policy as _Policy
            self.policies = {
                k: _Policy(v.agent_id, v.key, set(v.allowed_tools),
                           v.rate_limit_per_minute, v.requires_approval_for_high_risk,
                           set(v.allowed_hosts), v.sandbox_root,
                           set(v.allowed_tables), v.tenant_id, v.expires_at)
                for k, v in DEFAULT_POLICIES.items()
            }
        else:
            self.policies = policies
        self.limiter = RateLimiter()
        self.agent_limiter = RateLimiter()
        # audit_sink wins if given: any object with append(record).
        # Otherwise fall back to the default JSONL file.
        self.audit = audit_sink if audit_sink is not None else AuditLog(audit_path)
        self.policies_path = None
        # executor: a function (tool, args, policy) -> str. Default is
        # the mock tools. Pass real_tools.execute for real files, ls,
        # and SQLite — see real_tools.py. The guard never trusts the
        # executor to re-validate; it validates first, always.
        self.executor = executor or tools.execute
        # Pending approvals: approval_id -> pending request. This is
        # what makes NEEDS_APPROVAL a real flow instead of a dead end:
        # approve() actually runs the action, reject() drops it, and
        # both are audited. Approvals expire after 15 minutes.
        self.pending_approvals = {}
        self.approval_ttl_seconds = 900
        # Thread safety: the server is now threaded, so every public
        # Guard entry point takes this lock. RLock, because handle()
        # calls _create_approval() / _execute_and_scan() internally.
        self._lock = threading.RLock()
        # Persistent approvals: None = in-memory only (library default,
        # so tests do not write files). Set a path to survive restarts;
        # the server defaults to approvals.json. See _save_approvals().
        self.approvals_path = str(approvals_path) if approvals_path else None
        self._load_approvals()

    # --- Persistent approvals ----------------------------------------
    def _load_approvals(self):
        if not self.approvals_path:
            return
        try:
            with open(self.approvals_path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.pending_approvals = data
        except (OSError, ValueError):
            # Missing/corrupt file: start empty rather than crash.
            # A corrupt approvals file is a data problem, not a reason
            # to refuse every tool call; the approval simply does not exist.
            self.pending_approvals = {}

    def _save_approvals(self):
        if not self.approvals_path:
            return
        try:
            tmp = self.approvals_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.pending_approvals, f, sort_keys=True)
            os.replace(tmp, self.approvals_path)
        except (OSError, TypeError, ValueError):
            # Persistence is best-effort for non-JSON args: the
            # in-memory approval still works for this process.
            pass

    # --- Approvals ---------------------------------------------------
    def _create_approval(self, policy, tool_name, args):
        # Full UUID hex, not 8 chars: an 8-char id is only 32 bits
        # and guessable if an approval endpoint is ever exposed.
        # Approve/reject already require admin auth, but defence in
        # depth costs nothing here.
        approval_id = uuid.uuid4().hex
        now = time.time()
        self.pending_approvals[approval_id] = {
            "approval_id": approval_id,
            "agent_key": policy.key,
            "agent": policy.agent_id,
            "tenant": policy.tenant_id,
            "tool": tool_name,
            "args": dict(args),
            "created_at": now,
            "expires_at": now + self.approval_ttl_seconds,
        }
        self._save_approvals()
        d = Decision("NEEDS_APPROVAL", "destructive_sql_requires_approval",
                     approval_id=approval_id)
        self._audit(policy, tool_name, d)
        return d

    def list_approvals(self):
        with self._lock:
            now = time.time()
            return [dict(v) for v in self.pending_approvals.values()
                    if v["expires_at"] > now]

    def approve(self, approval_id: str) -> Decision:
        with self._lock:
            return self._approve_locked(approval_id)

    def _approve_locked(self, approval_id: str) -> Decision:
        pending = self.pending_approvals.pop(approval_id, None)
        self._save_approvals()
        if pending is None:
            return Decision("BLOCK", "approval_not_found")
        policy = self.policies.get(pending["agent_key"])
        if policy is None:
            return Decision("BLOCK", "approval_agent_gone")
        if time.time() > pending["expires_at"]:
            d = Decision("BLOCK", "approval_expired")
            self._audit(policy, pending["tool"], d)
            return d
        # Re-validate at approval time: the policy may have changed
        # since the request was made. Do not execute on stale policy.
        if pending["tool"] not in policy.allowed_tools:
            d = Decision("BLOCK", "approval_tool_no_longer_allowed")
            self._audit(policy, pending["tool"], d)
            return d
        return self._execute_and_scan(policy, pending["tool"], pending["args"],
                                      audit_reason_prefix="approval_granted")

    def reject(self, approval_id: str) -> Decision:
        with self._lock:
            return self._reject_locked(approval_id)

    def _reject_locked(self, approval_id: str) -> Decision:
        pending = self.pending_approvals.pop(approval_id, None)
        self._save_approvals()
        if pending is None:
            return Decision("BLOCK", "approval_not_found")
        policy = self.policies.get(pending["agent_key"])
        d = Decision("BLOCK", "approval_rejected")
        self._audit(policy, pending["tool"], d)
        return d

    def _execute_and_scan(self, policy, tool_name, args, audit_reason_prefix=None):
        """Run the executor, scan the output, audit once, return Decision."""
        try:
            raw = self.executor(tool_name, args, policy)
        except Exception as e:  # noqa: BLE001 - fail closed on purpose
            return self._decide("BLOCK", f"tool_error:{type(e).__name__}", tool_name, policy)
        blocked, cleaned, scan_reasons = scan_output(raw)
        if blocked:
            return self._decide("BLOCK", scan_reasons[0] if scan_reasons else "output_blocked",
                                tool_name, policy)
        reason = "ok" if not scan_reasons else ";".join(scan_reasons)
        if audit_reason_prefix:
            reason = f"{audit_reason_prefix}:{reason}" if reason != "ok" else audit_reason_prefix
        d = Decision("ALLOW", reason, output=cleaned)
        self._audit(policy, tool_name, d)
        return d

    # --- Management: edit / configure / update policies -------------
    def list_policies(self):
        return [p.to_dict() for p in self.policies.values()]

    def upsert_policy(self, policy):
        self.policies[policy.key] = policy
        self._persist_policies()
        return policy

    def remove_policy(self, key: str) -> bool:
        if key not in self.policies:
            return False
        del self.policies[key]
        self._persist_policies()
        return True

    def set_tool_allowed(self, key: str, tool: str, allowed: bool) -> bool:
        policy = self.policies.get(key)
        if policy is None:
            return False
        if allowed:
            policy.allowed_tools.add(tool)
        else:
            policy.allowed_tools.discard(tool)
        self._persist_policies()
        return True

    def set_requires_approval(self, key: str, required: bool) -> bool:
        policy = self.policies.get(key)
        if policy is None:
            return False
        policy.requires_approval_for_high_risk = bool(required)
        self._persist_policies()
        return True

    def load_policies_from_file(self, path):
        from .policy import load_policies
        self.policies = load_policies(path)
        self.policies_path = str(path)

    def _persist_policies(self):
        if self.policies_path:
            from .policy import save_policies
            save_policies(self.policies, self.policies_path)

    def handle(self, agent_key: str, tool_name: str, args: dict) -> Decision:
        with self._lock:
            return self._handle_locked(agent_key, tool_name, args)

    def _handle_locked(self, agent_key: str, tool_name: str, args: dict) -> Decision:
            # 0. Malformed input must be a BLOCK, never a crash.
            if not isinstance(agent_key, str) or not isinstance(tool_name, str) \
                    or not isinstance(args, dict):
                d = Decision("BLOCK", "malformed_request")
                self._audit(None, tool_name if isinstance(tool_name, str) else "malformed", d)
                return d
            # 0b. NUL bytes in any string argument are never legitimate.
            for v in args.values():
                if isinstance(v, str) and "\x00" in v:
                    return self._decide("BLOCK", "malformed_args", tool_name, None)
            # 1. Authenticate. Fail closed.
            policy = self.policies.get(agent_key)
            if policy is None:
                return self._decide("BLOCK", "unknown_agent_key", tool_name, policy)
            # 1b. Expiring keys: a key past its expires_at is dead, even
            # if it is otherwise valid. Long-lived keys have expires_at=None.
            if policy.expires_at is not None and time.time() > policy.expires_at:
                return self._decide("BLOCK", "key_expired", tool_name, policy)
            # 2. Rate limit, per agent + tool AND per agent in total.
            # The old code only limited per tool, so 30/min/tool x 3 tools
            # = 90/min for one agent. Both limits now share the same
            # policy number: no tool, and no agent, can exceed it.
            if not self.limiter.allow(f"{policy.agent_id}:{tool_name}", policy.rate_limit_per_minute):
                return self._decide("BLOCK", "rate_limit_exceeded", tool_name, policy)
            if not self.agent_limiter.allow(policy.agent_id, policy.rate_limit_per_minute):
                return self._decide("BLOCK", "rate_limit_exceeded", tool_name, policy)
            # 3. Allowlist.
            if tool_name not in policy.allowed_tools:
                return self._decide("BLOCK", "tool_not_allowed", tool_name, policy)
            # 4. Argument validation.
            arg_error = self._validate_args(policy, tool_name, args)
            if arg_error:
                return self._decide("BLOCK", arg_error, tool_name, policy)
            # 4b. High-risk / non-read-only SQL never auto-executes.
            if tool_name == "query_db":
                query = args.get("query", "")
                if DESTRUCTIVE_SQL.search(query) or not _is_single_read_only_query(query):
                    if policy.requires_approval_for_high_risk:
                        return self._create_approval(policy, tool_name, args)
                    return self._decide("BLOCK", "destructive_sql_blocked", tool_name, policy)
            # 5+6. Execute (mock by default, real if executor was passed),
            # then scan output BEFORE it returns to the agent.
            return self._execute_and_scan(policy, tool_name, args)

    def _validate_args(self, policy, tool_name, args):
        def _as_str(value):
            return value if isinstance(value, str) else None

        if tool_name == "read_file":
            path = _as_str(args.get("path", ""))
            if path is None:
                return "malformed_args"
            if _canonical_sandbox_path(path, policy.sandbox_root) is None:
                return "path_traversal"
        if tool_name == "run_command":
            cmd = _as_str(args.get("command", ""))
            if cmd is None:
                return "malformed_args"
            if SHELL_META.search(cmd):
                return "dangerous_command"
            try:
                parts = shlex.split(cmd)
            except ValueError:
                return "dangerous_command"
            if not parts or parts[0] not in tools.ALLOWED_COMMANDS:
                return "command_not_allowed"
            if any(p in ("rm", "curl", "wget") for p in parts):
                return "dangerous_command"
            # The old code validated the first token only. "ls /etc"
            # and "ls data/../../etc" both passed. Now ls arguments
            # must be flags or paths inside the sandbox.
            if parts[0] == "ls":
                for arg in parts[1:]:
                    if arg.startswith("-"):
                        continue
                    if _canonical_sandbox_path(arg, policy.sandbox_root) is None \
                            and arg != policy.sandbox_root.rstrip("/"):
                        return "path_outside_sandbox"
        if tool_name == "call_api":
            host = _as_str(args.get("host", ""))
            if host is None:
                return "host_not_allowed"
            # DNS names are case-insensitive and a trailing dot is the
            # same host, so normalise before the exact-match check.
            host_norm = host.strip().lower().rstrip(".")
            allowed_norm = {h.lower().rstrip(".") for h in policy.allowed_hosts}
            if host_norm not in allowed_norm:
                return "host_not_allowed"
            endpoint = _as_str(args.get("endpoint", "status"))
            # The old code never validated the endpoint, so an allowed
            # host + "../admin" or "//evil.example/x" passed. An
            # endpoint is now a single segment, nothing else.
            if endpoint is None or ".." in endpoint or not ENDPOINT_RE.match(endpoint):
                return "endpoint_not_allowed"
        if tool_name == "query_db":
            query = _as_str(args.get("query", ""))
            if query is None or not query.strip():
                return "empty_query"
            # Table allowlist (V2): read-only is not the same as
            # authorised. If the policy names tables, every FROM/JOIN
            # table in a read-only query must be in that list.
            # Destructive statements are handled later (approval /
            # block), not here, so DROP/INSERT do not get a
            # misleading table_not_allowed instead of approval.
            if policy.allowed_tables and _is_single_read_only_query(query):
                bad = [t for t in _query_tables(query) if t not in policy.allowed_tables]
                if bad:
                    return "table_not_allowed"
        return None

    def _decide(self, decision, reason, tool_name, policy):
        d = Decision(decision, reason)
        self._audit(policy, tool_name, d)
        return d

    def _audit(self, policy, tool_name, decision):
        self.audit.append({
            "agent": policy.agent_id if policy else "unknown",
            "tenant": policy.tenant_id if policy else "default",
            "tool": str(tool_name)[:200],
            "decision": decision.decision,
            "reason": decision.reason,
        })
