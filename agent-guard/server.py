"""Stdlib HTTP front-end.

- POST /tool            agent tool calls (X-Agent-Key header)
- GET  /health          liveness check
- GET  /admin           management UI (HTML) — edit policies in a browser
- GET  /admin/policies  list policies as JSON
- POST /admin/policies  create / update a policy (JSON body)
- DELETE /admin/policies?key=...   delete a policy
- GET  /admin/stats     audit stats (if the sink supports stats)
- POST /admin/reload    reload policies from POLICIES_PATH, if set
- GET  /admin/approvals list pending approvals (NEEDS_APPROVAL requests)
- POST /admin/approvals/approve  {"approval_id": "..."} -> actually runs it
- POST /admin/approvals/reject   {"approval_id": "..."} -> drops it, audited

Admin protection: if ADMIN_KEY is set, /admin/* requires the
X-Admin-Key header to match. If it is not set, admin is only open
when the server binds loopback; binding 0.0.0.0 without ADMIN_KEY
disables admin (403). Do not expose it publicly without setting
ADMIN_KEY and putting TLS + real auth in front of it.

Env: HOST (default 127.0.0.1), PORT (8080), AUDIT_BACKEND (jsonl|sqlite),
AUDIT_PATH, POLICIES_PATH (optional JSON file to load/persist policies),
REAL_TOOLS (1 = real file/ls/SQLite executor instead of mocks),
GENERIC_TOOL_REASONS (1 = return "blocked" for every BLOCK).
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .audit import make_audit_sink
from .guard import Guard
from .policy import Policy

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
MAX_BODY_SIZE = 1_000_000  # 1 MB: the old code read any Content-Length uncapped
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
POLICIES_PATH = os.environ.get("POLICIES_PATH", "")

_AUDIT_BACKEND = os.environ.get("AUDIT_BACKEND", "jsonl")
_AUDIT_PATH = os.environ.get(
    "AUDIT_PATH", "audit.db" if _AUDIT_BACKEND == "sqlite" else "audit.jsonl")
_executor = None
if os.environ.get("REAL_TOOLS", "") == "1":
    from .real_tools import execute as _executor
GUARD = Guard(audit_sink=make_audit_sink(_AUDIT_BACKEND, _AUDIT_PATH), executor=_executor)
if POLICIES_PATH and Path(POLICIES_PATH).exists():
    GUARD.load_policies_from_file(POLICIES_PATH)
elif POLICIES_PATH:
    GUARD.policies_path = POLICIES_PATH

_ADMIN_HTML = Path(__file__).parent / "admin.html"


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code, obj):
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _admin_ok(self):
        # Pentest fix (critical, Docker): the old code returned True
        # whenever ADMIN_KEY was unset — and the Dockerfile binds
        # 0.0.0.0, so /admin/policies leaked keys and /admin/policies
        # POST let anyone create a full policy, to anyone who could
        # reach the published port. Now: with ADMIN_KEY set, it is
        # required; without it, admin is only open when the server
        # itself binds loopback (local dev). Binding 0.0.0.0 without
        # ADMIN_KEY disables admin entirely (403), it does not open it.
        if ADMIN_KEY:
            return self.headers.get("X-Admin-Key", "") == ADMIN_KEY
        return HOST in LOOPBACK_HOSTS

    def _read_body(self):
        """Read the request body safely, or send an error and return None.

        The old code did int(Content-Length) outside any try, so a
        non-numeric header raised, and it read any size uncapped.
        """
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "invalid_content_length"}')
            return None
        if length < 0 or length > MAX_BODY_SIZE:
            self.send_response(413)
            self.end_headers()
            self.wfile.write(b'{"error": "body_too_large"}')
            return None
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        parsed = urlparse(self.path)
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        if parsed.path == "/admin":
            if not self._admin_ok():
                self.send_response(403)
                self.end_headers()
                return
            html = _ADMIN_HTML.read_text() if _ADMIN_HTML.exists() else "<h1>Admin UI missing</h1>"
            payload = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)
            return
        if parsed.path == "/admin/policies":
            if not self._admin_ok():
                self.send_response(403)
                self.end_headers()
                return
            self._send_json(200, GUARD.list_policies())
            return
        if parsed.path == "/admin/stats":
            if not self._admin_ok():
                self.send_response(403)
                self.end_headers()
                return
            stats = GUARD.audit.stats() if hasattr(GUARD.audit, "stats") else {}
            self._send_json(200, stats)
            return
        if parsed.path == "/admin/approvals":
            if not self._admin_ok():
                self.send_response(403)
                self.end_headers()
                return
            # Strip agent_key: the UI needs agent, tool, args, and
            # expiry, not the key itself, and an approval listing
            # should not become another place keys leak from.
            cleaned = [{k: v for k, v in a.items() if k != "agent_key"}
                       for a in GUARD.list_approvals()]
            self._send_json(200, cleaned)
            return
        self.send_response(404)
        self.end_headers()

    def _approval_action(self, approve: bool):
        if not self._admin_ok():
            self.send_response(403)
            self.end_headers()
            return
        raw = self._read_body()
        if raw is None:
            return
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid_json"})
            return
        approval_id = body.get("approval_id", "")
        if not isinstance(approval_id, str) or not approval_id:
            self._send_json(400, {"error": "missing approval_id"})
            return
        d = GUARD.approve(approval_id) if approve else GUARD.reject(approval_id)
        self._send_json(200, {"decision": d.decision, "reason": d.reason,
                              "output": d.output, "approval_id": d.approval_id})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/admin/approvals/approve":
            self._approval_action(approve=True)
            return
        if parsed.path == "/admin/approvals/reject":
            self._approval_action(approve=False)
            return
        if parsed.path == "/admin/reload":
            if not self._admin_ok():
                self.send_response(403)
                self.end_headers()
                return
            if not POLICIES_PATH or not Path(POLICIES_PATH).exists():
                self._send_json(400, {"error": "no POLICIES_PATH file to reload"})
                return
            GUARD.load_policies_from_file(POLICIES_PATH)
            self._send_json(200, {"reloaded": len(GUARD.policies)})
            return
        if parsed.path == "/admin/policies":
            if not self._admin_ok():
                self.send_response(403)
                self.end_headers()
                return
            raw = self._read_body()
            if raw is None:
                return
            try:
                body = json.loads(raw or b"{}")
                policy = Policy.from_dict(body)
            except (json.JSONDecodeError, ValueError) as e:
                self._send_json(400, {"error": str(e)})
                return
            GUARD.upsert_policy(policy)
            self._send_json(200, policy.to_dict())
            return
        if self.path != "/tool":
            self.send_response(404)
            self.end_headers()
            return
        raw = self._read_body()
        if raw is None:
            return
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "invalid_json"}')
            return
        if not isinstance(body, dict):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "body_must_be_object"}')
            return
        key = self.headers.get("X-Agent-Key", "")
        d = GUARD.handle(key, body.get("tool", ""), body.get("args", {}))
        # Oracle mitigation (opt-in): detailed reasons help a legitimate
        # agent debug, but they also let a key-guesser distinguish
        # "wrong key" from "right key, wrong tool". Set
        # GENERIC_TOOL_REASONS=1 to return "blocked" for every BLOCK
        # and put the detail only in the audit log. Default is off,
        # because breaking the reason field breaks legitimate debugging
        # and the demo keys are the real problem (rotate them).
        reason = d.reason
        if os.environ.get("GENERIC_TOOL_REASONS", "") == "1" and d.decision == "BLOCK":
            reason = "blocked"
        self._send_json(200, {"decision": d.decision, "reason": reason,
                              "output": d.output, "approval_id": d.approval_id})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/admin/policies":
            if not self._admin_ok():
                self.send_response(403)
                self.end_headers()
                return
            key = parse_qs(parsed.query).get("key", [None])[0]
            if not key:
                self._send_json(400, {"error": "missing ?key="})
                return
            if GUARD.remove_policy(key):
                self._send_json(200, {"deleted": key})
            else:
                self._send_json(404, {"error": "policy not found"})
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"agent-guard listening on {HOST}:{PORT}  (POST /tool, GET /health, GET /admin)")
    if not ADMIN_KEY and HOST not in LOOPBACK_HOSTS:
        print("WARNING: ADMIN_KEY is not set and HOST is not loopback — "
              "/admin/* is disabled (403) until ADMIN_KEY is set. "
              "Do not publish this port without it.")
    HTTPServer((HOST, PORT), Handler).serve_forever()
