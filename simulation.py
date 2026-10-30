"""Live simulation: a day in the life of Agent Guard.

Not a unit test and not the pentest. This is a story run through the
real Guard code, in order, with three actors:
  - research-agent: normal, benign work
  - ops-agent: normal work that sometimes touches risky tools
  - attacker: no valid key, plus a compromised-looking agent trying
    traversal, injection, destructive SQL and SSRF

Run: python3 simulation.py
Output is printed, and every decision is also audited in-memory.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_guard.guard import Guard
from agent_guard.policy import Policy


class MemSink:
    def __init__(self):
        self.records = []

    def append(self, r):
        self.records.append(r)


def main():
    sink = MemSink()
    g = Guard(audit_sink=sink)
    # Fresh, high-limit policies for the story, so the story is about
    # decisions, not about hitting the 30/min demo limit mid-story.
    g.policies = {
        "key-research-123": Policy("research-agent", "key-research-123",
                                   {"read_file", "query_db", "call_api"},
                                   rate_limit_per_minute=1000,
                                   allowed_hosts={"api.internal.example"}),
        "key-ops-456": Policy("ops-agent", "key-ops-456",
                              {"read_file", "query_db", "call_api", "run_command"},
                              rate_limit_per_minute=1000,
                              allowed_hosts={"api.internal.example"}),
    }

    scenes = [
        # (actor, description, key, tool, args)
        ("research-agent", "Morning: read the weekly report",
         "key-research-123", "read_file", {"path": "data/report.txt"}),
        ("research-agent", "Morning: check findings in the DB",
         "key-research-123", "query_db", {"query": "SELECT * FROM findings LIMIT 10"}),
        ("research-agent", "Morning: check internal API status",
         "key-research-123", "call_api", {"host": "api.internal.example", "endpoint": "status"}),
        ("research-agent", "Morning: read a file with contact info (PII inside)",
         "key-research-123", "read_file", {"path": "data/pii.txt"}),
        ("research-agent", "Morning: read a file with a deploy key inside",
         "key-research-123", "read_file", {"path": "data/secret.txt"}),
        ("ops-agent", "Midday: list files",
         "key-ops-456", "run_command", {"command": "ls"}),
        ("ops-agent", "Midday: try to delete something destructive",
         "key-ops-456", "run_command", {"command": "rm -rf /"}),
        ("research-agent", "Midday: try a tool she is not allowed",
         "key-research-123", "run_command", {"command": "ls"}),
        ("research-agent", "Midday: open a file that contains a planted instruction",
         "key-research-123", "read_file", {"path": "data/notes.txt"}),
        ("research-agent", "Midday: call an external host",
         "key-research-123", "call_api", {"host": "evil.example", "endpoint": "status"}),
        ("research-agent", "Midday: drop a table (high-risk)",
         "key-research-123", "query_db", {"query": "DROP TABLE findings"}),
        ("attacker", "Afternoon: no key at all",
         "key-nope", "read_file", {"path": "data/report.txt"}),
        ("attacker", "Afternoon: path traversal attempt",
         "key-research-123", "read_file", {"path": "data/../../etc/passwd"}),
        ("attacker", "Afternoon: encoded traversal attempt",
         "key-research-123", "read_file", {"path": "data/%2e%2e%2fsecret.txt"}),
        ("attacker", "Afternoon: write to the DB, disguised as a query",
         "key-research-123", "query_db", {"query": "INSERT INTO users VALUES (1, 'x')"}),
        ("attacker", "Afternoon: shell chaining",
         "key-ops-456", "run_command", {"command": "ls; id"}),
        ("research-agent", "Evening: back to normal work, still allowed",
         "key-research-123", "read_file", {"path": "data/report.txt"}),
    ]

    print("=== AGENT GUARD SIMULATION ===\n")
    for actor, desc, key, tool, args in scenes:
        d = g.handle(key, tool, args)
        out = d.output[:90].replace("\n", " ") if d.output else ""
        extra = f" approval={d.approval_id}" if d.approval_id else ""
        print(f"{actor:15} | {desc}")
        print(f"                -> {d.decision} ({d.reason}){extra}")
        if out:
            print(f"                   output: {out}")
        print()

    from collections import Counter
    counts = Counter(r["decision"] for r in sink.records)
    print("=== AUDIT SUMMARY ===")
    print(f"Total decisions: {len(sink.records)}")
    for k in ("ALLOW", "BLOCK", "NEEDS_APPROVAL"):
        print(f"  {k}: {counts.get(k, 0)}")
    print()
    print("=== RATE-LIMIT MINI-SCENE ===")
    g2 = Guard(audit_sink=MemSink())
    # ops-agent demo limit is 10/min for run_command in the real defaults
    allowed = 0
    for _ in range(12):
        if g2.handle("key-ops-456", "run_command", {"command": "ls"}).decision == "ALLOW":
            allowed += 1
    print(f"ops-agent asked for 'ls' 12 times in under a minute, "
          f"limit 10/min -> {allowed} allowed, {12 - allowed} blocked by rate limit")
    print("Legitimate work resumes in the next minute; nothing crashed.")
    print()
    print("=== V2 SCENES: real tools, approvals that actually run, tables, expiry ===")
    from agent_guard.real_tools import execute as real_execute
    import time as _time
    g3 = Guard(audit_sink=MemSink(), executor=real_execute)
    d = g3.handle("key-research-123", "read_file", {"path": "data/report.txt"})
    print(f"real read_file data/report.txt -> {d.decision}, output starts: {d.output[:60]!r}")
    d = g3.handle("key-research-123", "query_db", {"query": "SELECT * FROM findings"})
    print(f"real query findings -> {d.decision}, rows: {len(d.output.splitlines())-1}")
    d = g3.handle("key-research-123", "query_db", {"query": "SELECT * FROM users"})
    print(f"real query users (not in table allowlist) -> {d.decision} ({d.reason})")
    d = g3.handle("key-research-123", "query_db", {"query": "DROP TABLE findings"})
    print(f"DROP -> {d.decision}, approval_id={d.approval_id} (nothing ran yet)")
    if d.approval_id:
        # Reject it here, so the demo DB is not actually dropped in the
        # simulation. Approving is shown in tests and in the server demo.
        r = g3.reject(d.approval_id)
        print(f"human rejects it -> {r.decision} ({r.reason}), approval consumed")
    g3.policies["key-old"] = Policy("old-agent", "key-old", {"read_file"}, 30,
                                    tenant_id="acme", expires_at=_time.time() - 10)
    d = g3.handle("key-old", "read_file", {"path": "data/report.txt"})
    print(f"expired key (tenant acme) -> {d.decision} ({d.reason})")


if __name__ == "__main__":
    main()
