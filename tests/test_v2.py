import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.guard import Guard
from agent_guard.policy import Policy
from agent_guard.real_tools import execute as real_execute


class ListSink:
    def __init__(self):
        self.records = []

    def append(self, record):
        self.records.append(record)


def fresh(executor=None):
    return Guard(audit_sink=ListSink(), executor=executor)


class TestApprovals(unittest.TestCase):
    def test_approve_actually_runs_and_is_audited(self):
        g = fresh()
        d = g.handle("key-research-123", "query_db", {"query": "DROP TABLE findings"})
        self.assertEqual(d.decision, "NEEDS_APPROVAL")
        self.assertTrue(d.approval_id)
        # Before approval, nothing has run: the mock DROP returns a
        # result only when executed, and approval is the execution.
        approved = g.approve(d.approval_id)
        self.assertEqual(approved.decision, "ALLOW")
        self.assertIn("DROP TABLE findings", approved.output)
        reasons = [r["reason"] for r in g.audit.records]
        self.assertIn("approval_granted", reasons)
        self.assertEqual(g.list_approvals(), [])

    def test_reject_drops_and_is_audited(self):
        g = fresh()
        d = g.handle("key-research-123", "query_db", {"query": "DROP TABLE findings"})
        rejected = g.reject(d.approval_id)
        self.assertEqual(rejected.decision, "BLOCK")
        self.assertEqual(rejected.reason, "approval_rejected")
        # Approving the same id again now fails: it was consumed.
        self.assertEqual(g.approve(d.approval_id).reason, "approval_not_found")

    def test_approval_expires(self):
        g = fresh()
        g.approval_ttl_seconds = 0
        d = g.handle("key-research-123", "query_db", {"query": "DROP TABLE findings"})
        time.sleep(0.01)
        self.assertEqual(g.approve(d.approval_id).reason, "approval_expired")

    def test_approval_rechecks_policy(self):
        g = fresh()
        d = g.handle("key-research-123", "query_db", {"query": "DROP TABLE findings"})
        # Admin blocks query_db in the meantime: approval must not run it.
        g.set_tool_allowed("key-research-123", "query_db", False)
        self.assertEqual(g.approve(d.approval_id).reason, "approval_tool_no_longer_allowed")


class TestTableAllowlist(unittest.TestCase):
    def test_findings_allowed_users_blocked(self):
        g = fresh()
        self.assertEqual(
            g.handle("key-research-123", "query_db",
                     {"query": "SELECT * FROM findings"}).decision, "ALLOW")
        self.assertEqual(
            g.handle("key-research-123", "query_db",
                     {"query": "SELECT * FROM users"}).decision, "BLOCK")
        self.assertEqual(
            g.handle("key-research-123", "query_db",
                     {"query": "SELECT * FROM users"}).reason, "table_not_allowed")

    def test_no_table_query_still_allowed(self):
        g = fresh()
        self.assertEqual(
            g.handle("key-research-123", "query_db", {"query": "SELECT 1"}).decision, "ALLOW")


class TestExpiringTenantKeys(unittest.TestCase):
    def test_expired_key_blocks(self):
        g = fresh()
        g.policies["key-old"] = Policy(
            "old-agent", "key-old", {"read_file"}, 30,
            tenant_id="acme", expires_at=time.time() - 10)
        self.assertEqual(
            g.handle("key-old", "read_file", {"path": "data/report.txt"}).reason, "key_expired")

    def test_future_key_works_and_tenant_is_audited(self):
        g = fresh()
        g.policies["key-new"] = Policy(
            "new-agent", "key-new", {"read_file"}, 30,
            tenant_id="acme", expires_at=time.time() + 3600)
        self.assertEqual(
            g.handle("key-new", "read_file", {"path": "data/report.txt"}).decision, "ALLOW")
        self.assertEqual(g.audit.records[-1]["tenant"], "acme")


class TestRealTools(unittest.TestCase):
    def test_real_read_file(self):
        g = fresh(executor=real_execute)
        d = g.handle("key-research-123", "read_file", {"path": "data/report.txt"})
        self.assertEqual(d.decision, "ALLOW")
        self.assertIn("vulnerability trends", d.output)

    def test_real_ls(self):
        g = fresh(executor=real_execute)
        # ops-agent, real ls inside the sandbox
        d = g.handle("key-ops-456", "run_command", {"command": "ls data"})
        self.assertEqual(d.decision, "ALLOW")
        self.assertIn("report.txt", d.output)

    def test_real_sqlite_findings_allowed_users_blocked(self):
        g = fresh(executor=real_execute)
        d = g.handle("key-research-123", "query_db", {"query": "SELECT * FROM findings"})
        self.assertEqual(d.decision, "ALLOW")
        self.assertIn("CWE-787", d.output)
        # users is not in the demo allowlist, so guard blocks before
        # the real executor ever sees it
        d2 = g.handle("key-research-123", "query_db", {"query": "SELECT * FROM users"})
        self.assertEqual(d2.decision, "BLOCK")

    def test_real_read_outside_sandbox_blocks(self):
        g = fresh(executor=real_execute)
        self.assertEqual(
            g.handle("key-research-123", "read_file",
                     {"path": "data/../../etc/passwd"}).decision, "BLOCK")


if __name__ == "__main__":
    unittest.main()
