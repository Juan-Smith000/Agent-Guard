import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.guard import Guard


class ListSink:
    def __init__(self):
        self.records = []

    def append(self, record):
        self.records.append(record)


class TestPersistentApprovals(unittest.TestCase):
    def test_approval_survives_guard_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "approvals.json")
            g1 = Guard(audit_sink=ListSink(), approvals_path=path)
            d = g1.handle("key-research-123", "query_db",
                          {"query": "DROP TABLE findings"})
            self.assertEqual(d.decision, "NEEDS_APPROVAL")
            # New Guard, same file: the approval is still there.
            g2 = Guard(audit_sink=ListSink(), approvals_path=path)
            ids = [a["approval_id"] for a in g2.list_approvals()]
            self.assertIn(d.approval_id, ids)
            approved = g2.approve(d.approval_id)
            self.assertEqual(approved.decision, "ALLOW")
            self.assertIn("approval_granted", approved.reason)
            # Consumed: a third Guard does not see it again.
            g3 = Guard(audit_sink=ListSink(), approvals_path=path)
            self.assertEqual(g3.list_approvals(), [])

    def test_reject_is_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "approvals.json")
            g1 = Guard(audit_sink=ListSink(), approvals_path=path)
            d = g1.handle("key-research-123", "query_db",
                          {"query": "DROP TABLE findings"})
            g1.reject(d.approval_id)
            g2 = Guard(audit_sink=ListSink(), approvals_path=path)
            self.assertEqual(g2.list_approvals(), [])

    def test_concurrent_handles_do_not_crash(self):
        g = Guard(audit_sink=ListSink())
        errors = []

        def call():
            try:
                g.handle("key-research-123", "read_file",
                         {"path": "data/report.txt"})
            except Exception as e:  # noqa: BLE001 - test must surface it
                errors.append(e)

        threads = [threading.Thread(target=call) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
