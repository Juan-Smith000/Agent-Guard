import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.audit import AuditLog, SqliteAuditLog, make_audit_sink
from agent_guard.guard import Guard


class ListSink:
    def __init__(self):
        self.records = []

    def append(self, record):
        self.records.append(record)


class TestAuditSinks(unittest.TestCase):
    def test_jsonl_sink(self):
        path = tempfile.mktemp(suffix=".jsonl")
        g = Guard(audit_sink=AuditLog(path))
        g.handle("key-research-123", "read_file", {"path": "data/report.txt"})
        self.assertEqual(g.audit.stats()["total"], 1)

    def test_sqlite_sink(self):
        path = tempfile.mktemp(suffix=".db")
        g = Guard(audit_sink=SqliteAuditLog(path))
        g.handle("key-research-123", "read_file", {"path": "data/report.txt"})
        g.handle("key-nope", "read_file", {"path": "data/report.txt"})
        stats = g.audit.stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["by_decision"]["ALLOW"], 1)
        self.assertEqual(stats["by_decision"]["BLOCK"], 1)

    def test_custom_sink_plug_in(self):
        """This is the 'plug in your own database' contract: any
        object with append(record) works, no code change in Guard."""
        sink = ListSink()
        g = Guard(audit_sink=sink)
        g.handle("key-research-123", "query_db", {"query": "DROP TABLE findings"})
        self.assertEqual(len(sink.records), 1)
        self.assertEqual(sink.records[0]["decision"], "NEEDS_APPROVAL")

    def test_make_audit_sink(self):
        self.assertIsInstance(make_audit_sink("jsonl", tempfile.mktemp()), AuditLog)
        self.assertIsInstance(make_audit_sink("sqlite", tempfile.mktemp()), SqliteAuditLog)
        with self.assertRaises(ValueError):
            make_audit_sink("postgres", "x")
