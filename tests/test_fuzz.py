import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.fuzz import run_fuzz
from agent_guard.guard import Guard


class TestFuzz(unittest.TestCase):
    def test_seeded_fuzz_no_crashes_or_violations(self):
        stats, violations, crashes = run_fuzz(seed=42, iterations=500)
        self.assertEqual(crashes, [], "\n".join(crashes[:10]))
        self.assertEqual(violations, [], "\n".join(violations[:10]))
        self.assertEqual(stats["total"], 500)

    def test_malformed_inputs_are_blocks_not_crashes(self):
        g = Guard(audit_path=tempfile.mktemp(suffix=".jsonl"))
        for key, tool, args in [
            (None, "read_file", {"path": "data/report.txt"}),
            ("key-research-123", 123, {"path": "data/report.txt"}),
            ("key-research-123", "read_file", ["data/report.txt"]),
            ("key-research-123", "read_file", {"path": 12345}),
            ("key-research-123", "query_db", {"query": None}),
            ("key-research-123", "run_command", {"command": ["ls"]}),
            (["key"], "read_file", {"path": "data/report.txt"}),
        ]:
            d = g.handle(key, tool, args)  # type: ignore
            self.assertEqual(d.decision, "BLOCK", f"{key!r} {tool!r} {args!r}")
