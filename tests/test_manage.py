import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.guard import Guard
from agent_guard.policy import Policy, load_policies, save_policies


class TestManage(unittest.TestCase):
    def test_allow_block_approval_toggle_take_effect_immediately(self):
        g = Guard(audit_path=tempfile.mktemp(suffix=".jsonl"))
        # research agent cannot run commands at first
        self.assertEqual(
            g.handle("key-research-123", "run_command", {"command": "ls"}).decision, "BLOCK")
        # management: allow it
        self.assertTrue(g.set_tool_allowed("key-research-123", "run_command", True))
        self.assertEqual(
            g.handle("key-research-123", "run_command", {"command": "ls"}).decision, "ALLOW")
        # management: block it again
        self.assertTrue(g.set_tool_allowed("key-research-123", "run_command", False))
        self.assertEqual(
            g.handle("key-research-123", "run_command", {"command": "ls"}).decision, "BLOCK")
        # management: turn approval off -> destructive SQL is BLOCKed
        # outright (never auto-executed, with or without approval).
        self.assertTrue(g.set_requires_approval("key-research-123", False))
        self.assertEqual(
            g.handle("key-research-123", "query_db", {"query": "DROP TABLE findings"}).decision,
            "BLOCK")
        self.assertTrue(g.set_requires_approval("key-research-123", True))
        self.assertEqual(
            g.handle("key-research-123", "query_db", {"query": "DROP TABLE findings"}).decision,
            "NEEDS_APPROVAL")

    def test_policy_json_roundtrip(self):
        path = tempfile.mktemp(suffix=".json")
        policies = {"k1": Policy("a1", "k1", {"read_file"}, 10, True, {"h.example"})}
        save_policies(policies, path)
        loaded = load_policies(path)
        self.assertEqual(loaded["k1"].to_dict(), policies["k1"].to_dict())

    def test_upsert_and_remove(self):
        g = Guard(audit_path=tempfile.mktemp(suffix=".jsonl"))
        g.upsert_policy(Policy("analyst", "key-analyst-789", {"read_file"}, 20))
        self.assertEqual(
            g.handle("key-analyst-789", "read_file", {"path": "data/report.txt"}).decision, "ALLOW")
        self.assertTrue(g.remove_policy("key-analyst-789"))
        self.assertEqual(
            g.handle("key-analyst-789", "read_file", {"path": "data/report.txt"}).decision, "BLOCK")
