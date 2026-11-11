import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.guard import Guard
from agent_guard.templates import PROTECTED_RULES, TEMPLATES, list_templates, policy_from_template


class TestTemplates(unittest.TestCase):
    def test_all_templates_are_valid_policies(self):
        for tid in TEMPLATES:
            p = policy_from_template(tid, "test-agent", f"key-{tid}")
            self.assertTrue(p.agent_id and p.key)
            self.assertTrue(1 <= p.rate_limit_per_minute <= 1000)

    def test_unknown_template_rejected(self):
        with self.assertRaises(ValueError):
            policy_from_template("nope", "a", "k")

    def test_list_templates_covers_all(self):
        ids = {t["id"] for t in list_templates()}
        self.assertEqual(ids, set(TEMPLATES))
        # Lockdown is strictest: read_file only, no approval queue
        lockdown = next(t for t in list_templates() if t["id"] == "lockdown")
        self.assertEqual(lockdown["allowed_tools"], ["read_file"])

    def test_template_customisation_cannot_disable_protected_rules(self):
        # The point of PROTECTED_RULES: even the most permissive
        # template, and even a customised policy, cannot turn these off.
        # 1. Sandbox developer allows run_command, but rm is still blocked.
        g = Guard(audit_path=tempfile.mktemp(suffix=".jsonl"),
                  policies={"key-dev": policy_from_template(
                      "sandbox-developer", "dev", "key-dev")})
        self.assertEqual(g.handle("key-dev", "run_command",
                                  {"command": "rm -rf /"}).decision, "BLOCK")
        # 2. Same template allows query_db, but DROP still needs approval, never ALLOW.
        d = g.handle("key-dev", "query_db", {"query": "DROP TABLE findings"})
        self.assertEqual(d.decision, "NEEDS_APPROVAL")
        # 3. Research template allows query_db, but users table is still blocked.
        g2 = Guard(audit_path=tempfile.mktemp(suffix=".jsonl"),
                   policies={"key-r": policy_from_template(
                       "research-readonly", "research", "key-r")})
        d = g2.handle("key-r", "query_db", {"query": "SELECT * FROM users"})
        self.assertEqual(d.decision, "BLOCK")
        self.assertEqual(d.reason, "table_not_allowed")
        # 4. CI template has approval OFF, so destructive is BLOCK, not approval.
        g3 = Guard(audit_path=tempfile.mktemp(suffix=".jsonl"),
                   policies={"key-ci": policy_from_template(
                       "ci-compliance", "ci", "key-ci")})
        self.assertEqual(g3.handle("key-ci", "query_db",
                                   {"query": "DROP TABLE findings"}).decision, "BLOCK")

    def test_protected_rules_documented(self):
        ids = {r["id"] for r in PROTECTED_RULES}
        for wanted in ("sandbox_only", "no_dangerous_commands", "no_outside_hosts",
                       "no_auto_destructive", "unknown_is_block", "output_is_scanned",
                       "table_allowlist", "rate_limit_cannot_be_unlimited"):
            self.assertIn(wanted, ids)


if __name__ == "__main__":
    unittest.main()
