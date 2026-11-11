import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.guard import Guard
from agent_guard.policy import Policy
from agent_guard.real_tools import _check_public_host, execute as real_execute


class ListSink:
    def __init__(self):
        self.records = []

    def append(self, record):
        self.records.append(record)


def _policy_for(host):
    return Policy("api-agent", "key-api", {"call_api"}, 30,
                  allowed_hosts={host})


class TestSsrfBlocking(unittest.TestCase):
    def test_private_loopback_and_metadata_are_blocked(self):
        for host in ("127.0.0.1", "10.0.0.5", "192.168.1.1",
                     "169.254.169.254", "localhost", "::1"):
            with self.subTest(host=host):
                g = Guard(policies={"key-api": _policy_for(host)},
                          audit_sink=ListSink(), executor=real_execute)
                d = g.handle("key-api", "call_api",
                             {"host": host, "endpoint": "status"})
                self.assertEqual(d.decision, "BLOCK")

    def test_public_host_check_rejects_private_ip(self):
        with mock.patch("agent_guard.real_tools.socket.getaddrinfo",
                        return_value=[(None, None, None, None, ("10.0.0.5", 443))]):
            with self.assertRaises(ValueError):
                _check_public_host("example.com")

    def test_public_host_check_accepts_public_ip(self):
        with mock.patch("agent_guard.real_tools.socket.getaddrinfo",
                        return_value=[(None, None, None, None, ("93.184.216.34", 443))]):
            _check_public_host("example.com")  # must not raise

    def test_redirect_to_private_host_is_blocked(self):
        # Fake opener: first fetch redirects to a private host.
        # The loop must refuse the second hop before fetching it.
        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return b"ok"

        class FakeOpener:
            def __init__(self):
                self.calls = 0

            def open(self, req, timeout=None):
                self.calls += 1
                if self.calls == 1:
                    from agent_guard.real_tools import _Redirect
                    raise _Redirect("https://127.0.0.1/status")
                return FakeResp()

        fake = FakeOpener()
        with mock.patch("agent_guard.real_tools.socket.getaddrinfo",
                        return_value=[(None, None, None, None, ("93.184.216.34", 443))]):
            with mock.patch("agent_guard.real_tools.urllib.request.build_opener",
                            return_value=fake):
                g = Guard(policies={"key-api": _policy_for("example.com")},
                          audit_sink=ListSink(), executor=real_execute)
                d = g.handle("key-api", "call_api",
                             {"host": "example.com", "endpoint": "status"})
                self.assertEqual(d.decision, "BLOCK")
                self.assertEqual(fake.calls, 1)


if __name__ == "__main__":
    unittest.main()
