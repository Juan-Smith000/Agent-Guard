import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

KNOWN_TOOLS = {"read_file", "query_db", "call_api", "run_command"}
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TENANT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclass
class Policy:
    agent_id: str
    key: str
    allowed_tools: set
    rate_limit_per_minute: int = 30
    requires_approval_for_high_risk: bool = True
    allowed_hosts: set = field(default_factory=set)
    sandbox_root: str = "data/"
    # V2, from simulated-customer feedback:
    # - allowed_tables: empty = no table restriction (library default,
    #   for backwards compatibility). Demo policies set {"findings"},
    #   so a SELECT from any other table is blocked, not just a
    #   non-SELECT statement. See guard._query_tables().
    # - tenant_id: namespace for the agent, shown in audit records.
    #   It does not by itself change the sandbox; set sandbox_root
    #   per tenant (e.g. data/acme/) if you want tenant isolation.
    # - expires_at: epoch seconds, or None for a long-lived key.
    #   Guard blocks an expired key with key_expired.
    allowed_tables: set = field(default_factory=set)
    tenant_id: str = "default"
    expires_at: float | None = None

    def to_dict(self):
        """JSON form used by the management app and policies.json."""
        return {
            "agent_id": self.agent_id,
            "key": self.key,
            "allowed_tools": sorted(self.allowed_tools),
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "requires_approval_for_high_risk": self.requires_approval_for_high_risk,
            "allowed_hosts": sorted(self.allowed_hosts),
            "sandbox_root": self.sandbox_root,
            "allowed_tables": sorted(self.allowed_tables),
            "tenant_id": self.tenant_id,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, d: dict):
        if not isinstance(d, dict) or not d.get("key") or not d.get("agent_id"):
            raise ValueError("policy needs at least 'key' and 'agent_id'")
        # Pentest fix: the admin API used to accept anything here, so
        # an attacker with admin access (or a typo by a real admin)
        # could set sandbox_root="" (escape the sandbox), rate
        # 999999 (no rate limit), or an unknown tool. Validate now,
        # at the only place policies enter from JSON.
        allowed_tools = set(d.get("allowed_tools") or [])
        if not allowed_tools <= KNOWN_TOOLS:
            raise ValueError(f"unknown tool in allowed_tools: {sorted(allowed_tools - KNOWN_TOOLS)}")
        try:
            rate = int(d.get("rate_limit_per_minute", 30))
        except (TypeError, ValueError):
            raise ValueError("rate_limit_per_minute must be an integer")
        if not 1 <= rate <= 1000:
            raise ValueError("rate_limit_per_minute must be between 1 and 1000")
        sandbox_root = str(d.get("sandbox_root", "data/"))
        if not sandbox_root or sandbox_root.startswith("/") or ".." in sandbox_root.split("/"):
            raise ValueError("sandbox_root must be a relative path inside the project, no '..'")
        allowed_hosts = set(d.get("allowed_hosts") or [])
        for h in allowed_hosts:
            if not _HOST_RE.match(str(h)):
                raise ValueError(f"invalid allowed_host: {h!r}")
        allowed_tables = set(d.get("allowed_tables") or [])
        for t in allowed_tables:
            if not _TABLE_RE.match(str(t)):
                raise ValueError(f"invalid allowed_table: {t!r}")
        tenant_id = str(d.get("tenant_id", "default") or "default")
        if not _TENANT_RE.match(tenant_id):
            raise ValueError(f"invalid tenant_id: {tenant_id!r}")
        expires_at = d.get("expires_at")
        if d.get("expires_in_minutes") is not None:
            try:
                expires_at = time.time() + float(d["expires_in_minutes"]) * 60
            except (TypeError, ValueError):
                raise ValueError("expires_in_minutes must be a number")
        if expires_at is not None:
            try:
                expires_at = float(expires_at)
            except (TypeError, ValueError):
                raise ValueError("expires_at must be epoch seconds")
        return cls(
            agent_id=str(d["agent_id"]),
            key=str(d["key"]),
            allowed_tools=allowed_tools,
            rate_limit_per_minute=rate,
            requires_approval_for_high_risk=bool(d.get("requires_approval_for_high_risk", True)),
            allowed_hosts=allowed_hosts,
            sandbox_root=sandbox_root,
            allowed_tables=allowed_tables,
            tenant_id=tenant_id,
            expires_at=expires_at,
        )


# Demo keys only. A real deployment loads these from a secret store.
DEFAULT_POLICIES = {
    "key-research-123": Policy(
        agent_id="research-agent",
        key="key-research-123",
        allowed_tools={"read_file", "query_db", "call_api"},
        rate_limit_per_minute=30,
        allowed_hosts={"api.internal.example"},
        allowed_tables={"findings"},
    ),
    "key-ops-456": Policy(
        agent_id="ops-agent",
        key="key-ops-456",
        allowed_tools={"read_file", "query_db", "call_api", "run_command"},
        rate_limit_per_minute=10,
        allowed_hosts={"api.internal.example"},
        allowed_tables={"findings"},
    ),
}


def load_policies(path):
    """Load {key: Policy} from a JSON file. File format: a list of
    policy dicts (see Policy.to_dict), or {"policies": [...]}."""
    data = json.loads(Path(path).read_text())
    items = data.get("policies") if isinstance(data, dict) else data
    policies = {}
    for item in items or []:
        p = Policy.from_dict(item)
        policies[p.key] = p
    return policies


def save_policies(policies, path):
    """Save {key: Policy} to a JSON file the management app can reload."""
    data = {"policies": [p.to_dict() for p in policies.values()]}
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
