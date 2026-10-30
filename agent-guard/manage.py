"""Command-line management tool for policies.

Works on a policies.json file. If the server was started with
POLICIES_PATH pointing at that file, restart the server or
POST /admin/reload to pick up CLI changes; the web admin UI
(/admin) applies changes immediately without a restart.

Usage:
    python3 -m agent_guard.manage list --file policies.json
    python3 -m agent_guard.manage add --file policies.json \
        --agent-id analyst --key key-analyst-789 \
        --tools read_file query_db --rate 20 --approval
    python3 -m agent_guard.manage allow --file policies.json \
        --key key-analyst-789 --tool run_command
    python3 -m agent_guard.manage block --file policies.json \
        --key key-analyst-789 --tool run_command
    python3 -m agent_guard.manage approval --file policies.json \
        --key key-analyst-789 --off
    python3 -m agent_guard.manage remove --file policies.json \
        --key key-analyst-789
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.policy import Policy, load_policies, save_policies


def _load(path):
    return load_policies(path) if Path(path).exists() else {}


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["list", "add", "allow", "block", "approval", "remove"])
    p.add_argument("--file", default="policies.json")
    p.add_argument("--agent-id")
    p.add_argument("--key")
    p.add_argument("--tools", nargs="*")
    p.add_argument("--rate", type=int, default=30)
    p.add_argument("--approval", action="store_true")
    p.add_argument("--off", action="store_true")
    p.add_argument("--tool")
    p.add_argument("--hosts", nargs="*")
    p.add_argument("--tables", nargs="*")
    p.add_argument("--tenant")
    p.add_argument("--expires-in-minutes", type=float)
    args = p.parse_args(argv)

    policies = _load(args.file)
    if args.command == "list":
        for pol in policies.values():
            print(pol.to_dict())
        return 0
    if args.command == "add":
        if not args.agent_id or not args.key:
            p.error("add needs --agent-id and --key")
        import time as _time
        expires_at = None
        if args.expires_in_minutes is not None:
            expires_at = _time.time() + args.expires_in_minutes * 60
        policies[args.key] = Policy(
            agent_id=args.agent_id, key=args.key,
            allowed_tools=set(args.tools or []),
            rate_limit_per_minute=args.rate,
            requires_approval_for_high_risk=args.approval,
            allowed_hosts=set(args.hosts or []),
            allowed_tables=set(args.tables or []),
            tenant_id=args.tenant or "default",
            expires_at=expires_at,
        )
    elif args.command in ("allow", "block"):
        pol = policies.get(args.key or "")
        if pol is None:
            print(f"no policy for key {args.key!r}")
            return 1
        if args.command == "allow":
            pol.allowed_tools.add(args.tool)
        else:
            pol.allowed_tools.discard(args.tool)
    elif args.command == "approval":
        pol = policies.get(args.key or "")
        if pol is None:
            print(f"no policy for key {args.key!r}")
            return 1
        pol.requires_approval_for_high_risk = not args.off
    elif args.command == "remove":
        policies.pop(args.key or "", None)
    save_policies(policies, args.file)
    print(f"saved {len(policies)} policies to {args.file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
