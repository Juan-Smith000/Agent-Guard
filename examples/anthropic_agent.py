"""Example: Anthropic (Claude) model + Agent Guard. Stdlib only.

How it fits together — the same guard step as the Ollama / OpenAI
examples, only the wire format changes:
    Claude (model, api.anthropic.com)
        -> returns a tool_use block instead of text
        -> THIS LOOP intercepts it, it does NOT go straight to a tool
        -> Agent Guard decides ALLOW / BLOCK / NEEDS_APPROVAL
        -> if ALLOW, Guard's output (already scanned/redacted) is sent
           back as a tool_result block with the matching tool_use_id
        -> if BLOCK, the tool_result is marked is_error=True and
           explains the block; if NEEDS_APPROVAL, it says the call
           was NOT executed and needs a human (approve it in /admin,
           then re-run — see the approval flow in the README)

Setup:
    export ANTHROPIC_API_KEY="sk-ant-..."  # never put a key in code,
                                          # never print it — this
                                          # script only sends it in
                                          # a header
    python3 examples/anthropic_agent.py --prompt "Read data/report.txt"

Notes / honest limits:
- Not tested against a live Anthropic account in this VM (no API
  key here). The request/response shapes are the standard Messages
  API shapes: tools with name/description/input_schema, content
  blocks of type "tool_use" (id, name, input), and follow-up
  user messages with type "tool_result" (tool_use_id, content,
  is_error).
- If ANTHROPIC_API_KEY is unset, this script exits with
  instructions instead of making an unauthenticated request.
- Guard runs in-process here, with mock tools by default. To use
  real tools, pass executor=real_execute (from agent_guard.real_tools)
  to Guard, or run the server with REAL_TOOLS=1 and POST to /tool.
  Do NOT execute a tool a second time after an ALLOW — Guard's
  output is already the tool's (scanned) output.
- The loop caps at MAX_TURNS so a stubborn model cannot loop
  forever on a blocked call.
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.guard import Guard

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
MAX_TURNS = 5

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file inside the data/ sandbox.",
        "input_schema": {"type": "object", "properties": {
            "path": {"type": "string"}}, "required": ["path"]},
    },
    {
        "name": "query_db",
        "description": "Run a read-only query. Destructive queries need approval.",
        "input_schema": {"type": "object", "properties": {
            "query": {"type": "string"}}, "required": ["query"]},
    },
]


def call_anthropic(api_key, model, messages):
    req = urllib.request.Request(
        ANTHROPIC_URL,
        data=json.dumps({"model": model, "max_tokens": 1024,
                         "messages": messages, "tools": TOOLS}).encode(),
        headers={"Content-Type": "application/json",
                 "x-api-key": api_key,
                 "anthropic-version": ANTHROPIC_VERSION},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"Anthropic request failed: HTTP {e.code} — {e.read().decode(errors='replace')[:500]}")
        raise SystemExit(1)
    except urllib.error.URLError as e:
        print(f"Anthropic not reachable: {e}")
        raise SystemExit(1)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="claude-sonnet-4-5")
    p.add_argument("--prompt", required=True)
    p.add_argument("--agent-key", default="key-research-123")
    args = p.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("ANTHROPIC_API_KEY is not set.")
        print("Set it, then re-run, e.g.:")
        print('  export ANTHROPIC_API_KEY="sk-ant-..."')
        print("  python3 examples/anthropic_agent.py --prompt \"Read data/report.txt\"")
        raise SystemExit(1)

    guard = Guard()
    messages = [{"role": "user", "content": args.prompt}]

    for _ in range(MAX_TURNS):
        data = call_anthropic(api_key, args.model, messages)
        content = data.get("content") or []
        messages.append({"role": "assistant", "content": content})
        tool_uses = [b for b in content if b.get("type") == "tool_use"]
        if not tool_uses:
            print("".join(b.get("text", "") for b in content if b.get("type") == "text"))
            return
        results = []
        for block in tool_uses:
            name, call_args = block["name"], block.get("input") or {}
            # ---- THE GUARD STEP ----
            decision = guard.handle(args.agent_key, name, call_args)
            print(f"[guard] {name} {call_args} -> {decision.decision} ({decision.reason})")
            if decision.decision == "ALLOW":
                results.append({"type": "tool_result", "tool_use_id": block["id"],
                                "content": decision.output})
            elif decision.decision == "NEEDS_APPROVAL":
                results.append({"type": "tool_result", "tool_use_id": block["id"],
                                "content": (f"Tool call {name} needs human approval "
                                            f"(approval {decision.approval_id}) and was NOT executed."),
                                "is_error": True})
            else:
                results.append({"type": "tool_result", "tool_use_id": block["id"],
                                "content": f"Tool call {name} was blocked: {decision.reason}.",
                                "is_error": True})
        messages.append({"role": "user", "content": results})
    print("(stopped after max turns)")


if __name__ == "__main__":
    main()
