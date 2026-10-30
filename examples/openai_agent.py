"""Example: OpenAI model + Agent Guard. Stdlib only, no openai package.

How it fits together — the same guard step as the Ollama example,
only the wire format changes:
    OpenAI (model, api.openai.com)
        -> decides it wants a tool call (message.tool_calls)
        -> THIS LOOP intercepts it, it does NOT go straight to a tool
        -> Agent Guard decides ALLOW / BLOCK / NEEDS_APPROVAL
        -> if ALLOW, Guard's output (already scanned/redacted) is sent
           back as a "tool" message with the matching tool_call_id
        -> if BLOCK / NEEDS_APPROVAL, the model is told why, and the
           tool was NOT run (NEEDS_APPROVAL can be approved in /admin,
           then re-run — see the approval flow in the README)

Setup:
    export OPENAI_API_KEY="sk-..."   # never put a key in code, and
                                     # never print it — this script
                                     # only sends it in a header
    python3 examples/openai_agent.py --prompt "Read data/report.txt"

Notes / honest limits:
- Not tested against a live OpenAI account in this VM (no API key
  here). The request/response shapes are the standard Chat
  Completions tool-calling shapes: message.tool_calls with
  function.name / function.arguments (a JSON string), and a
  follow-up message with role "tool" and tool_call_id.
- If OPENAI_API_KEY is unset, this script exits with instructions
  instead of making an unauthenticated request.
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

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
MAX_TURNS = 5

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file inside the data/ sandbox.",
            "parameters": {"type": "object", "properties": {
                "path": {"type": "string"}}, "required": ["path"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_db",
            "description": "Run a read-only query. Destructive queries need approval.",
            "parameters": {"type": "object", "properties": {
                "query": {"type": "string"}}, "required": ["query"]},
        },
    },
]


def call_openai(api_key, model, messages):
    req = urllib.request.Request(
        OPENAI_URL,
        data=json.dumps({"model": model, "messages": messages,
                         "tools": TOOLS}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"OpenAI request failed: HTTP {e.code} — {e.read().decode(errors='replace')[:500]}")
        raise SystemExit(1)
    except urllib.error.URLError as e:
        print(f"OpenAI not reachable: {e}")
        raise SystemExit(1)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="gpt-4o-mini")
    p.add_argument("--prompt", required=True)
    p.add_argument("--agent-key", default="key-research-123")
    args = p.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        print("OPENAI_API_KEY is not set.")
        print("Set it, then re-run, e.g.:")
        print('  export OPENAI_API_KEY="sk-..."')
        print("  python3 examples/openai_agent.py --prompt \"Read data/report.txt\"")
        raise SystemExit(1)

    guard = Guard()
    messages = [{"role": "user", "content": args.prompt}]

    for _ in range(MAX_TURNS):
        data = call_openai(api_key, args.model, messages)
        msg = data["choices"][0]["message"]
        messages.append(msg)
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            print(msg.get("content", ""))
            return
        for call in tool_calls:
            fn = call["function"]
            name = fn["name"]
            try:
                call_args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                call_args = {}
            # ---- THE GUARD STEP ----
            decision = guard.handle(args.agent_key, name, call_args)
            print(f"[guard] {name} {call_args} -> {decision.decision} ({decision.reason})")
            if decision.decision == "ALLOW":
                content = decision.output
            elif decision.decision == "NEEDS_APPROVAL":
                content = (f"Tool call {name} needs human approval "
                           f"(approval {decision.approval_id}) and was NOT executed.")
            else:
                content = f"Tool call {name} was blocked: {decision.reason}."
            messages.append({"role": "tool", "tool_call_id": call["id"],
                             "content": content})
    print("(stopped after max turns)")


if __name__ == "__main__":
    main()
