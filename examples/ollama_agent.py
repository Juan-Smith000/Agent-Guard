"""Example: Ollama model + Agent Guard, all local. Stdlib only.

How it fits together:
    Ollama (model, localhost:11434)
        -> decides it wants a tool call (tool_calls)
        -> THIS LOOP intercepts it, it does NOT go straight to a tool
        -> Agent Guard decides ALLOW / BLOCK / NEEDS_APPROVAL
        -> if ALLOW, Guard's output (already scanned/redacted) is sent
           back to Ollama as a "tool" message
        -> if BLOCK / NEEDS_APPROVAL, the model is told why, and the
           tool was NOT run

That is the whole integration point. Ollama has no built-in guard
plugin, so the agent loop is where the guard lives — exactly the same
pattern as the weather example in Ollama's tool-calling docs, with
one extra step in the middle.

Setup:
    ollama serve
    ollama pull llama3.1        # or any model with tool support
    # Agent Guard needs no server here: this example uses Guard
    # in-process. Or run ./run.sh and POST to /tool instead — same
    # decisions, same audit log, just over HTTP.

Run:
    python3 examples/ollama_agent.py --prompt "Read data/report.txt"
    python3 examples/ollama_agent.py --model qwen2.5:7b --prompt "Read data/notes.txt"

Notes / honest limits:
- Tool support depends on the model. Small models hallucinate tool
  names/args more often — Guard will BLOCK those, and the loop caps
  at MAX_TURNS so a stubborn model cannot loop forever.
- Guard.handle() already runs the tool (mock by default, see
  agent_guard/tools.py) and returns its scanned output, so this
  example does NOT execute a tool a second time. To use real tools,
  pass executor=real_execute (from agent_guard.real_tools) to Guard,
  or run the server with REAL_TOOLS=1 — do not bypass the guard.
- NEEDS_APPROVAL means "not executed, ask a human". This example
  reports that to the model and stops that tool call. In V2 you can
  approve it in /admin (or via guard.approve()) and it will run,
  after re-validating policy — see the approval flow in the README.
"""
import argparse
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.guard import Guard

OLLAMA_URL = "http://localhost:11434/api/chat"
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


def call_ollama(model, messages):
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps({"model": model, "messages": messages,
                         "tools": TOOLS, "stream": False}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"Ollama not reachable at {OLLAMA_URL}: {e}")
        print("Start it with: ollama serve   (and pull a tool-capable model first)")
        raise SystemExit(1)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="llama3.1")
    p.add_argument("--prompt", required=True)
    p.add_argument("--agent-key", default="key-research-123")
    args = p.parse_args()

    guard = Guard()  # in-process; audit goes to audit.jsonl by default
    messages = [{"role": "user", "content": args.prompt}]

    for _ in range(MAX_TURNS):
        data = call_ollama(args.model, messages)
        msg = data["message"]
        messages.append(msg)
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            print(msg.get("content", ""))
            return
        for call in tool_calls:
            fn = call["function"]
            name, call_args = fn["name"], fn.get("arguments") or {}
            if isinstance(call_args, str):
                try:
                    call_args = json.loads(call_args)
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
            messages.append({"role": "tool", "content": content})
    print("(stopped after max turns)")


if __name__ == "__main__":
    main()
