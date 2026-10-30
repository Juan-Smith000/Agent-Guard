"""Example: a generic, framework-agnostic adapter. No model, no API key.

This is the example to copy when your agent framework is NOT
Ollama / OpenAI / Anthropic — LangChain, LlamaIndex, the OpenAI
Agents SDK, a home-grown loop, anything that calls tools as
functions. The pattern is the same in every framework, and it is
only one step:

    framework decides on a tool call
        -> call guard_tool_call() instead of calling the tool directly
        -> ALLOW: use the returned output (already scanned/redacted)
        -> BLOCK: do not run the tool, tell the framework/model why
        -> NEEDS_APPROVAL: do not run the tool, ask a human, and
           (in V2) approve it in /admin or via guard.approve() to run it

No LangChain / LlamaIndex package is required to run this file —
it deliberately has no framework dependency, so you can run it
offline right now. The docstring at the bottom shows, in
pseudocode, how the same GuardedTool plugs into LangChain-style
tools, because that is the question people ask most.

Run (no API key, no server, no model needed):
    python3 examples/framework_adapter.py

What it demonstrates, in order:
    1. A benign read -> ALLOW, scanned output returned.
    2. A path traversal -> BLOCK, tool never runs.
    3. A destructive query -> NEEDS_APPROVAL, tool never runs yet.
    4. Approving that approval -> ALLOW (approval_granted), output returned.
    5. A tool the agent is not allowed -> BLOCK (tool_not_allowed).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.guard import Guard


class GuardedTool:
    """One tool, guarded. Wrap every tool an agent may call in this.

    Usage:
        guarded_read = GuardedTool(guard, agent_key="key-research-123")
        decision, output = guarded_read("read_file", {"path": "data/report.txt"})
        if decision == "ALLOW":
            use(output)
        # else: output is the block / approval explanation, NOT tool output
    """

    def __init__(self, guard, agent_key):
        self.guard = guard
        self.agent_key = agent_key

    def __call__(self, tool_name, args):
        """Return (decision, output_or_message). Never raises on a guard decision."""
        decision = self.guard.handle(self.agent_key, tool_name, args)
        if decision.decision == "ALLOW":
            return "ALLOW", decision.output
        if decision.decision == "NEEDS_APPROVAL":
            return "NEEDS_APPROVAL", (
                f"Tool call {tool_name} needs human approval "
                f"(approval {decision.approval_id}) and was NOT executed."
            )
        return "BLOCK", f"Tool call {tool_name} was blocked: {decision.reason}."


def main():
    guard = Guard()  # mock tools by default; swap in real_execute for real tools
    tool = GuardedTool(guard, agent_key="key-research-123")

    print("1. Benign read:")
    print("  ", tool("read_file", {"path": "data/report.txt"}))
    print()
    print("2. Path traversal (must NOT run):")
    print("  ", tool("read_file", {"path": "../secret.txt"}))
    print()
    print("3. Destructive query (must NOT auto-run):")
    decision, message = tool("query_db", {"query": "DROP TABLE findings"})
    print("  ", decision, message)
    print()
    if decision == "NEEDS_APPROVAL":
        # In a real app a human approves in /admin. Here, approve it
        # directly to show the V2 flow end to end:
        pending = guard.list_approvals()
        approval_id = pending[0]["approval_id"] if pending else None
        print("4. Human approves it:")
        print("  ", guard.approve(approval_id) if approval_id else "no pending approval")
        print()
    print("5. Tool the agent is not allowed:")
    print("  ", tool("run_command", {"command": "ls"}))
    print()
    print("Rule to copy into your framework: never call the raw tool.")
    print("Always call it through GuardedTool, and only use the output on ALLOW.")


# ---------------------------------------------------------------------------
# Pseudocode: the same adapter in LangChain-style code (not executed here,
# because LangChain is not a dependency of this project — copy the shape,
# not the imports, into your own codebase):
#
#   from langchain_core.tools import tool
#
#   guard = Guard()
#   guarded = GuardedTool(guard, agent_key="key-research-123")
#
#   @tool
#   def read_file(path: str) -> str:
#       decision, output = guarded("read_file", {"path": path})
#       return output  # on BLOCK this is the block explanation, not file data
#
#   # Then give the agent [read_file] as usual. The agent never sees
#   # a raw, unguarded read — every call goes through Guard first.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
