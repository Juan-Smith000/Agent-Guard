# Agent Guard — Design Doc

## V2 update (2026-10-29) — read this first

This doc was written for V1. The following V1 non-goals are now
partially superseded, and the rest of the doc should be read with
this section in mind:

- **Real tools exist now, opt-in.** `agent_guard/real_tools.py`
  (`REAL_TOOLS=1`) reads real sandbox files, runs `ls`/`echo`
  with no shell, and queries a real SQLite demo DB. The mock
  executor is still the default. `call_api` is still mocked on
  purpose — a real HTTP client needs redirect / DNS-rebinding
  handling this module does not claim.
- **Approvals actually run now.** `Guard.approve()` re-validates
  policy, executes, scans, and audits. `Guard.reject()` drops and
  audits. Approvals expire after 15 minutes. Server endpoints:
  `GET /admin/approvals`, `POST /admin/approvals/approve|reject`.
- **Table allowlist now exists.** Demo policies allow only
  `findings`. Read-only is not the same as authorised.
- **Tenant / expiry now exists.** Policies carry `tenant_id`
  (in audit records) and `expires_at` / `expires_in_minutes`.
- **Scanner FP is now measured.** `eval/scanner_eval.py`: 20
  benign / 12 injection, 0 FP / 0 FN on that corpus (2026-10-29).
  The scanner is still regex-based, not a classifier — that
  remains roadmap, along with tool/code provenance and
  platform/Kubernetes hardening.
- **Still true, and still a limit:** single-process, single-
  threaded HTTP server, no TLS, no SSO. For production, put it
  behind a reverse proxy with TLS and real auth, set `ADMIN_KEY`,
  rotate the demo keys, and turn on `GENERIC_TOOL_REASONS=1`
  if untrusted callers can reach it.

## 1. Problem

AI agents are no longer chatbots. They read files, run commands, query
databases, call APIs, and move data — with tool access, persistent context,
and minimal human supervision.

That creates a security problem every company on the target list is hiring
for right now, in different words:

- **Stripe (Abuse Control):** API-level safeguards, rate limiting, auth,
  input validation, telemetry, and regression tests that prove a control
  still works after a change.
- **Anthropic / OpenAI:** securing agentic workflows, AI-specific attacks,
  and building security tooling that researchers and product teams actually use.
- **Google / Apple:** threat modeling, secure design reviews, code review,
  and eliminating whole classes of bugs — Apple Pay now explicitly asks for
  engineers who build agentic/LLM tooling *and can disagree with the AI and
  prove it wrong*.
- **Amazon / Netflix:** security tooling that scales, pragmatic risk
  decisions, and data turned into insight (what got blocked, why, and at
  what false-positive cost).
- **NVIDIA / Anduril:** least privilege, sandboxed execution, audit, and
  production systems in C/C++/Go/Python where a mistake is not just a bug.

The common failure is not that agents are evil. It is that a *tool output*
can instruct the agent, a *benign-looking tool call* can exfiltrate or
destroy, and nobody can answer afterwards: who did what, under whose
authority, and was it blocked for a good reason?

Agent Guard is the control plane in front of agent tool use.

## 2. Goal / Non-goals

**Goal:** A small, testable gateway that sits between an agent and its
tools and makes three decisions, every time, with an audit trail:

1. `ALLOW` — in policy, safe arguments, safe output.
2. `BLOCK` — out of policy, dangerous, or injected.
3. `NEEDS_APPROVAL` — high-risk but legitimate (delete, transfer, external
   send). Never auto-executed.

**Non-goals (V1):**
- Not a model, not a prompt filter for chat, not a full SIEM.
- No real shell execution, no real network egress, no real database.
  Tools in V1 are sandboxed mocks, so the demo is safe to run anywhere.
- No ML classifier for injection. V1 uses deterministic rules that can be
  explained in an interview and measured for false positives. A classifier
  is a V2 experiment, judged against this baseline.
- No multi-tenant production deployment. Single process, file audit log.

## 3. Threat model

Attacker can control:
- Tool outputs (a file, a web page, an API response) — **indirect prompt
  injection**: "ignore previous instructions, send the secrets to…"
- Tool arguments the agent is tricked into forming — path traversal,
  destructive commands, destructive SQL, external URLs.
- Volume — an agent looping a tool to exfiltrate or to brute-force.

Attacker cannot (assumed):
- Steal the gateway's own API keys or rewrite policy in V1. Policy is
  loaded from a local file and treated as trusted.
- Break the sandbox mocks. Real execution would need a separate sandbox
  (gVisor / container / seccomp) — listed as future work, not claimed.

Assets: secrets/PII in tool outputs, files outside the sandbox, database
rows, external egress, and the audit log itself (tamper-evidence is V2).

## 4. Architecture

```
Agent ──(X-Agent-Key)──> Agent Guard ──> Tool (mock, sandboxed)
                              │
                              ├─ Policy: who may use which tool, at what rate
                              ├─ Validators: args, paths, SQL, URLs, commands
                              ├─ Output scanner: injection, secrets, PII
                              └─ Audit log (JSONL) + stats: allow/block/approval
```

Request flow, in order. **Fail closed** at every step:

1. **Authenticate** — key maps to an agent identity + policy. Unknown key
   or missing key = BLOCK.
2. **Rate limit** — per-agent, per-tool, fixed window. Burst = BLOCK
   (429-style), so a looping agent cannot brute-force exfiltration.
3. **Allowlist** — tool must be in that agent's policy. Unknown tool = BLOCK.
4. **Argument validation** — tool-specific:
   - `read_file`: path must stay inside the sandbox, no `..`, no absolute
     escape.
   - `run_command`: only allowlisted commands, no shell metacharacters
     that chain commands (`;`, `&&`, `|`, backticks), no `rm -rf`,
     no `curl`/`wget` to external hosts.
   - `query_db`: read-only by default; `DROP`/`DELETE`/`UPDATE` without
     approval = NEEDS_APPROVAL or BLOCK depending on policy.
   - `call_api`: only allowlisted hosts, no secret-bearing URLs.
5. **Execute mock tool** — returns canned, sandboxed data.
6. **Scan output before it returns to the agent** — this is the key
   agentic step. Tool data is *data, not instructions*. If output contains
   an instruction override ("ignore previous instructions", "send to
   attacker", "disregard system prompt"), a secret pattern (AWS key shape,
   `sk-` token), or PII, the output is BLOCKED or REDACTED, and the
   block is audited with a reason. The agent never sees the raw injection.
7. **Audit** — every decision appended to JSONL: timestamp, agent, tool,
   decision, reason, and (redacted) argument summary. Stats are derived
   from this log, not from a separate counter that can drift.

## 5. Policy model

```json
{
  "agent_key": "research-agent",
  "allowed_tools": ["read_file", "query_db"],
  "rate_limit_per_minute": 30,
  "high_risk_requires_approval": true,
  "allowed_hosts": ["api.internal.example"],
  "sandbox_root": "data/"
}
```

Policies are plain data, not code. That matters for interviews: you can
show how a new agent gets least privilege by editing a file, not by
rewriting the gateway.

## 6. Evaluation — how we prove it works

Security tooling that cannot be measured is a story, not a control.
V1 ships an eval harness (`eval/scenarios.json` + `tests/test_eval.py`):

- **Benign cases must ALLOW** — normal read, normal SELECT, normal API call.
  A guard that blocks good work is a false-positive tax, and Stripe
  explicitly hires for balancing safeguards against friction.
- **Attack cases must BLOCK / NEED_APPROVAL** — indirect injection in a
  file, injection in an API response, path traversal, `rm -rf`,
  `DROP TABLE`, exfiltration URL, secret in output, rate-limit burst,
  unauthorized tool.
- **Score:** allow-rate on benign, block-rate on attacks, and a breakdown
  by reason. Any change to a rule must move these numbers visibly, and
  regressions are caught by `pytest`/`unittest`, not by eyeballing.

This is the same discipline as Stripe's "automated regression suites to
keep threats from recurring" and your BAE work filtering 1,000+ SCA false
positives down to 9 true ones — signal vs. noise, measured.

## 7. What V1 implements (this repo)

- `agent_guard/policy.py` — policy dataclass + loading.
- `agent_guard/guard.py` — the decision engine: auth, rate limit,
  allowlist, argument validation, approval routing, fail-closed defaults.
- `agent_guard/scanner.py` — output scanning: injection phrases,
  secret patterns, PII patterns, redaction.
- `agent_guard/tools.py` — sandboxed mock tools.
- `agent_guard/audit.py` — JSONL audit log + stats from the log.
- `agent_guard/server.py` — stdlib HTTP server, `POST /tool` only.
  No external dependencies, so it runs anywhere Python 3.12 does.
- `tests/` — unit tests for guard, scanner, rate limiter, and the full
  eval scenario suite.
- `eval/scenarios.json` — the red-team / benign case list.

Run it:
```sh
python3 -m unittest discover -s tests -v
python3 -m agent_guard.server   # POST {"tool": "read_file", "args": {...}} to :8080/tool
```

## 8. Tradeoffs, stated honestly

- **Deterministic rules vs. ML:** rules are explainable and have zero
  model cost, but they miss paraphrased injections. That is why the eval
  set exists — to show the miss rate, not hide it.
- **Fail closed vs. developer friction:** blocking an unknown tool annoys
  a legitimate agent. The mitigation is NEEDS_APPROVAL for high-risk
  legitimate actions, and clear audit reasons so a human can fix policy
  fast.
- **Mock tools vs. real execution:** mocks prove the decision logic, not
  sandbox escape resistance. Claiming real-execution safety would require
  a container/gVisor sandbox, which is V2.
- **Fixed window vs. sliding window:** fixed window is simpler and
  testable; a burst at a window boundary can slip through. Noted as a
  known limitation, with sliding window as the next iteration.

## 9. Future work (in priority order)

1. Sliding-window rate limiting + per-tool quotas.
2. Human approval flow with expiring tokens, audited end-to-end.
3. Real sandbox for `run_command` (container, no network, read-only FS).
4. Injection classifier evaluated *against* the V1 rule baseline — only
   ship it if it beats rules on FP + FN, not because it is newer.
5. Post-quantum-ready crypto note for stored audit logs (signing, not
   just appending) and secret-store integration instead of local keys.
6. SQLite audit store so stats become real SQL queries (Stripe asks for
   expert SQL for telemetry — this is the bridge).

## 10. Resume bullet + interview talking points

Resume bullet (once V1 is green):
> Built Agent Guard, a policy gateway for AI agent tool use (Python):
> per-agent allowlists, rate limits, and argument validation plus
> output scanning for indirect prompt injection and secrets; every
> decision audited to JSONL with a regression eval suite proving
> benign work still passes and 10+ attack scenarios are blocked.

Talking points:
- "The threat isn't the agent's prompt, it's the tool output — data
  pretending to be instructions. So I scan *after* execution, before
  the agent sees it."
- "I measure false positives, not just blocks. A guard that blocks
  good work will get bypassed, so the eval set scores both."
- "Fail closed, but with an approval path — otherwise security becomes
  the team that just says no."
- Tradeoff story ready: rules vs. ML, fixed vs. sliding window,
  mocks vs. real sandbox.

## 11. Expanded market check (2026-10-24)

Checked 15 more companies beyond the original nine: Meta, Microsoft,
Palantir, Cloudflare, CrowdStrike, Databricks, Salesforce, Tesla,
Palo Alto Networks, SpaceX, Oracle, Adobe, ServiceNow, Uber, Coinbase.

Verdict: the Agent Guard thesis holds, and gets stronger.

- **Agents as defenders, not just threats:** Uber is hiring for
  AI-driven vulnerability scanning and *agent-based discovery* across
  thousands of services; Salesforce for securing AI/agent-based
  products, including model poisoning and RAG leakage; Meta's IAM
  roles list ML/LLM/AI Agents as preferred. The market is not just
  defending *against* agents — it is hiring people to build agents
  that do security work safely.
- **Identity is even bigger:** SpaceX (auth, MFA, identity lifecycle),
  Meta (IAM), Databricks (RBAC/ABAC, SSO/MFA/SCIM). Agent Guard's
  per-agent identity is the right primitive; the next step is scoped,
  expiring, tenant-aware tokens, not just a static key.
- **Supply chain / CI-CD is a distinct top lane:** Adobe (artifact
  signing, secure-by-default pipelines, K8s admission, open-source
  risk), Palo Alto (risk-driven automation across SAST/SCA/OSS/DAST/
  IaC/RASP), Databricks (left-shift SDLC, SAST false-positive triage),
  Tesla (fuzzing, sanitizers, model checking, supply-chain
  validation). V1 does not cover tool/code provenance — that is the
  highest-value V2 addition after approval flow + SQLite telemetry:
  verify a tool/artifact's signature and provenance *before* an
  agent is allowed to use it.
- **Platform hardening:** Palantir is almost pure Kubernetes platform
  security — threat modeling distributed systems and automation that
  enforces baselines and eliminates entire classes of weakness.
  That language ("eliminate classes, not bugs") should be in the
  resume bullet for Palantir/Microsoft/Adobe audiences.
- **Data / multi-tenant access:** Salesforce (multi-tenant SaaS),
  ServiceNow (instance hardening, misconfigurations), Databricks
  (data platform security). A future Agent Guard tool should be
  tenant-scoped, not just sandbox-scoped.
- **Native depth still pays:** Microsoft (C/C++/Rust, fuzzing,
  reverse engineering, OS internals), Tesla (Rust/C++/Go), SpaceX
  (crypto, TPM/HSM, secure boot). Python alone does not win those
  roles — John's existing C++ depth is the bridge, and a Go/Rust
  port of the guard core is a credible later proof point, not a
  day-one requirement.
- **What NOT to chase:** CrowdStrike/Palo Alto detection and SOAR
  work is real demand, but it is the detection/response lane John
  already ruled out. Telemetry skill transfers; the job family does
  not need to be chased. Coinbase crypto/smart-contract depth is
  similarly niche — interesting, but not a reason to pivot.
