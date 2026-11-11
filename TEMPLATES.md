# Policy templates — basic configurations to choose from

Start from a template, then customise it. That is the intended
workflow, and it is deliberately the opposite of "pick a template
and never touch it again":

1. **Pick the closest template** — in the admin UI (Start from a
   template), with `manage.py add --template <id>`, with
   `POST /admin/templates/apply`, or with
   `policy_from_template(id, agent_id, key)` in code.
2. **Customise any field** — tools, rate, hosts, tables, sandbox,
   tenant, expiry — in the UI form, the CLI, or JSON, then save.
   The template does not lock you in.
3. **Do not move away from the protected rules** (below). Those
   are not template fields. If a template blocks something, or a
   protected rule blocks something, that is the control working.

## The templates

| Template | Risk | Tools | Rate | Approval | Best for |
| --- | --- | --- | --- | --- | --- |
| `lockdown` | Lowest | read_file | 10/min | Off (destructive = block) | Untrusted / public-facing agents, new agents on probation |
| `research-readonly` | Low | read_file, query_db, call_api | 30/min | On | Research, summarisation, RAG reading — safest default |
| `data-analyst` | Low | read_file, query_db | 60/min | On | Data / BI agents, reporting, many SELECTs, findings only |
| `support-api` | Low | read_file, call_api | 60/min | On | Support / helpdesk, internal API + docs, no DB, no commands |
| `ci-compliance` | Low | read_file, query_db | 20/min | Off (destructive = block) | CI, audit, scheduled unattended agents — no human watching |
| `ops-limited` | Medium | all four | 10/min | On | Ops / SRE, ls/echo only, destructive needs a human |
| `sandbox-developer` | High — local dev only | all four | 100/min | On | Local demos, trying a new loop on demo data only |

Full detail per template — description, recommended_for,
warnings, do_not_add, and use cases — is in
`agent_guard/templates.py` and in `GET /admin/templates`,
which the admin UI renders. The table above is the short
version; the code is the source of truth.

### How to use them

**In the UI:** open `/admin`, pick a template in "Start from a
template", click "Use this template in the form", edit anything
you want, then "Save policy". The form is pre-filled, not
submitted — you still choose before anything is created.

**From the CLI:**

```sh
python3 -m agent_guard.manage add --file policies.json \
  --template research-readonly --agent-id analyst --key key-analyst-789
# then customise, e.g. add a tool:
python3 -m agent_guard.manage allow --file policies.json \
  --key key-analyst-789 --tool call_api
```

**From the API:**

```sh
curl -X POST http://127.0.0.1:8080/admin/templates/apply \
  -H "X-Admin-Key: ..." -H "Content-Type: application/json" \
  -d '{"template": "support-api", "agent_id": "support-agent", "key": "key-support-1"}'
# then customise with POST /admin/policies as usual
```

**From code:**

```python
from agent_guard.templates import policy_from_template
from agent_guard.guard import Guard

policy = policy_from_template("research-readonly", "research-agent", "key-research-123")
# customise freely:
policy.rate_limit_per_minute = 50
guard = Guard(policies={policy.key: policy})
```

## Protected rules — strongly advised, and not configurable

**Customising a template cannot disable these.** They are
hard-coded in `guard.py` / `scanner.py` / `real_tools.py`, not
policy fields. To change one you would have to edit guard code
and re-run the tests — which is exactly the point: a config
change should never silently become a security change.

1. **Sandbox only.** A path resolving outside `sandbox_root`
   is BLOCKed, even if `read_file` is allowed. Classic `../`,
   encoded `%2e%2e`, NUL, and symlink escapes all count.
2. **No dangerous commands.** `rm`, `curl`, `wget`, shell
   chaining (`; && | \` $()`), `sudo` — BLOCKed even if
   `run_command` is ticked. The real executor only runs
   `ls`/`echo`, with no shell.
3. **No outside hosts.** `call_api` to a host not in
   `allowed_hosts` is BLOCKed, including suffix tricks like
   `api.internal.example.evil.example`.
4. **No auto-destructive actions.** Destructive SQL and
   actions are NEVER auto-executed. Approval on →
   NEEDS_APPROVAL, approval off → BLOCK. There is no
   "allow destructive" policy field.
5. **Unknown = block.** Unknown agent key or unknown tool is
   BLOCKed, fail closed. There is no default-allow.
6. **Output is scanned.** Tool output is scanned before the
   agent sees it. Injection → BLOCK. Secrets / PII →
   redacted, not leaked.
7. **Table allowlist.** If `allowed_tables` is set, a query
   touching any other table is BLOCKed, even if it is a
   read-only SELECT.
8. **Rate limits cannot be unlimited.** Policy validation
   rejects rates outside 1–1000/min. A looping agent is
   BLOCKed, not given a free run.
9. **Expired keys are blocked.** A key past `expires_at` is
   BLOCKed even if it is otherwise valid.

If you find yourself wanting to turn one of these off, stop
and ask what job actually needs it. In almost every case the
answer is a narrower template, a different tool, or a human
approval — not disabling the rule. If you do edit guard code
to change a rule, that is a fork of the security model, and
it should be reviewed, tested, and documented as one.

## Broadened use cases — who uses which template

Beyond the original research / data / ops / support cases in
`USE_CASES.md` and the README, templates make these cases
concrete, because each case now has a starting configuration
instead of just a description:

- **Classroom / workshop agent** → `lockdown` or
  `research-readonly`. Students can read, they cannot break
  anything, and the audit log is the teaching material.
- **Customer-facing demo agent** → `lockdown`. One tool,
  public docs only, low rate — a demo should not be able
  to become a data exfiltration demo.
- **Internal knowledge / RAG agent** → `research-readonly`.
  Reads docs and findings, calls the internal API, no writes.
- **Finance / reporting agent** → `data-analyst`. Many
  SELECTs, findings only, approval on for anything that
  looks destructive (which, for a reporting agent, should
  never happen — and the audit log proves it).
- **On-call / incident agent** → `ops-limited`. List files,
  check status, propose destructive actions for a human to
  approve in `/admin` — never auto-remediate by deleting.
- **Release / CI gate agent** → `ci-compliance`. Unattended,
  read-only, destructive = block. If CI needs to write,
  that write belongs to a human-approved pipeline step,
  not to an agent.
- **Multi-tenant SaaS agent** → one template per tenant,
  with `tenant_id` set and `sandbox_root` per tenant
  (e.g. `data/acme/`). Templates are per-agent, not
  per-deployment, so two tenants can have different
  templates on the same guard.
- **Hackathon / prototype agent** → `sandbox-developer`,
  local demo data only, then pick a stricter template
  before it leaves your laptop. The template name itself
  is the warning: if it is in production, it is wrong.
- **Compliance / audit agent** → `ci-compliance` +
  SQLite audit sink. The audit log is the evidence, and
  the template guarantees the agent itself could not
  have written to the data it audited.

## Customisation guide — what is safe to change, what is not

Safe to change (these are policy, not guard rules):

- Add or remove a tool, if the agent's job actually needs it
  — and remove it again when the job changes.
- Raise or lower the rate, within 1–1000/min, for the agent's
  real volume. A reporting agent at 60/min is normal; an
  ops agent at 10/min is deliberate.
- Add a host, if it is genuinely internal and you control it.
- Add a table, if the agent genuinely needs it — and only
  that table, not "all tables".
- Set a tenant, an expiry, a sandbox per tenant.

Not safe to change by configuration (and not possible by
configuration — see protected rules):

- Allowing paths outside the sandbox, dangerous commands,
  outside hosts, auto-destructive actions, unknown tools,
  unscanned output, or unlimited rates.
- Removing approval from a template that has it, for an
  agent that can request destructive actions, without
  replacing it with BLOCK (as `ci-compliance` does for
  unattended agents).
- Copying `sandbox-developer` to production, or pointing
  any template at a real database / real shell without a
  real sandbox in front of it.

When in doubt, start stricter (`lockdown` or
`research-readonly`), run the agent, read the audit log,
and loosen one field at a time with a reason. That audit
log is the evidence for why the policy is what it is.
