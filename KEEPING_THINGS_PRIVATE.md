# Keeping things private in (or around) this repo

Short answer: **GitHub has no per-file privacy inside a public
repo.** If a file is committed to a public repo, it is public —
including its history, its branches, and any forks made from it.
There is no "private file" or "private branch" setting that
hides one file from everyone else while the rest of the repo
stays public.

So the question is not "how do I mark this file private in the
public repo?" — it is "where should this thing live instead?"
Here are the patterns, in the order to try them.

## 1. Don't commit it at all (the right answer for secrets)

This is already how Agent Guard is set up, and it is the only
pattern that works for keys and credentials:

- **`.gitignore` already covers:** `policies.json` (real agent
  keys), `audit.jsonl`, `audit.db`, `data/demo.db`, `__pycache__`.
  Check `git status` before every commit — if one of those
  shows up, something changed the ignore rules.
- **Use environment variables, not code, for secrets:**
  `ADMIN_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, real
  agent keys. The examples in this repo read keys from env
  vars for exactly this reason, and never print them.
- **Use a secret manager for real deployments** (1Password,
  Vault, AWS Secrets Manager, etc.) and load the secret at
  runtime. A secret in a manager is not in the repo at all,
  so there is nothing to leak from a clone.

What must stay out of this repo, specifically:

| Keep private | Why |
| --- | --- |
| `ADMIN_KEY`, real agent keys | Anyone with a key can use / administer the guard |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` | Billable, and usable by anyone who copies them |
| Real `policies.json` | Contains real keys, tenants, hosts, tables |
| Audit logs (`audit.jsonl`, `audit.db`) | Contain tool arguments, which may contain PII or internal data |
| Real database credentials / connection strings | Obvious, but worth saying once |

What is safe to keep public here: the code, the demo keys
(`key-research-123`, `key-ops-456` — labelled demo everywhere,
and useless because everyone knows them), mock data, and docs.

## 2. A separate private repo (the right answer for internal code/docs)

If you have internal extensions, real policies, internal docs,
or a deployment config you do not want public, put them in a
**second, private repo** — e.g. `agent-guard-internal` — and
keep the public repo to the core only.

- The private repo can depend on the public one (`pip install
  agent-guard`, or import the public package) — it does not
  need to fork it.
- A private submodule inside a public repo is a trap for most
  people: the submodule *pointer* is public, and anyone without
  access to the private repo just sees an empty directory.
  It works, but it confuses collaborators. A separate private
  repo with a plain dependency is clearer.
- Do not put the private repo's content in a branch of the
  public repo. Branches in a public repo are public.

## 3. GitHub "Internal" visibility (the middle ground, org only)

If you are in a GitHub organisation with Enterprise, there is
a third visibility between public and private: **Internal**.
An internal repo is visible to everyone in the organisation,
but not to the public. That is the right fit for "internally
on the repo" in a company sense — team-internal, not
world-public — but it is not available for a personal account,
and it still does not give per-file privacy.

| Visibility | Who can see it | Good for |
| --- | --- | --- |
| Public | Everyone, indexed by Google/GitHub | This repo's code, docs, examples |
| Internal (org only) | Everyone in your org, not the public | Team-internal tools, internal docs |
| Private | Only you / collaborators you invite | Real policies, secrets-adjacent config, internal extensions |

## 4. Encrypted files in the public repo (use sparingly)

Tools like `git-crypt`, `git-secret`, or `sops` (with `age`)
let you commit an *encrypted* file to a public repo and decrypt
it locally with a key that is never committed. The content is
not readable from a clone without the key, and GitHub search
will not index it.

Use this only for small, low-churn config, and know the
trade-offs: key distribution is now your problem, key rotation
means re-encrypting, and if the key ever leaks, the history
is decrypted too. For most Agent Guard uses, pattern 1 or 2
is simpler and safer than encryption in the public repo.

## 5. GitHub Secrets (for CI only, not for code)

Repo **Settings → Secrets and variables → Actions** stores
values GitHub Actions can use at CI time. They are not in any
file, and GitHub masks them in logs (do not echo them
deliberately — masking is not a guarantee against a clever
exfiltration). This is for CI/CD, not for "keep this file
private" — it does not hide code or docs.

## 6. If a secret was already committed — assume it leaked

Deleting the file in a later commit does **not** remove it:
it is still in git history, and in any fork or clone made
before the delete. If that happens:

1. **Rotate the secret immediately** — new `ADMIN_KEY`, new
   agent keys, new API keys. Rotation is the fix; history
   cleaning is cosmetic without it.
2. Purge history with `git filter-repo` (preferred) or BFG,
   then force-push. This rewrites history for everyone, so
   warn collaborators first.
3. Check forks / clones you do not control — you cannot
   purge those, which is why step 1 comes first.

## Recommended setup for Agent Guard

- **Public repo `agent-guard`:** code, docs, examples, demo
  keys only. This is the discoverable, resume-facing repo.
- **Local only (no repo):** real `policies.json`, audit logs,
  `ADMIN_KEY`, API keys — via env vars and `.gitignore`.
- **Private repo `agent-guard-internal` (only if you need it):**
  real deployment configs, internal extensions, internal docs.
  It imports the public package; it does not contain a copy
  of the public code.
