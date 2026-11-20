# Keeping things private

A public repo has no per-file privacy. A committed file is public — its
history, its branches, every fork made from it. No setting hides one file
while the rest stays public. Anything that must stay private lives
somewhere else. The patterns below are in the order to try them.

## 1. Don't commit it

The only pattern that works for keys and credentials. CallScreen is
already set up this way.

- `.gitignore` covers `policies.json`, `audit.jsonl`, `audit.db`,
  `data/demo.db`, and `__pycache__`. Check `git status` before every
  commit. If one of those files shows up, the ignore rules changed —
  fix that before committing.
- Secrets come from environment variables, never from code: `ADMIN_KEY`,
  `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, real agent keys. The examples
  read keys from env vars and never print them.
- Real deployments load secrets from a secret manager (1Password, Vault,
  AWS Secrets Manager) at runtime. A secret in a manager is not in the
  repo, so a clone cannot leak it.

Keep out of this repo:

| Keep private | Why |
| --- | --- |
| `ADMIN_KEY`, real agent keys | Anyone holding one can use or administer the guard |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` | Billable, and usable by anyone who copies them |
| Real `policies.json` | Holds real keys, tenants, hosts, tables |
| Audit logs (`audit.jsonl`, `audit.db`) | Hold tool arguments, which may contain PII or internal data |
| Real database credentials / connection strings | Direct access to production data |

Safe to keep public: the code, the demo keys (`key-research-123`,
`key-ops-456` — labelled demo everywhere, and useless because everyone
knows them), mock data, docs.

## 2. A separate private repo

For internal extensions, real policies, internal docs, or deployment
config: put them in a second, private repo — e.g. `callscreen-internal` —
and keep the public repo to the core only.

- The private repo depends on the public one (`pip install callscreen`,
  or import the public package). It does not fork it.
- A private submodule inside a public repo is a trap: the submodule
  pointer is public, and anyone without access to the private repo sees
  an empty directory. A separate private repo with a plain dependency
  is clearer.
- Never put private content in a branch of the public repo. Branches in
  a public repo are public.

## 3. GitHub "Internal" visibility

For organisations with Enterprise, a third visibility exists between
public and private: Internal. An Internal repo is visible to everyone
in the organisation, not to the public. It fits team-internal tools and
docs. It is not available for a personal account, and it still does not
give per-file privacy.

| Visibility | Who can see it | Good for |
| --- | --- | --- |
| Public | Everyone, indexed by Google/GitHub | This repo's code, docs, examples |
| Internal (org only) | Everyone in your org, not the public | Team-internal tools, internal docs |
| Private | Only you and collaborators you invite | Real policies, secrets-adjacent config, internal extensions |

## 4. Encrypted files in the public repo

`git-crypt`, `git-secret`, or `sops` (with `age`) let you commit an
encrypted file to a public repo and decrypt it locally with a key that
is never committed. A clone cannot read the content without the key,
and GitHub search will not index it.

Use this only for small, low-churn config. Key distribution becomes
your problem, key rotation means re-encrypting, and a leaked key
decrypts the history too. For most CallScreen uses, pattern 1 or 2 is
simpler and safer.

## 5. GitHub Secrets

Repo Settings → Secrets and variables → Actions stores values GitHub
Actions can use at CI time. They live in no file, and GitHub masks them
in logs — do not echo them deliberately; masking is not a guarantee
against a clever exfiltration. This is for CI/CD. It does not hide code
or docs.

## 6. If a secret was already committed — assume it leaked

Deleting the file in a later commit does not remove it. It stays in git
history, and in any fork or clone made before the delete.

1. Rotate the secret immediately — new `ADMIN_KEY`, new agent keys, new
   API keys. Rotation is the fix. History cleaning without it is
   cosmetic.
2. Purge history with `git filter-repo` (preferred) or BFG, then
   force-push. This rewrites history for everyone, so warn collaborators
   first.
3. Check forks and clones you do not control. You cannot purge those,
   which is why rotation comes first.

## Recommended setup for CallScreen

- Public repo `callscreen`: code, docs, examples, demo keys only. The
  discoverable, resume-facing repo.
- Local only, no repo: real `policies.json`, audit logs, `ADMIN_KEY`,
  API keys — via env vars and `.gitignore`.
- Private repo `callscreen-internal`, only if needed: real deployment
  configs, internal extensions, internal docs. It imports the public
  package; it does not copy the public code.
