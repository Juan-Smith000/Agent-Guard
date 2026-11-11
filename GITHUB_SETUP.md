# Making Agent Guard findable on GitHub and Google

This file is not code — it is the copy-paste checklist for the
moment you create the public repo. GitHub topics, the repo
description, and public/private are set in GitHub's UI, not in
any file in this repo, so no file here can set them for you.
Do these steps once, in order, and the project becomes
searchable.

## 1. Create a PUBLIC repo (this is the step that matters most)

- Name: `Agent-Guard` (exact casing as you created it — GitHub preserves
  this in URLs; the local folder and PyPI package stay lowercase `agent-guard`)
- Visibility: **Public**. A private repo is invisible to Google
  and to GitHub search, no matter how good the README is.
- Do **not** check "Add a README" in GitHub's creator — this
  repo already has one, and a second README will conflict.
- Push from your machine:

```sh
git init
git add .
git status   # check: no audit.jsonl, audit.db, data/demo.db, policies.json
git commit -m "Agent Guard 0.2.0: real tools, approvals, table allowlist"
git branch -M main
git remote add origin https://github.com/Juan-Smith000/Agent-Guard.git
git push -u origin main
```

URLs in this file and in `pyproject.toml` now use your real repo: Juan-Smith000/Agent-Guard.

## 2. Paste this description (repo page → About → gear icon)

GitHub search and Google both use this text, and it is what
people see under the repo name. Keep it under ~350 characters:

> AI agent security gateway for LLM tool use — per-agent allowlists, rate limits, argument validation, indirect prompt injection scanning, secret redaction, and audited approvals. Python stdlib only, local-first, works with Ollama.

## 3. Add these topics (same About → gear icon, max 20)

GitHub search lets people filter by topic, and topics are how
browsing strangers find a repo they did not search for by name.
Paste these, one per line, in this order (most specific first):

```
ai-agents
llm-security
guardrails
prompt-injection
indirect-prompt-injection
agentic-ai
tool-use
function-calling
llm
python
security
allowlist
rate-limiting
audit-log
ollama
ai-safety
agent-tools
policy-engine
approval-workflow
stdlib
```

That is 19 topics, under GitHub's 20-topic limit. If you want
a 20th, add `openai` or `anthropic` — only if you are happy
being found for those names.

## 4. Set the website field (same About panel)

`https://github.com/Juan-Smith000/Agent-Guard` — or, if you later
publish docs, the docs URL. A website field helps Google
associate the repo with a canonical page.

## 5. Optional, but helps Google: publish to PyPI

Google indexes PyPI very well, and PyPI search is a second
discovery path besides GitHub. The package is already set up
for it (`pyproject.toml`, stdlib only, no dependencies):

```sh
pip install build twine
python3 -m build
python3 -m twine upload dist/*
```

After that, `pip install agent-guard` and a PyPI search for
"agent guard" / "llm guardrails" will both find it. Update
`pyproject.toml`'s Homepage / Repository / Issues URLs to
your real repo first — that step is now done (Juan-Smith000/Agent-Guard).

## 6. What to expect, honestly

- **GitHub search:** a public repo is searchable on GitHub
  almost immediately after push, by name, description, topics,
  README, and code.
- **Google search:** Google crawls public GitHub repos
  automatically, usually within days, not minutes. You cannot
  force it, and no one can guarantee a ranking — but a public
  repo, a keyword-rich first paragraph in the README (done),
  a matching description (above), topics (above), a LICENSE,
  and a PyPI page (optional) are the levers that actually
  move it.
- **What will NOT help:** keyword-stuffing the README,
  adding hidden keywords, or creating many near-duplicate
  repos. Google and GitHub both discount that, and it makes
  the README worse for the humans who do find it.

## 7. After you push, check it worked

- GitHub: search `agent-guard` and filter by your username,
  then search `indirect prompt injection python` and check
  the repo appears in code/README results.
- Google: search `site:github.com/Juan-Smith000/Agent-Guard`
  after a few days — that query shows whether Google has
  indexed the repo at all, regardless of ranking.
- If Google has not indexed it after a week, the usual cause
  is the repo being private, or the push not having happened
  yet — not the README.
