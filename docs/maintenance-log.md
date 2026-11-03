# Maintenance log

A dated record of maintenance work on Kalkan: what was done, what was found,
numbers and links. Newest entries at the bottom.

## 2026-11-03

### Preconditions

| Check | Result |
| --- | --- |
| Ollama (`curl -s http://localhost:11434/api/tags`) | **Down**: connection refused, no `ollama` binary installed. |
| Network to `ollama.com`, `curl.se`, `hackerone.com`, `docs.github.com` | Refused by the session's network policy. |
| GitHub REST reads | Work (`permissions.admin: true` on the repository). |
| GitHub GraphQL | Not available from this session (HTTP 403), so `gh repo view --json` and `gh pr create` cannot be used; REST equivalents are used instead. |
| GitHub repository settings writes | Refused by the session's GitHub proxy (HTTP 403). |
| `runs/` scratch folder | Git-ignored (`git check-ignore runs/x` -> `.gitignore:28:/runs/`). |

Because `docs.github.com` is blocked, the GitHub REST documentation was read
from GitHub's official OpenAPI description
(`github/rest-api-description`, `descriptions/api.github.com/api.github.com.2022-11-28.json`).

### Phase 1 - main branch and CI

- `git ls-remote --heads origin`: only `claude/new-session-ngweex` (`c6000a9`); no `main`.
- Created `main` from `origin/claude/new-session-ngweex` and pushed it.
- `gh repo edit --default-branch main`: **refused** (HTTP 403, "Repository
  settings writes are not permitted through this proxy"). REST docs confirm
  this is `PATCH /repos/{owner}/{repo}` with `default_branch`.
  The default branch is still `claude/new-session-ngweex`. **Manual step.**
- CI on `main`: run 41612456091 on `c6000a9`, green (lockfile, install, ruff
  lint, ruff format, mypy, pytest).
- `claude/new-session-ngweex` was kept.

### Phase 2 - repository security settings

Every write below was refused by the session's GitHub proxy (HTTP 403). The
REST endpoints were checked against the docs first; they match the commands
in the task (`PUT .../private-vulnerability-reporting` -> 204,
`PUT .../vulnerability-alerts` -> 204, `GET .../vulnerability-alerts` -> 204
enabled / 404 disabled, `PATCH /repos/{owner}/{repo}` with
`security_and_analysis`, `PUT .../topics` with `names`).

| Setting | Result | Verified state |
| --- | --- | --- |
| Private vulnerability reporting | PUT refused (403) | `GET` -> `{"enabled": false}` |
| Dependabot alerts | PUT refused (403); GET also refused | unknown |
| Secret scanning + push protection | PATCH refused (403) | `security_and_analysis` not returned |
| Description | refused (403) | `description: null` |
| Topics | PUT refused (403) | `topics: []` |

**Manual steps** (on <https://github.com/7suheel/kalkan>):

1. **Default branch**: Settings -> General -> Default branch -> click the
   switch (two arrows) icon -> choose `main` -> Update -> "I understand, update
   the default branch".
2. **Private vulnerability reporting**: Settings -> Advanced Security (called
   "Code security" or "Code security and analysis" on some accounts) ->
   Private vulnerability reporting -> Enable.
3. **Dependabot alerts**: same page -> Dependabot -> Dependabot alerts ->
   Enable (this also turns on the dependency graph if it is off).
4. **Secret scanning and push protection**: same page -> Secret Protection
   (or "Secret scanning") -> Enable, then Push protection -> Enable.
5. **Description and topics**: repository home page -> the gear icon next to
   "About" -> Description: `AI-assisted triage for incoming security
   vulnerability reports. Bring your own AI, or none.`; Topics: `security`,
   `vulnerability-management`, `triage`, `llm`, `ai-security`, `open-source`,
   `maintainers`, `cli` -> Save changes.

Also added `/runs/` to `.gitignore` for local scratch outputs.
PR: https://github.com/7suheel/kalkan/pull/1

### Phase 3 - stopped

Ollama is not running and cannot be installed from this session (`ollama.com`
is blocked), so Phase 3 and everything after it was not started, as the task's
global rule requires.
