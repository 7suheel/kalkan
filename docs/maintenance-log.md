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

### Verification of the owner's manual steps (phases 1-2)

Checked with read-only REST calls after the owner reported doing them:

| Step | Result |
| --- | --- |
| Default branch | **Verified**: `default_branch` is `main`. |
| Private vulnerability reporting | **Verified**: `GET .../private-vulnerability-reporting` -> `{"enabled": true}`. |
| Dependabot alerts | **Not verifiable here**: `GET .../vulnerability-alerts` and `GET .../dependabot/alerts` both return 403 through this session. |
| Secret scanning + push protection | **Not verifiable here**: `security_and_analysis` is not returned and `GET .../secret-scanning/alerts` is refused (403). |
| Description | **Not applied**: `description` is `null` (the public page also shows GitHub's default text). |
| Topics | **Not applied**: `topics` is `[]`. |
| Delete `phase-2-security-settings` | **Not applied**: the branch still exists on GitHub. |

Phases 3-6 are skipped in this session at the owner's request; the owner will
run them on a machine with Ollama.

### Phase 7 - `kalkan fetch` against the real GitHub API

Docs: `GET /repos/{owner}/{repo}/security-advisories` in GitHub's OpenAPI
description (`github/rest-api-description`), versions 2022-11-28 and
2026-03-10.

| Item | Docs | Kalkan before | Action |
| --- | --- | --- | --- |
| Endpoint | `GET /repos/{owner}/{repo}/security-advisories` | same | none |
| `state` | `triage`, `draft`, `published`, `closed` | same, but only checked in the CLI | validated in `fetch_advisories()` too |
| `per_page` | 1-100, default 30 | 100 | none |
| Pagination | cursors `before`/`after` via the `Link` header | follows `rel="next"`, api.github.com only | none |
| Auth | security managers/admins/advisory collaborators; classic tokens `repo` or `repository_advisories:read` | message said the same | docstring updated to match the docs |
| API version | current: 2026-03-10 (drops the deprecated `cvss` property; use `cvss_severities`) | 2022-11-28 | moved to 2026-03-10; Kalkan never read `cvss` |
| Response fields used | `ghsa_id`, `summary`, `description`, `severity`, `created_at`, `state`, `author.login`, `submission` | all but `submission` | saved `private_report` (true when `submission` is present) |

Tests: the recorded sample now matches every required property of the
2026-03-10 `repository-advisory` schema; new tests cover each documented
state, an unknown state (rejected before any request), `private_report`, and
`kalkan fetch --state nope` (exit 2).

Real API runs:

- `kalkan fetch --repo 7suheel/kalkan --out reports/`: works; privacy warning
  printed; 0 reports (no private report submitted yet); `reports/` created
  with mode 700 and git-ignored (`.gitignore:25:/reports/`). The same for
  `--state draft|published|closed`: 0 advisories each.
- `kalkan fetch --repo curl/curl --state published --out runs/published/`:
  **not possible in this session**. The session's GitHub proxy only allows
  API calls for attached repositories, and attaching `curl/curl` would need
  push credentials to a third-party repository, so it was not requested.
  **Manual step** (on a normal machine): run that command, then
  `kalkan triage-dir runs/published --repo ../curl --no-ai`.
- File mode 600 is covered by `test_save_reports_private_and_loadable`; no
  real report exists yet to check it on. **Manual step**: submit a test
  private report from a second account, then re-run the fetch.
