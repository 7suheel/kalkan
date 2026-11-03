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

PR: https://github.com/7suheel/kalkan/pull/2 (merged, CI green). The proxy
also refuses branch deletion, so `phase-7-github-fetch` stays on GitHub.

### Phase 8 - security review

Full review in [SECURITY_REVIEW.md](../SECURITY_REVIEW.md): 22 rows.

| Severity | Found | Fixed | Open |
| --- | --- | --- | --- |
| High | 0 | 0 | 0 |
| Medium | 6 | 6 | 0 |
| Low | 11 | 5 | 6 |
| Info (checked, no issue) | 5 | - | - |

What was found and fixed (each with a regression test that fails on the old
code):

- Hypothesis found two crashes on its own: control characters survived
  sanitizing (terminal escape injection), and a JSON report with a
  5,000-digit integer crashed the run and would abort `triage-dir`.
- Deeply nested JSON in model output crashed the run (`RecursionError`).
- A FIFO report path blocked forever.
- Every git call inherited the full environment, including API keys and
  `GIT_DIR`.
- Model prose could put clickable links, headings or a fake verdict line into
  the Markdown output; links could also reach the AI-written reply draft.
- Smaller hardening: redirects are explicit errors, adapters check their own
  endpoint, output files use `O_NOFOLLOW`, symlinks are not read at tags,
  `index.md` names are escaped.

Tools: `hypothesis` added as a dev dependency (property tests for every
extractor with a 500 ms deadline per input); `uvx pip-audit` on the 31 locked
packages found no known vulnerabilities. Workflows: all actions pinned by SHA,
least-privilege permissions, no `pull_request_target`, no `github.event`
interpolation in scripts.

PR: https://github.com/7suheel/kalkan/pull/3 (merged, CI green).

### Phase 9 - demo GIF, code of conduct, first issues

- **Demo GIF**: installed VHS (`go install github.com/charmbracelet/vhs@latest`),
  ttyd and gifsicle (apt), and used the preinstalled Chromium. The first
  recording ended on the bottom of the Markdown output, with the verdict and
  claim table scrolled away, so `demo.tape` now shows `cat` of the made-up
  report, `kalkan check` (compact claim table) and the verdict line from
  `kalkan triage --no-ai`. `docs/demo.gif`: 189 KB (1400x760), under the
  2 MB limit, so gifsicle was not needed. The last frame was checked by eye
  and is readable. The image line at the top of README.md is enabled.
- **Code of conduct**: the contact line is left as `[INSERT CONTACT METHOD]`
  at the owner's request. **Manual step.**
- **Issues**: the `good first issue` and `help wanted` labels already
  existed. No issues existed before (`GET /repos/{owner}/{repo}/issues?state=all`).
  Created the 8 issues from docs/first-issues.md, each with both labels,
  context, file pointers and a "Done when" section:
  - https://github.com/7suheel/kalkan/issues/4 Swift and Kotlin definitions
  - https://github.com/7suheel/kalkan/issues/5 openrouter: provider preset
  - https://github.com/7suheel/kalkan/issues/6 --no-ai reply template for mismatched claims
  - https://github.com/7suheel/kalkan/issues/7 affected-version ranges
  - https://github.com/7suheel/kalkan/issues/8 `kalkan check --quotes`
  - https://github.com/7suheel/kalkan/issues/9 CWE ids as a claim kind
  - https://github.com/7suheel/kalkan/issues/10 `triage-dir --fail-on`
  - https://github.com/7suheel/kalkan/issues/11 `--reply-language`
  Issue creation was allowed through the proxy, so
  docs/first-issues-ready.md was not needed.

PR: https://github.com/7suheel/kalkan/pull/12 (merged, CI green).

### Phase 10 - release prep (no tag created)

- Version: `src/kalkan/__init__.py` says `0.1.0` (pyproject reads it through
  hatch); CHANGELOG has `## [0.1.0] - unreleased` and now lists everything
  merged in PRs #1, #2, #3 and #12.
- `.github/workflows/release.yml` review:
  - triggers on `v*` tags;
  - runs `uv lock --check` and the full test suite;
  - builds with `uv build`;
  - publishes with `pypa/gh-action-pypi-publish` through Trusted Publishing,
    with `id-token: write` only on the publish job and the `pypi` environment;
  - all actions are pinned by SHA.

  Added:
  - a step that fails if the tag is not `v` + the package version
    (reads `GITHUB_REF_NAME` from the environment);
  - ruff, ruff format and mypy before the tests;
  - `uvx twine==7.0.0 check --strict dist/*`.
- `uv build` + `uvx twine check --strict dist/*`: both files PASSED.
- Wheel contents (`unzip -l`): `kalkan/` package and the three prompt
  templates (`kalkan/prompts/analyst.md`, `skeptic.md`, `writer.md`); no tests,
  fixtures, eval, `runs/`, `reports/` or secrets.
- sdist: the include patterns matched `README.md` at any depth (it picked up
  `docs/launch/README.md` and `eval/README.md`); patterns are now anchored to
  the project root. The sdist holds only `src/`, `prompts/`, `tests/`,
  README, LICENSE, CLAUDE.md, pyproject and PKG-INFO.
- README demo image now uses an absolute URL so it also renders on PyPI.
- Smoke test in a fresh virtual environment with only the wheel installed:
  - `kalkan --version` -> `kalkan 0.1.0`;
  - `kalkan schema` -> TriageResult schema;
  - `kalkan triage clean.md --repo <tiny fixture repo> --no-ai` -> exit 0,
    `needs_human` (Markdown and JSON, 10 claims);
  - prompt templates load from the installed package.

**PyPI Trusted Publisher** (the project does not exist on PyPI yet, so add a
*pending* publisher): pypi.org -> Account settings -> Publishing -> "Add a new
pending publisher" -> GitHub:

| Field | Value |
| --- | --- |
| PyPI Project Name | `kalkan` |
| Owner | `7suheel` |
| Repository name | `kalkan` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Optional but recommended: on GitHub, Settings -> Environments -> New
environment `pypi`, add yourself as a required reviewer and limit deployment
tags to `v*`.

**Release commands** (run on your machine; nothing here creates a tag):

```bash
git checkout main && git pull --ff-only origin main
# 1. Put the release date in CHANGELOG.md ("## [0.1.0] - YYYY-MM-DD"), merge
#    that through a PR, then pull main again.
git tag -a v0.1.0 -m "Kalkan 0.1.0"
git push origin v0.1.0
# 2. Watch Actions -> Release (approve the pypi environment if you protected it).
# 3. Check the published package from a clean folder:
uvx kalkan@0.1.0 --version
# 4. Create the GitHub release from the CHANGELOG section:
gh release create v0.1.0 --title "Kalkan 0.1.0" --notes-file <(sed -n '/^## \[0.1.0\]/,/^\[0.1.0\]:/p' CHANGELOG.md | sed '$d')
```
