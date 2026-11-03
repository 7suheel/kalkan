# Kalkan security review

Date: 2026-11-03. Kalkan 0.1.0 (main at `fc2c663` plus this review's fixes).
Reviewed as an attacker would: a malicious reporter controls the report text
(and, through it, influences the model's answers); a compromised dependency or
workflow could act in CI. See [THREAT_MODEL.md](THREAT_MODEL.md) for assets
and attackers.

Severity: **High** = report content or keys leak, or code runs; **Medium** =
a hostile report can crash Kalkan, mislead the maintainer through the output,
or expose secrets to a local process; **Low** = needs an unusual setup or has
little impact; **Info** = checked, no issue.

Every fixed finding has a regression test in `tests/test_security_review.py`
(`test_srNN_*`) or `tests/test_properties.py`. The SR-01 to SR-12 tests fail
on the code before the fixes and pass after.

## Findings

| Id | Area | Severity | Description | Status |
| --- | --- | --- | --- | --- |
| SR-01 | Output (terminal) | Medium | Control characters (ESC, BEL, NUL) in a report survived sanitizing and reached the terminal through `kalkan check`, `inspect` and Markdown on stdout, so a report could inject terminal escape sequences (fake hyperlinks, screen clearing). Found by the Hypothesis sanitizer test. | Fixed: `sanitize` removes all C0/C1 control characters except newline and tab and notes it; Markdown output strips them again. |
| SR-02 | Hostile reports | Medium | A JSON report with an integer longer than 4,300 digits raised an uncaught `ValueError`; in `triage-dir` it aborted the whole batch. Found by Hypothesis. | Fixed: becomes `ReportError` (exit 2, batch continues). |
| SR-03 | Hostile model output | Medium | Deeply nested JSON in the model's answer (which a report can provoke) raised `RecursionError` and crashed the run. | Fixed: treated as invalid output, so the agent's opinion becomes NEEDS_HUMAN. |
| SR-04 | Hostile reports | Low | A report path that is a FIFO or device (`/dev/zero`) blocked forever. | Fixed: only regular files are read, with a bounded read. |
| SR-05 | Subprocess / secrets | Medium | Every `git` call inherited the full environment, including `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `GH_TOKEN`. Git does not need them, and any program git starts would see them. | Fixed: git gets a minimal environment (`PATH`, `HOME`, temp dirs and fixed `GIT_*`/`LC_ALL` values). |
| SR-06 | Subprocess / paths | Low | `GIT_DIR`/`GIT_WORK_TREE` in the environment could redirect git to another repository; repository config could still start programs (`core.hooksPath`, `gpg.program` via `log.showSignature`, `diff.external`); symlinks committed at a tag were read through `git show` (returning the link target text). | Fixed: environment overrides are dropped, git runs with `core.fsmonitor=false`, `core.hooksPath=/dev/null`, `log.showSignature=false`, `diff.external=` and no pager; files at a tag are limited to regular blobs (modes 100644/100755). The eval harness runs git with hooks disabled. |
| SR-07 | Subprocess | Info | Claimed names that look like git options (`--output=/x`, `-O/tmp/x`, `--open-files-in-pager=sh`) never become options: needles go after `-e`, paths after `--`, refs are validated, commit ids must be hex. No `shell=True` anywhere; every subprocess has a timeout. | No issue; tests added. |
| SR-08 | Output (Markdown) | Medium | Model-written prose (summary, agent reasoning, missing evidence) was inserted as Markdown: it could add clickable links, bare URLs that GitHub auto-links, headings, and a fake "**Suggested verdict**" line that looks like Kalkan's own. File names in `triage-dir`'s `index.md` were not escaped. | Fixed: prose is rendered as a quote block with links broken up and URLs shown as code; table cells and list items escape pipes, brackets and HTML; `index.md` escapes names and URL-encodes links. |
| SR-09 | Prompt injection | Medium | A report could get the writer to put an attacker-chosen URL into the maintainer summary or the reply draft. | Fixed: URLs in AI-written summary and reply are replaced with `[link removed]` and a note is shown. |
| SR-10 | Secrets / network | Low | httpx does not follow redirects by default, but a 3xx answer from a provider was parsed as data, and the clients did not state the setting. | Fixed: clients set `follow_redirects=False`; any 3xx from a provider or GitHub is an error. |
| SR-11 | Secrets | Low | The plain-http and URL-credential checks lived only in `resolve_settings`; adapters built directly could send a key over plain http to a remote host. | Fixed: adapters check their endpoint too. |
| SR-12 | Output files | Low | `--out`, `triage-dir` and `kalkan fetch` wrote through a symlink planted at the output path. | Fixed: files are opened with `O_NOFOLLOW`. |
| SR-13 | Network | Info | Only the configured provider is contacted during triage (GitHub only by `kalkan fetch`). Checked with a socket guard over `inspect`, `check`, `context`, `triage`, `triage-dir`, `schema` and an AI run with FakeProvider. The eval harness (not shipped in the wheel) also contacts the gist, `curl.se` and `hackerone.com`. | No issue; test added. |
| SR-14 | Prompt injection | Info | Delimiter tags (`<untrusted_report>`, `<code_context>`, `<analyst_opinion>`) cannot be opened or closed by untrusted text in any case or spacing (property test); fake role headers, role tokens and output-shaped JSON are flagged as injection. | No issue; property test added. |
| SR-15 | Hostile reports | Info | Size limits (5 MB file, 200 KB text), encoding errors (decoded with replacement), deeply nested JSON reports and catastrophic backtracking: covered by existing tests plus new Hypothesis tests for every extractor (500 ms per input). | No issue beyond SR-01/SR-02. |
| SR-16 | Supply chain | Info | `uvx pip-audit` on the 31 locked packages: no known vulnerabilities. Workflows: every action pinned by commit SHA, `permissions: contents: read` at the top, `id-token: write` only in the publish job, `persist-credentials: false`, no `pull_request_target`, no `${{ github.event.* }}` in `run:` scripts. | No issue. |
| SR-17 | Prompt injection | Low | Injection detection is pattern-based: paraphrased or translated instructions and homoglyphs (for example Cyrillic letters) can slip past the sanitizer. The prompts and the verdict rules remain as a second line of defense. | Open (documented limit). |
| SR-18 | Prompt injection | Low | The writer can still repeat attacker-chosen instructions as plain text (without links) in the reply draft. The reply is only a draft that the maintainer reviews; Kalkan never sends it. | Open. |
| SR-19 | Network | Low | In a partial clone (`--filter=blob:none`), reading a file at a tag can make git fetch the missing blob from the repository's own remote. | Open (documented; use a full clone for private work). |
| SR-20 | Budget | Low | The token budget is checked before each call, so one response can go over `KALKAN_MAX_TOKENS` by up to that call's `max_tokens`. | Open. |
| SR-21 | Secrets | Low | `kalkan fetch` runs `gh auth token` with the user's full environment (gh needs its own configuration to find the token). | Open (accepted). |
| SR-22 | Privacy | Low | The configured LLM provider receives the full report text. This is by design and stated before each run. | Open (by design; use Ollama or `--no-ai` for reports that must stay local). |

## Summary

| Severity | Found | Fixed | Open |
| --- | --- | --- | --- |
| High | 0 | 0 | 0 |
| Medium | 6 | 6 | 0 |
| Low | 11 | 5 | 6 |
| Info | 5 | - | - |

Medium: SR-01, SR-02, SR-03, SR-05, SR-08, SR-09 (all fixed). Low fixed:
SR-04, SR-06, SR-10, SR-11, SR-12. Low open: SR-17 to SR-22. Info (checked,
no issue): SR-07, SR-13, SR-14, SR-15, SR-16.
