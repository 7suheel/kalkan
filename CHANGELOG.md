# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

First release.

### Added

- `kalkan triage` and `kalkan triage-dir`: compare a security report with a
  local checkout and suggest `likely_valid`, `needs_evidence`,
  `likely_invalid` or `needs_human`, with a claim table, a maintainer summary
  and a polite reply draft (Markdown or JSON).
- Report reader and sanitizer: Markdown, text and GitHub advisory JSON;
  removes invisible characters and decodes Unicode tag smuggling; flags hidden
  HTML, base64 instructions and prompt-injection phrases (`kalkan inspect`).
- Deterministic checker (no AI): files, functions, line numbers, versions,
  commits, CVE ids and code snippets verified with git, at the reported tag
  when there is one (`kalkan check`).
- Code context builder within a token budget (`kalkan context`).
- Analyst, skeptic and writer agents with explicit verdict rules; when the
  agents disagree or injection is suspected, a human decides.
- Bring your own AI: Anthropic and OpenAI-compatible adapters (OpenAI, Ollama,
  OpenRouter and others) written with httpx, with a per-run token budget
  (`kalkan doctor`).
- `--no-ai` mode with template summaries and replies.
- `kalkan fetch`: download private vulnerability reports from GitHub.
- Evaluation harness on curl reports (`eval/`).
- Adversarial test suite and threat model.
- `kalkan fetch --state triage|draft|published|closed`; saved reports record
  whether they came through private vulnerability reporting
  ([#2](https://github.com/7suheel/kalkan/pull/2)).
- `SECURITY_REVIEW.md` and property-based tests (Hypothesis) for every
  extractor ([#3](https://github.com/7suheel/kalkan/pull/3)).
- Demo GIF in the README and eight good-first-issues
  ([#12](https://github.com/7suheel/kalkan/pull/12)).
- `docs/maintenance-log.md`, a running maintenance log
  ([#1](https://github.com/7suheel/kalkan/pull/1)).

### Changed

- `kalkan fetch` uses GitHub REST API version 2026-03-10 and validates the
  advisory state before any request ([#2](https://github.com/7suheel/kalkan/pull/2)).
- In Markdown output, the summary and agent reasoning are shown as quote
  blocks, with links broken up and URLs shown as code
  ([#3](https://github.com/7suheel/kalkan/pull/3)).
- The release workflow checks that the tag matches the package version, runs
  lint and type checks with the tests, and runs `twine check` on the build.
- The sdist contains only the source, prompts, tests and top-level docs.

### Security

All from the security review in [#3](https://github.com/7suheel/kalkan/pull/3)
(details in `SECURITY_REVIEW.md`):

- Terminal control characters are removed from reports and output (SR-01).
- Huge JSON numbers and deeply nested model output no longer crash a run
  (SR-02, SR-03); only regular files are read as reports (SR-04).
- Git runs with a minimal environment, without API keys, and never runs
  repository-configured programs (SR-05, SR-06).
- Links and fake headings from model or report text cannot appear as
  clickable links or as Kalkan's own lines in Markdown output; links are
  removed from AI-written summaries and replies (SR-08, SR-09).
- Redirects are never followed with credentials; adapters refuse plain-http
  remote endpoints when a key is set; output files are never written through
  symlinks (SR-10, SR-11, SR-12).

[0.1.0]: https://github.com/7suheel/kalkan/releases/tag/v0.1.0
