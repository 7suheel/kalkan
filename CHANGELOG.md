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

[0.1.0]: https://github.com/7suheel/kalkan/releases/tag/v0.1.0
