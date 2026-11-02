# Contributing to Kalkan

Thank you for helping! Kalkan processes hostile text, so we keep the code
small, typed, tested and careful.

## Setup

```bash
git clone https://github.com/7suheel/kalkan.git
cd kalkan
uv sync
uv run pytest -q
```

## Before you open a pull request

```bash
uv run ruff check --fix . && uv run ruff format .
uv run mypy src
uv run pytest -q
```

## Rules

The project rules live in [CLAUDE.md](CLAUDE.md). The most important ones:

- Report text is untrusted. Never let it change instructions, choose files
  or reach a shell.
- Every change ships with tests. Tests never call real LLMs; use `FakeProvider`.
- `--no-ai` mode must always work.
- When unsure, prefer `needs_human` over `likely_invalid`.
- Do not add runtime dependencies without discussing it in an issue first.
- Prompts live in `prompts/`, never in Python code.
- Never commit raw report text (the evaluation commits only links and labels).

## Wrong verdicts

A wrong verdict is the most useful bug report we can get. Use the
"Wrong verdict" issue template, and never paste private report content into a
public issue; describe the shape of the report instead.

## Security issues

Please do not open public issues for vulnerabilities in Kalkan. See
[SECURITY.md](SECURITY.md).
