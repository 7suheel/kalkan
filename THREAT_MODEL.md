# Kalkan threat model

Kalkan reads hostile text by design: anyone can send a security report. This
document lists what we protect, who might attack it, how, and what we do about
it. Please report gaps through GitHub private vulnerability reporting (see
SECURITY.md).

## Assets

- **Private report content.** Unpublished vulnerability details. Leaking them
  can put users at risk before a fix exists.
- **The maintainer's machine and repository.** Kalkan runs locally with the
  maintainer's permissions next to their checkout.
- **API keys** for the LLM provider the maintainer chose.
- **The verdict.** A wrong `likely_invalid` can bury a real vulnerability; a
  wrong `likely_valid` wastes time and can be used to get attention.

## Attackers

1. **Malicious reporter.** Controls the full report text and can try to steer
   the AI, read files, run commands, or slow Kalkan down.
2. **Compromised dependency.** A malicious release of a Python package or a
   GitHub Action (LiteLLM was compromised on PyPI in March 2026).
3. **Curious CI log viewer.** Anyone can read Actions logs of public
   repositories; reports processed there would be public.

## Attacks and mitigations

| Attack | Mitigation |
| --- | --- |
| Prompt injection ("ignore previous instructions", fake `SYSTEM:` lines, role tags) | The report is wrapped in `<untrusted_report>` and every prompt says it is data. The sanitizer flags injection phrases; if injection is suspected and an agent answers `likely_valid`, the verdict becomes `needs_human` (verdict rule 1). |
| Hidden instructions (HTML comments, `display:none`, white text, `<details>`, zero-width characters, Unicode tag characters, base64 blocks) | Invisible characters are removed before analysis, tag-character text is decoded and shown, hidden HTML is reported, base64 blocks are decoded and scanned. |
| Closing our tags early (`</untrusted_report>`, `<code_context>`) | Delimiter tags inside untrusted text are neutralized before prompts are built. |
| Fake output (JSON shaped like Kalkan's own schema) | Detected as an injection marker; agent output is validated against a strict schema and citations outside the code context are dropped. |
| Made-up claims (functions, lines, snippets that do not exist) | The deterministic checker verifies every claim against the repository without AI. |
| Path traversal (`../../etc/passwd`, absolute paths, symlinks) | Paths are normalized, `..` is rejected, only tracked files are read, and resolved paths must stay inside the repository root. |
| Command injection (shell metacharacters in names) | Git runs only with argument lists, never `shell=True`; values go after `-e` or `--`; refs are validated; `core.fsmonitor` and pagers are disabled. |
| ReDoS (inputs built to make regexes backtrack) | All patterns are bounded; tests check each one under 100 ms on 200 KB hostile inputs. Reports are capped at 200 KB of text and 5 MB on disk. |
| Data exfiltration through rendered Markdown (images, HTML) | Output escapes report-controlled text; model prose cannot contain raw HTML or images. |
| Dismissive replies that drive reporters away | The writer is told never to accuse reporters of using AI; dismissive wording falls back to the template reply. |
| Key leakage | Keys come from environment variables, are never printed or logged, and are redacted from error messages. HTTP client logging is silenced. |
| Private reports in public CI | Kalkan is a local CLI. `kalkan fetch` warns, saves reports with 0600 permissions, and `reports/` is gitignored. |
| Compromised dependency | Three runtime dependencies (Typer, Pydantic, httpx); no LLM gateway libraries; `uv.lock` checked in CI with `uv lock --check`; GitHub Actions pinned to commit SHAs; Dependabot enabled. |
| Agents acting on their own | Agents have no tools, no network and no file access. Our code chooses the code they see. Kalkan never closes, sends or publishes anything. |

## Known limits

- Injection detection is pattern-based. Paraphrased or translated instructions,
  and homoglyphs (for example Cyrillic letters), can slip past the sanitizer;
  the agents' instructions and the verdict rules are the second line of defense.
- The model provider the maintainer chooses sees the report. Use a local model
  (Ollama) or `--no-ai` for reports that must not leave the machine.
- Function detection uses regexes, not a parser: unusual definitions (macros,
  generated code) may be reported as "referenced" or "not found".
- Line numbers are checked at HEAD and, when the report names a tagged
  version, at that tag; other versions are not checked.
- A malicious repository checkout is out of scope: Kalkan trusts the
  maintainer's own repository.
