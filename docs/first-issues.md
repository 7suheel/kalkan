# Good first issues (drafts)

Eight starter tasks. Each one is small, has a clear test and touches one module.
They are open as GitHub issues #4 to #11 with the `good first issue` and
`help wanted` labels: <https://github.com/7suheel/kalkan/issues?q=label%3A%22good+first+issue%22>.

## 1. Add Swift and Kotlin function definitions to the checker

`src/kalkan/checks/verify.py` recognizes function definitions with regex
templates in `_DEFINITION_TEMPLATES`. Add Swift (`func name(`) and improve
Kotlin (`fun Type.name(`, `suspend fun name(`).

- Add the templates (bounded repetition only, no nested quantifiers).
- Add a Swift and a Kotlin file to a temporary repo in `tests/test_checks.py`
  and test that the definition is CONFIRMED with the right line.
- The adversarial regex speed test must still pass.

## 2. Add a provider preset for OpenRouter

Today OpenRouter works through `compat:` with `KALKAN_BASE_URL`. Add an
`openrouter:<model-id>` provider in `src/kalkan/llm/config.py` that uses
`https://openrouter.ai/api/v1` and `OPENROUTER_API_KEY`.

- Only `OPENROUTER_API_KEY` may be sent to OpenRouter (see
  `test_keys_never_go_to_another_service`).
- Tests with `httpx.MockTransport`; no real network.

## 3. Improve the template reply for `likely_invalid`

`template_reply` in `src/kalkan/report_render.py` is used in `--no-ai` mode.
For reports whose claims do not match the code, list each missing reference on
its own line and suggest the reporter checks the exact version.

- Keep the tone polite; never mention AI or spam.
- Update the snapshot with `KALKAN_UPDATE_SNAPSHOTS=1 uv run pytest -q` and
  review the diff.

## 4. Detect affected-version ranges

`extract_claims` finds single versions. Reports often say "8.0.0 to 8.4.0" or
"< 8.5.0". Extract both ends as VERSION claims and keep the quote.

- Tests in `tests/test_checks.py` for "from X to Y", "X - Y", "before X" and "< X".

## 5. Show the claim quote in `kalkan check`

`format_checks` in `src/kalkan/cli.py` prints the normalized claim value. Add a
`--quotes` flag that prints the exact quote from the report under each row
(clipped to 80 characters, one line).

- CLI test with `typer.testing.CliRunner`.

## 6. Count CWE ids as claims

Reports often name a CWE (`CWE-787`). Add a `CWE_ID` claim kind, extract it,
mark it NOT_CHECKABLE with a format check, and show it in the Markdown output.

- Update `ClaimKind`, `extract.py`, `verify.py`, the JSON schema test and the
  snapshots.

## 7. Add `--fail-on` to `triage-dir`

Let maintainers use Kalkan in local scripts: `--fail-on needs_human` exits with
code 1 when any report gets that verdict (after writing all results).

- Test with `--no-ai` and the fixture reports.

## 8. Translate the reply draft

Add `--reply-language <code>` to `kalkan triage`. With AI on, the writer prompt
asks for the reply in that language; with `--no-ai`, add German and Turkish
templates next to the English one.

- The prompt change goes in `prompts/writer.md`, never in Python.
- Tests with `FakeProvider` check the language instruction reaches the prompt.
