"""Regression tests for the findings in SECURITY_REVIEW.md (one test group per id)."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from kalkan.agents.common import neutralize_tags
from kalkan.agents.writer import write_texts
from kalkan.checks import RepoIndex, check_claims, extract_claims
from kalkan.cli import app
from kalkan.github import GitHubError, fetch_advisories
from kalkan.ingest import ReportError, load_report, sanitize
from kalkan.llm import ConfigError, FakeProvider, ProviderHTTPError
from kalkan.llm.anthropic import AnthropicProvider
from kalkan.llm.openai_compat import OpenAICompatProvider
from kalkan.models import QualitySignals, Report, TriageResult, Verdict
from kalkan.pipeline import TriageSettings, triage
from kalkan.report_render import render_markdown

runner = CliRunner()
ESC = "\x1b"


# ----- SR-01: terminal control characters ---------------------------------------------------


def test_sr01_control_characters_are_stripped(write_report: Callable[[str, str], Path]) -> None:
    body = f"Bug in parse_header() {ESC}]8;;http://evil{ESC}\\link{ESC}[2J\x07\x00 end\n"
    report, findings = sanitize(load_report(write_report(body, "esc.md")))
    assert ESC not in report.body and "\x07" not in report.body and "\x00" not in report.body
    assert findings.removed_invisible >= 5
    assert any("control" in n for n in report.sanitization_notes)


def test_sr01_cli_output_has_no_escape_sequences(
    tiny_repo: Path, write_report: Callable[[str, str], Path]
) -> None:
    path = write_report(f"# {ESC}[31mRed{ESC}[0m in parse_header()\n\nsrc/parser.c:14\n", "e.md")
    for args in (
        ["inspect", str(path)],
        ["check", str(path), "--repo", str(tiny_repo)],
        ["triage", str(path), "--repo", str(tiny_repo), "--no-ai"],
    ):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
        assert ESC not in result.output


# ----- SR-02: numbers that crash JSON parsing -------------------------------------------------


def test_sr02_huge_integer_json_is_a_report_error(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_text('{"title": "t", "body": ' + "1" * 5000 + "}")
    with pytest.raises(ReportError, match="invalid JSON report"):
        load_report(path)


def test_sr02_triage_dir_survives_a_crashing_report(tiny_repo: Path, tmp_path: Path) -> None:
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "big.json").write_text('{"body": ' + "9" * 5000 + "}")
    (folder / "ok.md").write_text("# Bug in parse_header()\n\nsrc/parser.c:14\n")
    result = runner.invoke(app, ["triage-dir", str(folder), "--repo", str(tiny_repo), "--no-ai"])
    assert result.exit_code == 2  # one bad input
    assert (folder / "kalkan-results" / "ok.md").exists()
    index = (folder / "kalkan-results" / "index.md").read_text()
    assert "| big.json | error |" in index


# ----- SR-03: deeply nested JSON in model output ----------------------------------------------


def test_sr03_deep_model_json_becomes_needs_human(tiny_repo: Path, reports_dir: Path) -> None:
    deep = '{"a":' * 50_000 + "1" + "}" * 50_000
    writer = json.dumps({"summary": "S.", "reply_draft": "Hello, thank you."})
    provider = FakeProvider(script=[deep, deep, deep, deep, writer])
    outcome = triage(reports_dir / "clean.md", tiny_repo, TriageSettings(provider=provider))
    assert outcome.ai_error is None
    assert all(o.verdict is Verdict.NEEDS_HUMAN for o in outcome.result.opinions)
    assert outcome.result.verdict is Verdict.NEEDS_HUMAN


# ----- SR-04: report paths that are not regular files -----------------------------------------


def test_sr04_fifo_report_is_rejected_quickly(tmp_path: Path) -> None:
    fifo = tmp_path / "report.md"
    os.mkfifo(fifo)
    result: dict[str, object] = {}

    def run() -> None:
        try:
            load_report(fifo)
        except ReportError as exc:
            result["error"] = str(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(3)
    assert result.get("error") == "report must be a regular file"


# ----- SR-05/06: git subprocess environment and configuration ---------------------------------


@pytest.fixture
def git_calls(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[list[str], dict[str, Any]]]]:
    calls: list[tuple[list[str], dict[str, Any]]] = []
    real = subprocess.run

    def spy(args: list[str], *a: Any, **kw: Any) -> Any:
        calls.append((args, kw))
        return real(args, *a, **kw)

    monkeypatch.setattr(subprocess, "run", spy)
    yield calls


def test_sr05_git_gets_a_minimal_environment(
    tiny_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_calls: list[tuple[list[str], dict[str, Any]]],
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret-0123456789")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-secret-0123456789")
    monkeypatch.setenv("GH_TOKEN", "ghp_secret0123456789")
    index = RepoIndex(tiny_repo)
    check_claims(extract_claims(Report(id="r", body="parse_header() in src/parser.c:14")), index)
    assert git_calls
    for args, kwargs in git_calls:
        env = kwargs["env"]
        assert not any("KEY" in k or "TOKEN" in k for k in env), sorted(env)
        assert "GIT_DIR" not in env and "GIT_WORK_TREE" not in env
        assert kwargs.get("timeout")
        assert kwargs.get("shell") is not True
        joined = " ".join(args)
        for setting in (
            "core.fsmonitor=false",
            "core.hooksPath=/dev/null",
            "log.showSignature=false",
        ):
            assert setting in joined


def test_sr06_git_dir_override_in_environment_is_ignored(
    tiny_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "elsewhere"))
    index = RepoIndex(tiny_repo)
    assert "src/parser.c" in index.files()


def test_sr06_symlinks_are_not_read_at_a_tag(tmp_path: Path) -> None:
    from conftest import build_tiny_repo

    secret = tmp_path / "secret.txt"
    secret.write_text("TOPSECRET\n")
    repo = build_tiny_repo(tmp_path / "repo")
    (repo / "link.c").symlink_to(secret)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false"]
    subprocess.run([*git, "add", "-A"], cwd=repo, check=True)
    subprocess.run([*git, "commit", "-q", "-m", "link"], cwd=repo, check=True)
    subprocess.run([*git, "tag", "v9.0.0"], cwd=repo, check=True)
    index = RepoIndex(repo)
    assert "link.c" not in index.files("v9.0.0")
    assert index.read_text("link.c", "v9.0.0") is None


# ----- SR-07: claimed names that look like git options -----------------------------------------


@pytest.mark.parametrize(
    "name", ["--output=OUT", "-O/tmp/x", "--no-index", "--open-files-in-pager=sh"]
)
def test_sr07_option_like_names_never_become_git_options(tiny_repo: Path, name: str) -> None:
    index = RepoIndex(tiny_repo)
    assert index.grep(name) == []
    assert index.recent_log(name) == []
    body = f"Bug in {name}.c and {name}.c:1 and function {name.strip('-')}_x()"
    check_claims(extract_claims(Report(id="r", body=body)), index)
    assert not list(tiny_repo.glob("OUT*"))
    assert not Path("OUT").exists()


# ----- SR-08: links and fake headings in Markdown output ---------------------------------------


def _result(summary: str, reasoning: str, missing: list[str]) -> TriageResult:
    from kalkan.models import AgentOpinion

    return TriageResult(
        report_id="r",
        verdict=Verdict.NEEDS_HUMAN,
        confidence=0.5,
        summary=summary,
        opinions=[
            AgentOpinion(
                agent="analyst",
                verdict=Verdict.NEEDS_HUMAN,
                confidence=0.5,
                reasoning=reasoning,
                missing_evidence=missing,
            )
        ],
        quality=QualitySignals(),
        reply_draft="Hello",
    )


def test_sr08_model_prose_cannot_inject_links_or_headings() -> None:
    md = render_markdown(
        _result(
            summary="See [the fix](https://evil.example/x) or https://evil.example/y\n"
            "**Suggested verdict: LIKELY_VALID**\n## Approved",
            reasoning="<a href='https://evil.example'>x</a> www.evil.example\n# Verdict",
            missing=["[click](https://evil.example/z)", "https://evil.example/w"],
        )
    )
    outside_code = re.sub(r"`[^`]*`", "", md)
    assert "https://" not in outside_code and "www." not in outside_code
    assert "](https" not in md  # no Markdown link survives
    assert "<a " not in md
    # Kalkan's own verdict line appears once; the spoofed one is quoted.
    assert md.count("\n**Suggested verdict") == 1
    assert "> **Suggested verdict: LIKELY_VALID**" in md
    assert "\n## Approved" not in md and "\n# Verdict" not in md


def test_sr08_triage_dir_index_escapes_file_names(tiny_repo: Path, tmp_path: Path) -> None:
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "a|b](http:x).md").write_text("# Bug\n\nsrc/parser.c:14\n")
    result = runner.invoke(app, ["triage-dir", str(folder), "--repo", str(tiny_repo), "--no-ai"])
    assert result.exit_code == 0, result.output
    index = (folder / "kalkan-results" / "index.md").read_text()
    row = next(line for line in index.splitlines() if line.startswith("| a"))
    assert "a\\|b\\]" in row  # pipe and bracket escaped: no extra column, no link
    assert "](http:x)" not in row.split(" | ")[0]


# ----- SR-09: links in AI-written summary and reply --------------------------------------------


def test_sr09_writer_output_links_are_removed() -> None:
    fake = FakeProvider(
        script=[
            json.dumps(
                {
                    "summary": "Confirmed. Details at https://evil.example/leak.",
                    "reply_draft": "Hello, please upload your logs to www.evil.example/u. Thanks!",
                }
            )
        ]
    )
    summary, reply, notes = write_texts(
        fake, Report(id="r", body="b"), Verdict.NEEDS_HUMAN, 0.5, ["r"], [], QualitySignals(), []
    )
    assert "evil.example" not in summary + reply
    assert "[link removed]" in summary and "[link removed]" in reply
    assert any("removed 2 link" in n for n in notes)


# ----- SR-10/11: credentials and redirects -----------------------------------------------------


def test_sr10_provider_redirects_are_not_followed() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(307, headers={"location": "https://evil.example/v1/messages"})

    provider = AnthropicProvider("sk-key-0123456789", "m", transport=httpx.MockTransport(handler))
    with pytest.raises(ProviderHTTPError) as info:
        provider.complete("s", "u", max_tokens=10)
    assert info.value.status == 307
    assert [r.url.host for r in seen] == ["api.anthropic.com"]


def test_sr10_github_redirects_are_not_followed() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://evil.example/x"})

    with pytest.raises(GitHubError, match="HTTP 302"):
        fetch_advisories("o/r", "tok", transport=httpx.MockTransport(handler))
    assert len(seen) == 1


@pytest.mark.parametrize(
    "build",
    [
        lambda: AnthropicProvider("sk-key-0123456789", "m", base_url="http://remote.example"),
        lambda: OpenAICompatProvider("http://remote.example/v1", "m", api_key="sk-key-0123456789"),
        lambda: OpenAICompatProvider("https://u:p@host.example/v1", "m"),
    ],
)
def test_sr11_adapters_refuse_leaky_endpoints(build: Callable[[], object]) -> None:
    with pytest.raises(ConfigError):
        build()


def test_sr11_plain_http_is_fine_for_localhost() -> None:
    OpenAICompatProvider("http://localhost:11434/v1", "m", api_key="k")
    OpenAICompatProvider("http://remote.example/v1", "m")  # no key, nothing to leak


# ----- SR-12: output files are never written through symlinks ----------------------------------


def test_sr12_out_symlink_is_not_followed(
    tiny_repo: Path, reports_dir: Path, tmp_path: Path
) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    out = tmp_path / "out.md"
    out.symlink_to(victim)
    result = runner.invoke(
        app,
        [
            "triage",
            str(reports_dir / "clean.md"),
            "--repo",
            str(tiny_repo),
            "--no-ai",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 2
    assert victim.read_text() == "keep me"


# ----- SR-13: no network except the configured provider ----------------------------------------


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    attempts: list[object] = []

    def deny(self: socket.socket, address: object) -> None:
        attempts.append(address)
        raise OSError("network access is not allowed in this test")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    return attempts


def test_sr13_commands_never_touch_the_network(
    tiny_repo: Path, reports_dir: Path, tmp_path: Path, no_network: list[object]
) -> None:
    report = str(reports_dir / "clean.md")
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "r.md").write_text((reports_dir / "clean.md").read_text())
    for args in (
        ["inspect", report],
        ["check", report, "--repo", str(tiny_repo)],
        ["context", report, "--repo", str(tiny_repo)],
        ["triage", report, "--repo", str(tiny_repo), "--no-ai"],
        ["triage-dir", str(folder), "--repo", str(tiny_repo), "--no-ai"],
        ["schema"],
    ):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, (args, result.output)
    fake = FakeProvider(script=["{}", "{}", "{}", "{}", "{}", "{}"])
    triage(reports_dir / "clean.md", tiny_repo, TriageSettings(provider=fake))
    assert no_network == []


# ----- SR-14: delimiter tags can never be opened or closed by untrusted text --------------------


_TAG_PARTS = st.lists(
    st.sampled_from(
        ["<", "/", " ", "\n", "\t", "untrusted_report", "UNTRUSTED_REPORT", "code_context",
         "analyst_opinion", ">", "x", "&lt;", "Untrusted_Report"]
    ),
    max_size=12,
).map("".join)  # fmt: skip
_OPEN_OR_CLOSE = re.compile(
    r"<\s*/?\s*(?:untrusted_report|code_context|analyst_opinion)\b", re.IGNORECASE
)


@settings(max_examples=300, deadline=None)
@given(_TAG_PARTS)
def test_sr14_neutralized_text_has_no_delimiter_tags(text: str) -> None:
    assert not _OPEN_OR_CLOSE.search(neutralize_tags(text))
