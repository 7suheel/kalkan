"""Tests for the code context builder."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kalkan.checks import RepoIndex, check_claims, extract_claims
from kalkan.cli import app
from kalkan.context import build_context, render_context
from kalkan.models import CodeContext, ContextSection, Report

runner = CliRunner()


def _ctx(body: str, repo: Path, budget: int = 12_000) -> CodeContext:
    report = Report(id="t", body=body)
    index = RepoIndex(repo)
    return build_context(report, check_claims(extract_claims(report), index), index, budget)


def test_function_body_is_included(tiny_repo: Path) -> None:
    ctx = _ctx("Overflow in parse_header() in src/parser.c", tiny_repo)
    section = next(s for s in ctx.sections if "parse_header" in s.reason)
    assert section.path == "src/parser.c"
    assert section.start_line == 10
    assert section.end_line == 23  # closing brace of the function
    assert "strcpy(name, line);" in section.code
    text = render_context(ctx)
    assert "14 |     strcpy(name, line);" in text
    assert "recent commits touching src/parser.c" in text
    assert "add read_body" in text


def test_line_reference_window(tiny_repo: Path) -> None:
    ctx = _ctx("See src/conn.c:10", tiny_repo)
    assert ctx.sections[0].path == "src/conn.c"
    assert ctx.sections[0].start_line == 1
    assert ctx.contains("src/conn.c:10")
    assert not ctx.contains("src/conn.c:999")
    assert not ctx.contains("src/other.c:10")


def test_reads_at_reported_tag(tiny_repo: Path) -> None:
    ctx = _ctx("In version 1.0.0 the function parse_header() in src/parser.c overflows", tiny_repo)
    assert ctx.ref == "v1.0.0"
    section = ctx.sections[0]
    assert section.ref == "v1.0.0"
    assert "read_body" not in "\n".join(s.code for s in ctx.sections)
    assert "at tag v1.0.0" in render_context(ctx)


def test_budget_cut_off_is_listed(tiny_repo: Path) -> None:
    body = "parse_header() in src/parser.c, free_conn() in src/conn.c and main() in src/main.c"
    full = _ctx(body, tiny_repo)
    assert len(full.sections) >= 3 and not full.omitted
    small = _ctx(body, tiny_repo, budget=250)
    assert small.token_estimate <= 250
    assert small.omitted
    assert len(small.sections) < len(full.sections)
    assert "omitted to stay within the token budget" in render_context(small)


def test_hallucinated_claims_give_empty_context(tiny_repo: Path) -> None:
    ctx = _ctx("Overflow in curl_url_parse_strict() in lib/urlapi.c at line 9999", tiny_repo)
    assert ctx.sections == []
    assert "No code could be matched" in render_context(ctx)


def test_contains_accepts_ranges() -> None:
    ctx = CodeContext(
        sections=[ContextSection(path="a.c", start_line=5, end_line=9, reason="r", code="")]
    )
    assert ctx.contains("a.c:5-7")
    assert ctx.contains("a.c")
    assert not ctx.contains("a.c:x")


def test_nothing_outside_the_repo_is_read(tmp_path: Path) -> None:
    outside = tmp_path / "secret.c"
    outside.write_text("int secret_function(void) { return 42; }\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.c").write_text("int ok(void) { return 0; }\n")
    (repo / "link.c").symlink_to(outside)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false"]
    subprocess.run([*git, "init", "-q"], cwd=repo, check=True)
    subprocess.run([*git, "add", "-A"], cwd=repo, check=True)
    subprocess.run([*git, "commit", "-q", "-m", "x"], cwd=repo, check=True)

    index = RepoIndex(repo)
    assert "link.c" in index.files()
    assert index.read_text("link.c") is None
    assert index.read_text("../secret.c") is None
    ctx = _ctx("See link.c:1 and ../secret.c:1 and secret_function()", repo)
    assert "return 42" not in render_context(ctx)


def test_context_command(tiny_repo: Path, reports_dir: Path) -> None:
    result = runner.invoke(
        app, ["context", str(reports_dir / "clean.md"), "--repo", str(tiny_repo)]
    )
    assert result.exit_code == 0, result.output
    assert "strcpy(name, line);" in result.output
    assert "tokens of 12000" in result.output


@pytest.mark.parametrize("budget", ["100"])
def test_context_command_rejects_tiny_budget(
    tiny_repo: Path, reports_dir: Path, budget: str
) -> None:
    result = runner.invoke(
        app,
        [
            "context",
            str(reports_dir / "clean.md"),
            "--repo",
            str(tiny_repo),
            "--token-budget",
            budget,
        ],
    )
    assert result.exit_code == 2
