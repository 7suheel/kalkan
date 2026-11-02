"""Typer command-line interface for Kalkan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from kalkan import __version__
from kalkan.checks import RepoError, RepoIndex, check_claims, compute_quality, extract_claims
from kalkan.ingest import ReportError, load_report, sanitize
from kalkan.models import ClaimCheck, QualitySignals, Report, SanitizerFindings, TriageResult

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_PROVIDER_ERROR = 3

app = typer.Typer(
    name="kalkan",
    help="AI-assisted triage for incoming security reports. Kalkan only suggests; you decide.",
    no_args_is_help=True,
    add_completion=False,
)

ReportArg = Annotated[Path, typer.Argument(help="Report file (.md, .txt or .json).")]
RepoOpt = Annotated[Path, typer.Option("--repo", help="Local git checkout of the project.")]


def _version_callback(value: bool) -> None:
    """Print the version and exit when --version is given."""
    if value:
        typer.echo(f"kalkan {__version__}")
        raise typer.Exit()


def _fail(message: str, code: int = EXIT_BAD_INPUT) -> typer.Exit:
    """Print an error to stderr and return an Exit to raise."""
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(code)


def _read(report_path: Path) -> tuple[Report, SanitizerFindings]:
    """Load and sanitize a report, turning input errors into exit code 2."""
    try:
        return sanitize(load_report(report_path))
    except ReportError as exc:
        raise _fail(str(exc)) from exc


def _open_repo(repo_path: Path) -> RepoIndex:
    """Open a repository, turning errors into exit code 2."""
    try:
        return RepoIndex(repo_path)
    except RepoError as exc:
        raise _fail(str(exc)) from exc


def _clip(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."


def format_checks(checks: list[ClaimCheck], quality: QualitySignals) -> str:
    """Render claim checks and quality signals as a plain-text table."""
    rows = [("STATUS", "KIND", "CLAIM", "EVIDENCE")]
    for c in checks:
        rows.append(
            (
                c.status.value,
                c.claim.kind.value,
                _clip(c.claim.value, 40),
                _clip(c.evidence, 70),
            )
        )
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    lines = [
        f"{r[0]:<{widths[0]}}  {r[1]:<{widths[1]}}  {r[2]:<{widths[2]}}  {r[3]}".rstrip()
        for r in rows
    ]
    if len(rows) == 1:
        lines.append("(no checkable claims found)")
    lines.append("")
    lines.append("Quality signals:")
    flags = [
        ("affected version", quality.has_affected_version),
        ("repro steps", quality.has_repro_steps),
        ("proof of concept", quality.has_poc),
        ("impact", quality.has_impact),
    ]
    for label, value in flags:
        lines.append(f"  [{'x' if value else ' '}] {label}")
    if quality.injection_suspected:
        lines.append("  [!] prompt injection suspected")
    for note in quality.notes:
        lines.append(f"  - {note}")
    return "\n".join(lines)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Kalkan compares a security report with your code and drafts a verdict and a reply."""


@app.command()
def triage(
    report: ReportArg,
    repo: Annotated[Path, typer.Option("--repo", help="Local checkout of the project.")] = Path(),
) -> None:
    """Triage a security report against a local repository."""
    typer.echo("not implemented yet")


@app.command()
def check(report: ReportArg, repo: RepoOpt = Path()) -> None:
    """Check the report's claims against the repository without any AI (the --no-ai core)."""
    loaded, findings = _read(report)
    index = _open_repo(repo)
    claims = extract_claims(loaded)
    try:
        checks = check_claims(claims, index)
    except RepoError as exc:
        raise _fail(str(exc)) from exc
    typer.echo(format_checks(checks, compute_quality(claims, findings)))


@app.command()
def inspect(report: ReportArg) -> None:
    """Show sanitization notes and detected injection phrases for a report."""
    loaded, findings = _read(report)
    typer.echo(f"Report: {loaded.id} ({loaded.source})")
    if loaded.title:
        typer.echo(f"Title: {loaded.title}")
    typer.echo(f"Length: {len(loaded.body)} characters")
    typer.echo("")
    typer.echo("Sanitization notes:")
    for note in loaded.sanitization_notes or ["(none)"]:
        typer.echo(f"  - {note}")
    typer.echo("")
    typer.echo("Injection phrases:")
    for phrase in findings.injection_phrases or ["(none)"]:
        typer.echo(f"  - {phrase}")
    typer.echo("")
    status = "SUSPECTED" if findings.injection_suspected else "not detected"
    typer.echo(f"Prompt injection: {status}")


@app.command()
def schema() -> None:
    """Print the JSON Schema of TriageResult."""
    typer.echo(json.dumps(TriageResult.model_json_schema(), indent=2))
