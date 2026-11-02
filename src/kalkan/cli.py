"""Typer command-line interface for Kalkan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from kalkan import __version__
from kalkan.ingest import ReportError, load_report, sanitize
from kalkan.models import Report, SanitizerFindings, TriageResult

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
