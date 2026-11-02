"""Typer command-line interface for Kalkan."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from kalkan import __version__

app = typer.Typer(
    name="kalkan",
    help="AI-assisted triage for incoming security reports. Kalkan only suggests; you decide.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    """Print the version and exit when --version is given."""
    if value:
        typer.echo(f"kalkan {__version__}")
        raise typer.Exit()


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
    report: Annotated[Path, typer.Argument(help="Report file (.md, .txt or .json).")],
    repo: Annotated[Path, typer.Option("--repo", help="Local checkout of the project.")] = Path(),
) -> None:
    """Triage a security report against a local repository."""
    typer.echo("not implemented yet")


@app.command()
def schema() -> None:
    """Print the JSON Schema of TriageResult."""
    import json

    from kalkan.models import TriageResult

    typer.echo(json.dumps(TriageResult.model_json_schema(), indent=2))
