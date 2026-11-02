"""Smoke tests for the CLI."""

from typer.testing import CliRunner

from kalkan import __version__
from kalkan.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
