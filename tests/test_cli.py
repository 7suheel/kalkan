"""Smoke tests for the CLI."""

from typer.testing import CliRunner

from kalkan import __version__
from kalkan.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_schema_prints_triage_result_schema() -> None:
    import json

    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0
    schema = json.loads(result.output)
    assert schema["title"] == "TriageResult"
    assert "verdict" in schema["properties"]
