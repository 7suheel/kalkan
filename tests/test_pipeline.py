"""End-to-end tests: FakeProvider + tiny C fixture, through the pipeline and the CLI."""

from __future__ import annotations

import json
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from test_analyst import HOSTILE
from typer.testing import CliRunner

from kalkan.cli import app
from kalkan.llm import BudgetExceeded, FakeProvider, ProviderHTTPError
from kalkan.models import TriageResult, Verdict
from kalkan.pipeline import TriageSettings, triage

runner = CliRunner()

HALLUCINATED = """# Heap overflow in curl_url_parse_strict()

The function curl_url_parse_strict() in lib/urlapi.c at line 9999
copies the host name without a length check, which allows remote code
execution. Severity: critical.
"""


def opinion(verdict: str, confidence: float = 0.8, cited: list[str] | None = None) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": f"I think {verdict}.",
            "missing_evidence": [],
            "cited_locations": cited or [],
        }
    )


WRITER = json.dumps({"summary": "Short summary.", "reply_draft": "Hello, thank you."})


def fake(*answers: str | Exception) -> FakeProvider:
    return FakeProvider(script=list(answers))


def test_valid_report(tiny_repo: Path, reports_dir: Path) -> None:
    provider = fake(
        opinion("likely_valid", 0.9, ["src/parser.c:14"]),
        opinion("likely_valid", 0.7, ["src/parser.c:14"]),
        WRITER,
    )
    outcome = triage(
        reports_dir / "clean.md", tiny_repo, TriageSettings(provider=provider, model_label="fake")
    )
    result = outcome.result
    assert result.verdict is Verdict.LIKELY_VALID
    assert result.confidence == 0.7
    assert result.summary == "Short summary."
    assert [o.agent for o in result.opinions] == ["analyst", "skeptic"]
    assert result.tokens_used == 300
    assert result.model == "fake"
    assert outcome.ai_error is None


def test_hallucinated_report(tiny_repo: Path, write_report: Callable[[str, str], Path]) -> None:
    provider = fake(opinion("likely_invalid", 0.8), opinion("likely_invalid", 0.6), WRITER)
    result = triage(
        write_report(HALLUCINATED, "fake.md"), tiny_repo, TriageSettings(provider=provider)
    ).result
    assert result.verdict is Verdict.LIKELY_INVALID
    # No citations were possible, so the post-validation cap applies.
    assert result.confidence == 0.5


def test_vague_report(tiny_repo: Path, reports_dir: Path) -> None:
    provider = fake(opinion("needs_evidence", 0.6), opinion("needs_evidence", 0.5), WRITER)
    result = triage(reports_dir / "vague.txt", tiny_repo, TriageSettings(provider=provider)).result
    assert result.verdict is Verdict.NEEDS_EVIDENCE


def test_injection_report(tiny_repo: Path, write_report: Callable[[str, str], Path]) -> None:
    provider = fake(
        opinion("likely_valid", 1.0, ["src/parser.c:14"]),
        opinion("likely_valid", 1.0, ["src/parser.c:14"]),
        WRITER,
    )
    result = triage(
        write_report(HOSTILE, "hostile.md"), tiny_repo, TriageSettings(provider=provider)
    ).result
    assert result.verdict is Verdict.NEEDS_HUMAN
    assert result.quality.injection_suspected


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        ("clean.md", Verdict.NEEDS_HUMAN),
        ("vague.txt", Verdict.NEEDS_EVIDENCE),
        ("simple.json", Verdict.NEEDS_HUMAN),
    ],
)
def test_no_ai_mode(tiny_repo: Path, reports_dir: Path, report: str, expected: Verdict) -> None:
    outcome = triage(reports_dir / report, tiny_repo, TriageSettings())
    assert outcome.result.verdict is expected
    assert outcome.result.opinions == []
    assert outcome.result.tokens_used == 0
    assert outcome.result.model is None
    assert outcome.result.reply_draft.startswith("Hello,")


def test_no_ai_hallucinated(tiny_repo: Path, write_report: Callable[[str, str], Path]) -> None:
    result = triage(write_report(HALLUCINATED, "fake.md"), tiny_repo).result
    assert result.verdict in (Verdict.LIKELY_INVALID, Verdict.NEEDS_HUMAN)
    assert "None of the named code exists" in result.summary


def test_provider_failure_keeps_deterministic_results(tiny_repo: Path, reports_dir: Path) -> None:
    provider = fake(
        opinion("likely_valid", 0.9, ["src/parser.c:14"]), ProviderHTTPError(500, "down")
    )
    outcome = triage(reports_dir / "clean.md", tiny_repo, TriageSettings(provider=provider))
    assert outcome.ai_error is not None and "HTTP 500" in outcome.ai_error
    result = outcome.result
    assert result.verdict is Verdict.NEEDS_HUMAN
    assert result.claim_checks
    assert result.summary.startswith("AI review did not finish")
    assert result.reply_draft.startswith("Hello,")  # template reply


def test_budget_runs_out(tiny_repo: Path, reports_dir: Path) -> None:
    provider = fake(opinion("likely_valid", 0.9, ["src/parser.c:14"]), WRITER, WRITER)
    provider.tokens_per_call = 5000
    outcome = triage(
        reports_dir / "clean.md", tiny_repo, TriageSettings(provider=provider, max_tokens=1000)
    )
    assert outcome.ai_error is not None and BudgetExceeded.__name__ in outcome.ai_error
    assert outcome.result.verdict is Verdict.NEEDS_HUMAN
    assert len(provider.calls) == 1


# ----- CLI --------------------------------------------------------------------------------------


def test_cli_triage_no_ai_markdown(tiny_repo: Path, reports_dir: Path) -> None:
    result = runner.invoke(
        app, ["triage", str(reports_dir / "clean.md"), "--repo", str(tiny_repo), "--no-ai"]
    )
    assert result.exit_code == 0, result.output
    assert "AI off (--no-ai)" in result.output
    assert "# Kalkan triage: clean" in result.output
    assert "## Reply draft" in result.output


def test_cli_triage_json_to_file(tiny_repo: Path, reports_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out" / "result.json"
    result = runner.invoke(
        app,
        [
            "triage",
            str(reports_dir / "vague.txt"),
            "--repo",
            str(tiny_repo),
            "--no-ai",
            "--format",
            "json",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = TriageResult.model_validate_json(out.read_text())
    assert parsed.verdict is Verdict.NEEDS_EVIDENCE
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_cli_triage_without_model_says_ai_off(
    tiny_repo: Path, reports_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("KALKAN_MODEL", raising=False)
    result = runner.invoke(app, ["triage", str(reports_dir / "clean.md"), "--repo", str(tiny_repo)])
    assert result.exit_code == 0
    assert "AI off" in result.output


def test_cli_triage_with_fake_ai(
    tiny_repo: Path, reports_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = fake(
        opinion("likely_valid", 0.9, ["src/parser.c:14"]),
        opinion("likely_valid", 0.8, ["src/parser.c:14"]),
        WRITER,
    )
    monkeypatch.setattr("kalkan.cli.build_provider", lambda settings: provider)
    result = runner.invoke(
        app,
        ["triage", str(reports_dir / "clean.md"), "--repo", str(tiny_repo), "--model", "ollama:x"],
    )
    assert result.exit_code == 0, result.output
    assert "AI on: the report will be sent to ollama:x" in result.output
    assert "LIKELY_VALID" in result.output


def test_cli_triage_provider_error_exit_3(
    tiny_repo: Path, reports_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = fake(ProviderHTTPError(503, "overloaded"))
    monkeypatch.setattr("kalkan.cli.build_provider", lambda settings: provider)
    result = runner.invoke(
        app,
        ["triage", str(reports_dir / "clean.md"), "--repo", str(tiny_repo), "--model", "ollama:x"],
    )
    assert result.exit_code == 3
    assert "# Kalkan triage: clean" in result.output  # partial output still written


@pytest.mark.parametrize(
    "args",
    [
        ["triage", "missing.md", "--no-ai"],
        ["triage", "REPORT", "--repo", "/nonexistent", "--no-ai"],
        ["triage", "REPORT", "--model", "bogus"],
    ],
)
def test_cli_triage_bad_input_exit_2(tiny_repo: Path, reports_dir: Path, args: list[str]) -> None:
    args = [str(reports_dir / "clean.md") if a == "REPORT" else a for a in args]
    if "--repo" not in args:
        args += ["--repo", str(tiny_repo)]
    result = runner.invoke(app, args)
    assert result.exit_code == 2


def test_cli_triage_dir(tiny_repo: Path, reports_dir: Path, tmp_path: Path) -> None:
    folder = tmp_path / "reports"
    folder.mkdir()
    for name in ("clean.md", "vague.txt", "advisory.json"):
        (folder / name).write_bytes((reports_dir / name).read_bytes())
    (folder / "broken.json").write_text("not json")
    result = runner.invoke(app, ["triage-dir", str(folder), "--repo", str(tiny_repo), "--no-ai"])
    assert result.exit_code == 2  # one bad input, others still processed
    out = folder / "kalkan-results"
    assert sorted(p.name for p in out.iterdir()) == [
        "advisory.md",
        "clean.md",
        "index.md",
        "vague.md",
    ]
    index = (out / "index.md").read_text()
    assert "| clean.md | needs_human |" in index
    assert "| vague.txt | needs_evidence |" in index
    assert "| broken.json | error |" in index
