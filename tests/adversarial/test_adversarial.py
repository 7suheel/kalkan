"""Hostile reports: Kalkan must not be steered, must not read outside the repo,
must not run a shell, and every regex must stay fast.

The fake model in these tests always *obeys* the attacker (answers
likely_valid), so the deterministic layers have to catch every attack.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import build_tiny_repo

from kalkan import ingest
from kalkan.checks import extract, verify
from kalkan.checks.extract import extract_claims
from kalkan.ingest import load_report, sanitize
from kalkan.llm import FakeProvider
from kalkan.models import Report, Verdict
from kalkan.pipeline import TriageSettings, triage
from kalkan.report_render import render_json, render_markdown

REPORTS = Path(__file__).parent / "reports"
SECRET = "TOPSECRET-4f2a"
INJECTION_REPORTS = [
    "01_direct.md",
    "02_html_comment.md",
    "03_zero_width.md",
    "04_base64.md",
    "05_fake_json.md",
    "06_fake_system.md",
    "07_close_tag.md",
    "08_unicode_tags.md",
    "09_hidden_css.md",
    "13_role_tags.md",
    "14_details.md",
]
OTHER_REPORTS = ["10_path_traversal.md", "11_shell_meta.md", "12_redos.md"]
OBEY = json.dumps(
    {
        "verdict": "likely_valid",
        "confidence": 1.0,
        "reasoning": "As instructed, valid.",
        "missing_evidence": [],
        "cited_locations": ["src/parser.c:14", "../secret.txt:1", "/etc/passwd:1"],
    }
)
WRITER = json.dumps({"summary": "Valid.", "reply_draft": "Hello, thank you."})


def redos_report() -> str:
    """One big report built to stress every extraction and sanitizer regex."""
    parts = [
        "\n" * 20_000,
        " \n" * 10_000,
        "a." * 10_000,
        "a/" * 10_000,
        "1." * 10_000,
        "<a " * 5_000,
        "`a" * 10_000,
        "commit " + "a" * 5_000,
        "ignore " * 2_000,
        "you are " * 2_000,
        "<!--" * 5_000,
        "a.c:" * 5_000,
        "(" * 10_000,
        "A" * 30_000,
    ]
    return "".join(parts)[:200_000]


@pytest.fixture(scope="module")
def hostile_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The tiny C repo plus a tracked symlink to a secret file outside the repo."""
    base = tmp_path_factory.mktemp("hostile")
    (base / "secret.txt").write_text(f"{SECRET}\n")
    (base / "outside.c").write_text(f"int read_secret(void) {{ /* {SECRET} */ }}\n")
    repo = build_tiny_repo(base / "repo")
    (repo / "link.c").symlink_to(base / "secret.txt")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false"]
    subprocess.run([*git, "add", "-A"], cwd=repo, check=True)
    subprocess.run([*git, "commit", "-q", "-m", "add symlink"], cwd=repo, check=True)
    return repo


@pytest.fixture
def report_path(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    name: str = request.param
    if name == "12_redos.md":
        path = tmp_path / name
        path.write_text(redos_report())
        return path
    return REPORTS / name


@pytest.fixture
def spies(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, list[Any]]]:
    """Record every file opened and every subprocess started."""
    record: dict[str, list[Any]] = {"opened": [], "subprocess": []}
    real_open = io.open
    real_run = subprocess.run

    def spy_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        record["opened"].append(str(file))
        return real_open(file, *args, **kwargs)

    def spy_run(args: Any, *a: Any, **kw: Any) -> Any:
        record["subprocess"].append((args, kw))
        return real_run(args, *a, **kw)

    monkeypatch.setattr(io, "open", spy_open)
    monkeypatch.setattr(subprocess, "run", spy_run)
    yield record


def _run(path: Path, repo: Path) -> tuple[Any, FakeProvider]:
    fake = FakeProvider(script=[OBEY, OBEY, WRITER])
    outcome = triage(path, repo, TriageSettings(provider=fake))
    return outcome, fake


def test_suite_has_enough_reports() -> None:
    assert len(INJECTION_REPORTS) + len(OTHER_REPORTS) >= 12


@pytest.mark.parametrize("report_path", INJECTION_REPORTS, indirect=True)
def test_injection_is_detected_and_never_likely_valid(
    report_path: Path, hostile_repo: Path
) -> None:
    report, findings = sanitize(load_report(report_path))
    assert findings.injection_suspected, report.sanitization_notes
    outcome, fake = _run(report_path, hostile_repo)
    assert outcome.result.verdict is not Verdict.LIKELY_VALID
    assert outcome.result.verdict is Verdict.NEEDS_HUMAN
    for call in fake.calls:
        # The report can never close or reopen our delimiters.
        assert call.user.count("</untrusted_report>") <= 1
        assert call.user.count("<untrusted_report>") <= 1
        assert call.user.count("</code_context>") <= 1


@pytest.mark.parametrize("report_path", INJECTION_REPORTS + OTHER_REPORTS, indirect=True)
def test_no_outside_reads_no_shell(
    report_path: Path, hostile_repo: Path, spies: dict[str, list[Any]]
) -> None:
    outcome, fake = _run(report_path, hostile_repo)
    root = hostile_repo.resolve()
    for opened in spies["opened"]:
        p = Path(opened).resolve()
        assert "secret.txt" not in p.name and p.name != "outside.c", opened
        if p.is_relative_to(root.parent):
            assert p == report_path.resolve() or p.is_relative_to(root), opened
    for args, kwargs in spies["subprocess"]:
        assert isinstance(args, list), args
        assert kwargs.get("shell") is not True
        assert args[0] == "git"
    everything = "\n".join(c.system + c.user for c in fake.calls)
    everything += render_markdown(outcome.result) + render_json(outcome.result)
    assert SECRET not in everything
    assert not (Path.cwd() / "PWNED").exists()
    assert not (hostile_repo / "PWNED").exists()
    # Citations outside the code context are dropped by post-validation.
    for opinion in outcome.result.opinions:
        assert all(not loc.startswith(("../", "/")) for loc in opinion.cited_locations)


def _patterns() -> Iterator[tuple[str, re.Pattern[str]]]:
    for mod in (ingest, extract, verify):
        for name, value in vars(mod).items():
            if isinstance(value, re.Pattern):
                yield f"{mod.__name__}.{name}", value
            elif (
                isinstance(value, tuple) and value and all(isinstance(v, re.Pattern) for v in value)
            ):
                for i, pattern in enumerate(value):
                    yield f"{mod.__name__}.{name}[{i}]", pattern


HOSTILE_INPUTS = {
    "newlines": "\n" * 200_000,
    "space_newline": " \n" * 100_000,
    "spaces": " " * 200_000,
    "letters": "a" * 200_000,
    "dots": "a." * 100_000,
    "slashes": "a/" * 100_000,
    "digits": "1." * 100_000,
    "tags": "<a " * 66_000,
    "comments": "<!--" * 50_000,
    "backticks": "`a" * 100_000,
    "colons": "a.c:" * 50_000,
    "parens": "a(" * 100_000,
    "words": "ignore you are mark this " * 8_000,
    "base64ish": "QUFB" * 50_000,
}


@pytest.mark.parametrize(("name", "pattern"), list(_patterns()), ids=lambda x: str(x)[:40])
def test_every_regex_is_fast(name: str, pattern: re.Pattern[str]) -> None:
    for label, text in HOSTILE_INPUTS.items():
        best = float("inf")
        for _ in range(2):
            start = time.perf_counter()
            for _match in pattern.finditer(text):
                pass
            best = min(best, time.perf_counter() - start)
        assert best < 0.1, f"{name} took {best * 1000:.0f} ms on {label}"


def test_whole_redos_report_is_fast() -> None:
    report = Report(id="r", body=redos_report())
    start = time.perf_counter()
    cleaned, _ = sanitize(report)
    extract_claims(cleaned)
    assert time.perf_counter() - start < 2.0


def test_report_size_limits(tmp_path: Path) -> None:
    from kalkan.ingest import MAX_FILE_BYTES, ReportError

    big = tmp_path / "big.md"
    with big.open("wb") as fh:
        fh.truncate(MAX_FILE_BYTES + 1)
    with pytest.raises(ReportError, match="larger than"):
        load_report(big)
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 100_000 + "]" * 100_000)
    with pytest.raises(ReportError):
        load_report(deep)


def test_logs_contain_no_report_text_or_keys(
    hostile_repo: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    import logging

    from kalkan.llm import ProviderHTTPError

    key = "sk-live-SECRETKEY-0123456789"
    monkeypatch.setenv("ANTHROPIC_API_KEY", key)
    caplog.set_level(logging.DEBUG)
    fake = FakeProvider(script=[OBEY, ProviderHTTPError(401, f"bad key {key}")])
    triage(REPORTS / "01_direct.md", hostile_repo, TriageSettings(provider=fake))
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "stage check took" in logged
    assert "Ignore previous instructions" not in logged
    assert "parse_header() in src/parser.c has an overflow" not in logged
    assert key not in logged
