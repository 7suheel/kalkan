"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from kalkan.checks import RepoIndex, check_claims, compute_quality, extract_claims
from kalkan.context import build_context
from kalkan.ingest import load_report, sanitize
from kalkan.models import (
    ClaimCheck,
    CodeContext,
    QualitySignals,
    Report,
    SanitizerFindings,
)

FIXTURES = Path(__file__).parent / "fixtures"
REPORTS = FIXTURES / "reports"


@pytest.fixture
def reports_dir() -> Path:
    """Directory with small sample reports."""
    return REPORTS


@pytest.fixture
def oversized_report(tmp_path: Path) -> Path:
    """A report larger than the 200 KB cap, generated so we don't commit it."""
    path = tmp_path / "oversized.md"
    path.write_text("# Big report\n\n" + ("A" * 99 + "\n") * 2500, encoding="utf-8")
    return path


TINYHTTP = FIXTURES / "tinyhttp"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def build_tiny_repo(dest: Path) -> Path:
    """Create the tiny C project as a git repo with tags v1.0.0 (older) and v1.2.0 (HEAD).

    v1.0.0 has a shorter src/parser.c without read_body(); v1.2.0 matches the fixture files.
    """
    shutil.copytree(TINYHTTP, dest)
    parser = dest / "src" / "parser.c"
    full = parser.read_text()
    parser.write_text("\n".join(full.splitlines()[:23]) + "\n")
    _git(dest, "init", "-q", "-b", "main")
    _git(dest, "add", "-A")
    _git(dest, "commit", "-q", "-m", "initial parser")
    _git(dest, "tag", "v1.0.0")
    parser.write_text(full)
    _git(dest, "add", "-A")
    _git(dest, "commit", "-q", "-m", "add read_body")
    _git(dest, "tag", "v1.2.0")
    return dest


@pytest.fixture(scope="session")
def tiny_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A tiny C project in a temporary git repository (shared, treat as read-only)."""
    return build_tiny_repo(tmp_path_factory.mktemp("repos") / "tinyhttp")


@dataclass
class Prepared:
    """A report run through the deterministic stages, ready for the agents."""

    report: Report
    findings: SanitizerFindings
    checks: list[ClaimCheck]
    quality: QualitySignals
    ctx: CodeContext


def prepare(report_path: Path, repo: Path) -> Prepared:
    """Load, sanitize, check and build context for a report (no AI)."""
    report, findings = sanitize(load_report(report_path))
    index = RepoIndex(repo)
    claims = extract_claims(report)
    checks = check_claims(claims, index)
    quality = compute_quality(claims, findings)
    ctx = build_context(report, checks, index)
    return Prepared(report, findings, checks, quality, ctx)


@pytest.fixture
def write_report(tmp_path: Path) -> Callable[[str, str], Path]:
    """Write a report file into a temp dir and return its path."""

    def _write(body: str, name: str = "report.md") -> Path:
        path = tmp_path / name
        path.write_text(body, encoding="utf-8")
        return path

    return _write
