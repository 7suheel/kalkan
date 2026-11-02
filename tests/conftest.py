"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

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
