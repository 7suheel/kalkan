"""Shared helpers for the evaluation harness."""

from __future__ import annotations

import csv
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
DATA_DIR = EVAL_DIR / "data"  # gitignored: raw report text lives here only
MANIFEST = EVAL_DIR / "datasets" / "curl" / "manifest.csv"
RESULTS_DIR = EVAL_DIR / "results"
USER_AGENT = "kalkan-eval/0.1 (+https://github.com/7suheel/kalkan; research on report triage)"


@dataclass(frozen=True)
class ManifestRow:
    """One labeled report. ``ref`` is the commit to check out, e.g. ``<sha>^``; empty = by date."""

    id: str
    url: str
    label: str  # "valid" | "invalid"
    published_at: str
    source: str
    notes: str = ""
    ref: str = ""


FIELDNAMES = [f.name for f in fields(ManifestRow)]
_SAFE_ID_RE = re.compile(r"(?:CVE-\d{4}-\d{4,7}|h1-\d{1,12})")


def report_file(data_dir: Path, row_id: str, suffix: str = ".md") -> Path:
    """Path of a report text inside ``data_dir``; rejects ids that could escape it."""
    if not _SAFE_ID_RE.fullmatch(row_id):
        raise ValueError(f"unexpected report id {row_id!r}")
    return data_dir / f"{row_id}{suffix}"


def read_manifest(path: Path = MANIFEST) -> list[ManifestRow]:
    """Load the manifest CSV."""
    with path.open(newline="", encoding="utf-8") as fh:
        return [
            ManifestRow(**{k: row.get(k, "") or "" for k in FIELDNAMES})
            for row in csv.DictReader(fh)
        ]


def write_manifest(rows: list[ManifestRow], path: Path = MANIFEST) -> None:
    """Write the manifest CSV (sorted by label, then id, for stable diffs)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in sorted(rows, key=lambda r: (r.label, r.id)):
            writer.writerow(asdict(row))
