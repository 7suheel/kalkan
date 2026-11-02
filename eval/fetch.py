"""Download report texts into eval/data/ (gitignored).

- invalid rows: the public HackerOne report JSON (title, text, dates);
- valid rows: the CVE advisory text from the local copy of vuln.json.

At most one request every 2 seconds, with a clear User-Agent. Failures are
logged and skipped. Files you save by hand as eval/data/<id>.md are kept.

Usage: uv run python -m eval.fetch [--limit N]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from eval.common import DATA_DIR, MANIFEST, USER_AGENT, ManifestRow, read_manifest, report_file

MIN_INTERVAL_S = 2.0


def cve_report(record: dict[str, Any]) -> str:
    """Turn one OSV record into a report-like Markdown text."""
    lines = [f"# {record.get('summary', '').strip()}", ""]
    versions: list[str] = []
    for affected in record.get("affected") or []:
        for rng in affected.get("ranges") or []:
            if rng.get("type") == "SEMVER":
                events = {k: v for e in rng.get("events") or [] for k, v in e.items()}
                if events:
                    versions.append(
                        f"introduced in curl {events.get('introduced', '?')}, "
                        f"fixed in curl {events.get('fixed', '?')}"
                    )
    if versions:
        lines += [f"Affected versions: {'; '.join(versions)}.", ""]
    lines.append(str(record.get("details", "")).strip())
    return "\n".join(lines).strip() + "\n"


def h1_report(data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Turn a HackerOne report JSON into (Markdown text, metadata)."""
    title = str(data.get("title") or "").strip()
    body = str(data.get("vulnerability_information") or "").strip()
    meta = {
        "submitted_at": data.get("submitted_at") or data.get("created_at") or "",
        "disclosed_at": data.get("disclosed_at") or "",
    }
    return f"# {title}\n\n{body}\n", meta


def fetch_all(
    rows: list[ManifestRow],
    data_dir: Path = DATA_DIR,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[int, list[str]]:
    """Fetch missing report texts. Returns (number written, list of failures)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    vuln_path = data_dir / "vuln.json"
    vuln: dict[str, dict[str, Any]] = {}
    if vuln_path.exists():
        for record in json.loads(vuln_path.read_text(encoding="utf-8")):
            for alias in record.get("aliases") or []:
                vuln[str(alias)] = record
    client = client or httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=30)
    written, failures = 0, []
    last = 0.0
    for row in rows:
        try:
            target = report_file(data_dir, row.id)
        except ValueError as exc:
            failures.append(str(exc))
            continue
        if target.exists():
            continue
        if row.label == "valid":
            record = vuln.get(row.id)
            if record is None:
                failures.append(f"{row.id}: not in local vuln.json (run eval.build_manifest)")
                continue
            target.write_text(cve_report(record), encoding="utf-8")
            written += 1
            continue
        wait = MIN_INTERVAL_S - (time.monotonic() - last)
        if wait > 0:
            sleep(wait)
        last = time.monotonic()
        try:
            response = client.get(f"{row.url}.json", headers={"Accept": "application/json"})
            response.raise_for_status()
            text, meta = h1_report(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            failures.append(f"{row.id}: {type(exc).__name__}")
            continue
        target.write_text(text, encoding="utf-8")
        (report_file(data_dir, row.id, ".meta.json")).write_text(json.dumps(meta), encoding="utf-8")
        written += 1
    return written, failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download eval report texts into eval/data/.")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args(argv)
    rows = read_manifest(args.manifest)
    if args.limit:
        rows = rows[: args.limit]
    written, failures = fetch_all(rows)
    print(f"wrote {written} report(s) to {DATA_DIR}")
    for failure in failures:
        print(f"skipped {failure}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
