"""Tests for the evaluation harness (no network: MockTransport and the tiny C repo)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import httpx
from conftest import FIXTURES

from eval.build_manifest import parse_gist, parse_vuln_json
from eval.common import ManifestRow, read_manifest, write_manifest
from eval.fetch import cve_report, fetch_all
from eval.run import Record, compute_metrics, render_results, run, select_rows
from kalkan.pipeline import TriageSettings

EVAL_FIXTURES = FIXTURES / "eval"


def test_parse_gist_markdown_and_html() -> None:
    rows = parse_gist((EVAL_FIXTURES / "gist.md").read_text())
    assert [r.id for r in rows] == ["h1-1000001", "h1-1000002"]
    assert rows[0].label == "invalid"
    assert rows[0].notes == "Buffer overflow in made_up_function"
    html_rows = parse_gist((EVAL_FIXTURES / "gist.html").read_text())
    assert html_rows[0].id == "h1-1000003"
    assert html_rows[0].notes == "Title & three"


def test_parse_vuln_json() -> None:
    rows = parse_vuln_json(json.loads((EVAL_FIXTURES / "vuln.json").read_text()))
    assert [r.id for r in rows] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert rows[0].label == "valid"
    assert rows[0].url == "https://curl.se/docs/CVE-2099-0001.html"
    assert rows[1].url == "https://curl.se/docs/CVE-2099-0002.html"
    assert rows[0].published_at.startswith("2099-01-01")
    assert rows[0].ref == ""  # "FIXSHA" is not a hex commit, so no ref


def test_manifest_round_trip(tmp_path: Path) -> None:
    rows = [
        ManifestRow("CVE-1", "u", "valid", "2020", "s", "n", "abc1234^"),
        ManifestRow("h1-1", "u", "invalid", "", "s"),
    ]
    path = tmp_path / "m.csv"
    write_manifest(rows, path)
    assert read_manifest(path) == sorted(rows, key=lambda r: (r.label, r.id))


def test_unexpected_ids_are_rejected() -> None:
    import pytest

    from eval.common import report_file

    rows = parse_vuln_json([{"id": "CURL-x", "aliases": ["CVE-../../etc/x"], "summary": ""}])
    assert rows == []
    with pytest.raises(ValueError):
        report_file(Path("/tmp"), "../x")


def test_cve_report_text() -> None:
    record = json.loads((EVAL_FIXTURES / "vuln.json").read_text())[0]
    text = cve_report(record)
    assert text.startswith("# made-up overflow for tests")
    assert "introduced in curl 1.0.0, fixed in curl 1.3.0" in text
    assert "parse_header()" in text


def test_fetch_all(tmp_path: Path) -> None:
    shutil.copy(EVAL_FIXTURES / "vuln.json", tmp_path / "vuln.json")
    (tmp_path / "h1-1000002.md").write_text("saved by hand")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path.endswith("1000001.json"):
            return httpx.Response(
                200,
                json={
                    "title": "T",
                    "vulnerability_information": "Body",
                    "submitted_at": "2024-05-01T00:00:00Z",
                },
            )
        return httpx.Response(404)

    rows = parse_gist((EVAL_FIXTURES / "gist.md").read_text()) + parse_gist(
        (EVAL_FIXTURES / "gist.html").read_text()
    )
    rows += parse_vuln_json(json.loads((EVAL_FIXTURES / "vuln.json").read_text()))
    client = httpx.Client(transport=httpx.MockTransport(handler), headers={"User-Agent": "t"})
    sleeps: list[float] = []
    written, failures = fetch_all(rows, tmp_path, client, sleep=sleeps.append)
    assert written == 3  # one H1 report and two CVEs
    assert failures == ["h1-1000003: HTTPStatusError"]
    assert (tmp_path / "h1-1000001.md").read_text() == "# T\n\nBody\n"
    meta = json.loads((tmp_path / "h1-1000001.meta.json").read_text())
    assert meta["submitted_at"] == "2024-05-01T00:00:00Z"
    assert (tmp_path / "h1-1000002.md").read_text() == "saved by hand"
    assert len(calls) == 2
    assert sleeps and all(s <= 2.0 for s in sleeps)


def test_select_rows_balances(tmp_path: Path) -> None:
    rows = [ManifestRow(f"h1-{n}", "u", "invalid", "", "s") for n in range(5)]
    rows += [ManifestRow(f"CVE-2020-000{n}", "u", "valid", "", "s") for n in range(5)]
    rows.append(ManifestRow("../../evil", "u", "valid", "", "s"))
    for r in rows[:-1]:
        (tmp_path / f"{r.id}.md").write_text("x")
    picked = select_rows(rows, tmp_path, 4)
    assert [r.id for r in picked] == ["h1-0", "CVE-2020-0000", "h1-1", "CVE-2020-0001"]
    assert len(select_rows(rows, tmp_path, 0)) == 10


def test_compute_metrics() -> None:
    records = [
        Record("i1", "invalid", "m", "likely_invalid", 0.8, 100, 1.0, "c"),
        Record("i2", "invalid", "m", "needs_human", 0.5, 100, 1.0, "c"),
        Record("v1", "valid", "m", "likely_invalid", 0.6, 100, 1.0, "c"),
        Record("v2", "valid", "m", "likely_valid", 0.6, 100, 3.0, "c"),
        Record("v3", "valid", "m", "", 0.0, 0, 0.0, "c", "boom"),
    ]
    m = compute_metrics(records)
    assert m["invalid_flagged"] == 1 and m["invalid_total"] == 2
    assert m["valid_wrongly_invalid_ids"] == ["v1"]
    assert m["valid_wrongly_invalid_rate"] == 0.5
    assert m["errors"] == 1
    assert m["needs_human_rate"] == 0.25
    assert m["avg_seconds"] == 1.5
    md = render_results(
        {"date": "d", "model": "m", "kalkan_version": "v", "reports": 5, "manifest": "x"},
        {"no-ai": records},
    )
    assert "- v1" in md and "| no-ai | 1/2 (50%)" in md


def test_run_checks_out_the_right_commit(tiny_repo: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(tiny_repo, repo)
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    data = tmp_path / "data"
    data.mkdir()
    (data / "CVE-2020-1111.md").write_text(
        "# Overflow\n\nIn version 1.0.0, parse_header() in src/parser.c:14 uses strcpy.\n"
    )
    (data / "h1-1.md").write_text("# Bug in fake_func()\n\nfake_func() in lib/nope.c is broken.\n")
    rows = [
        ManifestRow("CVE-2020-1111", "u", "valid", "", "s", "", f"{head}^"),
        ManifestRow("h1-1", "u", "invalid", "2000-01-01T00:00:00Z", "s"),
    ]
    by_mode = run(rows, repo, {"no-ai": TriageSettings()}, data)
    records = by_mode["no-ai"]
    assert [r.id for r in records] == ["CVE-2020-1111", "h1-1"]
    parent = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{head}^"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert records[0].commit == parent
    assert records[0].verdict != "likely_invalid"
    assert records[1].verdict == "needs_human"  # fabricated claims, no AI to confirm
    worktrees = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list"], capture_output=True, text=True, check=True
    ).stdout
    assert worktrees.count("\n") == 1  # temporary worktree was removed
