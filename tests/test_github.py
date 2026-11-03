"""Tests for fetching private reports from GitHub (MockTransport, no network)."""

from __future__ import annotations

import copy
import json
import stat
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import FIXTURES
from typer.testing import CliRunner

from kalkan.cli import app
from kalkan.github import GitHubError, fetch_advisories, get_token, save_reports
from kalkan.ingest import load_report

SAMPLE: list[dict[str, Any]] = json.loads((FIXTURES / "github" / "advisories.json").read_text())
runner = CliRunner()


def _second() -> dict[str, Any]:
    item = copy.deepcopy(SAMPLE[0])
    item["ghsa_id"] = "GHSA-2345-6789-cfgh"
    item["summary"] = "Second report"
    return item


def test_pagination_and_headers() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "after=CURSOR" in str(request.url):
            return httpx.Response(200, json=[_second()])
        next_url = "https://api.github.com/repos/octo/tinyhttp/security-advisories?after=CURSOR"
        return httpx.Response(200, json=SAMPLE, headers={"link": f'<{next_url}>; rel="next"'})

    items = fetch_advisories("octo/tinyhttp", "tok", transport=httpx.MockTransport(handler))
    assert [i["ghsa_id"] for i in items] == ["GHSA-cfgh-2345-wxqr", "GHSA-2345-6789-cfgh"]
    first = seen[0]
    assert first.url.path == "/repos/octo/tinyhttp/security-advisories"
    assert first.url.params["state"] == "triage"
    assert first.url.params["per_page"] == "100"
    assert first.headers["authorization"] == "Bearer tok"
    assert first.headers["x-github-api-version"] == "2026-03-10"


# Required properties of the `repository-advisory` schema in GitHub's OpenAPI
# description for REST API version 2026-03-10 (github/rest-api-description).
REQUIRED_2026_03_10 = {
    "ghsa_id", "cve_id", "url", "html_url", "summary", "description", "severity", "author",
    "publisher", "identifiers", "state", "created_at", "updated_at", "published_at",
    "closed_at", "withdrawn_at", "submission", "vulnerabilities", "cwes", "cwe_ids",
    "credits", "credits_detailed", "collaborating_users", "collaborating_teams",
    "private_fork",
}  # fmt: skip


def test_sample_matches_current_schema() -> None:
    assert set(SAMPLE[0]) >= REQUIRED_2026_03_10
    assert "cvss" not in SAMPLE[0]  # removed in 2026-03-10; Kalkan never reads it


@pytest.mark.parametrize("state", ["triage", "draft", "published", "closed"])
def test_every_documented_state(state: str) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=[])

    assert fetch_advisories("octo/tinyhttp", "tok", state, httpx.MockTransport(handler)) == []
    assert seen[0].url.params["state"] == state


def test_unknown_state_is_rejected_before_any_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    with pytest.raises(GitHubError, match="state must be one of"):
        fetch_advisories("octo/tinyhttp", "tok", "withdrawn", httpx.MockTransport(handler))


def test_refuses_pagination_to_other_hosts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json=SAMPLE, headers={"link": '<https://evil.example/steal>; rel="next"'}
        )

    with pytest.raises(GitHubError, match="another host"):
        fetch_advisories("octo/tinyhttp", "tok", transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(("status", "message"), [(401, "cannot read"), (404, "not found")])
def test_http_errors(status: int, message: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"message": "nope"})

    with pytest.raises(GitHubError, match=message):
        fetch_advisories("octo/tinyhttp", "tok", transport=httpx.MockTransport(handler))


@pytest.mark.parametrize("repo", ["octo", "../x/y", "a/b/c", "octo/x y"])
def test_bad_repo_names(repo: str) -> None:
    with pytest.raises(GitHubError):
        fetch_advisories(repo, "tok", transport=httpx.MockTransport(lambda r: httpx.Response(200)))


def test_token_sources() -> None:
    assert get_token({"GH_TOKEN": "a", "GITHUB_TOKEN": "b"}) == "a"
    assert get_token({"GITHUB_TOKEN": "b"}) == "b"

    def fake_gh(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert args == ["gh", "auth", "token"]
        return subprocess.CompletedProcess(args, 0, stdout="gho_x\n", stderr="")

    assert get_token({}, run=fake_gh) == "gho_x"

    def no_gh(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError

    with pytest.raises(GitHubError, match="GH_TOKEN"):
        get_token({}, run=no_gh)


def test_save_reports_private_and_loadable(tmp_path: Path) -> None:
    bad = copy.deepcopy(SAMPLE[0])
    bad["ghsa_id"] = "../../etc/passwd"
    out = tmp_path / "reports"
    written = save_reports([*SAMPLE, bad], out)
    assert [p.name for p in written] == ["GHSA-cfgh-2345-wxqr.json"]
    assert stat.S_IMODE(written[0].stat().st_mode) == 0o600
    data = json.loads(written[0].read_text())
    assert data["reporter"] == "reporter1"
    assert data["severity"] == "high"
    assert data["private_report"] is True  # the sample has a `submission` object
    report = load_report(written[0])
    assert report.id == "GHSA-cfgh-2345-wxqr"
    assert report.title == "Heap overflow in parse_header()"
    assert report.source == "github_advisory"


def test_published_advisory_is_not_a_private_report(tmp_path: Path) -> None:
    item = copy.deepcopy(SAMPLE[0])
    item["submission"] = None
    item["state"] = "published"
    written = save_reports([item], tmp_path)
    assert json.loads(written[0].read_text())["private_report"] is False


def test_fetch_command_rejects_unknown_state(tmp_path: Path) -> None:
    result = runner.invoke(app, ["fetch", "--repo", "a/b", "--state", "nope"])
    assert result.exit_code == 2
    assert "choose one of" in result.output


def test_fetch_command_then_triage_dir(
    tmp_path: Path, tiny_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SAMPLE)

    real_client = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setenv("GH_TOKEN", "tok")
    monkeypatch.setattr("kalkan.github.httpx.Client", client)
    out = tmp_path / "reports"
    result = runner.invoke(app, ["fetch", "--repo", "octo/tinyhttp", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "these reports are private" in result.output
    assert "tok" not in result.output
    assert (out / "GHSA-cfgh-2345-wxqr.json").exists()

    result = runner.invoke(app, ["triage-dir", str(out), "--repo", str(tiny_repo), "--no-ai"])
    assert result.exit_code == 0, result.output
    assert "GHSA-cfgh-2345-wxqr.json" in (out / "kalkan-results" / "index.md").read_text()
