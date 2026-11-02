"""Download private vulnerability reports from GitHub for local triage.

Endpoint: ``GET /repos/{owner}/{repo}/security-advisories`` (REST API version
2022-11-28) with ``state`` (triage, draft, published, closed) and
``per_page`` (max 100); pagination follows the ``Link: rel="next"`` header.
The token needs the fine-grained "Repository security advisories" read
permission (classic tokens: ``repo`` or ``repository_advisories:read``), and
the user must be an admin or security manager of the repository.

These reports are private. Kalkan saves them locally with 0600 permissions
and never uploads them anywhere.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

API_HOST = "api.github.com"
API_VERSION = "2022-11-28"
MAX_PAGES = 50
_REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_GHSA_RE = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")
_NEXT_RE = re.compile(r'<([^>]{1,2000})>\s*;\s*rel="next"')
PRIVACY_WARNING = (
    "warning: these reports are private. Never commit this folder and never run Kalkan on "
    "them in public CI: Actions logs of public repositories are visible to everyone."
)


class GitHubError(RuntimeError):
    """Fetching from GitHub failed."""


def get_token(
    env: Mapping[str, str] | None = None,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    """Token from GH_TOKEN / GITHUB_TOKEN, else from ``gh auth token``."""
    env = os.environ if env is None else env
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        if env.get(name):
            return env[name]
    try:
        proc = run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise GitHubError("no token: set GH_TOKEN or log in with `gh auth login`") from exc
    token = proc.stdout.strip()
    if proc.returncode != 0 or not token:
        raise GitHubError("no token: set GH_TOKEN or log in with `gh auth login`")
    return token


def fetch_advisories(
    repo: str,
    token: str,
    state: str = "triage",
    transport: httpx.BaseTransport | None = None,
) -> list[dict[str, Any]]:
    """List repository security advisories in ``state``, following pagination."""
    if not _REPO_RE.fullmatch(repo) or ".." in repo:
        raise GitHubError(f"repository must look like owner/name, got {repo!r}")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "kalkan",
    }
    url: str | None = (
        f"https://{API_HOST}/repos/{repo}/security-advisories?state={state}&per_page=100"
    )
    results: list[dict[str, Any]] = []
    with httpx.Client(transport=transport, timeout=30, headers=headers) as client:
        for _ in range(MAX_PAGES):
            if url is None:
                break
            parts = urlsplit(url)
            if parts.scheme != "https" or parts.hostname != API_HOST:
                raise GitHubError("refusing to follow a pagination link to another host")
            try:
                response = client.get(url)
            except httpx.HTTPError as exc:
                raise GitHubError(f"network error: {type(exc).__name__}") from None
            if response.status_code in (401, 403):
                raise GitHubError(
                    f"HTTP {response.status_code}: the token cannot read security advisories "
                    "(needs the 'Repository security advisories' read permission and admin or "
                    "security manager access)"
                )
            if response.status_code == 404:
                raise GitHubError("HTTP 404: repository not found or not visible to this token")
            if response.status_code >= 400:
                raise GitHubError(f"HTTP {response.status_code} from GitHub")
            page = response.json()
            if not isinstance(page, list):
                raise GitHubError("unexpected response from GitHub")
            results.extend(item for item in page if isinstance(item, dict))
            match = _NEXT_RE.search(response.headers.get("link", ""))
            url = match.group(1) if match else None
    return results


def to_report(advisory: dict[str, Any]) -> dict[str, Any]:
    """The fields Kalkan keeps from an advisory."""
    raw_author = advisory.get("author")
    author: dict[str, Any] = raw_author if isinstance(raw_author, dict) else {}
    return {
        "ghsa_id": advisory.get("ghsa_id"),
        "summary": advisory.get("summary") or "",
        "description": advisory.get("description") or "",
        "severity": advisory.get("severity"),
        "created_at": advisory.get("created_at"),
        "state": advisory.get("state"),
        "reporter": author.get("login"),
    }


def save_reports(advisories: list[dict[str, Any]], out_dir: Path) -> list[Path]:
    """Write one ``<ghsa_id>.json`` per advisory with 0600 permissions."""
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    written: list[Path] = []
    for advisory in advisories:
        ghsa = str(advisory.get("ghsa_id") or "")
        if not _GHSA_RE.fullmatch(ghsa):
            continue
        path = out_dir / f"{ghsa}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(to_report(advisory), fh, indent=2)
            fh.write("\n")
        path.chmod(0o600)  # also tighten files that already existed
        written.append(path)
    return written
