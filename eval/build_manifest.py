"""Build eval/datasets/curl/manifest.csv from two public sources.

- Daniel Stenberg's gist listing invalid AI-generated reports sent to curl
  (a Markdown list of HackerOne report links): label "invalid".
- curl's vuln.json (an array of OSV records, one per CVE): label "valid";
  each CVE's advisory text is used as the report.

Usage:
    uv run python -m eval.build_manifest
    uv run python -m eval.build_manifest --gist-file gist.md --vuln-file vuln.json
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path
from typing import Any

import httpx

from eval.common import DATA_DIR, MANIFEST, USER_AGENT, ManifestRow, write_manifest

GIST_RAW_URL = "https://gist.githubusercontent.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd/raw"
GIST_PAGE_URL = "https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd"
VULN_JSON_URL = "https://curl.se/docs/vuln.json"
_H1_LINK_RE = re.compile(r"https://hackerone\.com/reports/(\d{4,10})")
_MD_LINK_RE = re.compile(r"\[([^\]\n]{1,300})\]\((https://hackerone\.com/reports/\d{4,10})\)")
_HTML_LINK_RE = re.compile(
    r'<a[^>]{0,300}href="(https://hackerone\.com/reports/\d{4,10})"[^>]{0,300}>(.{0,600}?)</a>',
    re.S,
)


def parse_gist(text: str) -> list[ManifestRow]:
    """Extract HackerOne report links (and titles) from the gist's Markdown or HTML."""
    found: dict[str, str] = {}
    for title, url in _MD_LINK_RE.findall(text):
        found.setdefault(url, title.strip())
    for url, inner in _HTML_LINK_RE.findall(text):
        title = html.unescape(re.sub(r"<[^>]+>", "", inner)).strip()
        found.setdefault(url, title)
    for match in _H1_LINK_RE.finditer(text):
        found.setdefault(match.group(0), "")
    rows = []
    for url, title in found.items():
        num = _H1_LINK_RE.search(url)
        assert num is not None
        rows.append(
            ManifestRow(
                id=f"h1-{num.group(1)}",
                url=url,
                label="invalid",
                published_at="",
                source="bagder-gist",
                notes=" ".join(title.split())[:160],
            )
        )
    return rows


def _fix_commit(record: dict[str, Any]) -> str:
    for affected in record.get("affected") or []:
        for rng in affected.get("ranges") or []:
            if rng.get("type") != "GIT" or "curl/curl" not in str(rng.get("repo", "")):
                continue
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if isinstance(fixed, str) and re.fullmatch(r"[0-9a-f]{7,40}", fixed):
                    return fixed
    return ""


def parse_vuln_json(data: Any) -> list[ManifestRow]:
    """One "valid" row per OSV record in curl's vuln.json."""
    if not isinstance(data, list):
        raise ValueError("vuln.json should be a JSON array of OSV records")
    rows = []
    for record in data:
        if not isinstance(record, dict):
            continue
        aliases = [a for a in record.get("aliases") or [] if str(a).startswith("CVE-")]
        cve = aliases[0] if aliases else str(record.get("id", "")).removeprefix("CURL-")
        if not cve:
            continue
        extra = record.get("database_specific") or {}
        fix = _fix_commit(record)
        rows.append(
            ManifestRow(
                id=cve,
                url=str(extra.get("www") or f"https://curl.se/docs/{cve}.html"),
                label="valid",
                published_at=str(record.get("published", "")),
                source="curl-vuln.json",
                notes=" ".join(str(record.get("summary", "")).split())[:160],
                ref=f"{fix}^" if fix else "",
            )
        )
    return rows


def _get(url: str) -> str:
    response = httpx.get(url, headers={"User-Agent": USER_AGENT}, timeout=30, follow_redirects=True)
    response.raise_for_status()
    return response.text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gist-file", type=Path, help="Use a saved copy of the gist.")
    parser.add_argument("--vuln-file", type=Path, help="Use a saved copy of vuln.json.")
    parser.add_argument("--out", type=Path, default=MANIFEST)
    args = parser.parse_args(argv)

    if args.gist_file:
        gist = args.gist_file.read_text(encoding="utf-8")
    else:
        try:
            gist = _get(GIST_RAW_URL)
        except httpx.HTTPError:
            gist = _get(GIST_PAGE_URL)
    vuln_text = (
        args.vuln_file.read_text(encoding="utf-8") if args.vuln_file else _get(VULN_JSON_URL)
    )
    vuln = json.loads(vuln_text)

    # Keep a local copy so fetch.py can build CVE reports offline (eval/data is gitignored).
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "vuln.json").write_text(vuln_text, encoding="utf-8")

    invalid = parse_gist(gist)
    valid = parse_vuln_json(vuln)
    write_manifest(invalid + valid, args.out)
    print(f"wrote {args.out}: {len(invalid)} invalid, {len(valid)} valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
