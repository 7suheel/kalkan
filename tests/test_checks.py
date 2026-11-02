"""Tests for the deterministic checker against the tiny C fixture repo."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kalkan.checks import RepoError, RepoIndex, check_claims, compute_quality, extract_claims
from kalkan.cli import app
from kalkan.ingest import load_report, sanitize
from kalkan.models import CheckStatus, Claim, ClaimCheck, ClaimKind, Report, SanitizerFindings

runner = CliRunner()


def _report(body: str) -> Report:
    return Report(id="t", body=body)


def _check(body: str, repo: Path) -> list[ClaimCheck]:
    return check_claims(extract_claims(_report(body)), RepoIndex(repo))


def _by_kind(checks: list[ClaimCheck], kind: ClaimKind) -> list[ClaimCheck]:
    return [c for c in checks if c.claim.kind is kind]


def _status(checks: list[ClaimCheck], kind: ClaimKind, value: str) -> CheckStatus:
    for c in checks:
        if c.claim.kind is kind and c.claim.value == value:
            return c.status
    raise AssertionError(f"no {kind} claim {value!r} in {[c.claim.value for c in checks]}")


# ----- extraction -------------------------------------------------------------------------------


def test_extract_every_kind() -> None:
    body = (
        "The function `parse_header()` in src/parser.c at line 14 overflows.\n"
        "Also see lib/x.py:12 and L33 in foo.js.\n"
        "Tested on version 1.2.0 and v8.4.0, commit deadbeef12.\n"
        "Related: CVE-2024-12345.\n\n"
        "```c\nstrcpy(name, line);\n```\n\n"
        "## Steps to reproduce\n1. run it\n\n## PoC\nsee above\n\n"
        "## Impact\nAn attacker can crash it.\n"
    )
    claims = extract_claims(_report(body))
    kinds = {c.kind for c in claims}
    assert kinds == set(ClaimKind)
    values = {(c.kind, c.value) for c in claims}
    assert (ClaimKind.FILE_PATH, "src/parser.c") in values
    assert (ClaimKind.FILE_PATH, "lib/x.py") in values
    assert (ClaimKind.FUNCTION, "parse_header") in values
    assert (ClaimKind.LINE_REF, "src/parser.c:14") in values
    assert (ClaimKind.LINE_REF, "lib/x.py:12") in values
    assert (ClaimKind.LINE_REF, "foo.js:33") in values
    assert (ClaimKind.VERSION, "1.2.0") in values
    assert (ClaimKind.VERSION, "8.4.0") in values
    assert (ClaimKind.COMMIT, "deadbeef12") in values
    assert (ClaimKind.CVE_ID, "CVE-2024-12345") in values


def test_quotes_are_exact_and_spans_match() -> None:
    body = "Bug in `free_conn()` of src/conn.c."
    for claim in extract_claims(_report(body)):
        assert body[claim.span.start : claim.span.end].startswith(claim.quote[:20])
        assert len(claim.quote) <= 200


def test_claims_are_deduplicated() -> None:
    body = "parse_header() and again parse_header() in src/parser.c and src/parser.c"
    claims = extract_claims(_report(body))
    assert [c.value for c in claims if c.kind is ClaimKind.FUNCTION] == ["parse_header"]
    assert [c.value for c in claims if c.kind is ClaimKind.FILE_PATH] == ["src/parser.c"]


def test_urls_and_domains_are_not_paths() -> None:
    body = "See https://example.com/app.js and example.com, plus https://github.com/o/r/blob/main/lib/a.c"
    paths = [c.value for c in extract_claims(_report(body)) if c.kind is ClaimKind.FILE_PATH]
    assert paths == ["lib/a.c"]


def test_ip_addresses_and_cvss_are_not_versions() -> None:
    body = "Server at 10.0.0.1 has CVSS 9.8; affects version 2.3"
    versions = [c.value for c in extract_claims(_report(body)) if c.kind is ClaimKind.VERSION]
    assert versions == ["2.3"]


def test_code_inside_blocks_is_not_a_function_claim() -> None:
    body = "Run this:\n\n```python\nmain()\n```\n"
    claims = extract_claims(_report(body))
    assert not [c for c in claims if c.kind is ClaimKind.FUNCTION]
    assert [c.kind for c in claims] == [ClaimKind.CODE_SNIPPET]


def test_indented_code_block() -> None:
    body = "Code:\n\n    int x = 1;\n    strcpy(name, line);\n\nEnd."
    snippets = [c for c in extract_claims(_report(body)) if c.kind is ClaimKind.CODE_SNIPPET]
    assert snippets and "strcpy(name, line);" in snippets[0].value


# ----- verification -----------------------------------------------------------------------------


def test_existing_function_is_confirmed(tiny_repo: Path) -> None:
    checks = _check("Overflow in parse_header() in src/parser.c", tiny_repo)
    fn = _by_kind(checks, ClaimKind.FUNCTION)[0]
    assert fn.status is CheckStatus.CONFIRMED
    assert fn.locations == ["src/parser.c:10"]
    assert _status(checks, ClaimKind.FILE_PATH, "src/parser.c") is CheckStatus.CONFIRMED


def test_hallucinated_function_is_not_found(tiny_repo: Path) -> None:
    checks = _check("Overflow in parse_header_strict() in src/urlapi.c", tiny_repo)
    assert _status(checks, ClaimKind.FUNCTION, "parse_header_strict") is CheckStatus.NOT_FOUND
    assert _status(checks, ClaimKind.FILE_PATH, "src/urlapi.c") is CheckStatus.NOT_FOUND


def test_mentioned_only_function(tiny_repo: Path) -> None:
    checks = _check("The bug is in strchr()", tiny_repo)
    fn = _by_kind(checks, ClaimKind.FUNCTION)[0]
    assert fn.status is CheckStatus.CONFIRMED
    assert "no definition" in fn.evidence


def test_python_definition(tiny_repo: Path) -> None:
    checks = _check("make_request() builds a bad request", tiny_repo)
    fn = _by_kind(checks, ClaimKind.FUNCTION)[0]
    assert fn.locations == ["scripts/make_request.py:4"]


def test_unused_stdlib_function_is_not_checkable(tiny_repo: Path) -> None:
    checks = _check("It calls system() with user input", tiny_repo)
    assert _status(checks, ClaimKind.FUNCTION, "system") is CheckStatus.NOT_CHECKABLE


def test_suffix_match_for_file(tiny_repo: Path) -> None:
    checks = _check("bug in parser.c", tiny_repo)
    check = _by_kind(checks, ClaimKind.FILE_PATH)[0]
    assert check.status is CheckStatus.CONFIRMED
    assert check.locations == ["src/parser.c"]


def test_line_within_file_is_confirmed(tiny_repo: Path) -> None:
    checks = _check("src/parser.c:14 copies without a check", tiny_repo)
    check = _by_kind(checks, ClaimKind.LINE_REF)[0]
    assert check.status is CheckStatus.CONFIRMED
    assert "strcpy" in check.evidence


def test_line_past_end_of_file_is_contradicted(tiny_repo: Path) -> None:
    checks = _check("The function parse_header() in src/parser.c at line 9999 overflows", tiny_repo)
    assert _status(checks, ClaimKind.LINE_REF, "src/parser.c:9999") is CheckStatus.CONTRADICTED


def test_line_without_file_is_not_checkable(tiny_repo: Path) -> None:
    checks = _check("It crashes at line 42.", tiny_repo)
    assert _status(checks, ClaimKind.LINE_REF, "42") is CheckStatus.NOT_CHECKABLE


def test_line_checked_at_reported_tag(tiny_repo: Path) -> None:
    # At v1.0.0 the file has 23 lines; at HEAD it has 33. Line 30 exists only at HEAD.
    checks = _check("In version 1.0.0, src/parser.c:30 is wrong", tiny_repo)
    assert _status(checks, ClaimKind.LINE_REF, "src/parser.c:30") is CheckStatus.CONFIRMED


def test_versions(tiny_repo: Path) -> None:
    checks = _check("Affects version 1.2.0 and v1.0.0 but not version 9.9.9", tiny_repo)
    assert _status(checks, ClaimKind.VERSION, "1.2.0") is CheckStatus.CONFIRMED
    assert _status(checks, ClaimKind.VERSION, "1.0.0") is CheckStatus.CONFIRMED
    assert _status(checks, ClaimKind.VERSION, "9.9.9") is CheckStatus.NOT_FOUND


def test_commit(tiny_repo: Path) -> None:
    head = RepoIndex(tiny_repo).git("rev-parse", "HEAD").strip()
    checks = _check(f"Introduced in commit {head[:10]}; fixed in commit 0000000abc", tiny_repo)
    assert _status(checks, ClaimKind.COMMIT, head[:10]) is CheckStatus.CONFIRMED
    assert _status(checks, ClaimKind.COMMIT, "0000000abc") is CheckStatus.NOT_FOUND


def test_cve_format() -> None:
    from kalkan.checks.verify import check_cve
    from kalkan.models import Span

    def claim(value: str) -> Claim:
        return Claim(kind=ClaimKind.CVE_ID, value=value, quote=value, span=Span(start=0, end=1))

    assert check_cve(claim("CVE-2024-1234")).status is CheckStatus.NOT_CHECKABLE
    assert check_cve(claim("CVE-1970-1234")).status is CheckStatus.CONTRADICTED


def test_existing_snippet_is_confirmed(tiny_repo: Path) -> None:
    body = "Code:\n\n```c\n    size_t total = count *  size;\n    *buf = malloc(total);\n```\n"
    check = _by_kind(_check(body, tiny_repo), ClaimKind.CODE_SNIPPET)[0]
    assert check.status is CheckStatus.CONFIRMED
    assert check.locations == ["src/parser.c:27"]


def test_invented_snippet_is_not_found(tiny_repo: Path) -> None:
    body = (
        "Code:\n\n```c\nint parse_header_secure(char *input) {\n"
        "    char tmp[16];\n    memcpy(tmp, input, input_length);\n}\n```\n"
    )
    check = _by_kind(_check(body, tiny_repo), ClaimKind.CODE_SNIPPET)[0]
    assert check.status is CheckStatus.NOT_FOUND


def test_shell_snippet_is_not_checkable(tiny_repo: Path) -> None:
    body = "PoC:\n\n```bash\ncurl -H 'X: y' http://localhost:8080/\n```\n"
    check = _by_kind(_check(body, tiny_repo), ClaimKind.CODE_SNIPPET)[0]
    assert check.status is CheckStatus.NOT_CHECKABLE


def test_path_traversal_is_never_read(tiny_repo: Path) -> None:
    index = RepoIndex(tiny_repo)
    assert index.safe_path("../../etc/passwd") is None
    assert index.read_text("../../etc/passwd") is None
    assert index.resolve_file("/etc/passwd") == []
    checks = _check("See ../../etc/passwd.c line 1", tiny_repo)
    assert all(c.status is not CheckStatus.CONFIRMED for c in checks)


def test_not_a_repo(tmp_path: Path) -> None:
    with pytest.raises(RepoError):
        RepoIndex(tmp_path)
    with pytest.raises(RepoError):
        RepoIndex(tmp_path / "missing")


def test_unsafe_ref_is_rejected(tiny_repo: Path) -> None:
    with pytest.raises(RepoError):
        RepoIndex(tiny_repo).files("--output=/tmp/x")


# ----- quality ----------------------------------------------------------------------------------


def test_quality_signals(reports_dir: Path) -> None:
    report, findings = sanitize(load_report(reports_dir / "clean.md"))
    quality = compute_quality(extract_claims(report), findings)
    assert quality.has_affected_version and quality.has_repro_steps
    assert quality.has_poc and quality.has_impact
    assert not quality.injection_suspected

    vague, vague_findings = sanitize(load_report(reports_dir / "vague.txt"))
    vq = compute_quality(extract_claims(vague), vague_findings)
    assert not vq.has_poc and not vq.has_repro_steps
    assert any("nothing points at the code" in n for n in vq.notes)


def test_quality_flags_injection() -> None:
    quality = compute_quality([], SanitizerFindings(injection_phrases=["ignore previous"]))
    assert quality.injection_suspected


# ----- performance ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "a" * 200_000,
        "a/" * 100_000,
        "a." * 100_000,
        "(" * 200_000,
        "commit " * 30_000,
        "1." * 100_000,
        "`a` " * 50_000,
        "function " * 25_000,
    ],
)
def test_extraction_is_fast_on_hostile_input(body: str) -> None:
    start = time.perf_counter()
    extract_claims(_report(body))
    assert time.perf_counter() - start < 2.0


# ----- CLI --------------------------------------------------------------------------------------


def test_check_command(tiny_repo: Path, reports_dir: Path) -> None:
    result = runner.invoke(app, ["check", str(reports_dir / "clean.md"), "--repo", str(tiny_repo)])
    assert result.exit_code == 0, result.output
    assert "confirmed" in result.output
    assert "parse_header" in result.output
    assert "Quality signals" in result.output


def test_check_command_bad_repo(tmp_path: Path, reports_dir: Path) -> None:
    result = runner.invoke(app, ["check", str(reports_dir / "clean.md"), "--repo", str(tmp_path)])
    assert result.exit_code == 2


@pytest.mark.parametrize(
    "text",
    ["which allows remote code execution", "this is a DoS", "leads to arbitrary code running"],
)
def test_impact_phrases(text: str) -> None:
    kinds = {c.kind for c in extract_claims(_report(text))}
    assert ClaimKind.IMPACT_STATEMENT in kinds
