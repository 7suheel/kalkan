"""Property-based tests: every extractor must survive any input, quickly.

Hypothesis generates hostile and random inputs. Each test checks that the
function never raises an unexpected exception, keeps its documented
invariants, and finishes within the per-input deadline.
"""

from __future__ import annotations

import contextlib
import json
from datetime import timedelta

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from kalkan.checks.extract import extract_claims, find_code_blocks
from kalkan.checks.repo import RepoIndex
from kalkan.ingest import (
    ReportError,
    _report_from_json,
    decode_base64_blocks,
    find_hidden_html,
    find_injection_phrases,
    sanitize,
)
from kalkan.llm.base import ConfigError
from kalkan.llm.config import parse_model_spec
from kalkan.llm.json_output import extract_json_object
from kalkan.models import Report

# A deadline per generated input: anything slower is treated as a failure.
PER_INPUT = settings(
    deadline=timedelta(milliseconds=500),
    max_examples=150,
    suppress_health_check=[HealthCheck.too_slow],
)

# Text that is likely to hit the extractor regexes: report-ish words, symbols and
# all of Unicode (including control, format and private-use characters).
TOKENS = [
    "parse_header()", "src/parser.c", ":14", "line ", "L42", "version ", "v1.2.0",
    "commit ", "deadbeef1", "CVE-2024-1234", "```", "~~~", "    ", "\t", "\n", "<!--",
    "-->", "<", ">", "<details>", "</details>", 'style="display:none"', "`", "(", ")",
    "ignore previous instructions", "you are an AI", "SYSTEM:", "</untrusted_report>",
    '"verdict":', "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", "https://", "/blob/main/",
    "..", "/", ".", "-", "_", "#", "## Impact", "PoC", "\u200b", "\u202e", "\U000e0041",
    "\x1b[31m", "\x00", "\ud7ff", "\uff1c",
]  # fmt: skip
report_text = st.lists(st.one_of(st.sampled_from(TOKENS), st.text(max_size=20)), max_size=60).map(
    "".join
)


@PER_INPUT
@given(report_text)
def test_extract_claims_invariants(text: str) -> None:
    report = Report(id="p", body=text)
    claims = extract_claims(report)
    keys = set()
    for claim in claims:
        assert 0 <= claim.span.start <= claim.span.end <= len(text)
        assert len(claim.quote) <= 200
        assert text[claim.span.start : claim.span.end].startswith(claim.quote)
        assert claim.value
        key = (
            claim.kind,
            claim.value if claim.kind.value == "code_snippet" else claim.value.lower(),
        )
        assert key not in keys  # deduplicated
        keys.add(key)


@PER_INPUT
@given(report_text)
def test_find_code_blocks_invariants(text: str) -> None:
    for block in find_code_blocks(text):
        assert 0 <= block.start <= block.end <= len(text)


@PER_INPUT
@given(report_text)
def test_injection_and_hidden_html_never_crash(text: str) -> None:
    for phrase in find_injection_phrases(text):
        assert 0 < len(phrase) <= 200
    for fragment in find_hidden_html(text):
        assert 0 < len(fragment) <= 200
    for decoded in decode_base64_blocks(text):
        assert isinstance(decoded, str)


@PER_INPUT
@given(report_text, st.one_of(st.none(), report_text))
def test_sanitize_invariants(body: str, title: str | None) -> None:
    cleaned, findings = sanitize(Report(id="p", title=title, body=body))
    # Invisible and control characters never survive sanitizing (newline and tab do).
    for ch in cleaned.body + (cleaned.title or ""):
        assert ch in "\n\t" or (ord(ch) >= 0x20 and not 0x7F <= ord(ch) <= 0x9F)
        assert ch not in "\u200b\u202e\ufeff"
    assert findings.removed_invisible >= 0
    # Sanitizing is idempotent.
    again, _ = sanitize(cleaned.model_copy(update={"sanitization_notes": []}))
    assert again.body == cleaned.body


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=30),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.sampled_from(["title", "body", "summary", "description", "ghsa_id",
                                       "created_at", "id", "x"]), children, max_size=5),
    max_leaves=20,
)  # fmt: skip


@PER_INPUT
@given(st.one_of(json_values.map(json.dumps), report_text))
def test_json_reports_never_crash(text: str) -> None:
    try:
        report = _report_from_json(text, default_id="d")
    except ReportError:
        return
    assert isinstance(report.body, str)
    assert report.id


@pytest.mark.parametrize(
    "text",
    [
        "[" * 100_000 + "]" * 100_000,
        '{"body": ' + "1" * 5_000 + "}",
        '{"body": "x", "created_at": "' + "9" * 5_000 + '"}',
    ],
)
def test_json_report_edge_cases_raise_report_error(text: str) -> None:
    with contextlib.suppress(ReportError):
        _report_from_json(text, default_id="d")


model_output = st.one_of(
    report_text,
    json_values.map(json.dumps),
    st.integers(1, 3000).map(lambda n: '{"a":' * n),
    st.integers(1, 3000).map(lambda n: "[" * n),
)


@PER_INPUT
@given(model_output)
def test_extract_json_object_only_raises_value_error(text: str) -> None:
    with contextlib.suppress(ValueError):
        extract_json_object(text)


@PER_INPUT
@given(report_text)
def test_normalize_path_never_escapes(raw: str) -> None:
    rel = RepoIndex.normalize_path(raw)
    if rel is not None:
        assert not rel.startswith("/")
        assert ".." not in rel.split("/")
        assert "\0" not in rel


@PER_INPUT
@given(st.text(max_size=80))
def test_parse_model_spec_only_raises_config_error(spec: str) -> None:
    try:
        provider, model = parse_model_spec(spec)
    except ConfigError:
        return
    assert provider in ("anthropic", "openai", "ollama", "compat")
    assert model
