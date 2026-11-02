"""Tests for the core data models."""

import json

import pytest
from pydantic import ValidationError

from kalkan.models import (
    AgentOpinion,
    CheckStatus,
    Claim,
    ClaimCheck,
    ClaimKind,
    QualitySignals,
    Span,
    TriageResult,
    Verdict,
)


def _sample_result() -> TriageResult:
    claim = Claim(
        kind=ClaimKind.FUNCTION,
        value="parse_url",
        quote="parse_url()",
        span=Span(start=4, end=15),
    )
    return TriageResult(
        report_id="r1",
        verdict=Verdict.NEEDS_HUMAN,
        confidence=0.4,
        summary="The function exists.",
        claim_checks=[
            ClaimCheck(
                claim=claim,
                status=CheckStatus.CONFIRMED,
                evidence="defined in lib/url.c",
                locations=["lib/url.c:10"],
            )
        ],
        quality=QualitySignals(has_poc=True),
        opinions=[
            AgentOpinion(
                agent="analyst",
                verdict=Verdict.LIKELY_VALID,
                confidence=0.7,
                reasoning="ok",
                cited_locations=["lib/url.c:10"],
            )
        ],
        reply_draft="Thank you.",
    )


@pytest.mark.parametrize("value", [-0.01, 1.01, 2.0])
def test_confidence_must_stay_within_bounds(value: float) -> None:
    with pytest.raises(ValidationError):
        AgentOpinion(agent="analyst", verdict=Verdict.NEEDS_HUMAN, confidence=value, reasoning="")
    with pytest.raises(ValidationError):
        TriageResult(report_id="x", verdict=Verdict.NEEDS_HUMAN, confidence=value, summary="")


@pytest.mark.parametrize("value", [0.0, 0.5, 1.0])
def test_confidence_bounds_are_inclusive(value: float) -> None:
    op = AgentOpinion(agent="skeptic", verdict=Verdict.NEEDS_HUMAN, confidence=value, reasoning="")
    assert op.confidence == value


def test_enums_serialize_as_lowercase_strings() -> None:
    data = json.loads(_sample_result().model_dump_json())
    assert data["verdict"] == "needs_human"
    assert data["claim_checks"][0]["status"] == "confirmed"
    assert data["claim_checks"][0]["claim"]["kind"] == "function"
    assert data["opinions"][0]["verdict"] == "likely_valid"


def test_triage_result_round_trips_through_json() -> None:
    original = _sample_result()
    restored = TriageResult.model_validate_json(original.model_dump_json())
    assert restored == original


def test_quote_is_capped_at_200_chars() -> None:
    with pytest.raises(ValidationError):
        Claim(kind=ClaimKind.CODE_SNIPPET, value="x", quote="a" * 201, span=Span(start=0, end=1))


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        QualitySignals.model_validate({"has_poc": True, "surprise": 1})
