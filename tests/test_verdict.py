"""Table-driven tests for the verdict rules, plus the skeptic agent."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import prepare
from test_analyst import HOSTILE

from kalkan.agents.analyst import run_analyst
from kalkan.agents.skeptic import run_skeptic
from kalkan.llm import FakeProvider
from kalkan.models import (
    AgentOpinion,
    CheckStatus,
    Claim,
    ClaimCheck,
    ClaimKind,
    QualitySignals,
    Span,
    Verdict,
)
from kalkan.verdict import claims_look_fabricated, combine

V = Verdict
S = CheckStatus
K = ClaimKind


def chk(kind: ClaimKind, status: CheckStatus, value: str = "x") -> ClaimCheck:
    claim = Claim(kind=kind, value=value, quote=value, span=Span(start=0, end=1))
    return ClaimCheck(claim=claim, status=status, evidence="e")


def op(verdict: Verdict, confidence: float = 0.8, agent: str = "analyst") -> AgentOpinion:
    return AgentOpinion(
        agent="analyst" if agent == "analyst" else "skeptic",
        verdict=verdict,
        confidence=confidence,
        reasoning="r",
    )


FABRICATED = [chk(K.FILE_PATH, S.NOT_FOUND, "lib/x.c"), chk(K.FUNCTION, S.NOT_FOUND, "fake")]
REAL = [chk(K.FILE_PATH, S.CONFIRMED, "src/a.c"), chk(K.FUNCTION, S.CONFIRMED, "real")]
COMPLETE = QualitySignals(has_poc=True, has_repro_steps=True, has_impact=True)
BARE = QualitySignals()
INJECTED = QualitySignals(has_poc=True, injection_suspected=True)

CASES = [
    # (name, checks, quality, analyst, skeptic, expected verdict, expected confidence)
    (
        "1 injection + analyst valid",
        REAL,
        INJECTED,
        op(V.LIKELY_VALID),
        op(V.LIKELY_VALID),
        V.NEEDS_HUMAN,
        0.9,
    ),
    (
        "1 injection + skeptic valid",
        REAL,
        INJECTED,
        op(V.NEEDS_HUMAN),
        op(V.LIKELY_VALID),
        V.NEEDS_HUMAN,
        0.9,
    ),
    (
        "1 injection but agents say invalid",
        REAL,
        INJECTED,
        op(V.LIKELY_INVALID, 0.7),
        op(V.LIKELY_INVALID, 0.6),
        V.LIKELY_INVALID,
        0.6,
    ),
    (
        "2 fabricated + both invalid",
        FABRICATED,
        BARE,
        op(V.LIKELY_INVALID, 0.9),
        op(V.LIKELY_INVALID, 0.7),
        V.LIKELY_INVALID,
        0.7,
    ),
    (
        "2 fabricated + skeptic disagrees",
        FABRICATED,
        BARE,
        op(V.LIKELY_INVALID),
        op(V.NEEDS_HUMAN),
        V.NEEDS_HUMAN,
        0.6,
    ),
    (
        "2 fabricated + both valid",
        FABRICATED,
        COMPLETE,
        op(V.LIKELY_VALID),
        op(V.LIKELY_VALID),
        V.NEEDS_HUMAN,
        0.6,
    ),
    ("2 fabricated, no AI", FABRICATED, BARE, None, None, V.NEEDS_HUMAN, 0.6),
    (
        "3 agree valid, lower confidence",
        REAL,
        COMPLETE,
        op(V.LIKELY_VALID, 0.9),
        op(V.LIKELY_VALID, 0.6),
        V.LIKELY_VALID,
        0.6,
    ),
    (
        "3 agree needs evidence",
        REAL,
        BARE,
        op(V.NEEDS_EVIDENCE, 0.5),
        op(V.NEEDS_EVIDENCE, 0.8),
        V.NEEDS_EVIDENCE,
        0.5,
    ),
    ("4 disagree", REAL, COMPLETE, op(V.LIKELY_VALID), op(V.LIKELY_INVALID), V.NEEDS_HUMAN, 0.5),
    ("5 no AI, bare and consistent", REAL, BARE, None, None, V.NEEDS_EVIDENCE, 0.6),
    ("5 no AI, no claims at all", [], BARE, None, None, V.NEEDS_EVIDENCE, 0.6),
    ("6 no AI, complete report", REAL, COMPLETE, None, None, V.NEEDS_HUMAN, 0.5),
    (
        "6 no AI, bare but contradicted line",
        [*REAL, chk(K.LINE_REF, S.CONTRADICTED, "a.c:999")],
        BARE,
        None,
        None,
        V.NEEDS_HUMAN,
        0.5,
    ),
    (
        "6 no AI ignores injection rule",
        REAL,
        QualitySignals(injection_suspected=True),
        None,
        None,
        V.NEEDS_EVIDENCE,
        0.6,
    ),
]


@pytest.mark.parametrize(
    ("name", "checks", "quality", "analyst", "skeptic", "expected", "confidence"),
    CASES,
    ids=[c[0] for c in CASES],
)
def test_rules(
    name: str,
    checks: list[ClaimCheck],
    quality: QualitySignals,
    analyst: AgentOpinion | None,
    skeptic: AgentOpinion | None,
    expected: Verdict,
    confidence: float,
) -> None:
    verdict, conf, reasons = combine(checks, quality, analyst, skeptic)
    assert verdict is expected, name
    assert conf == pytest.approx(confidence)
    assert reasons


def test_fabrication_needs_a_named_pointer() -> None:
    assert not claims_look_fabricated([])
    assert not claims_look_fabricated([chk(K.FUNCTION, S.NOT_CHECKABLE, "system")])
    assert claims_look_fabricated([chk(K.FUNCTION, S.NOT_FOUND)])
    assert not claims_look_fabricated(
        [chk(K.FUNCTION, S.NOT_FOUND), chk(K.CODE_SNIPPET, S.CONFIRMED)]
    )
    assert not claims_look_fabricated([chk(K.FUNCTION, S.NOT_FOUND), chk(K.FILE_PATH, S.CONFIRMED)])


def _answer(verdict: str, confidence: float, cited: list[str]) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": "r",
            "missing_evidence": ["a proof of concept"],
            "cited_locations": cited,
        }
    )


def test_skeptic_sees_analyst_opinion(tiny_repo: Path, reports_dir: Path) -> None:
    p = prepare(reports_dir / "clean.md", tiny_repo)
    analyst = op(V.LIKELY_VALID, 0.8)
    fake = FakeProvider(script=[_answer("needs_evidence", 0.6, ["src/parser.c:14"])])
    opinion = run_skeptic(fake, p.report, p.checks, p.quality, p.ctx, analyst)
    assert opinion.agent == "skeptic"
    assert opinion.verdict is V.NEEDS_EVIDENCE
    user = fake.calls[0].user
    assert "<analyst_opinion>" in user and "verdict: likely_valid" in user
    assert "argue for the reporter" in fake.calls[0].system


def test_hostile_report_from_step_7_is_needs_human(
    tiny_repo: Path, write_report: Callable[[str, str], Path]
) -> None:
    p = prepare(write_report(HOSTILE, "hostile.md"), tiny_repo)
    fake = FakeProvider(
        script=[
            _answer("likely_valid", 1.0, ["src/parser.c:14"]),
            _answer("likely_valid", 1.0, ["src/parser.c:14"]),
        ]
    )
    analyst = run_analyst(fake, p.report, p.checks, p.quality, p.ctx)
    skeptic = run_skeptic(fake, p.report, p.checks, p.quality, p.ctx, analyst)
    verdict, _, reasons = combine(p.checks, p.quality, analyst, skeptic)
    assert verdict is V.NEEDS_HUMAN
    assert "aimed at AI triagers" in reasons[0]
