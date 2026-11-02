"""Combine deterministic checks and agent opinions into a verdict with explicit rules.

The rules are applied in order; the first that matches wins:

1. Injection suspected and an agent said LIKELY_VALID -> NEEDS_HUMAN.
2. Every file and function the report names is NOT_FOUND and no code
   snippet matched -> LIKELY_INVALID only if analyst and skeptic both say so,
   otherwise NEEDS_HUMAN.
3. Analyst and skeptic agree -> their verdict, with the lower confidence.
4. They disagree -> NEEDS_HUMAN.
5. No PoC, no repro steps and nothing contradicts the claims -> NEEDS_EVIDENCE.

In no-AI mode (no opinions) only rules 2 and 5 apply; anything else is
NEEDS_HUMAN. Kalkan never decides alone: every verdict is a suggestion.
"""

from __future__ import annotations

from kalkan.models import (
    AgentOpinion,
    CheckStatus,
    ClaimCheck,
    ClaimKind,
    QualitySignals,
    Verdict,
)

_POINTERS = (ClaimKind.FILE_PATH, ClaimKind.FUNCTION)
_CODE_CLAIMS = (ClaimKind.FILE_PATH, ClaimKind.FUNCTION, ClaimKind.LINE_REF, ClaimKind.CODE_SNIPPET)


def claims_look_fabricated(checks: list[ClaimCheck]) -> bool:
    """True if the report names files/functions, none exist, and no snippet matched."""
    pointers = [
        c for c in checks if c.claim.kind in _POINTERS and c.status is not CheckStatus.NOT_CHECKABLE
    ]
    if not pointers or any(c.status is not CheckStatus.NOT_FOUND for c in pointers):
        return False
    return not any(
        c.claim.kind is ClaimKind.CODE_SNIPPET and c.status is CheckStatus.CONFIRMED for c in checks
    )


def contradictions(checks: list[ClaimCheck]) -> list[ClaimCheck]:
    """Code claims that were not found or are contradicted by the repository."""
    return [
        c
        for c in checks
        if c.claim.kind in _CODE_CLAIMS
        and c.status in (CheckStatus.NOT_FOUND, CheckStatus.CONTRADICTED)
    ]


def _describe(checks: list[ClaimCheck]) -> str:
    return ", ".join(f"{c.claim.kind.value} `{c.claim.value[:60]}`" for c in checks[:4])


def combine(
    checks: list[ClaimCheck],
    quality: QualitySignals,
    analyst: AgentOpinion | None,
    skeptic: AgentOpinion | None,
) -> tuple[Verdict, float, list[str]]:
    """Return (verdict, confidence, reasons). Reasons are in plain English."""
    ai = analyst is not None and skeptic is not None
    opinions = [o for o in (analyst, skeptic) if o is not None]

    # Rule 1: never let an injected instruction produce LIKELY_VALID.
    if quality.injection_suspected and any(o.verdict is Verdict.LIKELY_VALID for o in opinions):
        return (
            Verdict.NEEDS_HUMAN,
            0.9,
            [
                "The report contains text aimed at AI triagers and an agent answered "
                "likely_valid; a human must review it.",
            ],
        )

    # Rule 2: everything the report points at is missing.
    if claims_look_fabricated(checks):
        missing = [c for c in checks if c.claim.kind in _POINTERS]
        reason = f"None of the named code exists in the repository: {_describe(missing)}."
        if (
            ai
            and analyst is not None
            and skeptic is not None
            and analyst.verdict is Verdict.LIKELY_INVALID
            and skeptic.verdict is Verdict.LIKELY_INVALID
        ):
            return (
                Verdict.LIKELY_INVALID,
                min(analyst.confidence, skeptic.confidence),
                [reason, "Analyst and skeptic both judged the report likely invalid."],
            )
        why = "the agents did not both agree it is invalid" if ai else "no AI review was run"
        return (
            Verdict.NEEDS_HUMAN,
            0.6,
            [reason, f"Not marked invalid because {why}; please confirm by hand."],
        )

    if ai and analyst is not None and skeptic is not None:
        # Rule 3: agreement.
        if analyst.verdict is skeptic.verdict:
            return (
                analyst.verdict,
                min(analyst.confidence, skeptic.confidence),
                [f"Analyst and skeptic agree: {analyst.verdict.value}."],
            )
        # Rule 4: disagreement goes to a human.
        return (
            Verdict.NEEDS_HUMAN,
            0.5,
            [
                f"Analyst said {analyst.verdict.value} and skeptic said "
                f"{skeptic.verdict.value}; a human should decide."
            ],
        )

    # Rule 5: plausible but unsupported.
    if not quality.has_poc and not quality.has_repro_steps and not contradictions(checks):
        return (
            Verdict.NEEDS_EVIDENCE,
            0.6,
            ["The report has no proof of concept and no steps to reproduce."],
        )

    reasons = ["Deterministic checks alone cannot decide this report."]
    found = contradictions(checks)
    if found:
        reasons.append(f"Some claims do not match the code: {_describe(found)}.")
    return Verdict.NEEDS_HUMAN, 0.5, reasons
