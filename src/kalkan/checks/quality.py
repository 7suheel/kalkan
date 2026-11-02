"""Quality signals computed from claims and sanitizer findings."""

from __future__ import annotations

from kalkan.models import Claim, ClaimKind, QualitySignals, SanitizerFindings


def compute_quality(claims: list[Claim], findings: SanitizerFindings) -> QualitySignals:
    """Summarize how complete a report is and whether it tries to steer an AI."""
    kinds = {c.kind for c in claims}
    has_version = bool(kinds & {ClaimKind.VERSION, ClaimKind.COMMIT})
    signals = QualitySignals(
        has_affected_version=has_version,
        has_repro_steps=ClaimKind.REPRO_STEPS in kinds,
        has_poc=ClaimKind.POC_PRESENT in kinds,
        has_impact=ClaimKind.IMPACT_STATEMENT in kinds,
        injection_suspected=findings.injection_suspected,
    )
    notes: list[str] = []
    if not signals.has_affected_version:
        notes.append("no affected version or commit given")
    if not signals.has_repro_steps:
        notes.append("no steps to reproduce")
    if not signals.has_poc:
        notes.append("no proof of concept")
    if not signals.has_impact:
        notes.append("no impact statement")
    if not kinds & {ClaimKind.FILE_PATH, ClaimKind.FUNCTION, ClaimKind.CODE_SNIPPET}:
        notes.append("no file, function or code named, so nothing points at the code")
    if findings.injection_suspected:
        notes.append("report contains text aimed at AI triagers")
    if findings.hidden_html:
        notes.append(f"{len(findings.hidden_html)} hidden HTML fragment(s)")
    return signals.model_copy(update={"notes": notes})
