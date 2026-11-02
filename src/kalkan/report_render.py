"""Template-based summary and reply (no AI), and the Markdown/JSON output formats.

Used in --no-ai mode and as the fallback whenever the writer agent fails.
"""

from __future__ import annotations

from kalkan.models import (
    AgentOpinion,
    CheckStatus,
    ClaimCheck,
    ClaimKind,
    QualitySignals,
    TriageResult,
    Verdict,
)

_STATUS_MARK = {
    CheckStatus.CONFIRMED: "✅ confirmed",
    CheckStatus.NOT_FOUND: "❌ not found",
    CheckStatus.CONTRADICTED: "⚠️ contradicted",
    CheckStatus.NOT_CHECKABLE: "⚪ not checkable",
}
_VERDICT_TEXT = {
    Verdict.LIKELY_VALID: "the report looks valid",
    Verdict.NEEDS_EVIDENCE: "the report may be real but lacks evidence",
    Verdict.LIKELY_INVALID: "the report's claims do not match the code",
    Verdict.NEEDS_HUMAN: "a human needs to look at this report",
}
_POINTER_KINDS = (
    ClaimKind.FILE_PATH,
    ClaimKind.FUNCTION,
    ClaimKind.LINE_REF,
    ClaimKind.CODE_SNIPPET,
)


def missing_evidence(quality: QualitySignals, opinions: list[AgentOpinion]) -> list[str]:
    """Missing items from quality signals plus what the agents asked for (deduplicated)."""
    items: list[str] = []
    if not quality.has_affected_version:
        items.append("the affected version or commit")
    if not quality.has_repro_steps:
        items.append("steps to reproduce")
    if not quality.has_poc:
        items.append("a proof of concept")
    if not quality.has_impact:
        items.append("the impact (what an attacker can achieve)")
    seen = {i.lower() for i in items}
    for opinion in opinions:
        for item in opinion.missing_evidence:
            text = " ".join(item.split())[:200]
            if text and text.lower() not in seen:
                seen.add(text.lower())
                items.append(text)
    return items


def _pointer_checks(checks: list[ClaimCheck], status: CheckStatus) -> list[ClaimCheck]:
    return [c for c in checks if c.claim.kind in _POINTER_KINDS and c.status is status]


def _short(check: ClaimCheck) -> str:
    value = " ".join(check.claim.value.split())
    if check.claim.kind is ClaimKind.CODE_SNIPPET:
        value = "the quoted code"
    elif check.claim.kind is ClaimKind.FUNCTION:
        value = f"{value}()"
    elif check.claim.kind is ClaimKind.LINE_REF:
        value = f"line {value}"
    loc = check.locations[0] if check.locations else ""
    where = f" ({loc})" if loc and loc != check.claim.value else ""
    return f"{value[:80]}{where}"


def _join(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def template_summary(
    verdict: Verdict,
    confidence: float,
    reasons: list[str],
    checks: list[ClaimCheck],
    quality: QualitySignals,
) -> str:
    """A 3-6 sentence summary built only from deterministic data."""
    sentences = [
        f"Suggested verdict: {verdict.value} ({confidence:.0%} confidence): "
        f"{_VERDICT_TEXT[verdict]}."
    ]
    confirmed = _pointer_checks(checks, CheckStatus.CONFIRMED)
    bad = _pointer_checks(checks, CheckStatus.NOT_FOUND) + _pointer_checks(
        checks, CheckStatus.CONTRADICTED
    )
    if confirmed:
        sentences.append(f"Confirmed in the code: {_join([_short(c) for c in confirmed[:4]])}.")
    if bad:
        sentences.append(f"Not found or contradicted: {_join([_short(c) for c in bad[:4]])}.")
    if not confirmed and not bad:
        sentences.append("The report does not point at any specific file, function or code.")
    sentences.extend(reasons[:2])
    if quality.injection_suspected:
        sentences.append("The report contains text that tries to instruct AI triage tools.")
    return " ".join(sentences[:6])


def template_reply(
    verdict: Verdict,
    checks: list[ClaimCheck],
    quality: QualitySignals,
    missing: list[str],
) -> str:
    """A polite reply draft built only from deterministic data."""
    lines = ["Hello,", "", "Thank you for taking the time to send us this security report."]
    confirmed = _pointer_checks(checks, CheckStatus.CONFIRMED)
    bad = _pointer_checks(checks, CheckStatus.NOT_FOUND) + _pointer_checks(
        checks, CheckStatus.CONTRADICTED
    )
    lines.append("")
    lines.append("We compared the report with our code.")
    if confirmed:
        lines.append(f"We could locate {_join([_short(c) for c in confirmed[:4]])}.")
    if bad:
        lines.append(
            f"We could not match {_join([_short(c) for c in bad[:4]])} to the current code "
            "or to the version mentioned. Could you check whether these references are "
            "correct, and tell us which version or commit you tested?"
        )
    if verdict is Verdict.LIKELY_VALID:
        lines.append(
            "Our first look suggests the issue is real, and we are looking into it further."
        )
    asks = [m for m in missing if not (bad and m == "the affected version or commit")]
    if asks:
        lines.append("")
        lines.append("To help us investigate, could you please send:")
        lines.extend(f"- {item}" for item in asks[:6])
    lines += [
        "",
        "We will get back to you once we have reviewed it.",
        "",
        "Best regards,",
        "[maintainer name]",
    ]
    return "\n".join(lines)


def _cell(text: str, limit: int = 120) -> str:
    """Make text safe for a Markdown table cell (no pipes, newlines, HTML or links)."""
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    for old, new in (
        ("\\", "\\\\"),
        ("|", "\\|"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("[", "\\["),
        ("]", "\\]"),
    ):
        text = text.replace(old, new)
    return text


def _prose(text: str) -> str:
    """Neutralize raw HTML and images in model-written prose (no remote loads on render)."""
    return text.strip().replace("<", "&lt;").replace("![", "!\\[")


def _code_cell(text: str, limit: int = 60) -> str:
    text = " ".join(text.split()).replace("`", "'")
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return f"`{text.replace('|', '¦')}`"


def render_markdown(result: TriageResult) -> str:
    """Render a TriageResult for the maintainer."""
    out = [
        f"# Kalkan triage: {_cell(result.report_id, 80)}",
        "",
        f"**Suggested verdict: {result.verdict.value.upper()}** "
        f"(confidence {result.confidence:.0%}). Kalkan only suggests; you make the final call.",
        "",
        "## Summary",
        "",
        _prose(result.summary),
        "",
        "## Claim checks",
        "",
    ]
    if result.claim_checks:
        out += ["| Status | Kind | Claim | Evidence |", "| --- | --- | --- | --- |"]
        for c in result.claim_checks:
            out.append(
                f"| {_STATUS_MARK[c.status]} | {c.claim.kind.value} | {_code_cell(c.claim.value)} "
                f"| {_cell(c.evidence)} |"
            )
    else:
        out.append("No checkable claims were found in the report.")
    q = result.quality
    out += ["", "## Quality signals", ""]
    for label, value in (
        ("Affected version given", q.has_affected_version),
        ("Steps to reproduce", q.has_repro_steps),
        ("Proof of concept", q.has_poc),
        ("Impact statement", q.has_impact),
    ):
        out.append(f"- [{'x' if value else ' '}] {label}")
    if q.injection_suspected:
        out.append("- **Prompt injection suspected**: the report contains text aimed at AI tools.")
    out += ["", "## Agent opinions", ""]
    if result.opinions:
        for o in result.opinions:
            out += [
                f"### {o.agent.capitalize()}: {o.verdict.value} ({o.confidence:.0%})",
                "",
                _prose(o.reasoning),
                "",
            ]
            if o.cited_locations:
                out += [f"Cited: {', '.join(_code_cell(x) for x in o.cited_locations)}", ""]
    else:
        out += ["AI was off for this run, so there are no agent opinions.", ""]
    missing = missing_evidence(q, result.opinions)
    out += ["## Missing evidence", ""]
    out += [f"- {_cell(m, 200)}" for m in missing] if missing else ["Nothing obvious is missing."]
    out += [
        "",
        "## Reply draft",
        "",
        "~~~text",
        result.reply_draft.replace("~~~", "~ ~ ~"),
        "~~~",
        "",
    ]
    footer = [f"Kalkan {result.kalkan_version}", f"model: {result.model or 'none (AI off)'}"]
    if result.tokens_used:
        footer.append(f"tokens: {result.tokens_used}")
    if result.cost_usd_estimate is not None:
        footer.append(f"est. cost: ${result.cost_usd_estimate:.4f}")
    out += ["---", "", " · ".join(footer), ""]
    return "\n".join(out)


def render_json(result: TriageResult) -> str:
    """Render a TriageResult as JSON."""
    return result.model_dump_json(indent=2) + "\n"
