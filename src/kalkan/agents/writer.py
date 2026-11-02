"""Writer agent: a maintainer summary and a polite reply draft.

Falls back to the deterministic templates in report_render when AI is off or
the model fails, so a summary and reply are always produced.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from kalkan.agents.common import (
    fill,
    load_prompt,
    neutralize_tags,
    render_claim_table,
    render_opinion,
)
from kalkan.llm import Provider, ProviderError, complete_json
from kalkan.llm.base import redact
from kalkan.models import AgentOpinion, ClaimCheck, QualitySignals, Report, Verdict
from kalkan.report_render import missing_evidence, template_reply, template_summary

WRITER_MAX_TOKENS = 3000
_RUDE_RE = re.compile(
    r"\b(?:ai[\s-]?slop|slop|spam|ai[\s-]generated|chatgpt|llm[\s-]generated|"
    r"waste\s+of\s+(?:our\s+)?time|fake\s+report)\b",
    re.IGNORECASE,
)


class WriterAnswer(BaseModel):
    """What the writer model must return."""

    summary: str = Field(min_length=1, max_length=3000)
    reply_draft: str = Field(min_length=1, max_length=6000)


def write_texts(
    provider: Provider | None,
    report: Report,
    verdict: Verdict,
    confidence: float,
    reasons: list[str],
    checks: list[ClaimCheck],
    quality: QualitySignals,
    opinions: list[AgentOpinion],
) -> tuple[str, str, list[str]]:
    """Return (summary, reply_draft, notes). Notes explain any fallback to templates."""
    missing = missing_evidence(quality, opinions)
    summary = template_summary(verdict, confidence, reasons, checks, quality)
    reply = template_reply(verdict, checks, quality, missing)
    if provider is None:
        return summary, reply, []

    template = load_prompt("writer")
    values = {
        "title": neutralize_tags(report.title or "(no title)"),
        "verdict": verdict.value,
        "confidence": f"{confidence:.2f}",
        "reasons": "\n".join(f"- {r}" for r in reasons) or "- none",
        "claim_table": render_claim_table(checks),
        "opinions": "\n\n".join(render_opinion(o) for o in opinions) or "none",
        "missing": "\n".join(f"- {neutralize_tags(m)}" for m in missing) or "- nothing obvious",
    }
    try:
        answer, problems = complete_json(
            provider,
            fill(template.system, values),
            fill(template.user, values),
            WriterAnswer,
            max_tokens=WRITER_MAX_TOKENS,
        )
    except ProviderError as exc:
        return summary, reply, [f"writer agent failed ({redact(str(exc))[:200]}); used templates"]
    if answer is None:
        return summary, reply, ["writer output invalid; used templates: " + "; ".join(problems)]
    notes: list[str] = []
    ai_reply = answer.reply_draft.strip()
    if _RUDE_RE.search(ai_reply):
        notes.append("writer reply used dismissive wording; replaced with the template reply")
        ai_reply = reply
    return answer.summary.strip(), ai_reply, notes
