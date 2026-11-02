"""Shared glue for the AI agents: prompt loading, rendering and post-validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from pydantic import BaseModel, Field

from kalkan.context import render_context
from kalkan.llm import Provider, complete_json
from kalkan.models import (
    AgentOpinion,
    ClaimCheck,
    CodeContext,
    QualitySignals,
    Report,
    Verdict,
)

DEFAULT_AGENT_MAX_TOKENS = 4000
DROPPED_CITATION_PENALTY = 0.2
NO_CITATION_CAP = 0.5
_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")
_TAG_RE = re.compile(r"<\s*(/?)\s*(untrusted_report|code_context|analyst_opinion)\b", re.I)


class AgentAnswer(BaseModel):
    """What an AI agent must return. The agent name is set by our code, not the model."""

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(max_length=4000)
    missing_evidence: list[str] = Field(default_factory=list, max_length=20)
    cited_locations: list[str] = Field(default_factory=list, max_length=40)


@dataclass(frozen=True)
class PromptTemplate:
    """A prompt split into its system and user parts."""

    system: str
    user: str


def prompts_dir() -> Path:
    """Directory with prompt templates: packaged copy first, then the repo's prompts/."""
    packaged = Path(__file__).resolve().parent.parent / "prompts"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[3] / "prompts"


@cache
def load_prompt(name: str) -> PromptTemplate:
    """Load ``prompts/<name>.md`` and split it at the ``## SYSTEM`` / ``## USER`` headings."""
    text = (prompts_dir() / f"{name}.md").read_text(encoding="utf-8")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    _, sep, rest = text.partition("## SYSTEM\n")
    system, sep2, user = rest.partition("## USER\n")
    if not sep or not sep2:
        raise ValueError(f"prompt {name!r} needs '## SYSTEM' and '## USER' sections")
    return PromptTemplate(system.strip(), user.strip())


def fill(template: str, values: dict[str, str]) -> str:
    """Replace ``{{name}}`` placeholders in one pass. Inserted values are never re-scanned."""

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            raise KeyError(f"missing prompt value {key!r}")
        return values[key]

    return _PLACEHOLDER_RE.sub(repl, template)


def neutralize_tags(text: str) -> str:
    """Stop untrusted text from opening or closing our delimiter tags."""
    return _TAG_RE.sub(lambda m: f"&lt;{m.group(1)}{m.group(2)}", text)


def render_report(report: Report) -> str:
    """The report text for the <untrusted_report> block (already sanitized)."""
    title = f"Title: {report.title}\n\n" if report.title else ""
    return neutralize_tags(title + report.body)


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def render_claim_table(checks: list[ClaimCheck]) -> str:
    """Claim checks as a compact list for prompts."""
    if not checks:
        return "(no checkable claims were found in the report)"
    lines = []
    for c in checks:
        locs = f" [{', '.join(c.locations[:3])}]" if c.locations else ""
        value = neutralize_tags(_clip(c.claim.value, 80))
        lines.append(
            f"- {c.status.value.upper()} {c.claim.kind.value} `{value}`: "
            f"{neutralize_tags(_clip(c.evidence, 160))}{locs}"
        )
    return "\n".join(lines)


def render_quality(quality: QualitySignals) -> str:
    """Quality signals as short lines for prompts."""
    flags = [
        f"affected version given: {'yes' if quality.has_affected_version else 'no'}",
        f"steps to reproduce: {'yes' if quality.has_repro_steps else 'no'}",
        f"proof of concept: {'yes' if quality.has_poc else 'no'}",
        f"impact statement: {'yes' if quality.has_impact else 'no'}",
        f"prompt injection suspected: {'YES' if quality.injection_suspected else 'no'}",
    ]
    return "\n".join(f"- {f}" for f in flags)


def render_code(ctx: CodeContext) -> str:
    """The code context for the <code_context> block."""
    return neutralize_tags(render_context(ctx))


def render_opinion(opinion: AgentOpinion) -> str:
    """An earlier agent's opinion, for the next agent."""
    missing = "; ".join(opinion.missing_evidence) or "none"
    cited = ", ".join(opinion.cited_locations) or "none"
    return (
        f"verdict: {opinion.verdict.value}\nconfidence: {opinion.confidence:.2f}\n"
        f"reasoning: {neutralize_tags(opinion.reasoning)}\n"
        f"missing evidence: {neutralize_tags(missing)}\ncited locations: {neutralize_tags(cited)}"
    )


def post_validate(answer: AgentAnswer, ctx: CodeContext, agent: str) -> AgentOpinion:
    """Drop citations that are not in the code context and adjust confidence.

    Each dropped citation lowers confidence by 0.2; an opinion that cites
    nothing valid is capped at 0.5.
    """
    kept = [loc for loc in answer.cited_locations if ctx.contains(loc)]
    dropped = len(answer.cited_locations) - len(kept)
    confidence = max(0.0, answer.confidence - DROPPED_CITATION_PENALTY * dropped)
    if not kept:
        confidence = min(confidence, NO_CITATION_CAP)
    reasoning = answer.reasoning
    if dropped:
        reasoning += f"\n[kalkan: removed {dropped} citation(s) not present in the code context]"
    return AgentOpinion(
        agent="analyst" if agent == "analyst" else "skeptic",
        verdict=answer.verdict,
        confidence=round(confidence, 3),
        reasoning=reasoning,
        missing_evidence=answer.missing_evidence,
        cited_locations=kept,
    )


def run_agent(
    provider: Provider,
    prompt_name: str,
    agent: str,
    values: dict[str, str],
    ctx: CodeContext,
    max_tokens: int = DEFAULT_AGENT_MAX_TOKENS,
) -> AgentOpinion:
    """Render a prompt, ask for JSON, and post-validate. Invalid output means NEEDS_HUMAN."""
    template = load_prompt(prompt_name)
    answer, problems = complete_json(
        provider,
        fill(template.system, values),
        fill(template.user, values),
        AgentAnswer,
        max_tokens=max_tokens,
    )
    if answer is None:
        return AgentOpinion(
            agent="analyst" if agent == "analyst" else "skeptic",
            verdict=Verdict.NEEDS_HUMAN,
            confidence=0.0,
            reasoning="The model did not return a valid answer after one repair attempt: "
            + "; ".join(problems)[:500],
        )
    return post_validate(answer, ctx, agent)
