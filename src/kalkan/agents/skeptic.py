"""Skeptic agent: argues against the analyst, in both directions."""

from __future__ import annotations

from kalkan.agents.analyst import analyst_values
from kalkan.agents.common import DEFAULT_AGENT_MAX_TOKENS, render_opinion, run_agent
from kalkan.llm import Provider
from kalkan.models import AgentOpinion, ClaimCheck, CodeContext, QualitySignals, Report


def run_skeptic(
    provider: Provider,
    report: Report,
    checks: list[ClaimCheck],
    quality: QualitySignals,
    ctx: CodeContext,
    analyst: AgentOpinion,
    max_tokens: int = DEFAULT_AGENT_MAX_TOKENS,
) -> AgentOpinion:
    """Ask the model to challenge the analyst's opinion."""
    values = analyst_values(report, checks, quality, ctx)
    values["analyst_opinion"] = render_opinion(analyst)
    return run_agent(provider, "skeptic", "skeptic", values, ctx, max_tokens)
