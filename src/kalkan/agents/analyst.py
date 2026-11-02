"""Analyst agent: compares the report's claims with the code."""

from __future__ import annotations

from kalkan.agents.common import (
    DEFAULT_AGENT_MAX_TOKENS,
    render_claim_table,
    render_code,
    render_quality,
    render_report,
    run_agent,
)
from kalkan.llm import Provider
from kalkan.models import AgentOpinion, ClaimCheck, CodeContext, QualitySignals, Report


def analyst_values(
    report: Report, checks: list[ClaimCheck], quality: QualitySignals, ctx: CodeContext
) -> dict[str, str]:
    """Prompt values shared by the analyst and the skeptic."""
    return {
        "report": render_report(report),
        "claim_table": render_claim_table(checks),
        "quality": render_quality(quality),
        "code_context": render_code(ctx),
    }


def run_analyst(
    provider: Provider,
    report: Report,
    checks: list[ClaimCheck],
    quality: QualitySignals,
    ctx: CodeContext,
    max_tokens: int = DEFAULT_AGENT_MAX_TOKENS,
) -> AgentOpinion:
    """Ask the model for the analyst's opinion, backed by citations from the context."""
    values = analyst_values(report, checks, quality, ctx)
    return run_agent(provider, "analyst", "analyst", values, ctx, max_tokens)
