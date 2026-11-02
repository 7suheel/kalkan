"""The triage pipeline: deterministic checks first, then (optionally) the AI agents.

Order: load + sanitize -> extract claims -> check claims -> quality ->
(if AI is on) context -> analyst -> skeptic -> combine -> writer (or
templates) -> TriageResult. If an AI stage fails or the budget runs out, the
deterministic results are kept and the verdict becomes NEEDS_HUMAN.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from kalkan import __version__
from kalkan.agents.analyst import run_analyst
from kalkan.agents.skeptic import run_skeptic
from kalkan.agents.writer import write_texts
from kalkan.checks import RepoIndex, check_claims, compute_quality, extract_claims
from kalkan.context import DEFAULT_TOKEN_BUDGET, build_context
from kalkan.ingest import load_report, sanitize
from kalkan.llm import Budget, BudgetedProvider, Provider, ProviderError
from kalkan.models import AgentOpinion, TriageResult, Verdict
from kalkan.verdict import combine

log = logging.getLogger("kalkan")


@dataclass
class TriageSettings:
    """How to run one triage. ``provider=None`` means AI is off (--no-ai)."""

    provider: Provider | None = None
    model_label: str | None = None
    max_tokens: int | None = None
    context_tokens: int = DEFAULT_TOKEN_BUDGET


@dataclass
class TriageOutcome:
    """The result plus anything the caller should report (e.g. a provider error)."""

    result: TriageResult
    ai_error: str | None = None
    notes: list[str] = field(default_factory=list)


@contextmanager
def _stage(name: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        log.debug("stage %s took %.3fs", name, time.perf_counter() - start)


def triage(
    report_path: Path, repo: Path | RepoIndex, settings: TriageSettings | None = None
) -> TriageOutcome:
    """Triage one report against a repository. Raises ReportError/RepoError on bad input."""
    settings = settings or TriageSettings()
    with _stage("load"):
        report, findings = sanitize(load_report(report_path))
    index = repo if isinstance(repo, RepoIndex) else RepoIndex(repo)
    with _stage("extract"):
        claims = extract_claims(report)
    with _stage("check"):
        checks = check_claims(claims, index)
    with _stage("quality"):
        quality = compute_quality(claims, findings)

    budget = Budget.from_env(settings.max_tokens)
    provider: Provider | None = None
    if settings.provider is not None:
        provider = BudgetedProvider(settings.provider, budget)

    opinions: list[AgentOpinion] = []
    ai_error: str | None = None
    analyst = skeptic = None
    if provider is not None:
        try:
            with _stage("context"):
                ctx = build_context(report, checks, index, settings.context_tokens)
            with _stage("analyst"):
                analyst = run_analyst(provider, report, checks, quality, ctx)
            opinions.append(analyst)
            with _stage("skeptic"):
                skeptic = run_skeptic(provider, report, checks, quality, ctx, analyst)
            opinions.append(skeptic)
        except ProviderError as exc:
            ai_error = f"{type(exc).__name__}: {exc}"
            log.debug("AI stage failed: %s", ai_error)

    with _stage("combine"):
        if ai_error is None:
            verdict, confidence, reasons = combine(checks, quality, analyst, skeptic)
        else:
            _, _, det_reasons = combine(checks, quality, None, None)
            verdict, confidence = Verdict.NEEDS_HUMAN, 0.5
            reasons = [f"AI review did not finish ({ai_error}).", *det_reasons]

    with _stage("writer"):
        writer_provider = provider if ai_error is None else None
        summary, reply, notes = write_texts(
            writer_provider, report, verdict, confidence, reasons, checks, quality, opinions
        )
    if ai_error is not None:
        summary = (
            f"AI review did not finish ({ai_error}); the verdict was set to needs_human "
            f"and only deterministic checks are shown. {summary}"
        )

    result = TriageResult(
        report_id=report.id,
        verdict=verdict,
        confidence=round(confidence, 3),
        summary=summary,
        claim_checks=checks,
        quality=quality,
        opinions=opinions,
        reply_draft=reply,
        model=settings.model_label if provider is not None else None,
        tokens_used=budget.used,
        cost_usd_estimate=budget.cost_usd() if provider is not None else None,
        kalkan_version=__version__,
    )
    return TriageOutcome(result=result, ai_error=ai_error, notes=notes)
