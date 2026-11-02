"""Data models shared by every Kalkan stage.

These models are the common language between the reader, the checker, the
agents and the writer. Enums serialize as lowercase strings so JSON output is
stable and easy to read.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from kalkan import __version__

Confidence = float
"""A probability-like score between 0 and 1."""


class _Model(BaseModel):
    """Base model: forbid unknown fields so typos fail loudly."""

    model_config = ConfigDict(extra="forbid")


class Report(_Model):
    """A security report as received by the maintainer."""

    id: str = Field(description="Stable identifier, e.g. the file stem or GHSA id.")
    source: Literal["file", "github_advisory"] = "file"
    title: str | None = None
    body: str = Field(description="Report text. Untrusted input.")
    received_at: datetime | None = None
    sanitization_notes: list[str] = Field(default_factory=list)


class SanitizerFindings(_Model):
    """What the sanitizer noticed in a report. The original text is kept."""

    removed_invisible: int = Field(default=0, ge=0, description="Invisible characters removed.")
    smuggled_text: str = Field(default="", description="Text hidden in Unicode tag characters.")
    hidden_html: list[str] = Field(default_factory=list, description="Hidden HTML fragments.")
    injection_phrases: list[str] = Field(
        default_factory=list, description="Phrases that look aimed at an AI triager."
    )

    @property
    def injection_suspected(self) -> bool:
        """True when the report seems to try to steer an AI reader."""
        return bool(self.injection_phrases or self.smuggled_text)


class ClaimKind(StrEnum):
    """Kinds of factual claims Kalkan can extract from a report."""

    FILE_PATH = "file_path"
    FUNCTION = "function"
    LINE_REF = "line_ref"
    VERSION = "version"
    COMMIT = "commit"
    CVE_ID = "cve_id"
    CODE_SNIPPET = "code_snippet"
    POC_PRESENT = "poc_present"
    REPRO_STEPS = "repro_steps"
    IMPACT_STATEMENT = "impact_statement"


class Span(_Model):
    """Character offsets of a quote inside the report body."""

    start: int = Field(ge=0)
    end: int = Field(ge=0)


class Claim(_Model):
    """One factual claim found in the report."""

    kind: ClaimKind
    value: str = Field(description="Normalized value, e.g. a path or function name.")
    quote: str = Field(max_length=200, description="Exact text from the report.")
    span: Span


class CheckStatus(StrEnum):
    """Result of checking one claim against the repository."""

    CONFIRMED = "confirmed"
    CONTRADICTED = "contradicted"
    NOT_FOUND = "not_found"
    NOT_CHECKABLE = "not_checkable"


class ClaimCheck(_Model):
    """A claim plus what the deterministic checker found."""

    claim: Claim
    status: CheckStatus
    evidence: str = Field(description="Short human-readable explanation.")
    locations: list[str] = Field(default_factory=list, description='"path:line" entries.')


class Verdict(StrEnum):
    """Suggested outcome of triage. A human always makes the final call."""

    LIKELY_VALID = "likely_valid"
    NEEDS_EVIDENCE = "needs_evidence"
    LIKELY_INVALID = "likely_invalid"
    NEEDS_HUMAN = "needs_human"


class AgentOpinion(_Model):
    """The structured opinion of one AI agent."""

    agent: Literal["analyst", "skeptic"]
    verdict: Verdict
    confidence: Confidence = Field(ge=0.0, le=1.0)
    reasoning: str
    missing_evidence: list[str] = Field(default_factory=list)
    cited_locations: list[str] = Field(default_factory=list)


class QualitySignals(_Model):
    """Cheap signals about how complete and trustworthy a report looks."""

    has_affected_version: bool = False
    has_repro_steps: bool = False
    has_poc: bool = False
    has_impact: bool = False
    injection_suspected: bool = False
    notes: list[str] = Field(default_factory=list)


class TriageResult(_Model):
    """Everything Kalkan produced for one report."""

    report_id: str
    verdict: Verdict
    confidence: Confidence = Field(ge=0.0, le=1.0)
    summary: str
    claim_checks: list[ClaimCheck] = Field(default_factory=list)
    quality: QualitySignals = Field(default_factory=QualitySignals)
    opinions: list[AgentOpinion] = Field(default_factory=list)
    reply_draft: str = ""
    model: str | None = None
    tokens_used: int = Field(default=0, ge=0)
    cost_usd_estimate: float | None = None
    kalkan_version: str = __version__
