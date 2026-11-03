"""Typer command-line interface for Kalkan."""

from __future__ import annotations

import json
import logging
import os
from enum import StrEnum
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

import typer

from kalkan import __version__
from kalkan.checks import RepoError, RepoIndex, check_claims, compute_quality, extract_claims
from kalkan.ingest import ReportError, load_report, sanitize
from kalkan.llm import ConfigError, ProviderError, build_provider, resolve_settings
from kalkan.llm.config import NO_AI_MESSAGE, redact_url
from kalkan.models import ClaimCheck, QualitySignals, Report, SanitizerFindings, TriageResult
from kalkan.pipeline import TriageSettings
from kalkan.pipeline import triage as run_triage
from kalkan.report_render import md_cell, render_json, render_markdown

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_PROVIDER_ERROR = 3

app = typer.Typer(
    name="kalkan",
    help="AI-assisted triage for incoming security reports. Kalkan only suggests; you decide.",
    no_args_is_help=True,
    add_completion=False,
)

ReportArg = Annotated[Path, typer.Argument(help="Report file (.md, .txt or .json).")]
ModelOpt = Annotated[
    str | None,
    typer.Option(
        "--model",
        help="provider:model, e.g. ollama:qwen2.5-coder:7b or anthropic:<model-id>. "
        "Overrides KALKAN_MODEL.",
    ),
]
BaseUrlOpt = Annotated[
    str | None,
    typer.Option("--base-url", help="Endpoint for OpenAI-compatible providers."),
]
RepoOpt = Annotated[Path, typer.Option("--repo", help="Local git checkout of the project.")]


def _version_callback(value: bool) -> None:
    """Print the version and exit when --version is given."""
    if value:
        typer.echo(f"kalkan {__version__}")
        raise typer.Exit()


def _fail(message: str, code: int = EXIT_BAD_INPUT) -> typer.Exit:
    """Print an error to stderr and return an Exit to raise."""
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(code)


def _read(report_path: Path) -> tuple[Report, SanitizerFindings]:
    """Load and sanitize a report, turning input errors into exit code 2."""
    try:
        return sanitize(load_report(report_path))
    except ReportError as exc:
        raise _fail(str(exc)) from exc


def _open_repo(repo_path: Path) -> RepoIndex:
    """Open a repository, turning errors into exit code 2."""
    try:
        return RepoIndex(repo_path)
    except RepoError as exc:
        raise _fail(str(exc)) from exc


def _clip(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."


def format_checks(checks: list[ClaimCheck], quality: QualitySignals) -> str:
    """Render claim checks and quality signals as a plain-text table."""
    rows = [("STATUS", "KIND", "CLAIM", "EVIDENCE")]
    for c in checks:
        rows.append(
            (
                c.status.value,
                c.claim.kind.value,
                _clip(c.claim.value, 40),
                _clip(c.evidence, 70),
            )
        )
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    lines = [
        f"{r[0]:<{widths[0]}}  {r[1]:<{widths[1]}}  {r[2]:<{widths[2]}}  {r[3]}".rstrip()
        for r in rows
    ]
    if len(rows) == 1:
        lines.append("(no checkable claims found)")
    lines.append("")
    lines.append("Quality signals:")
    flags = [
        ("affected version", quality.has_affected_version),
        ("repro steps", quality.has_repro_steps),
        ("proof of concept", quality.has_poc),
        ("impact", quality.has_impact),
    ]
    for label, value in flags:
        lines.append(f"  [{'x' if value else ' '}] {label}")
    if quality.injection_suspected:
        lines.append("  [!] prompt injection suspected")
    for note in quality.notes:
        lines.append(f"  - {note}")
    return "\n".join(lines)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Kalkan compares a security report with your code and drafts a verdict and a reply."""


class OutputFormat(StrEnum):
    """Output formats for triage results."""

    md = "md"
    json = "json"


REPORT_SUFFIXES = (".md", ".markdown", ".txt", ".json")


def _setup_ai(
    model: str | None, base_url: str | None, no_ai: bool, max_tokens: int | None
) -> TriageSettings:
    """Resolve AI settings and announce on stderr who will see the report."""
    if no_ai:
        typer.echo("AI off (--no-ai): only deterministic checks will run.", err=True)
        return TriageSettings(max_tokens=max_tokens)
    try:
        llm = resolve_settings(model, base_url)
        if llm is None:
            typer.echo(NO_AI_MESSAGE, err=True)
            return TriageSettings(max_tokens=max_tokens)
        provider = build_provider(llm)
    except ConfigError as exc:
        raise _fail(str(exc)) from exc
    typer.echo(f"AI on: the report will be sent to {llm.describe()}.", err=True)
    return TriageSettings(provider=provider, model_label=llm.describe(), max_tokens=max_tokens)


def _render(result: TriageResult, fmt: OutputFormat) -> str:
    return render_json(result) if fmt is OutputFormat.json else render_markdown(result)


def write_private(path: Path, text: str) -> None:
    """Write a file readable only by the current user (reports may be private)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_NOFOLLOW: never write through a symlink planted at the output path.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise _fail(f"cannot write {path}: {exc.strerror or exc}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    # Never log HTTP traffic: request logs could include headers or report text.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


NoAiOpt = Annotated[bool, typer.Option("--no-ai", help="Run deterministic checks only.")]
FormatOpt = Annotated[OutputFormat, typer.Option("--format", help="Output format.")]
MaxTokensOpt = Annotated[
    int | None,
    typer.Option("--max-tokens", min=1000, help="Token budget per report (default 60000)."),
]
VerboseOpt = Annotated[bool, typer.Option("--verbose", "-v", help="Log stage timings.")]


@app.command()
def triage(
    report: ReportArg,
    repo: RepoOpt = Path(),
    model: ModelOpt = None,
    base_url: BaseUrlOpt = None,
    no_ai: NoAiOpt = False,
    fmt: FormatOpt = OutputFormat.md,
    out: Annotated[
        Path | None, typer.Option("--out", help="Write to this file instead of stdout.")
    ] = None,
    max_tokens: MaxTokensOpt = None,
    verbose: VerboseOpt = False,
) -> None:
    """Triage a security report against a local repository.

    Exit codes: 0 done, 2 bad input, 3 provider error (partial output is still written).
    """
    _configure_logging(verbose)
    settings = _setup_ai(model, base_url, no_ai, max_tokens)
    try:
        outcome = run_triage(report, repo, settings)
    except (ReportError, RepoError) as exc:
        raise _fail(str(exc)) from exc
    text = _render(outcome.result, fmt)
    if out is None:
        typer.echo(text, nl=False)
    else:
        write_private(out, text)
        typer.echo(f"Wrote {out}", err=True)
    for note in outcome.notes:
        typer.echo(f"note: {note}", err=True)
    if outcome.ai_error:
        raise _fail(f"AI stage failed: {outcome.ai_error}", EXIT_PROVIDER_ERROR)


@app.command("triage-dir")
def triage_dir(
    folder: Annotated[Path, typer.Argument(help="Folder with report files.")],
    repo: RepoOpt = Path(),
    model: ModelOpt = None,
    base_url: BaseUrlOpt = None,
    no_ai: NoAiOpt = False,
    fmt: FormatOpt = OutputFormat.md,
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Output folder (default: <folder>/kalkan-results)."),
    ] = None,
    max_tokens: MaxTokensOpt = None,
    verbose: VerboseOpt = False,
) -> None:
    """Triage every report in a folder; write one result per report and an index.md."""
    _configure_logging(verbose)
    if not folder.is_dir():
        raise _fail(f"not a folder: {folder}")
    out_dir = out or folder / "kalkan-results"
    reports = sorted(
        p
        for p in folder.iterdir()
        if p.is_file() and p.suffix.lower() in REPORT_SUFFIXES and p.name != "index.md"
    )
    if not reports:
        raise _fail(f"no .md, .txt or .json reports in {folder}")
    settings = _setup_ai(model, base_url, no_ai, max_tokens)
    index = _open_repo(repo)
    rows = ["| Report | Verdict | Confidence | Result |", "| --- | --- | --- | --- |"]
    exit_code = EXIT_OK
    for path in reports:
        try:
            outcome = run_triage(path, index, settings)
        except ReportError as exc:
            rows.append(f"| {md_cell(path.name)} | error | - | {md_cell(str(exc))} |")
            exit_code = max(exit_code, EXIT_BAD_INPUT)
            continue
        except RepoError as exc:
            raise _fail(str(exc)) from exc
        result = outcome.result
        target = out_dir / f"{path.stem}.{fmt.value}"
        write_private(target, _render(result, fmt))
        rows.append(
            f"| {md_cell(path.name)} | {result.verdict.value} | {result.confidence:.0%} "
            f"| [{md_cell(target.name)}]({quote(target.name)}) |"
        )
        if outcome.ai_error:
            exit_code = EXIT_PROVIDER_ERROR
            typer.echo(f"{path.name}: AI stage failed: {outcome.ai_error}", err=True)
        typer.echo(f"{path.name}: {result.verdict.value}", err=True)
    index_text = "# Kalkan triage results\n\n" + "\n".join(rows) + "\n"
    write_private(out_dir / "index.md", index_text)
    typer.echo(f"Wrote {len(reports)} result(s) and index.md to {out_dir}", err=True)
    if exit_code:
        raise typer.Exit(exit_code)


@app.command()
def check(report: ReportArg, repo: RepoOpt = Path()) -> None:
    """Check the report's claims against the repository without any AI (the --no-ai core)."""
    loaded, findings = _read(report)
    index = _open_repo(repo)
    claims = extract_claims(loaded)
    try:
        checks = check_claims(claims, index)
    except RepoError as exc:
        raise _fail(str(exc)) from exc
    typer.echo(format_checks(checks, compute_quality(claims, findings)))


@app.command()
def context(
    report: ReportArg,
    repo: RepoOpt = Path(),
    token_budget: Annotated[
        int, typer.Option("--token-budget", min=500, help="Approximate token budget.")
    ] = 12_000,
) -> None:
    """Debug: print the code context the AI agents would see for this report."""
    from kalkan.context import build_context, render_context

    loaded, _ = _read(report)
    index = _open_repo(repo)
    try:
        checks = check_claims(extract_claims(loaded), index)
        ctx = build_context(loaded, checks, index, token_budget=token_budget)
    except RepoError as exc:
        raise _fail(str(exc)) from exc
    typer.echo(render_context(ctx))
    typer.echo(f"\n(~{ctx.token_estimate} tokens of {token_budget})")


@app.command()
def inspect(report: ReportArg) -> None:
    """Show sanitization notes and detected injection phrases for a report."""
    loaded, findings = _read(report)
    typer.echo(f"Report: {loaded.id} ({loaded.source})")
    if loaded.title:
        typer.echo(f"Title: {loaded.title}")
    typer.echo(f"Length: {len(loaded.body)} characters")
    typer.echo("")
    typer.echo("Sanitization notes:")
    for note in loaded.sanitization_notes or ["(none)"]:
        typer.echo(f"  - {note}")
    typer.echo("")
    typer.echo("Injection phrases:")
    for phrase in findings.injection_phrases or ["(none)"]:
        typer.echo(f"  - {phrase}")
    typer.echo("")
    status = "SUSPECTED" if findings.injection_suspected else "not detected"
    typer.echo(f"Prompt injection: {status}")


@app.command()
def fetch(
    repo: Annotated[str, typer.Option("--repo", help="GitHub repository as owner/name.")],
    out: Annotated[Path, typer.Option("--out", help="Folder for the reports.")] = Path("reports"),
    state: Annotated[
        str, typer.Option("--state", help="Advisory state: triage, draft, published or closed.")
    ] = "triage",
) -> None:
    """Download private vulnerability reports from GitHub to triage them locally."""
    from kalkan.github import (
        PRIVACY_WARNING,
        STATES,
        GitHubError,
        fetch_advisories,
        get_token,
        save_reports,
    )

    if state not in STATES:
        raise _fail(f"invalid state {state!r}; choose one of {', '.join(STATES)}")
    typer.echo(PRIVACY_WARNING, err=True)
    try:
        advisories = fetch_advisories(repo, get_token(), state)
    except GitHubError as exc:
        raise _fail(str(exc), EXIT_PROVIDER_ERROR) from exc
    written = save_reports(advisories, out)
    typer.echo(f"Saved {len(written)} report(s) to {out}/")
    if written:
        typer.echo(f"Next: kalkan triage-dir {out} --repo .")


@app.command()
def doctor(model: ModelOpt = None, base_url: BaseUrlOpt = None) -> None:
    """Show the configured AI provider and check that it answers. Prints no secrets."""
    try:
        settings = resolve_settings(model, base_url)
    except ConfigError as exc:
        raise _fail(str(exc)) from exc
    if settings is None:
        typer.echo(NO_AI_MESSAGE)
        return
    typer.echo(f"Provider: {settings.provider}")
    typer.echo(f"Model:    {settings.model}")
    if settings.base_url:
        typer.echo(f"Endpoint: {redact_url(settings.base_url)}")
    typer.echo(f"API key:  {'set' if settings.api_key else 'not set'}")
    try:
        provider = build_provider(settings)
        response = provider.complete(
            "You are a connectivity check. Reply with one word.", "ping", max_tokens=512
        )
    except (ConfigError, ProviderError) as exc:
        raise _fail(f"provider check failed: {exc}", EXIT_PROVIDER_ERROR) from exc
    typer.echo(
        f"OK: {response.model} answered "
        f"({response.input_tokens} input / {response.output_tokens} output tokens)."
    )


@app.command()
def schema() -> None:
    """Print the JSON Schema of TriageResult."""
    typer.echo(json.dumps(TriageResult.model_json_schema(), indent=2))
