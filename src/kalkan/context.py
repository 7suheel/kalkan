"""Build the code context the AI agents will see.

Agents never choose files: this module does, based on claims the
deterministic checker confirmed. Everything is read through RepoIndex, so
nothing outside the repository (no ``../`` paths, no symlinks leaving the
repo) can be read.
"""

from __future__ import annotations

from dataclasses import dataclass

from kalkan.checks.repo import RepoIndex
from kalkan.checks.verify import definition_patterns, find_version_tag
from kalkan.models import CheckStatus, ClaimCheck, ClaimKind, CodeContext, ContextSection, Report

DEFAULT_TOKEN_BUDGET = 12_000
AROUND_LINE = 40
AROUND_SNIPPET = 20
FILE_HEAD_LINES = 60
MAX_FUNCTION_LINES = 200
LOG_ENTRIES = 5


def estimate_tokens(text: str) -> int:
    """Rough token estimate: characters / 4."""
    return (len(text) + 3) // 4


@dataclass
class _Candidate:
    priority: int
    path: str
    start: int
    end: int
    reason: str


def _function_end(lines: list[str], start_idx: int) -> int:
    """Index of the last line of a function starting at ``start_idx`` (0-based)."""
    first = lines[start_idx]
    stripped = first.lstrip()
    if stripped.startswith(("def ", "async def ")) and first.rstrip().endswith(":"):
        indent = len(first) - len(stripped)
        end = start_idx
        for i in range(start_idx + 1, min(len(lines), start_idx + MAX_FUNCTION_LINES)):
            text = lines[i]
            if text.strip() and len(text) - len(text.lstrip()) <= indent:
                break
            end = i
        return end
    depth = 0
    seen_open = False
    for i in range(start_idx, min(len(lines), start_idx + MAX_FUNCTION_LINES)):
        depth += lines[i].count("{") - lines[i].count("}")
        seen_open = seen_open or "{" in lines[i]
        if seen_open and depth <= 0:
            return i
        if not seen_open and i - start_idx > 5:
            break
    return min(len(lines) - 1, start_idx + AROUND_LINE)


def _find_definition(lines: list[str], name: str) -> int | None:
    patterns = definition_patterns(name)
    for i, line in enumerate(lines):
        stripped = line.rstrip()
        if stripped.endswith(";") and "{" not in stripped:
            continue
        if any(p.search(stripped) for p in patterns):
            return i
    return None


def _split_location(location: str) -> tuple[str, int] | None:
    path, sep, num = location.rpartition(":")
    if not sep or not num.isdigit():
        return None
    return path, int(num)


class _Reader:
    """Reads files at the reported tag when possible, else at HEAD."""

    def __init__(self, repo: RepoIndex, ref: str | None) -> None:
        self.repo = repo
        self.ref = ref
        self.used_ref: dict[str, str | None] = {}

    def lines(self, path: str) -> list[str] | None:
        if self.ref is not None:
            text = self.repo.read_text(path, self.ref)
            if text is not None:
                self.used_ref[path] = self.ref
                return text.splitlines()
        text = self.repo.read_text(path)
        if text is None:
            return None
        self.used_ref[path] = None
        return text.splitlines()


def _candidates(checks: list[ClaimCheck], reader: _Reader) -> list[_Candidate]:
    out: list[_Candidate] = []
    for check in checks:
        if check.status is not CheckStatus.CONFIRMED:
            continue
        kind = check.claim.kind
        if kind is ClaimKind.FUNCTION:
            defined = check.evidence.startswith("defined")
            for loc in check.locations[:2]:
                split = _split_location(loc)
                if split is None:
                    continue
                path, line = split
                lines = reader.lines(path)
                if lines is None:
                    continue
                if defined:
                    idx = _find_definition(lines, check.claim.value)
                    if idx is None:
                        idx = min(line, len(lines)) - 1
                    end = _function_end(lines, idx)
                    out.append(
                        _Candidate(0, path, idx + 1, end + 1, f"function {check.claim.value}()")
                    )
                else:
                    out.append(
                        _Candidate(
                            2,
                            path,
                            max(1, line - AROUND_LINE // 2),
                            line + AROUND_LINE // 2,
                            f"use of {check.claim.value}",
                        )
                    )
        elif kind is ClaimKind.LINE_REF:
            for loc in check.locations[:1]:
                split = _split_location(loc)
                if split:
                    path, line = split
                    out.append(
                        _Candidate(
                            0,
                            path,
                            max(1, line - AROUND_LINE),
                            line + AROUND_LINE,
                            f"line {line} cited in report",
                        )
                    )
        elif kind is ClaimKind.CODE_SNIPPET:
            for loc in check.locations[:1]:
                split = _split_location(loc)
                if split:
                    path, line = split
                    n = len([ln for ln in check.claim.value.splitlines() if ln.strip()])
                    out.append(
                        _Candidate(
                            1,
                            path,
                            max(1, line - AROUND_SNIPPET),
                            line + n + AROUND_SNIPPET,
                            "code quoted in report",
                        )
                    )
        elif kind is ClaimKind.FILE_PATH:
            for loc in check.locations[:1]:
                out.append(_Candidate(3, loc, 1, FILE_HEAD_LINES, "file named in report"))
    return out


def _merge(cands: list[_Candidate]) -> list[_Candidate]:
    """Merge overlapping or adjacent ranges in the same file, keeping the best priority."""
    # File-head candidates are only useful when nothing else from that file is included.
    focused = {c.path for c in cands if c.priority < 3}
    cands = [c for c in cands if c.priority < 3 or c.path not in focused]
    by_path: dict[str, list[_Candidate]] = {}
    for c in cands:
        by_path.setdefault(c.path, []).append(c)
    merged: list[_Candidate] = []
    for path, items in by_path.items():
        items.sort(key=lambda c: c.start)
        current = items[0]
        for nxt in items[1:]:
            if nxt.start <= current.end + 3:
                reasons = (
                    current.reason
                    if nxt.reason in current.reason
                    else (f"{current.reason}; {nxt.reason}")
                )
                current = _Candidate(
                    min(current.priority, nxt.priority),
                    path,
                    current.start,
                    max(current.end, nxt.end),
                    reasons,
                )
            else:
                merged.append(current)
                current = nxt
        merged.append(current)
    return sorted(merged, key=lambda c: (c.priority, c.path, c.start))


def build_context(
    report: Report,
    claim_checks: list[ClaimCheck],
    repo: RepoIndex,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
) -> CodeContext:
    """Pick relevant code for the agents, most relevant first, within ``token_budget``."""
    del report  # selection is driven by checked claims, not by raw report text
    ref: str | None = None
    for check in claim_checks:
        if check.claim.kind is ClaimKind.VERSION and check.status is CheckStatus.CONFIRMED:
            ref = find_version_tag(check.claim.value, repo)
            if ref:
                break
    reader = _Reader(repo, ref)
    candidates = _merge(_candidates(claim_checks, reader))

    ctx = CodeContext(ref=ref)
    used = 0
    for cand in candidates:
        lines = reader.lines(cand.path)
        if not lines:
            continue
        start = max(1, cand.start)
        end = min(len(lines), cand.end)
        if start > end:
            continue
        section = ContextSection(
            path=cand.path,
            start_line=start,
            end_line=end,
            ref=reader.used_ref.get(cand.path),
            reason=cand.reason,
            code="\n".join(lines[start - 1 : end]),
        )
        log = ctx.logs.get(cand.path)
        if log is None:
            log = repo.recent_log(cand.path, LOG_ENTRIES)
        cost = estimate_tokens(render_section(section)) + (
            0 if cand.path in ctx.logs else estimate_tokens("\n".join(log))
        )
        if used + cost > token_budget:
            ctx.omitted.append(f"{cand.path}:{start}-{end} ({cand.reason}; ~{cost} tokens)")
            continue
        used += cost
        ctx.sections.append(section)
        ctx.logs.setdefault(cand.path, log)
    ctx.token_estimate = used
    return ctx


def render_section(section: ContextSection) -> str:
    """One section with numbered lines so agents can cite ``path:line``."""
    where = f", at tag {section.ref}" if section.ref else ""
    header = (
        f"=== {section.path} lines {section.start_line}-{section.end_line}{where}"
        f" ({section.reason}) ==="
    )
    width = len(str(section.end_line))
    body = "\n".join(
        f"{n:>{width}} | {line}"
        for n, line in enumerate(section.code.split("\n"), start=section.start_line)
    )
    return f"{header}\n{body}\n=== end {section.path} ==="


def render_context(ctx: CodeContext) -> str:
    """Render the whole context as plain text with clear delimiters."""
    parts: list[str] = []
    if ctx.ref:
        parts.append(
            f"Code is shown at tag {ctx.ref}, the version named in the report "
            "(unless a section says otherwise)."
        )
    else:
        parts.append("Code is shown at the current checkout (HEAD).")
    if not ctx.sections:
        parts.append("No code could be matched to the report's claims.")
    for section in ctx.sections:
        parts.append(render_section(section))
    for path, log in ctx.logs.items():
        if log:
            parts.append(f"--- recent commits touching {path} (newest first, at HEAD) ---")
            parts.extend(log)
    if ctx.omitted:
        parts.append("--- omitted to stay within the token budget ---")
        parts.extend(ctx.omitted)
    return "\n".join(parts)
