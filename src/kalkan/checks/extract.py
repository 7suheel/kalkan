"""Extract checkable claims from a report with regexes and simple heuristics.

No AI is used here. Every pattern is bounded (explicit repetition limits,
no nested quantifiers) so hostile input cannot cause catastrophic
backtracking.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from kalkan.models import Claim, ClaimKind, Report, Span

MAX_QUOTE = 200
MAX_SNIPPET_CHARS = 4000

CODE_EXTENSIONS = frozenset(
    [
        "c",
        "h",
        "cc",
        "cpp",
        "cxx",
        "hpp",
        "hh",
        "hxx",
        "py",
        "pyi",
        "js",
        "mjs",
        "cjs",
        "ts",
        "tsx",
        "jsx",
        "go",
        "rs",
        "java",
        "kt",
        "kts",
        "rb",
        "php",
        "cs",
        "swift",
        "m",
        "mm",
        "sh",
        "bash",
        "zsh",
        "pl",
        "pm",
        "lua",
        "scala",
        "zig",
        "dart",
        "ex",
        "exs",
        "erl",
        "hs",
        "ml",
        "clj",
        "sql",
        "html",
        "htm",
        "css",
        "scss",
        "vue",
        "svelte",
        "json",
        "yaml",
        "yml",
        "toml",
        "xml",
        "gradle",
        "cmake",
        "mk",
        "ini",
        "cfg",
        "conf",
    ]
)

_PATH_TOKEN_RE = re.compile(r"[\w./\-]{3,300}")
_FUNC_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{0,100}) ?\(\)")
_FUNC_BACKTICK_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]{1,100})`")
_FUNC_WORD_BEFORE_RE = re.compile(
    r"\b(?:function|method|func|routine|handler|macro)\s{1,5}`?([A-Za-z_][A-Za-z0-9_]{2,100})\b"
)
_FUNC_WORD_AFTER_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]{2,100})`?\s{1,5}(?:function|method|routine|handler|macro)\b"
)
_FUNC_CONTEXT_WORDS = ("function", "method", "func ", "routine", "handler", "callback", "macro")
_KEYWORDS = frozenset(
    [
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "catch",
        "else",
        "do",
        "try",
        "new",
        "delete",
        "typeof",
        "await",
        "yield",
        "the",
        "this",
        "that",
        "and",
        "when",
        "then",
        "with",
        "which",
        "from",
        "into",
    ]
)

_LINE_PATH_RE = re.compile(r"(?<![\w./\-])([\w./\-]{1,300}\.[A-Za-z0-9]{1,6}):(\d{1,7})\b")
_LINE_WORD_RE = re.compile(r"\b(?:on\s+|at\s+)?lines?\s{1,3}(\d{1,7})\b", re.IGNORECASE)
_LINE_L_RE = re.compile(r"#?\bL(\d{1,7})\b")

_VERSION_RE = re.compile(
    r"(?:\b(?:version|versions|release|tag|tested\s+on|affects?|affected)\s{0,3}:?\s{0,3}"
    r"v?(\d{1,6}(?:[._]\d{1,6}){1,3})\b)"
    r"|(?<![\w.])v(\d{1,6}(?:\.\d{1,6}){1,3})\b"
    r"|(?<![\w.])(\d{1,6}\.\d{1,6}\.\d{1,6})(?![\w.]*\d)",
    re.IGNORECASE,
)
_COMMIT_RE = re.compile(
    r"\bcommit(?:ted)?\b[^\n]{0,30}?\b([0-9a-f]{7,40})\b|/commit/([0-9a-f]{7,40})\b",
    re.IGNORECASE,
)
_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)

_POC_RE = re.compile(
    r"(?im)^ {0,3}#{1,6} {0,3}(?:proof[\s-]of[\s-]concept|poc|exploit)\b"
    r"|\bproof[\s-]of[\s-]concept\b|\bPoC\b|\bexploit\s(?:code|script)\b"
)
_REPRO_RE = re.compile(
    r"(?i)\b(?:steps?\s{1,3}to\s{1,3}reproduce|how\s{1,3}to\s{1,3}reproduce|"
    r"reproduction\s{1,3}steps|repro\s{1,3}steps|to\s{1,3}reproduce|reproducer)\b"
)
_IMPACT_RE = re.compile(
    r"(?im)^ {0,3}#{1,6} {0,3}impact\b"
    r"|\bimpact\s{0,3}:"
    r"|\ban?\s{1,3}(?:remote\s|local\s|unauthenticated\s|malicious\s)?attackers?\s{1,3}"
    r"(?:can|could|may|might|is\s{1,3}able\s{1,3}to)\b"
    r"|\ballows?\s{1,3}(?:an?\s{1,3})?(?:remote\s|local\s|unauthenticated\s)?attackers?\s{1,3}to\b"
    r"|\b(?:leads?|leading|could\s{1,3}lead|may\s{1,3}lead)\s{1,3}to\b"
)
_FENCE_RE = re.compile(r" {0,3}(`{3,}|~{3,}) {0,3}([\w+#.\-]{0,30})")
_LIST_ITEM_RE = re.compile(r"\s{0,12}(?:[-*+]|\d{1,3}[.)])\s")


@dataclass(frozen=True)
class CodeBlock:
    """A fenced or indented code block in the report."""

    start: int
    end: int
    code: str
    language: str


def find_code_blocks(text: str) -> list[CodeBlock]:
    """Find fenced (```) and indented code blocks with their character offsets."""
    blocks: list[CodeBlock] = []
    lines = text.split("\n")
    offsets: list[int] = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1

    i = 0
    prev_blank = True
    while i < len(lines):
        fence = _FENCE_RE.match(lines[i])
        if fence:
            marker = fence.group(1)
            j = i + 1
            while j < len(lines) and not lines[j].lstrip(" ").startswith(marker):
                j += 1
            code = "\n".join(lines[i + 1 : j])
            end = offsets[j] + len(lines[j]) if j < len(lines) else len(text)
            blocks.append(CodeBlock(offsets[i], end, code, fence.group(2).lower()))
            i = j + 1
            prev_blank = False
            continue
        line = lines[i]
        is_indented = line.startswith(("    ", "\t")) and line.strip() != ""
        if is_indented and prev_blank and not _LIST_ITEM_RE.match(line):
            j = i
            while j < len(lines) and (
                lines[j].startswith(("    ", "\t")) or lines[j].strip() == ""
            ):
                j += 1
            while j > i and lines[j - 1].strip() == "":
                j -= 1
            if j - i >= 2:
                code = "\n".join(ln[4:] if ln.startswith("    ") else ln[1:] for ln in lines[i:j])
                end = offsets[j - 1] + len(lines[j - 1])
                blocks.append(CodeBlock(offsets[i], end, code, ""))
                i = j
                prev_blank = False
                continue
        prev_blank = line.strip() == ""
        i += 1
    return blocks


def _in_blocks(pos: int, blocks: list[CodeBlock]) -> bool:
    return any(b.start <= pos < b.end for b in blocks)


def _claim(kind: ClaimKind, value: str, text: str, start: int, end: int) -> Claim:
    return Claim(
        kind=kind,
        value=value,
        quote=text[start:end][:MAX_QUOTE],
        span=Span(start=start, end=end),
    )


def _iter_paths(text: str, blocks: list[CodeBlock]) -> Iterator[tuple[str, int, int]]:
    """Yield (path, start, end) for things that look like source file paths."""
    for match in _PATH_TOKEN_RE.finditer(text):
        start, token = match.start(), match.group(0)
        if _in_blocks(start, blocks):
            continue
        if token.startswith("//"):
            # Part of a URL. Accept GitHub/GitLab blob links: .../blob/<ref>/<path>
            for marker in ("/blob/", "/tree/", "/-/blob/"):
                if marker in token:
                    after = token.split(marker, 1)[1]
                    _, _, path = after.partition("/")
                    token = path
                    start = match.start() + match.group(0).rfind(path)
                    break
            else:
                continue
        elif text[max(0, start - 3) : start].endswith(("://", "@")):
            continue
        token = token.rstrip(".-/")
        if not _has_code_extension(token):
            continue
        if "/" not in token and token.count(".") > 1 and not token.startswith("."):
            # foo.bar.c is unusual; domain-like tokens such as example.com.js are skipped
            continue
        yield token, start, start + len(token)


def _has_code_extension(token: str) -> bool:
    """True if the last path segment looks like ``name.ext`` with a known code extension."""
    base = token.rsplit("/", 1)[-1]
    stem, dot, ext = base.rpartition(".")
    return bool(dot and stem.strip(".-") and ext.lower() in CODE_EXTENSIONS)


def _looks_like_identifier(name: str) -> bool:
    return (
        "_" in name or any(c.isdigit() for c in name) or re.search(r"[a-z][A-Z]", name) is not None
    )


def _iter_functions(text: str, blocks: list[CodeBlock]) -> Iterator[tuple[str, int, int]]:
    for match in _FUNC_CALL_RE.finditer(text):
        yield match.group(1), match.start(), match.end()
    for match in _FUNC_BACKTICK_RE.finditer(text):
        window = text[max(0, match.start() - 50) : match.end() + 50].lower()
        if any(w in window for w in _FUNC_CONTEXT_WORDS):
            yield match.group(1), match.start(), match.end()
    for regex in (_FUNC_WORD_BEFORE_RE, _FUNC_WORD_AFTER_RE):
        for match in regex.finditer(text):
            if _looks_like_identifier(match.group(1)):
                yield match.group(1), match.start(), match.end()


def _nearest_path(paths: list[tuple[str, int, int]], start: int, end: int) -> str | None:
    """The file a line reference belongs to.

    A path right after the reference ("line 3 in foo.c") wins; otherwise the closest
    path mentioned before it (within 300 chars); otherwise one shortly after it.
    """
    right_after = [p for p in paths if 0 <= p[1] - end <= 12]
    if right_after:
        return right_after[0][0]
    before = [p for p in paths if p[2] <= start and start - p[2] <= 300]
    if before:
        return before[-1][0]
    after = [p for p in paths if p[1] >= end and p[1] - end <= 100]
    return after[0][0] if after else None


def extract_claims(report: Report) -> list[Claim]:
    """Extract deduplicated claims (with exact quotes and spans) from a report body."""
    text = report.body
    blocks = find_code_blocks(text)
    claims: list[Claim] = []
    seen: set[tuple[ClaimKind, str]] = set()

    def add(kind: ClaimKind, value: str, start: int, end: int) -> None:
        key = (kind, value.lower() if kind is not ClaimKind.CODE_SNIPPET else value)
        if value and key not in seen:
            seen.add(key)
            claims.append(_claim(kind, value, text, start, end))

    paths = list(_iter_paths(text, blocks))
    for path, start, end in paths:
        add(ClaimKind.FILE_PATH, path, start, end)

    for name, start, end in _iter_functions(text, blocks):
        if name.lower() in _KEYWORDS or _in_blocks(start, blocks):
            continue
        add(ClaimKind.FUNCTION, name, start, end)

    line_spans: list[tuple[int, int]] = []
    for match in _LINE_PATH_RE.finditer(text):
        if _in_blocks(match.start(), blocks):
            continue
        path = match.group(1).lstrip("./") if match.group(1).startswith("./") else match.group(1)
        add(ClaimKind.LINE_REF, f"{path}:{int(match.group(2))}", match.start(), match.end())
        line_spans.append((match.start(), match.end()))
    for regex in (_LINE_WORD_RE, _LINE_L_RE):
        for match in regex.finditer(text):
            if _in_blocks(match.start(), blocks):
                continue
            if any(s <= match.start() < e for s, e in line_spans):
                continue
            num = int(match.group(1))
            near = _nearest_path(paths, match.start(), match.end())
            value = f"{near}:{num}" if near else str(num)
            add(ClaimKind.LINE_REF, value, match.start(), match.end())

    for match in _VERSION_RE.finditer(text):
        raw = match.group(1) or match.group(2) or match.group(3)
        if raw is None or _in_blocks(match.start(), blocks):
            continue
        add(ClaimKind.VERSION, raw.replace("_", "."), match.start(), match.end())

    for match in _COMMIT_RE.finditer(text):
        sha = (match.group(1) or match.group(2)).lower()
        if any(c.isdigit() for c in sha):
            add(ClaimKind.COMMIT, sha, match.start(), match.end())

    for match in _CVE_RE.finditer(text):
        add(ClaimKind.CVE_ID, match.group(0).upper(), match.start(), match.end())

    for block in blocks:
        code = block.code.strip("\n")
        if code.strip():
            add(ClaimKind.CODE_SNIPPET, code[:MAX_SNIPPET_CHARS], block.start, block.end)

    for kind, regex in (
        (ClaimKind.POC_PRESENT, _POC_RE),
        (ClaimKind.REPRO_STEPS, _REPRO_RE),
        (ClaimKind.IMPACT_STATEMENT, _IMPACT_RE),
    ):
        found = regex.search(text)
        if found:
            add(kind, " ".join(found.group(0).lower().lstrip("# ").split()), *found.span())

    return claims
