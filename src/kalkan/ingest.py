"""Reading and sanitizing incoming reports.

Reports are untrusted input. This module only reads local files: it never
executes, fetches or follows anything written in a report. Every regex here
is bounded so hostile input cannot make it backtrack for long.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import stat
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any

from kalkan.models import Report, SanitizerFindings

MAX_BODY_CHARS = 200 * 1024
"""Reports longer than this are truncated (and the truncation is noted)."""

MAX_FILE_BYTES = 5 * 1024 * 1024
"""Report files larger than this are rejected without being read."""

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,20000}={0,2}(?![A-Za-z0-9+/=])")
MAX_BASE64_BLOCKS = 50

SUPPORTED_SUFFIXES = frozenset({".md", ".markdown", ".txt", ".json"})

# Zero-width, bidi control and other invisible formatting characters.
_INVISIBLE_CHARS = frozenset(
    [
        "\u00ad",  # soft hyphen
        "\u180e",  # mongolian vowel separator
        *(chr(c) for c in range(0x200B, 0x2010)),  # zero-width space .. right-to-left mark
        *(chr(c) for c in range(0x202A, 0x202F)),  # bidi embeddings and overrides
        *(chr(c) for c in range(0x2060, 0x2065)),  # word joiner, invisible operators
        *(chr(c) for c in range(0x2066, 0x206A)),  # bidi isolates
        "\ufeff",  # zero-width no-break space / BOM
    ]
)
_TAG_BLOCK = range(0xE0000, 0xE0080)
"""Unicode tag characters: invisible, and can smuggle ASCII text to LLMs."""

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(?:ignore|disregard|forget|override)\s{1,10}(?:all\s{1,10}|any\s{1,10}|the\s{1,10})?"
        r"(?:previous|prior|above|earlier|preceding|your)\s{1,10}"
        r"(?:instructions?|prompts?|rules|directions|guidelines|context)",
        r"\byou\s{1,10}are\s{1,10}(?:now\s{1,10})?(?:an?\s{1,10})?(?:ai|llm|language\s{1,10}model|assistant|chatbot|"
        r"security\s{1,10}triager|triage\s{1,10}(?:bot|agent|assistant))\b",
        r"\b(?:mark|classify|label|rate|treat|flag)\s{1,10}(?:this|the|it|my)\s{0,10}(?:report|issue|"
        r"submission|finding|vulnerability)?\s{1,10}as\s{1,10}(?:a\s{1,10})?(?:valid|legit(?:imate)?|"
        r"critical|confirmed|high|true\s{1,10}positive)\b",
        r"\bsystem\s{1,10}prompt\b",
        r"\bnew\s{1,10}instructions?\s{0,10}:",
        r"\b(?:verdict|answer|respond|output)\s{0,10}(?:is|=|:|with)?\s{0,10}\"?likely[_ ]valid\b",
        r"</?\s{0,10}(?:system|assistant|user|instructions?|untrusted_report|code_context)\s{0,10}>",
        r"<\|im_(?:start|end)\|>|\[/?INST\]|<<\s{0,10}/?SYS\s{0,10}>>",
        r"(?m)^[ \t>]{0,20}(?:system|assistant)[ \t]{0,10}:",
        r"\bas\s{1,10}an?\s{1,10}(?:ai|llm|language\s{1,10}model)\b[^.\n]{0,80}\b(?:must|should|will)\b",
        # JSON that imitates Kalkan's own output schema
        r"\"(?:verdict|cited_locations|missing_evidence|reply_draft|confidence)\"\s{0,10}:",
    )
)

_TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]{0,20})\b([^<>]{0,2000})>")
_STYLE_ATTR_RE = re.compile(r"""style\s*=\s*(["'])([^"'<>]{0,1000})\1""", re.IGNORECASE)
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d]*[1-9])|"
    r"opacity\s*:\s*0(?![.\d]*[1-9])|"
    r"(?<![-\w])color\s*:\s*(?:white|#fff(?:fff)?\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))",
    re.IGNORECASE,
)
_HIDDEN_ATTR_RE = re.compile(r"(?:^|\s)(?:hidden|aria-hidden\s*=\s*[\"']?true)", re.IGNORECASE)
_DETAILS_RE = re.compile(r"<details\b[^<>]{0,500}>", re.IGNORECASE)
_SNIPPET_LEN = 200


class ReportError(ValueError):
    """Raised when a report file cannot be read or understood."""


def load_report(path: Path) -> Report:
    """Read a report from a .md, .txt or .json file.

    JSON may be a GitHub repository security advisory (``summary`` becomes the
    title and ``description`` the body) or a simple ``{"title": ..., "body": ...}``.
    Line endings are normalized and the body is capped at ``MAX_BODY_CHARS``.
    """
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        raise ReportError(f"unsupported report type {suffix!r}; use .md, .txt or .json")
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            # FIFOs and devices could block forever or never end.
            raise ReportError("report must be a regular file")
        if info.st_size > MAX_FILE_BYTES:
            raise ReportError(f"report file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
        with path.open("rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ReportError(f"report file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    except OSError as exc:
        raise ReportError(f"cannot read report: {exc.strerror or exc}") from exc
    text = raw.decode("utf-8", errors="replace")
    if suffix == ".json":
        report = _report_from_json(text, default_id=path.stem)
    else:
        report = Report(id=path.stem, source="file", body=text)
    return _normalize(report)


def _report_from_json(text: str, default_id: str) -> Report:
    """Build a Report from a GitHub advisory object or a ``{title, body}`` object."""
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"invalid JSON report: {exc.msg} (line {exc.lineno})") from exc
    except RecursionError as exc:
        raise ReportError("invalid JSON report: nested too deeply") from exc
    except ValueError as exc:
        # e.g. integers longer than Python's int string-conversion limit
        raise ReportError(f"invalid JSON report: {str(exc)[:120]}") from exc
    if not isinstance(data, dict):
        raise ReportError("JSON report must be an object")

    if "description" in data or "summary" in data or "ghsa_id" in data:
        return Report(
            id=_str_or(data.get("ghsa_id"), default_id),
            source="github_advisory",
            title=_str_or_none(data.get("summary")),
            body=_str_or(data.get("description"), ""),
            received_at=_parse_dt(data.get("submitted_at") or data.get("created_at")),
        )
    if "body" in data:
        return Report(
            id=_str_or(data.get("id"), default_id),
            source="file",
            title=_str_or_none(data.get("title")),
            body=_str_or(data.get("body"), ""),
            received_at=_parse_dt(data.get("received_at") or data.get("created_at")),
        )
    raise ReportError('JSON report needs "description"/"summary" (GitHub advisory) or "body"')


def _str_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _parse_dt(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _normalize(report: Report) -> Report:
    """Normalize line endings and cap the body size."""
    body = report.body.replace("\r\n", "\n").replace("\r", "\n")
    notes = list(report.sanitization_notes)
    if len(body) > MAX_BODY_CHARS:
        notes.append(
            f"report truncated from {len(body)} to {MAX_BODY_CHARS} characters; "
            "the rest was not analyzed"
        )
        body = body[:MAX_BODY_CHARS]
    title = report.title.replace("\r", " ").replace("\n", " ") if report.title else None
    return report.model_copy(update={"body": body, "title": title, "sanitization_notes": notes})


def sanitize(report: Report) -> tuple[Report, SanitizerFindings]:
    """Clean invisible characters and flag hidden or manipulative content.

    Hidden HTML and injection phrases are kept in the text (a human may need to
    see them) but recorded in the findings and in ``sanitization_notes``.
    """
    notes = list(report.sanitization_notes)
    body, removed, smuggled = _strip_invisible(report.body)
    title, t_removed, t_smuggled = _strip_invisible(report.title or "")
    removed += t_removed
    smuggled += t_smuggled
    if removed:
        notes.append(
            f"removed {removed} invisible or control characters "
            "(zero-width, bidi, tag or terminal control)"
        )
    if smuggled.strip():
        notes.append(f"hidden text found in Unicode tag characters: {_clip(smuggled)!r}")

    hidden = find_hidden_html(body)
    for fragment in hidden:
        notes.append(f"hidden HTML content: {_clip(fragment)!r}")

    decoded = decode_base64_blocks(body)
    phrases = find_injection_phrases(f"{title}\n{body}\n{smuggled}\n" + "\n".join(decoded))
    for text in decoded:
        if find_injection_phrases(text):
            notes.append(f"base64 block decodes to instructions: {_clip(text)!r}")
    if phrases:
        notes.append(
            "possible prompt injection aimed at AI triagers: " + ", ".join(repr(p) for p in phrases)
        )

    findings = SanitizerFindings(
        removed_invisible=removed,
        smuggled_text=smuggled.strip(),
        hidden_html=hidden,
        injection_phrases=phrases,
    )
    cleaned = report.model_copy(
        update={"body": body, "title": title or None, "sanitization_notes": notes}
    )
    return cleaned, findings


def _strip_invisible(text: str) -> tuple[str, int, str]:
    """Remove invisible and control characters (except newline and tab).

    Returns (clean text, count removed, ASCII smuggled in Unicode tag characters).
    """
    out: list[str] = []
    smuggled: list[str] = []
    removed = 0
    for ch in text:
        code = ord(ch)
        if ch in _INVISIBLE_CHARS:
            removed += 1
        elif code in _TAG_BLOCK:
            removed += 1
            if 0xE0020 <= code <= 0xE007E:
                smuggled.append(chr(code - 0xE0000))
        elif unicodedata.category(ch) == "Cf":
            # Other format characters are also invisible; drop them too.
            removed += 1
        elif unicodedata.category(ch) == "Cc" and ch not in "\n\t":
            # Control characters (ESC, NUL, BEL...) could drive the maintainer's terminal.
            removed += 1
        else:
            out.append(ch)
    return "".join(out), removed, "".join(smuggled)


def decode_base64_blocks(text: str) -> list[str]:
    """Decode base64-looking blocks that turn into mostly printable text."""
    out: list[str] = []
    for match in _BASE64_RE.finditer(text):
        if len(out) >= MAX_BASE64_BLOCKS:
            break
        token = match.group(0)
        if token.isalpha() or token.isdigit():
            continue  # plain words or numbers, not base64
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = raw.decode("utf-8", errors="replace")
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in decoded)
        if decoded and printable / len(decoded) > 0.9:
            out.append(decoded)
    return out


def find_injection_phrases(text: str) -> list[str]:
    """Return distinct phrases that look like instructions aimed at an AI triager."""
    found: list[str] = []
    seen: set[str] = set()
    for pattern in _INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            phrase = " ".join(match.group(0).split())[:_SNIPPET_LEN]
            key = phrase.lower()
            if phrase and key not in seen:
                seen.add(key)
                found.append(phrase)
    return found


def find_hidden_html(text: str) -> list[str]:
    """Find HTML comments, hidden elements and collapsed blocks that carry instructions."""
    fragments: list[str] = []
    fragments.extend(_html_comments(text))
    for match in _TAG_RE.finditer(text):
        attrs = match.group(2)
        style = _STYLE_ATTR_RE.search(attrs)
        hidden_by_style = bool(style and _HIDDEN_STYLE_RE.search(style.group(2)))
        if hidden_by_style or _HIDDEN_ATTR_RE.search(attrs):
            following = text[match.end() : match.end() + _SNIPPET_LEN].split("<", 1)[0]
            fragments.append(f"{match.group(0)[:100]}{following}")
    for match in _DETAILS_RE.finditer(text):
        end = text.find("</details>", match.end())
        block = text[match.end() : end if end != -1 else match.end() + 4000]
        if find_injection_phrases(block):
            fragments.append(f"<details> {block.strip()[:_SNIPPET_LEN]}")
    return [f for f in (_squash(f) for f in fragments) if f]


def _html_comments(text: str) -> list[str]:
    """Extract ``<!-- ... -->`` comments with a linear scan (no regex backtracking)."""
    comments: list[str] = []
    pos = 0
    while (start := text.find("<!--", pos)) != -1:
        end = text.find("-->", start + 4)
        if end == -1:
            comments.append(text[start : start + _SNIPPET_LEN + 4])
            break
        comments.append(text[start : min(end + 3, start + _SNIPPET_LEN + 7)])
        pos = end + 3
    return comments


def _squash(text: str) -> str:
    return " ".join(text.split())[:_SNIPPET_LEN]


def _clip(text: str, limit: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"
