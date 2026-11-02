"""Check extracted claims against a real repository. No AI is used here."""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable
from datetime import UTC, datetime

from kalkan.checks.extract import find_code_blocks
from kalkan.checks.repo import GrepHit, RepoIndex
from kalkan.models import CheckStatus, Claim, ClaimCheck, ClaimKind

SNIPPET_MATCH_RATIO = 0.85
MAX_SNIPPET_LINES = 60
MAX_LOCATIONS = 5

# Well-known library functions: absence from the repo says nothing about the report.
STDLIB_FUNCTIONS = frozenset(
    [
        "malloc",
        "calloc",
        "realloc",
        "free",
        "memcpy",
        "memmove",
        "memset",
        "memcmp",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strlen",
        "strcmp",
        "strncmp",
        "strchr",
        "strrchr",
        "strstr",
        "strdup",
        "strndup",
        "sprintf",
        "snprintf",
        "vsprintf",
        "vsnprintf",
        "printf",
        "fprintf",
        "scanf",
        "sscanf",
        "fscanf",
        "gets",
        "fgets",
        "puts",
        "fputs",
        "fopen",
        "fclose",
        "fread",
        "fwrite",
        "read",
        "write",
        "open",
        "close",
        "system",
        "popen",
        "exec",
        "execve",
        "execl",
        "execvp",
        "fork",
        "atoi",
        "atol",
        "strtol",
        "strtoul",
        "alloca",
        "abort",
        "exit",
        "assert",
        "eval",
        "print",
        "len",
        "input",
        "pickle",
        "loads",
        "dumps",
        "load",
        "dump",
        "setTimeout",
        "setInterval",
        "require",
        "JSON",
        "parse",
        "stringify",
        "innerHTML",
        "unserialize",
        "serialize",
        "include",
        "include_once",
        "require_once",
        "shell_exec",
        "passthru",
        "proc_open",
    ]
)

_SHELL_HINTS = re.compile(
    r"^\s*(?:\$ |# |>>> |curl\s|wget\s|python3?\s|node\s|php\s|ruby\s|perl\s|bash\s|sh\s|"
    r"nc\s|ncat\s|echo\s|printf\s|cat\s|\./|make\b|gcc\s|clang\s|go\s+run|cargo\s|npm\s|"
    r"pip\s|git\s|docker\s|GET\s/|POST\s/|PUT\s/|HEAD\s/|HTTP/)",
    re.IGNORECASE,
)
_SHELL_LANGS = frozenset(
    [
        "sh",
        "bash",
        "shell",
        "console",
        "zsh",
        "text",
        "txt",
        "http",
        "plaintext",
        "output",
        "log",
        "terminal",
        "ps",
        "powershell",
    ]
)
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,80}")
_SNIPPET_STOPWORDS = frozenset(
    [
        "return",
        "const",
        "static",
        "struct",
        "unsigned",
        "signed",
        "void",
        "char",
        "long",
        "short",
        "double",
        "float",
        "while",
        "break",
        "continue",
        "default",
        "sizeof",
        "typedef",
        "extern",
        "inline",
        "public",
        "private",
        "protected",
        "class",
        "import",
        "from",
        "function",
        "self",
        "None",
        "True",
        "False",
        "null",
        "true",
        "false",
        "else",
        "elif",
    ]
)


_DEFINITION_TEMPLATES = (
    # C / C++ / Java / C#: a type before the name, no '=' or '(' before it, not a prototype
    r"^\s{0,8}[A-Za-z_][\w\s\*&<>,:\[\]]{0,200}[\s\*&]NAME\s{0,4}\([^;]{0,400}$",
    # K&R / GNU style: return type on the previous line
    r"^NAME\s{0,4}\([^;]{0,400}$",
    r"^\s{0,8}#\s{0,4}define\s{1,8}NAME\b",
    # Python
    r"^\s{0,40}(?:async\s{1,4})?def\s{1,4}NAME\s{0,4}\(",
    # JS / TS / PHP
    r"\bfunction\s{0,4}\*?\s{0,4}NAME\s{0,4}\(",
    r"\b(?:const|let|var)\s{1,4}NAME\s{0,4}=\s{0,4}(?:async\s{0,4})?"
    r"(?:function\b|\(|[A-Za-z_]\w{0,40}\s{0,4}=>)",
    r"^\s{0,40}(?:(?:async|static|public|private|protected|get|set)\s{1,4}){0,4}"
    r"NAME\s{0,4}\([^)]{0,300}\)\s{0,4}(?::\s{0,4}[\w<>\[\]|, ]{1,80})?\s{0,4}\{",
    # Go
    r"^\s{0,8}func\s{1,4}(?:\([^)]{0,200}\)\s{0,4})?NAME\s{0,4}[\[(]",
    # Rust
    r"\bfn\s{1,4}NAME\s{0,4}[<(]",
    # Kotlin
    r"\bfun\s{1,4}(?:[\w.<>]{1,80}\.)?NAME\s{0,4}[<(]",
    # Ruby
    r"^\s{0,40}def\s{1,4}(?:self\.)?NAME\b",
)


def definition_patterns(name: str) -> list[re.Pattern[str]]:
    """Regexes that recognize a definition of ``name`` in common languages."""
    escaped = re.escape(name)
    return [re.compile(t.replace("NAME", escaped)) for t in _DEFINITION_TEMPLATES]


def _is_definition(hit: GrepHit, patterns: list[re.Pattern[str]]) -> bool:
    line = hit.text.rstrip()
    if line.endswith(";") and "{" not in line:
        return False
    return any(p.search(line) for p in patterns)


def _locs(items: list[str]) -> list[str]:
    return items[:MAX_LOCATIONS]


def check_file_path(claim: Claim, repo: RepoIndex, ref: str | None = None) -> ClaimCheck:
    """FILE_PATH: exists (exact or unique suffix match) or not found."""
    if RepoIndex.normalize_path(claim.value) is None:
        return ClaimCheck(
            claim=claim,
            status=CheckStatus.NOT_FOUND,
            evidence="path points outside the repository; not checked",
        )
    matches = repo.resolve_file(claim.value)
    if len(matches) == 1:
        exact = matches[0] == RepoIndex.normalize_path(claim.value)
        how = "exists" if exact else f"matches {matches[0]}"
        return ClaimCheck(
            claim=claim, status=CheckStatus.CONFIRMED, evidence=how, locations=[matches[0]]
        )
    if len(matches) > 1:
        return ClaimCheck(
            claim=claim,
            status=CheckStatus.NOT_CHECKABLE,
            evidence=f"ambiguous: {len(matches)} files match",
            locations=_locs(matches),
        )
    if ref is not None:
        at_ref = repo.resolve_file(claim.value, ref)
        if len(at_ref) == 1:
            return ClaimCheck(
                claim=claim,
                status=CheckStatus.CONFIRMED,
                evidence=f"exists at {ref} (not at HEAD)",
                locations=[at_ref[0]],
            )
    return ClaimCheck(
        claim=claim, status=CheckStatus.NOT_FOUND, evidence="no such file in the repository"
    )


def check_function(claim: Claim, repo: RepoIndex, ref: str | None = None) -> ClaimCheck:
    """FUNCTION: defined somewhere, only mentioned, or not found."""
    name = claim.value
    hits = repo.grep(name, word=True)
    if not hits and ref is not None:
        hits = repo.grep(name, word=True, ref=ref)
    patterns = definition_patterns(name)
    defs = [h.location for h in hits if _is_definition(h, patterns)]
    if defs:
        return ClaimCheck(
            claim=claim,
            status=CheckStatus.CONFIRMED,
            evidence=f"defined at {defs[0]}",
            locations=_locs(defs),
        )
    if hits:
        return ClaimCheck(
            claim=claim,
            status=CheckStatus.CONFIRMED,
            evidence=f"referenced at {hits[0].location} but no definition found "
            "(may be external or a macro)",
            locations=_locs([h.location for h in hits]),
        )
    if name in STDLIB_FUNCTIONS:
        return ClaimCheck(
            claim=claim,
            status=CheckStatus.NOT_CHECKABLE,
            evidence="well-known library function; not used in this repository",
        )
    return ClaimCheck(
        claim=claim,
        status=CheckStatus.NOT_FOUND,
        evidence="name does not appear anywhere in the repository",
    )


def check_line_ref(claim: Claim, repo: RepoIndex, ref: str | None = None) -> ClaimCheck:
    """LINE_REF: the file exists and the line is within the file length."""
    path_part, sep, num_part = claim.value.rpartition(":")
    if not sep or not path_part:
        return ClaimCheck(
            claim=claim,
            status=CheckStatus.NOT_CHECKABLE,
            evidence="line number without a file name",
        )
    line = int(num_part)
    head = repo.resolve_file(path_part)
    at_ref = repo.resolve_file(path_part, ref) if ref is not None else []
    # A report that names a version means its line numbers refer to that version.
    attempts: list[tuple[str | None, str]] = []
    if len(at_ref) == 1:
        attempts.append((ref, at_ref[0]))
    if len(head) == 1:
        attempts.append((None, head[0]))
    if not attempts:
        if len(head) > 1:
            return ClaimCheck(
                claim=claim,
                status=CheckStatus.NOT_CHECKABLE,
                evidence=f"ambiguous: {len(head)} files match",
            )
        return ClaimCheck(claim=claim, status=CheckStatus.NOT_FOUND, evidence="file not found")
    lengths: list[str] = []
    for at, rel in attempts:
        count = repo.line_count(rel, at)
        if count is None:
            continue
        where = "HEAD" if at is None else at
        if 1 <= line <= count:
            text = (repo.read_text(rel, at) or "").splitlines()[line - 1].strip()
            suffix = "" if at is None else f" (at {at})"
            return ClaimCheck(
                claim=claim,
                status=CheckStatus.CONFIRMED,
                evidence=f"line exists{suffix}: {text[:120]}",
                locations=[f"{rel}:{line}"],
            )
        lengths.append(f"{count} lines at {where}")
    if not lengths:
        return ClaimCheck(claim=claim, status=CheckStatus.NOT_CHECKABLE, evidence="file unreadable")
    return ClaimCheck(
        claim=claim,
        status=CheckStatus.CONTRADICTED,
        evidence=f"line {line} is past the end of the file ({', '.join(lengths)})",
    )


_MANIFESTS = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "package.json",
    "Cargo.toml",
    "CMakeLists.txt",
    "configure.ac",
    "meson.build",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "VERSION",
    "version.txt",
    "include/curl/curlver.h",
)


def _version_key(text: str) -> str:
    return ".".join(str(int(p)) for p in re.findall(r"\d+", text)[:4])


def find_version_tag(version: str, repo: RepoIndex) -> str | None:
    """Return the tag that names ``version`` (v1.2.0, 1.2.0, curl-8_4_0 ...), if any."""
    key = _version_key(version)
    if not key:
        return None
    for tag in repo.tags():
        if _version_key(tag) == key:
            return tag
    return None


def check_version(claim: Claim, repo: RepoIndex) -> ClaimCheck:
    """VERSION: matches a git tag or a version string in a common manifest file."""
    tag = find_version_tag(claim.value, repo)
    if tag is not None:
        return ClaimCheck(claim=claim, status=CheckStatus.CONFIRMED, evidence=f"tag {tag} exists")
    files = set(repo.files())
    for manifest in _MANIFESTS:
        if manifest not in files:
            continue
        text = repo.read_text(manifest) or ""
        for i, line in enumerate(text.splitlines(), start=1):
            if re.search(rf"(?<![\d.]){re.escape(claim.value)}(?![\d])", line):
                return ClaimCheck(
                    claim=claim,
                    status=CheckStatus.CONFIRMED,
                    evidence=f"found in {manifest}",
                    locations=[f"{manifest}:{i}"],
                )
    if not repo.tags():
        return ClaimCheck(
            claim=claim,
            status=CheckStatus.NOT_CHECKABLE,
            evidence="repository has no tags and no manifest mentions this version",
        )
    return ClaimCheck(
        claim=claim, status=CheckStatus.NOT_FOUND, evidence="no tag or manifest has this version"
    )


def check_commit(claim: Claim, repo: RepoIndex) -> ClaimCheck:
    """COMMIT: ``git cat-file -e`` succeeds."""
    if repo.commit_exists(claim.value):
        return ClaimCheck(claim=claim, status=CheckStatus.CONFIRMED, evidence="commit exists")
    return ClaimCheck(
        claim=claim,
        status=CheckStatus.NOT_FOUND,
        evidence="commit not found (the checkout may be shallow)",
    )


def check_cve(claim: Claim) -> ClaimCheck:
    """CVE_ID: format check only; nothing is looked up offline."""
    match = re.fullmatch(r"CVE-(\d{4})-(\d{4,7})", claim.value)
    year = int(match.group(1)) if match else 0
    if not match or year < 1999 or year > datetime.now(UTC).year + 1:
        return ClaimCheck(claim=claim, status=CheckStatus.CONTRADICTED, evidence="invalid CVE id")
    return ClaimCheck(
        claim=claim, status=CheckStatus.NOT_CHECKABLE, evidence="format ok; not checked offline"
    )


def looks_like_command(claim: Claim) -> bool:
    """True if a code block looks like a shell command, request or output, not repo code."""
    blocks = find_code_blocks(claim.quote)
    if blocks and blocks[0].language in _SHELL_LANGS:
        return True
    lines = [ln for ln in claim.value.splitlines() if ln.strip()]
    if not lines:
        return True
    shell_lines = sum(1 for ln in lines if _SHELL_HINTS.match(ln))
    return shell_lines * 2 >= len(lines)


def _squash_line(line: str) -> str:
    return "".join(line.split())


def check_snippet(claim: Claim, repo: RepoIndex, ref: str | None = None) -> ClaimCheck:
    """CODE_SNIPPET: whitespace-insensitive fuzzy match against the repository."""
    if looks_like_command(claim):
        return ClaimCheck(
            claim=claim,
            status=CheckStatus.NOT_CHECKABLE,
            evidence="looks like a command, request or output, not code from the repository",
        )
    snippet = [_squash_line(ln) for ln in claim.value.splitlines()[:MAX_SNIPPET_LINES]]
    snippet = [ln for ln in snippet if ln]
    idents = sorted(
        {m.group(0) for m in _IDENT_RE.finditer(claim.value)} - _SNIPPET_STOPWORDS,
        key=lambda s: (-len(s), s),
    )
    if not snippet or not idents:
        return ClaimCheck(
            claim=claim, status=CheckStatus.NOT_CHECKABLE, evidence="no identifiers to search for"
        )
    target = "\n".join(snippet)
    best: tuple[float, str] = (0.0, "")
    refs: list[str | None] = [None] if ref is None else [None, ref]
    for anchor in idents[:3]:
        anchor_idx = next((i for i, ln in enumerate(snippet) if anchor in ln), 0)
        for at in refs:
            for hit in repo.grep(anchor, ref=at, max_hits=200):
                text = repo.read_text(hit.path, at)
                if text is None:
                    continue
                found = _best_window(text, hit, anchor_idx, snippet, target, at)
                if found[0] > best[0]:
                    best = found
                if best[0] >= 0.999:
                    break
        if best[0] >= SNIPPET_MATCH_RATIO:
            break
    ratio, location = best
    if ratio >= SNIPPET_MATCH_RATIO:
        return ClaimCheck(
            claim=claim,
            status=CheckStatus.CONFIRMED,
            evidence=f"matches the code at {location} ({ratio:.0%} similar)",
            locations=[location.split(" ", 1)[0]],
        )
    hint = f"; closest is {location} ({ratio:.0%} similar)" if location and ratio >= 0.5 else ""
    return ClaimCheck(
        claim=claim,
        status=CheckStatus.NOT_FOUND,
        evidence=f"snippet not found in the repository{hint}",
    )


def _best_window(
    text: str,
    hit: GrepHit,
    anchor_idx: int,
    snippet: list[str],
    target: str,
    ref: str | None,
) -> tuple[float, str]:
    """Compare the snippet with windows of non-blank file lines aligned on the grep hit."""
    numbered = [(i, _squash_line(ln)) for i, ln in enumerate(text.splitlines(), start=1)]
    numbered = [(i, ln) for i, ln in numbered if ln]
    pos = next((k for k, (i, _) in enumerate(numbered) if i == hit.line), None)
    if pos is None:
        return (0.0, "")
    best = (0.0, "")
    for shift in range(-2, 3):
        start = max(0, pos - anchor_idx + shift)
        window = numbered[start : start + len(snippet)]
        if not window:
            continue
        candidate = "\n".join(ln for _, ln in window)
        matcher = difflib.SequenceMatcher(None, target, candidate, autojunk=False)
        if matcher.real_quick_ratio() < best[0] or matcher.quick_ratio() < best[0]:
            continue
        ratio = matcher.ratio()
        if ratio > best[0]:
            where = f"{hit.path}:{window[0][0]}" + (f" at {ref}" if ref else "")
            best = (ratio, where)
    return best


def check_claims(claims: list[Claim], repo: RepoIndex) -> list[ClaimCheck]:
    """Check every claim. If a claimed version is a tag, also look at the code at that tag."""
    ref: str | None = None
    for claim in claims:
        if claim.kind is ClaimKind.VERSION:
            ref = find_version_tag(claim.value, repo)
            if ref is not None:
                break

    checkers: dict[ClaimKind, Callable[[Claim], ClaimCheck]] = {
        ClaimKind.FILE_PATH: lambda c: check_file_path(c, repo, ref),
        ClaimKind.FUNCTION: lambda c: check_function(c, repo, ref),
        ClaimKind.LINE_REF: lambda c: check_line_ref(c, repo, ref),
        ClaimKind.VERSION: lambda c: check_version(c, repo),
        ClaimKind.COMMIT: lambda c: check_commit(c, repo),
        ClaimKind.CVE_ID: check_cve,
        ClaimKind.CODE_SNIPPET: lambda c: check_snippet(c, repo, ref),
    }
    results: list[ClaimCheck] = []
    for claim in claims:
        checker = checkers.get(claim.kind)
        if checker is None:
            results.append(
                ClaimCheck(
                    claim=claim,
                    status=CheckStatus.NOT_CHECKABLE,
                    evidence="present in the report; cannot be checked against code",
                )
            )
        else:
            results.append(checker(claim))
    return results
