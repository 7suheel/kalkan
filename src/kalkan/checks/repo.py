"""Read-only access to a local git checkout.

All git calls use an argument list (never ``shell=True``), a timeout, and
``--`` separators so values from a report can never become options. Paths
are validated so nothing outside the repository can be read.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

GIT_TIMEOUT_S = 20
MAX_GREP_HITS = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
_HEX_RE = re.compile(r"[0-9a-fA-F]{7,40}")
_SAFE_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+-]{0,200}")


class RepoError(RuntimeError):
    """Raised when the repository is missing, invalid, or git fails badly."""


@dataclass(frozen=True)
class GrepHit:
    """One line matched by ``git grep``."""

    path: str
    line: int
    text: str

    @property
    def location(self) -> str:
        """The hit as ``path:line``."""
        return f"{self.path}:{self.line}"


class RepoIndex:
    """A cached, read-only view of a git repository."""

    def __init__(self, path: Path) -> None:
        candidate = Path(path).expanduser()
        if not candidate.is_dir():
            raise RepoError(f"repository path is not a directory: {path}")
        top = self._run_git(candidate.resolve(), ["rev-parse", "--show-toplevel"]).strip()
        if not top:
            raise RepoError(f"not a git repository: {path}")
        self.root = Path(top).resolve()
        self._files: dict[str, list[str]] = {}
        self._tags: list[str] | None = None
        self._text_cache: dict[tuple[str, str], str | None] = {}

    # ----- low level -------------------------------------------------------------------------

    @staticmethod
    def _run_git(cwd: Path, args: list[str], ok_codes: tuple[int, ...] = (0,)) -> str:
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "LC_ALL": "C",
        }
        try:
            proc = subprocess.run(
                [
                    "git",
                    # Never run commands configured in the repository (fsmonitor, pagers...).
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.quotepath=off",
                    "-c",
                    "core.pager=cat",
                    "--no-pager",
                    "-C",
                    str(cwd),
                    *args,
                ],
                capture_output=True,
                timeout=GIT_TIMEOUT_S,
                env=env,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RepoError("git is not installed or not on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise RepoError(f"git {args[0]} timed out after {GIT_TIMEOUT_S}s") from exc
        if proc.returncode not in ok_codes:
            if args[:1] == ["rev-parse"]:
                raise RepoError(f"not a git repository: {cwd}")
            err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            raise RepoError(f"git {args[0]} failed: {err[-1] if err else proc.returncode}")
        return proc.stdout.decode("utf-8", "replace")

    def git(self, *args: str, ok_codes: tuple[int, ...] = (0,)) -> str:
        """Run a read-only git command inside the repository."""
        return self._run_git(self.root, list(args), ok_codes)

    # ----- refs ------------------------------------------------------------------------------

    def tags(self) -> list[str]:
        """All tag names."""
        if self._tags is None:
            self._tags = [t for t in self.git("tag", "--list").splitlines() if t]
        return self._tags

    def is_tag(self, name: str) -> bool:
        """True if ``name`` is an existing tag."""
        return name in self.tags()

    def commit_exists(self, sha: str) -> bool:
        """True if ``sha`` names a commit in this repository."""
        if not _HEX_RE.fullmatch(sha):
            return False
        try:
            self.git("cat-file", "-e", f"{sha}^{{commit}}")
        except RepoError:
            return False
        return True

    def _check_ref(self, ref: str | None) -> None:
        if ref is not None and (not _SAFE_REF_RE.fullmatch(ref) or ".." in ref):
            raise RepoError(f"unsafe git ref: {ref!r}")

    # ----- files -----------------------------------------------------------------------------

    def files(self, ref: str | None = None) -> list[str]:
        """Tracked files at HEAD's working tree (``ref=None``) or at ``ref``."""
        self._check_ref(ref)
        key = ref or ""
        if key not in self._files:
            if ref is None:
                out = self.git("ls-files", "-z")
            else:
                out = self.git("ls-tree", "-r", "-z", "--name-only", ref, "--")
            self._files[key] = [f for f in out.split("\0") if f]
        return self._files[key]

    @staticmethod
    def normalize_path(raw: str) -> str | None:
        """Turn a path from a report into a safe repo-relative POSIX path, or None."""
        text = raw.strip().strip("`'\"").replace("\\", "/")
        while text.startswith("./"):
            text = text[2:]
        if not text or "\0" in text:
            return None
        parts = PurePosixPath(text).parts
        if any(p == ".." for p in parts):
            return None
        return text.lstrip("/") or None

    def resolve_file(self, raw: str, ref: str | None = None) -> list[str]:
        """Find tracked files matching ``raw`` exactly or by path suffix."""
        rel = self.normalize_path(raw)
        if rel is None:
            return []
        files = self.files(ref)
        if rel in files:
            return [rel]
        suffix = "/" + rel
        return [f for f in files if f.endswith(suffix)]

    def safe_path(self, rel: str) -> Path | None:
        """Absolute path for a tracked file, or None if it would leave the repository."""
        norm = self.normalize_path(rel)
        if norm is None:
            return None
        full = (self.root / norm).resolve()
        if not full.is_relative_to(self.root) or not full.is_file():
            return None
        return full

    def read_text(self, rel: str, ref: str | None = None) -> str | None:
        """Read a tracked file at the working tree or at ``ref``. None if unavailable."""
        self._check_ref(ref)
        key = (ref or "", rel)
        if key in self._text_cache:
            return self._text_cache[key]
        text: str | None = None
        if rel in set(self.files(ref)):
            if ref is None:
                full = self.safe_path(rel)
                if full is not None and full.stat().st_size <= MAX_FILE_BYTES:
                    text = full.read_bytes().decode("utf-8", "replace")
            else:
                try:
                    out = self.git("show", f"{ref}:{rel}")
                except RepoError:
                    out = None
                if out is not None and len(out) <= MAX_FILE_BYTES:
                    text = out
        self._text_cache[key] = text
        return text

    def line_count(self, rel: str, ref: str | None = None) -> int | None:
        """Number of lines in a tracked file, or None if it cannot be read."""
        text = self.read_text(rel, ref)
        if text is None:
            return None
        return len(text.splitlines())

    # ----- search ----------------------------------------------------------------------------

    def grep(
        self,
        needle: str,
        *,
        word: bool = False,
        ref: str | None = None,
        max_hits: int = MAX_GREP_HITS,
    ) -> list[GrepHit]:
        """Fixed-string search over tracked text files."""
        self._check_ref(ref)
        if not needle or "\n" in needle or "\0" in needle:
            return []
        args = ["grep", "-n", "-I", "--no-color", "-F", "--full-name"]
        if word:
            args.append("-w")
        args += ["-e", needle]
        if ref is not None:
            args.append(ref)
        args.append("--")
        out = self.git(*args, ok_codes=(0, 1))
        hits: list[GrepHit] = []
        prefix = f"{ref}:" if ref is not None else ""
        for line in out.splitlines():
            if prefix and line.startswith(prefix):
                line = line[len(prefix) :]
            path, sep1, rest = line.partition(":")
            num, sep2, text = rest.partition(":")
            if not (sep1 and sep2 and num.isdigit()):
                continue
            hits.append(GrepHit(path=path, line=int(num), text=text[:500]))
            if len(hits) >= max_hits:
                break
        return hits

    def recent_log(self, rel: str, n: int = 5) -> list[str]:
        """``git log -n N`` one-liners (hash, date, subject) for a tracked file."""
        if self.safe_path(rel) is None and rel not in self.files():
            return []
        out = self.git("log", f"-n{n}", "--format=%h %ad %s", "--date=short", "--", rel)
        return [line for line in out.splitlines() if line]
