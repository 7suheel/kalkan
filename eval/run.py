"""Run Kalkan over the labeled curl reports and measure accuracy.

For each report, the curl checkout is moved (in a separate git worktree) to
the commit just before the report: the parent of the fix commit for CVEs, or
the last commit before the report date otherwise. The pipeline runs with the
given model and always in --no-ai mode too, and the results are compared
with the labels.

Usage:
    uv run python -m eval.run --model ollama:qwen2.5-coder:7b --limit 20
    uv run python -m eval.run --no-ai --repo ../curl
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.common import DATA_DIR, MANIFEST, RESULTS_DIR, ManifestRow, read_manifest
from kalkan.checks import RepoIndex
from kalkan.ingest import ReportError
from kalkan.llm import build_provider, resolve_settings
from kalkan.models import Verdict
from kalkan.pipeline import TriageSettings, triage

FLAGGED = {Verdict.LIKELY_INVALID.value, Verdict.NEEDS_EVIDENCE.value}


@dataclass
class Record:
    """The outcome for one report in one mode."""

    id: str
    label: str
    mode: str
    verdict: str
    confidence: float
    tokens: int
    seconds: float
    commit: str
    error: str = ""


def select_rows(rows: list[ManifestRow], data_dir: Path, limit: int) -> list[ManifestRow]:
    """Rows with a downloaded text; with a limit, alternate invalid/valid for balance."""
    have = [r for r in rows if (data_dir / f"{r.id}.md").exists()]
    if not limit:
        return have
    invalid = [r for r in have if r.label == "invalid"]
    valid = [r for r in have if r.label == "valid"]
    picked: list[ManifestRow] = []
    while len(picked) < limit and (invalid or valid):
        for pool in (invalid, valid):
            if pool and len(picked) < limit:
                picked.append(pool.pop(0))
    return picked


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=300, check=True
    )
    return out.stdout.strip()


def report_date(row: ManifestRow, data_dir: Path) -> str:
    """Published date from the manifest, or the submission date saved by fetch.py."""
    if row.published_at:
        return row.published_at
    meta = data_dir / f"{row.id}.meta.json"
    if meta.exists():
        data = json.loads(meta.read_text(encoding="utf-8"))
        return str(data.get("submitted_at") or "")
    return ""


def commit_for(row: ManifestRow, repo: Path, data_dir: Path) -> str:
    """The commit to check out for this report."""
    if row.ref and re.fullmatch(r"[0-9a-f]{7,40}\^?", row.ref):
        try:
            return _git(repo, "rev-parse", "--verify", f"{row.ref}^{{commit}}")
        except subprocess.CalledProcessError:
            pass
    date = report_date(row, data_dir)
    if date:
        sha = _git(repo, "rev-list", "-n1", f"--before={date}", "HEAD")
        if sha:
            return sha
    return _git(repo, "rev-parse", "HEAD")


@contextmanager
def worktree(repo: Path) -> Iterator[Path]:
    """A temporary detached worktree of ``repo``, removed afterwards."""
    tmp = Path(tempfile.mkdtemp(prefix="kalkan-eval-"))
    path = tmp / "wt"
    _git(repo, "worktree", "add", "--detach", "-q", str(path), "HEAD")
    try:
        yield path
    finally:
        try:
            _git(repo, "worktree", "remove", "--force", str(path))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def compute_metrics(records: list[Record]) -> dict[str, Any]:
    """Accuracy numbers for one mode."""
    invalid = [r for r in records if r.label == "invalid" and not r.error]
    valid = [r for r in records if r.label == "valid" and not r.error]
    done = [r for r in records if not r.error]
    wrong = [r.id for r in valid if r.verdict == Verdict.LIKELY_INVALID.value]

    def share(part: int, whole: int) -> float:
        return round(part / whole, 3) if whole else 0.0

    return {
        "reports": len(records),
        "errors": len(records) - len(done),
        "invalid_total": len(invalid),
        "invalid_flagged": sum(1 for r in invalid if r.verdict in FLAGGED),
        "invalid_flagged_rate": share(
            sum(1 for r in invalid if r.verdict in FLAGGED), len(invalid)
        ),
        "valid_total": len(valid),
        "valid_wrongly_invalid": len(wrong),
        "valid_wrongly_invalid_rate": share(len(wrong), len(valid)),
        "valid_wrongly_invalid_ids": wrong,
        "needs_human_rate": share(
            sum(1 for r in done if r.verdict == Verdict.NEEDS_HUMAN.value), len(done)
        ),
        "avg_tokens": round(sum(r.tokens for r in done) / len(done)) if done else 0,
        "avg_seconds": round(sum(r.seconds for r in done) / len(done), 2) if done else 0.0,
    }


def render_results(meta: dict[str, Any], by_mode: dict[str, list[Record]]) -> str:
    """Markdown results table (ids and verdicts only, never report text)."""
    out = [
        f"# Kalkan eval: curl ({meta['date']})",
        "",
        f"- Model: {meta['model']}",
        f"- Kalkan: {meta['kalkan_version']}",
        f"- Reports: {meta['reports']} (manifest: {meta['manifest']})",
        "- Method: eval/README.md",
        "",
        "| Mode | Invalid flagged | Valid wrongly called invalid | Needs human | "
        "Avg tokens | Avg time |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for mode, records in by_mode.items():
        m = compute_metrics(records)
        out.append(
            f"| {mode} | {m['invalid_flagged']}/{m['invalid_total']} "
            f"({m['invalid_flagged_rate']:.0%}) | {m['valid_wrongly_invalid']}/{m['valid_total']} "
            f"({m['valid_wrongly_invalid_rate']:.0%}) | {m['needs_human_rate']:.0%} "
            f"| {m['avg_tokens']} | {m['avg_seconds']}s |"
        )
    for mode, records in by_mode.items():
        wrong = compute_metrics(records)["valid_wrongly_invalid_ids"]
        out += ["", f"## Valid reports wrongly called invalid ({mode})", ""]
        out += [f"- {w}" for w in wrong] if wrong else ["None."]
    out += [
        "",
        "## Per report",
        "",
        "| Report | Label | Mode | Verdict | Commit |",
        "| --- | --- | --- | --- | --- |",
    ]
    for mode, records in by_mode.items():
        for r in records:
            verdict = r.verdict if not r.error else f"error: {r.error[:60]}"
            out.append(f"| {r.id} | {r.label} | {mode} | {verdict} | {r.commit[:10]} |")
    return "\n".join(out) + "\n"


def run(
    rows: list[ManifestRow],
    repo: Path,
    modes: dict[str, TriageSettings],
    data_dir: Path = DATA_DIR,
) -> dict[str, list[Record]]:
    """Triage every row in every mode."""
    by_mode: dict[str, list[Record]] = {mode: [] for mode in modes}
    with worktree(repo) as wt:
        for i, row in enumerate(rows, start=1):
            commit = commit_for(row, repo, data_dir)
            _git(wt, "checkout", "-q", "--detach", commit)
            for mode, settings in modes.items():
                start = time.perf_counter()
                try:
                    outcome = triage(data_dir / f"{row.id}.md", RepoIndex(wt), settings)
                except ReportError as exc:
                    by_mode[mode].append(
                        Record(row.id, row.label, mode, "", 0.0, 0, 0.0, commit, str(exc))
                    )
                    continue
                result = outcome.result
                by_mode[mode].append(
                    Record(
                        row.id,
                        row.label,
                        mode,
                        result.verdict.value,
                        result.confidence,
                        result.tokens_used,
                        round(time.perf_counter() - start, 2),
                        commit,
                        outcome.ai_error or "",
                    )
                )
            print(f"[{i}/{len(rows)}] {row.id} ({row.label}) done", file=sys.stderr)
    return by_mode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure Kalkan on labeled curl reports.")
    parser.add_argument("--model", help="provider:model; omit to run --no-ai only")
    parser.add_argument("--base-url")
    parser.add_argument("--no-ai", action="store_true", help="Only run the no-AI mode.")
    parser.add_argument("--repo", type=Path, default=Path("../curl"))
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--data", type=Path, default=DATA_DIR)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR)
    args = parser.parse_args(argv)

    rows = select_rows(read_manifest(args.manifest), args.data, args.limit)
    if not rows:
        print(
            "no downloaded reports; run eval.build_manifest and eval.fetch first", file=sys.stderr
        )
        return 2
    modes: dict[str, TriageSettings] = {}
    label = "no-ai"
    if args.model and not args.no_ai:
        llm = resolve_settings(args.model, args.base_url)
        assert llm is not None
        modes["ai"] = TriageSettings(provider=build_provider(llm), model_label=llm.describe())
        label = llm.describe()
    modes["no-ai"] = TriageSettings()

    by_mode = run(rows, args.repo, modes, args.data)
    from kalkan import __version__

    date = datetime.now(UTC).strftime("%Y-%m-%d")
    meta = {
        "date": date,
        "model": label,
        "kalkan_version": __version__,
        "reports": len(rows),
        "manifest": args.manifest.name,
    }
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", label.split(" at ")[0])
    args.out.mkdir(parents=True, exist_ok=True)
    md_path = args.out / f"{date}-{slug}.md"
    md_path.write_text(render_results(meta, by_mode), encoding="utf-8")
    payload = {
        **meta,
        "metrics": {mode: compute_metrics(recs) for mode, recs in by_mode.items()},
        "records": [asdict(r) for recs in by_mode.values() for r in recs],
    }
    (args.out / f"{date}-{slug}.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
