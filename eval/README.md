# Evaluation

How we measure Kalkan on real reports sent to curl. Raw report text is never
committed: only the manifest (links and labels), the code and the results.

## Data

- **Invalid**: the HackerOne reports in Daniel Stenberg's public list of
  invalid AI-generated reports to curl
  (<https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd>).
- **Valid**: curl's published CVEs (<https://curl.se/docs/vuln.json>); each
  advisory's text is used as the report.

## Steps

```bash
git clone https://github.com/curl/curl.git ../curl
uv run python -m eval.build_manifest   # writes eval/datasets/curl/manifest.csv
uv run python -m eval.fetch            # downloads texts into eval/data/ (gitignored)
uv run python -m eval.run --model ollama:qwen2.5-coder:7b --limit 20
```

`eval.fetch` makes at most one request every 2 seconds. You can also save a
report by hand as `eval/data/<id>.md`.

For every report, `eval.run` checks out curl in a temporary git worktree at
the commit just before the report (the parent of the fix commit for CVEs; the
last commit before the submission date otherwise), runs the pipeline with
the model and in `--no-ai` mode, and writes `eval/results/<date>-<model>.md`
and `.json`.

## Metrics

- **Invalid flagged**: invalid reports that got `likely_invalid` or `needs_evidence`.
- **Valid wrongly called invalid**: valid reports that got `likely_invalid`.
  This is the most important number and must stay close to zero; every such
  report is listed.
- **Needs human**: share of reports handed to a human.
- Average tokens and time per report.

## Known limits

- CVE advisories are written after the fix by the maintainers, so they are
  cleaner than typical first reports.
- The invalid set only contains reports that curl published.
