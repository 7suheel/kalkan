# r/opensource post

## Title

I built a local tool that checks security reports against your code before you answer them

## Body

Many maintainers now receive security reports that mention functions, files
or line numbers that do not exist in their code. Kalkan is a small
Apache-2.0 CLI that does the first, boring part of triage:

- verifies each concrete claim with git (files, functions, lines, versions,
  quoted code), with no AI needed;
- optionally asks a model you choose (your own API key, or a free local model
  through Ollama) to compare the claims with the code, with a second pass that
  argues against the first;
- suggests a verdict and drafts a polite reply asking for missing evidence.

It runs on your machine, has no telemetry, and never sends or closes
anything. When unsure it says "needs a human".

Results on public curl reports ([[date]], [[model]]): [[X]] of [[Y]] invalid
reports flagged, [[Z]] of [[W]] valid reports wrongly called invalid.

I'd love feedback, especially examples where the verdict was wrong:
https://github.com/7suheel/kalkan
