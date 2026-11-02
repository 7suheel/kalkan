# Show HN

## Title

Show HN: Kalkan – check a security report's claims against your code before you reply

## First comment (under 150 words)

I maintain open-source code and, like many maintainers, get security reports
that cite functions, files or lines that do not exist. Checking each one by
hand takes time, and real reports are mixed in with them.

Kalkan is a local CLI. It reads a report, verifies each concrete claim
(files, functions, line numbers, versions, code snippets) with git, and only
then optionally asks a model of your choice (your own key, or Ollama). It
suggests a verdict and drafts a polite reply asking for missing evidence. It
never sends or closes anything, and when in doubt it says "needs a human".

On [[N]] curl reports ([[date]], [[model]]): [[X]] of [[Y]] invalid reports
flagged, [[Z]] of [[W]] valid reports wrongly called invalid. Method:
eval/README.md.

Feedback on wrong verdicts is the most useful thing you can send.
