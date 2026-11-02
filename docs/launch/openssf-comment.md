# Comment for the OpenSSF AI-slop discussion

Hi all, a small contribution to this thread rather than an announcement.

I built Kalkan, an Apache-2.0 command-line tool that helps maintainers with
the first pass over an incoming security report. It runs locally. Before any
AI is involved, it checks the report's concrete claims against the
repository with git: do the named files and functions exist, is the line
number inside the file, does the quoted code match, does the version exist.
An optional model (the maintainer's own key, or a local model) then reviews
the evidence, and a second pass argues against the first. Disagreements go to
a human. It drafts a polite reply asking for exactly what is missing, and it
never sends, closes or publishes anything.

On [[N]] public curl reports ([[date]], [[model]]), it flagged [[X]] of [[Y]]
invalid reports and called [[Z]] of [[W]] valid reports invalid. The method
and its limits are in eval/README.md.

I would value feedback from people who triage reports: what would make this
useful or safe enough for your project? Repository: https://github.com/7suheel/kalkan
