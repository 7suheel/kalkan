# Security policy

Kalkan processes hostile text by design, so we take vulnerabilities in Kalkan
itself seriously.

## Reporting a vulnerability

Please report security issues **privately** through GitHub's private
vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, the affected version, steps to reproduce and the impact.

Please do not open a public issue for security problems.

We aim to acknowledge reports within 7 days. We will keep you updated while we
work on a fix and credit you in the advisory unless you prefer otherwise.

## Scope

In scope: anything that lets a malicious report make Kalkan read files outside
the given repository, run commands, leak API keys or report content, or flip a
verdict through injected instructions.

## Supported versions

Only the latest released version receives security fixes while Kalkan is in
early development.
