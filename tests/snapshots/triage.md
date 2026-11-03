# Kalkan triage: fake-report

**Suggested verdict: NEEDS_EVIDENCE** (confidence 50%). Kalkan only suggests; you make the final call.

## Summary

> Suggested verdict: needs_evidence. parse_header exists at src/parser.c:10.

## Claim checks

| Status | Kind | Claim | Evidence |
| --- | --- | --- | --- |
| ✅ confirmed | file_path | `src/parser.c` | exists |
| ✅ confirmed | function | `parse_header` | defined at src/parser.c:10 |
| ⚠️ contradicted | line_ref | `src/parser.c:9999` | line 9999 is past the end of the file (33 lines at HEAD) |
| ❌ not found | function | `parse_header_strict` | name does not appear anywhere in the repository |
| ⚪ not checkable | code_snippet | `x ¦ y <img src=x>` | looks like a command \| not code |

## Quality signals

- [ ] Affected version given
- [ ] Steps to reproduce
- [ ] Proof of concept
- [x] Impact statement

## Agent opinions

### Analyst: needs_evidence (60%)

> parse_header copies into a 64-byte buffer (src/parser.c:14), but line 9999 does not exist.

Cited: `src/parser.c:14`

### Skeptic: needs_evidence (50%)

> Plausible, but no PoC.

## Missing evidence

- the affected version or commit
- steps to reproduce
- a proof of concept
- the header length that triggers the overflow

## Reply draft

~~~text
Hello,

Thank you for the report.

Best regards,
[maintainer name]
~~~

---

Kalkan 0.0.0-test · model: fake:fake-model · tokens: 1234
