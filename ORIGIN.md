# Origin and honest attribution

Selected semantic reference: `pdfid.py` (PDFiD 0.2.10) by Didier Stevens, fixed
[`DidierStevens/DidierStevensSuite`](https://github.com/DidierStevens/DidierStevensSuite/blob/b248e9aabac4dedc2619c986d07eb7a5f4c18d37/pdfid.py)
commit `b248e9aabac4dedc2619c986d07eb7a5f4c18d37`.
The module SHA-256 is
`e958a01f1c2596470f27d3c308061b85d7059ff476a58d74f1957a71b4f1248f`.
All 1,089 physical lines of this module, including imports, helpers and CLI entry,
were read and reviewed locally. No other suite module or third-party dependency
implementation was audited. The suite as a whole has no uniform root license in
the selection record; its unreviewed tools are not part of this project.

The author places this module in the public domain. Its complete declaration,
author/site attribution and warning are preserved in
`licenses/PDFiD-PUBLIC-DOMAIN.txt`. This is a module-specific declaration; it is
not converted into a suite-wide permission claim.

The upstream source includes ordinary local and URL input in `cBinaryFile`, ZIP
first-member reading with a preset password, XML/JSON output, entropy/date/EOF
tracking, keyword configuration, file-list/glob/recursive discovery, plugin loading
with `exec`, selection expressions with `eval`, and disarm/output-log writes.
Review notes and exact reviewed-module identity are in `evidence/upstream-review.json`.

PDFActionReview was newly implemented with OpenAI Codex assistance, without
copying, renaming, importing or wrapping upstream runtime code. Its new contribution
is a bounded immutable snapshot, context-aware byte lexer, dictionary key/value
parsing for direct stream boundaries, per-context fixed-name counts and offsets,
privacy-preserving diagnostics, explicit completeness states and targeted tests.
The tool does not treat arbitrary bytes inside strings/comments/streams as actual
PDF document names, and never promotes keyword presence into a malicious verdict.

Removed capabilities: URL input, ZIP input/preset passwords, stdin, plugins,
`exec`/`eval`, custom executable expressions, disarm/write-back, output logs,
directory recursion, globs and `@file` lists. Entropy/date extraction, arbitrary
name dumps, XML/CSV output and complete upstream CLI/API compatibility were also
excluded. This is a complete new implementation of the selected read-only lexical
review contract, not a complete reproduction of all PDFiD or PDF semantics.

The applicant may truthfully describe this AI-assisted new implementation and
their independently attributable review/maintenance, after checking it. They must
not claim authorship of Didier Stevens' work, independent human authorship of AI
output, complete suite rewriting, an observed incident or CVP approval.
