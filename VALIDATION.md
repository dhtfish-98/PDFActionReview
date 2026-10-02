# Validation record

Version 0.1.1 re-audit date: 2026-10-03 (Asia/Tokyo). The local source suite has
40 passing methods on Python 3.14.6. New controls cover a format FAIL arriving
after earlier OPEN findings fill the budget, retention through report reduction,
and fixed OPEN JSON for invalid/missing CLI arguments without private argument
echo in either stream. `evidence/reaudit-0.1.1.json` records the new targeted gates.
The prior 0.1.0 observations below are historical and do not validate new bytes.

Historical local validation date: 2026-10-02 (Asia/Tokyo). `evidence/validation.json` records
test results, interpreter and independently installed CLI/package checks.
`evidence/source-review.json` identifies every new runtime/test/package/CI source
reviewed; `evidence/upstream-review.json` records all 1,089 lines of the selected
upstream module and explicitly excludes the rest of the suite.

The targeted suite covers a conventional generated one-page raw PDF, watched and
`#xx`-encoded names, physical byte offsets, comments, nested/escaped strings,
octal-string and hex-string counterexamples, direct-length opaque streams and
embedded fake endstream/EOF names. Missing/duplicate/indirect/bad stream lengths,
corrupt/truncated lexical regions, container/dictionary grammar, non-PDF/ZIP input,
one-byte EOF truncation, duplicate/trailing EOF and resource budgets retain OPEN
or demonstrated lexical failure as appropriate. Presence never means malicious.

Input hashes/bytes remain unchanged. URL/network/process/ZIP/decompression mocks
and removed CLI flags test prohibited paths. Privacy tests ensure arbitrary names,
private string/comment content, paths and raw exception details are absent from
reports. An independent fresh environment installs only this tool's built wheel,
runs the suite and CLI, and checks source/notice/provenance identity in wheel/sdist.
No reviewed PDF is opened, interpreted by a viewer or executed.

CI is defined for Python 3.11 and 3.14. The prior public 0.1.0 commit had observed
matching hosted jobs. New 0.1.1 jobs remain pending until their exact commit is
observed passing. Local tests establish only the measured CPython/platform result.
No full semantic parser or CVP approval result was validated. Final
distribution hashes are stored outside the packages in the engineering handoff,
avoiding a circular package self-hash claim.
