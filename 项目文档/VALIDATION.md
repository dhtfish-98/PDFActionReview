> 本页保留 0.1.3 的历史验证记录；0.1.4 的发布验证状态请以对应提交的 GitHub Actions 和 Release 资产为准。

# Current licensing validation — 0.1.3

This patch removes only 1 confirmed unused complete reference-license/notice copies. New implementation author remains dhtfish98. Runtime parsing and evidence interpretation are unchanged; runtime changes are package version constants and any existing version display. The new source suite ran **44 unittest methods with nonzero PASS**. Current source identities are in SOURCE_MANIFEST.json, and LICENSE_CLEANUP.json describes the exact licensing boundary. Wheel and sdist reconstruction, fresh isolated consumer tests, CLI contracts, runtime/notice byte identity and package metadata are independently bound to the new assets in the batch release records; source tests alone do not prove those outcomes. New hosted CI and publication remain separate observations.

## Historical validation evidence

All following earlier version/count/native observations are historical evidence, not validation of this new patch. Statements below about then-retained reference copies describe the earlier artifacts. Current licensing membership is LICENSE_CLEANUP.json.

# Current validation — 0.1.2

The 2026-10-03 attribution update identifies the new implementation author and maintainer as dhtfish98. The final wheel and sdist were rebuilt, and a fresh isolated consumer ran **44 existing and targeted unittest methods successfully**, imported the installed package from site-packages, exercised the declared CLI contract and matched every shipped runtime/notice byte to current source. Wheel metadata records author dhtfish98 and version 0.1.2; RECORD and source-distribution contents were checked. Current runtime identities are in SOURCE_MANIFEST.json; ATTRIBUTION_UPDATE.json records the exact selected validation scope. The matching private build/install/test logs and artifact hashes are retained in the batch validation records, outside this public project.

This update also checks every required safe-read flag for exact positive integer capability before input is opened. API/CLI tests cover missing, None, zero and boolean flags, ordinary files and symbolic links. The PDF reader additionally refuses a FIFO before open when nonblocking capability is unavailable.

## Historical validation evidence

The following earlier records retain their original versions, counts and fixed source identities. They are historical observations, not evidence that an old artifact is the current package.

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
