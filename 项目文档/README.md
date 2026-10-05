> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# PDFActionReview

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.5**. Upstream authors and reused components retain their original attribution.


A defensive, local-only PDF lexical review tool. It records selected PDF names,
`#xx`-encoded names, structural words and byte offsets while separating document
tokens from comment/literal-string spellings and opaque stream bytes. It does not
execute JavaScript, open links, extract attachments, decompress streams or modify
the input. Runtime dependencies are Python's standard library only.

This is a new implementation by dhtfish98, with PDFiD's `pdfid.py` as a
semantic reference. It is not a rewrite of DidierStevensSuite as a whole, and it
does not wrap or execute upstream code. [ORIGIN](<ORIGIN.md>) records the fixed
source commit, complete module review and attributable contribution.

## Run

```sh
python -m pip install .
pdf-action-review /path/to/document.pdf
python -m pdf_action_review /path/to/document.pdf
```

Requires Python 3.11+. Supply exactly one local regular raw file. Input suffix is
not trusted: ZIP bytes renamed `.pdf` fail the raw header profile. URLs, stdin,
`@list`, directory recursion, glob expansion and archive inputs are unsupported.
The command produces JSON on stdout. It never writes a report or modifies a file;
the caller can explicitly redirect stdout if needed.

Exit `0` is PASS within the stated lexical checks; `1` is a demonstrated lexical
failure such as a mismatched delimiter or malformed hex string; `2` is OPEN for
unsupported, ambiguous, partial or review-requiring observations. FAIL has priority
if an OPEN observation also exists. Counts are observations, not action executions.
Version 0.1.1 preserves a newly observed FAIL even if earlier OPEN findings have
filled the diagnostic budget; report reduction also keeps that failure. Invalid
or missing command arguments produce an OPEN JSON report with a fixed diagnostic
and exit 2, without echoing argument values or paths to stdout or stderr.

Every report keeps `document_safety`, `action_semantics` and
`xref_object_resolution` equal to **OPEN**, including lexical PASS reports.
An absent watched name does not prove a PDF safe. An observed `/JS` or `/Launch`
does not prove an executable action, reachability or malicious behavior.

## What the implementation understands

- Strict version header at byte zero and a following EOL; PDF versions 1.0-1.7
  and 2.0 are recognized lexically. Prefixed/relaxed headers remain OPEN.
- PDF whitespace, delimiters, case-sensitive name tokens and valid `#xx` name
  escapes. `encoded_count` counts names containing at least one such escape;
  offsets identify the physical slash byte in the input snapshot.
- Nested/escaped literal-string boundaries, line continuations, hexadecimal
  strings, comments and balanced array/dictionary delimiters. Literal strings
  and comments have their own fixed-watchlist spelling counts. Literal octal
  escapes and hex-string values are not decoded into PDF names.
- Dictionary key/value boundaries needed to distinguish a direct integer
  `/Length` key from name values, duplicates and indirect references. This is
  limited object grammar, not general PDF object/reference resolution.
- Streams with an immediate direct dictionary, one nonnegative direct integer
  length, a following EOL and an exact delimited `endstream` at the length boundary.
  Bytes within that span are **opaque**, even when uncompressed. Name-like byte
  spans there are labeled `stream_bytes`, not document names.
- Context-valid `%%EOF` lines, offsets, duplicate EOF and trailing data;
  traditional object/xref/trailer/startxref token presence and object/container
  balance. Cross-reference tables, target offsets, revisions and object links
  are not resolved or validated.

The fixed names include `/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`,
`/EmbeddedFile`, `/Encrypt`, `/ObjStm`, `/XRef`, `/Filter`, `/AcroForm`, `/RichMedia`,
`/XFA`, `/JBIG2Decode`, `/Page`, `/URI`, `/SubmitForm` and `/GoToR`.
Activity-related document names produce OPEN presence observations. `/ObjStm`,
`/XRef`, `/Filter` and `/Encrypt` keep potential semantic content OPEN.
`/AcroForm`, `/Page` and `/JBIG2Decode` are inventory names rather than execution
claims; a real associated action/object can only be established by a semantic parser.

All streams produce OPEN because their semantic contents are unsupported. Missing,
duplicate, indirect or invalid stream lengths stop the scan with OPEN. The tool
does not heuristically search for an `endstream` in unknown bytes. This prevents
false document-name counts from payloads containing fake boundary tokens.

## Limits and privacy

Defaults: 8 MiB raw input, 200,000 tokens, 256 bytes per name/word, 1 MiB per
literal or hex region, 16 KiB per comment, 4 MiB per stream, 32 levels of container
or literal nesting, 4,096 tokens per container, 1,024 recorded offsets, 100 findings
and 128 KiB JSON. There is no archive recursion or decompression. The `Limits`
Python API can tighten these defaults; it cannot increase them.

Unknown input and budget exhaustion never produce a clean result. The report
records `lexical_complete` and `offsets_complete` separately: offset recording can
stop while bounded counts continue. Report reduction emits explicit OPEN.

Reports omit the input path, arbitrary names, string/comment values, stream
excerpts and raw exception details. Only fixed watchlist names, counts, offsets,
version, size, input SHA-256 and fixed diagnostic messages are emitted. The
snapshot fingerprint is evidence identity, not authenticity or anonymization.
Final path-component symlinks are rejected using `O_NOFOLLOW` on platforms that
provide it. Parent components follow normal OS resolution. Regular-file
snapshots check size/time identity before and after reading. Passing the wrong
type for the library's `limits` argument raises TypeError instead of using defaults.

## Verification

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python -m build
```

[VALIDATION](<VALIDATION.md>) and `evidence/` record actual source/package/CLI checks.
[DEFENSIVE_SCOPE](<DEFENSIVE_SCOPE.md>) describes authorized use and limitations.
The new MIT license and the complete selected module's public-domain declaration
are retained in both distributions; no suite-wide license claim is made.

Syntax reference consulted: [PDF Association PDF basics](https://pdfa.org/wp-content/uploads/2023/08/PDF-Basics-CheatSheet.pdf).

Safe local file input requires positive integer `O_NOFOLLOW`, `O_NONBLOCK` flags, plus directory-relative operations only where used by this reader. Missing, None, zero or boolean flags return the existing controlled unsupported/error result before opening input. File-reader validation covers macOS/Linux; native Windows safe file reading is not established.
