"""Independent byte lexer with context separation and explicit semantic unknowns."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import stat

WHITE = frozenset(b"\x00\t\n\x0c\r ")
DELIMITERS = frozenset(b"()<>[]{}/%")
HEX = frozenset(b"0123456789abcdefABCDEF")
WATCHED = (b"JS", b"JavaScript", b"OpenAction", b"AA", b"Launch", b"EmbeddedFile",
           b"Encrypt", b"ObjStm", b"XRef", b"Filter", b"AcroForm", b"RichMedia",
           b"XFA", b"JBIG2Decode", b"Page", b"URI", b"SubmitForm", b"GoToR")
ACTIVE = frozenset({b"JS", b"JavaScript", b"OpenAction", b"AA", b"Launch", b"EmbeddedFile",
                    b"RichMedia", b"XFA", b"URI", b"SubmitForm", b"GoToR"})
STRUCTURAL = (b"obj", b"endobj", b"stream", b"endstream", b"xref", b"trailer", b"startxref")
CONTEXTS = ("document", "literal_string", "comment", "stream_bytes")


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 8 * 1024 * 1024
    tokens: int = 200000
    name_bytes: int = 256
    word_bytes: int = 256
    literal_bytes: int = 1024 * 1024
    hex_bytes: int = 1024 * 1024
    comment_bytes: int = 16 * 1024
    stream_bytes: int = 4 * 1024 * 1024
    nesting: int = 32
    dictionary_tokens: int = 4096
    offsets: int = 1024
    findings: int = 100
    report_bytes: int = 128 * 1024

    def validate(self):
        defaults = Limits()
        for name, value in asdict(self).items():
            if type(value) is not int or value < 1 or value > getattr(defaults, name):
                raise ValueError(f"Limits must be positive integers no greater than default: {name}")
        if self.findings < 2 or self.report_bytes < 8192:
            raise ValueError("At least 2 findings and 8192 report bytes are required")


class Stop(Exception):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    value: bytes
    offset: int


@dataclass
class Frame:
    kind: str
    offset: int
    tokens: list[Token] = field(default_factory=list)


class Review:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.offset_count = 0
        self.offset_limit_reported = False
        self.data = {
            "schema": "pdf-action-review/1", "status": "OPEN",
            "result_scope": "bounded contextual lexical observations only",
            "document_safety": "OPEN", "action_semantics": "OPEN", "xref_object_resolution": "OPEN",
            "lexical_complete": True, "offsets_complete": True,
            "input_sha256": None, "input_bytes": None,
            "header": {"offset": None, "version": None},
            "eof": {"count": 0, "offsets": [], "trailing_bytes": None},
            "name_counts": {context: {"/" + n.decode(): {"count": 0, "encoded_count": 0, "offsets": []} for n in WATCHED} for context in CONTEXTS},
            "structural_counts": {n.decode(): {"count": 0, "offsets": []} for n in STRUCTURAL},
            "counts": {"tokens": 0, "unknown_document_names": 0, "literal_strings": 0,
                       "hex_strings": 0, "comments": 0, "opaque_streams": 0},
            "limits": asdict(limits), "findings": [],
            "privacy": "No input paths, arbitrary names, strings, comments or stream excerpts are emitted.",
        }

    def add(self, status: str, code: str, offset: int | None, detail: str, *, incomplete=False):
        if incomplete:
            self.data["lexical_complete"] = False
        if len(self.data["findings"]) >= self.limits.findings - 1:
            self.data["findings"].append({"status": "OPEN", "code": "finding_limit", "offset": offset,
                                          "detail": "Finding budget reached; remaining input was not reviewed."})
            self.data["lexical_complete"] = False
            raise Stop
        self.data["findings"].append({"status": status, "code": code, "offset": offset, "detail": detail})

    def stop(self, code: str, offset: int | None, detail: str):
        self.add("OPEN", code, offset, detail, incomplete=True)
        raise Stop

    def offset(self, target: list, offset: int):
        if self.offset_count < self.limits.offsets:
            target.append(offset)
            self.offset_count += 1
        elif not self.offset_limit_reported:
            self.offset_limit_reported = True
            self.data["offsets_complete"] = False
            self.add("OPEN", "offset_limit", offset, "Offset inventory is partial; counts continue within other budgets.")

    def name(self, value: bytes, encoded: bool, offset: int, context: str):
        if value in WATCHED:
            item = self.data["name_counts"][context]["/" + value.decode()]
            item["count"] += 1
            item["encoded_count"] += int(encoded)
            self.offset(item["offsets"], offset)
        elif context == "document":
            self.data["counts"]["unknown_document_names"] += 1

    def finish(self):
        flags = {f["status"] for f in self.data["findings"]}
        self.data["status"] = "FAIL" if "FAIL" in flags else ("OPEN" if "OPEN" in flags else "PASS")
        if len(json.dumps(self.data, ensure_ascii=True).encode()) > self.limits.report_bytes:
            failure = next((f for f in self.data["findings"] if f["status"] == "FAIL"), None)
            self.data["name_counts"] = {}
            self.data["structural_counts"] = {}
            self.data["eof"]["offsets"] = []
            self.data["findings"] = [{"status": "OPEN", "code": "report_limit", "offset": None,
                                      "detail": "Report exceeded byte budget; detailed counts and offsets were removed."}]
            if failure:
                self.data["findings"].append(failure)
            self.data["offsets_complete"] = False
            self.data["lexical_complete"] = False
            if self.data["status"] != "FAIL":
                self.data["status"] = "OPEN"
        return self.data


def read_local(path: str | os.PathLike, review: Review) -> bytes:
    value = os.fspath(path)
    if not isinstance(value, str) or not value or value == "-" or "://" in value or value.startswith("@"):
        review.stop("input_contract", None, "One local path is required; URL, stdin and @list input are unsupported.")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(Path(value), flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            review.stop("input_type", None, "Input must be a local regular file; devices, pipes and directories are unsupported.")
        if before.st_size > review.limits.input_bytes:
            review.stop("input_limit", None, "Raw file exceeds byte budget.")
        data = stream.read(review.limits.input_bytes + 1)
        after = os.fstat(stream.fileno())
        if len(data) > review.limits.input_bytes:
            review.stop("input_limit", None, "Raw file grew beyond byte budget.")
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            review.stop("input_changed", None, "Input changed during observation; snapshot was not stable.")
    review.data["input_sha256"] = hashlib.sha256(data).hexdigest()
    review.data["input_bytes"] = len(data)
    return data


def decode_name(raw: bytes) -> tuple[bytes, bool, bool]:
    value, encoded, valid, i = bytearray(), False, True, 0
    while i < len(raw):
        if raw[i] == 35:
            if i + 2 < len(raw) and raw[i + 1] in HEX and raw[i + 2] in HEX:
                value.append(int(raw[i + 1:i + 3], 16)); encoded = True; i += 3
                if value[-1] == 0:
                    valid = False
                continue
            valid = False
        value.append(raw[i]); i += 1
    return bytes(value), encoded, valid


def contextual_spellings(data: bytes, start: int, end: int, context: str, review: Review):
    """Record only physical /name-looking spans; no decoding of string/stream content."""
    i = start
    while i < end:
        if data[i] != 47:
            i += 1; continue
        at = i; i += 1; begin = i
        while i < end and data[i] not in WHITE and data[i] not in DELIMITERS:
            i += 1
            if i - begin > review.limits.name_bytes:
                # Long arbitrary string/stream spelling is not a document name.
                while i < end and data[i] not in WHITE and data[i] not in DELIMITERS:
                    i += 1
                break
        if i - begin <= review.limits.name_bytes:
            value, encoded, valid = decode_name(data[begin:i])
            if valid:
                review.name(value, encoded, at, context)


class Lexer:
    def __init__(self, data: bytes, review: Review):
        self.data, self.r = data, review
        self.pos, self.frames = 0, []
        self.recent_dict = None
        self.history = []
        self.object_open = False
        self.last_eof_end = None

    def token(self, token: Token, *, record_frame=True):
        self.r.data["counts"]["tokens"] += 1
        if self.r.data["counts"]["tokens"] > self.r.limits.tokens:
            self.r.stop("token_limit", token.offset, "Token budget exceeded.")
        if self.frames and record_frame:
            frame = self.frames[-1]
            if len(frame.tokens) >= self.r.limits.dictionary_tokens:
                self.r.stop("container_token_limit", token.offset, "Container token budget exceeded.")
            frame.tokens.append(token)
        self.history.append(token)
        self.history = self.history[-3:]

    def literal(self):
        start, nesting = self.pos, 1
        self.pos += 1
        while self.pos < len(self.data):
            if self.pos - start >= self.r.limits.literal_bytes:
                self.r.stop("literal_limit", start, "Literal-string byte budget exceeded.")
            char = self.data[self.pos]; self.pos += 1
            if char == 92:
                if self.pos < len(self.data):
                    escaped = self.data[self.pos]; self.pos += 1
                    if escaped == 13 and self.pos < len(self.data) and self.data[self.pos] == 10:
                        self.pos += 1
            elif char == 40:
                nesting += 1
                if nesting > self.r.limits.nesting:
                    self.r.stop("nesting_limit", self.pos - 1, "Literal-string parenthesis nesting exceeds budget.")
            elif char == 41:
                nesting -= 1
                if nesting == 0:
                    if self.pos - start > self.r.limits.literal_bytes:
                        self.r.stop("literal_limit", start, "Literal-string byte budget exceeded.")
                    contextual_spellings(self.data, start + 1, self.pos - 1, "literal_string", self.r)
                    self.r.data["counts"]["literal_strings"] += 1
                    self.token(Token("string", b"", start)); return
        contextual_spellings(self.data, start + 1, self.pos, "literal_string", self.r)
        self.r.stop("unterminated_literal", start, "Literal string is truncated or unbalanced.")

    def hex_string(self):
        start, bad = self.pos, False
        self.pos += 1
        while self.pos < len(self.data) and self.data[self.pos] != 62:
            if self.pos - start >= self.r.limits.hex_bytes:
                self.r.stop("hex_limit", start, "Hex-string byte budget exceeded.")
            if self.data[self.pos] not in WHITE and self.data[self.pos] not in HEX:
                bad = True
            self.pos += 1
        if self.pos == len(self.data):
            self.r.stop("unterminated_hex", start, "Hex string has no closing delimiter.")
        self.pos += 1
        if self.pos - start > self.r.limits.hex_bytes:
            self.r.stop("hex_limit", start, "Hex-string byte budget exceeded.")
        if bad:
            self.r.add("FAIL", "invalid_hex_string", start, "Hex string contains non-hex, non-whitespace bytes.")
        self.r.data["counts"]["hex_strings"] += 1
        self.token(Token("string", b"", start))

    def comment(self):
        start = self.pos
        while self.pos < len(self.data) and self.data[self.pos] not in {10, 13}:
            if self.pos - start >= self.r.limits.comment_bytes:
                self.r.stop("comment_limit", start, "Comment byte budget exceeded.")
            self.pos += 1
        end = self.pos
        self.r.data["counts"]["comments"] += 1
        contextual_spellings(self.data, start, end, "comment", self.r)
        line_prefix_valid = False
        if self.data[start:end].rstrip(bytes(WHITE)) == b"%%EOF":
            # Walk only the candidate line prefix; avoid repeated whole-prefix
            # searches for absent CR bytes on files containing many LF comments.
            cursor = start - 1
            while cursor >= 0 and self.data[cursor] in WHITE and self.data[cursor] not in {10, 13}:
                cursor -= 1
            line_prefix_valid = cursor < 0 or self.data[cursor] in {10, 13}
        if line_prefix_valid:
            self.r.data["eof"]["count"] += 1
            self.r.offset(self.r.data["eof"]["offsets"], start)
            self.last_eof_end = end

    def direct_length(self, frame: Frame):
        lengths, seen, i = [], set(), 0
        tokens = frame.tokens
        # Parse dictionary key/value boundaries, including indirect references.
        # A /Length appearing as another key's name value must not be trusted.
        while i < len(tokens):
            key_token = tokens[i]
            if key_token.kind != "name" or i + 1 >= len(tokens):
                self.r.add("OPEN", "dictionary_grammar", key_token.offset, "Dictionary key/value grammar is incomplete or unsupported.", incomplete=True)
                return None
            if key_token.value in seen:
                self.r.add("OPEN", "duplicate_dictionary_key", key_token.offset, "Duplicate dictionary key makes interpretation ambiguous.", incomplete=True)
                return None
            seen.add(key_token.value)
            value = tokens[i + 1]
            width = 1
            reference = value.kind == "integer" and i + 3 < len(tokens) and tokens[i + 2].kind == "integer" and tokens[i + 3].value == b"R"
            if reference:
                width = 3
            elif value.kind not in {"name", "integer", "real", "string", "container"} and not (value.kind == "word" and value.value in {b"true", b"false", b"null"}):
                self.r.add("OPEN", "dictionary_grammar", value.offset, "Dictionary value grammar is unsupported.", incomplete=True)
                return None
            if key_token.value == b"Length":
                lengths.append(int(value.value) if value.kind == "integer" and not reference else None)
            i += 1 + width
        if len(lengths) != 1 or lengths[0] is None or lengths[0] < 0:
            return None
        return lengths[0]

    def stream(self, at: int):
        if self.frames or not self.object_open or self.recent_dict is None:
            self.r.stop("stream_dictionary", at, "Stream has no supported immediate direct dictionary inside an indirect object.")
        length = self.recent_dict[0]
        if length is None:
            self.r.stop("stream_length_unresolved", at, "Missing, duplicate, indirect or invalid /Length; remaining boundary is unknown.")
        if length > self.r.limits.stream_bytes:
            self.r.stop("stream_limit", at, "Opaque stream exceeds byte budget.")
        if self.data[self.pos:self.pos + 2] == b"\r\n":
            self.pos += 2
        elif self.pos < len(self.data) and self.data[self.pos] in {10, 13}:
            self.pos += 1
        else:
            self.r.stop("stream_eol", at, "stream keyword is not immediately followed by EOL.")
        begin, end = self.pos, self.pos + length
        if end > len(self.data):
            self.r.stop("truncated_stream", at, "Direct stream length extends beyond raw file.")
        contextual_spellings(self.data, begin, end, "stream_bytes", self.r)
        self.r.data["counts"]["opaque_streams"] += 1
        self.r.add("OPEN", "opaque_stream", begin, "Stream bytes remain opaque; no decompression, action interpretation or attachment extraction.")
        self.pos = end
        if self.data[self.pos:self.pos + 2] == b"\r\n":
            self.pos += 2
        elif self.pos < len(self.data) and self.data[self.pos] in {10, 13}:
            self.pos += 1
        if self.data[self.pos:self.pos + 9] != b"endstream" or (self.pos + 9 < len(self.data) and self.data[self.pos + 9] not in WHITE | DELIMITERS):
            self.r.stop("stream_boundary", self.pos, "Direct /Length does not lead to a delimited endstream token.")
        self.r.data["structural_counts"]["endstream"]["count"] += 1
        self.r.offset(self.r.data["structural_counts"]["endstream"]["offsets"], self.pos)
        self.token(Token("word", b"endstream", self.pos))
        self.pos += 9
        self.recent_dict = None

    def scan(self):
        while self.pos < len(self.data):
            at, char = self.pos, self.data[self.pos]
            if char in WHITE:
                self.pos += 1; continue
            if char == 37:
                self.comment(); continue
            if char == 40:
                self.recent_dict = None; self.literal(); continue
            if char == 60 and self.data[self.pos:self.pos + 2] != b"<<":
                self.recent_dict = None; self.hex_string(); continue
            opening = "dict" if self.data[self.pos:self.pos + 2] == b"<<" else ("array" if char == 91 else None)
            if opening:
                self.token(Token("container", b"", at))
                self.frames.append(Frame(opening, at))
                if len(self.frames) > self.r.limits.nesting:
                    self.r.stop("nesting_limit", at, "Array/dictionary nesting exceeds budget.")
                self.pos += 2 if opening == "dict" else 1
                self.recent_dict = None; continue
            closing = "dict" if self.data[self.pos:self.pos + 2] == b">>" else ("array" if char == 93 else None)
            if closing:
                if not self.frames or self.frames[-1].kind != closing:
                    self.r.add("FAIL", "container_mismatch", at, "Unmatched or mismatched array/dictionary delimiter.")
                    self.recent_dict = None
                else:
                    frame = self.frames.pop()
                    length = self.direct_length(frame) if closing == "dict" else None
                    self.recent_dict = (length, at) if closing == "dict" and not self.frames else None
                self.pos += 2 if closing == "dict" else 1
                self.token(Token("close", b"", at), record_frame=False); continue
            if char in DELIMITERS and char != 47:
                self.r.add("FAIL", "unexpected_delimiter", at, "Unexpected delimiter outside a supported lexical context.")
                self.pos += 1; self.recent_dict = None; continue
            self.pos += 1
            begin = self.pos if char == 47 else at
            while self.pos < len(self.data) and self.data[self.pos] not in WHITE | DELIMITERS:
                self.pos += 1
                bound = self.r.limits.name_bytes if char == 47 else self.r.limits.word_bytes
                if self.pos - begin > bound:
                    self.r.stop("name_limit" if char == 47 else "word_limit", at, "Name/word token exceeds byte budget.")
            raw = self.data[begin:self.pos]
            if char == 47:
                value, encoded, valid = decode_name(raw)
                if not raw or not valid:
                    self.r.add("OPEN", "name_encoding", at, "Empty name, malformed #xx escape or decoded NUL is outside supported name grammar.", incomplete=True)
                self.r.name(value, encoded, at, "document")
                self.token(Token("name", value, at)); self.recent_dict = None; continue
            signed = raw.lstrip(b"+-")
            is_integer = bool(signed) and all(c in b"0123456789" for c in signed) and raw[:1] not in {b"", b"."} and not raw.startswith((b"++", b"--", b"+-", b"-+"))
            is_real = bool(signed.replace(b".", b"")) and signed.count(b".") == 1 and all(c in b"0123456789." for c in signed) and not raw.startswith((b"++", b"--", b"+-", b"-+"))
            if is_integer:
                token = Token("integer", raw, at)
            elif is_real:
                token = Token("real", raw, at)
            else:
                token = Token("word", raw, at)
            prior = self.history[-2:]
            self.token(token)
            if raw in STRUCTURAL:
                item = self.r.data["structural_counts"][raw.decode()]
                item["count"] += 1; self.r.offset(item["offsets"], at)
            if raw == b"obj":
                if self.object_open or len(prior) != 2 or any(t.kind != "integer" for t in prior) or (all(t.kind == "integer" for t in prior) and len(prior) == 2 and (int(prior[0].value) <= 0 or int(prior[1].value) < 0)):
                    self.r.add("OPEN", "object_header", at, "Indirect object header is unsupported or an object was not closed.", incomplete=True)
                self.object_open = True
            elif raw == b"endobj":
                if not self.object_open or self.frames:
                    self.r.add("OPEN", "object_balance", at, "Indirect object close lacks a matching balanced opening.", incomplete=True)
                self.object_open = False
            elif raw == b"stream":
                self.stream(at); continue
            elif raw == b"endstream":
                self.r.add("OPEN", "orphan_endstream", at, "endstream occurs outside a supported direct-length stream.", incomplete=True)
            elif token.kind == "word" and raw not in {*STRUCTURAL, b"R", b"true", b"false", b"null", b"n", b"f"}:
                self.r.add("OPEN", "unknown_keyword", at, "Unrecognized keyword outside opaque content; full object/content grammar is not implemented.", incomplete=True)
            self.recent_dict = None
        self.final_checks()

    def final_checks(self):
        if self.frames or self.object_open:
            self.r.add("OPEN", "truncated_structure", len(self.data), "Container or indirect object remains open at end of input.", incomplete=True)
        eof = self.r.data["eof"]
        if not eof["count"]:
            self.r.add("OPEN", "missing_eof", len(self.data), "No context-valid %%EOF line; truncation or unsupported layout remains possible.", incomplete=True)
        else:
            eof["trailing_bytes"] = len(self.data) - self.last_eof_end
            if any(c not in WHITE for c in self.data[self.last_eof_end:]):
                self.r.add("OPEN", "trailing_data", self.last_eof_end, "Non-whitespace bytes occur after the last context-valid EOF marker.", incomplete=True)
            if eof["count"] > 1:
                self.r.add("OPEN", "multiple_eof", None, "Multiple EOF markers may indicate revisions; revision/object resolution is not implemented.")
        for word in ("obj", "endobj", "xref", "trailer", "startxref"):
            if not self.r.data["structural_counts"][word]["count"]:
                self.r.add("OPEN", "structural_presence", None, "Traditional object/xref/trailer/startxref token is missing; unsupported or incomplete layout.", incomplete=True)
                break
        document = self.r.data["name_counts"]["document"]
        for name in sorted(ACTIVE):
            item = document["/" + name.decode()]
            if item["count"]:
                self.r.add("OPEN", "watched_name_presence", item["offsets"][0] if item["offsets"] else None,
                           "Watched activity-related name is present; no action execution, reachability or maliciousness is established.")
        for name in (b"ObjStm", b"XRef", b"Encrypt", b"Filter"):
            item = document["/" + name.decode()]
            if item["count"]:
                self.r.add("OPEN", "unsupported_semantic_content", item["offsets"][0] if item["offsets"] else None,
                           "Potential compressed-object/xref/filter/encryption content is not interpreted.")


def review_pdf(path: str | os.PathLike, *, limits: Limits | None = None) -> dict:
    if limits is None:
        limits = Limits()
    elif type(limits) is not Limits:
        raise TypeError("limits must be a Limits instance or None")
    limits.validate()
    review = Review(limits)
    try:
        data = read_local(path, review)
        if len(data) < 9 or not data.startswith(b"%PDF-") or data[8] not in {10, 13}:
            review.stop("pdf_header", 0, "Raw PDF version header at byte zero followed by EOL is missing or truncated.")
        version = data[5:8]
        if version not in {b"1.0", b"1.1", b"1.2", b"1.3", b"1.4", b"1.5", b"1.6", b"1.7", b"2.0"}:
            review.stop("pdf_version", 5, "PDF version is outside the supported lexical profile.")
        review.data["header"] = {"offset": 0, "version": version.decode()}
        Lexer(data, review).scan()
    except Stop:
        pass
    except (OSError, ValueError, UnicodeError) as exc:
        try:
            review.add("OPEN", "input_error", None, f"Review stopped on {type(exc).__name__}; paths and raw exception details are suppressed.", incomplete=True)
        except Stop:
            pass
    return review.finish()
