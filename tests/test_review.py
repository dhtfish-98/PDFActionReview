"""Inert generated PDFs and bounded lexical boundary counterexamples."""

from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.request
import zipfile
import zlib

from pdf_action_review import Limits, review_pdf
from pdf_action_review.cli import main


def pdf(extra=b"", stream=None, *, eol=b"\n"):
    objects = [b"<< /Type /Catalog /Pages 2 0 R " + extra + b" >>",
               b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Resources << >> >>"]
    if stream is not None:
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>" + eol + b"stream" + eol + stream + eol + b"endstream")
    data = b"%PDF-1.7" + eol + b"%\xe2\xe3\xcf\xd3" + eol
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(data));data += str(i).encode() + b" 0 obj" + eol + obj + eol + b"endobj" + eol
    xref = len(data)
    data += b"xref" + eol + b"0 " + str(len(objects) + 1).encode() + eol + b"0000000000 65535 f \r\n"
    for offset in offsets:
        data += f"{offset:010d} 00000 n \r\n".encode()
    data += b"trailer" + eol + b"<< /Root 1 0 R /Size " + str(len(objects) + 1).encode() + b" >>" + eol
    data += b"startxref" + eol + str(xref).encode() + eol + b"%%EOF" + eol
    return data


class PDFReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "fixture.pdf"

    def check(self, data=None, **kwargs):
        data = pdf() if data is None else data
        self.path.write_bytes(data)
        before = self.path.read_bytes()
        report = review_pdf(self.path, **kwargs)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertLessEqual(len(json.dumps(report).encode()), (kwargs.get("limits") or Limits()).report_bytes)
        self.assertEqual(report["document_safety"], "OPEN")
        self.assertEqual(report["action_semantics"], "OPEN")
        return report

    def codes(self, report):
        return {f["code"] for f in report["findings"]}

    def expect(self, code, data, *, status="OPEN", **kwargs):
        report = self.check(data, **kwargs)
        self.assertEqual(report["status"], status, report)
        self.assertIn(code, self.codes(report), report)
        return report

    def test_plain_pdf_is_scoped_pass(self):
        report = self.check()
        self.assertEqual(report["status"], "PASS", report)
        self.assertTrue(report["lexical_complete"])
        self.assertEqual(report["input_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(report["structural_counts"]["obj"]["count"], 3)
        self.assertEqual(report["eof"]["count"], 1)

    def test_activity_name_is_presence_not_malicious_verdict(self):
        for name in (b"JS", b"JavaScript", b"OpenAction", b"AA", b"Launch", b"EmbeddedFile", b"URI", b"RichMedia", b"XFA", b"SubmitForm", b"GoToR"):
            with self.subTest(name=name):
                report = self.expect("watched_name_presence", pdf(b"/" + name + b" null"))
                self.assertEqual(report["name_counts"]["document"]["/" + name.decode()]["count"], 1)
                self.assertFalse(any(f["status"] == "FAIL" for f in report["findings"]))
                self.assertNotIn('"malicious":', json.dumps(report))

    def test_encoded_name_exact_byte_offset(self):
        data = pdf(b"/J#53 null /Java#53cript null /Open#41ction null")
        report = self.check(data)
        for raw, name in ((b"/J#53", "/JS"), (b"/Java#53cript", "/JavaScript"), (b"/Open#41ction", "/OpenAction")):
            item = report["name_counts"]["document"][name]
            self.assertEqual(item["count"], 1)
            self.assertEqual(item["encoded_count"], 1)
            self.assertEqual(item["offsets"], [data.index(raw)])

    def test_name_delimiters_and_exact_case(self):
        report = self.check(pdf(b"/Note /JSsuffix /Other /js"))
        self.assertEqual(report["status"], "PASS", report)
        self.assertEqual(report["name_counts"]["document"]["/JS"]["count"], 0)

    def test_comment_spelling_does_not_become_name(self):
        data = pdf(b"\n% /JS /J#53 /Launch stream obj\n")
        report = self.check(data)
        self.assertEqual(report["status"], "PASS", report)
        self.assertEqual(report["name_counts"]["comment"]["/JS"]["count"], 2)
        self.assertEqual(report["name_counts"]["comment"]["/JS"]["encoded_count"], 1)
        self.assertEqual(report["name_counts"]["document"]["/JS"]["count"], 0)
        self.assertEqual(report["structural_counts"]["stream"]["count"], 0)

    def test_literal_nesting_escape_and_line_continuation(self):
        for extra in (b"/Note (/JS (nested /Launch) /J#53)", b"/Note (escaped \\( /JS \\) end)", b"/Note (line\\\r\n /JS)"):
            report = self.check(pdf(extra))
            self.assertEqual(report["status"], "PASS", report)
            self.assertGreater(report["name_counts"]["literal_string"]["/JS"]["count"], 0)
            self.assertEqual(report["name_counts"]["document"]["/JS"]["count"], 0)

    def test_octal_string_not_decoded_as_name(self):
        report = self.check(pdf(b"/Note (\\057JS)"))
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["name_counts"]["literal_string"]["/JS"]["count"], 0)

    def test_hex_string_is_not_document_name(self):
        for value in (b"<2f4a53>", b"<2 f4 a5 3>", b"<ABC>", b"<>"):
            report = self.check(pdf(b"/Note " + value))
            self.assertEqual(report["status"], "PASS", report)
            self.assertEqual(report["name_counts"]["document"]["/JS"]["count"], 0)

    def test_malformed_name_escapes_remain_unknown(self):
        for raw in (b"/J#5", b"/J#ZZ", b"/J#00S", b"/"):
            self.expect("name_encoding", pdf(raw + b" null"))

    def test_unterminated_literal_and_hex(self):
        self.expect("unterminated_literal", b"%PDF-1.7\n1 0 obj << /Note (unterminated /JS")
        self.expect("unterminated_hex", b"%PDF-1.7\n1 0 obj << /Note <123")

    def test_invalid_hex_and_container_mismatch(self):
        self.expect("invalid_hex_string", pdf(b"/Note <zz>"), status="FAIL")
        self.expect("container_mismatch", pdf(b"]"), status="FAIL")
        self.expect("unexpected_delimiter", pdf(b")"), status="FAIL")

    def test_unknown_keyword_and_dictionary_grammar(self):
        self.expect("unknown_keyword", pdf(b"/Note unrecognized"))
        self.expect("dictionary_grammar", pdf(b"/Missing"))
        self.expect("duplicate_dictionary_key", pdf(b"/Note null /Note false"))

    def test_supported_direct_stream_is_opaque(self):
        data = pdf(stream=b"/JS /J#53 endstream %%EOF /Launch")
        report = self.expect("opaque_stream", data)
        self.assertTrue(report["lexical_complete"])
        self.assertEqual(report["name_counts"]["stream_bytes"]["/JS"]["count"], 2)
        self.assertEqual(report["name_counts"]["document"]["/JS"]["count"], 0)
        self.assertEqual(report["structural_counts"]["endstream"]["count"], 1)
        self.assertEqual(report["eof"]["count"], 1)

    def test_empty_stream_and_crlf(self):
        for eol in (b"\n", b"\r\n", b"\r"):
            report = self.expect("opaque_stream", pdf(stream=b"", eol=eol))
            self.assertEqual(report["eof"]["count"], 1)

    def test_indirect_or_duplicate_stream_length_is_unknown(self):
        for value in (b"/Length 5 0 R", b"/Length 5 /Length 5", b"/Length -1", b"/Length 1.0", b"/Length /Unknown", b"/Other /Length 5", b"/Type /Something"):
            data = b"%PDF-1.7\n1 0 obj << " + value + b" >>\nstream\n/JS\nendstream\nendobj\n%%EOF\n"
            report = self.expect("stream_length_unresolved", data)
            self.assertFalse(report["lexical_complete"])
            self.assertEqual(report["name_counts"]["document"]["/JS"]["count"], 0)

    def test_bad_stream_boundary_and_eol(self):
        self.expect("stream_boundary", pdf(stream=b"abc").replace(b"/Length 3", b"/Length 1"))
        self.expect("stream_eol", pdf(stream=b"abc").replace(b"\nstream\n", b"\nstream "))
        self.expect("stream_dictionary", b"%PDF-1.7\nstream\n/JS\nendstream\n%%EOF\n")

    def test_truncated_stream_and_open_structure(self):
        self.expect("truncated_stream", b"%PDF-1.7\n1 0 obj << /Length 1000 >>\nstream\nx")
        self.expect("truncated_structure", b"%PDF-1.7\n1 0 obj << /Note null\n%%EOF\n")

    def test_object_stream_filter_encryption_names_stay_open(self):
        for name in (b"ObjStm", b"Filter", b"Encrypt", b"XRef"):
            self.expect("unsupported_semantic_content", pdf(b"/Note /" + name))

    def test_missing_eof_one_byte_truncation(self):
        data = pdf().rstrip(b"\n")[:-1]
        self.expect("missing_eof", data)
        # Removing only the last EOL leaves an intact EOF token.
        self.assertEqual(self.check(pdf().rstrip(b"\n"))["status"], "PASS")

    def test_duplicate_eof_trailing_data_and_fake_markers(self):
        self.expect("multiple_eof", pdf() + b"%%EOF\n")
        self.expect("trailing_data", pdf() + b"private_payload")
        report = self.check(pdf(b"/Note (%%EOF)\n% text %%EOF\n"))
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["eof"]["count"], 1)

    def test_non_pdf_zip_prefixed_or_unknown_version(self):
        for data in (b"", b"%PDF", b"%PDF-1.", b"PK\x03\x04zip", b"prefix" + pdf(), b"%PDF-1.7 "+pdf()):
            self.expect("pdf_header", data)
        self.expect("pdf_version", pdf().replace(b"%PDF-1.7", b"%PDF-9.9"))

    def test_no_traditional_structure_is_unknown(self):
        self.expect("structural_presence", b"%PDF-1.7\n%%EOF\n")

    def test_invalid_object_or_orphan_endstream(self):
        self.expect("object_header", pdf().replace(b"1 0 obj", b"-1 0 obj"))
        self.expect("object_balance", pdf().replace(b"1 0 obj", b"1 0 endobj"))
        self.expect("orphan_endstream", pdf(b"/Note null endstream"))

    def test_bytes_tokens_regions_and_nesting_budgets(self):
        cases = [
            ("input_limit", replace(Limits(), input_bytes=100), pdf()),
            ("token_limit", replace(Limits(), tokens=3), pdf()),
            ("name_limit", replace(Limits(), name_bytes=8), pdf(b"/LongerName null")),
            ("word_limit", replace(Limits(), word_bytes=3), pdf()),
            ("literal_limit", replace(Limits(), literal_bytes=5), pdf(b"/Note (123456)")),
            ("hex_limit", replace(Limits(), hex_bytes=5), pdf(b"/Note <0123456789>")),
            ("comment_limit", replace(Limits(), comment_bytes=10), pdf(b"\n% " + b"x" * 20 + b"\n")),
            ("stream_limit", replace(Limits(), stream_bytes=2), pdf(stream=b"abc")),
            ("nesting_limit", replace(Limits(), nesting=2), pdf(b"/Note [[[null]]]")),
            ("nesting_limit", replace(Limits(), nesting=2), pdf(b"/Note (((text)))")),
            ("container_token_limit", replace(Limits(), dictionary_tokens=2), pdf()),
        ]
        for code, limits, data in cases:
            with self.subTest(code=code):
                self.expect(code, data, limits=limits)

    def test_offset_budget_keeps_counts_partial_offsets(self):
        report = self.expect("offset_limit", pdf(b"/JS null /AA null"), limits=replace(Limits(), offsets=2))
        self.assertFalse(report["offsets_complete"])
        self.assertEqual(report["name_counts"]["document"]["/JS"]["count"], 1)

    def test_finding_and_report_budgets(self):
        report = self.expect("finding_limit", pdf(b") ] }"), status="FAIL", limits=replace(Limits(), findings=2))
        self.assertFalse(report["lexical_complete"])
        report = self.expect("report_limit", pdf(b"\n% " + b"/JS " * 500 + b"\n"), limits=replace(Limits(), report_bytes=8192))
        self.assertFalse(report["lexical_complete"])

    def test_current_failure_is_retained_when_prior_open_findings_fill_budget(self):
        for count in (2, Limits().findings):
            data = b"%PDF-1.7\n" + b"unknown\n" * (count - 1) + b"]\n%%EOF\n"
            with self.subTest(findings=count):
                report = self.expect("container_mismatch", data, status="FAIL",
                                     limits=replace(Limits(), findings=count))
                self.assertEqual(len(report["findings"]), count)
                self.assertIn("finding_limit", [f["code"] for f in report["findings"]])
                self.assertFalse(report["lexical_complete"])
                self.assertEqual(report["document_safety"], "OPEN")

    def test_failure_survives_findings_and_report_reduction(self):
        data = b"%PDF-1.7\n% " + b"/JS " * 1000 + b"\nunknown\n]\n%%EOF\n"
        report = self.expect("container_mismatch", data, status="FAIL",
                             limits=replace(Limits(), findings=2, report_bytes=8192))
        self.assertIn("report_limit", [f["code"] for f in report["findings"]])
        self.assertFalse(report["lexical_complete"])

    def test_local_contract_and_io_errors_hide_paths(self):
        for path in ("https://example.invalid/private.pdf", "@list.txt", "-", self.root, self.root / "private_missing.pdf"):
            report = review_pdf(path)
            self.assertEqual(report["status"], "OPEN")
            if len(str(path)) > 1:
                self.assertNotIn(str(path), json.dumps(report))
            self.assertNotIn("input_path", report)
        target = self.root / "target.pdf";target.write_bytes(pdf())
        self.path.symlink_to(target)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertEqual(review_pdf(self.path)["status"], "OPEN")
        self.path.unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.path)
            self.assertEqual(review_pdf(self.path)["status"], "OPEN")

    def test_report_privacy_for_private_content(self):
        secret = b"unrelated_private_text_9aa31"
        data = pdf(b"/" + secret + b" (" + secret + b" /JS)\n% " + secret + b" /AA\n")
        report = self.check(data)
        rendered = json.dumps(report)
        self.assertNotIn(secret.decode(), rendered)
        self.assertNotIn(str(self.path), rendered)
        self.assertEqual(report["status"], "PASS", report)

    def test_no_url_process_zip_decompression_or_writeback(self):
        data = pdf(b"/JS () /URI (https://example.invalid/) ")
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network")), \
             mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("url")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             mock.patch.object(zipfile, "ZipFile", side_effect=AssertionError("zip")), \
             mock.patch.object(zlib, "decompress", side_effect=AssertionError("decompress")):
            self.expect("watched_name_presence", data)

    def test_cli_statuses_and_removed_options(self):
        for data, expected in [(pdf(), 0), (pdf(b"]"), 1), (pdf(b"/JS ()"), 2)]:
            self.path.write_bytes(data)
            with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(main([str(self.path)]), expected)
                self.assertEqual(json.loads(output.getvalue())["status"], {0:"PASS",1:"FAIL",2:"OPEN"}[expected])
        for option in ("--plugins", "--select", "--disarm", "--output", "--scan", "--recursedir"):
            with mock.patch("sys.stderr", new_callable=io.StringIO) as error, \
                    mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(main([str(self.path), option]), 2)
                self.assertEqual(error.getvalue(), "")
                self.assertEqual(json.loads(output.getvalue())["findings"][0]["code"], "invalid_arguments")

    def test_cli_invalid_or_missing_arguments_are_private_open_json(self):
        private = "PRIVATE_ARGUMENT_MARKER"
        for arguments in ([], [private, "--unsupported=" + private],
                          [private, "--plugins", private], ["--unsupported=" + private]):
            with self.subTest(arguments=arguments), \
                    mock.patch("sys.stderr", new_callable=io.StringIO) as error, \
                    mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(main(arguments), 2)
                self.assertEqual(error.getvalue(), "")
                self.assertNotIn(private, output.getvalue())
                report = json.loads(output.getvalue())
                self.assertEqual(report["status"], "OPEN")
                self.assertFalse(report["lexical_complete"])
                self.assertEqual(report["input_sha256"], None)
                self.assertEqual(report["document_safety"], "OPEN")
                self.assertEqual(report["action_semantics"], "OPEN")
                self.assertEqual(report["xref_object_resolution"], "OPEN")

    def test_limits_only_tighten(self):
        for limits in (replace(Limits(), tokens=0), replace(Limits(), tokens=True), replace(Limits(), input_bytes=Limits().input_bytes+1)):
            with self.assertRaises(ValueError):
                review_pdf(self.path, limits=limits)

    def test_wrong_limit_types_are_not_defaulted(self):
        for value in (0, False, "", {}, [], 1):
            with self.subTest(value=value), self.assertRaises(TypeError):
                review_pdf(self.path, limits=value)

    def test_compressed_stream_is_not_decompressed_or_classified_clean(self):
        compressed = zlib.compress(b"/JS /JavaScript")
        data = pdf(stream=compressed)
        old = b"<< /Length " + str(len(compressed)).encode() + b" >>"
        data = data.replace(old, old[:-2] + b"/Filter /FlateDecode >>")
        with mock.patch.object(zlib, "decompress", side_effect=AssertionError("must remain opaque")):
            report = self.expect("opaque_stream", data)
        self.assertIn("unsupported_semantic_content", self.codes(report))
        self.assertEqual(report["name_counts"]["document"]["/JS"]["count"], 0)

    def test_stream_dictionary_keys_distinguish_name_values(self):
        data = pdf(stream=b"abc")
        data = data.replace(b"/Length 3", b"/Other /Length /Length 3")
        report = self.expect("opaque_stream", data)
        self.assertNotIn("stream_length_unresolved", self.codes(report))
        self.assertNotIn("duplicate_dictionary_key", self.codes(report))

    def test_nested_dictionary_grammar_is_checked(self):
        self.expect("dictionary_grammar", pdf(b"/Note << /Key >>"))
        self.expect("duplicate_dictionary_key", pdf(b"/Note [ << /Key true /Key false >> ]"))

    def test_eof_line_prefix_must_be_whitespace(self):
        data = pdf().replace(b"%%EOF\n", b"null %%EOF\n")
        self.expect("missing_eof", data)

    def test_counts_continue_after_offset_limit_without_private_excerpt(self):
        data = pdf(b"/JS null /AA null /Launch null")
        report = self.expect("offset_limit", data, limits=replace(Limits(), offsets=1))
        for name in ("/JS", "/AA", "/Launch"):
            self.assertEqual(report["name_counts"]["document"][name]["count"], 1)
        self.assertTrue(report["lexical_complete"])


if __name__ == "__main__":
    unittest.main()
