"""Safe-read capability refusal is controlled and precedes any input open."""

from contextlib import redirect_stdout, redirect_stderr
import importlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pdf_action_review import cli
from pdf_action_review.review import Stop
reader = importlib.import_module("pdf_action_review.review")


def read(path):
    return reader.read_local(path, reader.Review(reader.Limits()))


class SafeReadCapabilities(unittest.TestCase):
    def test_missing_none_zero_bool_flags_refuse_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            original = reader.os.open
            for flag in ('O_NOFOLLOW', 'O_NONBLOCK'):
                for value in ("MISSING", None, 0, True, False):
                    with self.subTest(flag=flag, value=value):
                        with patch.object(reader.os, flag, value, create=True):
                            if value == "MISSING":
                                delattr(reader.os, flag)
                            with patch.object(reader.os, "open", wraps=original) as opened:
                                with patch.object(reader.os, "supports_dir_fd", set(reader.os.supports_dir_fd) | {opened}):
                                    with self.assertRaises(Stop) as failure:
                                        read(str(sample))
                                    pass  # Stop carries the fixed OPEN finding in the Review.
                                    output, errors = io.StringIO(), io.StringIO()
                                    with redirect_stdout(output), redirect_stderr(errors):
                                        exitcode = cli.main([str(sample)])
                                    self.assertEqual(exitcode, 2)
                                    if output.getvalue():
                                        self.assertEqual(json.loads(output.getvalue())["status"], "OPEN")
                                    self.assertNotIn(str(sample), output.getvalue()+errors.getvalue())
                                    opened.assert_not_called()
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_normal_file_and_symbolic_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            self.assertEqual(read(str(sample)), b"synthetic")
            link = sample.with_name("link.bin")
            link.symlink_to(sample)
            with self.assertRaises((Stop, OSError)):
                read(str(link))
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_zero_nofollow_refuses_symbolic_target_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            link = sample.with_name("link.bin")
            link.symlink_to(sample)
            with patch.object(reader.os, "O_NOFOLLOW", 0):
                with self.assertRaises(Stop):
                    read(str(link))
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    exitcode = cli.main([str(link)])
                self.assertEqual(exitcode, 2)
                if output.getvalue():
                    self.assertEqual(json.loads(output.getvalue())["status"], "OPEN")
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_unavailable_nonblocking_capability_never_opens_fifo(self):
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary).resolve() / "input.pipe"
            reader.os.mkfifo(fifo)
            original = reader.os.open
            with patch.object(reader.os, "O_NONBLOCK", None):
                with patch.object(reader.os, "open", wraps=original) as opened:
                    report = reader.review_pdf(str(fifo))
                    self.assertEqual(report["status"], "OPEN")
                    self.assertEqual(report["findings"][0]["code"], "safe_open_unsupported")
                    opened.assert_not_called()
