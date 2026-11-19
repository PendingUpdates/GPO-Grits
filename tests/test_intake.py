"""Regression coverage for timestamps, XML intake, and output protection."""
import contextlib
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from grits.cli import main
from grits.gpo import load_xml
from grits.rsop import _reported_time


class IntakeTests(unittest.TestCase):
    def test_journal_time_retains_windows_precision(self):
        stamp = "2024-06-01T12:00:00.1234567Z"
        root = load_xml(f'<Rsop xmlns="http://www.microsoft.com/GroupPolicy/Rsop"><ReadTime>{stamp}</ReadTime></Rsop>'.encode())
        self.assertEqual(_reported_time(root), stamp)

    def test_document_types_are_rejected_in_windows_encoding(self):
        with self.assertRaisesRegex(ValueError, "document type"):
            load_xml("<!DOCTYPE GPO><GPO/>".encode("utf-16"))

    def test_rejected_import_writes_both_files_and_refuses_overwrite(self):
        with TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            root = Path(folder)
            report = root / "output"
            args = ["audit", "--gpo", str(root / "missing.xml"), "--out", str(report)]
            self.assertEqual(main(args), 1)
            copies = {f.name: f.read_bytes() for f in report.iterdir()}
            self.assertEqual(set(copies), {"report.html", "report.json"})
            with self.assertRaises(SystemExit) as raised:
                main(args)
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(copies, {f.name: f.read_bytes() for f in report.iterdir()})
