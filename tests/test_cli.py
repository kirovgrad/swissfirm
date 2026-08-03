"""Tests for the report rendering and the CLI."""

from __future__ import annotations

import json
import os
import unittest
from contextlib import redirect_stdout
from io import StringIO

import swissfirm.report as report
from swissfirm import cli
from swissfirm.searchers import SearchResult
from helpers import TempFs


def _result() -> SearchResult:
    return SearchResult(
        title="demo",
        columns=["name", "value"],
        rows=[{"name": "a", "value": 1}, {"name": "b", "value": "long " * 30}],
        summary="2 rows",
    )


class ReportRenderTest(unittest.TestCase):
    def test_table_contains_header_and_rows(self):
        out = report.render_result(_result(), fmt="table")
        self.assertIn("demo", out)
        self.assertIn("name", out)
        self.assertIn("a", out)

    def test_markdown(self):
        out = report.render_result(_result(), fmt="markdown")
        self.assertIn("| name", out)
        self.assertIn("| ---", out)

    def test_json_parseable(self):
        out = report.render_result(_result(), fmt="json")
        data = json.loads(out)
        self.assertEqual(data["title"], "demo")
        self.assertEqual(len(data["rows"]), 2)

    def test_max_rows_truncates(self):
        out = report.render_result(_result(), fmt="table", max_rows=1)
        self.assertIn("more row(s) omitted", out)

    def test_long_cells_are_ellipsized(self):
        out = report.render_result(_result(), fmt="table")
        self.assertIn("…", out)


class CliTest(unittest.TestCase):
    def test_requires_fsdir(self):
        with TempFs() as root:
            with self.assertRaises(SystemExit):
                cli.main([root])  # no operation selected

    def test_origin(self):
        with TempFs() as root:
            out = StringIO()
            with redirect_stdout(out):
                rc = cli.main([root, "-fo", "wifi_probe", "-q"])
            self.assertEqual(rc, 0)
            self.assertIn("wifi_probe", out.getvalue())

    def test_kernel_symbols(self):
        with TempFs() as root:
            out = StringIO()
            with redirect_stdout(out):
                rc = cli.main([root, "-ko", "wifi.ko", "-q"])
            self.assertEqual(rc, 0)
            self.assertIn(".text+0xc0", out.getvalue())

    def test_json_output_file(self):
        with TempFs() as root:
            out_path = os.path.join(root, "report.json")
            out = StringIO()
            with redirect_stdout(out):
                rc = cli.main([root, "-i", "-o", out_path, "--format", "json", "-q"])
            self.assertEqual(rc, 0)
            with open(out_path) as fh:
                data = json.load(fh)
            self.assertEqual(data["title"], "ELF inventory")

    def test_missing_operation_error(self):
        with TempFs() as root:
            # invalid mnemonic arch => SearchError surfaced as exit code 2
            self.assertEqual(cli.main([root, "-fm", "bad:insn", "-q"]), 2)

    def test_nonexistent_dir_rejected(self):
        with self.assertRaises(SystemExit):
            cli.main(["/definitely/not/a/real/path", "-fo", "x"])


if __name__ == "__main__":
    unittest.main()
