"""Tests for the search operations."""

from __future__ import annotations

import os
import tempfile
import unittest

import swissfirm.searchers as s
from elfbuilder import build_dynamic, build_reloc
from helpers import TempFs


class FunctionSearcherTest(unittest.TestCase):
    def test_exact_match_ignores_gcc_clones(self):
        with TempFs() as root:
            result = s.FunctionSearcher(root, "wifi_probe", whole_name=True).run()
            rows = result.rows
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["name"].startswith("wifi_probe"))

    def test_substring_match(self):
        with TempFs() as root:
            result = s.FunctionSearcher(root, "probe", whole_name=False).run()
            names = {r["name"] for r in result.rows}
            self.assertIn("wifi_probe.isra.1", names)

    def test_no_match(self):
        with TempFs() as root:
            result = s.FunctionSearcher(root, "does_not_exist_xyz").run()
            self.assertEqual(len(result.rows), 0)

    def test_mapping_symbols_never_returned(self):
        with TempFs() as root:
            result = s.FunctionSearcher(root, "$a", whole_name=False).run()
            self.assertEqual(len(result.rows), 0)

    def test_module_rows_use_section_relative_addresses(self):
        with TempFs() as root:
            result = s.FunctionSearcher(root, "init_module").run()
            for row in result.rows:
                self.assertTrue(row["address"].startswith(".text+"))


class ByteSearcherTest(unittest.TestCase):
    def test_hex_flexibility(self):
        with TempFs() as root:
            # bytes of 'add' from the builder's .text: 55 48 89 e5 c3
            r1 = s.ByteSearcher(root, "55 48 89 e5").run()
            self.assertGreater(len(r1.rows), 0)
            r2 = s.ByteSearcher(root, "0x554889e5").run()
            self.assertEqual(len(r1.rows), len(r2.rows))

    def test_invalid_hex_raises(self):
        with TempFs() as root:
            with self.assertRaises(s.SearchError):
                s.ByteSearcher(root, "zz").run()

    def test_empty_pattern_raises(self):
        with TempFs() as root:
            with self.assertRaises(s.SearchError):
                s.ByteSearcher(root, "").run()


class MnemonicSearcherTest(unittest.TestCase):
    def test_bad_arch_raises(self):
        with TempFs() as root:
            with self.assertRaises(s.SearchError):
                s.MnemonicSearcher(root, "vax:movl r0,r1").run()

    def test_bad_spec_raises(self):
        with TempFs() as root:
            with self.assertRaises(s.SearchError):
                s.MnemonicSearcher(root, "noarchnoinstruction").run()


class NeededLibSearcherTest(unittest.TestCase):
    def test_recursive_resolution_with_missing(self):
        with TempFs() as root:
            result = s.NeededLibSearcher(root, "myapp").run()
            by_lib = {r["lib"]: r["path"] for r in result.rows}
            self.assertEqual(by_lib["libc.so.6"], "lib/libc.so.6")
            self.assertEqual(by_lib["libm.so.6"], "lib/libm.so.6")
            self.assertEqual(by_lib["libfoo.so.1"], "<missing>")

    def test_cycle_does_not_loop_forever(self):
        with TempFs() as root:
            result = s.NeededLibSearcher(root, "libc.so.6").run()
            by_lib = {r["lib"] for r in result.rows}
            self.assertIn("libm.so.6", by_lib)
            self.assertNotIn("libc.so.6", by_lib)  # initial itself is not a "needed"

    def test_initial_not_found_raises(self):
        with TempFs() as root:
            with self.assertRaises(s.SearchError):
                s.NeededLibSearcher(root, "ghost_binary").run()


if __name__ == "__main__":
    unittest.main()
