"""Tests for the static-analysis passes."""

from __future__ import annotations

import unittest

import swissfirm.analyze as a
from helpers import TempFs


class StringsAnalyzerTest(unittest.TestCase):
    def test_finds_interesting_strings_in_plaintext_files(self):
        with TempFs() as root:
            result = a.StringsAnalyzer(root).run()
            cats = {r["category"] for r in result.rows}
            self.assertIn("credential", cats)
            self.assertIn("network", cats)
            self.assertIn("version", cats)
            strings = {r["string"] for r in result.rows}
            self.assertIn("password=admin123", strings)
            self.assertIn("http://evil.example.com", strings)

    def test_elf_only_mode_skips_configs(self):
        with TempFs() as root:
            result = a.StringsAnalyzer(root, elf_only=True).run()
            files = {r["file"] for r in result.rows}
            self.assertNotIn("etc/passwd", files)

    def test_min_len_enforced(self):
        with TempFs() as root:
            short = a.StringsAnalyzer(root, min_len=30).run()
            for row in short.rows:
                self.assertGreaterEqual(len(row["string"]), 30)


class SecurityAuditTest(unittest.TestCase):
    def test_report_columns_present(self):
        with TempFs() as root:
            result = a.SecurityAuditAnalyzer(root).run()
            self.assertGreater(len(result.rows), 0)
            for row in result.rows:
                for col in ("nx", "pie", "relro", "canary", "fortify", "score"):
                    self.assertIn(col, row)

    def test_dynamic_binaries_score_pie(self):
        with TempFs() as root:
            result = a.SecurityAuditAnalyzer(root).run()
            dyn = [r for r in result.rows if r["kind"] == "DYN"]
            self.assertGreater(len(dyn), 0)
            for row in dyn:
                self.assertEqual(row["pie"], "yes")


class DangerousImportsTest(unittest.TestCase):
    def test_classifies_dangerous_symbols(self):
        with TempFs() as root:
            result = a.DangerousImportsAnalyzer(root).run()
            # nothing dangerous is expected in the fixture, so it must not crash
            self.assertIsInstance(result.rows, list)

    def test_classify_helper(self):
        self.assertEqual(a._classify_dangerous("system"), "command-execution")
        self.assertEqual(a._classify_dangerous("strcpy"), "memory-unsafe")
        self.assertEqual(a._classify_dangerous("__sprintf_chk"), "memory-unsafe")
        self.assertEqual(a._classify_dangerous("MD5_Init"), "weak-crypto")
        self.assertIsNone(a._classify_dangerous("memset"))


class CryptoConstantsTest(unittest.TestCase):
    def test_finds_embedded_constants(self):
        import os

        from elfbuilder import build_reloc

        with TempFs() as root:
            # embed the AES S-box bytes in a relocatable's .text
            from swissfirm.analyze import _AES_SBOX

            build_reloc(
                os.path.join(root, "bin/crypto.o"),
                text=_AES_SBOX,
                symbols=[("aes_thing", 0, len(_AES_SBOX), 1, 2, 1)],
            )
            result = a.CryptoConstantsAnalyzer(root).run()
            sigs = {r["signature"] for r in result.rows}
            self.assertIn("AES forward S-box", sigs)


class InventoryTest(unittest.TestCase):
    def test_counts_binaries(self):
        with TempFs() as root:
            result = a.InventoryAnalyzer(root).run()
            self.assertGreater(len(result.rows), 0)
            kinds = {r["kind"] for r in result.rows}
            self.assertIn("module", kinds)
            self.assertIn("DYN", kinds)


class FirmwareSummaryTest(unittest.TestCase):
    def test_detects_kernel_version(self):
        with TempFs() as root:
            result = a.FirmwareSummaryAnalyzer(root).run()
            values = {r["value"] for r in result.rows}
            self.assertTrue(any("4.14.77" in str(v) for v in values))
            items = {r["item"] for r in result.rows}
            self.assertIn("total files", items)


class KernelAnalyzerTest(unittest.TestCase):
    def test_lists_modules_and_compressed(self):
        with TempFs() as root:
            result = a.KernelModulesAnalyzer(root).run()
            names = {r["name"] for r in result.rows}
            self.assertIn("wifi", names)
            for row in result.rows:
                if row["name"] == "wifi":
                    self.assertIn("5.10.0", row["vermagic"])

    def test_symbols_dumper(self):
        with TempFs() as root:
            result = a.KernelSymbolsDumper(root, "wifi.ko").run()
            names = {r["name"] for r in result.rows}
            self.assertIn("wifi_probe.isra.1", names)
            self.assertNotIn("$a", names)

    def test_symbols_dumper_rejects_non_module(self):
        with TempFs() as root:
            with self.assertRaises(ValueError):
                a.KernelSymbolsDumper(root, "myapp").run()


if __name__ == "__main__":
    unittest.main()
