"""Tests for kernel module inspection (decompression, modinfo, symbols)."""

from __future__ import annotations

import os
import unittest

import swissfirm.kernelmod as km
from helpers import TempFs


class ModinfoTest(unittest.TestCase):
    def test_plain_module_modinfo(self):
        with TempFs() as root:
            path = os.path.join(root, "lib/modules/5.10.0/kernel/drivers/wifi.ko")
            info = km.read_modinfo(path)
            self.assertEqual(info["name"], "wifi")
            self.assertEqual(info["license"], "GPL")
            self.assertEqual(info["depends"], "tun,cfg80211")
            self.assertIn("5.10.0", info["vermagic"])

    def test_compressed_module_decompressed_and_parsed(self):
        with TempFs() as root:
            gz_path = os.path.join(
                root, "lib/modules/5.10.0/kernel/drivers/wifi.ko.gz"
            )
            self.assertTrue(km.is_module_path(gz_path))
            with km.ModuleWorkspace() as ws:
                target = ws.resolve(gz_path)
                info = km.read_modinfo(target)
                self.assertEqual(info["name"], "wifi")
                funcs = km.format_module_functions(target)
                names = {f["name"] for f in funcs}
                self.assertIn("wifi_probe.isra.1", names)
                # mapping symbols never appear in the function listing
                self.assertNotIn("$a", names)

    def test_format_module_functions_uses_section_offsets(self):
        with TempFs() as root:
            path = os.path.join(root, "lib/modules/5.10.0/kernel/drivers/wifi.ko")
            rows = km.format_module_functions(path)
            addrs = {r["address"] for r in rows}
            self.assertIn(".text+0xc0", addrs)
            for row in rows:
                self.assertTrue(row["address"].startswith(".text+"))

    def test_iter_kernel_modules_finds_compressed(self):
        with TempFs() as root:
            found = km.iter_kernel_modules(root)
            names = {os.path.basename(p) for p in found}
            self.assertIn("wifi.ko", names)
            self.assertIn("wifi.ko.gz", names)

    def test_modinfo_table_ordering(self):
        with TempFs() as root:
            path = os.path.join(root, "lib/modules/5.10.0/kernel/drivers/wifi.ko")
            rows = km.modinfo_table(km.read_modinfo(path))
            keys = [k for k, _ in rows]
            self.assertEqual(keys[0], "name")
            self.assertIn("vermagic", keys)
            self.assertIn("license", keys)


if __name__ == "__main__":
    unittest.main()
