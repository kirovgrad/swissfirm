"""Tests for the pyelftools-backed ELF view."""

from __future__ import annotations

import os
import tempfile
import unittest

import swissfirm.elf as elf
import swissfirm.symbols as symbols
from elfbuilder import build_dynamic, build_reloc
from helpers import TempFs


class ElfBasicsTest(unittest.TestCase):
    def test_relocatable_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.o")
            build_reloc(path, text=b"\xc3", symbols=[("add", 0, 8, 1, 2, 1)])
            e = elf.parse_elf(path)
            self.assertTrue(e.is_relocatable)
            self.assertEqual(e.elf_class, 64)
            self.assertEqual(e.endianness, "little")
            self.assertEqual(e.machine_name, "x86-64")

    def test_dynamic_needed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "libx.so")
            build_dynamic(path, needed=["liba.so.1", "libb.so"])
            e = elf.parse_elf(path)
            self.assertTrue(e.is_shared)
            self.assertEqual(e.needed, ["liba.so.1", "libb.so"])

    def test_not_elf_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "junk")
            with open(path, "w") as fh:
                fh.write("not an elf")
            with self.assertRaises(elf.ElfParseError):
                elf.parse_elf(path)

    def test_function_symbols_filtered(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "m.ko")
            build_reloc(
                path,
                symbols=[
                    ("func_a", 0x0, 16, 1, 2, 1),     # global func
                    ("func_b.isra.0", 0x20, 8, 1, 2, 1),  # gcc clone
                    ("$a", 0x0, 0, 0, 0, 1),            # mapping symbol
                    (".Ltmp0", 0x30, 4, 0, 2, 1),        # local label
                    ("__ksymtab_x", 0x0, 8, 1, 1, 2),    # object, not func
                    ("", 0x40, 4, 0, 0, 1),              # anonymous
                ],
            )
            e = elf.parse_elf(path)
            funcs = symbols.iter_function_symbols(e)
            names = [s.name for s in funcs]
            self.assertIn("func_a", names)
            self.assertIn("func_b.isra.0", names)
            self.assertNotIn("$a", names)
            self.assertNotIn(".Ltmp0", names)
            self.assertNotIn("__ksymtab_x", names)
            self.assertNotIn("", names)

    def test_human_address_relocatable_vs_linked(self):
        with tempfile.TemporaryDirectory() as tmp:
            rel = os.path.join(tmp, "r.o")
            build_reloc(rel, symbols=[("add", 0x10, 8, 1, 2, 1)])
            e1 = elf.parse_elf(rel)
            sym = e1.defined_functions()[0]
            self.assertEqual(symbols.human_address(e1, sym), ".text+0x10")

            dyn = os.path.join(tmp, "d.so")
            build_dynamic(dyn, needed=[])
            e2 = elf.parse_elf(dyn)
            self.assertTrue(symbols.human_address(e2, sym).startswith("0x"))


class GccBaseTest(unittest.TestCase):
    def test_strips_clone_suffixes(self):
        self.assertEqual(symbols.gcc_base("foo"), "foo")
        self.assertEqual(symbols.gcc_base("foo.isra.3"), "foo")
        self.assertEqual(symbols.gcc_base("foo.constprop.0"), "foo")
        self.assertEqual(symbols.gcc_base("foo.part.2"), "foo")
        self.assertEqual(symbols.gcc_base("foo.cfi"), "foo")
        self.assertEqual(symbols.gcc_base("foo.bar"), "foo.bar")

    def test_versionless(self):
        self.assertEqual(symbols.versionless("printf@GLIBC_2.2.5"), "printf")
        self.assertEqual(symbols.versionless("printf@@GLIBC_2.2.5"), "printf")
        self.assertEqual(symbols.versionless("printf"), "printf")


class KernelModuleTest(unittest.TestCase):
    def test_is_kernel_module(self):
        with TempFs() as root:
            path = os.path.join(root, "lib/modules/5.10.0/kernel/drivers/wifi.ko")
            e = elf.parse_elf(path)
            self.assertTrue(e.is_kernel_module())
            self.assertTrue(e.has_modinfo)

    def test_gcc_base_matches_isra_symbols(self):
        with TempFs() as root:
            path = os.path.join(root, "lib/modules/5.10.0/kernel/drivers/wifi.ko")
            e = elf.parse_elf(path)
            names = {symbols.gcc_base(s.name) for s in e.defined_functions()}
            self.assertIn("wifi_probe", names)


if __name__ == "__main__":
    unittest.main()
