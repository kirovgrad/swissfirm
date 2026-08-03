from __future__ import annotations

import binascii
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import symbols as _symbols
from .util import parallel_map, relpath, walk_elf_files


class SearchError(Exception):
    """User-facing error (bad input, missing tool, unsupported arch)."""


class ElfParseError(Exception):
    """Raised when a file cannot be interpreted as a supported ELF."""


@dataclass
class SearchResult:
    title: str
    columns: List[str]
    rows: List[Dict[str, object]] = field(default_factory=list)
    summary: Optional[str] = None


def _parse_elf(path: str):
    try:
        return _symbols.parse_elf(path)
    except Exception as exc:
        raise ElfParseError(f"failed to parse {path!r}: {exc}") from exc


# ---------------------------------------------------------------------------
# function origin / substring search
# ---------------------------------------------------------------------------

class FunctionSearcher:
    """Locate which binary defines a function, by exact name or substring.

    Correct across ELF kinds:

    * relocatable objects (kernel modules) are matched on section-relative
      symbols, so ``.text+0x..`` offsets are reported instead of fake VA's;
    * GCC clone suffixes (``foo.isra.0``) are ignored for exact matches;
    * version suffixes (``foo@GLIBC_2.2``) are ignored;
    * ARM mapping symbols / ``.L`` labels are never reported.
    """

    def __init__(
        self,
        root: str,
        query: str,
        whole_name: bool = True,
        jobs: int = 10,
    ) -> None:
        self.root = os.path.abspath(root)
        self.query = query.strip().lower()
        self.whole_name = whole_name
        self.jobs = jobs
        if not self.query:
            raise SearchError("empty function/substring query")

    def _scan_one(self, path: str) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        try:
            elffile = _parse_elf(path)
        except ElfParseError:
            return rows
        for sym in _symbols.iter_function_symbols(elffile):
            base = _symbols.gcc_base(_symbols.versionless(sym.name)).lower()
            if self.whole_name:
                if base != self.query:
                    continue
            else:
                if self.query not in base:
                    continue
            rows.append(
                {
                    "file": relpath(path, self.root),
                    "section": sym.section,
                    "offset": sym.value,
                    "address": _symbols.human_address(elffile, sym),
                    "size": sym.size,
                    "bind": sym.bind_name(),
                    "type": _symbols.nm_letter(sym),
                    "name": sym.name,
                }
            )
            if self.whole_name:
                break
        return rows

    def run(self) -> SearchResult:
        files = list(walk_elf_files(self.root))
        collected = parallel_map(self._scan_one, files, self.jobs)
        rows = [row for chunk in collected for row in chunk]
        rows.sort(key=lambda r: (r["name"], r["file"]))
        title = "function origin" if self.whole_name else "function substring"
        return SearchResult(
            title=title,
            columns=["name", "file", "address", "size", "bind", "type"],
            rows=rows,
            summary=(
                f"{len(rows)} definition(s) of {self.query!r} across "
                f"{len(files)} ELF files"
            ),
        )


# ---------------------------------------------------------------------------
# raw byte pattern search
# ---------------------------------------------------------------------------

class ByteSearcher:
    """Search for a raw byte pattern (hex string or ``0x``/whitespace form)."""

    def __init__(self, root: str, hex_bytes: str, jobs: int = 10, per_file: int = 10):
        self.root = os.path.abspath(root)
        self.hex_input = hex_bytes
        self.jobs = jobs
        self.per_file = per_file
        try:
            self.search_bytes = binascii.unhexlify(
                hex_bytes.replace("0x", "").replace("0X", "").replace(" ", "")
            )
        except (binascii.Error, ValueError) as exc:
            raise SearchError(f"invalid hex string: {exc}") from exc
        if not self.search_bytes:
            raise SearchError("empty byte pattern")

    def _scan_one(self, path: str) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return rows
        hay = self.search_bytes
        pos = data.find(hay)
        count = 0
        while pos != -1:
            rows.append(
                {
                    "file": relpath(path, self.root),
                    "offset": pos,
                    "hex": f"0x{pos:x}",
                }
            )
            count += 1
            if count >= self.per_file:
                break
            pos = data.find(hay, pos + 1)
        return rows

    def run(self) -> SearchResult:
        files = list(walk_elf_files(self.root))
        collected = parallel_map(self._scan_one, files, self.jobs)
        rows = [row for chunk in collected for row in chunk]
        return SearchResult(
            title="byte pattern",
            columns=["file", "offset"],
            rows=rows,
            summary=(
                f"{len(rows)} hit(s) for {self.search_bytes.hex()} "
                f"across {len(files)} ELF files"
            ),
        )


# ---------------------------------------------------------------------------
# mnemonic -> bytes search (keystone)
# ---------------------------------------------------------------------------

_KS_ARCHES = {
    "i386": ("KS_ARCH_X86", "KS_MODE_32"),
    "x8664": ("KS_ARCH_X86", "KS_MODE_64"),
    "arm32": ("KS_ARCH_ARM", "KS_MODE_ARM"),
    "thumb": ("KS_ARCH_ARM", "KS_MODE_THUMB"),
    "arm64": ("KS_ARCH_ARM64", "KS_MODE_LITTLE_ENDIAN"),
    "mips32": ("KS_ARCH_MIPS", "KS_MODE_MIPS32"),
    "mips64": ("KS_ARCH_MIPS", "KS_MODE_MIPS64"),
    "ppc": ("KS_ARCH_PPC", "KS_MODE_BIG_ENDIAN"),
    "ppc64": ("KS_ARCH_PPC64", "KS_MODE_BIG_ENDIAN"),
    "riscv64": ("KS_ARCH_RISCV", "KS_MODE_RISCV64"),
}


def assemble_mnemonics(spec: str) -> bytes:
    """``arch:instruction;instruction`` -> assembled bytes (keystone)."""
    try:
        arch, instructions = (part.strip() for part in spec.split(":", 1))
    except ValueError as exc:
        raise SearchError(
            "invalid mnemonic spec - expected 'arch:instruction;instruction'"
        ) from exc
    arch = arch.lower()
    if arch not in _KS_ARCHES:
        raise SearchError(
            f"unsupported arch {arch!r} - use one of: {', '.join(sorted(_KS_ARCHES))}"
        )
    try:
        from keystone import Ks, KsError  # type: ignore

        arch_attr, mode_attr = _KS_ARCHES[arch]
        ks = Ks(getattr(Ks, arch_attr), getattr(Ks, mode_attr))
    except ImportError as exc:
        raise SearchError(
            "keystone-engine is required for mnemonic search - "
            "install it with: pip install keystone-engine"
        ) from exc
    except AttributeError as exc:
        raise SearchError(f"keystone lacks arch/mode {arch_attr}/{mode_attr}") from exc
    try:
        encoding, _count = ks.asm(instructions)
    except KsError as exc:  # type: ignore
        raise SearchError(f"assembly failed: {exc}") from exc
    if not encoding:
        raise SearchError("assembly produced no bytes")
    return bytes(encoding)


class MnemonicSearcher(ByteSearcher):
    def __init__(self, root: str, spec: str, jobs: int = 10, per_file: int = 10):
        super().__init__(root, assemble_mnemonics(spec).hex(), jobs, per_file)
        self.spec = spec

    def run(self) -> SearchResult:
        result = super().run()
        result.title = "mnemonic pattern"
        result.summary = f"assembled {self.spec!r} -> {self.search_bytes.hex()} bytes"
        return result


# ---------------------------------------------------------------------------
# needed-library resolution
# ---------------------------------------------------------------------------

class NeededLibSearcher:
    """Recursively resolve the shared libraries a binary depends on.

    Resolution is by basename against the ELF files present in the firmware
    tree (with a tolerant prefix fallback, e.g. ``libm.so.6`` may resolve to
    ``libm.so.6.1``), so results distinguish *available in the tree* from
    *missing* (would need to be provided by the root filesystem / kernel).
    """

    def __init__(self, root: str, lib_name: str, jobs: int = 10):
        self.root = os.path.abspath(root)
        self.lib_name = lib_name
        self.jobs = jobs

    def _find_initial(self, basename_map: Dict[str, str], stem_map: Dict[str, str]) -> str:
        if self.lib_name in basename_map:
            return basename_map[self.lib_name]
        if self.lib_name in stem_map:
            return stem_map[self.lib_name]
        raise SearchError(
            f"initial binary {self.lib_name!r} not found among ELF files in {self.root}"
        )

    def run(self) -> SearchResult:
        files = list(walk_elf_files(self.root))
        basename_map: Dict[str, str] = {}
        stem_map: Dict[str, str] = {}
        for path in files:
            base = os.path.basename(path)
            basename_map.setdefault(base, path)
            stem_map.setdefault(base.split(".", 1)[0], path)

        def resolve(name: str) -> Optional[str]:
            if name in basename_map:
                return basename_map[name]
            candidates = [p for b, p in basename_map.items() if b.startswith(name + ".")]
            if candidates:
                return min(candidates, key=len)
            return None

        initial = self._find_initial(basename_map, stem_map)
        initial_base = os.path.basename(initial)

        try:
            init_elf = _parse_elf(initial)
        except ElfParseError:
            raise SearchError(f"{initial!r} is not a parseable ELF") from None

        visited: List[str] = []
        pending: List[str] = list(_symbols.get_needed(init_elf))
        available: Dict[str, str] = {}
        missing: List[str] = []
        chain: List[Dict[str, object]] = []

        while pending:
            name = pending.pop(0)
            if name in visited or name == initial_base:
                continue
            visited.append(name)
            resolved = resolve(name)
            if resolved is None:
                missing.append(name)
                continue
            available[name] = relpath(resolved, self.root)
            try:
                need = _symbols.get_needed(_parse_elf(resolved))
            except ElfParseError:
                need = []
            for dep in need:
                if dep not in visited and dep != initial_base:
                    pending.append(dep)
            chain.append({"lib": name, "path": relpath(resolved, self.root)})

        rows = [{"lib": name, "path": path} for name, path in sorted(available.items())]
        for name in sorted(missing):
            rows.append({"lib": name, "path": "<missing>"})

        summary = (
            f"{initial_base}: {len(available)} available, "
            f"{len(missing)} missing in {self.root}"
        )
        return SearchResult(
            title="needed libraries",
            columns=["lib", "path"],
            rows=rows,
            summary=summary,
        )
