"""Kernel module (``.ko``) inspection.

Kernel modules are relocatable ELF objects (``ET_REL``) with a ``.modinfo``
section holding ``key=value`` metadata (``vermagic``, ``depends``, ...).
They are frequently shipped compressed (``.ko.gz`` / ``.ko.xz`` / ``.ko.zst``
/ ``.ko.bz2`` / ``.ko.lz4``), which this module transparently handles by
decompressing into a temporary directory before parsing.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import tempfile
from typing import Dict, List, Optional, Tuple

from . import symbols as _symbols
from .searchers import ElfParseError

KO_EXTENSIONS = (
    ".ko",
    ".ko.gz",
    ".ko.xz",
    ".ko.bz2",
    ".ko.zst",
    ".ko.lzma",
    ".ko.lz4",
)


def is_module_path(path: str) -> bool:
    """True if the file name looks like a (possibly compressed) kernel module."""
    return os.path.basename(path).endswith(KO_EXTENSIONS)


def iter_kernel_modules(root: str) -> List[str]:
    """All module-looking files under *root*, plus genuine ``.ko`` relocatables
    with a ``.modinfo`` section regardless of their file name."""
    found = []
    for path in _symbols._iter_files(root):
        if is_module_path(path):
            found.append(path)
    return found


class ModuleWorkspace:
    """Manages a temporary directory for decompressed modules."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="swissfirm-ko-")
        self._index: Dict[str, str] = {}

    def __enter__(self) -> "ModuleWorkspace":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()

    @property
    def tmpdir(self) -> str:
        return self._tmp.name

    def resolve(self, path: str) -> str:
        """Return a parseable ELF path for *path*, decompressing if needed."""
        if path in self._index:
            return self._index[path]
        result = _maybe_decompress(path, self.tmpdir)
        if result is not None:
            self._index[path] = result
            return result
        return path

    def cleanup(self) -> None:
        self._tmp.cleanup()


def _maybe_decompress(path: str, tmpdir: str) -> Optional[str]:
    """Decompress ``.ko.<comp>`` into *tmpdir* and return the new path."""
    if not is_module_path(path) or path.endswith(".ko"):
        return None
    base = os.path.basename(path)
    stem = base[:-3]
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    try:
        if base.endswith(".gz"):
            raw = gzip.decompress(data)
        elif base.endswith((".xz", ".lzma")):
            raw = lzma.decompress(data)
        elif base.endswith(".bz2"):
            raw = bz2.decompress(data)
        elif base.endswith(".zst"):
            try:
                import zstandard  # type: ignore

                raw = zstandard.ZstdDecompressor().decompress(
                    data, max_output_size=512 * 1024 * 1024
                )
            except ImportError:
                return None
        elif base.endswith(".lz4"):
            try:
                import lz4.frame  # type: ignore

                raw = lz4.frame.decompress(data)
            except ImportError:
                return None
        else:
            return None
    except Exception:
        return None

    out_path = os.path.join(tmpdir, stem)
    with open(out_path, "wb") as out:
        out.write(raw)
    return out_path


def read_modinfo(path: str) -> Dict[str, str]:
    """Parse the ``.modinfo`` section of a kernel module into ``{key: value}``.

    Takes the (already decompressed) ELF *path*.  Returns an empty dict when
    there is no modinfo section.
    """
    try:
        elffile = _symbols.parse_elf(path)
    except Exception:
        return {}
    sec = _symbols.get_section(elffile, ".modinfo")
    if sec is None:
        return {}
    try:
        with open(path, "rb") as fh:
            fh.seek(sec["sh_offset"])
            data = fh.read(sec["sh_size"])
    except OSError:
        return {}
    result: Dict[str, str] = {}
    for chunk in data.split(b"\x00"):
        if b"=" in chunk:
            k, _, v = chunk.partition(b"=")
            result[k.decode("utf-8", errors="replace")] = v.decode(
                "utf-8", errors="replace"
            )
    return result


def modinfo_table(info: Dict[str, str]) -> List[Tuple[str, str]]:
    """Flatten modinfo into display rows, highlighting the interesting keys."""
    order = [
        "name",
        "vermagic",
        "depends",
        "author",
        "description",
        "license",
        "srcversion",
        "alias",
        "firmware",
        "parm",
        "version",
        "retpoline",
        "intree",
    ]
    rows = []
    for key in order:
        if key in info:
            rows.append((key, info[key]))
    for key, value in sorted(info.items()):
        if key not in order:
            rows.append((key, value))
    return rows


def format_module_functions(path: str) -> List[Dict[str, object]]:
    """Function symbols of a kernel module with section-relative addressing."""
    elffile = _symbols.parse_elf(path)
    rows = []
    for sym in _symbols.iter_function_symbols(elffile):
        rows.append(
            {
                "name": sym.name,
                "base": _symbols.gcc_base(sym.name),
                "section": sym.section,
                "offset": sym.value,
                "size": sym.size,
                "type": _symbols.nm_letter(sym),
                "bind": sym.bind_name(),
                "address": _symbols.human_address(elffile, sym),
            }
        )
    return rows


def is_genuine_module(path: str, elffile: Optional[object] = None) -> bool:
    """True when *path* parses as an ELF relocatable with a .modinfo section."""
    if elffile is None:
        try:
            elffile = _symbols.parse_elf(path)
        except Exception:
            return False
    return _symbols.is_kernel_module(elffile)
