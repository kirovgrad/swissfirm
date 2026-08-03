"""Programmatic ELF64 relocatable object builder for tests.

Builds a self-contained little-endian ``ET_REL`` object (the same shape as a
kernel module / ``*.o``) so tests do not depend on a compiler.  Supports
custom text bytes, a ``.modinfo`` section and an arbitrary symbol table.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Sequence, Tuple

ELF_MAGIC = b"\x7fELF"
ET_REL = 1
ET_DYN = 3
EM_X86_64 = 62

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

DT_NULL = 0
DT_NEEDED = 1

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3

# (name, value, size, bind, type, shndx)
SymbolSpec = Tuple[str, int, int, int, int, int]


def _strtab(names: Sequence[str]) -> Tuple[bytes, Dict[str, int]]:
    data = bytearray(b"\x00")
    offsets: Dict[str, int] = {}
    for name in names:
        offsets[name] = len(data)
        data += name.encode("utf-8") + b"\x00"
    return bytes(data), offsets


def build_reloc(
    path: str,
    text: bytes = b"\xc3",
    modinfo: Optional[List[str]] = None,
    symbols: Optional[List[SymbolSpec]] = None,
    machine: int = EM_X86_64,
    extra_sections: Optional[Dict[str, bytes]] = None,
) -> None:
    """Write a minimal ELF64 relocatable object to *path*.

    ``modinfo`` is a list of ``key=value`` strings.  ``symbols`` defaults to a
    couple of exported functions in ``.text``.  ``extra_sections`` adds
    named PROGBITS sections (e.g. ``{".init.text": b"..."}``) whose symbols
    can be referenced by their index.
    """
    modinfo_data = b"".join((kv.encode("utf-8") + b"\x00") for kv in (modinfo or []))

    extra = dict(extra_sections or {})
    # section ordering: [NULL, .text, .modinfo, ...extras..., .symtab, .strtab, .shstrtab]
    named_sections = [".text", ".modinfo"] + sorted(extra)
    symtab_index = len(named_sections) + 1  # +1 for NULL
    strtab_index = symtab_index + 1
    shstrtab_index = strtab_index + 1
    num_sections = shstrtab_index + 1

    if symbols is None:
        symbols = [
            ("add", 0x0, 32, STB_GLOBAL, STT_FUNC, 1),
            ("mul", 0x20, 32, STB_GLOBAL, STT_FUNC, 1),
            ("helper", 0x40, 16, STB_LOCAL, STT_FUNC, 1),
        ]

    symbol_names = [s[0] for s in symbols]
    strtab_data, str_off = _strtab(symbol_names)

    # build symbol table entries up-front (we need the real size for layout)
    symtab_entries = bytearray()
    first_global = len(symbols)
    for idx, (name, value, size, bind, stype, shndx) in enumerate(symbols):
        if bind == STB_GLOBAL and idx < first_global:
            first_global = idx
        st_info = (bind << 4) | stype
        symtab_entries += struct.pack(
            "<IBBHQQ",
            str_off.get(name, 0),
            st_info,
            0,
            shndx,
            value,
            size,
        )
    if not any(bind == STB_GLOBAL for _, _, _, bind, _, _ in symbols):
        first_global = len(symbols)
    symtab_size = len(symtab_entries)

    shstr_names = [""] + named_sections + [".symtab", ".strtab", ".shstrtab"]
    shstr_data, shstr_off = _strtab(shstr_names[1:])
    shstr_name_ofs = {name: shstr_off[name] for name in shstr_names[1:]}

    # ---- layout: text, modinfo, extras, symtab, strtab, shstrtab, shdrs
    offset = 64  # ELF header
    section_meta: List[Tuple[str, int, int, int]] = []  # (name, type, flags, align)

    def place(name: str, data: bytes, stype: int, flags: int, align: int):
        nonlocal offset
        start = offset
        offset += len(data)
        section_meta.append((name, stype, flags, align))
        return start, data

    text_off, _ = place(".text", text, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 16)
    modinfo_off, _ = place(".modinfo", modinfo_data, SHT_PROGBITS, SHF_ALLOC, 8)

    extra_off: Dict[str, int] = {}
    for name in sorted(extra):
        off, _ = place(name, extra[name], SHT_PROGBITS, SHF_ALLOC, 8)
        extra_off[name] = off

    symtab_off, _ = place(".symtab", b"", SHT_SYMTAB, 0, 8)
    offset += symtab_size  # account for the symbol table bytes written later
    strtab_off, _ = place(".strtab", strtab_data, SHT_STRTAB, 0, 1)
    shstrtab_off, _ = place(".shstrtab", shstr_data, SHT_STRTAB, 0, 1)

    # ---- section headers
    e_shoff = offset
    shentsize = 64
    shdrs = bytearray()

    def sh(name_ofs: int, stype: int, flags: int, addr: int, soff: int, size: int,
           link: int, info: int, align: int, entsize: int):
        nonlocal shdrs
        shdrs += struct.pack(
            "<IIQQQQIIQQ",
            name_ofs, stype, flags, addr, soff, size, link, info, align, entsize,
        )

    sh(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)  # NULL
    sh(shstr_name_ofs[".text"], SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0,
       text_off, len(text), 0, 0, 16, 0)
    sh(shstr_name_ofs[".modinfo"], SHT_PROGBITS, SHF_ALLOC, 0,
       modinfo_off, len(modinfo_data), 0, 0, 8, 0)
    for name in sorted(extra):
        sh(shstr_name_ofs[name], SHT_PROGBITS, SHF_ALLOC, 0,
           extra_off[name], len(extra[name]), 0, 0, 8, 0)
    sh(shstr_name_ofs[".symtab"], SHT_SYMTAB, 0, 0,
       symtab_off, symtab_size, strtab_index, first_global, 8, 24)
    sh(shstr_name_ofs[".strtab"], SHT_STRTAB, 0, 0,
       strtab_off, len(strtab_data), 0, 0, 1, 0)
    sh(shstr_name_ofs[".shstrtab"], SHT_STRTAB, 0, 0,
       shstrtab_off, len(shstr_data), 0, 0, 1, 0)

    header = bytearray(64)
    header[0:4] = ELF_MAGIC
    header[4] = 2  # ELFCLASS64
    header[5] = 1  # little endian
    header[6] = 1  # EV_CURRENT
    header[16:18] = struct.pack("<H", ET_REL)
    header[18:20] = struct.pack("<H", machine)
    header[40:48] = struct.pack("<Q", e_shoff)
    header[52:54] = struct.pack("<H", 64)      # e_ehsize
    header[54:56] = struct.pack("<H", 0)       # e_phentsize
    header[56:58] = struct.pack("<H", 0)       # e_phnum
    header[58:60] = struct.pack("<H", shentsize)
    header[60:62] = struct.pack("<H", num_sections)
    header[62:64] = struct.pack("<H", shstrtab_index)

    with open(path, "wb") as fh:
        fh.write(bytes(header))
        fh.write(text)
        fh.write(modinfo_data)
        for name in sorted(extra):
            fh.write(extra[name])
        fh.write(bytes(symtab_entries))
        fh.write(strtab_data)
        fh.write(shstr_data)
        fh.write(bytes(shdrs))


def build_dynamic(
    path: str,
    needed: Sequence[str],
    text: bytes = b"\xc3",
    machine: int = EM_X86_64,
) -> None:
    """Write a minimal ELF64 ET_DYN object with a .dynamic/DT_NEEDED table."""
    dynstr_names = list(needed)
    dynstr_data, dynstr_off = _strtab(dynstr_names)

    dyn_entries = bytearray()
    for name in needed:
        dyn_entries += struct.pack("<QQ", DT_NEEDED, dynstr_off[name])
    dyn_entries += struct.pack("<QQ", DT_NULL, 0)

    dynsym_entries = bytearray(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))  # null sym
    dynsym_names = [""]

    strtab_data = b"\x00"
    shstr_names = ["", ".text", ".dynsym", ".dynstr", ".dynamic",
                   ".symtab", ".strtab", ".shstrtab"]
    shstr_data, shstr_off = _strtab(shstr_names[1:])
    name_ofs = {name: shstr_off[name] for name in shstr_names[1:]}

    dynsym_index = 2
    dynstr_index = 3
    dynamic_index = 4
    symtab_index = 5
    strtab_index = 6
    shstrtab_index = 7
    num_sections = 8

    # layout
    offset = 64
    text_off = offset; offset += len(text)
    dynsym_off = offset; offset += len(dynsym_entries)
    dynstr_off = offset; offset += len(dynstr_data)
    dynamic_off = offset; offset += len(dyn_entries)
    symtab_off = offset; offset += 0  # empty symtab
    strtab_off = offset; offset += len(strtab_data)
    shstrtab_off = offset; offset += len(shstr_data)
    e_shoff = offset

    shdrs = bytearray()

    def sh(name_ofs, stype, flags, addr, soff, size, link, info, align, entsize):
        nonlocal shdrs
        shdrs += struct.pack("<IIQQQQIIQQ", name_ofs, stype, flags, addr,
                             soff, size, link, info, align, entsize)

    sh(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
    sh(name_ofs[".text"], SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0,
       text_off, len(text), 0, 0, 16, 0)
    sh(name_ofs[".dynsym"], SHT_DYNSYM, SHF_ALLOC, 0,
       dynsym_off, len(dynsym_entries), dynstr_index, 1, 8, 24)
    sh(name_ofs[".dynstr"], SHT_STRTAB, SHF_ALLOC, 0,
       dynstr_off, len(dynstr_data), 0, 0, 1, 0)
    sh(name_ofs[".dynamic"], SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, 0,
       dynamic_off, len(dyn_entries), dynstr_index, 0, 8, 16)
    sh(name_ofs[".symtab"], SHT_SYMTAB, 0, 0,
       symtab_off, 0, strtab_index, 0, 8, 24)
    sh(name_ofs[".strtab"], SHT_STRTAB, 0, 0,
       strtab_off, len(strtab_data), 0, 0, 1, 0)
    sh(name_ofs[".shstrtab"], SHT_STRTAB, 0, 0,
       shstrtab_off, len(shstr_data), 0, 0, 1, 0)

    header = bytearray(64)
    header[0:4] = ELF_MAGIC
    header[4] = 2
    header[5] = 1
    header[6] = 1
    header[16:18] = struct.pack("<H", ET_DYN)
    header[18:20] = struct.pack("<H", machine)
    header[40:48] = struct.pack("<Q", e_shoff)
    header[52:54] = struct.pack("<H", 64)
    header[58:60] = struct.pack("<H", 64)
    header[60:62] = struct.pack("<H", num_sections)
    header[62:64] = struct.pack("<H", shstrtab_index)

    with open(path, "wb") as fh:
        fh.write(bytes(header))
        fh.write(text)
        fh.write(bytes(dynsym_entries))
        fh.write(dynstr_data)
        fh.write(bytes(dyn_entries))
        fh.write(strtab_data)
        fh.write(shstr_data)
        fh.write(bytes(shdrs))
