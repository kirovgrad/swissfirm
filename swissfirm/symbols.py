from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterator, List

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.enums import (
        ENUM_E_MACHINE,
        ENUM_E_TYPE,
        ENUM_SH_TYPE_BASE,
        ENUM_ST_INFO_BIND,
        ENUM_ST_INFO_TYPE,
    )

    HAS_PYELFTOOLS = True
except ImportError:
    HAS_PYELFTOOLS = False

ET_REL = 1
ET_EXEC = 2
ET_DYN = 3

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_GNU_IFUNC = 10

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

SHN_UNDEF = 0

_MAPPING_PREFIX = ("$a", "$t", "$x", "$p", "$c", "$d", "$m", "$v")
_GCC_SUFFIXES = ("isra", "constprop", "part", "cfi", "cold", "lto_priv", "eh")
_NOISE_NAMES = {
    "_GLOBAL_OFFSET_TABLE_",
    "_PROCEDURE_LINKAGE_TABLE_",
    "__dso_handle",
    "_DYNAMIC",
    "_init",
    "_fini",
    "__init_array_start",
    "__init_array_end",
    "__fini_array_start",
    "__fini_array_end",
    "__preinit_array_start",
    "__preinit_array_end",
    "__bss_start",
    "_edata",
    "_end",
    "__data_start",
    "__etext",
    "_etext",
    "__executable_start",
    "__GNU_EH_FRAME_HDR",
    "__frame_dummy_init_array_entry",
    "__FRAME_END__",
    "frame_dummy",
    "__gnu_local_gp",
    "_gp",
    "KERNEL_SYSCTL_TABLE",
    "__ksymtab_strings",
    "__versions",
    "__this_module",
    "this_module",
    "__modver_attr",
    "__mod_device_table",
}


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    bind: int
    type: int
    shndx: int
    section: str
    section_flags: int = 0
    is_undefined: bool = False

    @property
    def is_func(self) -> bool:
        return self.type in (STT_FUNC, STT_GNU_IFUNC)

    def nm_type(self) -> str:
        base = {STT_NOTYPE: "n", STT_OBJECT: "d", STT_FUNC: "t", STT_GNU_IFUNC: "i"}.get(self.type, "n")
        return base.upper() if self.bind != STB_LOCAL else base

    def bind_name(self) -> str:
        if self.bind == STB_GLOBAL:
            return "GLOBAL"
        if self.bind == STB_WEAK:
            return "WEAK"
        if self.bind == STB_LOCAL:
            return "LOCAL"
        return f"bind{self.bind}"


def _enum(name: str, table: dict) -> int:
    if isinstance(name, int):
        return name
    return table.get(name, -1)


def is_mapping_symbol(name: str) -> bool:
    return name.startswith(_MAPPING_PREFIX)


def is_noise_symbol(name: str) -> bool:
    if not name:
        return True
    if name.startswith("$"):
        return True
    if name.startswith(".L"):
        return True
    if name.startswith("__gnu_lto"):
        return True
    if name in _NOISE_NAMES:
        return True
    return False


def gcc_base(name: str) -> str:
    parts = name.split(".")
    while len(parts) > 1:
        tail = parts[-1]
        if tail.isdigit() or tail in _GCC_SUFFIXES:
            parts.pop()
            continue
        break
    return ".".join(parts)


def versionless(name: str) -> str:
    if "@" in name:
        return name.split("@", 1)[0]
    return name


def _section_name_for(all_sections: list, shndx: object) -> str:
    if isinstance(shndx, str):
        return f"*{shndx.replace('SHN_', '')}*"
    if isinstance(shndx, int):
        if shndx == 0:
            return "*UNDEF*"
        if 0 < shndx < len(all_sections):
            return all_sections[shndx].name or f"*idx{shndx}*"
        return f"*idx{shndx}*"
    return f"*{shndx}*"


def convert_symbols(all_sections: list, sec) -> List[Symbol]:
    out = []
    for sym in sec.iter_symbols():
        st_shndx = sym["st_shndx"]
        is_undef = isinstance(st_shndx, str) and st_shndx == "SHN_UNDEF"
        sec_name = _section_name_for(all_sections, st_shndx)
        shndx = st_shndx if isinstance(st_shndx, int) else 0xFFFF
        flags = 0
        if isinstance(st_shndx, int) and 0 < st_shndx < len(all_sections):
            flags = all_sections[st_shndx].header.get("sh_flags", 0) or 0
        out.append(
            Symbol(
                name=sym.name,
                value=sym["st_value"],
                size=sym["st_size"],
                bind=_enum(sym["st_info"]["bind"], ENUM_ST_INFO_BIND),
                type=_enum(sym["st_info"]["type"], ENUM_ST_INFO_TYPE),
                shndx=shndx,
                section=sec_name,
                section_flags=flags,
                is_undefined=is_undef,
            )
        )
    return out


def _parse_elf(path: str):
    if not HAS_PYELFTOOLS:
        raise ImportError("pyelftools is required but not installed")
    return ELFFile(open(path, "rb"))


def parse_elf(path: str):
    elffile = _parse_elf(path)
    elffile.name = path
    return elffile


def is_relocatable(elffile: ELFFile) -> bool:
    return _enum(elffile.header["e_type"], ENUM_E_TYPE) == ET_REL


def is_shared(elffile: ELFFile) -> bool:
    return _enum(elffile.header["e_type"], ENUM_E_TYPE) == ET_DYN


def is_executable(elffile: ELFFile) -> bool:
    return _enum(elffile.header["e_type"], ENUM_E_TYPE) == ET_EXEC


def defined_functions(elffile: ELFFile) -> List[Symbol]:
    all_sections = list(elffile.iter_sections())
    symtab = elffile.get_section_by_name(".symtab")
    dynsym = elffile.get_section_by_name(".dynsym")

    funcs = []
    if symtab is not None:
        for s in convert_symbols(all_sections, symtab):
            if s.is_func and not s.is_undefined and s.shndx < 0xFF00 and s.section_flags & SHF_EXECINSTR:
                funcs.append(s)

    if not is_relocatable(elffile):
        seen = {s.name for s in funcs}
        if dynsym is not None:
            for s in convert_symbols(all_sections, dynsym):
                if s.is_func and not s.is_undefined and s.shndx < 0xFF00 and s.section_flags & SHF_EXECINSTR:
                    if s.name not in seen:
                        funcs.append(s)
                        seen.add(s.name)

    funcs.sort(key=lambda s: (s.shndx, s.value))
    return funcs


def undefined_symbols(elffile: ELFFile) -> List[Symbol]:
    all_sections = list(elffile.iter_sections())
    dynsym = elffile.get_section_by_name(".dynsym")
    if dynsym is None:
        return []
    syms = [s for s in convert_symbols(all_sections, dynsym) if s.is_undefined and s.name]
    return sorted(syms, key=lambda s: (s.name.lower(), s.value))


def iter_function_symbols(elffile: ELFFile) -> List[Symbol]:
    return [s for s in defined_functions(elffile) if not is_noise_symbol(s.name)]


def get_section(elffile: ELFFile, name: str):
    return elffile.get_section_by_name(name)


def has_section(elffile: ELFFile, name: str) -> bool:
    return elffile.get_section_by_name(name) is not None


def human_address(elffile: ELFFile, sym: Symbol) -> str:
    if is_relocatable(elffile):
        return f"{sym.section}+0x{sym.value:x}"
    return f"0x{sym.value:x}"


def nm_letter(sym: Symbol) -> str:
    return sym.nm_type()


def machine_name(elffile: ELFFile) -> str:
    EM_NAMES = {
        3: "x86",
        62: "x86-64",
        40: "ARM",
        183: "AArch64",
        20: "PPC",
        21: "PPC64",
        8: "MIPS",
        2: "SPARC",
        43: "SPARCv9",
        243: "RISC-V",
        42: "SuperH",
        45: "ARC",
        140: "TMS320C6000",
        189: "MicroBlaze",
        258: "LoongArch",
    }
    e_machine = _enum(elffile.header["e_machine"], ENUM_E_MACHINE)
    return EM_NAMES.get(e_machine, f"machine_{e_machine}")


def type_name(elffile: ELFFile) -> str:
    ET_NAMES = {
        0: "NONE",
        ET_REL: "REL (relocatable)",
        ET_EXEC: "EXEC (executable)",
        ET_DYN: "DYN (pie/shared)",
        4: "CORE",
    }
    e_type = _enum(elffile.header["e_type"], ENUM_E_TYPE)
    return ET_NAMES.get(e_type, f"ET_{e_type}")


def elf_class(elffile: ELFFile) -> int:
    return 64 if elffile.elfclass == 64 else 32


def endianness(elffile: ELFFile) -> str:
    return "little" if elffile.little_endian else "big"


def is_stripped(elffile: ELFFile) -> bool:
    return not has_section(elffile, ".symtab")


def has_gnu_stack_exec(elffile: ELFFile) -> bool:
    for seg in elffile.iter_segments():
        if seg["p_type"] == "PT_GNU_STACK" and seg.header.get("p_flags", 0) & 0x1:
            return True
    return False


def has_gnu_relro(elffile: ELFFile) -> bool:
    for seg in elffile.iter_segments():
        if seg["p_type"] == "PT_GNU_RELRO":
            return True
    return False


def has_bind_now(elffile: ELFFile) -> bool:
    dynamic = elffile.get_section_by_name(".dynamic")
    if dynamic is not None:
        for tag in dynamic.iter_tags():
            d_tag = tag.entry.d_tag
            if d_tag == "DT_BIND_NOW":
                return True
            elif d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):
                return True
    return False


def has_exec_writable_load(elffile: ELFFile) -> bool:
    for seg in elffile.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            flags = seg.header.get("p_flags", 0)
            if flags & 0x2 and flags & 0x1:
                return True
    return False


def is_kernel_module(elffile: ELFFile) -> bool:
    return is_relocatable(elffile) and has_section(elffile, ".modinfo")


def all_symbols(elffile: ELFFile) -> List[Symbol]:
    all_sections = list(elffile.iter_sections())
    out = []
    seen = set()

    symtab = elffile.get_section_by_name(".symtab")
    if symtab is not None:
        for s in convert_symbols(all_sections, symtab):
            out.append(s)
            seen.add(s.name)

    dynsym = elffile.get_section_by_name(".dynsym")
    if dynsym is not None:
        for s in convert_symbols(all_sections, dynsym):
            if s.name not in seen:
                out.append(s)
                seen.add(s.name)

    return out


def get_needed(elffile: ELFFile) -> List[str]:
    needed = []
    dynamic = elffile.get_section_by_name(".dynamic")
    if dynamic is not None:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                needed.append(tag.needed)
    return needed


_VERSION_RE = re.compile(r"Linux version ([0-9]+\.[0-9]+(?:\.[0-9]+)?)")


def find_kernel_version(strings: List[str]) -> List[str]:
    versions = []
    for text in strings:
        m = _VERSION_RE.search(text)
        if m and m.group(1) not in versions:
            versions.append(m.group(1))
    return versions


def _iter_files(root: str):
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            if not os.path.islink(path) and os.path.isfile(path):
                yield path


def importable_symbols(elffile: ELFFile) -> List[Symbol]:
    out = list(iter_function_symbols(elffile))
    if not is_relocatable(elffile):
        seen = {s.name for s in out}
        all_sections = list(elffile.iter_sections())
        dynsym = elffile.get_section_by_name(".dynsym")
        if dynsym is not None:
            for s in convert_symbols(all_sections, dynsym):
                if not is_noise_symbol(s.name) and s.name not in seen:
                    if s.is_func and not s.is_undefined and s.shndx < 0xFF00 and s.section_flags & SHF_EXECINSTR:
                        out.append(s)
                        seen.add(s.name)
    return out
