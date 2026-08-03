from __future__ import annotations

import os
import re
import string
from typing import Dict, List, Optional

from . import symbols as _symbols
from .kernelmod import (
    format_module_functions,
    is_genuine_module,
    is_module_path,
    iter_kernel_modules,
    modinfo_table,
    read_modinfo,
)
from .searchers import SearchResult, ElfParseError
from .util import human_size, parallel_map, relpath, walk_elf_files

_PRINTABLE = bytes(range(0x20, 0x7F))

# ---------------------------------------------------------------------------
# 1. strings extraction + classification
# ---------------------------------------------------------------------------

_STRING_CATEGORIES = [
    ("credential", re.compile(
        r"(password|passwd|secret|api[_-]?key|apikey|token|"
        r"login|username|admin|root|shadow|credential)", re.I)),
    ("network", re.compile(
        r"(https?://|ftp://|telnet|ssh://|sockets?|bind\(|connect\(|"
        r"listen\(|192\.168\.|10\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.)")),
    ("shell", re.compile(r"(/bin/sh|/bin/bash|sh -c|system\(|popen\(|"
                         r"execve?\(|/dev/tty|/tmp/|/var/tmp)")),
    ("crypto", re.compile(r"(BEGIN (RSA |EC |)PRIVATE KEY|CERTIFICATE|"
                          r"AES-?|RSA|SHA-?(1|2)|MD5|bcrypt|salt|nonce)", re.I)),
    ("filesystem", re.compile(r"(/etc/|/var/|/proc/|/dev/|/usr/|/lib/|/mnt/|/opt/)")),
    ("version", re.compile(r"(Linux version|kernel|firmware version|VERSION|REVISION)", re.I)),
    ("busybox", re.compile(r"BusyBox|ToyBox|applet", re.I)),
]


def _categorize_string(text: str) -> Optional[str]:
    for name, pattern in _STRING_CATEGORIES:
        if pattern.search(text):
            return name
    return None

def _extract_ascii(data: bytes, min_len: int) -> List[bytes]:
    out = []
    run = bytearray()
    for byte in data:
        if byte in _PRINTABLE:
            run.append(byte)
        else:
            if len(run) >= min_len:
                out.append(bytes(run))
            run = bytearray()
    if len(run) >= min_len:
        out.append(bytes(run))
    return out

def _extract_utf16le(data: bytes, min_len: int) -> List[bytes]:
    out = []
    run = bytearray()
    i = 0
    n = len(data)
    while i < n - 1:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and lo in _PRINTABLE:
            run.append(lo)
        else:
            if len(run) >= min_len:
                out.append(bytes(run))
            run = bytearray()
        i += 2
    if len(run) >= min_len:
        out.append(bytes(run))
    return out

class StringsAnalyzer:
    def __init__(
        self,
        root: str,
        jobs: int = 10,
        min_len: int = 5,
        encoding: str = "both",
        per_file: int = 25,
        elf_only: bool = False,
    ):
        self.root = os.path.abspath(root)
        self.jobs = jobs
        self.min_len = max(3, min_len)
        self.encoding = encoding
        self.per_file = per_file
        self.elf_only = elf_only

    def _scan_one(self, path: str) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return rows
        candidates: List[bytes] = []
        if self.encoding in ("ascii", "both"):
            candidates.extend(_extract_ascii(data, self.min_len))
        if self.encoding in ("utf16", "both"):
            candidates.extend(_extract_utf16le(data, self.min_len))

        count = 0
        for raw in candidates:
            try:
                text = raw.decode("ascii", errors="replace")
            except UnicodeDecodeError:
                continue
            if not text or len(text) < self.min_len:
                continue
            category = _categorize_string(text)
            if category is None:
                continue
            if count >= self.per_file:
                break
            offset = data.find(raw)
            rows.append(
                {
                    "file": relpath(path, self.root),
                    "category": category,
                    "offset": f"0x{offset:x}",
                    "string": text,
                }
            )
            count += 1
        return rows

    def run(self) -> SearchResult:
        from .util import iter_files

        sources = list(walk_elf_files(self.root) if self.elf_only else iter_files(self.root))
        collected = parallel_map(self._scan_one, sources, self.jobs)
        rows = [row for chunk in collected for row in chunk]
        rows.sort(key=lambda r: (r["category"], r["file"]))
        by_cat: Dict[str, int] = {}
        for row in rows:
            by_cat[row["category"]] = by_cat.get(row["category"], 0) + 1
        summary = "categories: " + ", ".join(
            f"{k}={v}" for k, v in sorted(by_cat.items())
        )
        return SearchResult(
            title="interesting strings",
            columns=["category", "file", "offset", "string"],
            rows=rows,
            summary=summary,
        )

# ---------------------------------------------------------------------------
# 2. security hardening audit
# ---------------------------------------------------------------------------

class SecurityAuditAnalyzer:
    def __init__(self, root: str, jobs: int = 10, sort: str = "score"):
        self.root = os.path.abspath(root)
        self.jobs = jobs
        self.sort = sort

    def _scan_one(self, path: str) -> List[Dict[str, object]]:
        try:
            elffile = _symbols.parse_elf(path)
        except Exception:
            return []
        syms = _symbols.all_symbols(elffile)
        names = {_symbols.versionless(s.name) for s in syms}
        canary = bool(
            names & {"__stack_chk_fail", "__stack_chk_fail_local", "__stack_chk_guard"}
        )
        fortify = any(
            n.startswith("__") and n.endswith("_chk") and n not in ("__stack_chk_fail", "__stack_chk_fail_local")
            for n in names
        )
        nx = not _symbols.has_gnu_stack_exec(elffile)
        pie = _symbols.is_shared(elffile)
        relro = _symbols.has_gnu_relro(elffile)
        full_relro = relro and _symbols.has_bind_now(elffile)
        wx = _symbols.has_exec_writable_load(elffile)

        score = sum([nx, pie, relro, canary, fortify])
        relro_label = "full" if full_relro else ("partial" if relro else "none")

        return [
            {
                "file": relpath(path, self.root),
                "kind": _symbols.type_name(elffile).split(" ")[0],
                "arch": _symbols.machine_name(elffile),
                "nx": "yes" if nx else "NO",
                "pie": "yes" if pie else "no",
                "relro": relro_label,
                "canary": "yes" if canary else "no",
                "fortify": "yes" if fortify else "no",
                "w^X": "NO" if wx else "ok",
                "score": score,
            }
        ]

    def run(self) -> SearchResult:
        files = list(walk_elf_files(self.root))
        collected = parallel_map(self._scan_one, files, self.jobs)
        rows = [row for chunk in collected for row in chunk]
        rows.sort(
            key=lambda r: (r["score"], r["file"]) if self.sort == "score" else r["file"]
        )
        safe = sum(1 for r in rows if r["score"] >= 4)
        return SearchResult(
            title="security hardening audit",
            columns=["file", "kind", "arch", "nx", "pie", "relro", "canary", "fortify", "w^X", "score"],
            rows=rows,
            summary=f"{safe}/{len(rows)} binaries with >=4 hardening features",
        )

# ---------------------------------------------------------------------------
# 3. dangerous function usage (imports / undefined references)
# ---------------------------------------------------------------------------

_DANGEROUS_FUNCS: Dict[str, List[str]] = {
    "memory-unsafe": [
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
        "mktemp", "tmpnam", "tempnam", "strncpy", "strncat", "sprintf", "wcscpy",
        "wcscat", "realpath", "bcopy",
    ],
    "command-execution": [
        "system", "popen", "execl", "execlp", "execle", "execv", "execvp",
        "execve", "fexecve", "posix_spawn", "dlopen", "ldconfig",
    ],
    "weak-crypto": [
        "MD5", "MD4", "SHA1", "DES", "des_", "rand", "srand", "random",
        "srandom", "mt19937", "crypt",
    ],
    "privilege": [
        "setuid", "setgid", "seteuid", "setegid", "chroot", "mknod",
        "ptrace", "mprotect", "init_module", "finit_module", "delete_module",
    ],
    "format-string": ["printf", "fprintf", "sprintf", "snprintf", "vprintf"],
}

def _classify_dangerous(name: str) -> Optional[str]:
    base = _symbols.gcc_base(_symbols.versionless(name))
    low = base.lower()
    for category, funcs in _DANGEROUS_FUNCS.items():
        for func in funcs:
            f = func.lower()
            if low == f or low.startswith(f + "_") or low.startswith("__" + f):
                return category
    return None

class DangerousImportsAnalyzer:
    def __init__(self, root: str, jobs: int = 10):
        self.root = os.path.abspath(root)
        self.jobs = jobs

    def _scan_one(self, path: str) -> List[Dict[str, object]]:
        try:
            elffile = _symbols.parse_elf(path)
        except Exception:
            return []
        imports = _symbols.undefined_symbols(elffile)
        if _symbols.is_relocatable(elffile) and not imports:
            all_sections = list(elffile.iter_sections())
            symtab = elffile.get_section_by_name(".symtab")
            if symtab:
                imports = [s for s in _symbols.convert_symbols(all_sections, symtab) if s.is_undefined and s.name]
        rows = []
        for sym in imports:
            category = _classify_dangerous(sym.name)
            if category is None:
                continue
            rows.append(
                {
                    "file": relpath(path, self.root),
                    "category": category,
                    "symbol": sym.name,
                }
            )
        return rows

    def run(self) -> SearchResult:
        files = list(walk_elf_files(self.root))
        collected = parallel_map(self._scan_one, files, self.jobs)
        rows = [row for chunk in collected for row in chunk]
        rows.sort(key=lambda r: (r["category"], r["symbol"], r["file"]))
        by_cat: Dict[str, int] = {}
        for row in rows:
            by_cat[row["category"]] = by_cat.get(row["category"], 0) + 1
        summary = "categories: " + ", ".join(
            f"{k}={v}" for k, v in sorted(by_cat.items())
        )
        return SearchResult(
            title="dangerous function usage",
            columns=["category", "file", "symbol"],
            rows=rows,
            summary=summary,
        )

# ---------------------------------------------------------------------------
# 4. crypto-constant signatures
# ---------------------------------------------------------------------------

_AES_SBOX = bytes(
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]
)

def _le_words(*words: int) -> bytes:
    out = bytearray()
    for w in words:
        out += w.to_bytes(4, "little")
    return bytes(out)

def _be_words(*words: int) -> bytes:
    out = bytearray()
    for w in words:
        out += w.to_bytes(4, "big")
    return bytes(out)

_CRYPTO_SIGNATURES: Dict[str, bytes] = {
    "AES forward S-box": _AES_SBOX,
    "base64 alphabet": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "MD5 init (LE)": _le_words(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
    "SHA1 init (LE)": _le_words(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0),
    "SHA256 init (LE)": _le_words(
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ),
    "Blowfish P-array (BE)": _be_words(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344),
}

class CryptoConstantsAnalyzer:
    def __init__(self, root: str, jobs: int = 10, elf_only: bool = False):
        self.root = os.path.abspath(root)
        self.jobs = jobs
        self.elf_only = elf_only

    def _scan_one(self, path: str) -> List[Dict[str, object]]:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return []
        rows = []
        for name, sig in _CRYPTO_SIGNATURES.items():
            count = data.count(sig)
            if count:
                rows.append(
                    {
                        "file": relpath(path, self.root),
                        "signature": name,
                        "count": count,
                        "size": len(sig),
                    }
                )
        return rows

    def run(self) -> SearchResult:
        from .util import iter_files

        sources = list(walk_elf_files(self.root) if self.elf_only else iter_files(self.root))
        collected = parallel_map(self._scan_one, sources, self.jobs)
        rows = [row for chunk in collected for row in chunk]
        rows.sort(key=lambda r: (r["signature"], r["file"]))
        return SearchResult(
            title="crypto constants",
            columns=["file", "signature", "count"],
            rows=rows,
            summary=f"{len(rows)} embedded crypto constant hit(s) across {len(sources)} files",
        )


# ---------------------------------------------------------------------------
# 5. filesystem inventory / overview
# ---------------------------------------------------------------------------

_FS_MAGICS = [
    ("gzip", b"\x1f\x8b"),
    ("xz", b"\xfd7zXZ\x00"),
    ("zip", b"PK\x03\x04"),
    ("bzip2", b"BZh"),
    ("zstd", b"\x28\xb5\x2f\xfd"),
    ("lz4", b"\x04\x22\x4d\x18"),
    ("7zip", b"7z\xbc\xaf\x27\x1c"),
    ("uImage", b"\x27\x05\x19\x56"),
    ("squashfs", b"hsqs"),
    ("ubifs", b"\x31\x18\x10\x06"),
    ("lzma", b"\x5d\x00\x00"),
    ("tar", b"ustar"),
]

def _magic_name(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return None
    for name, magic in _FS_MAGICS:
        if head.startswith(magic):
            return name
    return None

def _is_text(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            sample = fh.read(1024)
    except OSError:
        return False
    if not sample:
        return False
    if sample.startswith(b"#!"):
        return True
    if b"\x00" in sample:
        return False
    text = sample.decode("utf-8", errors="replace")
    printable = sum(1 for ch in text if ch in string.printable)
    return printable / max(1, len(text)) > 0.9

class InventoryAnalyzer:
    def __init__(self, root: str, jobs: int = 10):
        self.root = os.path.abspath(root)
        self.jobs = jobs

    def _elf_row(self, path: str) -> Optional[Dict[str, object]]:
        try:
            elffile = _symbols.parse_elf(path)
        except Exception:
            return None
        size = os.path.getsize(path)
        kind = "module" if _symbols.is_relocatable(elffile) else _symbols.type_name(elffile).split(" ")[0]
        return {
            "file": relpath(path, self.root),
            "kind": kind,
            "arch": _symbols.machine_name(elffile),
            "bits": f"{_symbols.elf_class(elffile)}-bit",
            "endian": _symbols.endianness(elffile),
            "size": human_size(size),
            "stripped": "yes" if _symbols.is_stripped(elffile) else "no",
        }

    def run(self) -> SearchResult:
        elfs = list(walk_elf_files(self.root))
        rows = [r for r in parallel_map(self._elf_row, elfs, self.jobs) if r]
        rows.sort(key=lambda r: (r["kind"], r["arch"], r["file"]))

        counts: Dict[str, int] = {}
        for r in rows:
            key = f"{r['kind']}/{r['arch']}/{r['bits']}"
            counts[key] = counts.get(key, 0) + 1
        census = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items()))

        summary = f"{len(rows)} ELF files ({census})"
        return SearchResult(
            title="ELF inventory",
            columns=["file", "kind", "arch", "bits", "endian", "size", "stripped"],
            rows=rows,
            summary=summary,
        )

class FirmwareSummaryAnalyzer:
    def __init__(self, root: str, jobs: int = 10, scan_small_files: bool = True):
        self.root = os.path.abspath(root)
        self.jobs = jobs
        self.scan_small_files = scan_small_files

    def run(self) -> SearchResult:
        total = 0
        text_files = 0
        magic_counts: Dict[str, int] = {}
        interesting: List[str] = []
        versions: List[str] = []
        total_bytes = 0

        for dirpath, _dirs, names in os.walk(self.root):
            for name in names:
                path = os.path.join(dirpath, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                total += 1
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                total_bytes += size
                low = name.lower()
                if any(tok in low for tok in ("passwd", "shadow", "secret", "key", "cred")):
                    interesting.append(relpath(path, self.root))
                if low.endswith((".conf", ".cfg", ".config", ".ini", ".xml", ".json", ".sh", "release")):
                    if _is_text(path):
                        text_files += 1
                if self.scan_small_files and size <= 256 * 1024 and _is_text(path):
                    try:
                        with open(path, "rb") as fh:
                            content = fh.read().decode("utf-8", errors="replace")
                    except OSError:
                        content = ""
                    for m in re.finditer(r"Linux version (\S+)", content):
                        if m.group(1) not in versions:
                            versions.append(m.group(1))
                magic = _magic_name(path)
                if magic:
                    magic_counts[magic] = magic_counts.get(magic, 0) + 1

        rows = [{"item": "total files", "value": total},
                {"item": "plaintext config/scripts", "value": text_files},
                {"item": "total bytes", "value": human_size(total_bytes)}]
        for magic, count in sorted(magic_counts.items()):
            rows.append({"item": f"{magic} archives", "value": count})
        for path in interesting[:30]:
            rows.append({"item": "interesting file", "value": path})
        for version in versions:
            rows.append({"item": "kernel version", "value": version})
        if not versions:
            rows.append({"item": "kernel version", "value": "(not detected)"})

        return SearchResult(
            title="firmware summary",
            columns=["item", "value"],
            rows=rows,
            summary=f"{total} files scanned",
        )


# ---------------------------------------------------------------------------
# 6. kernel module analysis
# ---------------------------------------------------------------------------

class KernelModulesAnalyzer:
    def __init__(self, root: str, jobs: int = 10):
        self.root = os.path.abspath(root)
        self.jobs = jobs

    def _row(self, ws, path: str) -> Optional[Dict[str, object]]:
        target = ws.resolve(path)
        info = read_modinfo(target)
        if not info and not is_module_path(path):
            return None
        try:
            funcs = len(format_module_functions(target))
        except ElfParseError:
            funcs = 0
        try:
            size = os.path.getsize(target)
        except OSError:
            size = 0
        return {
            "module": relpath(path, self.root),
            "name": info.get("name", "-"),
            "vermagic": info.get("vermagic", "-"),
            "depends": info.get("depends", "-") or "-",
            "license": info.get("license", "-"),
            "funcs": funcs,
            "size": human_size(size),
        }

    def run(self) -> SearchResult:
        from .kernelmod import ModuleWorkspace

        with ModuleWorkspace() as ws:
            modules = iter_kernel_modules(self.root)
            rows = [
                r
                for r in parallel_map(lambda p: self._row(ws, p), modules, self.jobs)
                if r
            ]
            rows.sort(key=lambda r: (r["name"], r["module"]))
            summary = f"{len(rows)} kernel module(s) found"
            return SearchResult(
                title="kernel modules",
                columns=["module", "name", "vermagic", "depends", "license", "funcs", "size"],
                rows=rows,
                summary=summary,
            )

class KernelSymbolsDumper:
    def __init__(self, root: str, module: str):
        self.root = os.path.abspath(root)
        self.module = module

    def _locate(self) -> str:
        if os.path.isabs(self.module) and os.path.isfile(self.module):
            return self.module
        for dirpath, _dirs, names in os.walk(self.root):
            for name in names:
                if name == self.module:
                    return os.path.join(dirpath, name)
        raise FileNotFoundError(f"module {self.module!r} not found under {self.root}")

    def run(self) -> SearchResult:
        from .kernelmod import ModuleWorkspace

        path = self._locate()
        with ModuleWorkspace() as ws:
            target = ws.resolve(path)
            try:
                elffile = _symbols.parse_elf(target)
            except Exception as exc:
                raise ElfParseError(f"failed to parse {target!r}: {exc}") from exc
            if not _symbols.is_kernel_module(elffile):
                raise ValueError(f"{path!r} is not a kernel module (ET_REL + .modinfo)")
            info = read_modinfo(target)
            rows = []
            for s in _symbols.iter_function_symbols(elffile):
                rows.append(
                    {
                        "name": s.name,
                        "section": s.section,
                        "offset": _symbols.human_address(elffile, s),
                        "size": s.size,
                        "type": _symbols.nm_letter(s),
                        "bind": s.bind_name(),
                    }
                )
            summary = " | ".join(f"{k}={v}" for k, v in modinfo_table(info)[:6])
            return SearchResult(
                title=f"symbols of {os.path.basename(path)}",
                columns=["name", "section", "offset", "size", "type", "bind"],
                rows=rows,
                summary=summary,
            )
