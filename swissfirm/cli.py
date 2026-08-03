from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from . import analyze, report, searchers
from .util import parse_jobs

OPERATIONS = [
    # (id, argname, flag, help, nargs)
    ("origin", "find_origin", "-fo", "Locate which binary defines a function (exact name).", None),
    ("subfunc", "find_subfunc", "-fs", "Locate binaries defining functions whose name contains the substring.", None),
    ("bytes", "find_bytes", "-fb", "Search for a raw byte pattern (hex, 0x/space tolerated).", None),
    ("mnemonic", "find_mnemonic", "-fm", "Assemble mnemonics (arch:insn;insn) and search for the bytes.", None),
    ("needed", "find_needed", "-fn", "Resolve the shared libraries a binary needs, recursively.", None),
    ("strings", "strings", "-st", "Extract interesting strings from binaries (credential/network/shell/...).", "?"),
    ("audit", "audit", "-au", "Per-binary security hardening audit (NX/PIE/RELRO/canary/fortify/W^X).", "?"),
    ("imports", "imports", "-im", "Flag dangerous function usage (strcpy/system/weak-crypto/...).", "?"),
    ("crypto", "crypto", "-cr", "Scan binaries for embedded crypto constants (AES S-box, hash inits, ...).", "?"),
    ("kernel", "kernel", "-k", "Inventory kernel modules: decompress, modinfo, function counts.", "?"),
    ("kernel-symbols", "kernel_symbols", "-ko", "Dump a single kernel module's symbols (ET_REL-aware).", None),
    ("inventory", "inventory", "-i", "ELF inventory + firmware summary (arch/type census, kernel version).", "?"),
]

_OP_KEYS = [op[1] for op in OPERATIONS]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="swissfirm",
        description="Swiss tool for firmware static analysis "
        "(ELF search, hardening audit, kernel module inspection).",
        epilog=(
            "examples:\n"
            "  swissfirm ./fs -fo base64_parser\n"
            "  swissfirm ./fs -fs init\n"
            "  swissfirm ./fs -fb deadbeef\n"
            "  swissfirm ./fs -fm 'i386:mov eax, 1;push eax'\n"
            "  swissfirm ./fs -fn libc.so.6\n"
            "  swissfirm ./fs -k -ko drivers/net/wireless/foo.ko\n"
            "  swissfirm ./fs -au -im --format json -o report.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("fsdir", type=str, help="Firmware filesystem directory to search.")
    parser.add_argument("-j", "--jobs", type=str, default="10",
                        help="parallel workers (int or 'cpu', default 10).")
    parser.add_argument("--max-results", type=int, default=None,
                        help="cap displayed rows per result (default: unlimited).")
    parser.add_argument("--format", dest="fmt", choices=["table", "markdown", "json"],
                        default="table", help="output rendering (default table).")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="write the report to a file instead of stdout.")
    parser.add_argument("-V", "--version", action="version",
                        version=f"swissfirm {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress the progress banner.")
    parser.add_argument("--elf-only", action="store_true",
                        help="restrict --strings/--crypto scans to ELF files only.")

    group = parser.add_argument_group("operations")
    for _key, name, flag, help_text, nargs in OPERATIONS:
        kw = dict(type=str, metavar="QUERY", help=help_text)
        if nargs == "?":
            kw.update(nargs="?", const="all", default=None)
        group.add_argument(flag, f"--{name.replace('_', '-')}", **kw)

    strings = parser.add_argument_group("strings options")
    strings.add_argument("--min-len", type=int, default=5,
                         help="minimum string length for --strings (default 5).")
    strings.add_argument("--encoding", choices=["ascii", "utf16", "both"], default="both",
                         help="string encodings to scan (default both).")

    audit = parser.add_argument_group("audit options")
    audit.add_argument("--audit-sort", choices=["score", "file"], default="score",
                       help="sort order for the audit report (default score).")
    return parser


def _check_ops(args: argparse.Namespace) -> List[str]:
    requested = [key for key in _OP_KEYS if getattr(args, key)]
    return requested


def _dispatch(args: argparse.Namespace, fsdir: str, jobs: int):
    jobs_workers = jobs

    def origin(q): return searchers.FunctionSearcher(fsdir, q, whole_name=True, jobs=jobs_workers).run()
    def subfunc(q): return searchers.FunctionSearcher(fsdir, q, whole_name=False, jobs=jobs_workers).run()
    def bytes_(q): return searchers.ByteSearcher(fsdir, q, jobs=jobs_workers).run()
    def mnemonic(q): return searchers.MnemonicSearcher(fsdir, q, jobs=jobs_workers).run()
    def needed(q): return searchers.NeededLibSearcher(fsdir, q, jobs=jobs_workers).run()
    def strings(q): return analyze.StringsAnalyzer(fsdir, jobs=jobs_workers,
                                                   min_len=args.min_len,
                                                   encoding=args.encoding,
                                                   elf_only=args.elf_only).run()
    def audit(q): return analyze.SecurityAuditAnalyzer(fsdir, jobs=jobs_workers,
                                                       sort=args.audit_sort).run()
    def imports(q): return analyze.DangerousImportsAnalyzer(fsdir, jobs=jobs_workers).run()
    def crypto(q): return analyze.CryptoConstantsAnalyzer(fsdir, jobs=jobs_workers,
                                                         elf_only=args.elf_only).run()
    def kernel(q): return analyze.KernelModulesAnalyzer(fsdir, jobs=jobs_workers).run()
    def kernel_symbols(q): return analyze.KernelSymbolsDumper(fsdir, q).run()
    def inventory(q): return analyze.InventoryAnalyzer(fsdir, jobs=jobs_workers).run()

    dispatch = {
        "find_origin": origin,
        "find_subfunc": subfunc,
        "find_bytes": bytes_,
        "find_mnemonic": mnemonic,
        "find_needed": needed,
        "strings": strings,
        "audit": audit,
        "imports": imports,
        "crypto": crypto,
        "kernel": kernel,
        "kernel_symbols": kernel_symbols,
        "inventory": inventory,
    }
    return dispatch


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fsdir = args.fsdir
    if not os.path.isdir(fsdir):
        parser.error(f"fsdir {fsdir!r} is not a directory")

    requested = _check_ops(args)
    if not requested:
        parser.error("no operation selected (use -fo, -fb, -fn, -fs, -fm, "
                     "-st, -au, -im, -cr, -k, -ko, -i; see --help)")
    jobs = parse_jobs(args.jobs)
    dispatch = _dispatch(args, fsdir, jobs)

    if not args.quiet:
        print(f"swissfirm - scanning {fsdir!r} with {jobs} workers")
        print()

    blocks = []
    for key in _OP_KEYS:
        if key in requested:
            try:
                result = dispatch[key](args.__dict__.get(key))
            except (searchers.SearchError, ValueError, FileNotFoundError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            except searchers.ElfParseError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            blocks.append(report.render_result(result, fmt=args.fmt,
                                               max_rows=args.max_results))
            blocks.append("")

    text = "\n".join(blocks).rstrip() + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(text)
        if not args.quiet:
            print(f"report written to {args.output}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
