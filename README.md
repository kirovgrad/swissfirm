# swissfirm

Firmware static analysis toolkit for reverse engineers. Analyzes ELF binaries extracted from firmware filesystems, with support for kernel modules, shared libraries, and embedded systems binaries.

## Features

- **Function Search**: Locate which binary defines a function by exact name or substring
- **Byte Pattern Search**: Find raw byte patterns in firmware binaries
- **Mnemonic Search**: Assemble instructions and search for resulting bytes
- **Library Resolution**: Recursively resolve shared library dependencies
- **Strings Extraction**: Flag credentials, network indicators, shell paths, crypto keys
- **Security Audit**: Check NX, PIE, RELRO, stack canaries, fortify, W^X
- **Dangerous Imports**: Detect unsafe functions (strcpy, system, weak crypto)
- **Crypto Constants**: Identify AES S-boxes, hash initialization vectors
- **Kernel Modules**: Handle compressed `.ko` files, extract modinfo and symbols
- **ELF Inventory**: Census by architecture, type, bitness, and endianness

## Installation

```bash
pip install pyelftools keystone-engine
```

## Usage

```bash
swissfirm <firmware_dir> [options] -fo <function>     # Find function origin (exact)
swissfirm <firmware_dir> [options] -fs <substring>   # Find function by substring
swissfirm <firmware_dir> [options] -fb <hex>         # Search byte pattern
swissfirm <firmware_dir> [options] -fm <arch:insn>   # Search by assembly
swissfirm <firmware_dir> [options] -fn <lib.so>      # Resolve library dependencies
swissfirm <firmware_dir> [options] -st               # Extract interesting strings
swissfirm <firmware_dir> [options] -au               # Security hardening audit
swissfirm <firmware_dir> [options] -im               # Flag dangerous imports
swissfirm <firmware_dir> [options] -cr               # Find crypto constants
swissfirm <firmware_dir> [options] -k                # Inventory kernel modules
swissfirm <firmware_dir> [options] -ko <module.ko>   # Dump module symbols
swissfirm <firmware_dir> [options] -i                # ELF inventory
```

## Examples

```bash
# Find which binary defines a function
swissfirm ./fs -fo base64_encode

# Search for functions containing "init"
swissfirm ./fs -fs init

# Find byte pattern deadbeef
swissfirm ./fs -fb deadbeef

# Search for x86 assembly pattern
swissfirm ./fs -fm 'i386:mov eax, 1;push eax'

# Resolve libc dependencies
swissfirm ./fs -fn libc.so.6

# Audit all binaries for hardening features
swissfirm ./fs -au

# Generate JSON report
swissfirm ./fs -au -im --format json -o report.json

# Inventory kernel modules
swissfirm ./fs -k

# Dump symbols from a specific kernel module
swissfirm ./fs -k -ko drivers/net/wireless/foo.ko
```

## Options

| Option | Description |
|--------|-------------|
| `-j, --jobs N` | Parallel workers (default: 10) |
| `--format table\|markdown\|json` | Output format |
| `-o, --output FILE` | Write report to file |
| `-q, --quiet` | Suppress progress banner |
| `--elf-only` | Restrict strings/crypto to ELF files only |
| `--min-len N` | Minimum string length (default: 5) |
| `--encoding ascii\|utf16\|both` | String encoding (default: both) |

## Output

All operations return machine-readable rows rendered as tables, markdown, or JSON:

```
swissfirm - scanning './fs' with 10 workers

function origin: 'base64_encode' across 156 ELF files
+--------+----------------+--------+------+-------+------+
| name             | file                    | address      | size | bind   | type |
+------------------+-------------------------+--------------+------+--------+------+
| base64_encode    | lib/libcurl.so          | 0x1a3c2      | 256  | GLOBAL | T    |
| base64_encode    | usr/bin/httpd           | .text+0x84   | 192  | GLOBAL | T    |
+------------------+-------------------------+--------------+------+--------+------+
```

## Requirements

- Python 3.8+
- [pyelftools](https://pypi.org/project/pyelftools/) - ELF parsing
- [keystone-engine](https://pypi.org/project/keystone-engine/) - Assembly (optional, for mnemonic search)
