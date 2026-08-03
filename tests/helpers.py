"""Shared test fixtures: build a small firmware tree in a temp dir."""

from __future__ import annotations

import gzip
import os
import shutil
import tempfile
from typing import Optional

from elfbuilder import build_dynamic, build_reloc

MAPPING = "$a"


def build_tree(root: str) -> None:
    """Populate *root* with a representative firmware layout."""
    bin_dir = os.path.join(root, "bin")
    lib_dir = os.path.join(root, "lib")
    mod_dir = os.path.join(root, "lib/modules/5.10.0/kernel/drivers")
    etc_dir = os.path.join(root, "etc")
    for d in (bin_dir, lib_dir, mod_dir, etc_dir):
        os.makedirs(d, exist_ok=True)

    # normal binaries (clang-independent, built programmatically)
    build_dynamic(os.path.join(lib_dir, "myapp"), needed=["libc.so.6", "libfoo.so.1"])
    build_dynamic(os.path.join(lib_dir, "libc.so.6"), needed=["libm.so.6"])
    build_dynamic(os.path.join(lib_dir, "libm.so.6"), needed=["libc.so.6"])
    build_reloc(
        os.path.join(bin_dir, "util.o"),
        text=b"\x55\x48\x89\xe5\xc3",
        symbols=[
            ("add", 0x0, 32, 1, 2, 1),
            ("mul", 0x20, 32, 1, 2, 1),
        ],
    )

    # kernel modules
    build_reloc(
        os.path.join(mod_dir, "wifi.ko"),
        text=b"\x55\x48\x89\xe5\x41\x57\xc3",
        modinfo=[
            "name=wifi",
            "vermagic=5.10.0 SMP preempt mod_unload ARMv7",
            "depends=tun,cfg80211",
            "license=GPL",
            "author=Acme Inc",
        ],
        symbols=[
            ("init_module", 0, 128, 1, 2, 1),
            ("cleanup_module", 0x80, 64, 1, 2, 1),
            ("wifi_probe.isra.1", 0xC0, 96, 1, 2, 1),
            ("wifi_remove", 0x120, 48, 1, 2, 1),
            ("__ksymtab_wifi_get", 0, 8, 1, 1, 2),
            (MAPPING, 0, 0, 0, 0, 1),  # ARM-style mapping symbol (noise)
        ],
    )
    # compressed module
    with open(os.path.join(mod_dir, "wifi.ko"), "rb") as fh:
        with gzip.open(os.path.join(mod_dir, "wifi.ko.gz"), "wb") as gz:
            shutil.copyfileobj(fh, gz)

    # plaintext artifacts
    with open(os.path.join(etc_dir, "passwd"), "w") as fh:
        fh.write("Linux version 4.14.77\n")
        fh.write("root::0:0:root:/root:/bin/sh\n")
        fh.write("http://evil.example.com\n")
        fh.write("password=admin123\n")


class TempFs:
    """Context manager that yields a populated firmware root."""

    def __init__(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="swissfirm-test-")

    def __enter__(self) -> str:
        build_tree(self._tmp)
        return self._tmp

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    @property
    def root(self) -> str:
        return self._tmp
