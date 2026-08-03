from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, Iterator, List, Optional, Tuple

_ELF_MAGIC = b"\x7fELF"
_MAGIC_LEN = 4

# Cache of is_elf() results so repeated passes over the same tree are cheap.
_is_elf_cache = {}


def is_elf_path(path: str) -> bool:
    cached = _is_elf_cache.get(path)
    if cached is not None:
        return cached
    result = False
    try:
        with open(path, "rb") as fh:
            result = fh.read(_MAGIC_LEN) == _ELF_MAGIC
    except (IOError, OSError, ValueError):
        result = False
    _is_elf_cache[path] = result
    return result


def iter_files(root: str) -> Iterator[str]:
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            if not os.path.islink(path) and os.path.isfile(path):
                yield path


def walk_elf_files(root: str) -> Iterator[str]:
    for path in iter_files(root):
        if is_elf_path(path):
            yield path


def run_parallel(
    func: Callable[[str], None],
    items: Iterable[str],
    max_workers: int = 10,
    desc: str = "processing",
) -> None:
    items = list(items)
    if not items:
        return
    workers = max(1, min(max_workers, len(items)))
    if workers == 1:
        for item in items:
            try:
                func(item)
            except Exception as exc:  # noqa: BLE001 - keep the run alive
                print(f"error while {desc} {item!r}: {exc}", file=sys.stderr)
        return

    def _guard(item: str) -> None:
        try:
            func(item)
        except Exception as exc:  # noqa: BLE001
            print(f"error while {desc} {item!r}: {exc}", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for _ in pool.map(_guard, items):
            pass


def parallel_map(
    func: Callable[[str], object],
    items: Iterable[str],
    max_workers: int = 10,
) -> List[object]:
    items = list(items)
    if not items:
        return []
    workers = max(1, min(max_workers, len(items)))
    if workers == 1:
        return [func(item) for item in items]
    out: List[object] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(func, items):
            out.append(result)
    return out


def relpath(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:  # e.g. on Windows with different drives
        return path


def count_items(items: Iterable[object]) -> int:
    return sum(1 for _ in items)


def human_size(num: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(num)} {unit}"
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TiB"


def take(items: Iterable[object], limit: Optional[int] = None) -> List[object]:
    if limit is None:
        return list(items)
    return list(items)[: max(0, limit)]


def parse_jobs(value: Optional[str]) -> int:
    if value is None:
        return 10
    if isinstance(value, int):
        return max(1, value)
    if value.strip().lower() == "cpu":
        return max(1, os.cpu_count() or 1)
    return max(1, int(value))


def unique(seq: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
