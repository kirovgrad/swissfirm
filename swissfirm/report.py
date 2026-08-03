from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Dict, List, Optional

_MAX_CELL = 60


def _cell(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if len(text) > _MAX_CELL:
        return text[:_MAX_CELL - 1] + "…"
    return text


def _cols_for(columns: List[str], rows: List[Dict[str, object]]) -> List[str]:
    cols = list(columns)
    if not rows:
        return cols
    extra = []
    for row in rows:
        for key in row:
            if key not in cols and key not in extra:
                extra.append(key)
    return cols + extra


def render_table(
    title: str,
    columns: List[str],
    rows: List[Dict[str, object]],
    summary: Optional[str] = None,
    max_rows: Optional[int] = None,
) -> str:
    cols = _cols_for(columns, rows)
    header = [_cell(c) for c in cols]
    widths = [len(h) for h in header]
    shown = rows
    extra_note = ""
    if max_rows is not None and len(rows) > max_rows:
        shown = rows[:max_rows]
        extra_note = f"\n... {len(rows) - max_rows} more row(s) omitted"
    data = []
    for row in shown:
        line = [_cell(row.get(c)) for c in cols]
        for i, cell in enumerate(line):
            widths[i] = max(widths[i], len(cell))
        data.append(line)

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out = []
    if title:
        out.append(title)
        out.append(sep)
    if summary:
        out.append("    " + summary)
    out.append(sep)
    out.append("| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(header)) + " |")
    out.append(sep)
    for line in data:
        out.append(
            "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(line)) + " |"
        )
    out.append(sep)
    if extra_note:
        out.append(extra_note)
    return "\n".join(out)


def render_markdown(
    title: str,
    columns: List[str],
    rows: List[Dict[str, object]],
    summary: Optional[str] = None,
    max_rows: Optional[int] = None,
) -> str:
    cols = _cols_for(columns, rows)
    out = []
    if title:
        out.append(f"### {title}")
    if summary:
        out.append(f"_{summary}_")
    header = "| " + " | ".join(_cell(c) for c in cols) + " |"
    sep = "| " + " | ".join("---" for _ in cols) + " |"
    out.append(header)
    out.append(sep)
    shown = rows
    if max_rows is not None and len(rows) > max_rows:
        shown = rows[:max_rows]
    for row in shown:
        out.append("| " + " | ".join(_cell(row.get(c)) for c in cols) + " |")
    if max_rows is not None and len(rows) > max_rows:
        out.append(f"_... {len(rows) - max_rows} more row(s) omitted_")
    return "\n".join(out)


def to_json(obj: object) -> str:
    def _default(o: object):
        if is_dataclass(o):
            return asdict(o)  # type: ignore[arg-type]
        if isinstance(o, bytes):
            return o.hex()
        return str(o)

    return json.dumps(obj, indent=2, default=_default)


def render_result(result, fmt: str = "table", max_rows: Optional[int] = None) -> str:
    title = getattr(result, "title", "")
    columns = getattr(result, "columns", [])
    rows = getattr(result, "rows", [])
    summary = getattr(result, "summary", None)
    if fmt == "json":
        payload = {"title": title, "summary": summary, "columns": columns, "rows": rows}
        return to_json(payload)
    if fmt == "markdown":
        return render_markdown(title, columns, rows, summary, max_rows=max_rows)
    return render_table(title, columns, rows, summary, max_rows=max_rows)
