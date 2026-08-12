"""Plain-text table formatting for CLI output.

Deliberately dependency-free (no ``rich``/``tabulate``) so the whole tool
runs with nothing beyond the Python standard library - clone the repo,
``python -m binspect ...``, done.
"""

from __future__ import annotations


def heading(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}"


def kv_table(pairs: list[tuple[str, str]]) -> str:
    if not pairs:
        return "(none)"
    width = max(len(k) for k, _ in pairs)
    return "\n".join(f"  {k.ljust(width)} : {v}" for k, v in pairs)


def table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "(none)"
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(cells: list[str]) -> str:
        return "  " + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    lines = [fmt_row(headers), "  " + "  ".join("-" * w for w in widths)]
    lines.extend(fmt_row(row) for row in rows)
    return "\n".join(lines)
