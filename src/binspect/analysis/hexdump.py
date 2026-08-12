"""A classic hex + ASCII gutter viewer, in the style of ``xxd``/
``hexdump -C``.

Every other view in this tool (headers, sections, strings) is an
*interpretation* of the raw bytes. The hex dump is the ground truth
underneath all of them - useful for confirming a parser read the right
offset, or for eyeballing a region a parser doesn't understand (unknown
file formats, custom packer stubs, etc.).
"""

from __future__ import annotations

BYTES_PER_ROW = 16


def format_hexdump(data: bytes, offset: int = 0, length: int | None = None) -> str:
    """Render ``data[offset:offset+length]`` as 16-bytes-per-row hex with
    an ASCII gutter (unprintable bytes shown as '.'), each row prefixed
    with its absolute file offset.
    """
    end = len(data) if length is None else min(len(data), offset + length)
    lines = []
    row_start = offset - (offset % BYTES_PER_ROW)
    for row in range(row_start, end, BYTES_PER_ROW):
        chunk = data[max(row, offset) : min(row + BYTES_PER_ROW, end)]
        pad = row + BYTES_PER_ROW - max(row, offset) - len(chunk)
        # Left-pad rows that start mid-row so the hex columns stay aligned.
        skip = max(row, offset) - row
        hex_cols = ["  "] * skip
        ascii_cols = [" "] * skip
        for b in chunk:
            hex_cols.append(f"{b:02x}")
            ascii_cols.append(chr(b) if 0x20 <= b <= 0x7E else ".")
        hex_cols.extend(["  "] * pad)

        hex_str = " ".join(hex_cols[:8]) + "  " + " ".join(hex_cols[8:])
        ascii_str = "".join(ascii_cols)
        lines.append(f"{row:08x}  {hex_str}  |{ascii_str}|")
    return "\n".join(lines)
