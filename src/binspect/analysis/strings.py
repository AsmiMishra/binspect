"""Printable-string extraction, the Python equivalent of the Unix
``strings`` command.

Even a stripped, non-symbolicated binary usually leaks information
through the literal string constants embedded in it: file paths,
registry keys, URLs, IP addresses, error/format strings, and library
names. Pulling these out with no disassembly at all is one of the
highest-value-per-effort steps in static triage - it's often the first
thing an analyst runs on an unknown sample, before anything more
expensive like disassembly.

Two encodings are extracted because both are common in real binaries:
- ASCII / narrow strings: the default for POSIX and for most literals in
  any language, found via a straightforward regex over raw bytes.
- UTF-16LE / wide strings: Windows APIs are natively UTF-16
  (`CreateFileW`, wide literals from `L"..."` in C), so a huge fraction of
  the human-readable text in a Windows PE is one NUL byte between every
  ASCII character - invisible to a plain ASCII scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_MIN_LENGTH = 4


@dataclass(frozen=True)
class FoundString:
    offset: int
    text: str
    encoding: str  # "ascii" or "utf-16le"


def extract_ascii(data: bytes, min_length: int = DEFAULT_MIN_LENGTH) -> list[FoundString]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    return [
        FoundString(offset=m.start(), text=m.group().decode("ascii"), encoding="ascii")
        for m in pattern.finditer(data)
    ]


def extract_utf16le(data: bytes, min_length: int = DEFAULT_MIN_LENGTH) -> list[FoundString]:
    """Match a printable ASCII byte followed by 0x00, repeated - the
    on-disk shape of an ASCII-range string stored as UTF-16LE.
    """
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    results = []
    for m in pattern.finditer(data):
        raw = m.group()
        text = raw.decode("utf-16le")
        results.append(FoundString(offset=m.start(), text=text, encoding="utf-16le"))
    return results


def extract_all(data: bytes, min_length: int = DEFAULT_MIN_LENGTH) -> list[FoundString]:
    found = extract_ascii(data, min_length) + extract_utf16le(data, min_length)
    found.sort(key=lambda s: s.offset)
    return found
