"""Magic-byte file format identification.

Real-world triage tools (``file``, VirusTotal, YARA) all start the same
way: look at the first few bytes before doing anything expensive. Magic
numbers are fixed byte sequences that file formats put at a predictable
offset (almost always byte 0) so a program can identify the format in
O(1) time without parsing the whole file.
"""

from __future__ import annotations

from dataclasses import dataclass

# Offset 0 magic numbers for formats binspect understands, plus a few
# common ones it recognizes but does not parse (so the CLI can still
# report "what is this" honestly instead of guessing).
_MAGIC_TABLE: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),  # confirmed later via the PE\0\0 signature at e_lfanew
    (b"\xfe\xed\xfa\xce", "macho32"),
    (b"\xfe\xed\xfa\xcf", "macho64"),
    (b"\xce\xfa\xed\xfe", "macho32-swap"),
    (b"\xcf\xfa\xed\xfe", "macho64-swap"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"PK\x03\x04", "zip"),  # also JAR/APK/docx/xlsx/etc.
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"%PDF", "pdf"),
)

SUPPORTED_FORMATS = {"elf", "pe"}


@dataclass(frozen=True)
class Identification:
    format: str
    description: str
    supported: bool


_DESCRIPTIONS = {
    "elf": "ELF (Executable and Linkable Format) - Linux/Unix",
    "pe": "PE (Portable Executable) - Windows",
    "macho32": "Mach-O 32-bit - macOS/iOS",
    "macho64": "Mach-O 64-bit - macOS/iOS",
    "macho32-swap": "Mach-O 32-bit (byte-swapped)",
    "macho64-swap": "Mach-O 64-bit (byte-swapped)",
    "macho-fat": "Mach-O Fat/Universal binary",
    "zip": "ZIP archive (or ZIP-based container: JAR/APK/DOCX/...)",
    "png": "PNG image",
    "pdf": "PDF document",
}


def identify(data: bytes) -> Identification:
    """Identify a file format from its leading bytes.

    Returns an ``Identification`` with ``format="unknown"`` rather than
    raising, because "I don't recognize this" is itself a useful,
    non-exceptional answer during triage.
    """
    for magic, fmt in _MAGIC_TABLE:
        if data.startswith(magic):
            if fmt == "pe" and not _looks_like_pe(data):
                continue
            return Identification(fmt, _DESCRIPTIONS[fmt], fmt in SUPPORTED_FORMATS)
    return Identification("unknown", "Unrecognized format", False)


def _looks_like_pe(data: bytes) -> bool:
    """MZ alone only means "DOS header". Confirm the PE signature exists
    at the offset the DOS header points to, so a stray MZ-prefixed file
    (or a real 16-bit DOS executable) isn't misreported as PE.
    """
    if len(data) < 0x40:
        return False
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    return data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
