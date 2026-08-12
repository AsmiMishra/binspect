"""A from-scratch ELF (Executable and Linkable Format) parser.

ELF is the executable format used by Linux, BSD, and most other Unix-like
systems. Every field parsed here is read directly from the spec (see the
System V ABI and the elf(5) man page) using ``struct`` — no ``pyelftools``
or ``elftools`` dependency — because the point of this project is to
understand *why* a loader can turn these bytes into a running process,
not just to call a library that already knows.

Layout of an ELF file, top to bottom:

    +----------------------+
    | ELF header           |  <- fixed size, tells you everything else
    +----------------------+
    | Program headers       |  <- how the OS loader maps segments into memory
    +----------------------+
    | .text, .data, ...     |  <- actual section bytes
    +----------------------+
    | Section headers       |  <- how a linker/analysis tool finds sections
    +----------------------+

The two header tables (program headers, section headers) describe the
*same* bytes from two different audiences' points of view: the runtime
loader only cares about program headers (segments); tools like
objdump/gdb/binspect mostly want section headers (named, fine-grained).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"

EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7

ELFCLASS = {1: "ELF32", 2: "ELF64"}
ELFDATA = {1: "little-endian", 2: "big-endian"}

E_TYPE = {
    0: "ET_NONE (no file type)",
    1: "ET_REL (relocatable)",
    2: "ET_EXEC (executable)",
    3: "ET_DYN (shared object / PIE)",
    4: "ET_CORE (core dump)",
}

# The subset of e_machine values you actually run into day to day.
E_MACHINE = {
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x2A: "SuperH",
    0x32: "IA-64",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}

OSABI = {
    0x00: "System V",
    0x01: "HP-UX",
    0x02: "NetBSD",
    0x03: "Linux",
    0x06: "Solaris",
    0x09: "FreeBSD",
    0x0C: "OpenBSD",
}

# Program header p_type: what kind of segment the loader is looking at.
P_TYPE = {
    0: "PT_NULL",
    1: "PT_LOAD",  # a segment the loader maps into memory - this is the one that matters most
    2: "PT_DYNAMIC",  # dynamic linking info (imported libraries live here)
    3: "PT_INTERP",  # path to the dynamic linker/interpreter, e.g. /lib64/ld-linux-x86-64.so.2
    4: "PT_NOTE",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",  # presence/flags here tell you if the stack is executable (NX)
    0x6474E552: "PT_GNU_RELRO",  # RELRO hardening: makes GOT read-only after relocation
}

PF_X, PF_W, PF_R = 0x1, 0x2, 0x4

# Section header sh_type.
SH_TYPE = {
    0: "SHT_NULL",
    1: "SHT_PROGBITS",
    2: "SHT_SYMTAB",
    3: "SHT_STRTAB",
    4: "SHT_RELA",
    5: "SHT_HASH",
    6: "SHT_DYNAMIC",
    7: "SHT_NOTE",
    8: "SHT_NOBITS",  # .bss: takes up no space in the file, only in memory
    9: "SHT_REL",
    11: "SHT_DYNSYM",
}

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4

# DT_* tags in the .dynamic section that matter for import analysis.
DT_NEEDED = 1  # a required shared library, e.g. "libc.so.6"
DT_SONAME = 14  # this library's own name, when the file itself is a shared object


class ELFParseError(ValueError):
    pass


@dataclass
class ProgramHeader:
    p_type: int
    p_type_name: str
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    @property
    def permissions(self) -> str:
        return (
            ("R" if self.p_flags & PF_R else "-")
            + ("W" if self.p_flags & PF_W else "-")
            + ("X" if self.p_flags & PF_X else "-")
        )


@dataclass
class Section:
    name: str
    sh_type: int
    sh_type_name: str
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int

    @property
    def writable(self) -> bool:
        return bool(self.sh_flags & SHF_WRITE)

    @property
    def executable(self) -> bool:
        return bool(self.sh_flags & SHF_EXECINSTR)


@dataclass
class ELFInfo:
    ei_class: str
    ei_data: str
    ei_osabi: str
    e_type: str
    e_machine: str
    e_entry: int
    e_phoff: int
    e_shoff: int
    is_64bit: bool
    program_headers: list[ProgramHeader] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    needed_libraries: list[str] = field(default_factory=list)
    soname: str | None = None
    interpreter: str | None = None

    @property
    def is_pie(self) -> bool:
        """A PIE (position-independent executable) is an ET_DYN file that
        also has an entry point and PT_INTERP - distinguishing it from a
        plain shared library (.so), which is ET_DYN without those.
        """
        return "ET_DYN" in self.e_type and self.interpreter is not None

    @property
    def has_nx_stack(self) -> bool:
        """PT_GNU_STACK without PF_X means the stack is non-executable -
        a mitigation against classic stack-smashing shellcode injection.
        Its absence (no PT_GNU_STACK segment at all) means an older
        toolchain that never opted in, which most loaders now treat as
        "assume executable" for compatibility.
        """
        for ph in self.program_headers:
            if ph.p_type_name == "PT_GNU_STACK":
                return not (ph.p_flags & PF_X)
        return False

    @property
    def has_relro(self) -> bool:
        return any(ph.p_type_name == "PT_GNU_RELRO" for ph in self.program_headers)


def parse(data: bytes) -> ELFInfo:
    if len(data) < 20 or data[:4] != ELF_MAGIC:
        raise ELFParseError("not an ELF file (missing \\x7fELF magic)")

    ei_class = data[EI_CLASS]
    ei_data = data[EI_DATA]
    if ei_class not in ELFCLASS:
        raise ELFParseError(f"unknown EI_CLASS {ei_class!r}")
    if ei_data not in ELFDATA:
        raise ELFParseError(f"unknown EI_DATA {ei_data!r}")

    is_64bit = ei_class == 2
    endian = "<" if ei_data == 1 else ">"
    ei_osabi = OSABI.get(data[EI_OSABI], f"unknown (0x{data[EI_OSABI]:02x})")

    # e_ident is 16 bytes; the rest of the header differs between 32/64-bit
    # only in field *width* (addresses/offsets are 4 bytes vs 8), not in
    # field order, so one struct format per class covers everything.
    if is_64bit:
        fmt = endian + "HHIQQQIHHHHHH"
        size = 16 + struct.calcsize(fmt)
        if len(data) < size:
            raise ELFParseError("file truncated before end of ELF64 header")
        (
            e_type, e_machine, _e_version, e_entry, e_phoff, e_shoff,
            _e_flags, _e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
            e_shstrndx,
        ) = struct.unpack(fmt, data[16:size])
    else:
        fmt = endian + "HHIIIIIHHHHHH"
        size = 16 + struct.calcsize(fmt)
        if len(data) < size:
            raise ELFParseError("file truncated before end of ELF32 header")
        (
            e_type, e_machine, _e_version, e_entry, e_phoff, e_shoff,
            _e_flags, _e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
            e_shstrndx,
        ) = struct.unpack(fmt, data[16:size])

    info = ELFInfo(
        ei_class=ELFCLASS[ei_class],
        ei_data=ELFDATA[ei_data],
        ei_osabi=ei_osabi,
        e_type=E_TYPE.get(e_type, f"unknown (0x{e_type:x})"),
        e_machine=E_MACHINE.get(e_machine, f"unknown (0x{e_machine:x})"),
        e_entry=e_entry,
        e_phoff=e_phoff,
        e_shoff=e_shoff,
        is_64bit=is_64bit,
    )

    info.program_headers = _parse_program_headers(
        data, endian, is_64bit, e_phoff, e_phnum, e_phentsize
    )
    info.sections = _parse_sections(
        data, endian, is_64bit, e_shoff, e_shnum, e_shentsize, e_shstrndx
    )
    info.interpreter = _read_interpreter(data, info.program_headers)
    info.needed_libraries, info.soname = _read_dynamic_imports(
        data, endian, is_64bit, info.program_headers
    )
    return info


def _parse_program_headers(
    data: bytes, endian: str, is_64bit: bool, off: int, count: int, entsize: int
) -> list[ProgramHeader]:
    headers = []
    fmt = endian + ("IIQQQQQQ" if is_64bit else "IIIIIIII")
    expect = struct.calcsize(fmt)
    for i in range(count):
        start = off + i * entsize
        chunk = data[start : start + expect]
        if len(chunk) < expect:
            break
        if is_64bit:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = (
                struct.unpack(fmt, chunk)
            )
        else:
            (
                p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags,
                p_align,
            ) = struct.unpack(fmt, chunk)
        headers.append(
            ProgramHeader(
                p_type=p_type,
                p_type_name=P_TYPE.get(p_type, f"0x{p_type:x}"),
                p_flags=p_flags,
                p_offset=p_offset,
                p_vaddr=p_vaddr,
                p_filesz=p_filesz,
                p_memsz=p_memsz,
                p_align=p_align,
            )
        )
    return headers


def _parse_sections(
    data: bytes,
    endian: str,
    is_64bit: bool,
    off: int,
    count: int,
    entsize: int,
    shstrndx: int,
) -> list[Section]:
    if off == 0 or count == 0:
        return []  # a stripped executable can legally have no section headers at all

    fmt = endian + ("IIQQQQIIQQ" if is_64bit else "IIIIIIIIII")
    expect = struct.calcsize(fmt)
    raw = []
    for i in range(count):
        start = off + i * entsize
        chunk = data[start : start + expect]
        if len(chunk) < expect:
            break
        (
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
            _link, _info, _addralign, _entsize,
        ) = struct.unpack(fmt, chunk)
        raw.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size))

    # Resolve section names via .shstrtab, the one section whose only job
    # is holding other sections' names as NUL-terminated strings.
    strtab = b""
    if shstrndx < len(raw):
        _, _, _, _, str_off, str_size = raw[shstrndx]
        strtab = data[str_off : str_off + str_size]

    sections = []
    for sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size in raw:
        name = _cstr(strtab, sh_name) if strtab else ""
        sections.append(
            Section(
                name=name or "(unnamed)",
                sh_type=sh_type,
                sh_type_name=SH_TYPE.get(sh_type, f"0x{sh_type:x}"),
                sh_flags=sh_flags,
                sh_addr=sh_addr,
                sh_offset=sh_offset,
                sh_size=sh_size,
            )
        )
    return sections


def _read_interpreter(data: bytes, phs: list[ProgramHeader]) -> str | None:
    for ph in phs:
        if ph.p_type_name == "PT_INTERP":
            raw = data[ph.p_offset : ph.p_offset + ph.p_filesz]
            return raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    return None


def _read_dynamic_imports(
    data: bytes, endian: str, is_64bit: bool, phs: list[ProgramHeader]
) -> tuple[list[str], str | None]:
    """Walk PT_DYNAMIC to find DT_NEEDED entries - the shared libraries
    this binary requires at load time. This is the single most useful
    piece of static triage information for an unknown ELF binary: it's
    the same "what does this thing talk to" signal that PE imports give
    you, just addressed by tag/value pairs instead of a table.
    """
    dyn_ph = next((p for p in phs if p.p_type_name == "PT_DYNAMIC"), None)
    if dyn_ph is None:
        return [], None

    fmt = endian + ("qQ" if is_64bit else "iI")
    entsize = struct.calcsize(fmt)
    entries = []
    off = dyn_ph.p_offset
    end = off + dyn_ph.p_filesz
    strtab_off = None
    strtab_size = 0
    while off + entsize <= end:
        d_tag, d_val = struct.unpack(fmt, data[off : off + entsize])
        entries.append((d_tag, d_val))
        if d_tag == 0:  # DT_NULL terminates the table
            break
        if d_tag == 5:  # DT_STRTAB: virtual address of the dynamic string table
            strtab_off = d_val
        elif d_tag == 10:  # DT_STRSZ: its size
            strtab_size = d_val
        off += entsize

    if strtab_off is None:
        return [], None

    # DT_STRTAB gives a *virtual address*; translate it to a file offset
    # via the PT_LOAD segment that covers it, since we're reading the
    # file on disk, not a mapped process image.
    file_off = _vaddr_to_offset(strtab_off, phs)
    if file_off is None:
        return [], None
    strtab = data[file_off : file_off + strtab_size]

    needed = []
    soname = None
    for d_tag, d_val in entries:
        if d_tag == DT_NEEDED:
            needed.append(_cstr(strtab, d_val))
        elif d_tag == DT_SONAME:
            soname = _cstr(strtab, d_val)
    return needed, soname


def _vaddr_to_offset(vaddr: int, phs: list[ProgramHeader]) -> int | None:
    for ph in phs:
        if ph.p_type_name == "PT_LOAD" and ph.p_vaddr <= vaddr < ph.p_vaddr + ph.p_filesz:
            return ph.p_offset + (vaddr - ph.p_vaddr)
    return None


def _cstr(buf: bytes, offset: int) -> str:
    if offset >= len(buf):
        return ""
    end = buf.find(b"\x00", offset)
    if end == -1:
        end = len(buf)
    return buf[offset:end].decode("ascii", "replace")
