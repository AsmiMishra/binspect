"""A from-scratch PE (Portable Executable) parser.

PE is the executable format used by Windows (.exe, .dll, .sys, ...). Its
ancestry shows: a PE file starts with a real, bootable MS-DOS 2.0
executable (the "DOS stub" that prints "This program cannot be run in
DOS mode"), and only *after* that does the real Windows header begin, at
an offset the DOS header points to. That backward-compatibility hack is
still how every Windows loader (and every AV engine, and this parser)
finds its way into the file today.

Layout:

    +----------------------+
    | MZ / DOS header       |  <- legacy 16-bit header; only e_lfanew matters to us
    +----------------------+
    | DOS stub               |
    +----------------------+
    | "PE\\0\\0" signature    |  <- at e_lfanew
    +----------------------+
    | COFF file header       |  <- machine type, section count, timestamp
    +----------------------+
    | Optional header         |  <- despite the name, always present; entry point, subsystem, DLL characteristics
    +----------------------+
    | Section headers         |  <- name, virtual/raw size+addr, characteristics (R/W/X)
    +----------------------+
    | .text, .rdata, ...       |  <- section bytes, including the import/export directories
    +----------------------+

Everything here is decoded with ``struct`` directly from the Microsoft
PE/COFF specification, with no ``pefile`` dependency, for the same reason
the ELF parser avoids ``pyelftools``: manually walking the format is the
learning exercise.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

PE_SIGNATURE = b"PE\x00\x00"

MACHINE_TYPES = {
    0x014C: "x86 (I386)",
    0x0200: "IA-64",
    0x8664: "x64 (AMD64)",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x01C4: "ARMv7 (Thumb-2)",
}

# COFF Characteristics flags (IMAGE_FILE_HEADER.Characteristics).
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000

SUBSYSTEMS = {
    1: "Native (no subsystem required)",
    2: "Windows GUI",
    3: "Windows console (CUI)",
    5: "OS/2 console",
    7: "POSIX console",
    9: "Windows CE GUI",
    10: "EFI application",
    14: "Xbox",
}

# DllCharacteristics bits (IMAGE_OPTIONAL_HEADER.DllCharacteristics) -
# these are the exploit-mitigation flags: the PE analogue of ELF's
# PT_GNU_STACK (NX) / PT_GNU_RELRO checks.
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040  # ASLR
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100  # DEP
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000  # Control Flow Guard

# IMAGE_SCN_* section characteristics we care about (permissions).
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1


class PEParseError(ValueError):
    pass


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int
    characteristics: int

    @property
    def permissions(self) -> str:
        return (
            ("R" if self.characteristics & IMAGE_SCN_MEM_READ else "-")
            + ("W" if self.characteristics & IMAGE_SCN_MEM_WRITE else "-")
            + ("X" if self.characteristics & IMAGE_SCN_MEM_EXECUTE else "-")
        )


@dataclass
class ImportedDLL:
    name: str
    functions: list[str] = field(default_factory=list)


@dataclass
class PEInfo:
    machine: str
    is_pe32_plus: bool
    is_dll: bool
    is_executable_image: bool
    num_sections: int
    timestamp: int
    entry_point: int
    image_base: int
    subsystem: str
    dll_characteristics: int
    sections: list[Section] = field(default_factory=list)
    imports: list[ImportedDLL] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    export_dll_name: str | None = None

    @property
    def has_aslr(self) -> bool:
        return bool(self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

    @property
    def has_dep(self) -> bool:
        return bool(self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

    @property
    def has_cfg(self) -> bool:
        return bool(self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)

    @property
    def has_seh(self) -> bool:
        return not (self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)


def parse(data: bytes) -> PEInfo:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEParseError("not a PE file (missing MZ magic)")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != PE_SIGNATURE:
        raise PEParseError("no PE\\0\\0 signature at e_lfanew - not a valid PE file")

    coff_off = e_lfanew + 4
    coff_fmt = "<HHIIIHH"
    coff_size = struct.calcsize(coff_fmt)
    if len(data) < coff_off + coff_size:
        raise PEParseError("file truncated in COFF header")
    (
        machine, num_sections, timestamp, _sym_table_ptr, _num_syms,
        opt_hdr_size, characteristics,
    ) = struct.unpack_from(coff_fmt, data, coff_off)

    opt_off = coff_off + coff_size
    if opt_hdr_size == 0 or len(data) < opt_off + 2:
        raise PEParseError("missing optional header")

    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_pe32_plus = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        raise PEParseError(f"unrecognized optional header magic 0x{magic:x}")

    if is_pe32_plus:
        # PE32+ widens ImageBase/Stack/Heap fields to 8 bytes and drops
        # BaseOfData, versus PE32 - everything before that point is
        # identical in layout.
        fmt = "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII"
    else:
        fmt = "<HBBIIIIIIIIIIHHHHHHIIIIHHIIIIII"
    fixed_size = struct.calcsize(fmt)
    if len(data) < opt_off + fixed_size:
        raise PEParseError("file truncated in optional header")
    fields = struct.unpack_from(fmt, data, opt_off)

    if is_pe32_plus:
        (
            _magic, _maj_lv, _min_lv, _code_sz, _init_sz, _uninit_sz,
            entry_point, _base_of_code, image_base, _sect_align,
            _file_align, _os_maj, _os_min, _img_maj, _img_min, _sub_maj,
            _sub_min, _win32ver, _size_of_image, _size_of_headers,
            _checksum, subsystem, dll_characteristics, _stack_res,
            _stack_commit, _heap_res, _heap_commit, _loader_flags,
            num_rva_and_sizes,
        ) = fields
    else:
        (
            _magic, _maj_lv, _min_lv, _code_sz, _init_sz, _uninit_sz,
            entry_point, _base_of_code, _base_of_data, image_base,
            _sect_align, _file_align, _os_maj, _os_min, _img_maj,
            _img_min, _sub_maj, _sub_min, _win32ver, _size_of_image,
            _size_of_headers, _checksum, subsystem, dll_characteristics,
            _stack_res, _stack_commit, _heap_res, _heap_commit,
            _loader_flags, num_rva_and_sizes,
        ) = fields

    # The data directories array (RVA+size pairs for imports, exports,
    # resources, ...) follows immediately after the fields above.
    dir_off = opt_off + fixed_size
    directories = []
    for i in range(num_rva_and_sizes):
        start = dir_off + i * 8
        if len(data) < start + 8:
            break
        rva, size = struct.unpack_from("<II", data, start)
        directories.append((rva, size))

    section_off = dir_off + num_rva_and_sizes * 8
    sections = _parse_sections(data, section_off, num_sections)

    info = PEInfo(
        machine=MACHINE_TYPES.get(machine, f"unknown (0x{machine:x})"),
        is_pe32_plus=is_pe32_plus,
        is_dll=bool(characteristics & IMAGE_FILE_DLL),
        is_executable_image=bool(characteristics & IMAGE_FILE_EXECUTABLE_IMAGE),
        num_sections=num_sections,
        timestamp=timestamp,
        entry_point=entry_point,
        image_base=image_base,
        subsystem=SUBSYSTEMS.get(subsystem, f"unknown ({subsystem})"),
        dll_characteristics=dll_characteristics,
        sections=sections,
    )

    if len(directories) > IMAGE_DIRECTORY_ENTRY_IMPORT:
        rva, size = directories[IMAGE_DIRECTORY_ENTRY_IMPORT]
        if rva and size:
            info.imports = _parse_imports(data, rva, sections, is_pe32_plus)
    if len(directories) > IMAGE_DIRECTORY_ENTRY_EXPORT:
        rva, size = directories[IMAGE_DIRECTORY_ENTRY_EXPORT]
        if rva and size:
            info.exports, info.export_dll_name = _parse_exports(data, rva, sections)

    return info


def _parse_sections(data: bytes, off: int, count: int) -> list[Section]:
    fmt = "<8sIIIIIIHHI"
    entsize = struct.calcsize(fmt)
    sections = []
    for i in range(count):
        start = off + i * entsize
        chunk = data[start : start + entsize]
        if len(chunk) < entsize:
            break
        (
            raw_name, virtual_size, virtual_address, raw_size, raw_ptr,
            _reloc_ptr, _line_ptr, _num_relocs, _num_lines, characteristics,
        ) = struct.unpack(fmt, chunk)
        name = raw_name.rstrip(b"\x00").decode("ascii", "replace")
        sections.append(
            Section(
                name=name,
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                raw_size=raw_size,
                raw_ptr=raw_ptr,
                characteristics=characteristics,
            )
        )
    return sections


def _rva_to_offset(rva: int, sections: list[Section]) -> int | None:
    """PE tables are addressed by RVA (offset from the loaded image
    base) rather than raw file offset, because virtual size and raw
    (on-disk) size for a section can differ - .bss-like padding is
    zero-filled by the loader rather than stored in the file. We find
    the section whose virtual range contains the RVA and translate.
    """
    for sec in sections:
        span = max(sec.virtual_size, sec.raw_size)
        if sec.virtual_address <= rva < sec.virtual_address + span:
            return sec.raw_ptr + (rva - sec.virtual_address)
    return None


def _cstr(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("ascii", "replace")


def _parse_imports(
    data: bytes, rva: int, sections: list[Section], is_pe32_plus: bool
) -> list[ImportedDLL]:
    """Walk the Import Directory Table: one IMAGE_IMPORT_DESCRIPTOR per
    DLL this file depends on, each pointing to an Import Lookup Table
    (or Original First Thunk) that names the specific functions pulled
    in from that DLL. This is PE's answer to ELF's DT_NEEDED, but one
    level more detailed - it tells you not just "links against
    kernel32.dll" but "calls CreateFileW, WriteFile, ..." which is far
    more useful for judging what a binary actually does.
    """
    off = _rva_to_offset(rva, sections)
    if off is None:
        return []

    descriptor_fmt = "<IIIII"  # OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
    descsize = struct.calcsize(descriptor_fmt)
    dlls = []
    while True:
        chunk = data[off : off + descsize]
        if len(chunk) < descsize:
            break
        orig_thunk, _ts, _fwd, name_rva, _first_thunk = struct.unpack(
            descriptor_fmt, chunk
        )
        if orig_thunk == 0 and name_rva == 0:
            break  # a zeroed descriptor terminates the table
        off += descsize

        name_off = _rva_to_offset(name_rva, sections)
        dll_name = _cstr(data, name_off) if name_off is not None else "?"
        dll = ImportedDLL(name=dll_name)

        thunk_rva = orig_thunk  # prefer the ILT; it survives even after binding
        thunk_off = _rva_to_offset(thunk_rva, sections)
        if thunk_off is not None:
            dll.functions = _walk_thunk_table(data, thunk_off, sections, is_pe32_plus)
        dlls.append(dll)
    return dlls


def _walk_thunk_table(
    data: bytes, off: int, sections: list[Section], is_pe32_plus: bool
) -> list[str]:
    """ILT/IAT entries are 8 bytes wide in PE32+ but only 4 bytes in
    PE32 - getting this wrong silently misreads every other import as
    garbage, since the whole table shifts out of alignment.
    """
    entry_fmt = "<Q" if is_pe32_plus else "<I"
    entry_size = 8 if is_pe32_plus else 4
    ordinal_flag = (1 << 63) if is_pe32_plus else (1 << 31)
    ordinal_mask = 0x7FFFFFFFFFFFFFFF if is_pe32_plus else 0x7FFFFFFF

    functions = []
    while True:
        chunk = data[off : off + entry_size]
        if len(chunk) < entry_size:
            break
        (entry,) = struct.unpack(entry_fmt, chunk)
        if entry == 0:
            break
        off += entry_size
        if entry & ordinal_flag:
            functions.append(f"Ordinal#{entry & 0xFFFF}")
            continue
        # The remaining bits are an RVA to an IMAGE_IMPORT_BY_NAME
        # struct: a 2-byte Hint followed by the NUL-terminated name.
        name_rva = entry & ordinal_mask
        name_off = _rva_to_offset(name_rva, sections)
        if name_off is not None:
            functions.append(_cstr(data, name_off + 2))
    return functions


def _parse_exports(
    data: bytes, rva: int, sections: list[Section]
) -> tuple[list[str], str | None]:
    """Walk the Export Directory Table. Present mainly in DLLs: the list
    of function names other modules can `GetProcAddress` out of this
    file. Relatively rare in plain .exe files, but a strong signal when
    present (e.g. distinguishing a plugin/DLL from a standalone tool).
    """
    off = _rva_to_offset(rva, sections)
    if off is None:
        return [], None

    fmt = "<IIHHIIIIIII"
    size = struct.calcsize(fmt)
    chunk = data[off : off + size]
    if len(chunk) < size:
        return [], None
    (
        _flags, _ts, _maj, _min, name_rva, _base, _num_functions,
        num_names, _addr_of_funcs, addr_of_names, _addr_of_ords,
    ) = struct.unpack(fmt, chunk)

    dll_name = None
    name_off = _rva_to_offset(name_rva, sections)
    if name_off is not None:
        dll_name = _cstr(data, name_off)

    names_off = _rva_to_offset(addr_of_names, sections)
    if names_off is None or num_names == 0:
        return [], dll_name

    names = []
    for i in range(num_names):
        entry_off = names_off + i * 4
        chunk = data[entry_off : entry_off + 4]
        if len(chunk) < 4:
            break
        (fn_name_rva,) = struct.unpack("<I", chunk)
        fn_off = _rva_to_offset(fn_name_rva, sections)
        if fn_off is not None:
            names.append(_cstr(data, fn_off))
    return names, dll_name
