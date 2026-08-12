"""Generates tiny, synthetic-but-spec-valid ELF64 and PE32+ binaries for
the test suite.

No compiler is required (or used) to produce these: every byte is
assembled by hand from the ELF and PE/COFF specifications, the same way
a linker would. They contain no real code - just headers, section
tables, and (for the "dynamic"/"imports" variants) a minimal dynamic-
linking / import table, which is exactly the surface area binspect's
parsers need to exercise. Because nothing here is copied from any real,
copyrighted binary, these fixtures are safe to commit and redistribute.

Run directly to (re)write the fixtures:

    python tests/fixtures/generate.py
"""

from __future__ import annotations

import struct
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent


class Builder:
    """Append-only byte buffer that tracks its own current offset, so
    fixture layout can be expressed as "write this, then that" instead
    of hand-computed magic-number offsets.
    """

    def __init__(self) -> None:
        self.buf = bytearray()

    @property
    def offset(self) -> int:
        return len(self.buf)

    def write(self, data: bytes) -> int:
        start = self.offset
        self.buf.extend(data)
        return start

    def pack(self, fmt: str, *args) -> int:
        return self.write(struct.pack(fmt, *args))

    def pad_to(self, offset: int) -> None:
        if self.offset < offset:
            self.buf.extend(b"\x00" * (offset - self.offset))

    def bytes(self) -> bytes:
        return bytes(self.buf)


def build_minimal_elf() -> bytes:
    """A static (no PT_DYNAMIC), non-PIE ELF64 executable: just an ELF
    header, one PT_LOAD segment, and a .text/.shstrtab section pair.
    Exercises the base header + program header + section header parsing
    path with no dynamic-linking complexity.
    """
    b = Builder()
    VADDR_BASE = 0x400000

    # Reserve space for the ELF header (64 bytes) and the one program
    # header (56 bytes) we'll fill in after we know later offsets.
    ehdr_off = b.write(b"\x00" * 64)
    phdr_off = b.write(b"\x00" * 56)

    text_off = b.write(b"\x90" * 16)  # 16 NOPs - stand-in "code"

    shstrtab_off = b.offset
    names = {}

    def intern(name: str) -> int:
        rel = len(b.buf) - shstrtab_off
        b.write(name.encode() + b"\x00")
        return rel

    b.write(b"\x00")  # index 0: empty string, per ELF convention
    names[".text"] = intern(".text")
    names[".shstrtab"] = intern(".shstrtab")
    shstrtab_size = b.offset - shstrtab_off

    shdr_off = b.offset
    # Section 0: SHT_NULL, all zero, required as index 0.
    b.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    # Section 1: .text (SHT_PROGBITS, alloc+exec)
    b.pack(
        "<IIQQQQIIQQ",
        names[".text"], 1, 0x2 | 0x4, VADDR_BASE + text_off, text_off, 16, 0, 0, 1, 0,
    )
    # Section 2: .shstrtab (SHT_STRTAB, no alloc)
    b.pack(
        "<IIQQQQIIQQ",
        names[".shstrtab"], 3, 0, 0, shstrtab_off, shstrtab_size, 0, 0, 1, 0,
    )

    total_size = b.offset

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type = ET_EXEC
        0x3E,  # e_machine = x86-64
        1,  # e_version
        VADDR_BASE + text_off,  # e_entry
        phdr_off,  # e_phoff
        shdr_off,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        1,  # e_phnum
        64,  # e_shentsize
        3,  # e_shnum
        2,  # e_shstrndx
    )
    b.buf[ehdr_off : ehdr_off + 64] = ehdr

    phdr = struct.pack(
        "<IIQQQQQQ",
        1,  # p_type = PT_LOAD
        0x4 | 0x1,  # p_flags = R+X
        0,  # p_offset
        VADDR_BASE,  # p_vaddr
        VADDR_BASE,  # p_paddr
        total_size,  # p_filesz
        total_size,  # p_memsz
        0x1000,  # p_align
    )
    b.buf[phdr_off : phdr_off + 56] = phdr

    return b.bytes()


def build_dynamic_elf() -> bytes:
    """An ELF64 executable with PT_INTERP and PT_DYNAMIC, so the
    DT_NEEDED-walking / vaddr-to-file-offset-translation code path in
    elf.py gets exercised: it "needs" a fake shared library, the way a
    real dynamically-linked binary needs libc.
    """
    b = Builder()
    VADDR_BASE = 0x400000

    ehdr_off = b.write(b"\x00" * 64)
    phdr_off = b.write(b"\x00" * (56 * 3))  # PT_LOAD, PT_INTERP, PT_DYNAMIC

    text_off = b.write(b"\x90" * 16)

    interp_off = b.write(b"/lib64/ld-linux-x86-64.so.2\x00")

    dynstr_off = b.offset
    b.write(b"\x00")  # empty-string convention at index 0
    needed_name_off = b.offset - dynstr_off
    b.write(b"libfake.so.1\x00")
    dynstr_size = b.offset - dynstr_off

    dynamic_off = b.offset
    DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_NULL = 1, 5, 10, 0
    b.pack("<qQ", DT_NEEDED, needed_name_off)
    b.pack("<qQ", DT_STRTAB, VADDR_BASE + dynstr_off)
    b.pack("<qQ", DT_STRSZ, dynstr_size)
    b.pack("<qQ", DT_NULL, 0)
    dynamic_size = b.offset - dynamic_off

    shstrtab_off = b.offset
    names = {}

    def intern(name: str) -> int:
        rel = b.offset - shstrtab_off
        b.write(name.encode() + b"\x00")
        return rel

    b.write(b"\x00")
    names[".text"] = intern(".text")
    names[".dynamic"] = intern(".dynamic")
    names[".shstrtab"] = intern(".shstrtab")
    shstrtab_size = b.offset - shstrtab_off

    shdr_off = b.offset
    b.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    b.pack(
        "<IIQQQQIIQQ",
        names[".text"], 1, 0x2 | 0x4, VADDR_BASE + text_off, text_off, 16, 0, 0, 1, 0,
    )
    b.pack(
        "<IIQQQQIIQQ",
        names[".dynamic"], 6, 0x2 | 0x1, VADDR_BASE + dynamic_off, dynamic_off,
        dynamic_size, 0, 0, 8, 16,
    )
    b.pack(
        "<IIQQQQIIQQ",
        names[".shstrtab"], 3, 0, 0, shstrtab_off, shstrtab_size, 0, 0, 1, 0,
    )

    total_size = b.offset

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,  # e_type = ET_DYN (PIE)
        0x3E,
        1,
        VADDR_BASE + text_off,
        phdr_off,
        shdr_off,
        0,
        64,
        56,
        3,  # e_phnum
        64,
        4,  # e_shnum
        3,  # e_shstrndx
    )
    b.buf[ehdr_off : ehdr_off + 64] = ehdr

    phdrs = struct.pack(
        "<IIQQQQQQ", 1, 0x4 | 0x1, 0, VADDR_BASE, VADDR_BASE, total_size, total_size, 0x1000
    )
    phdrs += struct.pack(
        "<IIQQQQQQ",
        3,  # PT_INTERP
        0x4,
        interp_off,
        VADDR_BASE + interp_off,
        VADDR_BASE + interp_off,
        29,
        29,
        1,
    )
    phdrs += struct.pack(
        "<IIQQQQQQ",
        2,  # PT_DYNAMIC
        0x4 | 0x2,
        dynamic_off,
        VADDR_BASE + dynamic_off,
        VADDR_BASE + dynamic_off,
        dynamic_size,
        dynamic_size,
        8,
    )
    b.buf[phdr_off : phdr_off + len(phdrs)] = phdrs

    return b.bytes()


def build_minimal_pe() -> bytes:
    """A minimal PE32+ EXE with one .text section and a single-DLL
    import table (KERNEL32.dll: ExitProcess, GetStdHandle), exercising
    the DOS/COFF/optional-header parse path plus RVA-to-file-offset
    translation and Import Lookup Table walking.
    """
    b = Builder()
    IMAGE_BASE = 0x140000000
    SECTION_RVA = 0x1000

    # --- DOS header: only e_lfanew (at fixed offset 0x3C) matters. ---
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    b.write(bytes(dos))

    b.write(b"PE\x00\x00")
    coff_off = b.offset
    b.write(b"\x00" * struct.calcsize("<HHIIIHH"))  # filled in once we know sizes

    opt_off = b.offset
    opt_fmt = "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII"
    b.write(b"\x00" * struct.calcsize(opt_fmt))

    dir_off = b.offset
    NUM_RVA_AND_SIZES = 2  # export, import
    b.write(b"\x00" * (8 * NUM_RVA_AND_SIZES))

    section_hdr_off = b.offset
    b.write(b"\x00" * struct.calcsize("<8sIIIIIIHHI"))  # one section

    # --- Section raw data: import directory table + ILT + names ---
    section_data_off = b.offset
    section_rva_of = lambda file_off: SECTION_RVA + (file_off - section_data_off)

    import_dir_off = b.offset
    b.write(b"\x00" * (20 * 2))  # 1 real descriptor + 1 null terminator

    ilt_off = b.offset
    b.write(b"\x00" * (8 * 3))  # 2 functions + null terminator

    hint_name_offs = []
    for fn in ("ExitProcess", "GetStdHandle"):
        off = b.offset
        b.write(struct.pack("<H", 0) + fn.encode() + b"\x00")
        hint_name_offs.append(off)

    dll_name_off = b.write(b"KERNEL32.dll\x00")

    section_size = b.offset - section_data_off

    # Now backfill the ILT with RVAs to each IMAGE_IMPORT_BY_NAME.
    ilt_entries = [section_rva_of(o) for o in hint_name_offs] + [0]
    struct.pack_into("<3Q", b.buf, ilt_off, *ilt_entries)

    # And the import descriptor: OriginalFirstThunk, TimeDateStamp,
    # ForwarderChain, Name RVA, FirstThunk.
    struct.pack_into(
        "<IIIII",
        b.buf,
        import_dir_off,
        section_rva_of(ilt_off),
        0,
        0,
        section_rva_of(dll_name_off),
        section_rva_of(ilt_off),
    )

    total_size = b.offset

    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    section_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        section_size,  # virtual size
        SECTION_RVA,
        section_size,  # raw size
        section_data_off,
        0,
        0,
        0,
        0,
        IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    )
    b.buf[section_hdr_off : section_hdr_off + len(section_hdr)] = section_hdr

    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    opt_hdr_size = struct.calcsize(opt_fmt) + 8 * NUM_RVA_AND_SIZES
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,  # machine = x64
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable (deprecated/unused)
        0,  # NumberOfSymbols
        opt_hdr_size,
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE,
    )
    b.buf[coff_off : coff_off + len(coff)] = coff

    DYNAMIC_BASE, NX_COMPAT, GUARD_CF = 0x0040, 0x0100, 0x4000
    opt = struct.pack(
        opt_fmt,
        0x20B,  # Magic = PE32+
        14, 0,  # Linker version
        16, 0, 0,  # SizeOfCode/InitializedData/UninitializedData
        SECTION_RVA,  # AddressOfEntryPoint
        SECTION_RVA,  # BaseOfCode
        IMAGE_BASE,
        0x1000, 0x200,  # SectionAlignment, FileAlignment
        6, 0, 0, 0, 6, 0,  # OS/Image/Subsystem version fields
        0,  # Win32VersionValue
        total_size,  # SizeOfImage
        section_data_off,  # SizeOfHeaders
        0,  # CheckSum
        3,  # Subsystem = console
        DYNAMIC_BASE | NX_COMPAT | GUARD_CF,
        0x100000, 0x1000, 0x100000, 0x1000,  # stack/heap reserve+commit
        0,  # LoaderFlags
        NUM_RVA_AND_SIZES,
    )
    b.buf[opt_off : opt_off + len(opt)] = opt

    struct.pack_into("<II", b.buf, dir_off, 0, 0)  # export dir: absent
    struct.pack_into(
        "<II", b.buf, dir_off + 8, section_rva_of(import_dir_off), 40
    )  # import dir

    return b.bytes()


def main() -> None:
    fixtures = {
        "minimal.elf": build_minimal_elf(),
        "dynamic.elf": build_dynamic_elf(),
        "minimal.pe": build_minimal_pe(),
    }
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in fixtures.items():
        (FIXTURES_DIR / name).write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
