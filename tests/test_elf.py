import pytest

from binspect.formats import elf


def test_parses_minimal_static_elf(minimal_elf_bytes):
    info = elf.parse(minimal_elf_bytes)
    assert info.ei_class == "ELF64"
    assert info.ei_data == "little-endian"
    assert info.is_64bit
    assert "ET_EXEC" in info.e_type
    assert info.e_machine == "x86-64"
    assert info.interpreter is None
    assert info.needed_libraries == []
    assert not info.is_pie


def test_minimal_elf_sections(minimal_elf_bytes):
    info = elf.parse(minimal_elf_bytes)
    names = [s.name for s in info.sections]
    assert names == ["(unnamed)", ".text", ".shstrtab"]
    text = next(s for s in info.sections if s.name == ".text")
    assert text.sh_size == 16
    assert text.executable
    assert not text.writable


def test_minimal_elf_program_headers(minimal_elf_bytes):
    info = elf.parse(minimal_elf_bytes)
    assert len(info.program_headers) == 1
    load = info.program_headers[0]
    assert load.p_type_name == "PT_LOAD"
    assert load.permissions == "R-X"


def test_parses_dynamic_elf_needed_libraries(dynamic_elf_bytes):
    info = elf.parse(dynamic_elf_bytes)
    assert info.needed_libraries == ["libfake.so.1"]
    assert info.interpreter == "/lib64/ld-linux-x86-64.so.2"
    assert "ET_DYN" in info.e_type
    assert info.is_pie  # ET_DYN + interpreter present => PIE, not a plain .so


def test_rejects_bad_magic():
    with pytest.raises(elf.ELFParseError):
        elf.parse(b"NOTANELFFILE" + b"\x00" * 100)


def test_rejects_truncated_header():
    with pytest.raises(elf.ELFParseError):
        elf.parse(b"\x7fELF\x02\x01\x01\x00")  # magic + ident only, header cut off


def test_has_nx_stack_false_without_gnu_stack_segment(minimal_elf_bytes):
    # The synthetic fixture has no PT_GNU_STACK segment at all, which
    # should read as "not confirmed NX", not crash or default to True.
    info = elf.parse(minimal_elf_bytes)
    assert info.has_nx_stack is False
    assert info.has_relro is False
