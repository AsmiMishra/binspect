import pytest

from binspect.formats import pe


def test_parses_minimal_pe(minimal_pe_bytes):
    info = pe.parse(minimal_pe_bytes)
    assert info.is_pe32_plus
    assert info.machine == "x64 (AMD64)"
    assert not info.is_dll
    assert info.has_aslr
    assert info.has_dep
    assert info.has_cfg


def test_minimal_pe_sections(minimal_pe_bytes):
    info = pe.parse(minimal_pe_bytes)
    assert len(info.sections) == 1
    text = info.sections[0]
    assert text.name == ".text"
    assert text.permissions == "R-X"


def test_minimal_pe_imports(minimal_pe_bytes):
    info = pe.parse(minimal_pe_bytes)
    assert len(info.imports) == 1
    dll = info.imports[0]
    assert dll.name == "KERNEL32.dll"
    assert dll.functions == ["ExitProcess", "GetStdHandle"]


def test_minimal_pe_has_no_exports(minimal_pe_bytes):
    info = pe.parse(minimal_pe_bytes)
    assert info.exports == []


def test_rejects_missing_mz_magic():
    with pytest.raises(pe.PEParseError):
        pe.parse(b"not a PE file" + b"\x00" * 100)


def test_rejects_mz_without_pe_signature():
    data = bytearray(128)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    # bytes at offset 64 are left zeroed, not "PE\0\0"
    with pytest.raises(pe.PEParseError):
        pe.parse(bytes(data))


def test_rejects_truncated_file():
    with pytest.raises(pe.PEParseError):
        pe.parse(b"MZ" + b"\x00" * 10)
