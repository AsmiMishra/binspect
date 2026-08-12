from binspect.formats import identify


def test_identifies_elf(minimal_elf_bytes):
    result = identify.identify(minimal_elf_bytes)
    assert result.format == "elf"
    assert result.supported


def test_identifies_pe(minimal_pe_bytes):
    result = identify.identify(minimal_pe_bytes)
    assert result.format == "pe"
    assert result.supported


def test_mz_without_pe_signature_is_not_pe():
    # A bare "MZ" header with garbage where the PE signature should be
    # must not be misreported as PE - it could be a real 16-bit DOS exe.
    data = b"MZ" + b"\x00" * 0x3E
    result = identify.identify(data)
    assert result.format != "pe"


def test_unknown_format():
    result = identify.identify(b"not a real binary at all")
    assert result.format == "unknown"
    assert not result.supported


def test_zip_recognized_but_unsupported():
    result = identify.identify(b"PK\x03\x04rest of a zip file")
    assert result.format == "zip"
    assert not result.supported


def test_empty_data_does_not_raise():
    result = identify.identify(b"")
    assert result.format == "unknown"
