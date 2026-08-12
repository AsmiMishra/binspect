from binspect.analysis import strings


def test_extract_ascii_finds_literal():
    data = b"\x00\x01garbage" + b"Hello, world!" + b"\x02\x03"
    found = strings.extract_ascii(data, min_length=4)
    texts = [s.text for s in found]
    assert "garbageHello, world!" in texts  # contiguous printable run


def test_extract_ascii_respects_min_length():
    data = b"\x00ab\x00cdef\x00"
    found = strings.extract_ascii(data, min_length=4)
    assert [s.text for s in found] == ["cdef"]


def test_extract_utf16le_finds_wide_string():
    text = "CreateFileW"
    data = b"\x00\x00" + text.encode("utf-16le") + b"\x00\x00"
    found = strings.extract_utf16le(data, min_length=4)
    assert any(s.text == text for s in found)


def test_extract_all_sorted_by_offset():
    ascii_part = b"AAAA"
    wide_part = "BBBB".encode("utf-16le")
    data = wide_part + b"\x00\x00" + ascii_part
    found = strings.extract_all(data, min_length=4)
    offsets = [s.offset for s in found]
    assert offsets == sorted(offsets)


def test_no_false_positive_on_random_bytes():
    data = bytes([0, 1, 2, 3, 4, 5, 255, 254])
    found = strings.extract_all(data, min_length=4)
    assert found == []
