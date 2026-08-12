from binspect.analysis import hexdump


def test_hexdump_shows_offset_and_bytes():
    data = bytes(range(32))
    out = hexdump.format_hexdump(data)
    lines = out.splitlines()
    assert lines[0].startswith("00000000")
    assert lines[1].startswith("00000010")


def test_hexdump_ascii_gutter_shows_printable_chars():
    data = b"Hello, world!!!!"
    out = hexdump.format_hexdump(data)
    assert "|Hello, world!!!!|" in out


def test_hexdump_unprintable_bytes_shown_as_dot():
    data = bytes([0x00, 0x01, 0x02, 0xFF]) * 4
    out = hexdump.format_hexdump(data)
    assert "|................|" in out


def test_hexdump_respects_length_window():
    data = bytes(range(64))
    out = hexdump.format_hexdump(data, offset=0, length=16)
    assert len(out.splitlines()) == 1


def test_hexdump_respects_offset():
    data = bytes(range(64))
    out = hexdump.format_hexdump(data, offset=32, length=16)
    assert out.startswith("00000020")
