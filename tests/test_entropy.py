import os

from binspect.analysis import entropy


def test_all_zero_bytes_have_zero_entropy():
    assert entropy.shannon_entropy(b"\x00" * 1000) == 0.0


def test_empty_bytes_have_zero_entropy():
    assert entropy.shannon_entropy(b"") == 0.0


def test_uniform_random_bytes_are_high_entropy():
    data = os.urandom(4096)
    assert entropy.shannon_entropy(data) >= entropy.PACKED_THRESHOLD


def test_repeated_pattern_is_lower_entropy_than_random():
    pattern = (b"AB" * 2048)
    random_data = os.urandom(4096)
    assert entropy.shannon_entropy(pattern) < entropy.shannon_entropy(random_data)


def test_analyze_regions_flags_high_entropy_region():
    regions = [
        ("low", b"\x00" * 256),
        ("high", os.urandom(256)),
    ]
    results = entropy.analyze_regions(regions)
    by_name = {r.name: r for r in results}
    assert not by_name["low"].likely_packed
    assert by_name["high"].likely_packed
