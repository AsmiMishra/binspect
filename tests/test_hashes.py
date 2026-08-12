import hashlib

from binspect.analysis import hashes


def test_matches_stdlib_hashlib():
    data = b"the quick brown fox jumps over the lazy dog"
    result = hashes.compute(data)
    assert result.md5 == hashlib.md5(data).hexdigest()
    assert result.sha1 == hashlib.sha1(data).hexdigest()
    assert result.sha256 == hashlib.sha256(data).hexdigest()


def test_different_input_different_hash():
    a = hashes.compute(b"abc")
    b = hashes.compute(b"abd")
    assert a.sha256 != b.sha256


def test_empty_input():
    result = hashes.compute(b"")
    assert result.sha256 == hashlib.sha256(b"").hexdigest()
