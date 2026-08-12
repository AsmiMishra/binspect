"""Cryptographic hashing for file identification.

A hash is how the security industry answers "have I seen this exact file
before?" - antivirus signatures, malware-sample databases (VirusTotal,
MalwareBazaar), and incident-response runbooks all key on file hashes
because a single-bit change in a binary produces a completely different,
uncorrelated digest (the avalanche effect). MD5 and SHA1 are included
despite being cryptographically broken (collision attacks exist) because
they're still the *lingua franca* IDs used across nearly all existing
malware databases; SHA256 is the modern default you should prefer for
new integrity checks.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Hashes:
    md5: str
    sha1: str
    sha256: str


def compute(data: bytes) -> Hashes:
    return Hashes(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )
