"""Shannon entropy analysis - the standard heuristic for spotting packed,
encrypted, or compressed regions of a binary without executing it.

Shannon entropy measures how "surprising" the next byte is, given the
distribution of bytes seen so far:

    H = -sum( p(b) * log2(p(b)) )  for each byte value b that appears

It ranges from 0 (every byte identical - maximally predictable) to 8.0
bits/byte (all 256 byte values equally likely - maximally unpredictable).
Normal compiled code and readable strings cluster in the middle: opcode
bytes repeat, ASCII text uses a small alphabet, so typical `.text`/`.data`
entropy sits roughly in the 4-6.5 range. Compressed and encrypted data,
by contrast, is specifically *designed* to look statistically uniform -
that's what makes compression efficient and encryption secure - so it
reliably scores above ~7.0-7.2. That's why entropy is a cheap, effective
first pass for malware packing detection: a "packer" like UPX compresses
the real payload and unpacks it at runtime, and the compressed payload's
high entropy is very hard to hide without actually decompressing it.

Entropy is a heuristic, not proof - legitimately compressed resources
(embedded PNGs, zipped resources) also score high. It tells you where to
look closer, not what you'll find.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

PACKED_THRESHOLD = 7.0


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


@dataclass(frozen=True)
class RegionEntropy:
    name: str
    entropy: float
    size: int

    @property
    def likely_packed(self) -> bool:
        return self.entropy >= PACKED_THRESHOLD


def analyze_regions(regions: list[tuple[str, bytes]]) -> list[RegionEntropy]:
    """Compute entropy per named byte region (e.g. one per section), so
    callers can spot *which part* of a file looks packed rather than
    just an undifferentiated whole-file average that could hide a small
    high-entropy payload inside a large low-entropy binary.
    """
    return [
        RegionEntropy(name=name, entropy=shannon_entropy(chunk), size=len(chunk))
        for name, chunk in regions
    ]
