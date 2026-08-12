from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def minimal_elf_bytes() -> bytes:
    return (FIXTURES_DIR / "minimal.elf").read_bytes()


@pytest.fixture
def dynamic_elf_bytes() -> bytes:
    return (FIXTURES_DIR / "dynamic.elf").read_bytes()


@pytest.fixture
def minimal_pe_bytes() -> bytes:
    return (FIXTURES_DIR / "minimal.pe").read_bytes()
