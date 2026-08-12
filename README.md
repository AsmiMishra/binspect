# binspect

[![CI](https://github.com/AsmiMishra/binspect/actions/workflows/ci.yml/badge.svg)](https://github.com/AsmiMishra/binspect/actions/workflows/ci.yml)

A from-scratch **ELF and PE binary inspector**, written to learn (and demonstrate) the fundamentals of static binary analysis — the same category of reasoning used in reverse engineering, malware triage, and vulnerability research.

```
$ binspect all notepad.exe

Format identification
----------------------
  format           : pe
  description      : PE (Portable Executable) - Windows

PE header
---------
  format              : PE32+
  machine             : x64 (AMD64)
  subsystem           : Windows GUI
  entry point (RVA)   : 0x19c0
  ASLR (DYNAMIC_BASE) : True
  DEP (NX_COMPAT)     : True
  CFG (GUARD_CF)      : True

Sections
--------
  name    virt addr  raw size  perms
  ------  ---------  --------  -----
  .text   0x1000      159,744  R-X
  .rdata  0x29000      45,056  R--
  .data   0x34000       4,096  RW-
  ...

Imports (50 DLLs)
------------------
  USER32.dll  (87 functions)
    MessageBoxW, ShowWindow, SetCursor, ...

Entropy analysis
------------------
  whole file : 4.732 bits/byte
  ...
```

## Why this exists

Most tools that "inspect a binary" call `pefile` or `pyelftools` and print
whatever comes out. That's useful in production, but it teaches you
nothing about *why* an operating system loader can turn a sequence of
bytes into a running process. binspect decodes the ELF and PE formats by
hand, straight from the specs, using nothing but Python's `struct` and
`hashlib` — no parsing library, no dependencies, no magic. Reading the
source is meant to double as a walkthrough of how executables actually
work.

## Concepts covered

| Area | What it teaches |
|---|---|
| **File format identification** | Magic-byte sniffing (`\x7fELF`, `MZ`+`PE\0\0`, Mach-O, ZIP/PNG/PDF) — how triage tools decide what they're looking at in O(1) before doing any real parsing. |
| **ELF internals** | ELF header, program headers (segments the OS loader maps into memory) vs. section headers (what a linker/analyst sees), `.dynamic`/`DT_NEEDED` walking to resolve imported shared libraries, `PT_INTERP` (dynamic linker path). |
| **PE internals** | The MS-DOS-compatible DOS header → `PE\0\0` signature → COFF header → Optional header chain, section table, the Import Directory Table / Import Lookup Table walk that recovers imported DLLs *and function names*, the Export Directory Table. |
| **Exploit mitigations** | Reading `PT_GNU_STACK`/`PT_GNU_RELRO` (NX, RELRO) on ELF and `DllCharacteristics` (ASLR, DEP, CFG) on PE — the same flags security tooling checks when judging how hardened a binary is. |
| **Static malware triage** | Shannon entropy per section (packing/encryption detection), printable ASCII + UTF-16LE string extraction (IOC/config/URL discovery without disassembly), cryptographic hashing (MD5/SHA1/SHA256) for sample identification against threat-intel feeds. |
| **Raw analysis** | A `hexdump`-style byte viewer, because every higher-level view here is ultimately just an interpretation of these bytes. |

## Install

Requires Python 3.10+. No dependencies for normal use.

```bash
git clone https://github.com/<your-username>/binspect.git
cd binspect
pip install -e .          # installs the `binspect` command
# or just:
python -m binspect --help # run directly from source, no install needed
```

## Usage

```
binspect identify  <file>              # what format is this?
binspect header    <file>              # ELF/PE header fields + mitigation flags
binspect sections  <file>              # section table
binspect imports   <file> [--limit N]  # DT_NEEDED (ELF) / import table (PE)
binspect exports   <file>              # export table (PE)
binspect strings   <file> [--min-length N]
binspect entropy   <file>              # whole-file + per-section Shannon entropy
binspect hash       <file>              # MD5 / SHA1 / SHA256
binspect hexdump    <file> [--offset O] [--length L]
binspect all         <file>              # everything above, one report
```

Every subcommand accepts `--json` for machine-readable output.

## Architecture

```
src/binspect/
  formats/
    identify.py   magic-byte format identification
    elf.py        from-scratch ELF32/ELF64 parser (struct-based)
    pe.py         from-scratch PE32/PE32+ parser (struct-based)
  analysis/
    hashes.py     MD5/SHA1/SHA256
    entropy.py    Shannon entropy (packing heuristic)
    strings.py    ASCII + UTF-16LE string extraction
    hexdump.py    hex + ASCII byte viewer
  report.py       dependency-free text table formatting
  cli.py          argparse-based CLI
```

Each parser is a pure function: `bytes -> dataclass`. No global state, no
I/O inside the parsing code — files are read once in the CLI layer and
handed down as `bytes`, which is what makes every piece independently
unit-testable.

## Testing

The test suite includes hand-assembled, spec-valid **synthetic** ELF64
and PE32+ fixtures (`tests/fixtures/generate.py`) built byte-by-byte from
the format specs — no compiler required, and safe to commit since they
contain no real code, just conformant headers/sections/import tables.
The parsers have also been manually verified against real-world system
binaries during development.

```bash
pip install -e ".[dev]"
python tests/fixtures/generate.py   # (re)generate fixtures
pytest -q
ruff check src tests
```

## Roadmap

Deliberately scoped to "do ELF and PE well" rather than "half-support
everything." Natural next steps if this grows further:
- Mach-O parsing (mirroring the ELF/PE approach)
- YARA-style byte-signature matching
- A minimal disassembly view (via `capstone`) for the entry point

## License

MIT — see [LICENSE](LICENSE).
