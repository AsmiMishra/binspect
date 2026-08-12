"""Command-line interface for binspect.

Design note: every subcommand loads the whole file into memory once and
operates on the resulting ``bytes``. That's a deliberate simplification -
real-world malware analysis tools memory-map multi-gigabyte samples - but
for the class of files this tool targets (typical executables, well
under a few hundred MB) it keeps every parser a pure, easily-testable
function of `bytes -> dataclass`, which matters more for a learning
project than streaming performance would.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from binspect import report
from binspect.analysis import entropy as entropy_mod
from binspect.analysis import hashes as hashes_mod
from binspect.analysis import hexdump as hexdump_mod
from binspect.analysis import strings as strings_mod
from binspect.formats import elf as elf_mod
from binspect.formats import identify as identify_mod
from binspect.formats import pe as pe_mod


def _to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, tuple):
        return [_to_jsonable(x) for x in obj]
    return obj


def _load(path: str) -> bytes:
    data = Path(path).read_bytes()
    if not data:
        raise SystemExit(f"error: {path} is empty")
    return data


def _parse_binary(data: bytes, path: str):
    """Identify the format and return (kind, info) or exit with an
    actionable error for formats binspect doesn't parse yet.
    """
    ident = identify_mod.identify(data)
    if ident.format == "elf":
        return "elf", elf_mod.parse(data)
    if ident.format == "pe":
        return "pe", pe_mod.parse(data)
    raise SystemExit(
        f"error: {path} is {ident.description!r} - binspect only parses "
        "ELF and PE headers/sections/imports (identify/strings/entropy/"
        "hash/hexdump work on any file)"
    )


def cmd_identify(args: argparse.Namespace) -> None:
    data = _load(args.file)
    ident = identify_mod.identify(data)
    if args.json:
        print(json.dumps(_to_jsonable(ident), indent=2))
        return
    print(report.heading("Format identification"))
    print(report.kv_table([
        ("format", ident.format),
        ("description", ident.description),
        ("binspect support", "yes" if ident.supported else "no (magic-byte ID only)"),
        ("file size", f"{len(data):,} bytes"),
    ]))


def cmd_header(args: argparse.Namespace) -> None:
    data = _load(args.file)
    kind, info = _parse_binary(data, args.file)
    if args.json:
        print(json.dumps({"format": kind, **_to_jsonable(info)}, indent=2, default=str))
        return
    print(report.heading(f"{kind.upper()} header"))
    if kind == "elf":
        print(report.kv_table([
            ("class", info.ei_class),
            ("data", info.ei_data),
            ("OS/ABI", info.ei_osabi),
            ("type", info.e_type),
            ("machine", info.e_machine),
            ("entry point", hex(info.e_entry)),
            ("interpreter", info.interpreter or "(none - statically linked or ET_REL)"),
            ("PIE", str(info.is_pie)),
            ("NX stack (no-exec)", str(info.has_nx_stack)),
            ("RELRO", str(info.has_relro)),
        ]))
    else:
        print(report.kv_table([
            ("format", "PE32+" if info.is_pe32_plus else "PE32"),
            ("machine", info.machine),
            ("type", "DLL" if info.is_dll else "EXE"),
            ("subsystem", info.subsystem),
            ("sections", str(info.num_sections)),
            ("entry point (RVA)", hex(info.entry_point)),
            ("image base", hex(info.image_base)),
            ("ASLR (DYNAMIC_BASE)", str(info.has_aslr)),
            ("DEP (NX_COMPAT)", str(info.has_dep)),
            ("CFG (GUARD_CF)", str(info.has_cfg)),
            ("SafeSEH/SEH enabled", str(info.has_seh)),
        ]))


def cmd_sections(args: argparse.Namespace) -> None:
    data = _load(args.file)
    kind, info = _parse_binary(data, args.file)
    if args.json:
        print(json.dumps(_to_jsonable(info.sections), indent=2))
        return
    print(report.heading("Sections"))
    if kind == "elf":
        rows = [
            [s.name, s.sh_type_name, hex(s.sh_addr), hex(s.sh_offset), f"{s.sh_size:,}",
             ("W" if s.writable else "-") + ("X" if s.executable else "-")]
            for s in info.sections
        ]
        print(report.table(["name", "type", "addr", "offset", "size", "flags"], rows))
    else:
        rows = [
            [s.name, hex(s.virtual_address), f"{s.virtual_size:,}", hex(s.raw_ptr),
             f"{s.raw_size:,}", s.permissions]
            for s in info.sections
        ]
        print(report.table(
            ["name", "virt addr", "virt size", "raw ptr", "raw size", "perms"], rows
        ))


def cmd_imports(args: argparse.Namespace) -> None:
    data = _load(args.file)
    kind, info = _parse_binary(data, args.file)
    if kind == "elf":
        if args.json:
            print(json.dumps(info.needed_libraries, indent=2))
            return
        print(report.heading("Needed libraries (DT_NEEDED)"))
        for lib in info.needed_libraries:
            print(f"  {lib}")
        if not info.needed_libraries:
            print("  (none - statically linked)")
        return

    if args.json:
        print(json.dumps(_to_jsonable(info.imports), indent=2))
        return
    print(report.heading(f"Imports ({len(info.imports)} DLLs)"))
    for dll in info.imports:
        print(f"\n  {dll.name}  ({len(dll.functions)} functions)")
        for fn in dll.functions[: args.limit]:
            print(f"    {fn}")
        if len(dll.functions) > args.limit:
            print(f"    ... and {len(dll.functions) - args.limit} more")


def cmd_exports(args: argparse.Namespace) -> None:
    data = _load(args.file)
    kind, info = _parse_binary(data, args.file)
    if kind != "pe":
        raise SystemExit("error: export tables are a PE concept; this is an ELF file")
    if args.json:
        print(json.dumps({"dll_name": info.export_dll_name, "exports": info.exports}, indent=2))
        return
    print(report.heading(f"Exports from {info.export_dll_name or args.file}"))
    for name in info.exports:
        print(f"  {name}")
    if not info.exports:
        print("  (no export table)")


def cmd_strings(args: argparse.Namespace) -> None:
    data = _load(args.file)
    found = strings_mod.extract_all(data, min_length=args.min_length)
    if args.json:
        print(json.dumps(_to_jsonable(found), indent=2))
        return
    print(report.heading(f"Strings (min length {args.min_length}, {len(found)} found)"))
    for s in found[: args.limit]:
        print(f"  {s.offset:#010x}  [{s.encoding:>9}]  {s.text}")
    if len(found) > args.limit:
        print(f"  ... and {len(found) - args.limit} more (use --limit to see more)")


def cmd_entropy(args: argparse.Namespace) -> None:
    data = _load(args.file)
    whole = entropy_mod.shannon_entropy(data)
    regions = []
    try:
        kind, info = _parse_binary(data, args.file)
        if kind == "elf":
            regions = [
                (s.name, data[s.sh_offset : s.sh_offset + s.sh_size])
                for s in info.sections
                if s.sh_type_name != "SHT_NOBITS"
            ]
        else:
            regions = [
                (s.name, data[s.raw_ptr : s.raw_ptr + s.raw_size]) for s in info.sections
            ]
    except SystemExit:
        pass  # unsupported/unknown format - whole-file entropy still works

    region_results = entropy_mod.analyze_regions(regions)
    if args.json:
        print(json.dumps({
            "whole_file": whole,
            "regions": _to_jsonable(region_results),
        }, indent=2))
        return

    print(report.heading("Entropy analysis"))
    flag = "  <- likely packed/compressed/encrypted" if whole >= entropy_mod.PACKED_THRESHOLD else ""
    print(f"  whole file : {whole:.3f} bits/byte{flag}")
    if region_results:
        rows = [
            [r.name, f"{r.entropy:.3f}", f"{r.size:,}", "yes" if r.likely_packed else ""]
            for r in region_results
        ]
        print()
        print(report.table(["region", "entropy", "size", "packed?"], rows))


def cmd_hash(args: argparse.Namespace) -> None:
    data = _load(args.file)
    h = hashes_mod.compute(data)
    if args.json:
        print(json.dumps(dataclasses.asdict(h), indent=2))
        return
    print(report.heading("Hashes"))
    print(report.kv_table([("MD5", h.md5), ("SHA1", h.sha1), ("SHA256", h.sha256)]))


def cmd_hexdump(args: argparse.Namespace) -> None:
    data = _load(args.file)
    print(hexdump_mod.format_hexdump(data, offset=args.offset, length=args.length))


def cmd_all(args: argparse.Namespace) -> None:
    args.limit = getattr(args, "limit", 20)
    args.min_length = getattr(args, "min_length", strings_mod.DEFAULT_MIN_LENGTH)
    args.offset = 0
    args.length = 256
    args.json = False

    cmd_identify(args)
    data_preview = _load(args.file)
    ident = identify_mod.identify(data_preview)
    if ident.supported:
        cmd_header(args)
        cmd_sections(args)
        cmd_imports(args)
        if ident.format == "pe":
            cmd_exports(args)
    else:
        print(f"\n(skipping header/sections/imports: unsupported format {ident.format!r})")
    cmd_entropy(args)
    cmd_hash(args)
    print(report.heading(f"Strings (first {args.limit}, min length {args.min_length})"))
    data = _load(args.file)
    found = strings_mod.extract_all(data, min_length=args.min_length)
    for s in found[: args.limit]:
        print(f"  {s.offset:#010x}  [{s.encoding:>9}]  {s.text}")
    print(report.heading(f"Hex dump (first {args.length} bytes)"))
    print(hexdump_mod.format_hexdump(data, offset=args.offset, length=args.length))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binspect",
        description="A from-scratch ELF/PE binary inspector for learning static analysis fundamentals.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("file", help="path to the binary to inspect")
        p.add_argument("--json", action="store_true", help="output machine-readable JSON")

    p = sub.add_parser("identify", help="identify the file format from magic bytes")
    add_common(p)
    p.set_defaults(func=cmd_identify)

    p = sub.add_parser("header", help="show the ELF/PE file header")
    add_common(p)
    p.set_defaults(func=cmd_header)

    p = sub.add_parser("sections", help="list sections")
    add_common(p)
    p.set_defaults(func=cmd_sections)

    p = sub.add_parser("imports", help="list imported libraries/functions")
    add_common(p)
    p.add_argument("--limit", type=int, default=20, help="max functions shown per DLL")
    p.set_defaults(func=cmd_imports)

    p = sub.add_parser("exports", help="list exported functions (PE only)")
    add_common(p)
    p.set_defaults(func=cmd_exports)

    p = sub.add_parser("strings", help="extract printable ASCII/UTF-16LE strings")
    add_common(p)
    p.add_argument("--min-length", type=int, default=strings_mod.DEFAULT_MIN_LENGTH)
    p.add_argument("--limit", type=int, default=100, help="max strings shown")
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("entropy", help="compute Shannon entropy (packing/encryption heuristic)")
    add_common(p)
    p.set_defaults(func=cmd_entropy)

    p = sub.add_parser("hash", help="compute MD5/SHA1/SHA256")
    add_common(p)
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("hexdump", help="hex + ASCII view of raw bytes")
    add_common(p)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--length", type=int, default=256)
    p.set_defaults(func=cmd_hexdump)

    p = sub.add_parser("all", help="run every analysis and print a full report")
    add_common(p)
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--min-length", type=int, default=strings_mod.DEFAULT_MIN_LENGTH)
    p.set_defaults(func=cmd_all)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except FileNotFoundError:
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
