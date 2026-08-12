import json

from binspect.cli import main


def test_identify_json(minimal_elf_bytes, tmp_path, capsys):
    f = tmp_path / "sample.bin"
    f.write_bytes(minimal_elf_bytes)
    rc = main(["identify", str(f), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["format"] == "elf"


def test_header_text_output(minimal_pe_bytes, tmp_path, capsys):
    f = tmp_path / "sample.exe"
    f.write_bytes(minimal_pe_bytes)
    rc = main(["header", str(f)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PE32+" in out


def test_all_command_runs_end_to_end(dynamic_elf_bytes, tmp_path, capsys):
    f = tmp_path / "sample.elf"
    f.write_bytes(dynamic_elf_bytes)
    rc = main(["all", str(f)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "libfake.so.1" in out
    assert "Hex dump" in out


def test_missing_file_reports_error(capsys):
    rc = main(["identify", "does-not-exist.bin"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not found" in err


def test_hash_json_has_three_digests(minimal_pe_bytes, tmp_path, capsys):
    f = tmp_path / "sample.exe"
    f.write_bytes(minimal_pe_bytes)
    main(["hash", str(f), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert set(out.keys()) == {"md5", "sha1", "sha256"}
