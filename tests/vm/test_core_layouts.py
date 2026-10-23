# SPDX-License-Identifier: GPL-3.0-or-later
"""CO-RE layout extraction from object relocations and its equality gate.

The extractor reads an object's .BTF/.BTF.ext core relocations and
emits profile-schema 0.1.2 layout items; --check gates that a profile
carries exactly the extracted set. Oracles: the five bpf_core_read
sites in bpf/programs/swiotlb_copy.bpf.c, the local types in
bpf/include/mv_fentry_types.h, and the relo_kinds.bpf.c source.
"""
import json
import struct
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "emit-core-layouts"
FIXTURES = REPO / "tests" / "fixtures"
ELF = FIXTURES / "elf"
CP_OK = ELF / "cp-ok.o"
OK = ELF / "ok.o"
LC_OK = ELF / "lc-ok.o"
RELO = FIXTURES / "core" / "relo_kinds.bpf.o"
CORE_DIR = FIXTURES / "scan" / "profiles-core"
CORE_REF = CORE_DIR / "core-ref.json"
LIVE_REF = FIXTURES / "scan" / "profiles-live" / "live-ref.json"

EXPECTED_CP = [
    {"capability": "copy-actual", "target": "field",
     "struct": "device", "field": "dma_parms",
     "type_kind": "ptr", "bit_size": 64, "optional": False},
    {"capability": "copy-actual", "target": "field",
     "struct": "device_dma_parameters", "field": "min_align_mask",
     "type_kind": "int", "bit_size": 32, "optional": False},
    {"capability": "copy-actual", "target": "field",
     "struct": "io_tlb_pool", "field": "nslabs",
     "type_kind": "int", "bit_size": 64, "optional": False},
    {"capability": "copy-actual", "target": "field",
     "struct": "io_tlb_pool", "field": "slots",
     "type_kind": "ptr", "bit_size": 64, "optional": False},
    {"capability": "copy-actual", "target": "field",
     "struct": "io_tlb_pool", "field": "start",
     "type_kind": "int", "bit_size": 64, "optional": False},
]

EXPECTED_KINDS = [
    {"capability": "copy-actual", "target": "enumerator",
     "struct": "mvt_hue", "field": "MVT_GREEN",
     "type_kind": "enum", "bit_size": 32, "optional": False},
    {"capability": "copy-actual", "target": "enumerator",
     "struct": "mvt_hue", "field": "MVT_RED",
     "type_kind": "enum", "bit_size": 32, "optional": False},
    {"capability": "copy-actual", "target": "field",
     "struct": "mvt_relo", "field": "f_opt",
     "type_kind": "int", "bit_size": 16, "optional": True},
    {"capability": "copy-actual", "target": "field",
     "struct": "mvt_relo", "field": "f_read",
     "type_kind": "int", "bit_size": 64, "optional": False},
    {"capability": "copy-actual", "target": "field",
     "struct": "mvt_relo", "field": "f_size",
     "type_kind": "int", "bit_size": 32, "optional": False},
    {"capability": "copy-actual", "target": "type",
     "struct": "mvt_sized",
     "type_kind": "struct", "bit_size": 128, "optional": False},
]


def _run(*args):
    return subprocess.run([str(TOOL)] + [str(a) for a in args],
                          capture_output=True, text=True)


def _print(*objects):
    proc = _run(*objects, "--print")
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    return json.loads(proc.stdout)


def _patch_relo_kind(data, to_kind, from_kind=None):
    """Copy an object with one core_relo kind byte rewritten.

    Minimal independent ELF/.BTF.ext walk to the first record
    (or the first record of from_kind); returns patched bytes.
    """
    assert data[:4] == b"\x7fELF"
    assert data[4] == 2 and data[5] == 1  # 64-bit LE
    shoff, = struct.unpack("<Q", data[0x28:0x30])
    shentsize, shnum, shstrndx = struct.unpack("<HHH", data[0x3A:0x40])
    assert shentsize == 64 and shnum > 0
    headers = []
    for i in range(shnum):
        off = shoff + i * 64
        name, _, _, _, sec_off, size = struct.unpack(
            "<IIQQQQ", data[off:off + 40])
        headers.append((name, sec_off, size))
    sname, soff, ssize = headers[shstrndx]
    strtab = data[soff:soff + ssize]

    def sec_name(off):
        return strtab[off:strtab.index(b"\x00", off)].decode()

    ext_off = ext_size = None
    for name, sec_off, size in headers:
        if sec_name(name) == ".BTF.ext":
            ext_off, ext_size = sec_off, size
    assert ext_off is not None
    ext = data[ext_off:ext_off + ext_size]
    magic, ver, _, hdrlen = struct.unpack("<HBBI", ext[:8])
    assert magic == 0xEB9F and ver == 1
    c_off, c_len = struct.unpack("<II", ext[24:32])
    base = hdrlen + c_off
    recsize, = struct.unpack("<I", ext[base:base + 4])
    assert recsize >= 16
    patched = bytearray(data)
    pos = base + 4
    end = base + c_len
    while pos < end:
        _, num = struct.unpack("<II", ext[pos:pos + 8])
        pos += 8
        for _ in range(num):
            rec = ext_off + pos
            kind, = struct.unpack("<I", data[rec + 12:rec + 16])
            if from_kind is None or kind == from_kind:
                patched[rec + 12:rec + 16] = struct.pack("<I", to_kind)
                return bytes(patched)
            pos += recsize
    raise AssertionError("no patchable record")


def test_extract_current_copy_object():
    assert _print("--object", "copy-actual=%s" % CP_OK) == EXPECTED_CP


def test_extract_no_core_objects():
    assert _print("--object", "attempt-trace=%s" % OK) == []
    assert _print("--object", "mapping-lifecycle=%s" % LC_OK) == []


def test_unrelocated_lists_slot():
    proc = _run("--object", "copy-actual=%s" % CP_OK,
                "--print", "--unrelocated")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == EXPECTED_CP
    assert proc.stderr == ("unrelocated: io_tlb_slot\n"
                           "unrelocated: mv_claim\n")


def test_extract_all_kinds():
    assert _print("--object", "copy-actual=%s" % RELO) == EXPECTED_KINDS


def test_bitfield_record_refused(tmp_path):
    for kind in (4, 5):
        patched = tmp_path / ("relo-%d.o" % kind)
        patched.write_bytes(_patch_relo_kind(RELO.read_bytes(), kind))
        proc = _run("--object", "copy-actual=%s" % patched, "--print")
        assert proc.returncode == 1
        assert proc.stderr == ("bitfield relocation in mvt_relo.f_read"
                               " unsupported\n")


def test_check_gate(tmp_path):
    doc = json.loads(CORE_REF.read_text())
    assert doc["schema_version"] == "0.1.2"
    assert doc["layouts"] == EXPECTED_CP
    gate = ["--object", "attempt-trace=%s" % OK,
            "--object", "mapping-lifecycle=%s" % LC_OK,
            "--object", "copy-actual=%s" % CP_OK]
    proc = _run(*gate, "--check", str(CORE_REF))
    assert proc.returncode == 0, proc.stderr
    missing = tmp_path / "missing.json"
    doc["layouts"] = doc["layouts"][1:]
    missing.write_text(json.dumps(doc))
    proc = _run(*gate, "--check", str(missing))
    assert proc.returncode == 1
    assert "dma_parms" in proc.stderr
    assert "missing:" in proc.stderr
    extra = tmp_path / "extra.json"
    doc["layouts"].append(dict(EXPECTED_CP[0], field="nope"))
    extra.write_text(json.dumps(doc))
    proc = _run(*gate, "--check", str(extra))
    assert proc.returncode == 1
    assert "extra:" in proc.stderr


def test_write_roundtrip(tmp_path):
    gate = ["--object", "attempt-trace=%s" % OK,
            "--object", "mapping-lifecycle=%s" % LC_OK,
            "--object", "copy-actual=%s" % CP_OK]
    first = tmp_path / "first.json"
    first.write_text(LIVE_REF.read_text())
    proc = _run(*gate, "--write", str(first))
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(first.read_text())
    assert doc["schema_version"] == "0.1.2"
    assert doc["layouts"] == EXPECTED_CP
    before = first.read_bytes()
    assert before.endswith(b"\n")
    proc = _run(*gate, "--write", str(first))
    assert proc.returncode == 0, proc.stderr
    assert first.read_bytes() == before


def test_type_id_ignored(tmp_path):
    for kind, word in ((6, "TYPE_ID_LOCAL"), (7, "TYPE_ID_TARGET")):
        patched = tmp_path / ("typeid-%d.o" % kind)
        patched.write_bytes(_patch_relo_kind(CP_OK.read_bytes(), kind))
        proc = _run("--object", "copy-actual=%s" % patched, "--print")
        assert proc.returncode == 0, proc.stderr
        assert word in proc.stderr
        assert "io_tlb_pool" in proc.stderr
        assert json.loads(proc.stdout) == EXPECTED_CP


def test_signed_maps_to_field(tmp_path):
    patched = tmp_path / "signed.o"
    patched.write_bytes(_patch_relo_kind(CP_OK.read_bytes(), 3))
    proc = _run("--object", "copy-actual=%s" % patched, "--print")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == EXPECTED_CP


def test_matches_maps_to_type(tmp_path):
    patched = tmp_path / "matches.o"
    patched.write_bytes(
        _patch_relo_kind(RELO.read_bytes(), 12, from_kind=8))
    proc = _run("--object", "copy-actual=%s" % patched, "--print")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == EXPECTED_KINDS


def test_usage_errors():
    assert _run().returncode == 2
    proc = _run("--object", "copy-actual=/nonexistent.o", "--print")
    assert proc.returncode == 2
    proc = _run("--object", "noequalsign", "--print")
    assert proc.returncode == 2


def test_fixture_matches_source():
    proc = subprocess.run([str(REPO / "tools" / "emit-core-fixtures"),
                           "--check"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
