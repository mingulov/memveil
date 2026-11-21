#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-side tests for the record3 minter transform.

apply_tracing is shared by the record3 lane and the gate
emitter: pre-flip docs gain the frozen tracing set, post-flip
docs verify their base and rebuild tracing from current
builds, and drift warns. Classic-lane tests need the built
BPF objects and skip honestly without them; the flat-lane
tests use committed toolchain objects and always run.
"""
import copy
import hashlib
import json
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_record3_profile as m

NEED_BUILDS = pytest.mark.skipif(
    not (os.path.isfile(m.LC_OBJ) and os.path.isfile(m.CP_OBJ)),
    reason="needs built lifecycle/copy objects")

# Committed toolchain objects: real compiler output with
# remapped debug paths, so the flat lane is covered without
# a build tree.
AYA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "aya")
AYA_ATTEMPT = os.path.join(AYA_DIR, "swiotlb_attempt.bpf.o")
AYA_LC = os.path.join(AYA_DIR, "swiotlb_lifecycle.bpf.o")
AYA_CP = os.path.join(AYA_DIR, "swiotlb_copy.bpf.o")
AYA_RING = 33554432


NARROW_TEST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "fixtures",
    "capabilities", "profiles-narrow-test",
    "test-narrow-validated.json")


def shipped():
    return json.loads(open(NARROW_TEST).read())


def strip_to_preflip(doc):
    doc = copy.deepcopy(doc)
    doc["hooks"] = [h for h in doc["hooks"]
                    if h["kind"] != "tracing"]
    doc["identity"]["source"]["note"] = " ".join(
        doc["identity"]["source"]["note"].split()[:8])
    for cap in doc["capabilities"]:
        if cap["id"] in ("mapping-lifecycle", "copy-actual"):
            cap["status"] = "unsupported"
            cap["hooks"] = []
            cap["reason"] = "x"
    return doc


@NEED_BUILDS
def test_preflip_gains_frozen_tracing():
    out = m.apply_tracing(strip_to_preflip(shipped()),
                          m.LC_OBJ, m.CP_OBJ, "lr", "cr", "n")
    names = [h["name"] for h in out["hooks"]
             if h["kind"] == "tracing"]
    assert names == [t[0] for t in m.TRACE_HOOKS]
    fields = out["identity"]["source"]["note"].split()
    assert len(fields) == 12
    assert fields[8].startswith("lc_object=sha256:")
    caps = {c["id"]: c for c in out["capabilities"]}
    assert caps["mapping-lifecycle"]["status"] == "supported"
    assert caps["mapping-lifecycle"]["reason"] == "lr"
    assert caps["copy-actual"]["hooks"] == list(m.CP_HOOK_NAMES)


@NEED_BUILDS
def test_postflip_idempotent():
    once = m.apply_tracing(shipped(), m.LC_OBJ, m.CP_OBJ,
                           "lr", "cr", "n")
    twice = m.apply_tracing(copy.deepcopy(once), m.LC_OBJ,
                            m.CP_OBJ, "lr", "cr", "n")
    assert twice == once


@NEED_BUILDS
def test_tracing_matches_fresh_mint():
    fresh = m.apply_tracing(strip_to_preflip(shipped()),
                            m.LC_OBJ, m.CP_OBJ, "lr", "cr",
                            "n")
    kept = m.apply_tracing(shipped(), m.LC_OBJ, m.CP_OBJ,
                           "lr", "cr", "n")
    assert kept["identity"] == fresh["identity"]
    assert kept["capabilities"] == fresh["capabilities"]

    def tracing(doc):
        return [(h["name"], h["kind"], h["function"],
                 h["attach"], h["signature"])
                for h in doc["hooks"]
                if h["kind"] == "tracing"]

    assert tracing(kept) == tracing(fresh)


@NEED_BUILDS
@pytest.mark.parametrize("note", [
    # Shape only: values are the live gate's job, so a
    # well-formed note with wrong values still mints.
    "a b c d e f g",
    "config=x config_src=y btf=z format=w object=v image=u "
    "image_bid=t",
    "config=x config_src=y btf=z format=w object=v image=u "
    "image_bid=t ring_bytes=1 lc_object=q lc_ring_bytes=1 "
    "cp_object=e",
    "config=x config_src=y btf=z format=w object=v image=u "
    "image_bid=t ring_bytes=1 WRONG=1 lc_ring_bytes=1 "
    "cp_object=1 cp_ring_bytes=1",
    " ".join("f%d" % i for i in range(13)),
])
def test_malformed_notes_refused(note):
    doc = shipped()
    doc["identity"]["source"]["note"] = note
    with pytest.raises(SystemExit):
        m.apply_tracing(doc, m.LC_OBJ, m.CP_OBJ,
                        "lr", "cr", "n")


@NEED_BUILDS
def test_drift_warns_and_rebuilds(capsys):
    doc = shipped()
    fields = doc["identity"]["source"]["note"].split()
    assert len(fields) == 12
    fields[9] = "lc_ring_bytes=4096"
    doc["identity"]["source"]["note"] = " ".join(fields)
    out = m.apply_tracing(doc, m.LC_OBJ, m.CP_OBJ,
                          "lr", "cr", "n")
    assert "differ from current builds" in capsys.readouterr().err
    rebuilt = out["identity"]["source"]["note"].split()
    assert rebuilt[9] != "lc_ring_bytes=4096"
    assert rebuilt[9].startswith("lc_ring_bytes=")


@NEED_BUILDS
def test_steady_state_silent(capsys):
    # Converge first: rebuilt trees (like CI) legitimately
    # differ from shipped pins, so silence holds only after
    # the transform rebuilds to the current builds.
    doc = shipped()
    fields = doc["identity"]["source"]["note"].split()
    assert len(fields) == 12
    fields[9] = "lc_ring_bytes=4096"
    doc["identity"]["source"]["note"] = " ".join(fields)
    converged = m.apply_tracing(doc, m.LC_OBJ, m.CP_OBJ,
                                "lr", "cr", "n")
    assert "differ from current builds" in capsys.readouterr().err
    m.apply_tracing(converged, m.LC_OBJ, m.CP_OBJ,
                    "lr", "cr", "n")
    assert capsys.readouterr().err == ""


@NEED_BUILDS
@pytest.mark.parametrize("field,value", [
    ("signature", "u64 f(void)"),
    ("function", "other_fn"),
    ("attach", "fentry"),
    ("kind", "tracepoint"),
])
def test_kept_hook_drift_refused(field, value):
    doc = shipped()
    for h in doc["hooks"]:
        if h["name"] == m.TRACE_HOOKS[0][0]:
            h[field] = value
    with pytest.raises(SystemExit):
        m.apply_tracing(doc, m.LC_OBJ, m.CP_OBJ,
                        "lr", "cr", "n")


def test_main_requires_explicit_base(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mint_record3_profile.py"])
    with pytest.raises(SystemExit) as exc:
        m.main()
    assert exc.value.code == 1
    assert "--base DOC" in capsys.readouterr().err


def test_main_object_flags_override_dev_defaults(
        tmp_path, monkeypatch):
    out = tmp_path / "profile.json"
    monkeypatch.setattr(sys, "argv", [
        "mint_record3_profile.py", "--base", NARROW_TEST,
        "--out", str(out), "--lc", "/nonexistent-lc.o",
        "--cp", "/nonexistent-cp.o"])
    with pytest.raises(FileNotFoundError) as exc:
        m.main()
    assert "nonexistent-lc" in str(exc.value)


@NEED_BUILDS
def test_main_object_flags_mint_from_named_objects(
        tmp_path, monkeypatch):
    out = tmp_path / "profile.json"
    monkeypatch.setattr(sys, "argv", [
        "mint_record3_profile.py", "--base", NARROW_TEST,
        "--out", str(out), "--lc", str(m.LC_OBJ),
        "--cp", str(m.CP_OBJ)])
    m.main()
    doc = json.loads(out.read_text())
    assert doc["profile_id"] == "record3-ephemeral"
    assert doc["status"] == "reference-unvalidated"


def test_committed_toolchain_objects_cover_the_flat_lane():
    """The committed objects parse on the flat lane.

    No build tree: both ring VARs are listed in DATASEC
    `maps` and parse to the same 32 MiB the loading path
    admits, so this test runs wherever the checkout runs.
    """
    for obj, var in ((AYA_LC, "mv_lifecycle"),
                     (AYA_CP, "mv_copies")):
        data = open(obj, "rb").read()
        recs, strings = m.btf_records(obj, data)
        var_id = [i for i, r in enumerate(recs)
                  if r[1] == m.KIND_VAR
                  and m.btf_name(obj, strings, r[0]) == var]
        assert len(var_id) == 1
        members = m.maps_datasec_members(obj, recs, strings)
        assert members is not None
        assert var_id[0] + 1 in [
            tid for tid, _off, _size in members]
        assert m.btf_ring_bytes(obj, var) == AYA_RING


def test_main_mints_from_committed_toolchain_objects(
        tmp_path, monkeypatch):
    """A full mint off committed objects, without a build tree."""
    out = tmp_path / "profile.json"
    monkeypatch.setattr(sys, "argv", [
        "mint_record3_profile.py", "--base", NARROW_TEST,
        "--out", str(out), "--lc", AYA_LC, "--cp", AYA_CP])
    m.main()
    doc = json.loads(out.read_text())
    assert doc["profile_id"] == "record3-ephemeral"
    assert doc["status"] == "reference-unvalidated"
    note = dict(part.split("=", 1) for part in
                doc["identity"]["source"]["note"].split())
    assert note["lc_ring_bytes"] == str(AYA_RING)
    assert note["cp_ring_bytes"] == str(AYA_RING)
    assert note["lc_object"] == "sha256:" + hashlib.sha256(
        open(AYA_LC, "rb").read()).hexdigest()
    assert note["cp_object"] == "sha256:" + hashlib.sha256(
        open(AYA_CP, "rb").read()).hexdigest()


def _section_headers(data):
    shoff, = struct.unpack("<Q", data[0x28:0x30])
    shnum, = struct.unpack("<H", data[0x3C:0x3E])
    shstrndx, = struct.unpack("<H", data[0x3E:0x40])
    head = struct.unpack(
        "<IIQQQQIIQQ",
        data[shoff + shstrndx * 64:shoff + (shstrndx + 1)
             * 64])
    strings = data[head[4]:head[4] + head[5]]
    out = {}
    for i in range(shnum):
        head = struct.unpack(
            "<IIQQQQIIQQ",
            data[shoff + i * 64:shoff + (i + 1) * 64])
        name = strings[head[0]:].split(b"\0")[0].decode()
        out[name] = (shoff + i * 64, head[4], head[5])
    return out


def _copy_with(obj, tmp_path, name, edits):
    """Committed object bytes with (offset, patch) edits applied."""
    data = bytearray(open(obj, "rb").read())
    for at, patch in edits:
        data[at:at + len(patch)] = patch
    out = tmp_path / name
    out.write_bytes(bytes(data))
    return str(out)


def _ring_entry_offset(obj, var):
    """File offset of one flat ring definition entry."""
    data = open(obj, "rb").read()
    recs, strings = m.btf_records(obj, data)
    var_id = [i for i, r in enumerate(recs)
              if r[1] == m.KIND_VAR
              and m.btf_name(obj, strings, r[0]) == var][0]
    members = m.maps_datasec_members(obj, recs, strings)
    index = [tid for tid, _off, _size in members].index(
        var_id + 1)
    _head, at, _size = _section_headers(data)["maps"]
    return at + index * m.AYA_MAP_DEF_BYTES


def _btf_record_offset(obj, index):
    """File offset of one BTF type record header."""
    data = open(obj, "rb").read()
    _head, at, _size = _section_headers(data)[".BTF"]
    sec = data[at:]
    _magic, _ver, _flags, hdr_len = struct.unpack(
        "<HBBI", sec[:8])
    type_off, _type_len, _str_off, _str_len = struct.unpack(
        "<IIII", sec[8:24])
    base = at + hdr_len + type_off
    recs = []
    pos = 0
    while True:
        _name_off, info, _size = struct.unpack(
            "<III", sec[hdr_len + type_off + pos:
                        hdr_len + type_off + pos + 12])
        recs.append(base + pos)
        if len(recs) > index:
            return recs[index]
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        if kind in (1, m.KIND_VAR, 17):
            pos += 12 + 4
        elif kind in (m.KIND_STRUCT, 5, m.KIND_DATASEC, 19):
            pos += 12 + vlen * 12
        elif kind in (6, 13):
            pos += 12 + vlen * 8
        elif kind == m.KIND_ARRAY:
            pos += 12 + 12
        else:
            pos += 12


def test_flat_lane_refuses_foreign_map_type(tmp_path, capsys):
    entry = _ring_entry_offset(AYA_LC, "mv_lifecycle")
    obj = _copy_with(AYA_LC, tmp_path, "lc.o",
                     [(entry, struct.pack("<I", 2))])
    with pytest.raises(SystemExit) as exc:
        m.btf_ring_bytes(obj, "mv_lifecycle")
    assert exc.value.code == 1
    assert "mv_lifecycle type 2, want 27" in \
        capsys.readouterr().err


def test_flat_lane_refuses_unsized_ring(tmp_path, capsys):
    entry = _ring_entry_offset(AYA_CP, "mv_copies")
    obj = _copy_with(AYA_CP, tmp_path, "cp.o",
                     [(entry + 12, struct.pack("<I", 1000))])
    with pytest.raises(SystemExit) as exc:
        m.btf_ring_bytes(obj, "mv_copies")
    assert exc.value.code == 1
    assert "mv_copies ring size 1000 rejected" in \
        capsys.readouterr().err


def test_flat_lane_refuses_truncated_definitions(
        tmp_path, capsys):
    data = open(AYA_LC, "rb").read()
    head, _at, _size = _section_headers(data)["maps"]
    obj = _copy_with(AYA_LC, tmp_path, "lc.o",
                     [(head + 32, struct.pack("<Q", 0))])
    with pytest.raises(SystemExit) as exc:
        m.btf_ring_bytes(obj, "mv_lifecycle")
    assert exc.value.code == 1
    assert "mv_lifecycle bad aya map shape" in \
        capsys.readouterr().err


def test_flat_lane_refuses_ragged_member_list(
        tmp_path, capsys):
    data = open(AYA_CP, "rb").read()
    recs, strings = m.btf_records(AYA_CP, data)
    datasec = [i for i, r in enumerate(recs)
               if r[1] == m.KIND_DATASEC
               and m.btf_name(AYA_CP, strings, r[0])
               == "maps"][0]
    at = _btf_record_offset(AYA_CP, datasec)
    obj = _copy_with(AYA_CP, tmp_path, "cp.o",
                     [(at + 12 + 8, struct.pack("<I", 16))])
    with pytest.raises(SystemExit) as exc:
        m.btf_ring_bytes(obj, "mv_copies")
    assert exc.value.code == 1
    assert "bad maps DATASEC" in capsys.readouterr().err


def test_flat_lane_refuses_foreign_linkage(tmp_path, capsys):
    data = open(AYA_LC, "rb").read()
    recs, strings = m.btf_records(AYA_LC, data)
    var = [i for i, r in enumerate(recs)
           if r[1] == m.KIND_VAR
           and m.btf_name(AYA_LC, strings, r[0])
           == "mv_lifecycle"][0]
    at = _btf_record_offset(AYA_LC, var)
    obj = _copy_with(AYA_LC, tmp_path, "lc.o",
                     [(at + 12, struct.pack("<I", 5))])
    with pytest.raises(SystemExit) as exc:
        m.btf_ring_bytes(obj, "mv_lifecycle")
    assert exc.value.code == 1
    assert "mv_lifecycle linkage 5" in capsys.readouterr().err
