#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Mint the ephemeral 3-channel test profile for the record3 lane.

Derives from the shipped narrow doc: keeps the qualified base
bindings (config/btf/format/object/image build the same
kernel the attempt lane qualifies), appends lc/cp object and
ring bindings from the current builds, adds the frozen
tracing hook sets, and flips both extra caps to supported.
Ring sizes are parsed from object BTF (VAR -> STRUCT member
max_entries -> PTR -> ARRAY nr_elems), never hardcoded.
Output is ignored scratch (build/vm/), never shipped; the
admission flip owns the shipped profile. `apply_tracing` is
the shared transform the gate emitter reuses, so the flip
cannot drift from this mint.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DOC = ROOT / "profiles" / "linux-x86_64-7.0.0-34-generic.json"
LC_OBJ = ROOT / "build" / "bpf" / "swiotlb_lifecycle.bpf.o"
CP_OBJ = ROOT / "build" / "bpf" / "swiotlb_copy.bpf.o"
OUT = ROOT / "build" / "vm" / "record3-profile.json"

KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_VAR = 14

TRACE_HOOKS = [
    ("fexit:swiotlb_tbl_map_single", "swiotlb_tbl_map_single",
     "fexit",
     "phys_addr_t swiotlb_tbl_map_single(struct device *dev,"
     " phys_addr_t orig_addr, size_t mapping_size,"
     " unsigned int alloc_align_mask,"
     " enum dma_data_direction dir, unsigned long attrs)"),
    ("fentry:__swiotlb_tbl_unmap_single",
     "__swiotlb_tbl_unmap_single", "fentry",
     "void __swiotlb_tbl_unmap_single(struct device *dev,"
     " phys_addr_t tlb_addr, size_t mapping_size,"
     " enum dma_data_direction dir, unsigned long attrs,"
     " struct io_tlb_pool *pool)"),
    ("fentry:__swiotlb_sync_single_for_device",
     "__swiotlb_sync_single_for_device", "fentry",
     "void __swiotlb_sync_single_for_device(struct device *dev,"
     " phys_addr_t tlb_addr, size_t size,"
     " enum dma_data_direction dir, struct io_tlb_pool *pool)"),
    ("fentry:__swiotlb_sync_single_for_cpu",
     "__swiotlb_sync_single_for_cpu", "fentry",
     "void __swiotlb_sync_single_for_cpu(struct device *dev,"
     " phys_addr_t tlb_addr, size_t size,"
     " enum dma_data_direction dir, struct io_tlb_pool *pool)"),
    ("fentry:swiotlb_bounce", "swiotlb_bounce", "fentry",
     "void swiotlb_bounce(struct device *dev,"
     " phys_addr_t tlb_addr, size_t size,"
     " enum dma_data_direction dir, struct io_tlb_pool *mem)"),
]
LC_HOOK_NAMES = [TRACE_HOOKS[0][0], TRACE_HOOKS[1][0]]
CP_HOOK_NAMES = [TRACE_HOOKS[2][0], TRACE_HOOKS[3][0],
                 TRACE_HOOKS[4][0]]


def fail(msg):
    print("mint_record3_profile: FAIL: %s" % msg,
          file=sys.stderr)
    raise SystemExit(1)


def elf_section(data, want):
    shoff, = struct.unpack("<Q", data[0x28:0x30])
    shentsize, = struct.unpack("<H", data[0x3A:0x3C])
    shnum, = struct.unpack("<H", data[0x3C:0x3E])
    shstrndx, = struct.unpack("<H", data[0x3E:0x40])
    if shentsize != 64 or shnum == 0 or shstrndx >= shnum:
        fail("bad ELF section table")
    def sec(i):
        return struct.unpack(
            "<IIQQQQIIQQ",
            data[shoff + i * 64:shoff + (i + 1) * 64])
    s = sec(shstrndx)
    strings = data[s[4]:s[4] + s[5]]
    for i in range(shnum):
        s = sec(i)
        name = strings[s[0]:].split(b"\0")[0].decode()
        if name == want:
            return data[s[4]:s[4] + s[5]]
    fail("missing %s section" % want)


def btf_ring_bytes(obj_path, var_name):
    """Parse one ringbuf max_entries from object BTF."""
    data = Path(obj_path).read_bytes()
    sec = elf_section(data, ".BTF")
    magic, ver, flags, hdr_len = struct.unpack("<HBBI", sec[:8])
    if magic != 0xEB9F or ver != 1 or hdr_len < 24:
        fail("%s: bad BTF header" % obj_path)
    type_off, type_len, str_off, str_len = struct.unpack(
        "<IIII", sec[8:24])
    types = sec[hdr_len + type_off:hdr_len + type_off + type_len]
    strings = sec[hdr_len + str_off:hdr_len + str_off + str_len]

    def name(off):
        if off >= len(strings):
            fail("%s: BTF strings corrupt" % obj_path)
        return strings[off:].split(b"\0")[0].decode()

    recs = []
    pos = 0
    while pos < len(types):
        if pos + 12 > len(types):
            fail("%s: truncated BTF" % obj_path)
        name_off, info, size = struct.unpack(
            "<III", types[pos:pos + 12])
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        body = types[pos + 12:]
        recs.append((name_off, kind, vlen, size, body))
        if kind == 1:
            pos += 12 + 4
        elif kind == KIND_VAR:
            pos += 12 + 4
        elif kind in (KIND_STRUCT, 5, 7, 10, 12):
            pos += 12 + vlen * 12
        elif kind in (6, 13):
            pos += 12 + vlen * 8
        elif kind == 19:
            pos += 12 + vlen * 12
        elif kind == KIND_ARRAY:
            pos += 12 + 12
        else:
            pos += 12
    if pos != len(types):
        fail("%s: BTF walk did not consume exact types"
             % obj_path)
    found = [i for i, r in enumerate(recs)
             if r[1] == KIND_VAR and name(r[0]) == var_name]
    if len(found) != 1:
        fail("%s: want 1 %s var, got %d"
             % (obj_path, var_name, len(found)))
    struct_id = recs[found[0]][3]
    if struct_id < 1 or struct_id > len(recs):
        fail("%s: bad %s type" % (obj_path, var_name))
    struct_rec = recs[struct_id - 1]
    if struct_rec[1] != KIND_STRUCT:
        fail("%s: %s not a struct" % (obj_path, var_name))
    target = None
    for m in range(struct_rec[2]):
        name_off, mtype = struct.unpack(
            "<II", struct_rec[4][m * 12:m * 12 + 8])
        if name(name_off) == "max_entries":
            if target is not None:
                fail("%s: duplicate max_entries" % obj_path)
            target = mtype
    if target is None or target < 1 or target > len(recs):
        fail("%s: missing max_entries" % obj_path)
    ptr = recs[target - 1]
    if ptr[1] != KIND_PTR:
        fail("%s: max_entries not a pointer" % obj_path)
    arr_id = ptr[3]
    if arr_id < 1 or arr_id > len(recs):
        fail("%s: bad max_entries target" % obj_path)
    arr = recs[arr_id - 1]
    if arr[1] != KIND_ARRAY:
        fail("%s: max_entries not an array" % obj_path)
    _etype, _itype, nr = struct.unpack("<III", arr[4][:12])
    if nr < 4096 or nr > 2147483648 or nr & (nr - 1):
        fail("%s: ring size %d rejected" % (obj_path, nr))
    return nr


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def frozen_scan_hooks():
    """The F2-2 frozen tracing set from the scan fixture."""
    path = (ROOT / "tests" / "fixtures" / "scan" / "profiles"
            / "valid-lc.json")
    doc = json.loads(path.read_text())
    return [(h["name"], h["function"], h["attach"],
             h["signature"]) for h in doc["hooks"]
            if h["kind"] == "tracing"]


BASE_FIELDS = ("config=", "config_src=", "btf=", "format=",
               "object=", "image=", "image_bid=",
               "ring_bytes=")
TRACE_FIELDS = ("lc_object=", "lc_ring_bytes=", "cp_object=",
                "cp_ring_bytes=")


def apply_tracing(doc, lc_obj, cp_obj, lc_reason,
                  cp_reason, hook_note):
    """Bind tracing caps onto a profile doc, in place.

    The single implementation of the tracing transform,
    shared by the record3 minter and the gate emitter: the
    frozen hook set (cross-checked against the scan
    fixture), fresh lc/cp object and ring bindings parsed
    from the current builds, and both extra caps flipped to
    supported. Accepts a pre-flip 8-field base note or a
    post-flip 12-field note (base verified, tracing fields
    rebuilt); hooks append idempotently. Warns when shipped
    tracing pins differ from the current builds.
    """
    if TRACE_HOOKS != frozen_scan_hooks():
        fail("minter tracing set drifts from scan fixture")
    shipped_note = doc["identity"]["source"]["note"]
    fields = shipped_note.split()
    had_tracing = (len(fields) == 12
                   and all(f.startswith(p) for f, p in
                           zip(fields[8:], TRACE_FIELDS)))
    if had_tracing:
        fields = fields[:8]
    if (len(fields) != 8
            or not all(f.startswith(p) for f, p in
                       zip(fields, BASE_FIELDS))):
        fail("shipped note is not the 8-field base")
    base = " ".join(fields)
    lc_obj = str(lc_obj)
    cp_obj = str(cp_obj)
    lc_ring = btf_ring_bytes(lc_obj, "mv_lifecycle")
    cp_ring = btf_ring_bytes(cp_obj, "mv_copies")
    note = base + (" lc_object=sha256:%s lc_ring_bytes=%d"
                   " cp_object=sha256:%s cp_ring_bytes=%d"
                   % (sha(lc_obj), lc_ring, sha(cp_obj),
                      cp_ring))
    if len(note) > 700:
        fail("note exceeds 700")
    if had_tracing and note != shipped_note:
        print("mint: shipped tracing pins differ from "
              "current builds; ephemeral doc rebuilt",
              file=sys.stderr)
    doc["identity"]["source"]["note"] = note
    have = {h["name"] for h in doc["hooks"]}
    for name, function, attach, signature in TRACE_HOOKS:
        if name in have:
            continue
        doc["hooks"].append({"name": name, "kind": "tracing",
                             "function": function,
                             "attach": attach,
                             "signature": signature,
                             "note": hook_note})
    for cap in doc["capabilities"]:
        if cap["id"] == "mapping-lifecycle":
            cap["status"] = "supported"
            cap["hooks"] = list(LC_HOOK_NAMES)
            cap["reason"] = lc_reason
        if cap["id"] == "copy-actual":
            cap["status"] = "supported"
            cap["hooks"] = list(CP_HOOK_NAMES)
            cap["reason"] = cp_reason
    return doc


def main():
    doc = json.loads(DOC.read_text())
    if doc.get("schema_version") != "0.1.1":
        fail("shipped doc is not profile 0.1.1")
    attempt = [c for c in doc["capabilities"]
               if c["id"] == "attempt-trace"]
    if len(attempt) != 1 or attempt[0]["status"] != "supported":
        fail("shipped doc lacks supported attempt-trace")
    apply_tracing(
        doc, LC_OBJ, CP_OBJ,
        "Record3 lane only: ephemeral 3-channel wiring proof.",
        "Record3 lane only: ephemeral 3-channel wiring proof.",
        "Record3 test hook.")
    doc["profile_id"] = "record3-ephemeral"
    doc["status"] = "reference-unvalidated"
    out = OUT
    args = sys.argv[1:]
    if args[:1] == ["--out"]:
        if len(args) != 2:
            fail("--out needs a value")
        out = Path(args[1])
    elif args:
        fail("usage: mint_record3_profile.py [--out PATH]")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print("minted %s" % out)


if __name__ == "__main__":
    main()
