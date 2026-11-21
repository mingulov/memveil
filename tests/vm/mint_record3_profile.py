#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Mint the ephemeral 3-channel test profile for the record3 lane.

Derives from an explicit --base doc: keeps its base
bindings (config/btf/format/object/image build the same
kernel the attempt lane qualifies), appends lc/cp object and
ring bindings from the current builds (or the --lc/--cp
objects a sealed leg names), adds the frozen
tracing hook sets, and flips both extra caps to supported.
Ring sizes are parsed from object map metadata, never
hardcoded: classic objects spell each map as a STRUCT with
a max_entries pointer to an ARRAY count, while toolchain
objects wrap maps in newtype STRUCTs over a flat
definition whose value lives in the ELF `maps` member.
DATASEC membership selects the lane. Output is ignored
scratch (build/vm/), never shipped; the admission flip owns
the shipped profile. `apply_tracing` is the shared
transform the gate emitter reuses, so the flip cannot drift
from this mint.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
LC_OBJ = ROOT / "build" / "bpf" / "swiotlb_lifecycle.bpf.o"
CP_OBJ = ROOT / "build" / "bpf" / "swiotlb_copy.bpf.o"
OUT = ROOT / "build" / "vm" / "record3-profile.json"

KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_VAR = 14
KIND_DATASEC = 15

# Flat map-definition geometry: one 28-byte definition per
# map, ringbuf type 27, ring sizes a power of two within
# the same bounds the loading path enforces.
AYA_MAP_DEF_BYTES = 28
MAP_RINGBUF = 27
MIN_RING_BYTES = 4096
MAX_RING_BYTES = 2147483648

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


def elf_sections(data):
    """All ELF sections by name; refuses a malformed table."""
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
    out = {}
    for i in range(shnum):
        s = sec(i)
        name = strings[s[0]:].split(b"\0")[0].decode()
        out[name] = data[s[4]:s[4] + s[5]]
    return out


def elf_section(data, want):
    sections = elf_sections(data)
    if want not in sections:
        fail("missing %s section" % want)
    return sections[want]


def btf_name(obj_path, strings, off):
    if off >= len(strings):
        fail("%s: BTF strings corrupt" % obj_path)
    return strings[off:].split(b"\0")[0].decode()


def btf_records(obj_path, data):
    """(records, strings) of an object's BTF type table."""
    sec = elf_section(data, ".BTF")
    magic, ver, flags, hdr_len = struct.unpack("<HBBI", sec[:8])
    if magic != 0xEB9F or ver != 1 or hdr_len < 24:
        fail("%s: bad BTF header" % obj_path)
    type_off, type_len, str_off, str_len = struct.unpack(
        "<IIII", sec[8:24])
    types = sec[hdr_len + type_off:hdr_len + type_off + type_len]
    strings = sec[hdr_len + str_off:hdr_len + str_off + str_len]
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
        # Trailing data per BTF kind; FUNC vlen is linkage, not members.
        if kind in (1, KIND_VAR, 17):
            pos += 12 + 4
        elif kind in (KIND_STRUCT, 5, KIND_DATASEC, 19):
            pos += 12 + vlen * 12
        elif kind in (6, 13):
            pos += 12 + vlen * 8
        elif kind == KIND_ARRAY:
            pos += 12 + 12
        else:
            pos += 12
    if pos != len(types):
        fail("%s: BTF walk did not consume exact types"
             % obj_path)
    return recs, strings


def maps_datasec_members(obj_path, recs, strings):
    """(type, offset, size) entries of DATASEC `maps`, or None.

    None when the object carries no such DATASEC; a
    duplicated DATASEC refuses, since two member lists
    cannot associate definitions with bytes.
    """
    found = None
    for index, rec in enumerate(recs):
        if rec[1] != KIND_DATASEC:
            continue
        if btf_name(obj_path, strings, rec[0]) != "maps":
            continue
        if found is not None:
            fail("%s: duplicate maps DATASEC" % obj_path)
        found = index
    if found is None:
        return None
    rec = recs[found]
    members = []
    for m in range(rec[2]):
        tid, off, size = struct.unpack(
            "<III", rec[4][m * 12:m * 12 + 12])
        members.append((tid, off, size))
    return members


def struct_member(obj_path, recs, strings, rec, want):
    """(type, bit offset) of a STRUCT member, or (None, None)."""
    for m in range(rec[2]):
        name_off, mtype, off = struct.unpack(
            "<III", rec[4][m * 12:m * 12 + 12])
        if btf_name(obj_path, strings, name_off) == want:
            return mtype, off
    return None, None


def rec_valid(recs, tid):
    return tid is not None and 1 <= tid <= len(recs)


def flat_shape(obj_path, var_name):
    fail("%s: %s bad aya map shape" % (obj_path, var_name))


def aya_ring_bytes(obj_path, data, recs, strings, var_id,
                   var_name):
    """Ring bytes of one flat-definition map VAR.

    The toolchain wraps each map in newtype STRUCTs over a
    flat leaf; the leaf's max_entries is a plain u32 slot
    whose value lives in the ELF `maps` member, indexed by
    DATASEC order. Every wrapper size and member offset is
    pinned, so a toolchain layout change refuses instead of
    misreading.
    """
    top = recs[var_id][3]
    if not rec_valid(recs, top) \
            or recs[top - 1][1] != KIND_STRUCT:
        fail("%s: %s not a struct" % (obj_path, var_name))
    linkage, = struct.unpack("<I", recs[var_id][4][:4])
    if linkage not in (0, 1):
        fail("%s: %s linkage %d" % (obj_path, var_name,
                                    linkage))
    node = top
    for want in ("def", "__0", "value"):
        rec = recs[node - 1]
        if rec[1] != KIND_STRUCT \
                or rec[3] != AYA_MAP_DEF_BYTES or rec[2] != 1:
            flat_shape(obj_path, var_name)
        mtype, off = struct_member(
            obj_path, recs, strings, rec, want)
        if mtype is None or off != 0:
            flat_shape(obj_path, var_name)
        if not rec_valid(recs, mtype) \
                or recs[mtype - 1][1] != KIND_STRUCT:
            flat_shape(obj_path, var_name)
        node = mtype
    leaf = recs[node - 1]
    if leaf[3] != AYA_MAP_DEF_BYTES or leaf[2] != 7:
        flat_shape(obj_path, var_name)
    for member, field, bit in (
            ("type_", "type", 0),
            ("max_entries", "max_entries", 96),
            ("key_size", "key", 32),
            ("value_size", "value", 64)):
        mtype, off = struct_member(
            obj_path, recs, strings, leaf, member)
        if mtype is None:
            fail("%s: %s missing %s" % (obj_path, var_name,
                                        field))
        target = recs[mtype - 1] if rec_valid(recs, mtype) \
            else None
        if target is None or target[1] != 1 \
                or target[3] != 4 or off != bit:
            fail("%s: %s bad %s" % (obj_path, var_name,
                                    field))
    for member, bit in (("map_flags", 128), ("id", 160),
                        ("pinning", 192)):
        mtype, off = struct_member(
            obj_path, recs, strings, leaf, member)
        target = recs[mtype - 1] if rec_valid(recs, mtype) \
            else None
        if target is None or target[1] != 1 \
                or target[3] != 4 or off != bit:
            flat_shape(obj_path, var_name)
    members = maps_datasec_members(obj_path, recs, strings)
    seen = set()
    index = None
    for tid, off, size in members:
        if not rec_valid(recs, tid) \
                or recs[tid - 1][1] != KIND_VAR \
                or off != 0 or size != AYA_MAP_DEF_BYTES \
                or tid in seen:
            fail("%s: bad maps DATASEC" % obj_path)
        seen.add(tid)
        if tid == var_id + 1:
            index = len(seen) - 1
    if index is None:
        fail("%s: %s not in maps DATASEC" % (obj_path,
                                             var_name))
    flat = elf_sections(data).get("maps")
    at = index * AYA_MAP_DEF_BYTES
    if flat is None or at + 16 > len(flat):
        flat_shape(obj_path, var_name)
    typ, _key, _val, nr = struct.unpack(
        "<IIII", flat[at:at + 16])
    if typ != MAP_RINGBUF:
        fail("%s: %s type %d, want %d" % (obj_path, var_name,
                                          typ, MAP_RINGBUF))
    if nr < MIN_RING_BYTES or nr > MAX_RING_BYTES \
            or nr & (nr - 1):
        fail("%s: %s ring size %d rejected" % (obj_path,
                                               var_name, nr))
    return nr


def btf_ring_bytes(obj_path, var_name):
    """Parse one ringbuf size from object map metadata.

    Two encodings: classic objects spell each map as a
    STRUCT with a max_entries pointer to an ARRAY count,
    while toolchain objects wrap maps in newtype STRUCTs
    over a flat definition whose value lives in the ELF
    `maps` member. DATASEC membership selects the lane: a
    VAR listed in `maps` takes the flat lane, any other VAR
    the classic lane.
    """
    data = Path(obj_path).read_bytes()
    recs, strings = btf_records(obj_path, data)
    found = [i for i, r in enumerate(recs)
             if r[1] == KIND_VAR
             and btf_name(obj_path, strings, r[0]) == var_name]
    if len(found) != 1:
        fail("%s: want 1 %s var, got %d"
             % (obj_path, var_name, len(found)))
    members = maps_datasec_members(obj_path, recs, strings)
    if members is not None and found[0] + 1 in [
            tid for tid, _off, _size in members]:
        return aya_ring_bytes(obj_path, data, recs, strings,
                              found[0], var_name)
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
        if btf_name(obj_path, strings, name_off) == "max_entries":
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
    if nr < MIN_RING_BYTES or nr > MAX_RING_BYTES \
            or nr & (nr - 1):
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
    rebuilt); kept hooks verify their frozen tuple before the
    idempotent skip. Warns when shipped tracing pins differ
    from the current builds.
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
    have = {h["name"]: h for h in doc["hooks"]}
    for name, function, attach, signature in TRACE_HOOKS:
        if name in have:
            kept = have[name]
            if (kept.get("kind"), kept.get("function"),
                    kept.get("attach"),
                    kept.get("signature")) != (
                        "tracing", function, attach,
                        signature):
                fail("shipped hook drifts from frozen set: "
                     + name)
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


USAGE = ("usage: mint_record3_profile.py --base DOC "
         "[--out PATH] [--lc OBJ --cp OBJ]")


def main():
    out = OUT
    base = None
    lc_obj = LC_OBJ
    cp_obj = CP_OBJ
    args = sys.argv[1:]
    while args:
        if args[0] not in ("--out", "--base", "--lc", "--cp") \
                or len(args) < 2:
            fail(USAGE)
        if args[0] == "--out":
            out = Path(args[1])
        elif args[0] == "--base":
            base = Path(args[1])
        elif args[0] == "--lc":
            lc_obj = Path(args[1])
        else:
            cp_obj = Path(args[1])
        args = args[2:]
    if base is None:
        fail(USAGE)
    doc = json.loads(base.read_text())
    if doc.get("schema_version") not in ("0.1.1", "0.1.2"):
        fail("shipped doc is not profile 0.1.1")
    attempt = [c for c in doc["capabilities"]
               if c["id"] == "attempt-trace"]
    if len(attempt) != 1 or attempt[0]["status"] != "supported":
        fail("shipped doc lacks supported attempt-trace")
    apply_tracing(
        doc, lc_obj, cp_obj,
        "Record3 lane only: ephemeral 3-channel wiring proof.",
        "Record3 lane only: ephemeral 3-channel wiring proof.",
        "Record3 test hook.")
    doc["profile_id"] = "record3-ephemeral"
    doc["status"] = "reference-unvalidated"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print("minted %s" % out)


if __name__ == "__main__":
    main()
