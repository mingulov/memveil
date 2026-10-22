# SPDX-License-Identifier: GPL-3.0-or-later

"""BTF map-definition reads from BPF objects."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.btf import (
    read_btf_copy_fb,
    read_btf_func_proto,
    read_btf_maps,
    read_btf_maps_ring,
    read_btf_member,
    resolve_btf_enumerator,
    resolve_btf_member,
)
from memveil.platform.narrow import verify_object_program
from memveil.platform.reader import read_host_file


def _read_fixture(path: String) raises -> List[UInt8]:
    return read_host_file(path, String("fixture"), 67108864)


def test_btf_ok() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/ok.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(v.ok)
    assert_equal(v.message, String(""))
    assert_equal(v.ring_bytes, 8388608)


def test_btf_badring() raises:
    # A smaller but sane ring passes the static read; only
    # the identity binding pins the exact expected value.
    var raw = _read_fixture(String("tests/fixtures/elf/badring.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(v.ok)
    assert_equal(v.ring_bytes, 4194304)


def test_btf_badmap() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/badmap.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("counts max_entries 7, want 6"))


def test_btf_nobtf() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/nobtf.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("no BTF section"))


def test_btf_extern() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/extern.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("counts linkage 2"))


def test_btf_tiny() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/tiny.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("no BTF section"))


def test_btf_nodatasec() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/nodatasec.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("no maps DATASEC"))


def test_btf_unlisted() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/unlisted.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("counts not in maps DATASEC"))


def test_btf_dupvar() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/dupvar.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("duplicate mv_counts"))


def test_btf_offsets_map_ok() raises:
    # ok.o is the byte copy of the rebuilt attempt object:
    # the static pin holds over the real mv_offsets map.
    var raw = _read_fixture(String("tests/fixtures/elf/ok.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(v.ok)
    assert_equal(v.message, String(""))
    assert_equal(v.ring_bytes, 8388608)


def test_btf_offsets_map_bad_geometry() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/badoff.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("offsets max_entries 2, want 1"))
    var missing = _read_fixture(String("tests/fixtures/elf/nooff.o"))
    var w = read_btf_maps(Span(missing))
    assert_true(not w.ok)
    assert_equal(w.message, String("missing mv_offsets"))


def test_btf_inline_edges() raises:
    var empty = List[UInt8]()
    var v = read_btf_maps(Span(empty))
    assert_true(not v.ok)
    assert_equal(v.message, String("no BTF section"))
    var text = String("not an object\n")
    var w = read_btf_maps(text.as_bytes())
    assert_true(not w.ok)
    assert_equal(w.message, String("no BTF section"))


def test_btf_lifecycle_ring() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/lc-ok.o"))
    var v = read_btf_maps_ring(
        Span(raw), String("mv_lifecycle"), String("lifecycle"))
    assert_true(v.ok)
    assert_equal(v.message, String(""))
    assert_equal(v.ring_bytes, 33554432)


def test_btf_copy_ring() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/cp-ok.o"))
    var v = read_btf_maps_ring(
        Span(raw), String("mv_copies"), String("copies"))
    assert_true(v.ok)
    assert_equal(v.message, String(""))
    assert_equal(v.ring_bytes, 33554432)


def test_btf_copy_nonpow2() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/cp-nonpow2.o"))
    var v = read_btf_maps_ring(
        Span(raw), String("mv_copies"), String("copies"))
    assert_true(not v.ok)
    assert_equal(
        v.message, String("copies ring size 1000 rejected"))


def test_btf_missing_ring() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/lc-ok.o"))
    var v = read_btf_maps_ring(
        Span(raw), String("mv_copies"), String("copies"))
    assert_true(not v.ok)
    assert_equal(v.message, String("missing mv_copies"))


def test_func_proto_ok() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/funcproto.bin"))
    var v = read_btf_func_proto(Span(raw), String("test_fn"))
    assert_true(v.ok)
    assert_equal(v.message, String(""))
    assert_equal(
        v.canonical, String("int (struct device *dev, size_t size)")
    )


def test_func_proto_missing() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/funcproto.bin"))
    var v = read_btf_func_proto(Span(raw), String("nope"))
    assert_true(not v.ok)
    assert_equal(v.message, String("function nope not found"))


def test_func_proto_duplicate() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/dupfunc.bin"))
    var v = read_btf_func_proto(Span(raw), String("test_fn"))
    assert_true(not v.ok)
    assert_equal(v.message, String("duplicate function test_fn"))


def test_func_proto_cycle() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/cycle.bin"))
    var v = read_btf_func_proto(Span(raw), String("cyc"))
    assert_true(not v.ok)
    assert_equal(v.message, String("type graph too deep"))


def test_func_proto_anon() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/anon.bin"))
    var v = read_btf_func_proto(Span(raw), String("anon"))
    assert_true(not v.ok)
    assert_equal(v.message, String("anonymous type in prototype"))


def test_func_proto_void() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/funcproto.bin"))
    var v = read_btf_func_proto(Span(raw), String("vret"))
    assert_true(v.ok)
    assert_equal(v.canonical, String("void (void)"))


def test_func_proto_int_alias() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/funcproto.bin"))
    var v = read_btf_func_proto(Span(raw), String("lint"))
    assert_true(v.ok)
    assert_equal(v.canonical, String("unsigned long (void)"))


def test_func_proto_voidptr() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/voidptr.bin"))
    var v = read_btf_func_proto(Span(raw), String("vptr"))
    assert_true(v.ok)
    assert_equal(v.canonical, String("void (void *p)"))


def test_func_proto_unnamed_param() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/unnamed.bin"))
    var v = read_btf_func_proto(Span(raw), String("unm"))
    assert_true(not v.ok)
    assert_equal(v.message, String("unnamed parameter in prototype"))


def test_func_proto_array() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/array.bin"))
    var v = read_btf_func_proto(Span(raw), String("arr"))
    assert_true(v.ok)
    assert_equal(v.canonical, String("void (int[4] a)"))


def test_func_proto_badref() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/badref.bin"))
    var v = read_btf_func_proto(Span(raw), String("bad"))
    assert_true(not v.ok)
    assert_equal(v.message, String("type id out of range"))


def test_func_proto_fnptr() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/fnptr.bin"))
    var v = read_btf_func_proto(Span(raw), String("cb"))
    assert_true(not v.ok)
    assert_equal(v.message, String("function pointer in prototype"))


def test_func_proto_chain31() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/chain31.bin"))
    var v = read_btf_func_proto(Span(raw), String("deep31"))
    assert_true(v.ok)
    var want = String("void (int")
    for _ in range(31):
        want += String(" *")
    want += String("p)")
    assert_equal(v.canonical, want)


def test_func_proto_chain32() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/chain32.bin"))
    var v = read_btf_func_proto(Span(raw), String("deep32"))
    assert_true(not v.ok)
    assert_equal(v.message, String("type graph too deep"))


def test_func_proto_truncated() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/funcproto.bin"))
    var cut = Span(raw)[0 : len(raw) - 10]
    var v = read_btf_func_proto(cut, String("test_fn"))
    assert_true(not v.ok)
    assert_equal(v.message, String("BTF sections out of range"))


def test_btf_kind_flag_struct_ok() raises:
    # kind_flag on STRUCT changes interpretation, not
    # member layout: the walker keeps 12-byte member
    # alignment and spells the return normally.
    var raw = _read_fixture(String("tests/fixtures/btf/kflag.bin"))
    var v = read_btf_func_proto(Span(raw), String("kfs"))
    assert_true(v.ok)
    assert_equal(v.message, String(""))
    assert_equal(v.canonical, String("struct device (void)"))


def test_btf_kind_flag_enum64_ok() raises:
    # kind_flag on ENUM64 likewise leaves the 12-byte
    # enumerator entries aligned; the parameter spells.
    var raw = _read_fixture(String("tests/fixtures/btf/kflag.bin"))
    var v = read_btf_func_proto(Span(raw), String("kfe"))
    assert_true(v.ok)
    assert_equal(v.message, String(""))
    assert_equal(v.canonical, String("void (enum color c)"))


def test_func_proto_int_size_mismatch() raises:
    # A 4-byte "long" is not an LP64 long: both the
    # return and the parameter position refuse with
    # the exact size diagnostic.
    var raw = _read_fixture(
        String("tests/fixtures/btf/intsize-bad.bin")
    )
    var r = read_btf_func_proto(Span(raw), String("badret"))
    assert_true(not r.ok)
    assert_equal(
        r.message,
        String("BTF int size 4 mismatch for long, want 8"),
    )
    var p = read_btf_func_proto(Span(raw), String("badpar"))
    assert_true(not p.ok)
    assert_equal(
        p.message,
        String("BTF int size 4 mismatch for long, want 8"),
    )


def test_func_proto_int_size_lp64_ok() raises:
    # Every LP64 integer spelling (plus kernel/BTF
    # aliases and a size_t typedef) spells exactly as
    # before once its BTF size matches the table.
    var raw = _read_fixture(
        String("tests/fixtures/btf/intsizes.bin")
    )
    var v = read_btf_func_proto(Span(raw), String("isz"))
    assert_true(v.ok)
    assert_equal(v.message, String(""))
    var want = String("void (char pa, signed char pb,")
    want += String(" unsigned char pc, short pd,")
    want += String(" unsigned short pe, int pf, unsigned int pg,")
    want += String(" long ph, unsigned long pi, long long pj,")
    want += String(" unsigned long long pk, bool pl, short pm,")
    want += String(" long pn, long long po, unsigned short pp,")
    want += String(" unsigned long pq, unsigned long long pr,")
    want += String(" size_t psz)")
    assert_equal(v.canonical, want)


def test_btf_member_pool() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/swiotlb-live.bin"))
    var s = read_btf_member(
        Span(raw), String("io_tlb_pool"), String("start"))
    assert_true(s.ok)
    assert_equal(s.message, String(""))
    assert_equal(s.bit_offset, 0)
    assert_equal(s.bit_size, 64)
    var n = read_btf_member(
        Span(raw), String("io_tlb_pool"), String("nslabs"))
    assert_true(n.ok)
    assert_equal(n.bit_offset, 192)
    assert_equal(n.bit_size, 64)
    var q = read_btf_member(
        Span(raw), String("io_tlb_pool"), String("slots"))
    assert_true(q.ok)
    assert_equal(q.bit_offset, 448)
    assert_equal(q.bit_size, 64)


def test_btf_member_slot() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/swiotlb-live.bin"))
    var o = read_btf_member(
        Span(raw), String("io_tlb_slot"), String("orig_addr"))
    assert_true(o.ok)
    assert_equal(o.bit_offset, 0)
    assert_equal(o.bit_size, 64)
    var a = read_btf_member(
        Span(raw), String("io_tlb_slot"), String("alloc_size"))
    assert_true(a.ok)
    assert_equal(a.bit_offset, 64)
    assert_equal(a.bit_size, 64)


def test_btf_member_device() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/swiotlb-live.bin"))
    var m = read_btf_member(
        Span(raw), String("device_dma_parameters"),
        String("min_align_mask"),
    )
    assert_true(m.ok)
    assert_equal(m.bit_offset, 32)
    assert_equal(m.bit_size, 32)
    var d = read_btf_member(
        Span(raw), String("device"), String("dma_parms"))
    assert_true(d.ok)
    assert_equal(d.bit_offset, 5056)
    assert_equal(d.bit_size, 64)


def test_btf_member_not_found() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/swiotlb-live.bin"))
    var s = read_btf_member(
        Span(raw), String("no_such_struct"), String("start"))
    assert_true(not s.ok)
    assert_equal(s.message, String("struct no_such_struct not found"))
    var m = read_btf_member(
        Span(raw), String("io_tlb_pool"), String("no_such_field"))
    assert_true(not m.ok)
    assert_equal(
        m.message, String("member no_such_field not found in io_tlb_pool")
    )


def test_btf_copy_fallback_declared() raises:
    var raw = _read_fixture(String("build/bpf/swiotlb_copy.bpf.o"))
    var fb = read_btf_copy_fb(Span(raw))
    assert_true(fb.ok)
    assert_equal(fb.message, String(""))
    var e = verify_object_program(
        Span(raw), String("mv_bounce"), String("fentry/"))
    assert_true(e.ok)
    var x = verify_object_program(
        Span(raw), String("mv_bounce_exit"), String("fexit/"))
    assert_true(x.ok)


def test_member_anon_offsets() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/members.bin"))
    var c = resolve_btf_member(
        Span(raw), String("mvt_anon"), String("c")
    )
    assert_true(c.ok)
    assert_true(c.found)
    assert_equal(c.bit_offset, 128)
    assert_equal(c.bit_size, 64)
    assert_equal(c.kind, String("int"))
    var m = resolve_btf_member(
        Span(raw), String("mvt_anon"), String("mapping")
    )
    assert_true(m.ok)
    assert_equal(m.bit_offset, 192)
    assert_equal(m.bit_size, 64)
    assert_equal(m.kind, String("ptr"))
    var d = resolve_btf_member(
        Span(raw), String("mvt_anon"), String("d")
    )
    assert_true(d.ok)
    assert_true(d.found)
    assert_equal(d.bit_offset, 64)


def test_member_real_shapes() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/members.bin"))
    var f = resolve_btf_member(
        Span(raw), String("mvt_dev"), String("offline_disabled")
    )
    assert_true(f.ok)
    assert_true(f.found)
    assert_true(f.bitfield)
    assert_equal(f.bit_offset, 6112)
    assert_equal(f.bit_size, 1)
    var o = resolve_btf_member(
        Span(raw), String("mvt_dev_old"), String("offline_disabled")
    )
    assert_true(o.ok)
    assert_true(o.found)
    assert_true(o.bitfield)
    var p = resolve_btf_member(
        Span(raw), String("mvt_tag"), String("p")
    )
    assert_true(p.ok)
    assert_equal(p.kind, String("ptr"))
    assert_equal(p.bit_size, 64)
    var q = resolve_btf_member(
        Span(raw), String("mvt_tag"), String("q")
    )
    assert_true(q.ok)
    assert_equal(q.kind, String("int"))
    assert_equal(q.bit_size, 64)
    var n = resolve_btf_member(
        Span(raw), String("mvt_tag"), String("name")
    )
    assert_true(n.ok)
    assert_equal(n.kind, String("array"))
    assert_equal(n.bit_size, 128)
    var e = resolve_btf_enumerator(
        Span(raw), String("mvt_e64"), String("MVT_BIG")
    )
    assert_true(e.ok)
    assert_true(e.found)
    assert_equal(e.kind, String("enum"))
    assert_equal(e.bit_size, 64)


def test_member_duplicates() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/members.bin"))
    var c = resolve_btf_member(
        Span(raw), String("mvt_console"), String("flags")
    )
    assert_true(c.ok)
    assert_true(c.found)
    assert_equal(c.bit_offset, 64)
    var d = resolve_btf_member(
        Span(raw), String("mvt_dup"), String("flags")
    )
    assert_true(not d.ok)
    assert_true(d.ambiguous)
    assert_equal(
        d.message,
        String("struct mvt_dup: 2 definitions disagree on flags"),
    )
    var e = resolve_btf_member(
        Span(raw), String("mvt_partial"), String("extra")
    )
    assert_true(e.ok)
    assert_true(e.found)
    assert_equal(e.bit_offset, 96)


def test_member_absent() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/members.bin"))
    var m = resolve_btf_member(
        Span(raw), String("mvt_anon"), String("nope")
    )
    assert_true(m.ok)
    assert_true(m.struct_found)
    assert_true(not m.found)
    var s = resolve_btf_member(
        Span(raw), String("mvt_none"), String("a")
    )
    assert_true(s.ok)
    assert_true(not s.struct_found)


def test_member_legacy_refuses_bitfield() raises:
    var raw = _read_fixture(String("tests/fixtures/btf/members.bin"))
    var v = read_btf_member(
        Span(raw), String("mvt_dev"), String("offline_disabled")
    )
    assert_true(not v.ok)
    assert_equal(
        v.message,
        String("bitfield member mvt_dev.offline_disabled unsupported"),
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_btf_ok]()
    suite.test[test_btf_badring]()
    suite.test[test_btf_badmap]()
    suite.test[test_btf_nobtf]()
    suite.test[test_btf_extern]()
    suite.test[test_btf_tiny]()
    suite.test[test_btf_nodatasec]()
    suite.test[test_btf_unlisted]()
    suite.test[test_btf_dupvar]()
    suite.test[test_btf_offsets_map_ok]()
    suite.test[test_btf_offsets_map_bad_geometry]()
    suite.test[test_btf_inline_edges]()
    suite.test[test_btf_lifecycle_ring]()
    suite.test[test_btf_copy_ring]()
    suite.test[test_btf_copy_nonpow2]()
    suite.test[test_btf_missing_ring]()
    suite.test[test_func_proto_ok]()
    suite.test[test_func_proto_missing]()
    suite.test[test_func_proto_duplicate]()
    suite.test[test_func_proto_cycle]()
    suite.test[test_func_proto_anon]()
    suite.test[test_func_proto_void]()
    suite.test[test_func_proto_int_alias]()
    suite.test[test_func_proto_voidptr]()
    suite.test[test_func_proto_unnamed_param]()
    suite.test[test_func_proto_array]()
    suite.test[test_func_proto_badref]()
    suite.test[test_func_proto_fnptr]()
    suite.test[test_func_proto_chain31]()
    suite.test[test_func_proto_chain32]()
    suite.test[test_func_proto_truncated]()
    suite.test[test_btf_kind_flag_struct_ok]()
    suite.test[test_btf_kind_flag_enum64_ok]()
    suite.test[test_func_proto_int_size_mismatch]()
    suite.test[test_func_proto_int_size_lp64_ok]()
    suite.test[test_btf_member_pool]()
    suite.test[test_btf_member_slot]()
    suite.test[test_btf_member_device]()
    suite.test[test_btf_member_not_found]()
    suite.test[test_btf_copy_fallback_declared]()
    suite.test[test_member_anon_offsets]()
    suite.test[test_member_real_shapes]()
    suite.test[test_member_duplicates]()
    suite.test[test_member_absent]()
    suite.test[test_member_legacy_refuses_bitfield]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
