# SPDX-License-Identifier: GPL-3.0-or-later

"""Narrow grammar, identity reads, and binding checks."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.narrow import (
    NarrowLive,
    check_narrow,
    check_narrow_extra,
    check_trace_layout,
    parse_narrow_note,
    parse_notes_bid,
    read_live_bid,
    read_live_bytes,
    read_live_config,
    read_live_object,
    verify_object,
    verify_object_program,
)
from memveil.platform.reader import read_host_file

comptime _REL = "7.0.0-test"
comptime _ZLIB = "libz.so.1"
comptime _CONFIG = "a5af36b05630b51bb596bc68f955ab97bb8802e857cd2fc1de05c0628e398fbb"
comptime _BTF = "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9"
comptime _FORMAT = "039a1a6bc665b91c4f846f735f9b2f9ec89d106d7d63a5e9d0b35e20213e80fb"
comptime _OBJECT = "7549adfdf9837cefd566373a0efeee8550abdb4cd678b6fa15fe11f3f4785a37"
comptime _IMAGE = "11a663ae36f0cdbecf94b8b7319503bbd0fffc2c3ba02c01cf81600d423dd251"
comptime _BID = "0102030405060708090a0b0c0d0e0f1011121314"
comptime _FMT_PATH = "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"


def _fields(src: String, ring: String) -> List[String]:
    var out = List[String]()
    out.append(String("config=sha256:") + String(_CONFIG))
    out.append(String("config_src=") + src)
    out.append(String("btf=sha256:") + String(_BTF))
    out.append(String("format=sha256:") + String(_FORMAT))
    out.append(String("object=sha256:") + String(_OBJECT))
    out.append(String("image=sha256:") + String(_IMAGE))
    out.append(String("image_bid=") + String(_BID))
    out.append(String("ring_bytes=") + ring)
    return out^


def _join(fields: List[String]) -> String:
    var out = String("")
    for i in range(len(fields)):
        if i > 0:
            out += String(" ")
        out += fields[i]
    return out^


def test_grammar_valid() raises:
    var p = parse_narrow_note(_join(_fields(String("gz"), String("8388608"))))
    assert_true(p.ok)
    assert_equal(p.bindings.config, String(_CONFIG))
    assert_equal(p.bindings.config_src, String("gz"))
    assert_equal(p.bindings.btf, String(_BTF))
    assert_equal(p.bindings.format, String(_FORMAT))
    assert_equal(p.bindings.object, String(_OBJECT))
    assert_equal(p.bindings.image, String(_IMAGE))
    assert_equal(p.bindings.image_bid, String(_BID))
    assert_equal(p.bindings.ring, String("8388608"))


def test_grammar_lengths() raises:
    # Worst case stays under the 512 note limit; the
    # design's 477 is the gz spelling, 479 with file.
    var gz_note = _join(_fields(String("gz"), String("4294967295")))
    var file_note = _join(_fields(String("file"), String("4294967295")))
    assert_equal(gz_note.byte_length(), 477)
    assert_equal(file_note.byte_length(), 479)
    assert_true(parse_narrow_note(gz_note).ok)
    assert_true(parse_narrow_note(file_note).ok)


def test_grammar_field_count() raises:
    var seven = _fields(String("gz"), String("8388608"))
    var cut = List[String]()
    for i in range(7):
        cut.append(seven[i])
    var p = parse_narrow_note(_join(cut))
    assert_true(not p.ok)
    assert_equal(p.message, String("narrow note: want 8 or 12 fields"))
    var nine = _join(_fields(String("gz"), String("8388608")))
    var q = parse_narrow_note(nine + String(" extra=1"))
    assert_true(not q.ok)
    assert_equal(q.message, String("narrow note: want 8 or 12 fields"))


def test_grammar_spacing() raises:
    var fields = _fields(String("gz"), String("8388608"))
    var double = String("")
    for i in range(len(fields)):
        if i > 0:
            if i == 2:
                double += String("  ")
            else:
                double += String(" ")
        double += fields[i]
    var p = parse_narrow_note(double)
    assert_true(not p.ok)
    assert_equal(p.message, String("narrow note: want 8 or 12 fields"))
    var base = _join(fields)
    assert_true(not parse_narrow_note(String(" ") + base).ok)
    assert_true(not parse_narrow_note(base + String(" ")).ok)
    var tabbed = fields[0] + String("\t") + fields[1]
    for i in range(2, len(fields)):
        tabbed += String(" ") + fields[i]
    assert_true(not parse_narrow_note(tabbed).ok)


def test_grammar_keys() raises:
    var fields = _fields(String("gz"), String("8388608"))
    var tmp = fields[2]
    fields[2] = fields[3]
    fields[3] = tmp
    var p = parse_narrow_note(_join(fields))
    assert_true(not p.ok)
    assert_equal(p.message, String("narrow note: bad btf"))
    var fields2 = _fields(String("gz"), String("8388608"))
    fields2[1] = String("config_src=gz")
    fields2[0] = String("conf=sha256:") + String(_CONFIG)
    var q = parse_narrow_note(_join(fields2))
    assert_true(not q.ok)
    assert_equal(q.message, String("narrow note: bad config"))


def test_grammar_values() raises:
    var fields = _fields(String("gz"), String("8388608"))
    fields[0] = String("config=sha256:") + String(
        "A5AF36b05630b51bb596bc68f955ab97bb8802e857cd2fc1de05c0628e398fbb"
    )
    var p = parse_narrow_note(_join(fields))
    assert_true(not p.ok)
    assert_equal(p.message, String("narrow note: bad config"))
    var fields2 = _fields(String("gz"), String("8388608"))
    fields2[0] = String("config=sha256:a5af")
    assert_equal(
        parse_narrow_note(_join(fields2)).message,
        String("narrow note: bad config"),
    )
    var fields3 = _fields(String("gz"), String("8388608"))
    fields3[0] = String("config=") + String(_CONFIG)
    assert_true(not parse_narrow_note(_join(fields3)).ok)
    var fields4 = _fields(String("gz"), String("8388608"))
    fields4[1] = String("config_src=raw")
    assert_equal(
        parse_narrow_note(_join(fields4)).message,
        String("narrow note: bad config_src"),
    )
    var fields5 = _fields(String("gz"), String("8388608"))
    fields5[6] = String("image_bid=0102")
    assert_equal(
        parse_narrow_note(_join(fields5)).message,
        String("narrow note: bad image_bid"),
    )


def test_grammar_ring() raises:
    var zero = _join(_fields(String("gz"), String("0")))
    assert_equal(
        parse_narrow_note(zero).message,
        String("narrow note: bad ring_bytes"),
    )
    var lead_zero = _join(_fields(String("gz"), String("01024")))
    assert_true(not parse_narrow_note(lead_zero).ok)
    var huge = _join(_fields(String("gz"), String("4294967296")))
    assert_true(not parse_narrow_note(huge).ok)
    var alpha = _join(_fields(String("gz"), String("8m")))
    assert_true(not parse_narrow_note(alpha).ok)
    var fields = _fields(String("gz"), String("8388608"))
    fields[7] = String("ring_bytes=")
    assert_true(not parse_narrow_note(_join(fields)).ok)


def _read_live(root: String) raises -> NarrowLive:
    var live = NarrowLive()
    var cfg = read_live_config(root, String(_REL), String(_ZLIB))
    live.config = cfg.value
    live.config_src = cfg.src
    live.btf = read_live_bytes(
        root, String("/sys/kernel/btf/vmlinux"), String("btf"), 67108864
    )
    live.format = read_live_bytes(
        root, String(_FMT_PATH), String("format"), 1048576
    )
    live.object = read_live_object(root + String("/object.o"))
    live.image = read_live_bytes(
        root,
        String("/boot/vmlinuz-") + String(_REL),
        String("image"),
        268435456,
    )
    live.image_bid = read_live_bid(root)
    live.ring.state = String("value")
    live.ring.value = String("8388608")
    return live^


def test_live_ok_root() raises:
    var live = _read_live(String("tests/fixtures/narrow/ok"))
    assert_equal(live.config_src, String("gz"))
    assert_equal(live.config.state, String("value"))
    assert_equal(live.config.value, String(_CONFIG))
    assert_equal(live.btf.value, String(_BTF))
    assert_equal(live.format.value, String(_FORMAT))
    assert_equal(live.object.value, String(_OBJECT))
    assert_equal(live.image.value, String(_IMAGE))
    assert_equal(live.image_bid.value, String(_BID))


def test_live_nogz_root() raises:
    var root = String("tests/fixtures/narrow/nogz")
    var cfg = read_live_config(root, String(_REL), String(_ZLIB))
    assert_equal(cfg.src, String("file"))
    assert_equal(cfg.value.state, String("value"))
    assert_equal(cfg.value.value, String(_CONFIG))


def test_live_none_root() raises:
    var root = String("tests/fixtures/narrow/none")
    var cfg = read_live_config(root, String(_REL), String(_ZLIB))
    assert_equal(cfg.src, String(""))
    assert_equal(cfg.value.state, String("uncheckable"))
    var btf = read_live_bytes(
        root, String("/sys/kernel/btf/vmlinux"), String("btf"), 67108864
    )
    assert_equal(btf.state, String("uncheckable"))
    assert_equal(read_live_bid(root).state, String("uncheckable"))
    assert_equal(
        read_live_object(root + String("/object.o")).state,
        String("uncheckable"),
    )


def test_check_bound() raises:
    var parsed = parse_narrow_note(
        _join(_fields(String("gz"), String("8388608")))
    )
    assert_true(parsed.ok)
    var v = check_narrow(
        parsed.bindings, _read_live(String("tests/fixtures/narrow/ok"))
    )
    assert_equal(v.state, String("bound"))
    assert_equal(v.key, String(""))


def test_check_mismatch_keys() raises:
    var parsed = parse_narrow_note(
        _join(_fields(String("gz"), String("8388608")))
    )
    # config_src mismatch beats config mismatch.
    var file_parsed = parse_narrow_note(
        _join(_fields(String("file"), String("8388608")))
    )
    var v = check_narrow(
        file_parsed.bindings,
        _read_live(String("tests/fixtures/narrow/ok")),
    )
    assert_equal(v.state, String("mismatch"))
    assert_equal(v.key, String("config_src"))
    # Skewed disk image refuses while the bid still matches.
    var skew = _read_live(String("tests/fixtures/narrow/skew"))
    assert_true(skew.image.value != String(_IMAGE))
    assert_equal(skew.image_bid.value, String(_BID))
    var s = check_narrow(parsed.bindings, skew)
    assert_equal(s.state, String("mismatch"))
    assert_equal(s.key, String("image"))


def test_check_uncheckable_precedence() raises:
    var parsed = parse_narrow_note(
        _join(_fields(String("gz"), String("8388608")))
    )
    var live = _read_live(String("tests/fixtures/narrow/ok"))
    live.btf.state = String("uncheckable")
    live.format.value = String(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    var v = check_narrow(parsed.bindings, live)
    assert_equal(v.state, String("uncheckable"))
    assert_equal(v.key, String("btf"))
    var live2 = _read_live(String("tests/fixtures/narrow/ok"))
    live2.ring.value = String("4096")
    var w = check_narrow(parsed.bindings, live2)
    assert_equal(w.state, String("mismatch"))
    assert_equal(w.key, String("ring_bytes"))


def _append_u32(mut blob: List[UInt8], v: Int):
    blob.append(UInt8(v & 0xFF))
    blob.append(UInt8((v >> 8) & 0xFF))
    blob.append(UInt8((v >> 16) & 0xFF))
    blob.append(UInt8((v >> 24) & 0xFF))


def test_notes_vectors() raises:
    var blob = List[UInt8]()
    _append_u32(blob, 4)
    _append_u32(blob, 20)
    _append_u32(blob, 3)
    blob.append(UInt8(0x47))
    blob.append(UInt8(0x4E))
    blob.append(UInt8(0x55))
    blob.append(UInt8(0))
    for i in range(1, 21):
        blob.append(UInt8(i))
    var v = parse_notes_bid(Span(blob))
    assert_equal(v.state, String("value"))
    assert_equal(v.value, String(_BID))
    var cut = List[UInt8]()
    for i in range(len(blob) - 5):
        cut.append(blob[i])
    assert_equal(parse_notes_bid(Span(cut)).state, String("uncheckable"))
    var empty = List[UInt8]()
    var e = parse_notes_bid(Span(empty))
    assert_equal(e.state, String("uncheckable"))
    assert_equal(e.detail, String("no build-id note"))


def test_notes_decoy_and_malformed() raises:
    # A type-3 Xen note must not satisfy the GNU check.
    var blob = List[UInt8]()
    _append_u32(blob, 4)
    _append_u32(blob, 8)
    _append_u32(blob, 3)
    blob.append(UInt8(0x58))
    blob.append(UInt8(0x65))
    blob.append(UInt8(0x6E))
    blob.append(UInt8(0))
    for _ in range(8):
        blob.append(UInt8(1))
    var v = parse_notes_bid(Span(blob))
    assert_equal(v.state, String("uncheckable"))
    assert_equal(v.detail, String("no build-id note"))
    # A GNU note with a short descriptor is malformed.
    var bad = List[UInt8]()
    _append_u32(bad, 4)
    _append_u32(bad, 8)
    _append_u32(bad, 3)
    bad.append(UInt8(0x47))
    bad.append(UInt8(0x4E))
    bad.append(UInt8(0x55))
    bad.append(UInt8(0))
    for _ in range(8):
        bad.append(UInt8(2))
    var w = parse_notes_bid(Span(bad))
    assert_equal(w.state, String("uncheckable"))
    assert_equal(w.detail, String("build-id malformed"))


def _read_fixture(path: String) raises -> List[UInt8]:
    return read_host_file(path, String("fixture"), 67108864)


comptime _PROG = "mv_swiotlb_attempt"


def test_layout_ok() raises:
    var raw = _read_fixture(String("tests/fixtures/layout/ok.format"))
    var v = check_trace_layout(Span(raw))
    assert_true(v.ok)
    assert_equal(v.message, String(""))


def test_layout_drift() raises:
    var raw = _read_fixture(String("tests/fixtures/layout/moved.format"))
    var v = check_trace_layout(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("field size: want @32:8"))


def test_layout_missing() raises:
    var raw = _read_fixture(String("tests/fixtures/layout/missing.format"))
    var v = check_trace_layout(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("missing field force"))


def test_layout_badtype() raises:
    var raw = _read_fixture(String("tests/fixtures/layout/badtype.format"))
    var v = check_trace_layout(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("field force: want type bool"))


def test_layout_garbage() raises:
    var raw = _read_fixture(String("tests/fixtures/layout/garbage.format"))
    var v = check_trace_layout(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("missing field common_type"))


def test_layout_inline_edges() raises:
    var bogus = String("field:bogus\n")
    var v = check_trace_layout(bogus.as_bytes())
    assert_true(not v.ok)
    assert_equal(v.message, String("format line unparseable"))
    var line = String(
        "field:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n"
    )
    var dup = line + line.copy()
    var w = check_trace_layout(dup.as_bytes())
    assert_true(not w.ok)
    assert_equal(w.message, String("duplicate field size"))


def test_object_ok() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/ok.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(v.ok)
    assert_equal(v.message, String(""))


def test_object_badarch() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/badarch.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(not v.ok)
    assert_equal(v.message, String("not a BPF object"))


def test_object_nosym() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/nosym.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(not v.ok)
    assert_equal(v.message, String("program symbol missing"))


def test_object_badsec() raises:
    # Losing the only tracepoint section refuses before
    # the symbol walk: section presence beats diagnosis.
    var raw = _read_fixture(String("tests/fixtures/elf/badsec.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(not v.ok)
    assert_equal(v.message, String("no tracepoint section"))


def test_object_wrongsec() raises:
    # A local decoy plus the global program outside any
    # tracepoint section refuses with the section detail.
    var raw = _read_fixture(String("tests/fixtures/elf/wrongsec.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(not v.ok)
    assert_equal(
        v.message,
        String("program symbol unusable: program in kprobe/foo"),
    )


def test_object_tiny() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/tiny.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(not v.ok)
    assert_equal(v.message, String("object too small"))


def test_object_emptysec() raises:
    # An emptied program section refuses at the extent
    # check: the symbol no longer fits its section.
    var raw = _read_fixture(String("tests/fixtures/elf/emptysec.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(not v.ok)
    assert_equal(
        v.message,
        String("program symbol unusable: program outside section"),
    )


def test_object_zerosym() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/zerosym.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(not v.ok)
    assert_equal(
        v.message, String("program symbol unusable: program empty")
    )


def test_object_mapsrange() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/mapsrange.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(not v.ok)
    assert_equal(v.message, String(".maps section out of range"))


def test_object_typemaps() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/typemaps.o"))
    var v = verify_object(Span(raw), String(_PROG))
    assert_true(not v.ok)
    assert_equal(v.message, String(".maps section bad type"))


comptime _LC_OBJECT = "9c8e7d6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e"
comptime _CP_OBJECT = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"


def _fields12() -> List[String]:
    var out = _fields(String("gz"), String("8388608"))
    out.append(String("lc_object=sha256:") + String(_LC_OBJECT))
    out.append(String("lc_ring_bytes=8388608"))
    out.append(String("cp_object=sha256:") + String(_CP_OBJECT))
    out.append(String("cp_ring_bytes=8388608"))
    return out^


def _live_extra(
    lc_object: String, lc_ring: String, cp_object: String, cp_ring: String
) -> NarrowLive:
    var live = NarrowLive()
    live.lc_object.state = String("value")
    live.lc_object.value = lc_object
    live.lc_ring.state = String("value")
    live.lc_ring.value = lc_ring
    live.cp_object.state = String("value")
    live.cp_object.value = cp_object
    live.cp_ring.state = String("value")
    live.cp_ring.value = cp_ring
    return live^


def test_grammar_extended_valid() raises:
    var p = parse_narrow_note(_join(_fields12()))
    assert_true(p.ok)
    assert_equal(p.bindings.lc_object, String(_LC_OBJECT))
    assert_equal(p.bindings.lc_ring, String("8388608"))
    assert_equal(p.bindings.cp_object, String(_CP_OBJECT))
    assert_equal(p.bindings.cp_ring, String("8388608"))
    assert_equal(p.bindings.object, String(_OBJECT))


def test_grammar_extended_absent() raises:
    var p = parse_narrow_note(
        _join(_fields(String("gz"), String("8388608"))))
    assert_true(p.ok)
    assert_equal(p.bindings.lc_object, String(""))
    assert_equal(p.bindings.lc_ring, String(""))
    assert_equal(p.bindings.cp_object, String(""))
    assert_equal(p.bindings.cp_ring, String(""))


def test_grammar_extended_field_count() raises:
    var ten = _fields12()
    var cut = List[String]()
    for i in range(10):
        cut.append(ten[i])
    var p = parse_narrow_note(_join(cut))
    assert_true(not p.ok)
    assert_equal(p.message, String("narrow note: want 8 or 12 fields"))


def _tail(text: String, start: Int) -> String:
    var out = String("")
    var raw = text.as_bytes()
    for i in range(start, len(raw)):
        out += String(text[byte=i])
    return out^


def _head(text: String, end: Int) -> String:
    var out = String("")
    for i in range(end):
        out += String(text[byte=i])
    return out^


def test_grammar_extended_values() raises:
    var fields = _fields12()
    fields[8] = (
        String("lc_object=sha256:zz")
        + _tail(String(_LC_OBJECT), 2)
    )
    var p = parse_narrow_note(_join(fields))
    assert_true(not p.ok)
    assert_equal(p.message, String("narrow note: bad lc_object"))
    fields = _fields12()
    fields[9] = String("lc_ring_bytes=abc")
    var q = parse_narrow_note(_join(fields))
    assert_true(not q.ok)
    assert_equal(q.message, String("narrow note: bad lc_ring_bytes"))
    fields = _fields12()
    fields[10] = (
        String("cp_object=sha256:") + _head(String(_CP_OBJECT), 62)
    )
    var r = parse_narrow_note(_join(fields))
    assert_true(not r.ok)
    assert_equal(r.message, String("narrow note: bad cp_object"))
    fields = _fields12()
    fields[11] = String("cp_ring_bytes=0")
    var s = parse_narrow_note(_join(fields))
    assert_true(not s.ok)
    assert_equal(s.message, String("narrow note: bad cp_ring_bytes"))


def test_check_extra_unwanted() raises:
    var parsed = parse_narrow_note(
        _join(_fields(String("gz"), String("8388608"))))
    assert_true(parsed.ok)
    var v = check_narrow_extra(
        parsed.bindings, NarrowLive(), False, False)
    assert_equal(v.state, String("bound"))
    assert_equal(v.key, String(""))


def test_check_extra_absent_binding() raises:
    var parsed = parse_narrow_note(
        _join(_fields(String("gz"), String("8388608"))))
    assert_true(parsed.ok)
    var live = _live_extra(
        String(_LC_OBJECT), String("8388608"),
        String(_CP_OBJECT), String("8388608"))
    var v = check_narrow_extra(parsed.bindings, live, True, False)
    assert_equal(v.state, String("mismatch"))
    assert_equal(v.key, String("lc_object"))
    var w = check_narrow_extra(parsed.bindings, live, False, True)
    assert_equal(w.state, String("mismatch"))
    assert_equal(w.key, String("cp_object"))


def test_check_extra_drift() raises:
    var parsed = parse_narrow_note(_join(_fields12()))
    assert_true(parsed.ok)
    var live = _live_extra(
        String("0") + _tail(String(_LC_OBJECT), 1),
        String("8388608"),
        String(_CP_OBJECT), String("8388608"))
    var v = check_narrow_extra(parsed.bindings, live, True, True)
    assert_equal(v.state, String("mismatch"))
    assert_equal(v.key, String("lc_object"))
    var live2 = _live_extra(
        String(_LC_OBJECT), String("8388608"),
        String(_CP_OBJECT), String("4096"))
    var w = check_narrow_extra(parsed.bindings, live2, True, True)
    assert_equal(w.state, String("mismatch"))
    assert_equal(w.key, String("cp_ring_bytes"))


def test_check_extra_bound() raises:
    var parsed = parse_narrow_note(_join(_fields12()))
    assert_true(parsed.ok)
    var live = _live_extra(
        String(_LC_OBJECT), String("8388608"),
        String(_CP_OBJECT), String("8388608"))
    var v = check_narrow_extra(parsed.bindings, live, True, True)
    assert_equal(v.state, String("bound"))
    assert_equal(v.key, String(""))


def test_object_tracing_ok() raises:
    var lc = _read_fixture(String("tests/fixtures/elf/lc-ok.o"))
    var a = verify_object_program(
        Span(lc), String("mv_map_result"), String("fexit/"))
    assert_true(a.ok)
    var b = verify_object_program(
        Span(lc), String("mv_unmap"), String("fentry/"))
    assert_true(b.ok)
    var cp = _read_fixture(String("tests/fixtures/elf/cp-ok.o"))
    for i in range(3):
        var names = List[String]()
        names.append(String("mv_sync_device"))
        names.append(String("mv_sync_cpu"))
        names.append(String("mv_bounce"))
        var v = verify_object_program(
            Span(cp), names[i], String("fentry/"))
        assert_true(v.ok)


def test_object_tracing_wrongsec() raises:
    var lc = _read_fixture(String("tests/fixtures/elf/lc-wrongsec.o"))
    var v = verify_object_program(
        Span(lc), String("mv_unmap"), String("fentry/"))
    assert_true(not v.ok)
    assert_equal(v.message, String("no fentry section"))
    var cp = _read_fixture(String("tests/fixtures/elf/cp-wrongsec.o"))
    var w = verify_object_program(
        Span(cp), String("mv_bounce"), String("fentry/"))
    assert_true(not w.ok)
    assert_equal(
        w.message,
        String(
            "program symbol unusable: program in kprobe/swiotlb_bounce"
        ),
    )


def test_object_bad_section_kind() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/ok.o"))
    var v = verify_object_program(
        Span(raw), String(_PROG), String("kprobe/"))
    assert_true(not v.ok)
    assert_equal(v.message, String("bad section kind"))


def test_object_kind_mismatch() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/ok.o"))
    var v = verify_object_program(
        Span(raw), String(_PROG), String("fentry/"))
    assert_true(not v.ok)
    assert_equal(v.message, String("no fentry section"))
    var lc = _read_fixture(String("tests/fixtures/elf/lc-ok.o"))
    var w = verify_object_program(
        Span(lc), String("mv_map_result"), String("tracepoint/"))
    assert_true(not w.ok)
    assert_equal(w.message, String("no tracepoint section"))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_grammar_valid]()
    suite.test[test_grammar_lengths]()
    suite.test[test_grammar_field_count]()
    suite.test[test_grammar_spacing]()
    suite.test[test_grammar_keys]()
    suite.test[test_grammar_values]()
    suite.test[test_grammar_ring]()
    suite.test[test_live_ok_root]()
    suite.test[test_live_nogz_root]()
    suite.test[test_live_none_root]()
    suite.test[test_check_bound]()
    suite.test[test_check_mismatch_keys]()
    suite.test[test_check_uncheckable_precedence]()
    suite.test[test_notes_vectors]()
    suite.test[test_notes_decoy_and_malformed]()
    suite.test[test_layout_ok]()
    suite.test[test_layout_drift]()
    suite.test[test_layout_missing]()
    suite.test[test_layout_badtype]()
    suite.test[test_layout_garbage]()
    suite.test[test_layout_inline_edges]()
    suite.test[test_object_ok]()
    suite.test[test_object_badarch]()
    suite.test[test_object_nosym]()
    suite.test[test_object_badsec]()
    suite.test[test_object_wrongsec]()
    suite.test[test_object_tiny]()
    suite.test[test_object_emptysec]()
    suite.test[test_object_zerosym]()
    suite.test[test_object_mapsrange]()
    suite.test[test_object_typemaps]()
    suite.test[test_grammar_extended_valid]()
    suite.test[test_grammar_extended_absent]()
    suite.test[test_grammar_extended_field_count]()
    suite.test[test_grammar_extended_values]()
    suite.test[test_check_extra_unwanted]()
    suite.test[test_check_extra_absent_binding]()
    suite.test[test_check_extra_drift]()
    suite.test[test_check_extra_bound]()
    suite.test[test_object_tracing_ok]()
    suite.test[test_object_tracing_wrongsec]()
    suite.test[test_object_bad_section_kind]()
    suite.test[test_object_kind_mismatch]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
