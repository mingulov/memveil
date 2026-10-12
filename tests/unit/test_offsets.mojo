# SPDX-License-Identifier: GPL-3.0-or-later

"""Load-time trace-offset table: probe, validation, encoding."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.collector import (
    Collector,
    CollectorConfig,
    GeomOut,
    OpOut,
)
from memveil.platform.narrow import (
    MV_FIXED_MAX,
    MV_OFFSETS_TABLE_LEN,
    MV_OFF_TABLE_MAGIC,
    MV_OFF_TABLE_VERSION,
    encode_offsets_table,
    probe_trace_offsets,
    validate_table_extents,
)
from memveil.platform.reader import read_host_file

from scripted import (
    NullWriter,
    ScriptClock,
    ScriptKernel,
    ScriptSignal,
    snap_ok,
    stats_ok,
)


def _read_fixture(path: String) raises -> List[UInt8]:
    return read_host_file(path, String("fixture"), 67108864)


def _pin_line(ftype: String, name: String, off: Int, size: Int) -> String:
    return (
        String("field:")
        + ftype
        + String(" ")
        + name
        + String(";\toffset:")
        + String(off)
        + String(";\tsize:")
        + String(size)
        + String(";\tsigned:0;\n")
    )


def _pin_format(moved: Int) -> String:
    # The four pinned fields, intact except pin `moved`
    # (0 common_type, 1 dev_name, 2 size, 3 force), which
    # shifts to a collision-free offset.
    var offs = List[Int]()
    offs.append(0)
    offs.append(8)
    offs.append(32)
    offs.append(40)
    if moved == 0:
        offs[0] = 8
    elif moved == 1:
        offs[1] = 16
    elif moved == 2:
        offs[2] = 48
    else:
        offs[3] = 56
    var out = _pin_line(
        String("unsigned short"), String("common_type"), offs[0], 2
    )
    out += _pin_line(
        String("__data_loc char[]"), String("dev_name"), offs[1], 4
    )
    out += _pin_line(
        String("size_t"), String("size"), offs[2], 8
    )
    out += _pin_line(
        String("bool"), String("force"), offs[3], 1
    )
    return out^


def _full_pins(
    dev_off: Int, size_off: Int, force_off: Int
) -> String:
    # Pinned header plus the three tabled pins at chosen
    # offsets; fixed_end covers force.
    var out = _pin_line(
        String("unsigned short"), String("common_type"), 0, 2
    )
    out += _pin_line(
        String("unsigned char"), String("common_flags"), 2, 1
    )
    out += _pin_line(
        String("int"), String("common_pid"), 4, 4
    )
    out += _pin_line(
        String("__data_loc char[]"), String("dev_name"), dev_off, 4
    )
    out += _pin_line(String("u64"), String("dma_mask"), 16, 8)
    out += _pin_line(
        String("size_t"), String("size"), size_off, 8
    )
    out += _pin_line(
        String("bool"), String("force"), force_off, 1
    )
    return out^


def test_probe_pinned_layout_returns_pins() raises:
    var raw = _read_fixture(String("tests/fixtures/layout/ok.format"))
    var p = probe_trace_offsets(Span(raw))
    assert_true(p.ok)
    assert_equal(p.message, String(""))
    assert_true(not p.moved)
    assert_equal(p.loc_off, 8)
    assert_equal(p.size_off, 32)
    assert_equal(p.force_off, 40)
    assert_equal(p.fixed_end, 41)


def test_probe_each_pin_moved_admits_offset() raises:
    # Offset-only moves of the three tabled pins admit
    # with the probed offset; the common_type anchor
    # never moves.
    for i in range(1, 4):
        var body = _pin_format(i)
        var p = probe_trace_offsets(body.as_bytes())
        assert_true(p.ok)
        assert_true(p.moved)
        var want_loc = 8
        var want_size = 32
        var want_force = 40
        if i == 1:
            want_loc = 16
        elif i == 2:
            want_size = 48
        else:
            want_force = 56
        assert_equal(p.loc_off, want_loc)
        assert_equal(p.size_off, want_size)
        assert_equal(p.force_off, want_force)


def test_probe_retype_refuses() raises:
    # Same-width respellings refuse: type is the semantic
    # contract, not the width.
    var body = _pin_line(
        String("unsigned short"), String("common_type"), 0, 2
    )
    body += _pin_line(
        String("__data_loc char[]"), String("dev_name"), 8, 4
    )
    body += _pin_line(
        String("unsigned long"), String("size"), 32, 8
    )
    body += _pin_line(String("bool"), String("force"), 40, 1)
    var p = probe_trace_offsets(body.as_bytes())
    assert_true(not p.ok)
    assert_equal(
        p.message,
        String("field size: want type size_t, live unsigned long"),
    )
    var fbody = _pin_line(
        String("unsigned short"), String("common_type"), 0, 2
    )
    fbody += _pin_line(
        String("__data_loc char[]"), String("dev_name"), 8, 4
    )
    fbody += _pin_line(String("size_t"), String("size"), 32, 8)
    fbody += _pin_line(String("u8"), String("force"), 40, 1)
    var q = probe_trace_offsets(fbody.as_bytes())
    assert_true(not q.ok)
    assert_equal(
        q.message,
        String("field force: want type bool, live u8"),
    )


def test_probe_resize_refuses() raises:
    var body = _pin_line(
        String("unsigned short"), String("common_type"), 0, 2
    )
    body += _pin_line(
        String("__data_loc char[]"), String("dev_name"), 8, 4
    )
    body += _pin_line(String("size_t"), String("size"), 32, 4)
    body += _pin_line(String("bool"), String("force"), 40, 1)
    var p = probe_trace_offsets(body.as_bytes())
    assert_true(not p.ok)
    assert_equal(
        p.message, String("field size: want size 8, live size 4")
    )


def test_probe_missing_refuses() raises:
    var raw = _read_fixture(String("tests/fixtures/layout/missing.format"))
    var p = probe_trace_offsets(Span(raw))
    assert_true(not p.ok)
    assert_equal(p.message, String("missing field force"))


def test_probe_common_type_move_refuses() raises:
    var body = _pin_format(0)
    var p = probe_trace_offsets(body.as_bytes())
    assert_true(not p.ok)
    assert_equal(
        p.message,
        String("field common_type: want @0:2, live @8:2"),
    )


def test_probe_overlap_refuses() raises:
    # size moved onto the force byte: one field's bytes
    # would read as another's.
    var body = _full_pins(8, 40, 40)
    var p = probe_trace_offsets(body.as_bytes())
    assert_true(not p.ok)
    assert_equal(
        p.message, String("overlapping extents size and force")
    )


def test_probe_over_cap_refuses() raises:
    var body = _full_pins(8, 32, 200)
    var p = probe_trace_offsets(body.as_bytes())
    assert_true(not p.ok)
    assert_equal(
        p.message,
        String("field force extent @200:1 exceeds fixed cap 128"),
    )


def test_probe_extra_fields_admit() raises:
    # The drifted-layout fixture (extra field plus moved
    # pins) admits with probed offsets.
    var raw = _read_fixture(String("tests/fixtures/layout/moved.format"))
    var p = probe_trace_offsets(Span(raw))
    assert_true(p.ok)
    assert_true(p.moved)
    assert_equal(p.loc_off, 8)
    assert_equal(p.size_off, 40)
    assert_equal(p.force_off, 48)
    assert_equal(p.fixed_end, 49)


def test_probe_fixed_end_covers_unpinned() raises:
    # An unpinned fixed field past every pin still sets
    # the dynamic floor.
    var body = _full_pins(8, 32, 40)
    body += _pin_line(String("u64"), String("extra_tail"), 64, 8)
    var p = probe_trace_offsets(body.as_bytes())
    assert_true(p.ok)
    assert_true(not p.moved)
    assert_equal(p.fixed_end, 72)


def test_probe_late_data_loc_sets_floor() raises:
    # A __data_loc descriptor past every other field
    # still sets the dynamic floor: the descriptor is
    # a fixed u32 slot, not dynamic data.
    var body = _full_pins(120, 32, 40)
    var p = probe_trace_offsets(body.as_bytes())
    assert_true(p.ok)
    assert_true(p.moved)
    assert_equal(p.loc_off, 120)
    assert_equal(p.fixed_end, 124)


def test_probe_extra_descriptor_counts_toward_cap() raises:
    # An unpinned __data_loc descriptor is still a
    # fixed slot: past the cap it refuses.
    var body = _full_pins(8, 32, 40)
    body += _pin_line(
        String("__data_loc char[]"), String("extra_blob"), 200, 4
    )
    var p = probe_trace_offsets(body.as_bytes())
    assert_true(not p.ok)
    assert_equal(
        p.message,
        String("fixed region end 204 exceeds cap 128"),
    )


def test_validate_table_floor_covers_extents() raises:
    # A floor below any tabled extent refuses:
    # dynamic data would otherwise start inside a
    # fixed slot.
    assert_equal(
        validate_table_extents(8, 32, 40, 0),
        String("fixed region end 0 below dev_name extent @8:4"),
    )
    assert_equal(
        validate_table_extents(8, 32, 40, 12),
        String("fixed region end 12 below size extent @32:8"),
    )
    assert_equal(
        validate_table_extents(8, 32, 40, 40),
        String("fixed region end 40 below force extent @40:1"),
    )
    assert_equal(
        validate_table_extents(120, 32, 40, 124), String("")
    )


def test_probe_garbage_refuses() raises:
    var raw = _read_fixture(String("tests/fixtures/layout/garbage.format"))
    var p = probe_trace_offsets(Span(raw))
    assert_true(not p.ok)
    assert_equal(p.message, String("missing field common_type"))
    var bogus = String("field:bogus\n")
    var q = probe_trace_offsets(bogus.as_bytes())
    assert_true(not q.ok)
    assert_equal(q.message, String("format line unparseable"))
    var line = String(
        "field:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n"
    )
    var dup = line + line.copy()
    var w = probe_trace_offsets(dup.as_bytes())
    assert_true(not w.ok)
    assert_equal(w.message, String("duplicate field size"))


def test_validate_table_extents() raises:
    assert_equal(validate_table_extents(8, 32, 40, 41), String(""))
    assert_equal(
        validate_table_extents(0, 32, 40, 41),
        String("overlapping extents common_type and dev_name"),
    )
    assert_equal(
        validate_table_extents(8, 32, 40, 129),
        String("fixed region end 129 exceeds cap 128"),
    )
    assert_equal(
        validate_table_extents(8, 125, 40, 41),
        String("field size extent @125:8 exceeds fixed cap 128"),
    )


def test_encode_offsets_table_layout() raises:
    assert_equal(MV_FIXED_MAX, 128)
    assert_equal(MV_OFFSETS_TABLE_LEN, 24)
    assert_equal(MV_OFF_TABLE_VERSION, 1)
    var table = encode_offsets_table(8, 32, 40, 41)
    assert_equal(len(table), 24)
    # magic "MFO5" little-endian, version 1, reserved 0.
    assert_equal(table[0], UInt8(0x4D))
    assert_equal(table[1], UInt8(0x4D))
    assert_equal(table[2], UInt8(0x46))
    assert_equal(table[3], UInt8(0x35))
    assert_equal(table[4], UInt8(1))
    assert_equal(table[5], UInt8(0))
    assert_equal(table[6], UInt8(0))
    assert_equal(table[7], UInt8(0))
    assert_equal(table[8], UInt8(8))
    assert_equal(table[12], UInt8(32))
    assert_equal(table[16], UInt8(40))
    assert_equal(table[20], UInt8(41))
    for i in range(24):
        if (
            i == 0
            or i == 1
            or i == 2
            or i == 3
            or i == 4
            or i == 8
            or i == 12
            or i == 16
            or i == 20
        ):
            continue
        assert_equal(table[i], UInt8(0))
    assert_equal(MV_OFF_TABLE_MAGIC, 0x35464D4D)


def test_encode_offsets_negative_refuses() raises:
    var table = encode_offsets_table(-1, 32, 40, 41)
    assert_equal(len(table), 0)


def _arm_kernel(mut kernel: ScriptKernel):
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    kernel.add_stats(
        stats_ok(UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0))
    )


def _startup_config() -> CollectorConfig:
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(60)
    cfg.max_events_bytes = 134217728
    cfg.output = String("/tmp/memveil-offsets-probe")
    cfg.profile_id = String("offsets-probe")
    cfg.pid = 4242
    return cfg^


def test_install_success_carries_table_bytes() raises:
    var cfg = _startup_config()
    cfg.off_loc = 8
    cfg.off_size = 40
    cfg.off_force = 48
    cfg.off_fixed_end = 49
    var kernel = ScriptKernel()
    _arm_kernel(kernel)
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    var coll = Collector(cfg^)
    var reason = coll.startup(kernel, clock, signal, writer)
    assert_equal(reason, String(""))
    assert_equal(kernel.install_calls, 1)
    assert_equal(kernel.attach_calls, 1)
    var want = encode_offsets_table(8, 40, 48, 49)
    assert_equal(len(kernel.installed), len(want))
    for i in range(len(want)):
        assert_equal(kernel.installed[i], want[i])


def test_install_verify_mismatch_refuses() raises:
    var cfg = _startup_config()
    var kernel = ScriptKernel()
    _arm_kernel(kernel)
    kernel.install_out = OpOut(
        False, String("offsets verify mismatch")
    )
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    var coll = Collector(cfg^)
    var reason = coll.startup(kernel, clock, signal, writer)
    assert_equal(
        reason, String("install offsets: offsets verify mismatch")
    )
    assert_equal(kernel.install_calls, 1)
    assert_equal(kernel.attach_calls, 0)


def test_install_failure_before_attach() raises:
    var cfg = _startup_config()
    var kernel = ScriptKernel()
    _arm_kernel(kernel)
    kernel.install_out = OpOut(False, String("bridge lost"))
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    var coll = Collector(cfg^)
    var reason = coll.startup(kernel, clock, signal, writer)
    assert_equal(reason, String("install offsets: bridge lost"))
    assert_equal(kernel.install_calls, 1)
    assert_equal(kernel.attach_calls, 0)


def test_offsets_geometry_refused() raises:
    var cfg = _startup_config()
    var kernel = ScriptKernel()
    _arm_kernel(kernel)
    kernel.offsets_geom = GeomOut(
        True, UInt32(2), UInt32(4), UInt32(8), UInt32(1),
        String(""),
    )
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    var coll = Collector(cfg^)
    var reason = coll.startup(kernel, clock, signal, writer)
    assert_equal(reason, String("map mv_offsets geometry"))
    assert_equal(kernel.install_calls, 0)
    assert_equal(kernel.attach_calls, 0)


def test_bad_config_offsets_refused() raises:
    var cfg = _startup_config()
    cfg.off_size = 40
    var kernel = ScriptKernel()
    _arm_kernel(kernel)
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    var coll = Collector(cfg^)
    var reason = coll.startup(kernel, clock, signal, writer)
    assert_equal(
        reason,
        String("install offsets: overlapping extents size and force"),
    )
    assert_equal(kernel.install_calls, 0)
    assert_equal(kernel.attach_calls, 0)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_probe_pinned_layout_returns_pins]()
    suite.test[test_probe_each_pin_moved_admits_offset]()
    suite.test[test_probe_retype_refuses]()
    suite.test[test_probe_resize_refuses]()
    suite.test[test_probe_missing_refuses]()
    suite.test[test_probe_common_type_move_refuses]()
    suite.test[test_probe_overlap_refuses]()
    suite.test[test_probe_over_cap_refuses]()
    suite.test[test_probe_extra_fields_admit]()
    suite.test[test_probe_fixed_end_covers_unpinned]()
    suite.test[test_probe_late_data_loc_sets_floor]()
    suite.test[test_probe_extra_descriptor_counts_toward_cap]()
    suite.test[test_validate_table_floor_covers_extents]()
    suite.test[test_probe_garbage_refuses]()
    suite.test[test_validate_table_extents]()
    suite.test[test_encode_offsets_table_layout]()
    suite.test[test_encode_offsets_negative_refuses]()
    suite.test[test_install_success_carries_table_bytes]()
    suite.test[test_install_verify_mismatch_refuses]()
    suite.test[test_install_failure_before_attach]()
    suite.test[test_offsets_geometry_refused]()
    suite.test[test_bad_config_offsets_refused]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
