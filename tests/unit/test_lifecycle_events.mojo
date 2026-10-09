# SPDX-License-Identifier: GPL-3.0-or-later

"""Lifecycle/copy Event normalization tests.

Pins the v1 wire-to-Event mapping: minted record-local
operation/mapping ids, per-probe hook names, copy direction
from the to_device flag, sync offset/length, and the unknown
copy refusal (an unreplicated length is never persisted, not
even as zero).
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.lifecycle import (
    decode_copy,
    decode_lifecycle,
    normalize_copy_event,
    normalize_lifecycle_event,
)
from memveil.capture.normalize import NormalizeError


def _le16(v: Int) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8(v & 0xFF))
    out.append(UInt8((v >> 8) & 0xFF))
    return out^


def _le32(v: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(4):
        out.append(UInt8((v >> (8 * i)) & 0xFF))
    return out^


def _le64(v: UInt64) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(8):
        out.append(UInt8((v >> UInt64(8 * i)) & UInt64(0xFF)))
    return out^


def _lc_raw(kind: Int, flags: Int, dir: Int, seq: UInt64,
            ktime: UInt64, size: UInt64, gen: UInt64) -> List[UInt8]:
    var out = _le32(0x434C564D)
    var tail = _le16(2) + _le16(kind) + _le16(flags) + _le16(dir)
    for b in tail:
        out.append(b)
    for b in _le64(seq) + _le64(ktime) + _le64(size) + _le64(gen):
        out.append(b)
    return out^


def _cp_raw(kind: Int, flags: Int, dir: Int, seq: UInt64,
            ktime: UInt64, requested: UInt64, effective: UInt64,
            reason: Int) -> List[UInt8]:
    var out = _le32(0x5043564D)
    var tail = _le16(1) + _le16(kind) + _le16(flags) + _le16(dir)
    for b in tail:
        out.append(b)
    for b in _le64(seq) + _le64(ktime) + _le64(requested) + _le64(effective):
        out.append(b)
    for b in _le16(reason):
        out.append(b)
    out.append(UInt8(0))
    out.append(UInt8(0))
    return out^


def test_map_ok_event() raises:
    var d = decode_lifecycle(
        _lc_raw(1, 1, 1, UInt64(7), UInt64(9), UInt64(4096), UInt64(7)))
    var ev = normalize_lifecycle_event(d)
    assert_equal(ev.kind, String("map_result"))
    assert_equal(ev.ts_ns, UInt64(9))
    assert_equal(
        ev.source_hook, String("fexit:swiotlb_tbl_map_single"))
    assert_equal(ev.source_backend, String("tracing"))
    assert_equal(ev.map_result.operation_id, String("lc-7"))
    assert_true(ev.map_result.success)
    assert_true(ev.map_result.has_mapping_id)
    assert_equal(ev.map_result.mapping_id, String("gen-7"))
    assert_true(not ev.map_result.has_return_code)
    assert_true(ev.map_result.has_mapped_bytes)
    assert_equal(ev.map_result.mapped_bytes, UInt64(4096))
    assert_true(ev.map_result.has_wire_generation)
    assert_equal(ev.map_result.wire_generation, UInt64(7))
    assert_true(ev.map_result.has_wire_identity)
    assert_equal(ev.map_result.wire_identity, String("known"))


def test_map_failed_event_carries_no_mapping() raises:
    var d = decode_lifecycle(
        _lc_raw(1, 0, 1, UInt64(11), UInt64(12), UInt64(4096), UInt64(0)))
    var ev = normalize_lifecycle_event(d)
    assert_equal(ev.kind, String("map_result"))
    assert_equal(ev.map_result.operation_id, String("lc-11"))
    assert_true(not ev.map_result.success)
    assert_true(not ev.map_result.has_mapping_id)
    assert_true(not ev.map_result.has_mapped_bytes)
    assert_true(ev.map_result.has_wire_generation)
    assert_true(not ev.map_result.has_wire_identity)


def test_unmap_event() raises:
    var d = decode_lifecycle(
        _lc_raw(2, 3, 2, UInt64(8), UInt64(10), UInt64(1024), UInt64(8)))
    var ev = normalize_lifecycle_event(d)
    assert_equal(ev.kind, String("unmap"))
    assert_equal(ev.ts_ns, UInt64(10))
    assert_equal(
        ev.source_hook,
        String("fentry:__swiotlb_tbl_unmap_single"))
    assert_equal(ev.source_backend, String("tracing"))
    assert_true(ev.unmap.has_mapping_id)
    assert_equal(ev.unmap.mapping_id, String("gen-8"))
    assert_true(ev.unmap.has_wire_generation)
    assert_equal(ev.unmap.wire_generation, UInt64(8))
    assert_true(ev.unmap.has_wire_identity)
    assert_equal(ev.unmap.wire_identity, String("known"))


def test_unassigned_map_event_carries_no_mapping() raises:
    var d = decode_lifecycle(
        _lc_raw(1, 9, 1, UInt64(13), UInt64(14), UInt64(4096), UInt64(0)))
    var ev = normalize_lifecycle_event(d)
    assert_equal(ev.kind, String("map_result"))
    assert_true(ev.map_result.success)
    assert_true(not ev.map_result.has_mapping_id)
    assert_true(ev.map_result.has_mapped_bytes)
    assert_true(ev.map_result.has_wire_generation)
    assert_true(ev.map_result.has_wire_identity)
    assert_equal(ev.map_result.wire_identity, String("unassigned"))


def test_missed_unmap_event_carries_no_mapping() raises:
    var d = decode_lifecycle(
        _lc_raw(2, 5, 1, UInt64(15), UInt64(16), UInt64(4096), UInt64(0)))
    var ev = normalize_lifecycle_event(d)
    assert_equal(ev.kind, String("unmap"))
    assert_true(not ev.unmap.has_mapping_id)
    assert_true(ev.unmap.has_wire_generation)
    assert_true(ev.unmap.has_wire_identity)
    assert_equal(ev.unmap.wire_identity, String("miss"))


def test_known_copy_event() raises:
    var d = decode_copy(
        _cp_raw(2, 3, 1, UInt64(3), UInt64(4), UInt64(4096),
                UInt64(1024), 0))
    var ev = normalize_copy_event(d)
    assert_equal(ev.kind, String("copy"))
    assert_equal(ev.ts_ns, UInt64(4))
    assert_equal(
        ev.source_hook, String("fentry:swiotlb_bounce"))
    assert_equal(ev.source_backend, String("tracing"))
    assert_equal(ev.copy.operation_id, String("lc-3"))
    assert_true(not ev.copy.has_mapping_id)
    assert_equal(ev.copy.direction, String("original_to_bounce"))
    assert_equal(ev.copy.bytes, UInt64(1024))


def test_copy_from_device_direction() raises:
    var d = decode_copy(
        _cp_raw(2, 2, 2, UInt64(25), UInt64(26), UInt64(2048),
                UInt64(2048), 0))
    var ev = normalize_copy_event(d)
    assert_equal(ev.copy.direction, String("bounce_to_original"))
    assert_equal(ev.copy.bytes, UInt64(2048))


def test_clamped_copy_keeps_effective() raises:
    var d = decode_copy(
        _cp_raw(2, 7, 1, UInt64(21), UInt64(22), UInt64(4096),
                UInt64(1024), 0))
    var ev = normalize_copy_event(d)
    assert_equal(ev.copy.bytes, UInt64(1024))


def test_early_zero_copy_persists_proved_zero() raises:
    var d = decode_copy(
        _cp_raw(2, 11, 2, UInt64(23), UInt64(24), UInt64(512),
                UInt64(0), 0))
    var ev = normalize_copy_event(d)
    assert_equal(ev.kind, String("copy"))
    assert_equal(ev.copy.bytes, UInt64(0))


def test_unknown_copy_refuses() raises:
    var d = decode_copy(
        _cp_raw(2, 0, 1, UInt64(27), UInt64(28), UInt64(4096),
                UInt64(0), 1))
    var raised = False
    try:
        _ = normalize_copy_event(d)
    except e:
        raised = True
        assert_equal(e.reason, String("UNKNOWN_COPY"))
        assert_true(not e.fatal)
    assert_true(raised)


def test_sync_for_device_event() raises:
    var d = decode_copy(
        _cp_raw(1, 1, 2, UInt64(5), UInt64(6), UInt64(512),
                UInt64(0), 4))
    var ev = normalize_copy_event(d)
    assert_equal(ev.kind, String("sync_request"))
    assert_equal(ev.ts_ns, UInt64(6))
    assert_equal(
        ev.source_hook,
        String("fentry:__swiotlb_sync_single_for_device"))
    assert_equal(ev.source_backend, String("tracing"))
    assert_equal(ev.sync.operation_id, String("lc-5"))
    assert_true(ev.sync.has_mapping_id)
    assert_equal(ev.sync.mapping_id, String("lc-5"))
    assert_true(not ev.sync.has_offset)
    assert_equal(ev.sync.length, UInt64(512))


def test_sync_for_cpu_event() raises:
    var d = decode_copy(
        _cp_raw(1, 0, 1, UInt64(29), UInt64(30), UInt64(256),
                UInt64(0), 4))
    var ev = normalize_copy_event(d)
    assert_equal(ev.kind, String("sync_request"))
    assert_equal(
        ev.source_hook,
        String("fentry:__swiotlb_sync_single_for_cpu"))
    assert_equal(ev.sync.length, UInt64(256))


def test_reuse_reports_distinct_event_ids() raises:
    var a = decode_lifecycle(
        _lc_raw(1, 1, 1, UInt64(121), UInt64(1), UInt64(4096), UInt64(41)))
    var b = decode_lifecycle(
        _lc_raw(1, 1, 1, UInt64(122), UInt64(2), UInt64(4096), UInt64(42)))
    var eva = normalize_lifecycle_event(a)
    var evb = normalize_lifecycle_event(b)
    assert_equal(eva.map_result.mapping_id, String("gen-41"))
    assert_equal(evb.map_result.mapping_id, String("gen-42"))
    assert_true(
        eva.map_result.mapping_id != evb.map_result.mapping_id)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
