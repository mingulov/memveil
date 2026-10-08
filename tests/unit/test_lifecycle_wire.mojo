# SPDX-License-Identifier: GPL-3.0-or-later

"""Lifecycle/copy wire tests: MVLC/MVCP decode, effective rule, ledger.

Pins the shipping decode contract against bpf/include/memveil_events.h
(same check order, same reason vocabulary) plus the RR-01 canonical
cases: nested 4096+1024 copies -> 5120 effective, copy before a failed
mapping keeps 4096 copied with no successful mapping, request-only
sync invents nothing, clamped 4096 -> 1024, early return -> 0, and
reused numeric addresses yield distinct mapping generations.

The v1 wire carries no mapping identity, so the ledger never pairs a
map with an unmap: lifetimes stay explicitly unavailable and the open
estimate saturates instead of pairing.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.lifecycle import (
    CP_LEN,
    LC_LEN,
    DecodedCopy,
    DecodedLifecycle,
    LifecycleLedger,
    decode_copy,
    decode_lifecycle,
    effective_bytes,
)
from memveil.capture.normalize import DecodeError


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
            ktime: UInt64, size: UInt64) -> List[UInt8]:
    var out = _le32(0x434C564D)
    var tail = _le16(1) + _le16(kind) + _le16(flags) + _le16(dir)
    for b in tail:
        out.append(b)
    for b in _le64(seq) + _le64(ktime) + _le64(size):
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


def test_wire_lengths() raises:
    assert_equal(LC_LEN, 36)
    assert_equal(CP_LEN, 48)


def test_decode_lifecycle_map() raises:
    var d = decode_lifecycle(_lc_raw(1, 1, 1, UInt64(7), UInt64(9), UInt64(4096)))
    assert_equal(Int(d.kind), 1)
    assert_true(d.ok)
    assert_true(not d.skip_sync)
    assert_equal(Int(d.dir), 1)
    assert_equal(d.seq, UInt64(7))
    assert_equal(d.ktime, UInt64(9))
    assert_equal(d.size, UInt64(4096))


def test_decode_lifecycle_unmap_skip_sync() raises:
    var d = decode_lifecycle(_lc_raw(2, 3, 2, UInt64(8), UInt64(10), UInt64(1024)))
    assert_equal(Int(d.kind), 2)
    assert_true(d.ok)
    assert_true(d.skip_sync)
    assert_equal(Int(d.dir), 2)
    assert_equal(d.size, UInt64(1024))


def test_decode_copy_known() raises:
    var d = decode_copy(_cp_raw(2, 3, 1, UInt64(3), UInt64(4), UInt64(4096), UInt64(1024), 0))
    assert_equal(Int(d.kind), 2)
    assert_true(d.to_device)
    assert_true(d.known)
    assert_true(not d.clamped)
    assert_true(not d.early_zero)
    assert_equal(d.requested, UInt64(4096))
    assert_equal(d.effective, UInt64(1024))


def test_decode_sync_request() raises:
    var d = decode_copy(_cp_raw(1, 1, 2, UInt64(5), UInt64(6), UInt64(512), UInt64(0), 4))
    assert_equal(Int(d.kind), 1)
    assert_true(not d.known)
    assert_equal(Int(d.reason), 4)
    assert_equal(d.requested, UInt64(512))
    assert_equal(d.effective, UInt64(0))


def _expect_lc(raw: List[UInt8], want: String) raises:
    var raised = False
    try:
        _ = decode_lifecycle(raw)
    except e:
        raised = True
        assert_equal(e.reason, want)
    assert_true(raised)


def _expect_cp(raw: List[UInt8], want: String) raises:
    var raised = False
    try:
        _ = decode_copy(raw)
    except e:
        raised = True
        assert_equal(e.reason, want)
    assert_true(raised)


def test_lifecycle_rejections() raises:
    var good = _lc_raw(1, 1, 0, UInt64(1), UInt64(1), UInt64(1))
    var short = List[UInt8]()
    for i in range(35):
        short.append(good[i])
    _expect_lc(short^, String("PAY_SHORT"))
    good.append(UInt8(0))
    _expect_lc(good^, String("PAY_LONG"))
    var bad = _lc_raw(1, 1, 0, UInt64(1), UInt64(1), UInt64(1))
    bad[0] = UInt8(0)
    _expect_lc(bad^, String("PAY_MAGIC"))
    bad = _lc_raw(1, 1, 0, UInt64(1), UInt64(1), UInt64(1))
    bad[4] = UInt8(2)
    _expect_lc(bad^, String("PAY_VERSION"))
    bad = _lc_raw(3, 1, 0, UInt64(1), UInt64(1), UInt64(1))
    _expect_lc(bad^, String("PAY_KIND"))
    bad = _lc_raw(1, 4, 0, UInt64(1), UInt64(1), UInt64(1))
    _expect_lc(bad^, String("PAY_FLAGS"))
    bad = _lc_raw(1, 1, 3, UInt64(1), UInt64(1), UInt64(1))
    _expect_lc(bad^, String("PAY_DIR"))


def test_copy_rejections() raises:
    var good = _cp_raw(2, 2, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(8), 0)
    var short = List[UInt8]()
    for i in range(47):
        short.append(good[i])
    _expect_cp(short^, String("PAY_SHORT"))
    good.append(UInt8(0))
    _expect_cp(good^, String("PAY_LONG"))
    var bad = _cp_raw(2, 2, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(8), 0)
    bad[0] = UInt8(0)
    _expect_cp(bad^, String("PAY_MAGIC"))
    bad = _cp_raw(2, 2, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(8), 0)
    bad[4] = UInt8(2)
    _expect_cp(bad^, String("PAY_VERSION"))
    bad = _cp_raw(9, 2, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(8), 0)
    _expect_cp(bad^, String("PAY_KIND"))
    bad = _cp_raw(2, 16, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(8), 0)
    _expect_cp(bad^, String("PAY_FLAGS"))
    bad = _cp_raw(2, 2, 0, UInt64(1), UInt64(1), UInt64(8), UInt64(8), 0)
    _expect_cp(bad^, String("PAY_DIR"))
    bad = _cp_raw(2, 2, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(8), 5)
    _expect_cp(bad^, String("PAY_REASON"))
    bad = _cp_raw(2, 2, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(8), 1)
    _expect_cp(bad^, String("PAY_REASON"))
    bad = _cp_raw(1, 0, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(0), 0)
    _expect_cp(bad^, String("PAY_REASON"))
    bad = _cp_raw(2, 0, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(0), 0)
    _expect_cp(bad^, String("PAY_REASON"))
    bad = _cp_raw(2, 0, 1, UInt64(1), UInt64(1), UInt64(8), UInt64(0), 4)
    _expect_cp(bad^, String("PAY_REASON"))


def test_effective_rule() raises:
    var e = effective_bytes(UInt64(4096), Int64(0), UInt64(4096), False)
    assert_equal(e.effective, UInt64(0))
    assert_true(e.early_zero)
    assert_true(not e.clamped)
    e = effective_bytes(UInt64(4096), Int64(3072), UInt64(4096), True)
    assert_equal(e.effective, UInt64(1024))
    assert_true(e.clamped)
    e = effective_bytes(UInt64(1024), Int64(0), UInt64(4096), True)
    assert_equal(e.effective, UInt64(1024))
    assert_true(not e.clamped)
    e = effective_bytes(UInt64(100), Int64(-50), UInt64(100), True)
    assert_equal(e.effective, UInt64(100))
    assert_true(not e.clamped)
    e = effective_bytes(UInt64(4096), Int64(4096), UInt64(4096), True)
    assert_equal(e.effective, UInt64(0))
    assert_true(e.clamped)


def test_canonical_nested_copies() raises:
    var ledger = LifecycleLedger()
    var a = decode_copy(_cp_raw(2, 3, 1, UInt64(1), UInt64(1), UInt64(4096), UInt64(4096), 0))
    var b = decode_copy(_cp_raw(2, 3, 1, UInt64(2), UInt64(2), UInt64(1024), UInt64(1024), 0))
    ledger.note_copy(a)
    ledger.note_copy(b)
    assert_equal(ledger.copies_known, UInt64(2))
    assert_equal(ledger.copies_known_effective_bytes, UInt64(5120))


def test_canonical_copy_before_failed_map() raises:
    var ledger = LifecycleLedger()
    var cp = decode_copy(_cp_raw(2, 3, 1, UInt64(1), UInt64(1), UInt64(4096), UInt64(4096), 0))
    var mp = decode_lifecycle(_lc_raw(1, 0, 1, UInt64(1), UInt64(2), UInt64(4096)))
    ledger.note_copy(cp)
    ledger.note_lifecycle(mp)
    assert_equal(ledger.copies_known_effective_bytes, UInt64(4096))
    assert_equal(ledger.maps_ok, UInt64(0))
    assert_equal(ledger.maps_failed, UInt64(1))


def test_canonical_sync_invents_nothing() raises:
    var ledger = LifecycleLedger()
    var s = decode_copy(_cp_raw(1, 1, 1, UInt64(1), UInt64(1), UInt64(4096), UInt64(0), 4))
    ledger.note_copy(s)
    assert_equal(ledger.sync_requests, UInt64(1))
    assert_equal(ledger.copies_known, UInt64(0))
    assert_equal(ledger.copies_known_effective_bytes, UInt64(0))


def test_canonical_clamp_and_early_return() raises:
    var ledger = LifecycleLedger()
    var c = decode_copy(_cp_raw(2, 7, 1, UInt64(1), UInt64(1), UInt64(4096), UInt64(1024), 0))
    assert_true(c.clamped)
    ledger.note_copy(c)
    var z = decode_copy(_cp_raw(2, 11, 2, UInt64(2), UInt64(2), UInt64(512), UInt64(0), 0))
    assert_true(z.early_zero)
    ledger.note_copy(z)
    assert_equal(ledger.copies_known_effective_bytes, UInt64(1024))


def test_reuse_mints_distinct_generations() raises:
    var ledger = LifecycleLedger()
    var a = decode_lifecycle(_lc_raw(1, 1, 1, UInt64(11), UInt64(1), UInt64(4096)))
    var b = decode_lifecycle(_lc_raw(1, 1, 1, UInt64(12), UInt64(2), UInt64(4096)))
    var ga = ledger.note_lifecycle(a)
    var gb = ledger.note_lifecycle(b)
    assert_true(ga != gb)
    assert_true(ga != String(""))
    assert_true(gb != String(""))


def test_lifetimes_stay_unavailable() raises:
    var ledger = LifecycleLedger()
    var m = decode_lifecycle(_lc_raw(1, 1, 1, UInt64(1), UInt64(1), UInt64(8)))
    var u = decode_lifecycle(_lc_raw(2, 1, 1, UInt64(2), UInt64(2), UInt64(8)))
    _ = ledger.note_lifecycle(m)
    _ = ledger.note_lifecycle(u)
    assert_true(not ledger.lifetimes_available())
    assert_true(ledger.lifetimes_reason() != String(""))
    assert_equal(ledger.open_estimate(), UInt64(0))
    var lone = decode_lifecycle(_lc_raw(2, 1, 1, UInt64(3), UInt64(3), UInt64(8)))
    _ = ledger.note_lifecycle(lone)
    assert_equal(ledger.open_estimate(), UInt64(0))
    assert_equal(ledger.unmaps, UInt64(2))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_wire_lengths]()
    suite.test[test_decode_lifecycle_map]()
    suite.test[test_decode_lifecycle_unmap_skip_sync]()
    suite.test[test_decode_copy_known]()
    suite.test[test_decode_sync_request]()
    suite.test[test_lifecycle_rejections]()
    suite.test[test_copy_rejections]()
    suite.test[test_effective_rule]()
    suite.test[test_canonical_nested_copies]()
    suite.test[test_canonical_copy_before_failed_map]()
    suite.test[test_canonical_sync_invents_nothing]()
    suite.test[test_canonical_clamp_and_early_return]()
    suite.test[test_reuse_mints_distinct_generations]()
    suite.test[test_lifetimes_stay_unavailable]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
