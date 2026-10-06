"""Pure collector unit tests: predicates, grammar, identities.

No sources, no writer, no clock: exact assertions on the
pure helpers the close-out machine is built from.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from memveil.capture.collector import (
    aggregate_reason,
    all_zero,
    byte_coverage_valid,
    byte_identity,
    checked_add,
    count_identity,
    counters_valid,
    detail_reason_known,
    detail_reason_unknown,
    detection_for,
    env_mode_for,
    op_limited,
    stable_cut,
    submit_valid,
    u64_max,
)
from memveil.platform.evidence import GuestInfo


def test_op_guard_boundary() raises:
    assert_false(op_limited(UInt64(0)))
    assert_false(op_limited(UInt64(4194303)))
    assert_true(op_limited(UInt64(4194304)))
    assert_true(op_limited(UInt64(4194305)))
    assert_true(op_limited(u64_max()))


def test_detail_known_grammar() raises:
    var got = detail_reason_known(
        UInt64(1),
        UInt64(2),
        UInt64(0),
        UInt64(0),
        UInt64(4),
        UInt64(0),
        UInt64(1),
        UInt64(0),
    )
    assert_equal(
        got,
        String(
            "detail loss 8 (submit_fail=(1) malformed=(2)"
            " dropped=(0) size_omitted=(0)"
            " duration_omitted=(4) signal_omitted=(0)"
            " rejected=(1) write_failed=(0))"
        ),
    )


def test_detail_unknown_grammar() raises:
    var got = detail_reason_unknown(
        String("drain budget exhausted"),
        String("unavailable"),
        String("3"),
        String("0"),
        UInt64(0),
        UInt64(9),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    assert_equal(
        got,
        String(
            "detail loss unknown (drain budget exhausted;"
            + " known: submit_fail=(unavailable) malformed=(3)"
            " dropped=(0) size_omitted=(0)"
            " duration_omitted=(9) signal_omitted=(0)"
            " rejected=(0) write_failed=(0))"
        ),
    )


def test_aggregate_grammar() raises:
    assert_equal(
        aggregate_reason(True, String("")),
        String(
            "counter snapshots present (valid cut, identity"
            " holds, coverage valid)"
        ),
    )
    assert_equal(
        aggregate_reason(False, String("no stable cut")),
        String("counter snapshots absent (no stable cut)"),
    )


def test_cut_and_identities() raises:
    var zeros = List[UInt64]()
    var ones = List[UInt64]()
    for _ in range(6):
        zeros.append(UInt64(0))
        ones.append(UInt64(1))
    assert_true(stable_cut(zeros, zeros))
    assert_false(stable_cut(zeros, ones))
    var short = List[UInt64]()
    short.append(UInt64(0))
    assert_false(stable_cut(zeros, short))
    assert_true(all_zero(zeros))
    assert_false(all_zero(ones))
    # O=2 E=1 S=1: identity holds.
    var good = List[UInt64]()
    good.append(UInt64(2))
    good.append(UInt64(10))
    good.append(UInt64(1))
    good.append(UInt64(6))
    good.append(UInt64(1))
    good.append(UInt64(0))
    assert_true(count_identity(good))
    assert_true(counters_valid(good))
    assert_true(byte_coverage_valid(good))
    assert_true(submit_valid(good))
    assert_true(byte_identity(good))
    # Paused-before-byte-update: O=2 E=1 S=0 breaks it.
    var paused = List[UInt64]()
    paused.append(UInt64(2))
    paused.append(UInt64(10))
    paused.append(UInt64(1))
    paused.append(UInt64(6))
    paused.append(UInt64(0))
    paused.append(UInt64(0))
    assert_false(count_identity(paused))
    assert_true(counters_valid(paused))
    assert_true(byte_coverage_valid(paused))
    # Submit wrap poisons the count epoch only.
    var wrapped = List[UInt64]()
    wrapped.append(UInt64(7))
    wrapped.append(UInt64(70))
    wrapped.append(UInt64(5))
    wrapped.append(UInt64(50))
    wrapped.append(UInt64(2))
    wrapped.append(UInt64(16))
    assert_true(count_identity(wrapped))
    assert_false(counters_valid(wrapped))
    assert_false(byte_coverage_valid(wrapped))
    assert_false(submit_valid(wrapped))
    # Byte coverage bit poisons bytes, not counts.
    var covered = List[UInt64]()
    covered.append(UInt64(2))
    covered.append(UInt64(0))
    covered.append(UInt64(0))
    covered.append(UInt64(0))
    covered.append(UInt64(2))
    covered.append(UInt64(32))
    assert_true(count_identity(covered))
    assert_true(counters_valid(covered))
    assert_false(byte_coverage_valid(covered))
    assert_true(submit_valid(covered))
    # Observed bytes below emitted bytes is incoherent.
    var incoherent = List[UInt64]()
    incoherent.append(UInt64(3))
    incoherent.append(UInt64(4))
    incoherent.append(UInt64(3))
    incoherent.append(UInt64(9))
    incoherent.append(UInt64(0))
    incoherent.append(UInt64(0))
    assert_false(byte_identity(incoherent))
    assert_false(byte_coverage_valid(incoherent))


def test_checked_add() raises:
    var top = u64_max()
    assert_equal(checked_add(UInt64(2), UInt64(3)), UInt64(5))
    assert_equal(checked_add(top, UInt64(1)), top)
    assert_equal(checked_add(top, top), top)
    assert_equal(checked_add(UInt64(0), UInt64(0)), UInt64(0))


def test_env_mapping() raises:
    var signals = List[String]()
    signals.append(String("sev_snp:cc_blob"))
    var snp = GuestInfo(String("snp"), signals.copy(), False, String(""))
    assert_equal(env_mode_for(snp), String("sev_snp"))
    assert_equal(detection_for(snp), String("kernel_reported"))
    var ordinary = GuestInfo(
        String("ordinary"), List[String](), False, String("")
    )
    assert_equal(env_mode_for(ordinary), String("none"))
    assert_equal(detection_for(ordinary), String("kernel_reported"))
    var unknown = GuestInfo(
        String("unknown"), List[String](), False, String("")
    )
    assert_equal(env_mode_for(unknown), String("unknown"))
    assert_equal(detection_for(unknown), String("unverified"))
    var conflicted = GuestInfo(
        String("tdx"), List[String](), False, String("dmi vs msr")
    )
    assert_equal(env_mode_for(conflicted), String("tdx"))
    assert_equal(detection_for(conflicted), String("conflicting"))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_op_guard_boundary]()
    suite.test[test_detail_known_grammar]()
    suite.test[test_detail_unknown_grammar]()
    suite.test[test_aggregate_grammar]()
    suite.test[test_cut_and_identities]()
    suite.test[test_checked_add]()
    suite.test[test_env_mapping]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
