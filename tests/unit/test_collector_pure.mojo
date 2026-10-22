# SPDX-License-Identifier: GPL-3.0-or-later

"""Pure collector unit tests: predicates, grammar, identities.

No sources, no writer, no clock: exact assertions on the
pure helpers the close-out machine is built from. The two
close-out timestamp tests drive one scripted startup or
shutdown each; everything else stays pure.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from scripted import (
    ScriptClock,
    ScriptKernel,
    ScriptSignal,
    ScriptWriter,
    snap_ok,
    stats_ok,
)
from memveil.capture.collector import (
    CNT_EMITTED,
    CNT_FLAGS,
    Collector,
    CollectorConfig,
    FLAG_ARGCNT,
    StatsOut,
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
        UInt64(3),
        UInt64(0),
        UInt64(4),
        UInt64(0),
        UInt64(1),
        UInt64(0),
    )
    assert_equal(
        got,
        String(
            "detail loss 11 (submit_fail=(1) malformed=(2)"
            " dropped=(0) recursion_missed=(3) size_omitted=(0)"
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
        String("unavailable"),
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
            " dropped=(0) recursion_missed=(unavailable)"
            " size_omitted=(0)"
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


def test_table_bad_cut_has_no_byte_coverage() raises:
    # One table-bad firing (unknown size): counts stay
    # coherent, but no requested-byte snapshot is
    # covered.
    var cut = List[UInt64]()
    cut.append(UInt64(1))
    cut.append(UInt64(0))
    cut.append(UInt64(0))
    cut.append(UInt64(0))
    cut.append(UInt64(1))
    cut.append(UInt64(32))
    assert_true(count_identity(cut))
    assert_true(counters_valid(cut))
    assert_false(byte_coverage_valid(cut))
    assert_true(submit_valid(cut))


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


def _argcnt_vals(flags: UInt64) -> List[UInt64]:
    var vals = List[UInt64]()
    vals.append(UInt64(10))
    vals.append(UInt64(100))
    vals.append(UInt64(9))
    vals.append(UInt64(90))
    vals.append(UInt64(1))
    vals.append(flags)
    return vals^


def _argcnt_start() -> StatsOut:
    return StatsOut(
        True, UInt64(0), UInt64(0), UInt64(0), UInt64(0),
        UInt64(0), String(""),
    )


def _argcnt_final() -> StatsOut:
    return StatsOut(
        True, UInt64(9), UInt64(9), UInt64(0), UInt64(0),
        UInt64(0), String(""),
    )


def test_evaluate_channel_argcnt_noted() raises:
    var collector = Collector(CollectorConfig())
    var vals = _argcnt_vals(FLAG_ARGCNT)
    assert_equal(vals[CNT_FLAGS], FLAG_ARGCNT)
    var out = collector._evaluate_channel(
        vals, True, _argcnt_start(), _argcnt_final(),
        String("lc"),
    )
    assert_equal(out, String(""))
    assert_equal(
        collector.unknown_cause,
        String("lc argument count mismatch"),
    )


def test_evaluate_channel_argcnt_precedes_identity() raises:
    var collector = Collector(CollectorConfig())
    var vals = _argcnt_vals(FLAG_ARGCNT)
    vals[CNT_EMITTED] = UInt64(5)
    var out = collector._evaluate_channel(
        vals, True, _argcnt_start(), _argcnt_final(),
        String("lc"),
    )
    assert_equal(out, String(""))
    assert_equal(
        collector.unknown_cause,
        String("lc argument count mismatch"),
    )
    var plain = Collector(CollectorConfig())
    var vals2 = _argcnt_vals(UInt64(0))
    vals2[CNT_EMITTED] = UInt64(5)
    var out2 = plain._evaluate_channel(
        vals2, True, _argcnt_start(), _argcnt_final(),
        String("lc"),
    )
    assert_equal(out2, String(""))
    assert_equal(
        plain.unknown_cause, String("lc kernel identity unproven")
    )


def _mkdtemp() raises -> String:
    var template = String("/tmp/memveil-collector-ts-XXXXXX")
    var buf = List[UInt8]()
    for b in template.as_bytes():
        buf.append(b)
    buf.append(UInt8(0))
    var p = external_call["mkdtemp", UInt64](Span(buf).unsafe_ptr())
    if p == UInt64(0):
        raise Error("mkdtemp failed")
    var raw = List[UInt8]()
    for i in range(len(buf)):
        if buf[i] == UInt8(0):
            break
        raw.append(buf[i])
    try:
        return String(from_utf8=Span(raw))
    except:
        raise Error("mkdtemp gave non-UTF8")


def _zero_snaps(mut kernel: ScriptKernel, channel: Int):
    var z = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap_at(channel, z.copy())
    kernel.add_snap_at(channel, z.copy())


def _zero_stats(mut kernel: ScriptKernel):
    var s = stats_ok(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    )
    kernel.add_stats(s.copy())


def test_ready_after_arm() raises:
    # Readiness lands after the copy arm: attach_ns < ready_ns
    # over strictly increasing scripted clock reads.
    var tmp = _mkdtemp()
    var cfg = CollectorConfig()
    cfg.output = tmp + String("/cap")
    cfg.max_events_bytes = 134217728
    cfg.profile_id = String("ts-probe")
    cfg.pid = 4242
    cfg.has_copy = True
    cfg.copy_ring_bytes = UInt32(8388608)
    var kernel = ScriptKernel()
    kernel.channels = 3
    _zero_snaps(kernel, 0)
    _zero_snaps(kernel, 2)
    _zero_stats(kernel)
    var s = stats_ok(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    )
    kernel.add_stats_at(0, s.copy())
    kernel.add_stats_at(2, s.copy())
    var clock = ScriptClock()
    clock.step = UInt64(1000)
    clock.add(UInt64(1000))
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    var collector = Collector(cfg^)
    var refusal = collector.startup(kernel, clock, signal, writer)
    assert_equal(refusal, String(""))
    assert_true(collector.attach_ns < collector.ready_ns)
    assert_equal(collector.attach_ns, UInt64(6000))
    assert_equal(collector.ready_ns, UInt64(7000))


def test_detach_begin_before_detach() raises:
    # The close-out window opens before it ends:
    # detach_begin_ns is the shutdown's first clock read and
    # detach_ns a later one.
    var tmp = _mkdtemp()
    var cfg = CollectorConfig()
    cfg.output = tmp + String("/cap")
    cfg.max_events_bytes = 134217728
    cfg.profile_id = String("ts-probe")
    cfg.pid = 4242
    var kernel = ScriptKernel()
    _zero_snaps(kernel, 0)
    _zero_stats(kernel)
    var clock = ScriptClock()
    clock.step = UInt64(1000)
    clock.add(UInt64(1000))
    var writer = ScriptWriter()
    var made = writer.create(tmp + String("/cap"), 134217728)
    assert_true(made.ok)
    var collector = Collector(cfg^)
    collector.stop_ctl.mark_ready()
    var result = collector.error_close(kernel, clock, writer)
    assert_true(collector.detach_begin_ns <= collector.detach_ns)
    assert_equal(collector.detach_begin_ns, UInt64(1000))
    assert_equal(collector.detach_ns, UInt64(2000))
    assert_true(result.exit_code != 0)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_ready_after_arm]()
    suite.test[test_detach_begin_before_detach]()
    suite.test[test_evaluate_channel_argcnt_noted]()
    suite.test[test_evaluate_channel_argcnt_precedes_identity]()
    suite.test[test_op_guard_boundary]()
    suite.test[test_detail_known_grammar]()
    suite.test[test_detail_unknown_grammar]()
    suite.test[test_aggregate_grammar]()
    suite.test[test_cut_and_identities]()
    suite.test[test_table_bad_cut_has_no_byte_coverage]()
    suite.test[test_checked_add]()
    suite.test[test_env_mapping]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
