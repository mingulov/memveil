# SPDX-License-Identifier: GPL-3.0-or-later

"""Committed accounting under append and closing-record failures."""

from std.testing import TestSuite, assert_equal, assert_true
from memveil.capture.collector import Collector, CollectorConfig
from memveil.capture.pools import NormalizedPoolSample
from memveil.model.integrity import EMPTY_SHA256
from scripted import AppendFault, ScriptWriter, ScriptClock, ScriptSignal
from test_lifecycle_capture import _lc_raw, _cp_raw
from test_normalize import make_payload
from test_writer import _mkdtemp


def _raw() -> List[UInt8]:
    return [UInt8(123), UInt8(125), UInt8(10)]


def test_detail_append_failure_does_not_consume_sequence() raises:
    for kind in [
        "bounce_attempt",
        "map_result",
        "unmap",
        "copy",
        "sync_request",
    ]:
        for failure in ["refused", "append_failed", "fatal"]:
            var collector = Collector(CollectorConfig())
            var writer = ScriptWriter()
            var made = writer.create(_mkdtemp() + "/capture", 131072)
            assert_true(made.ok)
            writer.append_faults.append(AppendFault(1, failure))
            collector.next_seq = UInt64(1)
            _ = collector._persist_line(
                writer, _raw(), UInt64(1), UInt64(1), kind
            )
            assert_equal(collector.next_seq, UInt64(0))
            var snapshot = collector.committed_stream.snapshot()
            assert_equal(snapshot.events_bytes, UInt64(0))
            assert_equal(snapshot.line_count, UInt64(0))
            assert_equal(snapshot.events_sha256, String(EMPTY_SHA256))
            assert_equal(writer.committed_len(), 0)
            if failure == "fatal":
                assert_equal(collector.result_state, String("unfinalizable"))
            writer.discard()


def test_pool_append_failure_does_not_consume_sequence() raises:
    for failure in ["refused", "append_failed", "fatal"]:
        for closing in [False, True]:
            var collector = Collector(CollectorConfig())
            var writer = ScriptWriter()
            assert_true(writer.create(_mkdtemp() + "/capture", 131072).ok)
            writer.append_faults.append(AppendFault(1, failure))
            if closing:
                var pool = NormalizedPoolSample()
                pool.pool_id = String("default")
                pool.allocator = String("swiotlb")
                collector.persist_pool_sample(writer, pool, UInt64(1))
            else:
                collector.next_seq = UInt64(1)
                _ = collector._persist_pool_mid(writer, _raw(), UInt64(1))
            assert_equal(collector.next_seq, UInt64(0))
            assert_equal(
                collector.committed_stream.snapshot().events_sha256,
                String(EMPTY_SHA256),
            )
            assert_equal(writer.committed_len(), 0)
            if failure == "fatal":
                assert_equal(collector.result_state, String("unfinalizable"))
            writer.discard()


def test_closing_group_failure_restores_accounting() raises:
    for failed_at in range(1, 5):
        var collector = Collector(CollectorConfig())
        var writer = ScriptWriter()
        assert_true(writer.create(_mkdtemp() + "/capture", 131072).ok)
        collector.has_end_cut = True
        for _ in range(6):
            collector.start_vals.append(UInt64(0))
            collector.end_vals.append(UInt64(0))
        assert_true(collector.snapshots_eligible())
        writer.append_faults.append(
            AppendFault(failed_at, String("append_failed"))
        )
        assert_equal(collector.closing_records(writer), String(""))
        assert_equal(writer.committed_len(), 0)
        assert_equal(collector.next_seq, UInt64(0))
        assert_equal(
            collector.committed_stream.snapshot().events_sha256,
            String(EMPTY_SHA256),
        )
        assert_true(not collector.snapshots_present)
        writer.discard()


def test_closing_group_failed_rollback_is_unfinalizable() raises:
    var collector = Collector(CollectorConfig())
    var writer = ScriptWriter()
    assert_true(writer.create(_mkdtemp() + "/capture", 131072).ok)
    collector.has_end_cut = True
    for _ in range(6):
        collector.start_vals.append(UInt64(0))
        collector.end_vals.append(UInt64(0))
    assert_true(collector.snapshots_eligible())
    writer.append_faults.append(AppendFault(3, String("append_failed")))
    writer.abort_fault = True
    assert_equal(collector.closing_records(writer), String("unfinalizable"))
    assert_equal(collector.result_state, String("unfinalizable"))
    assert_true(writer.committed_len() > 0)
    assert_equal(collector.committed_stream.snapshot().line_count, UInt64(2))
    writer.discard()


def test_gap_fatal_append_poison_propagates() raises:
    var collector = Collector(CollectorConfig())
    var writer = ScriptWriter()
    assert_true(writer.create(_mkdtemp() + "/capture", 131072).ok)
    collector.unknown_cause = String("test gap")
    writer.append_faults.append(AppendFault(1, String("fatal")))
    assert_equal(collector.closing_records(writer), String("unfinalizable"))
    assert_equal(collector.result_state, String("unfinalizable"))
    assert_equal(collector.next_seq, UInt64(0))
    assert_equal(collector.committed_stream.snapshot().line_count, UInt64(0))
    writer.discard()


def test_closing_group_fatal_append_never_recovers() raises:
    for failed_at in range(1, 5):
        var collector = Collector(CollectorConfig())
        var writer = ScriptWriter()
        assert_true(writer.create(_mkdtemp() + "/capture", 131072).ok)
        collector.has_end_cut = True
        for _ in range(6):
            collector.start_vals.append(UInt64(0))
            collector.end_vals.append(UInt64(0))
        assert_true(collector.snapshots_eligible())
        writer.append_faults.append(AppendFault(failed_at, String("fatal")))
        assert_equal(collector.closing_records(writer), String("unfinalizable"))
        assert_equal(collector.result_state, String("unfinalizable"))
        assert_equal(
            collector.committed_stream.snapshot().line_count,
            UInt64(failed_at - 1),
        )
        writer.discard()


def test_closing_encode_failures_consume_no_sequence() raises:
    var cfg = CollectorConfig()
    var long_text = String("")
    for _ in range(65536):
        long_text += "x"
    cfg.profile_id = long_text
    for kind in ["pool_sample", "counter_snapshot", "gap"]:
        var collector = Collector(cfg)
        var writer = ScriptWriter()
        assert_true(writer.create(_mkdtemp() + "/capture", 131072).ok)
        if kind == "pool_sample":
            collector.persist_pool_sample(
                writer, NormalizedPoolSample(), UInt64(1)
            )
        elif kind == "counter_snapshot":
            collector.has_end_cut = True
            for _ in range(6):
                collector.start_vals.append(UInt64(0))
                collector.end_vals.append(UInt64(0))
            assert_true(collector.snapshots_eligible())
            _ = collector.closing_records(writer)
        else:
            collector.unknown_cause = String("test gap")
            _ = collector.closing_records(writer)
        assert_equal(collector.next_seq, UInt64(0))
        assert_equal(
            collector.committed_stream.snapshot().line_count, UInt64(0)
        )
        assert_equal(writer.committed_len(), 0)
        assert_true(collector.closing_error)
        writer.discard()


def test_detail_encoding_failure_consumes_no_sequence() raises:
    var cfg = CollectorConfig()
    for _ in range(65536):
        cfg.profile_id += "x"
    var payloads = List[List[UInt8]]()
    payloads.append(make_payload(UInt64(1), False, UInt64(1), [UInt8(100)]))
    payloads.append(
        _lc_raw(1, 1, 1, UInt64(1), UInt64(1), UInt64(1), UInt64(41))
    )
    payloads.append(
        _lc_raw(2, 1, 1, UInt64(2), UInt64(2), UInt64(1), UInt64(41))
    )
    payloads.append(
        _cp_raw(2, 3, 1, UInt64(3), UInt64(3), UInt64(1), UInt64(1), 0)
    )
    payloads.append(
        _cp_raw(1, 1, 1, UInt64(4), UInt64(4), UInt64(1), UInt64(0), 4)
    )
    for i in range(len(payloads)):
        var collector = Collector(cfg)
        var writer = ScriptWriter()
        assert_true(writer.create(_mkdtemp() + "/capture", 131072).ok)
        var clock = ScriptClock()
        var signal = ScriptSignal()
        var result = String("")
        if i == 0:
            result = collector._admit_attempt(
                payloads[i], clock, signal, writer, UInt64(1000)
            )
        elif i < 3:
            result = collector._admit_lifecycle(
                payloads[i], clock, signal, writer, UInt64(1000)
            )
        else:
            result = collector._admit_copy(
                payloads[i], clock, signal, writer, UInt64(1000)
            )
        assert_equal(result, String("unfinalizable"))
        assert_equal(collector.next_seq, UInt64(0))
        assert_equal(collector.rejected, UInt64(0))
        assert_equal(writer.appends, 0)
        assert_equal(
            collector.committed_stream.snapshot().line_count, UInt64(0)
        )
        writer.discard()


def test_admission_rejections_consume_no_sequence() raises:
    var payloads = List[List[UInt8]]()
    payloads.append(make_payload(UInt64(1), False, UInt64(1), [UInt8(255)]))
    payloads.append(
        _lc_raw(99, 1, 1, UInt64(1), UInt64(1), UInt64(1), UInt64(41))
    )
    payloads.append(
        _cp_raw(2, 0, 1, UInt64(3), UInt64(3), UInt64(1), UInt64(0), 1)
    )
    for i in range(len(payloads)):
        var collector = Collector(CollectorConfig())
        var writer = ScriptWriter()
        assert_true(writer.create(_mkdtemp() + "/capture", 131072).ok)
        var clock = ScriptClock()
        var signal = ScriptSignal()
        if i == 0:
            _ = collector._admit_attempt(
                payloads[i], clock, signal, writer, UInt64(1000)
            )
        elif i == 1:
            _ = collector._admit_lifecycle(
                payloads[i], clock, signal, writer, UInt64(1000)
            )
        else:
            _ = collector._admit_copy(
                payloads[i], clock, signal, writer, UInt64(1000)
            )
        assert_equal(collector.rejected, UInt64(1))
        assert_equal(collector.next_seq, UInt64(0))
        assert_equal(writer.appends, 0)
        assert_equal(
            collector.committed_stream.snapshot().line_count, UInt64(0)
        )
        writer.discard()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
