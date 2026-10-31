# SPDX-License-Identifier: GPL-3.0-or-later

"""Committed accounting under append and closing-record failures."""

from std.testing import TestSuite, assert_equal, assert_true
from memveil.capture.collector import Collector, CollectorConfig
from memveil.capture.pools import NormalizedPoolSample
from memveil.capture.correlation import CorrelationRegistry
from memveil.capture.lifecycle import (
    decode_lifecycle, decode_copy,
    normalize_lifecycle_event, normalize_copy_event,
)
from memveil.model.integrity import EMPTY_SHA256, Integrity, INTEGRITY_KIND_COUNT
from memveil.platform.reader import read_host_file
from scripted import AppendFault, ScriptWriter, ScriptClock, ScriptSignal
from test_lifecycle_capture import _lc_raw, _cp_raw
from test_normalize import make_payload
from test_writer import _mkdtemp


def _raw() -> List[UInt8]:
    return [UInt8(123), UInt8(125), UInt8(10)]


def _seed_prefix(
    mut collector: Collector, mut writer: ScriptWriter,
    mut clock: ScriptClock, mut signal: ScriptSignal, path: String,
) raises -> List[UInt8]:
    assert_true(writer.create(path, 131072).ok)
    assert_equal(collector._admit_attempt(
        make_payload(UInt64(1), False, UInt64(1), [UInt8(100)]),
        clock, signal, writer, UInt64(1000),
    ), String(""))
    assert_equal(collector.next_seq, UInt64(1))
    return read_host_file(path + "/events.ndjson", "events", 131072)


def _assert_prefix(
    collector: Collector, writer: ScriptWriter, path: String,
    prefix: List[UInt8], before: Integrity,
) raises:
    assert_true(len(prefix) > 0)
    assert_equal(collector.next_seq, before.line_count)
    assert_equal(writer.appends, 1)
    assert_equal(writer.committed_len(), len(prefix))
    assert_equal(
        read_host_file(path + "/events.ndjson", "events", 131072), prefix
    )
    var after = collector.committed_stream.snapshot()
    assert_equal(after.events_bytes, before.events_bytes)
    assert_equal(after.line_count, before.line_count)
    assert_equal(after.first_seq, before.first_seq)
    assert_equal(after.last_seq, before.last_seq)
    assert_equal(after.events_sha256, before.events_sha256)
    for i in range(INTEGRITY_KIND_COUNT):
        assert_equal(after.kinds[i], before.kinds[i])


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
        var collector = Collector(CollectorConfig())
        var writer = ScriptWriter()
        var clock = ScriptClock()
        var signal = ScriptSignal()
        var path = _mkdtemp() + "/capture"
        var prefix = _seed_prefix(collector, writer, clock, signal, path)
        var before = collector.committed_stream.snapshot()
        collector.cfg.profile_id = cfg.profile_id
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
        assert_equal(collector.rejected, UInt64(0))
        _assert_prefix(collector, writer, path, prefix, before)
        writer.discard()


def test_unknown_copy_normalization_preserves_committed_prefix() raises:
    for reason in [1, 2, 3, 5, 6]:
        var collector = Collector(CollectorConfig())
        var writer = ScriptWriter()
        var clock = ScriptClock()
        var signal = ScriptSignal()
        var path = _mkdtemp() + "/capture"
        var prefix = _seed_prefix(collector, writer, clock, signal, path)
        var before = collector.committed_stream.snapshot()
        var payload = _cp_raw(
            2, 0, 1, UInt64(2), UInt64(2), UInt64(1), UInt64(0), reason
        )
        # Decoding succeeds; UNKNOWN_COPY is a normalization refusal before
        # fill_source_hook. It is not a registry-normalization exception.
        var decoded = decode_copy(payload)
        var refused = False
        try:
            _ = normalize_copy_event(decoded)
        except e:
            assert_equal(e.reason, String("UNKNOWN_COPY"))
            assert_true(not e.fatal)
            refused = True
        assert_true(refused)
        assert_equal(collector._admit_copy(
            payload, clock, signal, writer, UInt64(1000)
        ), String(""))
        assert_equal(collector.rejected, UInt64(1))
        assert_true(collector.unknown_copy_first != "")
        _assert_prefix(collector, writer, path, prefix, before)
        writer.discard()


def test_wire_normalizers_satisfy_registry_input_contract() raises:
    # Wire normalizers construct every field checked by registry exceptions.
    # Exercise admitted hooks so a missing hook cannot bypass those checks.
    for seq in [UInt64(0), UInt64(18446744073709551615)]:
        for flags in [0, 1, 9]:
            var gen = UInt64(18446744073709551614) if flags == 1 else UInt64(0)
            var ev = normalize_lifecycle_event(decode_lifecycle(
                _lc_raw(1, flags, 1, seq, UInt64(1), UInt64(1), gen)
            ))
            assert_true(ev.map_result.operation_id != "")
            assert_true(ev.map_result.has_wire_generation)
            var registry = CorrelationRegistry()
            registry.admit_hook(ev.source_hook, "iova")
            _ = registry.normalize(ev^, "capture")
        for flags in range(8):
            var gen = UInt64(0) if flags & 4 else UInt64(1)
            var ev = normalize_lifecycle_event(decode_lifecycle(
                _lc_raw(2, flags, 1, seq, UInt64(1), UInt64(1), gen)
            ))
            assert_true(ev.unmap.has_wire_generation)
            assert_true(ev.unmap.has_wire_identity)
            var registry = CorrelationRegistry()
            registry.admit_hook(ev.source_hook, "iova")
            _ = registry.normalize(ev^, "capture")
        for kind in [1, 2]:
            for to_device in [0, 1]:
                var flags = to_device + (2 if kind == 2 else 0)
                var reason = 0 if kind == 2 else 4
                var ev = normalize_copy_event(decode_copy(_cp_raw(
                    kind, flags, 1, seq, UInt64(1), UInt64(1), UInt64(1), reason
                )))
                if kind == 1:
                    assert_true(ev.sync.operation_id != "")
                    assert_true(ev.sync.has_mapping_id)
                else:
                    assert_true(ev.copy.operation_id != "")
                var registry = CorrelationRegistry()
                registry.admit_hook(ev.source_hook, "iova")
                _ = registry.normalize(ev^, "capture")


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
