# SPDX-License-Identifier: GPL-3.0-or-later

"""Canonical encoder unit tests: exact bytes, not vibes.

Every scalar and representative kinds assert the exact JSON
string. Full-corpus fidelity (parse/encode/reparse struct
equality over every fixture) runs in the writer lane via
tests/unit/roundtrip_check.mojo.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.model.encode import (
    EncodeError,
    encode_event,
    encode_session,
    format_i64,
    quote_json,
)
from memveil.model.event import Event, parse_event
from memveil.model.regions import RegionObservation
from memveil.model.session import Session, parse_session


def _bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        out.append(raw[i])
    return out^


def _string(data: List[UInt8]) raises -> String:
    try:
        return String(from_utf8=Span(data))
    except:
        raise Error("bad utf-8 in test helper")


def _control_string() raises -> String:
    var raw = List[UInt8]()
    raw.append(UInt8(0x00))
    raw.append(UInt8(0x01))
    raw.append(UInt8(0x1F))
    raw.append(UInt8(0x7F))
    return _string(raw)


def test_quote_ascii() raises:
    assert_equal(quote_json(String("abc")), String("\"abc\""))
    assert_equal(quote_json(String("")), String("\"\""))


def test_quote_specials() raises:
    assert_equal(
        quote_json(String("a\"b\\c")), String("\"a\\\"b\\\\c\"")
    )


def test_quote_shorts() raises:
    var raw = List[UInt8]()
    raw.append(UInt8(0x08))
    raw.append(UInt8(0x09))
    raw.append(UInt8(0x0A))
    raw.append(UInt8(0x0C))
    raw.append(UInt8(0x0D))
    assert_equal(
        quote_json(_string(raw)), String("\"\\b\\t\\n\\f\\r\"")
    )


def test_quote_controls() raises:
    var del_raw = List[UInt8]()
    del_raw.append(UInt8(0x7F))
    var delete = _string(del_raw)
    assert_equal(
        quote_json(_control_string()),
        String("\"\\u0000\\u0001\\u001f") + delete + String("\""),
    )


def test_quote_utf8() raises:
    assert_equal(quote_json(String("é")), String("\"é\""))


def test_format_i64() raises:
    assert_equal(format_i64(Int64(0)), String("0"))
    assert_equal(format_i64(Int64(42)), String("42"))
    assert_equal(format_i64(Int64(-1)), String("-1"))
    assert_equal(
        format_i64(Int64(9223372036854775807)),
        String("9223372036854775807"),
    )
    var lo = Int64(-9223372036854775807) - Int64(1)
    assert_equal(format_i64(lo), String("-9223372036854775808"))


def _base_event() -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = UInt64(7)
    ev.ts_ns = UInt64(123)
    ev.source_hook = String("h")
    ev.source_backend = String("tracepoint")
    ev.source_profile_id = String("p")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    return ev^


def test_bounce_exact() raises:
    var ev = _base_event()
    ev.kind = String("bounce_attempt")
    ev.bounce.device_id = String("d000001")
    ev.bounce.requested_bytes = UInt64(1500)
    ev.bounce.forced = True
    ev.bounce.operation_id = String("op7")
    assert_equal(
        encode_event(ev),
        String(
            "{\"schema_version\":\"0.1.0\",\"session_id\":\"s1\","
            "\"seq\":\"7\",\"ts_ns\":\"123\",\"kind\":\"bounce_attempt\","
            "\"source\":{\"hook\":\"h\",\"backend\":\"tracepoint\","
            "\"profile_id\":\"p\",\"measurement\":\"observed\","
            "\"correlation\":\"direct\"},\"data\":{\"device_id\":"
            "\"d000001\",\"requested_bytes\":\"1500\",\"forced\":true,"
            "\"operation_id\":\"op7\"}}"
        ),
    )
    var back = parse_event(_bytes(encode_event(ev)))
    assert_equal(back.bounce.device_id, String("d000001"))
    assert_equal(back.bounce.requested_bytes, UInt64(1500))
    assert_true(back.bounce.forced)
    assert_equal(back.seq, UInt64(7))


def test_gap_null() raises:
    var ev = _base_event()
    ev.kind = String("gap")
    ev.gap.channel = String("detail")
    ev.gap.reason = String("why")
    ev.gap.window_start_ns = UInt64(1)
    ev.gap.window_end_ns = UInt64(2)
    assert_equal(
        encode_event(ev),
        String(
            "{\"schema_version\":\"0.1.0\",\"session_id\":\"s1\","
            "\"seq\":\"7\",\"ts_ns\":\"123\",\"kind\":\"gap\","
            "\"source\":{\"hook\":\"h\",\"backend\":\"tracepoint\","
            "\"profile_id\":\"p\",\"measurement\":\"observed\","
            "\"correlation\":\"direct\"},\"data\":{\"channel\":\"detail\","
            "\"lost_count\":null,\"reason\":\"why\","
            "\"window_start_ns\":\"1\",\"window_end_ns\":\"2\"}}"
        ),
    )
    var back = parse_event(_bytes(encode_event(ev)))
    assert_true(not back.gap.has_lost_count)


def test_snapshot_scopes() raises:
    var ev = _base_event()
    ev.kind = String("counter_snapshot")
    ev.snapshot.counter_id = String("swiotlb.bounce_attempts")
    ev.snapshot.epoch = UInt64(0)
    ev.snapshot.scope_profile_id = String("p")
    ev.snapshot.value = UInt64(9)
    ev.snapshot.unit = String("count")
    var global_text = encode_event(ev)
    assert_true(global_text.find(String("\"scope\":{\"profile_id\":\"p\"}")) != -1)
    ev.snapshot.has_scope_device = True
    ev.snapshot.scope_device_id = String("d000001")
    var scoped = encode_event(ev)
    assert_true(
        scoped.find(
            String(
                "\"scope\":{\"device_id\":\"d000001\","
                "\"profile_id\":\"p\"}"
            )
        )
        != -1
    )
    var back = parse_event(_bytes(scoped))
    assert_true(back.snapshot.has_scope_device)
    assert_equal(back.snapshot.value, UInt64(9))


def test_observer() raises:
    var ev = _base_event()
    ev.kind = String("marker")
    ev.marker.text = String("m")
    ev.has_observer = True
    ev.has_cpu = True
    ev.cpu = Int64(3)
    ev.has_comm = True
    ev.comm = String("pc")
    var text = encode_event(ev)
    assert_true(
        text.find(
            String(
                "\"observer_context\":{\"cpu\":3,\"comm\":\"pc\","
                "\"relation\":\"execution_context_only\"}"
            )
        )
        != -1
    )
    var back = parse_event(_bytes(text))
    assert_true(back.has_observer)
    assert_equal(back.cpu, Int64(3))
    assert_true(not back.has_pid)


def test_map_nulls() raises:
    var ev = _base_event()
    ev.kind = String("map_result")
    ev.map_result.operation_id = String("op1")
    ev.map_result.success = False
    var text = encode_event(ev)
    assert_true(
        text.find(
            String(
                "\"mapping_id\":null,\"return_code\":null,"
                "\"mapped_bytes\":null"
            )
        )
        != -1
    )
    var back = parse_event(_bytes(text))
    assert_true(not back.map_result.has_mapping_id)


def test_unknown_kind() raises:
    var ev = _base_event()
    ev.kind = String("nope")
    var raised = False
    try:
        _ = encode_event(ev)
    except e:
        raised = True
        assert_equal(e.what, String("kind"))
    assert_true(raised)


def _base_session() -> Session:
    var s = Session()
    s.session_id = String("s1")
    s.synthetic = False
    s.product_version = String("0.0.0")
    s.env_mode = String("unknown")
    s.env_detection = String("unverified")
    s.env_attestation = String("not_performed")
    s.capture_mode = String("live")
    s.window_start_ns = UInt64(10)
    s.window_end_ns = UInt64(20)
    s.finalized = True
    s.baseline_complete = False
    s.cap_bounce_attempts.status = String("partial")
    s.cap_bounce_attempts.reason = String("r")
    s.cap_mapping_lifecycle.status = String("unavailable")
    s.cap_mapping_lifecycle.reason = String("r")
    s.cap_copy_bytes.status = String("unavailable")
    s.cap_copy_bytes.reason = String("r")
    s.cap_sync_requests.status = String("unavailable")
    s.cap_sync_requests.reason = String("r")
    s.cap_conversion_results.status = String("unavailable")
    s.cap_conversion_results.reason = String("r")
    s.cap_region_state.status = String("unavailable")
    s.cap_region_state.reason = String("r")
    s.cap_pool_stats.status = String("unavailable")
    s.cap_pool_stats.reason = String("r")
    s.cap_task_context.status = String("unavailable")
    s.cap_task_context.reason = String("r")
    s.q_detail.status = String("complete_for_scope")
    s.q_detail.has_loss_count = True
    s.q_detail.loss_count = UInt64(0)
    s.q_detail.scope = String("sc")
    s.q_detail.reason = String("rs")
    s.q_aggregate.status = String("unavailable")
    s.q_aggregate.scope = String("sc")
    s.q_aggregate.reason = String("rs")
    s.q_correlation.status = String("not_applicable")
    s.q_correlation.scope = String("sc")
    s.q_correlation.reason = String("rs")
    s.q_baseline.status = String("not_applicable")
    s.q_baseline.scope = String("sc")
    s.q_baseline.reason = String("rs")
    s.q_terminal.status = String("partial")
    s.q_terminal.scope = String("sc")
    s.q_terminal.reason = String("rs")
    return s^


def test_session_roundtrip() raises:
    var s = _base_session()
    var text = encode_session(s)
    assert_true(
        text.find(String("\"name\":\"memveil\"")) != -1
    )
    assert_true(text.find(String("\"loss_count\":\"0\"")) != -1)
    var back = parse_session(_bytes(text))
    assert_equal(back.session_id, String("s1"))
    assert_true(back.q_detail.has_loss_count)
    assert_true(not back.has_boot_id)
    assert_equal(encode_session(back), text)


def test_session_regions_roundtrip() raises:
    var s = _base_session()
    s.baseline_complete = True
    s.baseline_region_count = 2
    var first = RegionObservation()
    first.region_id = String("r1")
    first.state = String("shared")
    first.offset = UInt64(0)
    first.length = UInt64(8192)
    first.address_space = String("guest_physical")
    first.provenance = String("seed-a")
    first.generation = 2
    var second = RegionObservation()
    second.region_id = String("r2")
    second.state = String("unknown")
    second.offset = UInt64(8192)
    second.length = UInt64(4096)
    second.address_space = String("iova")
    second.provenance = String("seed-b")
    s.baseline_regions.append(first^)
    s.baseline_regions.append(second^)
    var text = encode_session(s)
    assert_true(text.find(String('"region_id":"r1"')) != -1)
    assert_true(text.find(String('"length":"4096"')) != -1)
    assert_true(text.find(String('"generation":2')) != -1)
    assert_true(text.find(String('"generation":1')) != -1)
    var back = parse_session(_bytes(text))
    assert_equal(len(back.baseline_regions), 2)
    assert_equal(back.baseline_regions[0].region_id, String("r1"))
    assert_equal(back.baseline_regions[0].generation, 2)
    assert_equal(back.baseline_regions[1].address_space, String("iova"))
    assert_equal(back.baseline_regions[1].generation, 1)
    assert_equal(encode_session(back), text)


def test_transition_exact() raises:
    var ev = _base_event()
    ev.kind = String("transition_result")
    ev.transition.region_id = String("r-1")
    ev.transition.requested_state = String("shared")
    ev.transition.success = True
    ev.transition.has_return_code = True
    ev.transition.return_code = Int64(0)
    ev.transition.offset = UInt64(0)
    ev.transition.length = UInt64(4096)
    ev.transition.has_address_space = True
    ev.transition.address_space = String("guest_physical")
    ev.transition.has_resolution = True
    ev.transition.resolution = String("resolved")
    ev.transition.generation = 2
    assert_equal(
        encode_event(ev),
        String(
            "{\"schema_version\":\"0.1.0\",\"session_id\":\"s1\","
            "\"seq\":\"7\",\"ts_ns\":\"123\",\"kind\":\"transition_result\","
            "\"source\":{\"hook\":\"h\",\"backend\":\"tracepoint\","
            "\"profile_id\":\"p\",\"measurement\":\"observed\","
            "\"correlation\":\"direct\"},\"data\":{\"region_id\":"
            "\"r-1\",\"requested_state\":\"shared\",\"success\":true,"
            "\"return_code\":0,\"offset\":\"0\",\"length\":\"4096\","
            "\"address_space\":\"guest_physical\",\"resolution\":"
            "\"resolved\",\"generation\":2}}"
        ),
    )
    var back = parse_event(_bytes(encode_event(ev)))
    assert_equal(back.transition.generation, 2)


def test_generation_sweep() raises:
    var vals = List[Int]()
    vals.append(1)
    vals.append(2)
    vals.append(3)
    vals.append(127)
    vals.append(128)
    vals.append(255)
    vals.append(256)
    vals.append(65535)
    vals.append(65536)
    vals.append(2147483647)
    vals.append(2147483648)
    vals.append(9223372036854775807)
    for i in range(len(vals)):
        var g = vals[i]
        var ev = _base_event()
        ev.kind = String("transition_result")
        ev.transition.region_id = String("r-1")
        ev.transition.requested_state = String("shared")
        ev.transition.success = True
        ev.transition.has_return_code = True
        ev.transition.return_code = Int64(0)
        ev.transition.offset = UInt64(0)
        ev.transition.length = UInt64(4096)
        ev.transition.generation = g
        var line = encode_event(ev)
        var back = parse_event(_bytes(line))
        assert_equal(back.transition.generation, g)
        assert_equal(encode_event(back), line)
        var s = _base_session()
        s.baseline_complete = True
        s.baseline_region_count = 1
        var o = RegionObservation()
        o.region_id = String("r1")
        o.state = String("shared")
        o.offset = UInt64(0)
        o.length = UInt64(8192)
        o.address_space = String("guest_physical")
        o.provenance = String("sweep")
        o.generation = g
        s.baseline_regions.append(o^)
        var text = encode_session(s)
        var bs = parse_session(_bytes(text))
        assert_equal(len(bs.baseline_regions), 1)
        assert_equal(bs.baseline_regions[0].generation, g)
        assert_equal(encode_session(bs), text)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_quote_ascii]()
    suite.test[test_quote_specials]()
    suite.test[test_quote_shorts]()
    suite.test[test_quote_controls]()
    suite.test[test_quote_utf8]()
    suite.test[test_format_i64]()
    suite.test[test_bounce_exact]()
    suite.test[test_gap_null]()
    suite.test[test_snapshot_scopes]()
    suite.test[test_observer]()
    suite.test[test_map_nulls]()
    suite.test[test_transition_exact]()
    suite.test[test_generation_sweep]()
    suite.test[test_unknown_kind]()
    suite.test[test_session_roundtrip]()
    suite.test[test_session_regions_roundtrip]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
