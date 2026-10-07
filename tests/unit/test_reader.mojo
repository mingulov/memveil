# SPDX-License-Identifier: GPL-3.0-or-later

"""Reader unit tests: bounded JSON scanner, model validation, and
capture reader limits plus cross-record checks (A05)."""

from std.pathlib import Path
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.jsonscan import (
    Scanner,
    TAIL_COMPLETE,
    TAIL_INCOMPLETE,
    TAIL_INVALID,
    classify_tail,
)
from memveil.model.validate import (
    ValidationError,
    check_bounded_text,
    check_opaque_id,
    parse_u64,
)
from memveil.model.session import Session, parse_session
from memveil.model.event import Event, parse_event, partial_record_definitive
from memveil.capture.reader import (
    CaptureReader,
    ReadError,
    ReaderLimits,
    READ_IO,
    READ_TOO_BIG,
    READ_PARSE,
    READ_INVALID,
    default_limits,
    read_capture,
)


def drain_events(mut r: CaptureReader) raises ReadError -> List[Event]:
    var out = List[Event]()
    while r.has_more():
        out.append(r.next_event())
    return out^


def expect_read_error(
    dir: String,
    allow: Bool,
    limits: ReaderLimits,
    want_code: UInt32,
    want_line: Int,
) raises:
    var code = UInt32(0)
    var line = -1
    try:
        var r = read_capture(dir, allow, limits)
        _ = drain_events(r)
    except e:
        code = e.code
        line = e.line_no
    assert_equal(code, want_code)
    assert_equal(line, want_line)


def event_doc(kind: String, data: String) raises -> String:
    return String(
        '{"schema_version": "0.1.0", "session_id": "s1", "seq": "7",'
        ' "ts_ns": "50", "kind": "'
    ) + kind + String(
        '", "source": {"hook": "h", "backend": "b",'
        ' "profile_id": "p", "measurement": "observed",'
        ' "correlation": "direct"}, "data": '
    ) + data + String("}")


def first_line(rel: String) raises -> String:
    var text = Path(rel).read_text()
    var parts = text.split("\n")
    return String(parts[0])


def fixture_bytes(rel: String) raises -> List[UInt8]:
    return Path(rel).read_bytes()


def fixture_text(rel: String) raises -> String:
    return Path(rel).read_text()


def utf8_bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    return out^


def cut_last(text: String) -> List[UInt8]:
    var raw = text.as_bytes()
    var out = List[UInt8]()
    for i in range(len(raw) - 1):
        out.append(raw[i])
    return out^


def prefix_before(text: String, marker: String) raises -> List[UInt8]:
    var at = text.find(marker)
    assert_true(at > 0)
    var raw = text.as_bytes()
    var out = List[UInt8]()
    for i in range(at):
        out.append(raw[i])
    return out^


def cat_bytes(a: List[UInt8], b: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    for x in a:
        out.append(x)
    for x in b:
        out.append(x)
    return out^


def nth_line(rel: String, want: Int) raises -> String:
    var text = Path(rel).read_text()
    var parts = text.split("\n")
    var seen = 0
    for i in range(len(parts)):
        var chunk = String(parts[i])
        if chunk.byte_length() > 0:
            if seen == want:
                return chunk^
            seen += 1
    return String("")


def tail_chunk(rel: String) raises -> List[UInt8]:
    var text = Path(rel).read_text()
    var parts = text.split("\n")
    var i = len(parts) - 1
    while i >= 0:
        var chunk = String(parts[i])
        if chunk.byte_length() > 0:
            return utf8_bytes(chunk)
        i -= 1
    return List[UInt8]()


comptime ATTEMPTS_SESSION = "tests/fixtures/attempts/session.json"


def test_scan_string_basic() raises:
    var s = Scanner(String('"hi"'))
    assert_equal(s.parse_string(), "hi")
    assert_true(s.at_end())


def test_scan_string_escapes() raises:
    var s = Scanner(String('"a\\"b\\\\c\\/d\\be\\ff\\ng\\rh\\ti"'))
    assert_equal(s.parse_string(), "a\"b\\c/d\be\ff\ng\rh\ti")
    assert_true(s.at_end())


def test_scan_string_unicode_escape() raises:
    var s = Scanner(String('"\\u00e9"'))
    assert_equal(s.parse_string(), "é")
    var pair = Scanner(String('"\\ud83d\\ude00"'))
    assert_equal(pair.parse_string(), "😀")


def test_scan_string_bad_escape() raises:
    var cases = List[String]()
    cases.append(String('"\\x"'))
    cases.append(String('"\\ud800"'))
    cases.append(String('"\\udc00"'))
    cases.append(String('"\\u12"'))
    cases.append(String('"\\ud83d"'))
    cases.append(String('"abc'))
    for bad in cases:
        var raised = False
        try:
            var s = Scanner(bad)
            _ = s.parse_string()
        except:
            raised = True
        assert_true(raised)


def test_scan_string_rejects_control() raises:
    var raised = False
    try:
        var s = Scanner(String('"a\nb"'))
        _ = s.parse_string()
    except:
        raised = True
    assert_true(raised)


def test_scan_string_rejects_bad_utf8() raises:
    var buf = List[UInt8]()
    buf.append(UInt8(0x22))
    buf.append(UInt8(0xFF))
    buf.append(UInt8(0x22))
    var raised = False
    try:
        var s = Scanner(buf)
        _ = s.parse_string()
    except:
        raised = True
    assert_true(raised)


def test_scan_literals() raises:
    var s = Scanner(String(' \t\r\ntrue \nfalse\t null '))
    s.skip_ws()
    assert_true(s.parse_bool())
    s.skip_ws()
    assert_true(not s.parse_bool())
    s.skip_ws()
    s.parse_null()
    s.skip_ws()
    assert_true(s.at_end())


def test_scan_literals_reject() raises:
    var cases = List[String]()
    cases.append(String("tru"))
    cases.append(String("nul"))
    cases.append(String("True"))
    for bad in cases:
        var raised = False
        try:
            var s = Scanner(bad)
            s.skip_ws()
            if bad == String("nul"):
                s.parse_null()
            else:
                _ = s.parse_bool()
        except:
            raised = True
        assert_true(raised)


def test_scan_int() raises:
    var cases = List[String]()
    var wants = List[Int64]()
    cases.append(String("0"))
    wants.append(Int64(0))
    cases.append(String("-1"))
    wants.append(Int64(-1))
    cases.append(String("4194304"))
    wants.append(Int64(4194304))
    cases.append(String("9223372036854775807"))
    wants.append(Int64(9223372036854775807))
    cases.append(String("-9223372036854775808"))
    wants.append(Int64(-9223372036854775807) - Int64(1))
    for i in range(len(cases)):
        var s = Scanner(cases[i])
        assert_equal(s.parse_int(), wants[i])
        assert_true(s.at_end())


def test_scan_int_rejects() raises:
    var cases = List[String]()
    cases.append(String("01"))
    cases.append(String("+1"))
    cases.append(String("-"))
    cases.append(String("9223372036854775808"))
    cases.append(String("-9223372036854775809"))
    cases.append(String("99999999999999999999999"))
    cases.append(String(""))
    for bad in cases:
        var raised = False
        try:
            var s = Scanner(bad)
            _ = s.parse_int()
        except:
            raised = True
        assert_true(raised)


def test_scan_depth_boundary() raises:
    var deep = String("")
    for _ in range(64):
        deep += "["
    for _ in range(64):
        deep += "]"
    var s = Scanner(deep)
    for _ in range(64):
        s.begin_array()
    for _ in range(64):
        s.end_array()
    assert_true(s.at_end())
    var too_deep = String("")
    for _ in range(65):
        too_deep += "["
    var t = Scanner(too_deep)
    var raised = False
    try:
        for _ in range(65):
            t.begin_array()
    except:
        raised = True
    assert_true(raised)


def test_scan_expect_peek() raises:
    var s = Scanner(String("{"))
    assert_equal(s.peek(), UInt8(0x7B))
    s.expect_byte(UInt8(0x7B))
    var raised = False
    try:
        _ = s.peek()
    except:
        raised = True
    assert_true(raised)
    var t = Scanner(String("}"))
    raised = False
    try:
        t.expect_byte(UInt8(0x7B))
    except:
        raised = True
    assert_true(raised)


def test_u64_canonical() raises:
    assert_equal(parse_u64(String("0")), UInt64(0))
    assert_equal(parse_u64(String("42")), UInt64(42))
    assert_equal(
        parse_u64(String("18446744073709551615")),
        UInt64(0xFFFFFFFFFFFFFFFF),
    )


def test_u64_rejects() raises:
    var cases = List[String]()
    cases.append(String(""))
    cases.append(String("00"))
    cases.append(String("01"))
    cases.append(String("-1"))
    cases.append(String("+5"))
    cases.append(String("4x"))
    cases.append(String(" 42"))
    cases.append(String("18446744073709551616"))
    cases.append(String("99999999999999999999999"))
    var long = String("1")
    for _ in range(20):
        long += "1"
    cases.append(long)
    for bad in cases:
        var raised = False
        try:
            _ = parse_u64(bad)
        except:
            raised = True
        assert_true(raised)


def test_opaque_id() raises:
    check_opaque_id(String("a"))
    check_opaque_id(String("dev-1"))
    check_opaque_id(String("A_0.-x"))
    var max_id = String("a")
    for _ in range(127):
        max_id += "b"
    check_opaque_id(max_id)


def test_opaque_id_rejects() raises:
    var cases = List[String]()
    cases.append(String(""))
    cases.append(String("-abc"))
    cases.append(String(".x"))
    cases.append(String("a b"))
    cases.append(String("é"))
    cases.append(String("a/b"))
    var long = String("a")
    for _ in range(128):
        long += "b"
    cases.append(long)
    for bad in cases:
        var raised = False
        try:
            check_opaque_id(bad)
        except e:
            raised = True
        assert_true(raised)


def test_bounded_text_counts_codepoints() raises:
    var sixty_four = String("")
    for _ in range(64):
        sixty_four += "é"
    check_bounded_text(sixty_four, 1, 64, "probe")
    var raised = False
    try:
        check_bounded_text(sixty_four + "é", 1, 64, "probe")
    except:
        raised = True
    assert_true(raised)
    raised = False
    try:
        check_bounded_text(String(""), 1, 64, "probe")
    except:
        raised = True
    assert_true(raised)


def test_parse_session_attempts() raises:
    var s = parse_session(fixture_bytes(ATTEMPTS_SESSION))
    assert_equal(s.session_id, "attempts-3-session")
    assert_true(s.synthetic)
    assert_true(not s.has_boot_id)
    assert_equal(s.product_name, "memveil")
    assert_equal(s.product_version, "0.1.0")
    assert_true(not s.has_build)
    assert_equal(s.env_mode, "unknown")
    assert_equal(s.env_detection, "unverified")
    assert_true(not s.has_asserted_mode)
    assert_equal(s.env_attestation, "not_performed")
    assert_equal(len(s.evidence), 0)
    assert_equal(s.capture_mode, "synthetic")
    assert_equal(s.window_start_ns, UInt64(1000000000))
    assert_equal(s.window_end_ns, UInt64(4000000000))
    assert_true(not s.has_filter_device)
    assert_true(s.finalized)
    assert_true(s.has_end_reason)
    assert_equal(s.end_reason, "duration")
    assert_equal(len(s.devices), 1)
    assert_equal(s.devices[0].device_id, "dev-1")
    assert_equal(s.devices[0].name, "testdev0")
    assert_true(s.devices[0].has_driver)
    assert_equal(s.devices[0].driver, "synthetic-test")
    assert_equal(s.devices[0].identity_status, "resolved")
    assert_true(not s.baseline_complete)
    assert_equal(s.baseline_region_count, 0)
    assert_equal(s.cap_bounce_attempts.status, "verified")
    assert_equal(len(s.cap_bounce_attempts.hooks), 1)
    assert_equal(s.cap_bounce_attempts.hooks[0], "swiotlb:swiotlb_bounced")
    assert_true(s.cap_bounce_attempts.has_profile_id)
    assert_equal(s.cap_mapping_lifecycle.status, "unavailable")
    assert_equal(s.cap_task_context.status, "unavailable")
    assert_equal(s.q_detail.status, "complete_for_scope")
    assert_true(s.q_detail.has_loss_count)
    assert_equal(s.q_detail.loss_count, UInt64(0))
    assert_equal(s.q_aggregate.status, "unavailable")
    assert_true(not s.q_aggregate.has_loss_count)
    assert_equal(s.q_terminal.status, "complete_for_scope")


def test_session_missing_synthetic() raises:
    var raw = fixture_bytes(
        "tests/fixtures/negative/missing-synthetic.json"
    )
    assert_true(len(raw) > 0)
    var raised = False
    try:
        _ = parse_session(raw^)
    except e:
        raised = True
        assert_true(String(e).find(String("missing field")) != -1)
    assert_true(raised)


def test_session_rejects_shape() raises:
    var base = fixture_text(ATTEMPTS_SESSION)
    var cases = List[String]()
    cases.append(String("{oops"))
    cases.append(String(""))
    cases.append(String("[]"))
    cases.append(base + "]")
    cases.append(
        base.replace(
            String('"schema_version": "0.1.0"'),
            String('"schema_version": "0.2.0"'),
        )
    )
    cases.append(
        base.replace(String('"quality": {'), String('"zzz": 1, "quality": {'))
    )
    cases.append(
        base.replace(
            String('"session_id": "attempts-3-session",'),
            String(
                '"session_id": "attempts-3-session", "session_id": "x",'
            ),
        )
    )
    cases.append(
        base.replace(String('"task_context": {'), String('"task_context2": {'))
    )
    for bad in cases:
        var raised = False
        try:
            _ = parse_session(utf8_bytes(bad))
        except:
            raised = True
        assert_true(raised)


def test_session_window_bounds() raises:
    var base = fixture_text(ATTEMPTS_SESSION)
    var empty_ok = base.replace(
        String('"start_ns": "1000000000"'),
        String('"start_ns": "4000000000"'),
    )
    var s = parse_session(utf8_bytes(empty_ok))
    assert_equal(s.window_start_ns, s.window_end_ns)
    var bad = base.replace(
        String('"start_ns": "1000000000"'),
        String('"start_ns": "4000000001"'),
    )
    var raised = False
    try:
        _ = parse_session(utf8_bytes(bad))
    except:
        raised = True
    assert_true(raised)


def test_session_rejects_dup_device() raises:
    var base = fixture_text(ATTEMPTS_SESSION)
    var needle = String(
        '      {\n        "device_id": "dev-1",\n'
        '        "name": "testdev0",\n'
        '        "driver": "synthetic-test",\n'
        '        "identity_status": "resolved"\n      }'
    )
    var extra = String(
        needle
        + ',\n      {\n        "device_id": "dev-1",\n'
        + '        "name": "other",\n'
        + '        "driver": "synthetic-test",\n'
        + '        "identity_status": "resolved"\n      }'
    )
    var raised = False
    try:
        _ = parse_session(utf8_bytes(base.replace(needle, extra)))
    except:
        raised = True
    assert_true(raised)


def test_session_evidence_bound() raises:
    var base = fixture_text(ATTEMPTS_SESSION)
    var items = String("")
    for i in range(65):
        if i > 0:
            items += ", "
        items += '{"type": "t", "source": "s", "interpretation": "i"}'
    var bad = base.replace(String('"evidence": []'), String('"evidence": [') + items + "]")
    var raised = False
    try:
        _ = parse_session(utf8_bytes(bad))
    except:
        raised = True
    assert_true(raised)


def test_session_optionals() raises:
    var base = fixture_text(ATTEMPTS_SESSION)
    var with_boot = base.replace(
        String('"session_id": "attempts-3-session",'),
        String('"session_id": "attempts-3-session", "boot_id": "b1",'),
    )
    var s = parse_session(utf8_bytes(with_boot))
    assert_true(s.has_boot_id)
    assert_equal(s.boot_id, "b1")
    var null_reason = base.replace(
        String('"end_reason": "duration"'), String('"end_reason": null')
    )
    var t = parse_session(utf8_bytes(null_reason))
    assert_true(not t.has_end_reason)


def test_session_tristate_optionals() raises:
    var base = fixture_text(ATTEMPTS_SESSION)
    var s = parse_session(utf8_bytes(base))
    assert_true(s.asserted_mode_present)
    assert_true(not s.has_asserted_mode)
    assert_true(s.devices[0].driver_present)
    assert_true(s.devices[0].has_driver)
    assert_equal(s.devices[0].driver, "synthetic-test")
    var no_asserted = base.replace(
        String('    "asserted_mode": null,\n'), String("")
    )
    var a = parse_session(utf8_bytes(no_asserted))
    assert_true(not a.asserted_mode_present)
    assert_true(not a.has_asserted_mode)
    var sev = base.replace(
        String('"asserted_mode": null'), String('"asserted_mode": "sev"')
    )
    var v = parse_session(utf8_bytes(sev))
    assert_true(v.asserted_mode_present)
    assert_true(v.has_asserted_mode)
    assert_equal(v.asserted_mode, "sev")
    var no_driver = base.replace(
        String('        "driver": "synthetic-test",\n'), String("")
    )
    var d = parse_session(utf8_bytes(no_driver))
    assert_true(not d.devices[0].driver_present)
    assert_true(not d.devices[0].has_driver)
    var null_driver = base.replace(
        String('"driver": "synthetic-test"'), String('"driver": null')
    )
    var n = parse_session(utf8_bytes(null_driver))
    assert_true(n.devices[0].driver_present)
    assert_true(not n.devices[0].has_driver)


def test_session_rejects_empty_reason() raises:
    var base = fixture_text(ATTEMPTS_SESSION)
    var bad = base.replace(
        String(
            '"reason": "Fictional successful state for analyzer tests; this session is synthetic."'
        ),
        String('"reason": ""'),
    )
    var raised = False
    try:
        _ = parse_session(utf8_bytes(bad))
    except:
        raised = True
    assert_true(raised)


def test_session_retains_baseline_observations() raises:
    var base = fixture_text(ATTEMPTS_SESSION)
    var seeded = base.replace(
        String('"region_observations": []'),
        String(
            '"region_observations": [{"region_id": "r1", "state":'
            ' "shared", "offset": "0", "length": "8192",'
            ' "address_space": "guest_physical", "provenance":'
            ' "test-seed"}, {"region_id": "r2", "state": "unknown",'
            ' "offset": "8192", "length": "4096", "address_space":'
            ' "guest_physical", "provenance": "test-seed"}]'
        ),
    )
    var s = parse_session(utf8_bytes(seeded))
    assert_equal(s.baseline_region_count, 2)
    assert_equal(len(s.baseline_regions), 2)
    assert_equal(s.baseline_regions[0].region_id, "r1")
    assert_equal(s.baseline_regions[0].state, "shared")
    assert_equal(s.baseline_regions[0].offset, UInt64(0))
    assert_equal(s.baseline_regions[0].length, UInt64(8192))
    assert_equal(
        s.baseline_regions[0].address_space, "guest_physical"
    )
    assert_equal(s.baseline_regions[0].provenance, "test-seed")
    assert_equal(s.baseline_regions[1].region_id, "r2")
    assert_equal(s.baseline_regions[1].state, "unknown")
    var c = s.copy()
    assert_equal(len(c.baseline_regions), 2)
    assert_equal(c.baseline_regions[0].region_id, "r1")


def test_parse_event_bounce() raises:
    var line = first_line("tests/fixtures/attempts/events.ndjson")
    var e = parse_event(utf8_bytes(line))
    assert_equal(e.session_id, "attempts-3-session")
    assert_equal(e.seq, UInt64(1))
    assert_equal(e.ts_ns, UInt64(1100000000))
    assert_equal(e.kind, "bounce_attempt")
    assert_equal(e.source_hook, "swiotlb:swiotlb_bounced")
    assert_equal(e.source_backend, "synthetic")
    assert_equal(e.source_profile_id, "synthetic-attempts-1")
    assert_equal(e.source_measurement, "observed")
    assert_equal(e.source_correlation, "direct")
    assert_true(not e.has_observer)
    assert_equal(e.bounce.device_id, "dev-1")
    assert_equal(e.bounce.requested_bytes, UInt64(4096))
    assert_true(e.bounce.forced)
    assert_equal(e.bounce.operation_id, "op-1")


def test_parse_event_kinds() raises:
    var m = parse_event(
        utf8_bytes(
            event_doc(
                String("map_result"),
                String(
                    '{"operation_id": "op-1", "success": true,'
                    ' "mapping_id": "m-9", "return_code": 0,'
                    ' "mapped_bytes": "8192"}'
                ),
            )
        )
    )
    assert_equal(m.kind, "map_result")
    assert_true(m.map_result.success)
    assert_true(m.map_result.has_mapping_id)
    assert_equal(m.map_result.mapping_id, "m-9")
    assert_true(m.map_result.has_return_code)
    assert_equal(m.map_result.return_code, Int64(0))
    assert_equal(m.map_result.mapped_bytes, UInt64(8192))
    var u = parse_event(
        utf8_bytes(event_doc(String("unmap"), String('{"mapping_id": null}')))
    )
    assert_equal(u.kind, "unmap")
    assert_true(not u.unmap.has_mapping_id)
    var c = parse_event(
        utf8_bytes(
            event_doc(
                String("copy"),
                String(
                    '{"operation_id": "op-2", "mapping_id": "m-9",'
                    ' "direction": "bounce_to_original", "bytes": "512"}'
                ),
            )
        )
    )
    assert_equal(c.copy.direction, "bounce_to_original")
    assert_equal(c.copy.bytes, UInt64(512))
    var s = parse_event(
        utf8_bytes(
            event_doc(
                String("sync_request"),
                String(
                    '{"operation_id": "op-3", "mapping_id": null,'
                    ' "offset": "0", "length": "64"}'
                ),
            )
        )
    )
    assert_equal(s.sync.length, UInt64(64))
    var t = parse_event(
        utf8_bytes(
            event_doc(
                String("transition_result"),
                String(
                    '{"region_id": "r-1", "requested_state": "shared",'
                    ' "success": false, "return_code": -22,'
                    ' "offset": "4096", "length": "4096",'
                    ' "address_space": "iova", "resolution": "resolved"}'
                ),
            )
        )
    )
    assert_equal(t.transition.requested_state, "shared")
    assert_true(not t.transition.success)
    assert_equal(t.transition.return_code, Int64(-22))
    assert_equal(t.transition.address_space, "iova")
    var p = parse_event(
        utf8_bytes(
            event_doc(
                String("pool_sample"),
                String(
                    '{"pool_id": "pool-0", "used_bytes": "1024",'
                    ' "capacity_bytes": null, "unit": "bytes"}'
                ),
            )
        )
    )
    assert_equal(p.pool.used_bytes, UInt64(1024))
    assert_true(not p.pool.has_capacity)
    var g = parse_event(
        utf8_bytes(
            event_doc(
                String("gap"),
                String(
                    '{"channel": "detail", "lost_count": null,'
                    ' "reason": "ring full",'
                    ' "window_start_ns": "10", "window_end_ns": "20"}'
                ),
            )
        )
    )
    assert_equal(g.gap.channel, "detail")
    assert_true(not g.gap.has_lost_count)
    var k = parse_event(
        utf8_bytes(event_doc(String("marker"), String('{"text": "hi"}')))
    )
    assert_equal(k.marker.text, "hi")
    var n = parse_event(
        utf8_bytes(
            event_doc(
                String("counter_snapshot"),
                String(
                    '{"counter_id": "swiotlb.bounce_attempts",'
                    ' "epoch": "3",'
                    ' "scope": {"device_id": null,'
                    ' "profile_id": "synthetic-attempts-1"},'
                    ' "value": "13", "unit": "count"}'
                ),
            )
        )
    )
    assert_equal(n.snapshot.counter_id, "swiotlb.bounce_attempts")
    assert_equal(n.snapshot.epoch, UInt64(3))
    assert_true(not n.snapshot.has_scope_device)
    assert_equal(n.snapshot.value, UInt64(13))


def test_parse_event_observer() raises:
    var doc = event_doc(
        String("marker"), String('{"text": "m"}')
    ).replace(
        String('"data": '),
        String(
            '"observer_context": {"cpu": 3, "pid": 100, "comm": "x",'
            ' "relation": "execution_context_only"}, "data": '
        ),
    )
    var e = parse_event(utf8_bytes(doc))
    assert_true(e.has_observer)
    assert_true(e.has_cpu)
    assert_equal(e.cpu, Int64(3))
    assert_true(e.has_pid)
    assert_equal(e.pid, Int64(100))
    assert_true(e.has_comm)
    assert_true(not e.has_tgid)
    assert_true(not e.has_cgroup_id)


def test_partial_record_definitive() raises:
    var sid = String("attempts-3-session")
    var line = first_line("tests/fixtures/attempts/events.ndjson")
    assert_true(
        not partial_record_definitive(cut_last(line), sid)
    )
    assert_true(
        not partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"kind"')),
                utf8_bytes(String('"kind": "bou')),
            ),
            sid,
        )
    )
    assert_true(
        not partial_record_definitive(
            tail_chunk(
                "tests/fixtures/reader/partial-tail/events.ndjson"
            ),
            sid,
        )
    )
    assert_true(
        not partial_record_definitive(utf8_bytes(String("{")), sid)
    )
    var bad_version = line.replace(String('"0.1.0"'), String('"9.0.0"'))
    assert_true(partial_record_definitive(cut_last(bad_version), sid))
    assert_true(
        partial_record_definitive(
            cat_bytes(
                cut_last(line), utf8_bytes(String(', "seq": "9'))
            ),
            sid,
        )
    )
    assert_true(
        partial_record_definitive(
            utf8_bytes(String('{"zzz": "tru')), sid
        )
    )
    var bad_kind = line.replace(
        String('"bounce_attempt"'), String('"bogus"')
    )
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(bad_kind, String('"data"')),
                utf8_bytes(String('"data": {"device_id": "dev-1"')),
            ),
            sid,
        )
    )
    var bad_measure = line.replace(
        String('"measurement": "observed"'),
        String('"measurement": "bogus"'),
    )
    assert_true(
        partial_record_definitive(
            prefix_before(bad_measure, String('"data"')), sid
        )
    )
    assert_true(
        partial_record_definitive(utf8_bytes(String("tru")), sid)
    )
    assert_true(
        partial_record_definitive(utf8_bytes(String("[1,2")), sid)
    )
    var bad_session = line.replace(sid, String("someone-else-session"))
    assert_true(partial_record_definitive(cut_last(bad_session), sid))
    var missing_backend = line.replace(
        String(', "backend": "synthetic"'), String("")
    )
    assert_true(
        partial_record_definitive(
            prefix_before(missing_backend, String('"data"')), sid
        )
    )
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"data"')),
                utf8_bytes(
                    String('"data": {"device_id": "dev-1", "zzz": "tru')
                ),
            ),
            sid,
        )
    )
    var sync_line = nth_line(
        "tests/fixtures/reader/f3-span-sync/events.ndjson", 1
    )
    assert_true(sync_line.find(String("sync_request")) != -1)
    assert_true(
        partial_record_definitive(
            cut_last(sync_line), String("lifecycle-mini-session")
        )
    )
    assert_true(
        partial_record_definitive(
            utf8_bytes(
                String('{"schema_version": "0.1.0", "schema_version"')
            ),
            sid,
        )
    )
    assert_true(
        partial_record_definitive(
            utf8_bytes(String('{"unknown"')), sid
        )
    )
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"seq"')),
                utf8_bytes(String('"seq": tru')),
            ),
            sid,
        )
    )
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"forced"')),
                utf8_bytes(String('"forced": "tru')),
            ),
            sid,
        )
    )
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"source"')),
                utf8_bytes(String('"source": {"hook": tru')),
            ),
            sid,
        )
    )
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"data"')),
                utf8_bytes(String('"data": tru')),
            ),
            sid,
        )
    )
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"data"')),
                utf8_bytes(
                    String('"data": {"device_id": "dev-1", "device_id"')
                ),
            ),
            sid,
        )
    )
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"data"')),
                utf8_bytes(String('"data": {"zzz"')),
            ),
            sid,
        )
    )
    var life = String("lifecycle-mini-session")
    var unmap_line = nth_line(
        "tests/fixtures/lifecycle/events-ok.ndjson", 3
    )
    assert_true(unmap_line.find(String('"unmap"')) != -1)
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(unmap_line, String('"mapping_id"')),
                utf8_bytes(String('"mapping_id": tru')),
            ),
            life,
        )
    )
    assert_true(
        not partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"seq"')),
                utf8_bytes(String('"seq": "12')),
            ),
            sid,
        )
    )
    assert_true(
        not partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"forced"')),
                utf8_bytes(String('"forced": tru')),
            ),
            sid,
        )
    )
    assert_true(
        not partial_record_definitive(
            cat_bytes(
                prefix_before(unmap_line, String('"mapping_id"')),
                utf8_bytes(String('"mapping_id": nul')),
            ),
            life,
        )
    )
    assert_true(
        not partial_record_definitive(
            utf8_bytes(String('{"seq":')), sid
        )
    )
    assert_true(
        not partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"data"')),
                utf8_bytes(
                    String('"data": {"device_id": "dev-1",')
                    + String(' "requested_bytes": "40')
                ),
            ),
            sid,
        )
    )
    assert_true(
        not partial_record_definitive(
            cat_bytes(
                prefix_before(line, String('"data"')),
                utf8_bytes(String('"observer_context": {"cpu": 4')),
            ),
            sid,
        )
    )
    var map_line = nth_line(
        "tests/fixtures/lifecycle/events-ok.ndjson", 1
    )
    assert_true(map_line.find(String('"map_result"')) != -1)
    assert_true(
        not partial_record_definitive(
            cat_bytes(
                prefix_before(map_line, String('"return_code"')),
                utf8_bytes(String('"return_code": nul')),
            ),
            life,
        )
    )
    var snap_line = nth_line(
        "tests/fixtures/reader/f9-agree/events.ndjson", 3
    )
    assert_true(snap_line.find(String('"counter_snapshot"')) != -1)
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(snap_line, String('"scope"')),
                utf8_bytes(String('"scope": {"device_id": tru')),
            ),
            sid,
        )
    )
    assert_true(
        partial_record_definitive(
            cat_bytes(
                prefix_before(snap_line, String('"scope"')),
                utf8_bytes(String('"scope": {"profile_id": fal')),
            ),
            sid,
        )
    )
    assert_true(
        not partial_record_definitive(
            cat_bytes(
                prefix_before(snap_line, String('"scope"')),
                utf8_bytes(String('"scope": {"device_id": "dev')),
            ),
            sid,
        )
    )


def test_f12_hostile_member_not_echoed() raises:
    var line = first_line(
        "tests/fixtures/reader/unsanitized-error/events.ndjson"
    )
    assert_true(line.find(String("dummy_pin_0000")) != -1)
    var raised = False
    try:
        _ = parse_event(utf8_bytes(line))
    except e:
        raised = True
        var msg = String(e)
        assert_true(msg.find(String("dummy_pin_0000")) == -1)
        assert_true(msg.find(String("unknown event field")) != -1)
        for b in msg.as_bytes():
            assert_true(b != UInt8(0x1B))
    assert_true(raised)
    var reader = read_capture(
        String("tests/fixtures/reader/unsanitized-error"),
        False,
        default_limits(),
    )
    var reader_raised = False
    try:
        _ = drain_events(reader)
    except e:
        reader_raised = True
        var rmsg = String(e)
        assert_true(rmsg.find(String("dummy_pin_0000")) == -1)
        for b in rmsg.as_bytes():
            assert_true(b != UInt8(0x1B))
    assert_true(reader_raised)


def test_event_rejects_negatives() raises:
    var names = List[String]()
    names.append(String("tests/fixtures/negative/bad-kind.ndjson"))
    names.append(String("tests/fixtures/negative/bad-version.ndjson"))
    names.append(String("tests/fixtures/negative/dup-keys.ndjson"))
    names.append(String("tests/fixtures/negative/leading-zeros.ndjson"))
    names.append(String("tests/fixtures/negative/number-bytes.ndjson"))
    names.append(String("tests/fixtures/negative/overflow-bytes.ndjson"))
    var wants = List[String]()
    wants.append(String("unknown event kind"))
    wants.append(String("bad const"))
    wants.append(String("duplicate"))
    wants.append(String("leading zero"))
    wants.append(String("expected byte 34"))
    wants.append(String("overflow"))
    for i in range(len(names)):
        var line = first_line(names[i])
        assert_true(line.byte_length() > 0)
        var raised = False
        try:
            _ = parse_event(utf8_bytes(line))
        except e:
            raised = True
            assert_true(String(e).find(wants[i]) != -1)
        assert_true(raised)
    var foreign = parse_event(
        utf8_bytes(first_line("tests/fixtures/negative/foreign-session.ndjson"))
    )
    assert_equal(foreign.session_id, "someone-else-session")


def test_event_rejects_payload_rules() raises:
    var cases = List[String]()
    cases.append(
        event_doc(
            String("map_result"),
            String(
                '{"operation_id": "op-1", "success": true,'
                ' "mapping_id": null, "return_code": 0,'
                ' "mapped_bytes": "8"}'
            ),
        )
    )
    cases.append(
        event_doc(
            String("map_result"),
            String(
                '{"operation_id": "op-1", "success": false,'
                ' "mapping_id": null, "return_code": -12,'
                ' "mapped_bytes": "8"}'
            ),
        )
    )
    cases.append(
        event_doc(
            String("copy"),
            String(
                '{"operation_id": "op-1", "mapping_id": null,'
                ' "direction": "sideways", "bytes": "8"}'
            ),
        )
    )
    cases.append(
        event_doc(
            String("gap"),
            String(
                '{"channel": "side", "lost_count": "1",'
                ' "reason": "r",'
                ' "window_start_ns": "1", "window_end_ns": "2"}'
            ),
        )
    )
    cases.append(
        event_doc(
            String("transition_result"),
            String(
                '{"region_id": "r", "requested_state": "moist",'
                ' "success": true, "return_code": null,'
                ' "offset": "0", "length": "1"}'
            ),
        )
    )
    cases.append(event_doc(String("marker"), String('{"text": ""}')))
    cases.append(
        event_doc(
            String("pool_sample"),
            String(
                '{"pool_id": "p", "used_bytes": null,'
                ' "capacity_bytes": null, "unit": "litres"}'
            ),
        )
    )
    cases.append(
        event_doc(
            String("sync_request"),
            String(
                '{"operation_id": "op-1", "mapping_id": null,'
                ' "offset": "0"}'
            ),
        )
    )
    cases.append(
        event_doc(
            String("unmap"),
            String('{"mapping_id": null, "extra": 1}'),
        )
    )
    cases.append(
        event_doc(
            String("counter_snapshot"),
            String(
                '{"counter_id": "c", "epoch": "0",'
                ' "scope": {"device_id": null},'
                ' "value": "1", "unit": "count"}'
            ),
        )
    )
    for bad in cases:
        var raised = False
        try:
            _ = parse_event(utf8_bytes(bad))
        except:
            raised = True
        assert_true(raised)


def test_event_rejects_bad_observer() raises:
    var base = event_doc(String("marker"), String('{"text": "m"}'))
    var cases = List[String]()
    cases.append(
        base.replace(
            String('"data": '),
            String(
                '"observer_context": {"cpu": 1048576,'
                ' "relation": "execution_context_only"}, "data": '
            ),
        )
    )
    cases.append(
        base.replace(
            String('"data": '),
            String(
                '"observer_context": {"pid": 4194305,'
                ' "relation": "execution_context_only"}, "data": '
            ),
        )
    )
    var long_comm = String("")
    for _ in range(65):
        long_comm += "c"
    cases.append(
        base.replace(
            String('"data": '),
            String('"observer_context": {"comm": "') + long_comm
            + String('", "relation": "execution_context_only"}, "data": '),
        )
    )
    cases.append(
        base.replace(
            String('"data": '),
            String('"observer_context": {"relation": "owner"}, "data": '),
        )
    )
    cases.append(
        base.replace(
            String('"data": '),
            String(
                '"observer_context": {"relation": "execution_context_only",'
                ' "zzz": 1}, "data": '
            ),
        )
    )
    for bad in cases:
        var raised = False
        try:
            _ = parse_event(utf8_bytes(bad))
        except:
            raised = True
        assert_true(raised)


def test_read_attempts_capture() raises:
    var r = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    assert_equal(r.session.session_id, "attempts-3-session")
    assert_true(not r.partial)
    var events = drain_events(r)
    assert_equal(len(events), 3)
    assert_equal(events[0].seq, UInt64(1))
    assert_equal(events[1].seq, UInt64(2))
    assert_equal(events[2].seq, UInt64(3))
    assert_equal(events[0].bounce.requested_bytes, UInt64(4096))
    assert_equal(events[2].bounce.requested_bytes, UInt64(1024))
    assert_true(not r.has_more())


def test_reader_cross_record() raises:
    var limits = default_limits()
    expect_read_error(
        String("tests/fixtures/reader/foreign"), False, limits,
        READ_INVALID, 1,
    )
    expect_read_error(
        String("tests/fixtures/reader/badseq"), False, limits,
        READ_INVALID, 2,
    )
    expect_read_error(
        String("tests/fixtures/reader/ts-end"), False, limits,
        READ_INVALID, 1,
    )
    expect_read_error(
        String("tests/fixtures/reader/ts-start"), False, limits,
        READ_INVALID, 1,
    )
    expect_read_error(
        String("tests/fixtures/reader/badkind"), False, limits,
        READ_PARSE, 1,
    )


def test_reader_baseline_floor() raises:
    var old = parse_session(
        fixture_bytes(
            String("tests/fixtures/reader/counters-single/session.json")
        )
    )
    assert_true(not old.has_baseline_start_ns)
    var r = read_capture(
        String("tests/fixtures/reader/snap-baseline-ok"),
        False,
        default_limits(),
    )
    assert_true(r.session.has_baseline_start_ns)
    assert_equal(r.session.baseline_start_ns, UInt64(50))
    var events = drain_events(r)
    assert_equal(len(events), 3)
    var limits = default_limits()
    expect_read_error(
        String("tests/fixtures/reader/snap-baseline-low"), False,
        limits, READ_INVALID, 1,
    )
    expect_read_error(
        String("tests/fixtures/reader/obs-baseline-gap"), False,
        limits, READ_INVALID, 1,
    )
    expect_read_error(
        String("tests/fixtures/reader/baseline-after-window"), False,
        limits, READ_PARSE, 0,
    )


def test_reader_limits_exact() raises:
    var dir = String("tests/fixtures/attempts")
    var session_size = len(fixture_bytes(dir + "/session.json"))
    var events_size = len(fixture_bytes(dir + "/events.ndjson"))
    var first_record = (
        String(fixture_text(dir + "/events.ndjson").split("\n")[0])
    ).byte_length() + 1
    var ok = read_capture(
        dir,
        False,
        ReaderLimits(session_size, first_record, events_size),
    )
    assert_equal(len(drain_events(ok)), 3)
    expect_read_error(
        dir, False,
        ReaderLimits(session_size - 1, first_record, events_size),
        READ_TOO_BIG, 0,
    )
    expect_read_error(
        dir, False,
        ReaderLimits(session_size, first_record - 1, events_size),
        READ_TOO_BIG, 1,
    )
    expect_read_error(
        dir, False,
        ReaderLimits(session_size, first_record, events_size - 1),
        READ_TOO_BIG, 0,
    )


def test_reader_size_fixtures() raises:
    var limits = default_limits()
    expect_read_error(
        String("tests/fixtures/reader/size-ok"), False, limits,
        READ_PARSE, 1,
    )
    expect_read_error(
        String("tests/fixtures/reader/size-over"), False, limits,
        READ_TOO_BIG, 1,
    )


def test_reader_partial_tail() raises:
    var dir = String("tests/fixtures/reader/partial-tail")
    var limits = default_limits()
    expect_read_error(dir, False, limits, READ_PARSE, 3)
    var r = read_capture(dir, True, limits)
    var events = drain_events(r)
    assert_equal(len(events), 2)
    assert_true(r.partial)
    assert_true(not r.has_more())


def test_reader_partial_only_final() raises:
    expect_read_error(
        String("tests/fixtures/reader/interior-corrupt"), True,
        default_limits(), READ_PARSE, 2,
    )


def test_reader_corrupt_tail_not_recovered() raises:
    var dir = String("tests/fixtures/reader/corrupt-tail")
    expect_read_error(dir, False, default_limits(), READ_PARSE, 3)
    expect_read_error(dir, True, default_limits(), READ_PARSE, 3)


def test_reader_valid_no_newline_rejected() raises:
    var dir = String("tests/fixtures/reader/valid-no-newline")
    expect_read_error(dir, False, default_limits(), READ_PARSE, 3)
    expect_read_error(dir, True, default_limits(), READ_PARSE, 3)


def test_reader_tail_foreign_rejected() raises:
    var dir = String("tests/fixtures/reader/tail-foreign")
    expect_read_error(dir, False, default_limits(), READ_INVALID, 3)
    expect_read_error(dir, True, default_limits(), READ_INVALID, 3)


def test_reader_f2_identities() raises:
    var limits = default_limits()
    var base = String("tests/fixtures/reader/")
    expect_read_error(
        base + "f2-unknown-device", False, limits, READ_INVALID, 1
    )
    expect_read_error(
        base + "f2-unknown-snapshot-device", False, limits, READ_INVALID, 2
    )
    expect_read_error(
        base + "f2-duplicate-op", False, limits, READ_INVALID, 2
    )
    expect_read_error(
        base + "f2-duplicate-mapping", False, limits, READ_INVALID, 7
    )
    expect_read_error(
        base + "f2-early-unmap", False, limits, READ_INVALID, 1
    )
    expect_read_error(
        base + "f2-unknown-copy", False, limits, READ_INVALID, 3
    )
    expect_read_error(
        base + "f2-unknown-sync", False, limits, READ_INVALID, 9
    )
    expect_read_error(
        base + "f2-unknown-sync", True, limits, READ_INVALID, 9
    )
    expect_read_error(
        base + "f2-double-unmap", False, limits, READ_INVALID, 4
    )
    expect_read_error(
        base + "f2-contradictory-provenance", False, limits, READ_PARSE, 0
    )


def test_reader_f3_overflow() raises:
    var limits = default_limits()
    var base = String("tests/fixtures/reader/")
    expect_read_error(
        base + "f3-sum-overflow", False, limits, READ_INVALID, 2
    )
    expect_read_error(base + "f3-span-sync", False, limits, READ_PARSE, 2)
    expect_read_error(
        base + "f3-span-transition", False, limits, READ_PARSE, 2
    )
    expect_read_error(base + "f3-baseline", False, limits, READ_PARSE, 0)
    expect_read_error(base + "overflow", False, limits, READ_INVALID, 2)


def test_reader_f2_lifecycle_ok() raises:
    var r = read_capture(
        String("tests/fixtures/reader/f2-lifecycle-ok"), False,
        default_limits(),
    )
    assert_equal(len(drain_events(r)), 8)
    assert_true(not r.partial)
    var f = read_capture(
        String("tests/fixtures/reader/f2-forward-ref-ok"), False,
        default_limits(),
    )
    assert_equal(len(drain_events(f)), 4)
    assert_true(not f.partial)
    # Copies and syncs repeat freely under one operation; only
    # attempts and map results claim an operation once.
    var g = read_capture(
        String("tests/fixtures/reader/f2-repeat-copy-sync-ok"), False,
        default_limits(),
    )
    assert_equal(len(drain_events(g)), 8)
    assert_true(not g.partial)


def test_reader_multi_chunk() raises:
    var r = read_capture(
        String("tests/fixtures/reader/multi-chunk"), False, default_limits()
    )
    var events = drain_events(r)
    assert_equal(len(events), 400)
    assert_equal(events[0].seq, UInt64(1))
    assert_equal(events[399].seq, UInt64(400))
    assert_equal(events[399].ts_ns, UInt64(1400000000))
    assert_true(not r.partial)
    assert_true(not r.has_more())


def test_reader_missing() raises:
    var limits = default_limits()
    expect_read_error(
        String("tests/fixtures/reader/no-such-dir"), False, limits,
        READ_IO, 0,
    )
    expect_read_error(
        String("tests/fixtures/reader/missing-events"), False, limits,
        READ_IO, 0,
    )
    expect_read_error(
        String("tests/fixtures/reader/missing-session"), False, limits,
        READ_IO, 0,
    )


def test_reader_empty_and_crlf() raises:
    var limits = default_limits()
    var empty = read_capture(
        String("tests/fixtures/reader/empty-events"), False, limits
    )
    assert_equal(len(drain_events(empty)), 0)
    assert_true(not empty.partial)
    var crlf = read_capture(
        String("tests/fixtures/reader/crlf"), False, limits
    )
    assert_equal(len(drain_events(crlf)), 3)


def check_tail(text: String, want: Int) raises:
    assert_equal(classify_tail(utf8_bytes(text)), want)


def check_tail_bytes(raw: List[UInt8], want: Int) raises:
    assert_equal(classify_tail(raw), want)


def test_classify_tail() raises:
    check_tail(String("{}"), TAIL_COMPLETE)
    check_tail(String("[]"), TAIL_COMPLETE)
    check_tail(String("123"), TAIL_COMPLETE)
    check_tail(String("-0"), TAIL_COMPLETE)
    check_tail(String("-0.5e+3"), TAIL_COMPLETE)
    check_tail(String('"a"'), TAIL_COMPLETE)
    check_tail(String("true"), TAIL_COMPLETE)
    check_tail(String("false"), TAIL_COMPLETE)
    check_tail(String("null"), TAIL_COMPLETE)
    check_tail(String('  { "a" : [1, {"b": null}] }  '), TAIL_COMPLETE)
    check_tail(String('"caf\\u00e9"'), TAIL_COMPLETE)
    check_tail(String('"\\ud800"'), TAIL_COMPLETE)
    check_tail(String("{"), TAIL_INCOMPLETE)
    check_tail(String('{"a"'), TAIL_INCOMPLETE)
    check_tail(String('{"a":'), TAIL_INCOMPLETE)
    check_tail(String('{"a":1'), TAIL_INCOMPLETE)
    check_tail(String('{"a":1,'), TAIL_INCOMPLETE)
    check_tail(String("[1,"), TAIL_INCOMPLETE)
    check_tail(String('"abc'), TAIL_INCOMPLETE)
    check_tail(String('"a\\u12'), TAIL_INCOMPLETE)
    check_tail(String('"a\\'), TAIL_INCOMPLETE)
    check_tail(String("tru"), TAIL_INCOMPLETE)
    check_tail(String("fals"), TAIL_INCOMPLETE)
    check_tail(String("nul"), TAIL_INCOMPLETE)
    check_tail(String("-"), TAIL_INCOMPLETE)
    check_tail(String("1e"), TAIL_INCOMPLETE)
    check_tail(String("1e+"), TAIL_INCOMPLETE)
    check_tail(String("1."), TAIL_INCOMPLETE)
    check_tail(String(""), TAIL_INVALID)
    check_tail(String("   "), TAIL_INVALID)
    check_tail(String("}"), TAIL_INVALID)
    check_tail(String("{,}"), TAIL_INVALID)
    check_tail(String('{"a":}'), TAIL_INVALID)
    check_tail(String("[1,]"), TAIL_INVALID)
    check_tail(String("hello"), TAIL_INVALID)
    check_tail(String("truX"), TAIL_INVALID)
    check_tail(String("01"), TAIL_INVALID)
    check_tail(String("{}}"), TAIL_INVALID)
    check_tail(String("{} {}"), TAIL_INVALID)
    check_tail(String('"\\x"'), TAIL_INVALID)
    check_tail(String('"\\u12Z"'), TAIL_INVALID)
    var cut = utf8_bytes('"ab')
    cut.append(UInt8(0xE2))
    cut.append(UInt8(0x82))
    check_tail_bytes(cut, TAIL_INCOMPLETE)
    var bad = utf8_bytes('"ab')
    bad.append(UInt8(0xFF))
    bad.append(UInt8(0x22))
    check_tail_bytes(bad, TAIL_INVALID)
    var overlong = utf8_bytes('"')
    overlong.append(UInt8(0xC0))
    overlong.append(UInt8(0x80))
    overlong.append(UInt8(0x22))
    check_tail_bytes(overlong, TAIL_INVALID)
    var deep = String("")
    for _ in range(65):
        deep += "["
    check_tail(deep, TAIL_INVALID)
    var raw = utf8_bytes('{"k":"v')
    raw.append(UInt8(0x1B))
    check_tail_bytes(raw, TAIL_INVALID)


def test_negative_fixtures_present() raises:
    """Rejection fixtures must exist; a missing file must error loudly."""
    var names = List[String]()
    names.append(String("tests/fixtures/negative/missing-synthetic.json"))
    names.append(String("tests/fixtures/negative/bad-kind.ndjson"))
    names.append(String("tests/fixtures/negative/bad-version.ndjson"))
    names.append(String("tests/fixtures/negative/dup-keys.ndjson"))
    names.append(String("tests/fixtures/negative/leading-zeros.ndjson"))
    names.append(String("tests/fixtures/negative/number-bytes.ndjson"))
    names.append(String("tests/fixtures/negative/overflow-bytes.ndjson"))
    names.append(String("tests/fixtures/negative/depth-65.json"))
    for name in names:
        assert_true(len(fixture_bytes(name)) > 0)


def test_skip_value_depth_fixtures() raises:
    var ok = Scanner(fixture_bytes("tests/fixtures/negative/depth-64.json"))
    ok.skip_value()
    ok.skip_ws()
    assert_true(ok.at_end())
    var deep = fixture_bytes("tests/fixtures/negative/depth-65.json")
    var raised = False
    try:
        var bad = Scanner(deep^)
        bad.skip_value()
    except:
        raised = True
    assert_true(raised)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_scan_string_basic]()
    suite.test[test_scan_string_escapes]()
    suite.test[test_scan_string_unicode_escape]()
    suite.test[test_scan_string_bad_escape]()
    suite.test[test_scan_string_rejects_control]()
    suite.test[test_scan_string_rejects_bad_utf8]()
    suite.test[test_scan_literals]()
    suite.test[test_scan_literals_reject]()
    suite.test[test_scan_int]()
    suite.test[test_scan_int_rejects]()
    suite.test[test_scan_depth_boundary]()
    suite.test[test_scan_expect_peek]()
    suite.test[test_u64_canonical]()
    suite.test[test_u64_rejects]()
    suite.test[test_opaque_id]()
    suite.test[test_opaque_id_rejects]()
    suite.test[test_bounded_text_counts_codepoints]()
    suite.test[test_parse_session_attempts]()
    suite.test[test_session_missing_synthetic]()
    suite.test[test_session_rejects_shape]()
    suite.test[test_session_window_bounds]()
    suite.test[test_session_rejects_dup_device]()
    suite.test[test_session_evidence_bound]()
    suite.test[test_session_optionals]()
    suite.test[test_session_tristate_optionals]()
    suite.test[test_session_rejects_empty_reason]()
    suite.test[test_session_retains_baseline_observations]()
    suite.test[test_parse_event_bounce]()
    suite.test[test_parse_event_kinds]()
    suite.test[test_parse_event_observer]()
    suite.test[test_event_rejects_negatives]()
    suite.test[test_f12_hostile_member_not_echoed]()
    suite.test[test_partial_record_definitive]()
    suite.test[test_event_rejects_payload_rules]()
    suite.test[test_event_rejects_bad_observer]()
    suite.test[test_read_attempts_capture]()
    suite.test[test_reader_cross_record]()
    suite.test[test_reader_baseline_floor]()
    suite.test[test_reader_limits_exact]()
    suite.test[test_reader_size_fixtures]()
    suite.test[test_reader_partial_tail]()
    suite.test[test_reader_partial_only_final]()
    suite.test[test_reader_corrupt_tail_not_recovered]()
    suite.test[test_reader_valid_no_newline_rejected]()
    suite.test[test_reader_tail_foreign_rejected]()
    suite.test[test_reader_f2_identities]()
    suite.test[test_reader_f2_lifecycle_ok]()
    suite.test[test_reader_f3_overflow]()
    suite.test[test_reader_multi_chunk]()
    suite.test[test_reader_missing]()
    suite.test[test_reader_empty_and_crlf]()
    suite.test[test_skip_value_depth_fixtures]()
    suite.test[test_classify_tail]()
    suite.test[test_negative_fixtures_present]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
