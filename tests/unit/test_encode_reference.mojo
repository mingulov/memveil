# SPDX-License-Identifier: GPL-3.0-or-later

"""Event encoder byte identity against the reference encoder.

The _ref_* functions are the previous List[String] encoder,
kept verbatim (renamed) as an independent oracle. Every case
asserts identical bytes, or the identical EncodeError, from
encode_event, encode_event_line and quote_json: every kind,
every optional flag, every escape class, invalid UTF-8.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.model.encode import (
    EncodeError,
    encode_event,
    encode_event_line,
    quote_json,
)
from memveil.model.event import EVENT_SCHEMA_VERSION, Event
from memveil.model.validate import format_u64


# Reference encoder: the pre-buffer implementation, verbatim.


def _ref_format_i64(v: Int64) -> String:
    """Canonical bare JSON integer, i64 range."""
    if v >= Int64(0):
        return format_u64(UInt64(v))
    if v == Int64(-9223372036854775807) - Int64(1):
        return String("-9223372036854775808")
    return String("-") + format_u64(UInt64(-v))


def _ref_hex_lo(v: Int) -> UInt8:
    if v < 10:
        return UInt8(0x30 + v)
    return UInt8(0x61 + v - 10)


def _ref_quote_json(text: String) raises EncodeError -> String:
    """Quote one string with canonical escapes."""
    var buf = List[UInt8]()
    buf.append(UInt8(0x22))
    var raw = text.as_bytes()
    for i in range(len(raw)):
        var b = raw[i]
        if b == UInt8(0x22):
            buf.append(UInt8(0x5C))
            buf.append(UInt8(0x22))
        elif b == UInt8(0x5C):
            buf.append(UInt8(0x5C))
            buf.append(UInt8(0x5C))
        elif b == UInt8(0x08):
            buf.append(UInt8(0x5C))
            buf.append(UInt8(0x62))
        elif b == UInt8(0x09):
            buf.append(UInt8(0x5C))
            buf.append(UInt8(0x74))
        elif b == UInt8(0x0A):
            buf.append(UInt8(0x5C))
            buf.append(UInt8(0x6E))
        elif b == UInt8(0x0C):
            buf.append(UInt8(0x5C))
            buf.append(UInt8(0x66))
        elif b == UInt8(0x0D):
            buf.append(UInt8(0x5C))
            buf.append(UInt8(0x72))
        elif b < UInt8(0x20):
            buf.append(UInt8(0x5C))
            buf.append(UInt8(0x75))
            buf.append(UInt8(0x30))
            buf.append(UInt8(0x30))
            buf.append(_ref_hex_lo(Int(b) // 16))
            buf.append(_ref_hex_lo(Int(b) % 16))
        else:
            buf.append(b)
    buf.append(UInt8(0x22))
    try:
        return String(from_utf8=Span(buf))
    except:
        raise EncodeError("string", "unencodable text")


def _ref_join(parts: List[String], sep: String) -> String:
    var out = String("")
    for i in range(len(parts)):
        if i > 0:
            out += sep
        out += parts[i]
    return out^


def _ref_member(name: String, value: String) raises EncodeError -> String:
    return _ref_quote_json(name) + String(":") + value


def _ref_jobj(parts: List[String]) -> String:
    return String("{") + _ref_join(parts, String(",")) + String("}")


def _ref_ju64(v: UInt64) raises EncodeError -> String:
    return _ref_quote_json(format_u64(v))


def _ref_jstr(text: String) raises EncodeError -> String:
    return _ref_quote_json(text)


def _ref_jbool(v: Bool) -> String:
    if v:
        return String("true")
    return String("false")


def _ref_jnull() -> String:
    return String("null")


def _ref_encode_source(ev: Event) raises EncodeError -> String:
    var parts = List[String]()
    parts.append(_ref_member(String("hook"), _ref_jstr(ev.source_hook)))
    parts.append(_ref_member(String("backend"), _ref_jstr(ev.source_backend)))
    parts.append(
        _ref_member(String("profile_id"), _ref_jstr(ev.source_profile_id))
    )
    parts.append(
        _ref_member(String("measurement"), _ref_jstr(ev.source_measurement))
    )
    parts.append(
        _ref_member(String("correlation"), _ref_jstr(ev.source_correlation))
    )
    return _ref_jobj(parts^)


def _ref_encode_observer(ev: Event) raises EncodeError -> String:
    var parts = List[String]()
    if ev.has_cpu:
        parts.append(_ref_member(String("cpu"), _ref_format_i64(ev.cpu)))
    if ev.has_pid:
        parts.append(_ref_member(String("pid"), _ref_format_i64(ev.pid)))
    if ev.has_tgid:
        parts.append(_ref_member(String("tgid"), _ref_format_i64(ev.tgid)))
    if ev.has_comm:
        parts.append(_ref_member(String("comm"), _ref_jstr(ev.comm)))
    if ev.has_cgroup_id:
        parts.append(_ref_member(String("cgroup_id"), _ref_jstr(ev.cgroup_id)))
    parts.append(
        _ref_member(String("relation"), _ref_jstr(String("execution_context_only")))
    )
    return _ref_jobj(parts^)


def _ref_encode_data(ev: Event) raises EncodeError -> String:
    var parts = List[String]()
    var kind = ev.kind
    if kind == "bounce_attempt":
        parts.append(
            _ref_member(String("device_id"), _ref_jstr(ev.bounce.device_id))
        )
        parts.append(
            _ref_member(
                String("requested_bytes"),
                _ref_ju64(ev.bounce.requested_bytes),
            )
        )
        parts.append(
            _ref_member(String("forced"), _ref_jbool(ev.bounce.forced))
        )
        parts.append(
            _ref_member(
                String("operation_id"), _ref_jstr(ev.bounce.operation_id)
            )
        )
    elif kind == "map_result":
        parts.append(
            _ref_member(
                String("operation_id"),
                _ref_jstr(ev.map_result.operation_id),
            )
        )
        parts.append(
            _ref_member(String("success"), _ref_jbool(ev.map_result.success))
        )
        if ev.map_result.has_mapping_id:
            parts.append(
                _ref_member(
                    String("mapping_id"),
                    _ref_jstr(ev.map_result.mapping_id),
                )
            )
        else:
            parts.append(_ref_member(String("mapping_id"), _ref_jnull()))
        if ev.map_result.has_return_code:
            parts.append(
                _ref_member(
                    String("return_code"),
                    _ref_format_i64(ev.map_result.return_code),
                )
            )
        else:
            parts.append(_ref_member(String("return_code"), _ref_jnull()))
        if ev.map_result.has_mapped_bytes:
            parts.append(
                _ref_member(
                    String("mapped_bytes"),
                    _ref_ju64(ev.map_result.mapped_bytes),
                )
            )
        else:
            parts.append(_ref_member(String("mapped_bytes"), _ref_jnull()))
        if ev.map_result.has_wire_generation:
            parts.append(
                _ref_member(
                    String("wire_generation"),
                    _ref_ju64(ev.map_result.wire_generation),
                )
            )
        else:
            parts.append(_ref_member(String("wire_generation"), _ref_jnull()))
        if ev.map_result.has_wire_identity:
            parts.append(
                _ref_member(
                    String("wire_identity"),
                    _ref_jstr(ev.map_result.wire_identity),
                )
            )
        else:
            parts.append(_ref_member(String("wire_identity"), _ref_jnull()))
    elif kind == "unmap":
        if ev.unmap.has_mapping_id:
            parts.append(
                _ref_member(
                    String("mapping_id"), _ref_jstr(ev.unmap.mapping_id)
                )
            )
        else:
            parts.append(_ref_member(String("mapping_id"), _ref_jnull()))
        if ev.unmap.has_wire_generation:
            parts.append(
                _ref_member(
                    String("wire_generation"),
                    _ref_ju64(ev.unmap.wire_generation),
                )
            )
        else:
            parts.append(_ref_member(String("wire_generation"), _ref_jnull()))
        if ev.unmap.has_wire_identity:
            parts.append(
                _ref_member(
                    String("wire_identity"),
                    _ref_jstr(ev.unmap.wire_identity),
                )
            )
        else:
            parts.append(_ref_member(String("wire_identity"), _ref_jnull()))
    elif kind == "copy":
        parts.append(
            _ref_member(
                String("operation_id"), _ref_jstr(ev.copy.operation_id)
            )
        )
        if ev.copy.has_mapping_id:
            parts.append(
                _ref_member(
                    String("mapping_id"), _ref_jstr(ev.copy.mapping_id)
                )
            )
        else:
            parts.append(_ref_member(String("mapping_id"), _ref_jnull()))
        parts.append(
            _ref_member(String("direction"), _ref_jstr(ev.copy.direction))
        )
        parts.append(_ref_member(String("bytes"), _ref_ju64(ev.copy.bytes)))
    elif kind == "sync_request":
        parts.append(
            _ref_member(
                String("operation_id"), _ref_jstr(ev.sync.operation_id)
            )
        )
        if ev.sync.has_mapping_id:
            parts.append(
                _ref_member(
                    String("mapping_id"), _ref_jstr(ev.sync.mapping_id)
                )
            )
        else:
            parts.append(_ref_member(String("mapping_id"), _ref_jnull()))
        parts.append(
            _ref_member(String("offset_known"), _ref_jbool(ev.sync.has_offset))
        )
        if ev.sync.has_offset:
            parts.append(
                _ref_member(String("offset"), _ref_ju64(ev.sync.offset))
            )
        else:
            parts.append(_ref_member(String("offset"), _ref_jnull()))
        parts.append(_ref_member(String("length"), _ref_ju64(ev.sync.length)))
    elif kind == "transition_result":
        parts.append(
            _ref_member(
                String("region_id"), _ref_jstr(ev.transition.region_id)
            )
        )
        parts.append(
            _ref_member(
                String("requested_state"),
                _ref_jstr(ev.transition.requested_state),
            )
        )
        parts.append(
            _ref_member(String("success"), _ref_jbool(ev.transition.success))
        )
        if ev.transition.has_return_code:
            parts.append(
                _ref_member(
                    String("return_code"),
                    _ref_format_i64(ev.transition.return_code),
                )
            )
        else:
            parts.append(_ref_member(String("return_code"), _ref_jnull()))
        parts.append(
            _ref_member(String("offset"), _ref_ju64(ev.transition.offset))
        )
        parts.append(
            _ref_member(String("length"), _ref_ju64(ev.transition.length))
        )
        if ev.transition.has_address_space:
            parts.append(
                _ref_member(
                    String("address_space"),
                    _ref_jstr(ev.transition.address_space),
                )
            )
        if ev.transition.has_resolution:
            parts.append(
                _ref_member(
                    String("resolution"),
                    _ref_jstr(ev.transition.resolution),
                )
            )
        parts.append(
            _ref_member(
                String("generation"), String(ev.transition.generation)
            )
        )
    elif kind == "pool_sample":
        parts.append(
            _ref_member(String("pool_id"), _ref_jstr(ev.pool.pool_id))
        )
        if ev.pool.has_used:
            parts.append(
                _ref_member(
                    String("used_bytes"), _ref_ju64(ev.pool.used_bytes)
                )
            )
        else:
            parts.append(_ref_member(String("used_bytes"), _ref_jnull()))
        if ev.pool.has_capacity:
            parts.append(
                _ref_member(
                    String("capacity_bytes"),
                    _ref_ju64(ev.pool.capacity_bytes),
                )
            )
        else:
            parts.append(_ref_member(String("capacity_bytes"), _ref_jnull()))
        parts.append(_ref_member(String("unit"), _ref_jstr(ev.pool.unit)))
        if ev.pool.allocator != "":
            parts.append(
                _ref_member(String("allocator"), _ref_jstr(ev.pool.allocator))
            )
        if ev.pool.has_unit_bytes:
            parts.append(
                _ref_member(
                    String("unit_bytes"),
                    _ref_ju64(ev.pool.unit_bytes),
                )
            )
        if ev.pool.has_hiwater:
            parts.append(
                _ref_member(
                    String("hiwater_bytes"),
                    _ref_ju64(ev.pool.hiwater_bytes),
                )
            )
        if ev.pool.reason != "":
            parts.append(
                _ref_member(String("reason"), _ref_jstr(ev.pool.reason))
            )
    elif kind == "gap":
        parts.append(
            _ref_member(String("channel"), _ref_jstr(ev.gap.channel))
        )
        if ev.gap.has_lost_count:
            parts.append(
                _ref_member(
                    String("lost_count"), _ref_ju64(ev.gap.lost_count)
                )
            )
        else:
            parts.append(_ref_member(String("lost_count"), _ref_jnull()))
        parts.append(_ref_member(String("reason"), _ref_jstr(ev.gap.reason)))
        parts.append(
            _ref_member(
                String("window_start_ns"),
                _ref_ju64(ev.gap.window_start_ns),
            )
        )
        parts.append(
            _ref_member(
                String("window_end_ns"), _ref_ju64(ev.gap.window_end_ns)
            )
        )
    elif kind == "marker":
        parts.append(_ref_member(String("text"), _ref_jstr(ev.marker.text)))
    elif kind == "counter_snapshot":
        parts.append(
            _ref_member(
                String("counter_id"), _ref_jstr(ev.snapshot.counter_id)
            )
        )
        parts.append(_ref_member(String("epoch"), _ref_ju64(ev.snapshot.epoch)))
        var scope = List[String]()
        if ev.snapshot.has_scope_device:
            scope.append(
                _ref_member(
                    String("device_id"),
                    _ref_jstr(ev.snapshot.scope_device_id),
                )
            )
        scope.append(
            _ref_member(
                String("profile_id"),
                _ref_jstr(ev.snapshot.scope_profile_id),
            )
        )
        parts.append(_ref_member(String("scope"), _ref_jobj(scope^)))
        parts.append(_ref_member(String("value"), _ref_ju64(ev.snapshot.value)))
        parts.append(_ref_member(String("unit"), _ref_jstr(ev.snapshot.unit)))
    else:
        raise EncodeError("kind", "unknown event kind: " + kind)
    return _ref_jobj(parts^)


def _ref_encode_event(ev: Event) raises EncodeError -> String:
    """Encode one event in canonical form (no trailing newline)."""
    var parts = List[String]()
    parts.append(
        _ref_member(String("schema_version"), _ref_jstr(EVENT_SCHEMA_VERSION))
    )
    parts.append(
        _ref_member(String("session_id"), _ref_jstr(ev.session_id))
    )
    parts.append(_ref_member(String("seq"), _ref_ju64(ev.seq)))
    parts.append(_ref_member(String("ts_ns"), _ref_ju64(ev.ts_ns)))
    parts.append(_ref_member(String("kind"), _ref_jstr(ev.kind)))
    parts.append(_ref_member(String("source"), _ref_encode_source(ev)))
    if ev.has_observer:
        parts.append(
            _ref_member(String("observer_context"), _ref_encode_observer(ev))
        )
    parts.append(_ref_member(String("data"), _ref_encode_data(ev)))
    return _ref_jobj(parts^)


def _ref_encode_event_line(ev: Event) raises EncodeError -> List[UInt8]:
    """Encode one event plus the NDJSON trailing newline."""
    var text = _ref_encode_event(ev)
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        out.append(raw[i])
    out.append(UInt8(0x0A))
    return out^


# Cases.


def _raw(data: List[UInt8]) -> String:
    """Wrap bytes unchecked so invalid UTF-8 reaches the encoder."""
    return String(unsafe_from_utf8=Span(data))


def _one(b: Int) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8(b))
    return out^


def _quote_new(text: String) -> String:
    try:
        return String("ok:") + quote_json(text)
    except e:
        return String("err:") + e.what + String("|") + e.message


def _quote_ref(text: String) -> String:
    try:
        return String("ok:") + _ref_quote_json(text)
    except e:
        return String("err:") + e.what + String("|") + e.message


def _event_new(ev: Event) -> String:
    try:
        return String("ok:") + encode_event(ev)
    except e:
        return String("err:") + e.what + String("|") + e.message


def _event_ref(ev: Event) -> String:
    try:
        return String("ok:") + _ref_encode_event(ev)
    except e:
        return String("err:") + e.what + String("|") + e.message


def _line_new(ev: Event) -> List[UInt8]:
    try:
        return encode_event_line(ev)
    except:
        return List[UInt8]()


def _line_ref(ev: Event) -> List[UInt8]:
    try:
        return _ref_encode_event_line(ev)
    except:
        return List[UInt8]()


def _assert_same(ev: Event) raises -> Bool:
    """Assert identical output or error; True when it encoded."""
    var got = _event_new(ev)
    var want = _event_ref(ev)
    assert_equal(got, want)
    var a = _line_new(ev)
    var b = _line_ref(ev)
    assert_equal(len(a), len(b))
    for i in range(len(a)):
        assert_equal(a[i], b[i])
    return got.startswith("ok:")


def _pool() -> List[String]:
    """Strings covering every escape class and UTF-8 width."""
    var out = List[String]()
    out.append(String(""))
    out.append(String("a"))
    out.append(String("op0"))
    out.append(String("d000001"))
    out.append(String("linux-x86_64-7.0.0-34-generic"))
    out.append(String("\""))
    out.append(String("\\"))
    out.append(String("a\"b\\c"))
    out.append(String("é"))
    out.append(String("€ 中文 😀"))
    var shorts = List[UInt8]()
    for b in [0x08, 0x0C, 0x0A, 0x0D, 0x09]:
        shorts.append(UInt8(b))
        out.append(_raw(_one(b)))
    out.append(_raw(shorts))
    var controls = List[UInt8]()
    for b in range(0x20):
        controls.append(UInt8(b))
    controls.append(UInt8(0x7F))
    out.append(_raw(controls))
    var edges = List[UInt8]()
    for b in [0x0A, 0x61, 0x62, 0x22, 0x22, 0x5C, 0x01, 0xC3, 0xA9, 0x0A]:
        edges.append(UInt8(b))
    out.append(_raw(edges))
    var mixed = String("")
    for i in range(200):
        mixed += String("run") + String(i)
        if i % 7 == 0:
            mixed += String("\"")
        if i % 11 == 0:
            mixed += String("\\")
        if i % 13 == 0:
            mixed += _raw(_one(i % 32))
        if i % 17 == 0:
            mixed += String("ü😀")
    out.append(mixed^)
    var long = String("")
    for _ in range(5000):
        long += String("x")
    out.append(long^)
    return out^


def _u64s() -> List[UInt64]:
    var out = List[UInt64]()
    for v in [0, 1, 9, 10, 99, 100, 4096, 4294967296, 9007199254740993]:
        out.append(UInt64(v))
    out.append(UInt64(10000000000000000000))
    out.append(UInt64(0xFFFFFFFFFFFFFFFF))
    return out^


def _i64s() -> List[Int64]:
    var out = List[Int64]()
    for v in [0, 1, -1, 9, -10, -4095, 9223372036854775807]:
        out.append(Int64(v))
    out.append(Int64(-9223372036854775807) - Int64(1))
    return out^


def _kinds() -> List[String]:
    var out = List[String]()
    out.append(String("bounce_attempt"))
    out.append(String("map_result"))
    out.append(String("unmap"))
    out.append(String("copy"))
    out.append(String("sync_request"))
    out.append(String("transition_result"))
    out.append(String("pool_sample"))
    out.append(String("gap"))
    out.append(String("marker"))
    out.append(String("counter_snapshot"))
    return out^


struct _Picker:
    """Deterministic value source rotating through the pools."""

    var strs: List[String]
    var u64s: List[UInt64]
    var i64s: List[Int64]
    var state: UInt64

    def __init__(out self, seed: UInt64):
        self.strs = _pool()
        self.u64s = _u64s()
        self.i64s = _i64s()
        self.state = seed

    def next(mut self) -> Int:
        self.state = (
            self.state * UInt64(6364136223846793005)
            + UInt64(1442695040888963407)
        )
        return Int(self.state >> UInt64(33))

    def s(mut self) -> String:
        return self.strs[self.next() % len(self.strs)]

    def u(mut self) -> UInt64:
        return self.u64s[self.next() % len(self.u64s)]

    def i(mut self) -> Int64:
        return self.i64s[self.next() % len(self.i64s)]


def _bit(mask: Int, n: Int) -> Bool:
    return (mask >> n) & 1 == 1


def _build(kind: String, mask: Int, mut p: _Picker) -> Event:
    """One event; mask bits 0-5 payload flags, 6-11 observer."""
    var ev = Event()
    ev.session_id = p.s()
    ev.seq = p.u()
    ev.ts_ns = p.u()
    ev.kind = kind
    ev.source_hook = p.s()
    ev.source_backend = p.s()
    ev.source_profile_id = p.s()
    ev.source_measurement = p.s()
    ev.source_correlation = p.s()
    ev.has_observer = _bit(mask, 6)
    ev.has_cpu = _bit(mask, 7)
    ev.cpu = p.i()
    ev.has_pid = _bit(mask, 8)
    ev.pid = p.i()
    ev.has_tgid = _bit(mask, 9)
    ev.tgid = p.i()
    ev.has_comm = _bit(mask, 10)
    ev.comm = p.s()
    ev.has_cgroup_id = _bit(mask, 11)
    ev.cgroup_id = p.s()
    ev.bounce.device_id = p.s()
    ev.bounce.requested_bytes = p.u()
    ev.bounce.forced = _bit(mask, 0)
    ev.bounce.operation_id = p.s()
    ev.map_result.operation_id = p.s()
    ev.map_result.success = _bit(mask, 0)
    ev.map_result.has_mapping_id = _bit(mask, 1)
    ev.map_result.mapping_id = p.s()
    ev.map_result.has_return_code = _bit(mask, 2)
    ev.map_result.return_code = p.i()
    ev.map_result.has_mapped_bytes = _bit(mask, 3)
    ev.map_result.mapped_bytes = p.u()
    ev.map_result.has_wire_generation = _bit(mask, 4)
    ev.map_result.wire_generation = p.u()
    ev.map_result.has_wire_identity = _bit(mask, 5)
    ev.map_result.wire_identity = p.s()
    ev.unmap.has_mapping_id = _bit(mask, 0)
    ev.unmap.mapping_id = p.s()
    ev.unmap.has_wire_generation = _bit(mask, 1)
    ev.unmap.wire_generation = p.u()
    ev.unmap.has_wire_identity = _bit(mask, 2)
    ev.unmap.wire_identity = p.s()
    ev.copy.operation_id = p.s()
    ev.copy.has_mapping_id = _bit(mask, 0)
    ev.copy.mapping_id = p.s()
    ev.copy.direction = p.s()
    ev.copy.bytes = p.u()
    ev.sync.operation_id = p.s()
    ev.sync.has_mapping_id = _bit(mask, 0)
    ev.sync.mapping_id = p.s()
    ev.sync.has_offset = _bit(mask, 1)
    ev.sync.offset = p.u()
    ev.sync.length = p.u()
    ev.transition.region_id = p.s()
    ev.transition.requested_state = p.s()
    ev.transition.success = _bit(mask, 0)
    ev.transition.has_return_code = _bit(mask, 1)
    ev.transition.return_code = p.i()
    ev.transition.offset = p.u()
    ev.transition.length = p.u()
    ev.transition.has_address_space = _bit(mask, 2)
    ev.transition.address_space = p.s()
    ev.transition.has_resolution = _bit(mask, 3)
    ev.transition.resolution = p.s()
    ev.transition.generation = Int(p.i())
    ev.pool.pool_id = p.s()
    ev.pool.has_used = _bit(mask, 0)
    ev.pool.used_bytes = p.u()
    ev.pool.has_capacity = _bit(mask, 1)
    ev.pool.capacity_bytes = p.u()
    ev.pool.unit = p.s()
    ev.pool.allocator = p.s() if _bit(mask, 2) else String("")
    ev.pool.has_unit_bytes = _bit(mask, 3)
    ev.pool.unit_bytes = p.u()
    ev.pool.has_hiwater = _bit(mask, 4)
    ev.pool.hiwater_bytes = p.u()
    ev.pool.reason = p.s() if _bit(mask, 5) else String("")
    ev.gap.channel = p.s()
    ev.gap.has_lost_count = _bit(mask, 0)
    ev.gap.lost_count = p.u()
    ev.gap.reason = p.s()
    ev.gap.window_start_ns = p.u()
    ev.gap.window_end_ns = p.u()
    ev.marker.text = p.s()
    ev.snapshot.counter_id = p.s()
    ev.snapshot.epoch = p.u()
    ev.snapshot.has_scope_device = _bit(mask, 0)
    ev.snapshot.scope_device_id = p.s()
    ev.snapshot.scope_profile_id = p.s()
    ev.snapshot.value = p.u()
    ev.snapshot.unit = p.s()
    return ev^


def test_quote_byte_pairs() raises:
    # Every 1- and 2-byte string, valid or not.
    for a in range(256):
        var one = _raw(_one(a))
        assert_equal(_quote_new(one), _quote_ref(one))
        for b in range(256):
            var two = List[UInt8]()
            two.append(UInt8(a))
            two.append(UInt8(b))
            var text = _raw(two)
            assert_equal(_quote_new(text), _quote_ref(text))


def test_quote_edge_sequences() raises:
    # Every 3- and 4-byte string over escape and UTF-8 edge bytes.
    var edge = List[Int]()
    for b in [0x00, 0x0A, 0x1F, 0x22, 0x5C, 0x41, 0x7F, 0x80]:
        edge.append(b)
    for b in [0xBF, 0xC2, 0xE0, 0xED, 0xF0, 0xF4, 0xF5, 0xFF]:
        edge.append(b)
    var n = len(edge)
    for i in range(n * n * n * n):
        var four = List[UInt8]()
        four.append(UInt8(edge[i % n]))
        four.append(UInt8(edge[(i // n) % n]))
        four.append(UInt8(edge[(i // (n * n)) % n]))
        var three = _raw(four)
        assert_equal(_quote_new(three), _quote_ref(three))
        four.append(UInt8(edge[i // (n * n * n)]))
        var text = _raw(four)
        assert_equal(_quote_new(text), _quote_ref(text))


def test_quote_pool() raises:
    var pool = _pool()
    for i in range(len(pool)):
        assert_equal(_quote_new(pool[i]), _quote_ref(pool[i]))
        assert_true(_quote_new(pool[i]).startswith("ok:"))


def test_event_flag_matrix() raises:
    # Every kind under every payload and observer flag combination.
    var kinds = _kinds()
    var p = _Picker(UInt64(1))
    var encoded = 0
    for k in range(len(kinds)):
        for mask in range(4096):
            if _assert_same(_build(kinds[k], mask, p)):
                encoded += 1
    assert_equal(encoded, len(kinds) * 4096)


def test_event_random() raises:
    var kinds = _kinds()
    var p = _Picker(UInt64(20261021))
    for _ in range(20000):
        var kind = kinds[p.next() % len(kinds)]
        _ = _assert_same(_build(kind, p.next() % 4096, p))


def test_event_values() raises:
    # Each scalar extreme lands in every scalar slot.
    var kinds = _kinds()
    var u = _u64s()
    var v = _i64s()
    var p = _Picker(UInt64(7))
    for k in range(len(kinds)):
        for i in range(len(u)):
            var ev = _build(kinds[k], 4095, p)
            ev.seq = u[i]
            ev.ts_ns = u[i]
            ev.bounce.requested_bytes = u[i]
            ev.map_result.mapped_bytes = u[i]
            ev.map_result.wire_generation = u[i]
            ev.unmap.wire_generation = u[i]
            ev.copy.bytes = u[i]
            ev.sync.offset = u[i]
            ev.sync.length = u[i]
            ev.transition.offset = u[i]
            ev.transition.length = u[i]
            ev.pool.used_bytes = u[i]
            ev.pool.capacity_bytes = u[i]
            ev.pool.unit_bytes = u[i]
            ev.pool.hiwater_bytes = u[i]
            ev.gap.lost_count = u[i]
            ev.gap.window_start_ns = u[i]
            ev.gap.window_end_ns = u[i]
            ev.snapshot.epoch = u[i]
            ev.snapshot.value = u[i]
            assert_true(_assert_same(ev))
        for i in range(len(v)):
            var ev = _build(kinds[k], 4095, p)
            ev.cpu = v[i]
            ev.pid = v[i]
            ev.tgid = v[i]
            ev.map_result.return_code = v[i]
            ev.transition.return_code = v[i]
            ev.transition.generation = Int(v[i])
            assert_true(_assert_same(ev))


def test_event_fixture_shape() raises:
    # A real capture line, byte for byte.
    var ev = Event()
    ev.session_id = String("cap-31673397184-520")
    ev.seq = UInt64(2)
    ev.ts_ns = UInt64(31868671010)
    ev.kind = String("map_result")
    ev.source_hook = String("fexit:swiotlb_tbl_map_single")
    ev.source_backend = String("tracing")
    ev.source_profile_id = String("linux-x86_64-7.0.0-34-generic")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    ev.map_result.operation_id = String("lc-0")
    ev.map_result.success = True
    ev.map_result.has_mapping_id = True
    ev.map_result.mapping_id = String("gen-1")
    ev.map_result.has_mapped_bytes = True
    ev.map_result.mapped_bytes = UInt64(4096)
    ev.map_result.has_wire_generation = True
    ev.map_result.wire_generation = UInt64(1)
    ev.map_result.has_wire_identity = True
    ev.map_result.wire_identity = String("known")
    assert_true(_assert_same(ev))
    assert_equal(
        encode_event(ev),
        String(
            "{\"schema_version\":\"0.1.1\",\"session_id\":"
            "\"cap-31673397184-520\",\"seq\":\"2\",\"ts_ns\":"
            "\"31868671010\",\"kind\":\"map_result\",\"source\":"
            "{\"hook\":\"fexit:swiotlb_tbl_map_single\",\"backend\":"
            "\"tracing\",\"profile_id\":\"linux-x86_64-7.0.0-34-generic\","
            "\"measurement\":\"observed\",\"correlation\":\"direct\"},"
            "\"data\":{\"operation_id\":\"lc-0\",\"success\":true,"
            "\"mapping_id\":\"gen-1\",\"return_code\":null,"
            "\"mapped_bytes\":\"4096\",\"wire_generation\":\"1\","
            "\"wire_identity\":\"known\"}}"
        ),
    )
    var line = encode_event_line(ev)
    assert_equal(line[len(line) - 1], UInt8(0x0A))


def _bad() -> String:
    var raw = List[UInt8]()
    raw.append(UInt8(0x61))
    raw.append(UInt8(0xC3))
    return _raw(raw)


def test_event_errors() raises:
    # Invalid UTF-8 in each string slot, and unknown kinds.
    var kinds = _kinds()
    var p = _Picker(UInt64(99))
    var slots = 36
    for k in range(len(kinds)):
        for slot in range(slots):
            var ev = _build(kinds[k], 4095, p)
            var s = slot
            if s == 0:
                ev.session_id = _bad()
            elif s == 1:
                ev.source_hook = _bad()
            elif s == 2:
                ev.source_backend = _bad()
            elif s == 3:
                ev.source_profile_id = _bad()
            elif s == 4:
                ev.source_measurement = _bad()
            elif s == 5:
                ev.source_correlation = _bad()
            elif s == 6:
                ev.comm = _bad()
            elif s == 7:
                ev.cgroup_id = _bad()
            elif s == 8:
                ev.bounce.device_id = _bad()
            elif s == 9:
                ev.bounce.operation_id = _bad()
            elif s == 10:
                ev.map_result.operation_id = _bad()
            elif s == 11:
                ev.map_result.mapping_id = _bad()
            elif s == 12:
                ev.map_result.wire_identity = _bad()
            elif s == 13:
                ev.unmap.mapping_id = _bad()
            elif s == 14:
                ev.unmap.wire_identity = _bad()
            elif s == 15:
                ev.copy.operation_id = _bad()
            elif s == 16:
                ev.copy.mapping_id = _bad()
            elif s == 17:
                ev.copy.direction = _bad()
            elif s == 18:
                ev.sync.operation_id = _bad()
            elif s == 19:
                ev.sync.mapping_id = _bad()
            elif s == 20:
                ev.transition.region_id = _bad()
            elif s == 21:
                ev.transition.requested_state = _bad()
            elif s == 22:
                ev.transition.address_space = _bad()
            elif s == 23:
                ev.transition.resolution = _bad()
            elif s == 24:
                ev.pool.pool_id = _bad()
            elif s == 25:
                ev.pool.unit = _bad()
            elif s == 26:
                ev.pool.allocator = _bad()
            elif s == 27:
                ev.pool.reason = _bad()
            elif s == 28:
                ev.gap.channel = _bad()
            elif s == 29:
                ev.gap.reason = _bad()
            elif s == 30:
                ev.marker.text = _bad()
            elif s == 31:
                ev.snapshot.counter_id = _bad()
            elif s == 32:
                ev.snapshot.scope_device_id = _bad()
            elif s == 33:
                ev.snapshot.scope_profile_id = _bad()
            elif s == 34:
                ev.snapshot.unit = _bad()
            else:
                ev.kind = String("nope")
                ev.session_id = _bad()
            _ = _assert_same(ev)
    var ev = _build(String("nope"), 4095, p)
    assert_true(not _assert_same(ev))
    assert_true(_event_new(ev).startswith("err:kind|unknown event kind: "))
    var bad_kind = _build(_bad(), 0, p)
    assert_equal(_event_new(bad_kind), String("err:string|unencodable text"))
    _ = _assert_same(bad_kind)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_quote_byte_pairs]()
    suite.test[test_quote_edge_sequences]()
    suite.test[test_quote_pool]()
    suite.test[test_event_flag_matrix]()
    suite.test[test_event_random]()
    suite.test[test_event_values]()
    suite.test[test_event_fixture_shape]()
    suite.test[test_event_errors]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
