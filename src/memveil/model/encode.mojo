# SPDX-License-Identifier: GPL-3.0-or-later

"""Canonical JSON encoding for events and sessions.

Byte rules mirror the event parsers exactly: u64 as quoted
canonical decimal, i64 and bool as bare JSON, strings quoted
with short escapes (\\" \\\\ \\b \\f \\n \\r \\t) and \\u00XX
for other controls, raw UTF-8 otherwise. Key order is fixed;
required keys are always emitted (null when the struct flag
is clear); optional keys are emitted iff present.

Output always reparses: any value the parser would reject
also fails the round-trip tests gating this module, so
validation checks are NOT duplicated here (a second copy
of every enum list would drift). Baseline region detail
round-trips exactly: the parser retains every observation
and the encoder reproduces the array in order.
"""

from memveil.model.event import EVENT_SCHEMA_VERSION, Event
from memveil.model.regions import RegionObservation
from memveil.model.session import (
    PRODUCT_NAME,
    SESSION_SCHEMA_VERSION,
    Capability,
    Channel,
    DeviceEntry,
    EvidenceItem,
    Session,
    StopState,
)
from memveil.model.validate import format_u64


@fieldwise_init
struct EncodeError(Copyable, Writable):
    """One encoding refusal naming its field."""

    var what: String
    var message: String


def format_i64(v: Int64) -> String:
    """Canonical bare JSON integer, i64 range."""
    if v >= Int64(0):
        return format_u64(UInt64(v))
    if v == Int64(-9223372036854775807) - Int64(1):
        return String("-9223372036854775808")
    return String("-") + format_u64(UInt64(-v))


def _hex_lo(v: Int) -> UInt8:
    if v < 10:
        return UInt8(0x30 + v)
    return UInt8(0x61 + v - 10)


# Typical event lines are 300-400 bytes; longer ones grow the buffer.
comptime _LINE_RESERVE = 512


def _lit(mut buf: List[UInt8], text: StringLiteral):
    buf.extend(text.as_bytes())


def _put_span(mut buf: List[UInt8], raw: Span[UInt8, _]) raises EncodeError:
    """Append one quoted string; unescaped runs copy in bulk."""
    var start = len(buf)
    buf.append(UInt8(0x22))
    var n = len(raw)
    var run = 0
    var seen = UInt8(0)
    for i in range(n):
        var b = raw[i]
        seen |= b
        if b >= UInt8(0x20) and b != UInt8(0x22) and b != UInt8(0x5C):
            continue
        if i > run:
            buf.extend(raw[run:i])
        run = i + 1
        buf.append(UInt8(0x5C))
        if b == UInt8(0x22):
            buf.append(UInt8(0x22))
        elif b == UInt8(0x5C):
            buf.append(UInt8(0x5C))
        elif b == UInt8(0x08):
            buf.append(UInt8(0x62))
        elif b == UInt8(0x09):
            buf.append(UInt8(0x74))
        elif b == UInt8(0x0A):
            buf.append(UInt8(0x6E))
        elif b == UInt8(0x0C):
            buf.append(UInt8(0x66))
        elif b == UInt8(0x0D):
            buf.append(UInt8(0x72))
        else:
            buf.append(UInt8(0x75))
            buf.append(UInt8(0x30))
            buf.append(UInt8(0x30))
            buf.append(_hex_lo(Int(b) // 16))
            buf.append(_hex_lo(Int(b) % 16))
    if n > run:
        buf.extend(raw[run:n])
    buf.append(UInt8(0x22))
    # Only non-ASCII input can be invalid; check the quoted bytes as before.
    if seen >= UInt8(0x80):
        try:
            _ = String(from_utf8=Span(buf)[start:])
        except:
            raise EncodeError("string", "unencodable text")


def _put_str(mut buf: List[UInt8], text: String) raises EncodeError:
    _put_span(buf, text.as_bytes())


def _put_u64(mut buf: List[UInt8], v: UInt64):
    """Bare canonical decimal, written in place."""
    var start = len(buf)
    var n = v
    while True:
        buf.append(UInt8(0x30) + UInt8(n % UInt64(10)))
        n //= UInt64(10)
        if n == UInt64(0):
            break
    var lo = start
    var hi = len(buf) - 1
    while lo < hi:
        var t = buf[lo]
        buf[lo] = buf[hi]
        buf[hi] = t
        lo += 1
        hi -= 1


def _put_qu64(mut buf: List[UInt8], v: UInt64):
    buf.append(UInt8(0x22))
    _put_u64(buf, v)
    buf.append(UInt8(0x22))


def _put_i64(mut buf: List[UInt8], v: Int64):
    if v >= Int64(0):
        _put_u64(buf, UInt64(v))
        return
    buf.append(UInt8(0x2D))
    # Two's-complement magnitude; exact for the i64 minimum too.
    _put_u64(buf, UInt64(0) - UInt64(v))


def _put_bool(mut buf: List[UInt8], v: Bool):
    if v:
        _lit(buf, "true")
    else:
        _lit(buf, "false")


def quote_json(text: String) raises EncodeError -> String:
    """Quote one string with canonical escapes."""
    var buf = List[UInt8](capacity=text.byte_length() + 2)
    _put_str(buf, text)
    return String(unsafe_from_utf8=Span(buf))


def _put_observer(mut buf: List[UInt8], ev: Event) raises EncodeError:
    buf.append(UInt8(0x7B))
    if ev.has_cpu:
        _lit(buf, "\"cpu\":")
        _put_i64(buf, ev.cpu)
        buf.append(UInt8(0x2C))
    if ev.has_pid:
        _lit(buf, "\"pid\":")
        _put_i64(buf, ev.pid)
        buf.append(UInt8(0x2C))
    if ev.has_tgid:
        _lit(buf, "\"tgid\":")
        _put_i64(buf, ev.tgid)
        buf.append(UInt8(0x2C))
    if ev.has_comm:
        _lit(buf, "\"comm\":")
        _put_str(buf, ev.comm)
        buf.append(UInt8(0x2C))
    if ev.has_cgroup_id:
        _lit(buf, "\"cgroup_id\":")
        _put_str(buf, ev.cgroup_id)
        buf.append(UInt8(0x2C))
    _lit(buf, "\"relation\":\"execution_context_only\"}")


def _put_data(mut buf: List[UInt8], ev: Event) raises EncodeError:
    if ev.kind == "bounce_attempt":
        _lit(buf, "{\"device_id\":")
        _put_str(buf, ev.bounce.device_id)
        _lit(buf, ",\"requested_bytes\":")
        _put_qu64(buf, ev.bounce.requested_bytes)
        _lit(buf, ",\"forced\":")
        _put_bool(buf, ev.bounce.forced)
        _lit(buf, ",\"operation_id\":")
        _put_str(buf, ev.bounce.operation_id)
    elif ev.kind == "map_result":
        _lit(buf, "{\"operation_id\":")
        _put_str(buf, ev.map_result.operation_id)
        _lit(buf, ",\"success\":")
        _put_bool(buf, ev.map_result.success)
        _lit(buf, ",\"mapping_id\":")
        if ev.map_result.has_mapping_id:
            _put_str(buf, ev.map_result.mapping_id)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"return_code\":")
        if ev.map_result.has_return_code:
            _put_i64(buf, ev.map_result.return_code)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"mapped_bytes\":")
        if ev.map_result.has_mapped_bytes:
            _put_qu64(buf, ev.map_result.mapped_bytes)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"wire_generation\":")
        if ev.map_result.has_wire_generation:
            _put_qu64(buf, ev.map_result.wire_generation)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"wire_identity\":")
        if ev.map_result.has_wire_identity:
            _put_str(buf, ev.map_result.wire_identity)
        else:
            _lit(buf, "null")
    elif ev.kind == "unmap":
        _lit(buf, "{\"mapping_id\":")
        if ev.unmap.has_mapping_id:
            _put_str(buf, ev.unmap.mapping_id)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"wire_generation\":")
        if ev.unmap.has_wire_generation:
            _put_qu64(buf, ev.unmap.wire_generation)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"wire_identity\":")
        if ev.unmap.has_wire_identity:
            _put_str(buf, ev.unmap.wire_identity)
        else:
            _lit(buf, "null")
    elif ev.kind == "copy":
        _lit(buf, "{\"operation_id\":")
        _put_str(buf, ev.copy.operation_id)
        _lit(buf, ",\"mapping_id\":")
        if ev.copy.has_mapping_id:
            _put_str(buf, ev.copy.mapping_id)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"direction\":")
        _put_str(buf, ev.copy.direction)
        _lit(buf, ",\"bytes\":")
        _put_qu64(buf, ev.copy.bytes)
    elif ev.kind == "sync_request":
        _lit(buf, "{\"operation_id\":")
        _put_str(buf, ev.sync.operation_id)
        _lit(buf, ",\"mapping_id\":")
        if ev.sync.has_mapping_id:
            _put_str(buf, ev.sync.mapping_id)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"offset_known\":")
        _put_bool(buf, ev.sync.has_offset)
        _lit(buf, ",\"offset\":")
        if ev.sync.has_offset:
            _put_qu64(buf, ev.sync.offset)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"length\":")
        _put_qu64(buf, ev.sync.length)
    elif ev.kind == "transition_result":
        _lit(buf, "{\"region_id\":")
        _put_str(buf, ev.transition.region_id)
        _lit(buf, ",\"requested_state\":")
        _put_str(buf, ev.transition.requested_state)
        _lit(buf, ",\"success\":")
        _put_bool(buf, ev.transition.success)
        _lit(buf, ",\"return_code\":")
        if ev.transition.has_return_code:
            _put_i64(buf, ev.transition.return_code)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"offset\":")
        _put_qu64(buf, ev.transition.offset)
        _lit(buf, ",\"length\":")
        _put_qu64(buf, ev.transition.length)
        if ev.transition.has_address_space:
            _lit(buf, ",\"address_space\":")
            _put_str(buf, ev.transition.address_space)
        if ev.transition.has_resolution:
            _lit(buf, ",\"resolution\":")
            _put_str(buf, ev.transition.resolution)
        _lit(buf, ",\"generation\":")
        _put_i64(buf, Int64(ev.transition.generation))
    elif ev.kind == "pool_sample":
        _lit(buf, "{\"pool_id\":")
        _put_str(buf, ev.pool.pool_id)
        _lit(buf, ",\"used_bytes\":")
        if ev.pool.has_used:
            _put_qu64(buf, ev.pool.used_bytes)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"capacity_bytes\":")
        if ev.pool.has_capacity:
            _put_qu64(buf, ev.pool.capacity_bytes)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"unit\":")
        _put_str(buf, ev.pool.unit)
        if ev.pool.allocator != "":
            _lit(buf, ",\"allocator\":")
            _put_str(buf, ev.pool.allocator)
        if ev.pool.has_unit_bytes:
            _lit(buf, ",\"unit_bytes\":")
            _put_qu64(buf, ev.pool.unit_bytes)
        if ev.pool.has_hiwater:
            _lit(buf, ",\"hiwater_bytes\":")
            _put_qu64(buf, ev.pool.hiwater_bytes)
        if ev.pool.reason != "":
            _lit(buf, ",\"reason\":")
            _put_str(buf, ev.pool.reason)
    elif ev.kind == "gap":
        _lit(buf, "{\"channel\":")
        _put_str(buf, ev.gap.channel)
        _lit(buf, ",\"lost_count\":")
        if ev.gap.has_lost_count:
            _put_qu64(buf, ev.gap.lost_count)
        else:
            _lit(buf, "null")
        _lit(buf, ",\"reason\":")
        _put_str(buf, ev.gap.reason)
        _lit(buf, ",\"window_start_ns\":")
        _put_qu64(buf, ev.gap.window_start_ns)
        _lit(buf, ",\"window_end_ns\":")
        _put_qu64(buf, ev.gap.window_end_ns)
    elif ev.kind == "marker":
        _lit(buf, "{\"text\":")
        _put_str(buf, ev.marker.text)
    elif ev.kind == "counter_snapshot":
        _lit(buf, "{\"counter_id\":")
        _put_str(buf, ev.snapshot.counter_id)
        _lit(buf, ",\"epoch\":")
        _put_qu64(buf, ev.snapshot.epoch)
        _lit(buf, ",\"scope\":{")
        if ev.snapshot.has_scope_device:
            _lit(buf, "\"device_id\":")
            _put_str(buf, ev.snapshot.scope_device_id)
            buf.append(UInt8(0x2C))
        _lit(buf, "\"profile_id\":")
        _put_str(buf, ev.snapshot.scope_profile_id)
        _lit(buf, "},\"value\":")
        _put_qu64(buf, ev.snapshot.value)
        _lit(buf, ",\"unit\":")
        _put_str(buf, ev.snapshot.unit)
    else:
        raise EncodeError("kind", "unknown event kind: " + ev.kind)
    buf.append(UInt8(0x7D))


def _put_event(mut buf: List[UInt8], ev: Event) raises EncodeError:
    _lit(buf, "{\"schema_version\":")
    _put_span(buf, EVENT_SCHEMA_VERSION.as_bytes())
    _lit(buf, ",\"session_id\":")
    _put_str(buf, ev.session_id)
    _lit(buf, ",\"seq\":")
    _put_qu64(buf, ev.seq)
    _lit(buf, ",\"ts_ns\":")
    _put_qu64(buf, ev.ts_ns)
    _lit(buf, ",\"kind\":")
    _put_str(buf, ev.kind)
    _lit(buf, ",\"source\":{\"hook\":")
    _put_str(buf, ev.source_hook)
    _lit(buf, ",\"backend\":")
    _put_str(buf, ev.source_backend)
    _lit(buf, ",\"profile_id\":")
    _put_str(buf, ev.source_profile_id)
    _lit(buf, ",\"measurement\":")
    _put_str(buf, ev.source_measurement)
    _lit(buf, ",\"correlation\":")
    _put_str(buf, ev.source_correlation)
    buf.append(UInt8(0x7D))
    if ev.has_observer:
        _lit(buf, ",\"observer_context\":")
        _put_observer(buf, ev)
    _lit(buf, ",\"data\":")
    _put_data(buf, ev)
    buf.append(UInt8(0x7D))


def encode_event(ev: Event) raises EncodeError -> String:
    """Encode one event in canonical form (no trailing newline)."""
    var buf = List[UInt8](capacity=_LINE_RESERVE)
    _put_event(buf, ev)
    # Every non-ASCII string was validated by _put_span.
    return String(unsafe_from_utf8=Span(buf))


def encode_event_line(ev: Event) raises EncodeError -> List[UInt8]:
    """Encode one event plus the NDJSON trailing newline."""
    var buf = List[UInt8](capacity=_LINE_RESERVE)
    _put_event(buf, ev)
    buf.append(UInt8(0x0A))
    return buf^


def _join(parts: List[String], sep: String) -> String:
    var out = String("")
    for i in range(len(parts)):
        if i > 0:
            out += sep
        out += parts[i]
    return out^


def _member(name: String, value: String) raises EncodeError -> String:
    return quote_json(name) + String(":") + value


def _jarr(parts: List[String]) -> String:
    return String("[") + _join(parts, String(",")) + String("]")


def _jobj(parts: List[String]) -> String:
    return String("{") + _join(parts, String(",")) + String("}")


def _ju64(v: UInt64) raises EncodeError -> String:
    return quote_json(format_u64(v))


def _jstr(text: String) raises EncodeError -> String:
    return quote_json(text)


def _jbool(v: Bool) -> String:
    if v:
        return String("true")
    return String("false")


def _jnull() -> String:
    return String("null")


def _encode_capability(cap: Capability) raises EncodeError -> String:
    var parts = List[String]()
    parts.append(_member(String("status"), _jstr(cap.status)))
    parts.append(_member(String("reason"), _jstr(cap.reason)))
    var hooks = List[String]()
    for i in range(len(cap.hooks)):
        hooks.append(_jstr(cap.hooks[i]))
    parts.append(_member(String("hooks"), _jarr(hooks^)))
    if cap.has_profile_id:
        parts.append(
            _member(String("profile_id"), _jstr(cap.profile_id))
        )
    if cap.has_grade:
        parts.append(_member(String("grade"), _jstr(cap.grade)))
    return _jobj(parts^)


def _encode_channel(ch: Channel) raises EncodeError -> String:
    var parts = List[String]()
    parts.append(_member(String("status"), _jstr(ch.status)))
    if ch.has_loss_count:
        parts.append(
            _member(String("loss_count"), _ju64(ch.loss_count))
        )
    else:
        parts.append(_member(String("loss_count"), _jnull()))
    parts.append(_member(String("scope"), _jstr(ch.scope)))
    parts.append(_member(String("reason"), _jstr(ch.reason)))
    var refs = List[String]()
    for i in range(len(ch.evidence_refs)):
        refs.append(_jstr(ch.evidence_refs[i]))
    parts.append(_member(String("evidence_refs"), _jarr(refs^)))
    return _jobj(parts^)


def _encode_correlation(s: Session) raises EncodeError -> String:
    """Encode quality.correlation with its optional relations."""
    var parts = List[String]()
    var ch = s.q_correlation.copy()
    parts.append(_member(String("status"), _jstr(ch.status)))
    if ch.has_loss_count:
        parts.append(
            _member(String("loss_count"), _ju64(ch.loss_count))
        )
    else:
        parts.append(_member(String("loss_count"), _jnull()))
    parts.append(_member(String("scope"), _jstr(ch.scope)))
    parts.append(_member(String("reason"), _jstr(ch.reason)))
    var refs = List[String]()
    for i in range(len(ch.evidence_refs)):
        refs.append(_jstr(ch.evidence_refs[i]))
    parts.append(_member(String("evidence_refs"), _jarr(refs^)))
    if s.has_corr_relations:
        var rel = List[String]()
        rel.append(
            _member(
                String("mapping_release"),
                _encode_channel(s.q_corr_mapping),
            )
        )
        rel.append(
            _member(
                String("copy_attribution"),
                _encode_channel(s.q_corr_copy),
            )
        )
        rel.append(
            _member(
                String("sync_attribution"),
                _encode_channel(s.q_corr_sync),
            )
        )
        parts.append(_member(String("relations"), _jobj(rel^)))
    return _jobj(parts^)


def _encode_device(dev: DeviceEntry) raises EncodeError -> String:
    var parts = List[String]()
    parts.append(
        _member(String("device_id"), _jstr(dev.device_id))
    )
    parts.append(_member(String("name"), _jstr(dev.name)))
    if dev.driver_present:
        if dev.has_driver:
            parts.append(
                _member(String("driver"), _jstr(dev.driver))
            )
        else:
            parts.append(_member(String("driver"), _jnull()))
    parts.append(
        _member(String("identity_status"), _jstr(dev.identity_status))
    )
    return _jobj(parts^)


def _encode_evidence_item(it: EvidenceItem) raises EncodeError -> String:
    var parts = List[String]()
    parts.append(_member(String("type"), _jstr(it.item_type)))
    parts.append(_member(String("source"), _jstr(it.source)))
    parts.append(
        _member(String("interpretation"), _jstr(it.interpretation))
    )
    return _jobj(parts^)


def _encode_region_observation(o: RegionObservation) raises EncodeError -> String:
    """Encode one baseline observation in schema key order."""
    var parts = List[String]()
    parts.append(_member(String("region_id"), _jstr(o.region_id)))
    parts.append(_member(String("state"), _jstr(o.state)))
    parts.append(_member(String("offset"), _ju64(o.offset)))
    parts.append(_member(String("length"), _ju64(o.length)))
    parts.append(
        _member(String("address_space"), _jstr(o.address_space))
    )
    parts.append(
        _member(String("provenance"), _jstr(o.provenance))
    )
    parts.append(
        _member(String("generation"), String(o.generation))
    )
    return _jobj(parts^)


def encode_session(s: Session) raises EncodeError -> String:
    """Encode one session in canonical form (no trailing newline)."""
    var parts = List[String]()
    parts.append(
        _member(String("schema_version"), _jstr(SESSION_SCHEMA_VERSION))
    )
    parts.append(_member(String("session_id"), _jstr(s.session_id)))
    if s.has_boot_id:
        parts.append(_member(String("boot_id"), _jstr(s.boot_id)))
    parts.append(_member(String("synthetic"), _jbool(s.synthetic)))
    var product = List[String]()
    product.append(_member(String("name"), _jstr(PRODUCT_NAME)))
    product.append(
        _member(String("version"), _jstr(s.product_version))
    )
    if s.has_build:
        product.append(_member(String("build"), _jstr(s.build)))
    parts.append(_member(String("product"), _jobj(product^)))
    var env = List[String]()
    env.append(_member(String("mode"), _jstr(s.env_mode)))
    env.append(
        _member(String("detection"), _jstr(s.env_detection))
    )
    if s.asserted_mode_present:
        if s.has_asserted_mode:
            env.append(
                _member(
                    String("asserted_mode"),
                    _jstr(s.asserted_mode),
                )
            )
        else:
            env.append(_member(String("asserted_mode"), _jnull()))
    env.append(
        _member(String("attestation"), _jstr(s.env_attestation))
    )
    var items = List[String]()
    for i in range(len(s.evidence)):
        items.append(_encode_evidence_item(s.evidence[i]))
    env.append(_member(String("evidence"), _jarr(items^)))
    parts.append(_member(String("environment"), _jobj(env^)))
    var capture = List[String]()
    capture.append(_member(String("mode"), _jstr(s.capture_mode)))
    var window = List[String]()
    window.append(
        _member(String("start_ns"), _ju64(s.window_start_ns))
    )
    window.append(_member(String("end_ns"), _ju64(s.window_end_ns)))
    if s.has_baseline_start_ns:
        window.append(
            _member(
                String("baseline_start_ns"),
                _ju64(s.baseline_start_ns),
            )
        )
    capture.append(_member(String("window"), _jobj(window^)))
    var filters = List[String]()
    if s.has_filter_device:
        filters.append(
            _member(String("device"), _jstr(s.filter_device))
        )
    capture.append(_member(String("filters"), _jobj(filters^)))
    capture.append(
        _member(String("finalized"), _jbool(s.finalized))
    )
    if s.has_end_reason:
        capture.append(
            _member(String("end_reason"), _jstr(s.end_reason))
        )
    parts.append(_member(String("capture"), _jobj(capture^)))
    var devices = List[String]()
    for i in range(len(s.devices)):
        devices.append(_encode_device(s.devices[i]))
    var catalog = List[String]()
    catalog.append(_member(String("devices"), _jarr(devices^)))
    parts.append(_member(String("device_catalog"), _jobj(catalog^)))
    var baseline = List[String]()
    baseline.append(
        _member(String("complete"), _jbool(s.baseline_complete))
    )
    var obs = List[String]()
    for i in range(len(s.baseline_regions)):
        obs.append(_encode_region_observation(s.baseline_regions[i]))
    baseline.append(
        _member(String("region_observations"), _jarr(obs^))
    )
    parts.append(_member(String("baseline"), _jobj(baseline^)))
    var caps = List[String]()
    caps.append(
        _member(
            String("bounce_attempts"),
            _encode_capability(s.cap_bounce_attempts),
        )
    )
    caps.append(
        _member(
            String("mapping_lifecycle"),
            _encode_capability(s.cap_mapping_lifecycle),
        )
    )
    caps.append(
        _member(
            String("copy_bytes"), _encode_capability(s.cap_copy_bytes)
        )
    )
    caps.append(
        _member(
            String("sync_requests"),
            _encode_capability(s.cap_sync_requests),
        )
    )
    caps.append(
        _member(
            String("conversion_results"),
            _encode_capability(s.cap_conversion_results),
        )
    )
    caps.append(
        _member(
            String("region_state"),
            _encode_capability(s.cap_region_state),
        )
    )
    caps.append(
        _member(
            String("pool_stats"), _encode_capability(s.cap_pool_stats)
        )
    )
    caps.append(
        _member(
            String("task_context"),
            _encode_capability(s.cap_task_context),
        )
    )
    parts.append(_member(String("capabilities"), _jobj(caps^)))
    var quality = List[String]()
    quality.append(
        _member(String("detail"), _encode_channel(s.q_detail))
    )
    quality.append(
        _member(String("aggregate"), _encode_channel(s.q_aggregate))
    )
    quality.append(
        _member(String("correlation"), _encode_correlation(s))
    )
    quality.append(
        _member(String("baseline"), _encode_channel(s.q_baseline))
    )
    quality.append(
        _member(String("terminal"), _encode_channel(s.q_terminal))
    )
    parts.append(_member(String("quality"), _jobj(quality^)))
    parts.append(_member(String("stop"), _encode_stop(s.stop)))
    return _jobj(parts^)


def _encode_stop(st: StopState) raises EncodeError -> String:
    var parts = List[String]()
    parts.append(_member(String("outcome"), _jstr(st.outcome)))
    parts.append(_member(String("reason"), _jstr(st.reason)))
    parts.append(_member(String("budget_ms"), _ju64(st.budget_ms)))
    parts.append(_member(String("elapsed_ms"), _ju64(st.elapsed_ms)))
    parts.append(
        _member(String("admission_closed"), _jbool(st.admission_closed))
    )
    parts.append(
        _member(
            String("quiescence_observed"), _jbool(st.quiescence_observed)
        )
    )
    parts.append(
        _member(String("writers_settled"), _ju64(st.writers_settled))
    )
    parts.append(
        _member(String("in_flight_at_close"), _ju64(st.in_flight_at_close))
    )
    parts.append(
        _member(
            String("late_submits_drained"), _ju64(st.late_submits_drained)
        )
    )
    parts.append(
        _member(String("drained_records"), _ju64(st.drained_records))
    )
    parts.append(
        _member(String("busy_at_drain"), _jbool(st.busy_at_drain))
    )
    parts.append(
        _member(String("counters_valid"), _jbool(st.counters_valid))
    )
    parts.append(
        _member(String("open_mappings"), _ju64(st.open_mappings))
    )
    return _jobj(parts^)
