# SPDX-License-Identifier: GPL-3.0-or-later

"""Canonical JSON encoding for events and sessions.

Byte rules mirror the A05 parsers exactly: u64 as quoted
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


def quote_json(text: String) raises EncodeError -> String:
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
            buf.append(_hex_lo(Int(b) // 16))
            buf.append(_hex_lo(Int(b) % 16))
        else:
            buf.append(b)
    buf.append(UInt8(0x22))
    try:
        return String(from_utf8=Span(buf))
    except:
        raise EncodeError("string", "unencodable text")


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


def _encode_source(ev: Event) raises EncodeError -> String:
    var parts = List[String]()
    parts.append(_member(String("hook"), _jstr(ev.source_hook)))
    parts.append(_member(String("backend"), _jstr(ev.source_backend)))
    parts.append(
        _member(String("profile_id"), _jstr(ev.source_profile_id))
    )
    parts.append(
        _member(String("measurement"), _jstr(ev.source_measurement))
    )
    parts.append(
        _member(String("correlation"), _jstr(ev.source_correlation))
    )
    return _jobj(parts^)


def _encode_observer(ev: Event) raises EncodeError -> String:
    var parts = List[String]()
    if ev.has_cpu:
        parts.append(_member(String("cpu"), format_i64(ev.cpu)))
    if ev.has_pid:
        parts.append(_member(String("pid"), format_i64(ev.pid)))
    if ev.has_tgid:
        parts.append(_member(String("tgid"), format_i64(ev.tgid)))
    if ev.has_comm:
        parts.append(_member(String("comm"), _jstr(ev.comm)))
    if ev.has_cgroup_id:
        parts.append(_member(String("cgroup_id"), _jstr(ev.cgroup_id)))
    parts.append(
        _member(String("relation"), _jstr(String("execution_context_only")))
    )
    return _jobj(parts^)


def _encode_data(ev: Event) raises EncodeError -> String:
    var parts = List[String]()
    var kind = ev.kind
    if kind == "bounce_attempt":
        parts.append(
            _member(String("device_id"), _jstr(ev.bounce.device_id))
        )
        parts.append(
            _member(
                String("requested_bytes"),
                _ju64(ev.bounce.requested_bytes),
            )
        )
        parts.append(
            _member(String("forced"), _jbool(ev.bounce.forced))
        )
        parts.append(
            _member(
                String("operation_id"), _jstr(ev.bounce.operation_id)
            )
        )
    elif kind == "map_result":
        parts.append(
            _member(
                String("operation_id"),
                _jstr(ev.map_result.operation_id),
            )
        )
        parts.append(
            _member(String("success"), _jbool(ev.map_result.success))
        )
        if ev.map_result.has_mapping_id:
            parts.append(
                _member(
                    String("mapping_id"),
                    _jstr(ev.map_result.mapping_id),
                )
            )
        else:
            parts.append(_member(String("mapping_id"), _jnull()))
        if ev.map_result.has_return_code:
            parts.append(
                _member(
                    String("return_code"),
                    format_i64(ev.map_result.return_code),
                )
            )
        else:
            parts.append(_member(String("return_code"), _jnull()))
        if ev.map_result.has_mapped_bytes:
            parts.append(
                _member(
                    String("mapped_bytes"),
                    _ju64(ev.map_result.mapped_bytes),
                )
            )
        else:
            parts.append(_member(String("mapped_bytes"), _jnull()))
    elif kind == "unmap":
        if ev.unmap.has_mapping_id:
            parts.append(
                _member(
                    String("mapping_id"), _jstr(ev.unmap.mapping_id)
                )
            )
        else:
            parts.append(_member(String("mapping_id"), _jnull()))
    elif kind == "copy":
        parts.append(
            _member(
                String("operation_id"), _jstr(ev.copy.operation_id)
            )
        )
        if ev.copy.has_mapping_id:
            parts.append(
                _member(
                    String("mapping_id"), _jstr(ev.copy.mapping_id)
                )
            )
        else:
            parts.append(_member(String("mapping_id"), _jnull()))
        parts.append(
            _member(String("direction"), _jstr(ev.copy.direction))
        )
        parts.append(_member(String("bytes"), _ju64(ev.copy.bytes)))
    elif kind == "sync_request":
        parts.append(
            _member(
                String("operation_id"), _jstr(ev.sync.operation_id)
            )
        )
        if ev.sync.has_mapping_id:
            parts.append(
                _member(
                    String("mapping_id"), _jstr(ev.sync.mapping_id)
                )
            )
        else:
            parts.append(_member(String("mapping_id"), _jnull()))
        parts.append(_member(String("offset"), _ju64(ev.sync.offset)))
        parts.append(_member(String("length"), _ju64(ev.sync.length)))
    elif kind == "transition_result":
        parts.append(
            _member(
                String("region_id"), _jstr(ev.transition.region_id)
            )
        )
        parts.append(
            _member(
                String("requested_state"),
                _jstr(ev.transition.requested_state),
            )
        )
        parts.append(
            _member(String("success"), _jbool(ev.transition.success))
        )
        if ev.transition.has_return_code:
            parts.append(
                _member(
                    String("return_code"),
                    format_i64(ev.transition.return_code),
                )
            )
        else:
            parts.append(_member(String("return_code"), _jnull()))
        parts.append(
            _member(String("offset"), _ju64(ev.transition.offset))
        )
        parts.append(
            _member(String("length"), _ju64(ev.transition.length))
        )
        if ev.transition.has_address_space:
            parts.append(
                _member(
                    String("address_space"),
                    _jstr(ev.transition.address_space),
                )
            )
        if ev.transition.has_resolution:
            parts.append(
                _member(
                    String("resolution"),
                    _jstr(ev.transition.resolution),
                )
            )
        parts.append(
            _member(
                String("generation"), String(ev.transition.generation)
            )
        )
    elif kind == "pool_sample":
        parts.append(
            _member(String("pool_id"), _jstr(ev.pool.pool_id))
        )
        if ev.pool.has_used:
            parts.append(
                _member(
                    String("used_bytes"), _ju64(ev.pool.used_bytes)
                )
            )
        else:
            parts.append(_member(String("used_bytes"), _jnull()))
        if ev.pool.has_capacity:
            parts.append(
                _member(
                    String("capacity_bytes"),
                    _ju64(ev.pool.capacity_bytes),
                )
            )
        else:
            parts.append(_member(String("capacity_bytes"), _jnull()))
        parts.append(_member(String("unit"), _jstr(ev.pool.unit)))
        if ev.pool.allocator != "":
            parts.append(
                _member(String("allocator"), _jstr(ev.pool.allocator))
            )
        if ev.pool.has_unit_bytes:
            parts.append(
                _member(
                    String("unit_bytes"),
                    _ju64(ev.pool.unit_bytes),
                )
            )
        if ev.pool.has_hiwater:
            parts.append(
                _member(
                    String("hiwater_bytes"),
                    _ju64(ev.pool.hiwater_bytes),
                )
            )
        if ev.pool.reason != "":
            parts.append(
                _member(String("reason"), _jstr(ev.pool.reason))
            )
    elif kind == "gap":
        parts.append(
            _member(String("channel"), _jstr(ev.gap.channel))
        )
        if ev.gap.has_lost_count:
            parts.append(
                _member(
                    String("lost_count"), _ju64(ev.gap.lost_count)
                )
            )
        else:
            parts.append(_member(String("lost_count"), _jnull()))
        parts.append(_member(String("reason"), _jstr(ev.gap.reason)))
        parts.append(
            _member(
                String("window_start_ns"),
                _ju64(ev.gap.window_start_ns),
            )
        )
        parts.append(
            _member(
                String("window_end_ns"), _ju64(ev.gap.window_end_ns)
            )
        )
    elif kind == "marker":
        parts.append(_member(String("text"), _jstr(ev.marker.text)))
    elif kind == "counter_snapshot":
        parts.append(
            _member(
                String("counter_id"), _jstr(ev.snapshot.counter_id)
            )
        )
        parts.append(_member(String("epoch"), _ju64(ev.snapshot.epoch)))
        var scope = List[String]()
        if ev.snapshot.has_scope_device:
            scope.append(
                _member(
                    String("device_id"),
                    _jstr(ev.snapshot.scope_device_id),
                )
            )
        scope.append(
            _member(
                String("profile_id"),
                _jstr(ev.snapshot.scope_profile_id),
            )
        )
        parts.append(_member(String("scope"), _jobj(scope^)))
        parts.append(_member(String("value"), _ju64(ev.snapshot.value)))
        parts.append(_member(String("unit"), _jstr(ev.snapshot.unit)))
    else:
        raise EncodeError("kind", "unknown event kind: " + kind)
    return _jobj(parts^)


def encode_event(ev: Event) raises EncodeError -> String:
    """Encode one event in canonical form (no trailing newline)."""
    var parts = List[String]()
    parts.append(
        _member(String("schema_version"), _jstr(EVENT_SCHEMA_VERSION))
    )
    parts.append(
        _member(String("session_id"), _jstr(ev.session_id))
    )
    parts.append(_member(String("seq"), _ju64(ev.seq)))
    parts.append(_member(String("ts_ns"), _ju64(ev.ts_ns)))
    parts.append(_member(String("kind"), _jstr(ev.kind)))
    parts.append(_member(String("source"), _encode_source(ev)))
    if ev.has_observer:
        parts.append(
            _member(String("observer_context"), _encode_observer(ev))
        )
    parts.append(_member(String("data"), _encode_data(ev)))
    return _jobj(parts^)


def encode_event_line(ev: Event) raises EncodeError -> List[UInt8]:
    """Encode one event plus the NDJSON trailing newline."""
    var text = encode_event(ev)
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        out.append(raw[i])
    out.append(UInt8(0x0A))
    return out^


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
        _member(String("correlation"), _encode_channel(s.q_correlation))
    )
    quality.append(
        _member(String("baseline"), _encode_channel(s.q_baseline))
    )
    quality.append(
        _member(String("terminal"), _encode_channel(s.q_terminal))
    )
    parts.append(_member(String("quality"), _jobj(quality^)))
    return _jobj(parts^)
