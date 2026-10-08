# SPDX-License-Identifier: GPL-3.0-or-later

"""Typed normalized event: one events.ndjson line, format 0.1.0.

The parser validates a single line against the frozen event schema:
const version, opaque IDs, canonical u64 strings, source and observer
bounds, and the kind-specific payload. Unknown kinds, unknown fields,
and duplicated keys are refused. Cross-record rules (session match,
strictly increasing sequence, window membership) belong to the
capture reader, not to this per-line parse.

JSON integers are accepted within the int64 domain; schema maxima
for observer cpu/pid/tgid are enforced exactly.
"""

from memveil.jsonscan import (
    MAX_DEPTH_DEFAULT,
    TAIL_COMPLETE,
    TAIL_INCOMPLETE,
    TAIL_INVALID,
    Scanner,
    TailMember,
    tail_scan_members,
)
from memveil.model.common import (
    MaybeI64,
    MaybeString,
    MaybeU64,
    array_is_empty,
    array_next,
    expect_colon,
    object_is_empty,
    object_next,
    parse_maybe_int,
    parse_maybe_string,
    parse_maybe_u64,
    parse_u64_field,
)
from memveil.model.validate import (
    ValidationError,
    check_bounded_text,
    check_opaque_id,
    checked_add,
)

comptime EVENT_SCHEMA_VERSION = "0.1.0"
comptime MAX_CPU = Int64(1048575)
comptime MAX_PID = Int64(4194304)


struct BounceAttempt(ImplicitlyCopyable):
    var device_id: String
    var requested_bytes: UInt64
    var forced: Bool
    var operation_id: String

    def __init__(out self):
        self.device_id = String("")
        self.requested_bytes = UInt64(0)
        self.forced = False
        self.operation_id = String("")


struct MapResult(ImplicitlyCopyable):
    var operation_id: String
    var success: Bool
    var has_mapping_id: Bool
    var mapping_id: String
    var has_return_code: Bool
    var return_code: Int64
    var has_mapped_bytes: Bool
    var mapped_bytes: UInt64

    def __init__(out self):
        self.operation_id = String("")
        self.success = False
        self.has_mapping_id = False
        self.mapping_id = String("")
        self.has_return_code = False
        self.return_code = Int64(0)
        self.has_mapped_bytes = False
        self.mapped_bytes = UInt64(0)


struct Unmap(ImplicitlyCopyable):
    var has_mapping_id: Bool
    var mapping_id: String

    def __init__(out self):
        self.has_mapping_id = False
        self.mapping_id = String("")


struct CopyPayload(ImplicitlyCopyable):
    var operation_id: String
    var has_mapping_id: Bool
    var mapping_id: String
    var direction: String
    var bytes: UInt64

    def __init__(out self):
        self.operation_id = String("")
        self.has_mapping_id = False
        self.mapping_id = String("")
        self.direction = String("")
        self.bytes = UInt64(0)


struct SyncRequest(ImplicitlyCopyable):
    var operation_id: String
    var has_mapping_id: Bool
    var mapping_id: String
    var offset: UInt64
    var length: UInt64

    def __init__(out self):
        self.operation_id = String("")
        self.has_mapping_id = False
        self.mapping_id = String("")
        self.offset = UInt64(0)
        self.length = UInt64(0)


struct TransitionResult(ImplicitlyCopyable):
    var region_id: String
    var requested_state: String
    var success: Bool
    var has_return_code: Bool
    var return_code: Int64
    var offset: UInt64
    var length: UInt64
    var has_address_space: Bool
    var address_space: String
    var has_resolution: Bool
    var resolution: String
    var generation: Int

    def __init__(out self):
        self.region_id = String("")
        self.requested_state = String("")
        self.success = False
        self.has_return_code = False
        self.return_code = Int64(0)
        self.offset = UInt64(0)
        self.length = UInt64(0)
        self.has_address_space = False
        self.address_space = String("")
        self.has_resolution = False
        self.resolution = String("")
        self.generation = 1


struct PoolSample(ImplicitlyCopyable):
    var pool_id: String
    var has_used: Bool
    var used_bytes: UInt64
    var has_capacity: Bool
    var capacity_bytes: UInt64
    var unit: String
    var allocator: String
    var has_unit_bytes: Bool
    var unit_bytes: UInt64
    var has_hiwater: Bool
    var hiwater_bytes: UInt64
    var reason: String

    def __init__(out self):
        self.pool_id = String("")
        self.has_used = False
        self.used_bytes = UInt64(0)
        self.has_capacity = False
        self.capacity_bytes = UInt64(0)
        self.unit = String("")
        self.allocator = String("")
        self.has_unit_bytes = False
        self.unit_bytes = UInt64(0)
        self.has_hiwater = False
        self.hiwater_bytes = UInt64(0)
        self.reason = String("")


struct Gap(ImplicitlyCopyable):
    var channel: String
    var has_lost_count: Bool
    var lost_count: UInt64
    var reason: String
    var window_start_ns: UInt64
    var window_end_ns: UInt64

    def __init__(out self):
        self.channel = String("")
        self.has_lost_count = False
        self.lost_count = UInt64(0)
        self.reason = String("")
        self.window_start_ns = UInt64(0)
        self.window_end_ns = UInt64(0)


struct Marker(ImplicitlyCopyable):
    var text: String

    def __init__(out self):
        self.text = String("")


struct CounterSnapshot(ImplicitlyCopyable):
    var counter_id: String
    var epoch: UInt64
    var has_scope_device: Bool
    var scope_device_id: String
    var scope_profile_id: String
    var value: UInt64
    var unit: String

    def __init__(out self):
        self.counter_id = String("")
        self.epoch = UInt64(0)
        self.has_scope_device = False
        self.scope_device_id = String("")
        self.scope_profile_id = String("")
        self.value = UInt64(0)
        self.unit = String("")


def _parse_id(mut scan: Scanner, what: String) raises -> String:
    var v = scan.parse_string()
    try:
        check_opaque_id(v)
    except e:
        raise ValidationError(what, String(e))
    return v


def _parse_maybe_id(mut scan: Scanner, what: String) raises -> MaybeString:
    var m = parse_maybe_string(scan)
    if m.has:
        try:
            check_opaque_id(m.value)
        except e:
            raise ValidationError(what, String(e))
    return m^


def _check_measurement(v: String) raises:
    if v == "observed" or v == "derived" or v == "estimated":
        return
    raise ValidationError("source.measurement", "bad enum")


def _check_correlation(v: String) raises:
    if v == "direct" or v == "unpaired":
        return
    raise ValidationError("source.correlation", "bad enum")


def _check_kind(v: String) raises:
    if (
        v == "bounce_attempt"
        or v == "map_result"
        or v == "unmap"
        or v == "copy"
        or v == "sync_request"
        or v == "transition_result"
        or v == "pool_sample"
        or v == "gap"
        or v == "marker"
        or v == "counter_snapshot"
    ):
        return
    raise ValidationError("kind", "unknown event kind")


struct Event:
    """One validated normalized event. Only the kind-matching payload
    is populated; the rest keep their defaults."""

    var session_id: String
    var seq: UInt64
    var ts_ns: UInt64
    var kind: String
    var source_hook: String
    var source_backend: String
    var source_profile_id: String
    var source_measurement: String
    var source_correlation: String
    var has_observer: Bool
    var has_cpu: Bool
    var cpu: Int64
    var has_pid: Bool
    var pid: Int64
    var has_tgid: Bool
    var tgid: Int64
    var has_comm: Bool
    var comm: String
    var has_cgroup_id: Bool
    var cgroup_id: String
    var bounce: BounceAttempt
    var map_result: MapResult
    var unmap: Unmap
    var copy: CopyPayload
    var sync: SyncRequest
    var transition: TransitionResult
    var pool: PoolSample
    var gap: Gap
    var marker: Marker
    var snapshot: CounterSnapshot

    def __init__(out self):
        self.session_id = String("")
        self.seq = UInt64(0)
        self.ts_ns = UInt64(0)
        self.kind = String("")
        self.source_hook = String("")
        self.source_backend = String("")
        self.source_profile_id = String("")
        self.source_measurement = String("")
        self.source_correlation = String("")
        self.has_observer = False
        self.has_cpu = False
        self.cpu = Int64(0)
        self.has_pid = False
        self.pid = Int64(0)
        self.has_tgid = False
        self.tgid = Int64(0)
        self.has_comm = False
        self.comm = String("")
        self.has_cgroup_id = False
        self.cgroup_id = String("")
        self.bounce = BounceAttempt()
        self.map_result = MapResult()
        self.unmap = Unmap()
        self.copy = CopyPayload()
        self.sync = SyncRequest()
        self.transition = TransitionResult()
        self.pool = PoolSample()
        self.gap = Gap()
        self.marker = Marker()
        self.snapshot = CounterSnapshot()


def _parse_bounce(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_device = False
    var has_bytes = False
    var has_forced = False
    var has_op = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "bounce_attempt")
            if key == "device_id":
                if has_device:
                    raise ValidationError("device_id", "duplicate")
                out.bounce.device_id = _parse_id(scan, "bounce.device_id")
                has_device = True
            elif key == "requested_bytes":
                if has_bytes:
                    raise ValidationError("requested_bytes", "duplicate")
                out.bounce.requested_bytes = parse_u64_field(
                    scan, "bounce.requested_bytes"
                )
                has_bytes = True
            elif key == "forced":
                if has_forced:
                    raise ValidationError("forced", "duplicate")
                scan.skip_ws()
                out.bounce.forced = scan.parse_bool()
                has_forced = True
            elif key == "operation_id":
                if has_op:
                    raise ValidationError("operation_id", "duplicate")
                out.bounce.operation_id = _parse_id(scan, "bounce.operation_id")
                has_op = True
            else:
                raise ValidationError("bounce_attempt", "unknown bounce_attempt field")
            if not object_next(scan, "bounce_attempt"):
                break
    scan.end_object()
    if not has_device or not has_bytes or not has_forced or not has_op:
        raise ValidationError("bounce_attempt", "missing field")


def _parse_map_result(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_op = False
    var has_success = False
    var has_mapping = False
    var has_code = False
    var has_bytes = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "map_result")
            if key == "operation_id":
                if has_op:
                    raise ValidationError("operation_id", "duplicate")
                out.map_result.operation_id = _parse_id(
                    scan, "map_result.operation_id"
                )
                has_op = True
            elif key == "success":
                if has_success:
                    raise ValidationError("success", "duplicate")
                scan.skip_ws()
                out.map_result.success = scan.parse_bool()
                has_success = True
            elif key == "mapping_id":
                if has_mapping:
                    raise ValidationError("mapping_id", "duplicate")
                var m = _parse_maybe_id(scan, "map_result.mapping_id")
                if m.has:
                    out.map_result.mapping_id = m.value
                    out.map_result.has_mapping_id = True
                has_mapping = True
            elif key == "return_code":
                if has_code:
                    raise ValidationError("return_code", "duplicate")
                var m = parse_maybe_int(scan)
                if m.has:
                    out.map_result.return_code = m.value
                    out.map_result.has_return_code = True
                has_code = True
            elif key == "mapped_bytes":
                if has_bytes:
                    raise ValidationError("mapped_bytes", "duplicate")
                var m = parse_maybe_u64(scan)
                if m.has:
                    out.map_result.mapped_bytes = m.value
                    out.map_result.has_mapped_bytes = True
                has_bytes = True
            else:
                raise ValidationError("map_result", "unknown map_result field")
            if not object_next(scan, "map_result"):
                break
    scan.end_object()
    if (
        not has_op
        or not has_success
        or not has_mapping
        or not has_code
        or not has_bytes
    ):
        raise ValidationError("map_result", "missing field")
    if out.map_result.success:
        if not out.map_result.has_mapping_id:
            raise ValidationError("map_result", "success lacks mapping_id")
        if not out.map_result.has_mapped_bytes:
            raise ValidationError("map_result", "success lacks mapped_bytes")
    else:
        if out.map_result.has_mapping_id:
            raise ValidationError("map_result", "failure carries mapping_id")
        if out.map_result.has_mapped_bytes:
            raise ValidationError("map_result", "failure carries mapped_bytes")


def _parse_unmap(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_mapping = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "unmap")
            if key == "mapping_id":
                if has_mapping:
                    raise ValidationError("mapping_id", "duplicate")
                var m = _parse_maybe_id(scan, "unmap.mapping_id")
                if m.has:
                    out.unmap.mapping_id = m.value
                    out.unmap.has_mapping_id = True
                has_mapping = True
            else:
                raise ValidationError("unmap", "unknown unmap field")
            if not object_next(scan, "unmap"):
                break
    scan.end_object()
    if not has_mapping:
        raise ValidationError("unmap", "missing field")


def _parse_copy(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_op = False
    var has_mapping = False
    var has_dir = False
    var has_bytes = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "copy")
            if key == "operation_id":
                if has_op:
                    raise ValidationError("operation_id", "duplicate")
                out.copy.operation_id = _parse_id(scan, "copy.operation_id")
                has_op = True
            elif key == "mapping_id":
                if has_mapping:
                    raise ValidationError("mapping_id", "duplicate")
                var m = _parse_maybe_id(scan, "copy.mapping_id")
                if m.has:
                    out.copy.mapping_id = m.value
                    out.copy.has_mapping_id = True
                has_mapping = True
            elif key == "direction":
                if has_dir:
                    raise ValidationError("direction", "duplicate")
                var v = scan.parse_string()
                if v != "original_to_bounce" and v != "bounce_to_original":
                    raise ValidationError("copy.direction", "bad enum")
                out.copy.direction = v
                has_dir = True
            elif key == "bytes":
                if has_bytes:
                    raise ValidationError("bytes", "duplicate")
                out.copy.bytes = parse_u64_field(scan, "copy.bytes")
                has_bytes = True
            else:
                raise ValidationError("copy", "unknown copy field")
            if not object_next(scan, "copy"):
                break
    scan.end_object()
    if not has_op or not has_mapping or not has_dir or not has_bytes:
        raise ValidationError("copy", "missing field")


def _parse_sync(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_op = False
    var has_mapping = False
    var has_offset = False
    var has_length = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "sync_request")
            if key == "operation_id":
                if has_op:
                    raise ValidationError("operation_id", "duplicate")
                out.sync.operation_id = _parse_id(scan, "sync.operation_id")
                has_op = True
            elif key == "mapping_id":
                if has_mapping:
                    raise ValidationError("mapping_id", "duplicate")
                var m = _parse_maybe_id(scan, "sync.mapping_id")
                if m.has:
                    out.sync.mapping_id = m.value
                    out.sync.has_mapping_id = True
                has_mapping = True
            elif key == "offset":
                if has_offset:
                    raise ValidationError("offset", "duplicate")
                out.sync.offset = parse_u64_field(scan, "sync.offset")
                has_offset = True
            elif key == "length":
                if has_length:
                    raise ValidationError("length", "duplicate")
                out.sync.length = parse_u64_field(scan, "sync.length")
                has_length = True
            else:
                raise ValidationError("sync_request", "unknown sync_request field")
            if not object_next(scan, "sync_request"):
                break
    scan.end_object()
    if not has_op or not has_mapping or not has_offset or not has_length:
        raise ValidationError("sync_request", "missing field")
    try:
        _ = checked_add(out.sync.offset, out.sync.length)
    except:
        raise ValidationError("sync_request", "span overflows")


def _parse_transition(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_region = False
    var has_state = False
    var has_success = False
    var has_code = False
    var has_offset = False
    var has_length = False
    var has_generation = False
    var has_space = False
    var has_resolution = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "transition_result")
            if key == "region_id":
                if has_region:
                    raise ValidationError("region_id", "duplicate")
                out.transition.region_id = _parse_id(
                    scan, "transition.region_id"
                )
                has_region = True
            elif key == "requested_state":
                if has_state:
                    raise ValidationError("requested_state", "duplicate")
                var v = scan.parse_string()
                if v != "shared" and v != "private":
                    raise ValidationError(
                        "transition.requested_state", "bad enum"
                    )
                out.transition.requested_state = v
                has_state = True
            elif key == "success":
                if has_success:
                    raise ValidationError("success", "duplicate")
                scan.skip_ws()
                out.transition.success = scan.parse_bool()
                has_success = True
            elif key == "return_code":
                if has_code:
                    raise ValidationError("return_code", "duplicate")
                var m = parse_maybe_int(scan)
                if m.has:
                    out.transition.return_code = m.value
                    out.transition.has_return_code = True
                has_code = True
            elif key == "offset":
                if has_offset:
                    raise ValidationError("offset", "duplicate")
                out.transition.offset = parse_u64_field(
                    scan, "transition.offset"
                )
                has_offset = True
            elif key == "length":
                if has_length:
                    raise ValidationError("length", "duplicate")
                out.transition.length = parse_u64_field(
                    scan, "transition.length"
                )
                has_length = True
            elif key == "generation":
                if has_generation:
                    raise ValidationError("generation", "duplicate")
                scan.skip_ws()
                var g = scan.parse_int()
                if g < Int64(1):
                    raise ValidationError(
                        "transition.generation", "must be positive"
                    )
                out.transition.generation = Int(g)
                has_generation = True
            elif key == "address_space":
                if has_space:
                    raise ValidationError("address_space", "duplicate")
                var v = scan.parse_string()
                if (
                    v != "guest_physical"
                    and v != "kernel_virtual"
                    and v != "iova"
                    and v != "identity_only"
                ):
                    raise ValidationError(
                        "transition.address_space", "bad enum"
                    )
                out.transition.address_space = v
                out.transition.has_address_space = True
                has_space = True
            elif key == "resolution":
                if has_resolution:
                    raise ValidationError("resolution", "duplicate")
                var v = scan.parse_string()
                if v != "resolved" and v != "unresolved":
                    raise ValidationError("transition.resolution", "bad enum")
                out.transition.resolution = v
                out.transition.has_resolution = True
                has_resolution = True
            else:
                raise ValidationError("transition_result", "unknown transition_result field")
            if not object_next(scan, "transition_result"):
                break
    scan.end_object()
    if (
        not has_region
        or not has_state
        or not has_success
        or not has_code
        or not has_offset
        or not has_length
    ):
        raise ValidationError("transition_result", "missing field")
    try:
        _ = checked_add(out.transition.offset, out.transition.length)
    except:
        raise ValidationError("transition_result", "span overflows")


def _parse_pool(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_pool = False
    var has_used = False
    var has_cap = False
    var has_unit = False
    var has_allocator = False
    var has_unit_bytes = False
    var has_hiwater = False
    var has_reason = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "pool_sample")
            if key == "pool_id":
                if has_pool:
                    raise ValidationError("pool_id", "duplicate")
                out.pool.pool_id = _parse_id(scan, "pool.pool_id")
                has_pool = True
            elif key == "used_bytes":
                if has_used:
                    raise ValidationError("used_bytes", "duplicate")
                var m = parse_maybe_u64(scan)
                if m.has:
                    out.pool.used_bytes = m.value
                    out.pool.has_used = True
                has_used = True
            elif key == "capacity_bytes":
                if has_cap:
                    raise ValidationError("capacity_bytes", "duplicate")
                var m = parse_maybe_u64(scan)
                if m.has:
                    out.pool.capacity_bytes = m.value
                    out.pool.has_capacity = True
                has_cap = True
            elif key == "unit":
                if has_unit:
                    raise ValidationError("unit", "duplicate")
                var v = scan.parse_string()
                if v != "bytes" and v != "unknown":
                    raise ValidationError("pool.unit", "bad enum")
                out.pool.unit = v
                has_unit = True
            elif key == "allocator":
                if has_allocator:
                    raise ValidationError("allocator", "duplicate")
                out.pool.allocator = _parse_id(scan, "pool.allocator")
                has_allocator = True
            elif key == "unit_bytes":
                if has_unit_bytes:
                    raise ValidationError("unit_bytes", "duplicate")
                var u = parse_u64_field(scan, "pool.unit_bytes")
                if u == UInt64(0):
                    raise ValidationError(
                        "pool.unit_bytes", "must be positive"
                    )
                out.pool.unit_bytes = u
                out.pool.has_unit_bytes = True
                has_unit_bytes = True
            elif key == "hiwater_bytes":
                if has_hiwater:
                    raise ValidationError("hiwater_bytes", "duplicate")
                var h = parse_maybe_u64(scan)
                if h.has:
                    out.pool.hiwater_bytes = h.value
                    out.pool.has_hiwater = True
                has_hiwater = True
            elif key == "reason":
                if has_reason:
                    raise ValidationError("reason", "duplicate")
                var r = scan.parse_string()
                if (
                    r != "denied"
                    and r != "absent"
                    and r != "unparseable"
                ):
                    raise ValidationError("pool.reason", "bad enum")
                out.pool.reason = r
                has_reason = True
            else:
                raise ValidationError("pool_sample", "unknown pool_sample field")
            if not object_next(scan, "pool_sample"):
                break
    scan.end_object()
    if not has_pool or not has_used or not has_cap or not has_unit:
        raise ValidationError("pool_sample", "missing field")


def _parse_gap(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_channel = False
    var has_lost = False
    var has_reason = False
    var has_start = False
    var has_end = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "gap")
            if key == "channel":
                if has_channel:
                    raise ValidationError("channel", "duplicate")
                var v = scan.parse_string()
                if (
                    v != "detail"
                    and v != "aggregate"
                    and v != "correlation"
                    and v != "baseline"
                    and v != "terminal"
                ):
                    raise ValidationError("gap.channel", "bad enum")
                out.gap.channel = v
                has_channel = True
            elif key == "lost_count":
                if has_lost:
                    raise ValidationError("lost_count", "duplicate")
                var m = parse_maybe_u64(scan)
                if m.has:
                    out.gap.lost_count = m.value
                    out.gap.has_lost_count = True
                has_lost = True
            elif key == "reason":
                if has_reason:
                    raise ValidationError("reason", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 512, "gap.reason")
                out.gap.reason = v
                has_reason = True
            elif key == "window_start_ns":
                if has_start:
                    raise ValidationError("window_start_ns", "duplicate")
                out.gap.window_start_ns = parse_u64_field(
                    scan, "gap.window_start_ns"
                )
                has_start = True
            elif key == "window_end_ns":
                if has_end:
                    raise ValidationError("window_end_ns", "duplicate")
                out.gap.window_end_ns = parse_u64_field(
                    scan, "gap.window_end_ns"
                )
                has_end = True
            else:
                raise ValidationError("gap", "unknown gap field")
            if not object_next(scan, "gap"):
                break
    scan.end_object()
    if (
        not has_channel
        or not has_lost
        or not has_reason
        or not has_start
        or not has_end
    ):
        raise ValidationError("gap", "missing field")


def _parse_marker(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_text = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "marker")
            if key == "text":
                if has_text:
                    raise ValidationError("text", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 256, "marker.text")
                out.marker.text = v
                has_text = True
            else:
                raise ValidationError("marker", "unknown marker field")
            if not object_next(scan, "marker"):
                break
    scan.end_object()
    if not has_text:
        raise ValidationError("marker", "missing field")


def _parse_snapshot_scope(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_device = False
    var has_profile = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "counter_snapshot.scope")
            if key == "device_id":
                if has_device:
                    raise ValidationError("device_id", "duplicate")
                var m = _parse_maybe_id(scan, "snapshot.scope.device_id")
                if m.has:
                    out.snapshot.scope_device_id = m.value
                    out.snapshot.has_scope_device = True
                has_device = True
            elif key == "profile_id":
                if has_profile:
                    raise ValidationError("profile_id", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 128, "snapshot.scope.profile_id")
                out.snapshot.scope_profile_id = v
                has_profile = True
            else:
                raise ValidationError("counter_snapshot.scope", "unknown snapshot scope field")
            if not object_next(scan, "counter_snapshot.scope"):
                break
    scan.end_object()
    if not has_profile:
        raise ValidationError("counter_snapshot.scope", "missing field")


def _parse_snapshot(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_counter = False
    var has_epoch = False
    var has_scope = False
    var has_value = False
    var has_unit = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "counter_snapshot")
            if key == "counter_id":
                if has_counter:
                    raise ValidationError("counter_id", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 128, "snapshot.counter_id")
                out.snapshot.counter_id = v
                has_counter = True
            elif key == "epoch":
                if has_epoch:
                    raise ValidationError("epoch", "duplicate")
                out.snapshot.epoch = parse_u64_field(scan, "snapshot.epoch")
                has_epoch = True
            elif key == "scope":
                if has_scope:
                    raise ValidationError("scope", "duplicate")
                _parse_snapshot_scope(scan, out)
                has_scope = True
            elif key == "value":
                if has_value:
                    raise ValidationError("value", "duplicate")
                out.snapshot.value = parse_u64_field(scan, "snapshot.value")
                has_value = True
            elif key == "unit":
                if has_unit:
                    raise ValidationError("unit", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 32, "snapshot.unit")
                out.snapshot.unit = v
                has_unit = True
            else:
                raise ValidationError("counter_snapshot", "unknown counter_snapshot field")
            if not object_next(scan, "counter_snapshot"):
                break
    scan.end_object()
    if (
        not has_counter
        or not has_epoch
        or not has_scope
        or not has_value
        or not has_unit
    ):
        raise ValidationError("counter_snapshot", "missing field")


def _parse_source(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_hook = False
    var has_backend = False
    var has_profile = False
    var has_measurement = False
    var has_correlation = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "source")
            if key == "hook":
                if has_hook:
                    raise ValidationError("source.hook", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 256, "source.hook")
                out.source_hook = v
                has_hook = True
            elif key == "backend":
                if has_backend:
                    raise ValidationError("source.backend", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 64, "source.backend")
                out.source_backend = v
                has_backend = True
            elif key == "profile_id":
                if has_profile:
                    raise ValidationError("source.profile_id", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 128, "source.profile_id")
                out.source_profile_id = v
                has_profile = True
            elif key == "measurement":
                if has_measurement:
                    raise ValidationError("source.measurement", "duplicate")
                var v = scan.parse_string()
                _check_measurement(v)
                out.source_measurement = v
                has_measurement = True
            elif key == "correlation":
                if has_correlation:
                    raise ValidationError("source.correlation", "duplicate")
                var v = scan.parse_string()
                _check_correlation(v)
                out.source_correlation = v
                has_correlation = True
            else:
                raise ValidationError("source", "unknown source field")
            if not object_next(scan, "source"):
                break
    scan.end_object()
    if (
        not has_hook
        or not has_backend
        or not has_profile
        or not has_measurement
        or not has_correlation
    ):
        raise ValidationError("source", "missing field")


def _parse_observer(mut scan: Scanner, mut out: Event) raises:
    scan.begin_object()
    var has_cpu = False
    var has_pid = False
    var has_tgid = False
    var has_comm = False
    var has_cgroup = False
    var has_relation = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "observer_context")
            if key == "cpu":
                if has_cpu:
                    raise ValidationError("observer.cpu", "duplicate")
                scan.skip_ws()
                var v = scan.parse_int()
                if v < Int64(0) or v > MAX_CPU:
                    raise ValidationError("observer.cpu", "out of range")
                out.cpu = v
                out.has_cpu = True
                has_cpu = True
            elif key == "pid":
                if has_pid:
                    raise ValidationError("observer.pid", "duplicate")
                scan.skip_ws()
                var v = scan.parse_int()
                if v < Int64(0) or v > MAX_PID:
                    raise ValidationError("observer.pid", "out of range")
                out.pid = v
                out.has_pid = True
                has_pid = True
            elif key == "tgid":
                if has_tgid:
                    raise ValidationError("observer.tgid", "duplicate")
                scan.skip_ws()
                var v = scan.parse_int()
                if v < Int64(0) or v > MAX_PID:
                    raise ValidationError("observer.tgid", "out of range")
                out.tgid = v
                out.has_tgid = True
                has_tgid = True
            elif key == "comm":
                if has_comm:
                    raise ValidationError("observer.comm", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 0, 64, "observer.comm")
                out.comm = v
                out.has_comm = True
                has_comm = True
            elif key == "cgroup_id":
                if has_cgroup:
                    raise ValidationError("observer.cgroup_id", "duplicate")
                out.cgroup_id = _parse_id(scan, "observer.cgroup_id")
                out.has_cgroup_id = True
                has_cgroup = True
            elif key == "relation":
                if has_relation:
                    raise ValidationError("observer.relation", "duplicate")
                var v = scan.parse_string()
                if v != "execution_context_only":
                    raise ValidationError("observer.relation", "bad const")
                has_relation = True
            else:
                raise ValidationError("observer", "unknown observer field")
            if not object_next(scan, "observer_context"):
                break
    scan.end_object()
    if not has_relation:
        raise ValidationError("observer_context", "missing field")
    out.has_observer = True


def _parse_data_span(
    kind: String, span: List[UInt8], mut out: Event
) raises:
    """Parse a deferred data object now that the kind is known."""
    var scan = Scanner(span)
    scan.skip_ws()
    if kind == "bounce_attempt":
        _parse_bounce(scan, out)
    elif kind == "map_result":
        _parse_map_result(scan, out)
    elif kind == "unmap":
        _parse_unmap(scan, out)
    elif kind == "copy":
        _parse_copy(scan, out)
    elif kind == "sync_request":
        _parse_sync(scan, out)
    elif kind == "transition_result":
        _parse_transition(scan, out)
    elif kind == "pool_sample":
        _parse_pool(scan, out)
    elif kind == "gap":
        _parse_gap(scan, out)
    elif kind == "marker":
        _parse_marker(scan, out)
    elif kind == "counter_snapshot":
        _parse_snapshot(scan, out)
    else:
        raise ValidationError("kind", "unknown event kind")
    scan.skip_ws()
    if not scan.at_end():
        raise ValidationError("data", "trailing data")


def parse_event(data: List[UInt8]) raises -> Event:
    """Parse and validate one event line.

    Key order is free: the data object is captured as a source span
    on first sight and parsed after the kind is known.
    """
    var scan = Scanner(data)
    scan.skip_ws()
    scan.begin_object()
    var out = Event()
    var has_version = False
    var has_session = False
    var has_seq = False
    var has_ts = False
    var has_kind = False
    var has_source = False
    var has_observer = False
    var has_data = False
    var data_start = -1
    var data_end = -1
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "event")
            if key == "schema_version":
                if has_version:
                    raise ValidationError("schema_version", "duplicate")
                var v = scan.parse_string()
                if v != EVENT_SCHEMA_VERSION:
                    raise ValidationError("schema_version", "bad const")
                has_version = True
            elif key == "session_id":
                if has_session:
                    raise ValidationError("session_id", "duplicate")
                out.session_id = _parse_id(scan, "event.session_id")
                has_session = True
            elif key == "seq":
                if has_seq:
                    raise ValidationError("seq", "duplicate")
                out.seq = parse_u64_field(scan, "event.seq")
                has_seq = True
            elif key == "ts_ns":
                if has_ts:
                    raise ValidationError("ts_ns", "duplicate")
                out.ts_ns = parse_u64_field(scan, "event.ts_ns")
                has_ts = True
            elif key == "kind":
                if has_kind:
                    raise ValidationError("kind", "duplicate")
                var v = scan.parse_string()
                _check_kind(v)
                out.kind = v
                has_kind = True
            elif key == "source":
                if has_source:
                    raise ValidationError("source", "duplicate")
                _parse_source(scan, out)
                has_source = True
            elif key == "observer_context":
                if has_observer:
                    raise ValidationError("observer_context", "duplicate")
                _parse_observer(scan, out)
                has_observer = True
            elif key == "data":
                if has_data:
                    raise ValidationError("data", "duplicate")
                scan.skip_ws()
                data_start = scan.offset()
                scan.skip_value()
                data_end = scan.offset()
                has_data = True
            else:
                raise ValidationError("event", "unknown event field")
            if not object_next(scan, "event"):
                break
    scan.end_object()
    if (
        not has_version
        or not has_session
        or not has_seq
        or not has_ts
        or not has_kind
        or not has_source
        or not has_data
    ):
        raise ValidationError("event", "missing field")
    scan.skip_ws()
    if not scan.at_end():
        raise ValidationError("event", "trailing data")
    var span = scan.span_bytes(data_start, data_end)
    var kind = out.kind
    if kind == "copy" and out.source_measurement != "observed":
        raise ValidationError(
            "copy.source.measurement", "executed copies require observed measurement"
        )
    _parse_data_span(kind, span, out)
    return out^


def _top_field_known(key: String) -> Bool:
    """Mirror of parse_event's accepted top-level keys."""
    return (
        key == "schema_version"
        or key == "session_id"
        or key == "seq"
        or key == "ts_ns"
        or key == "kind"
        or key == "source"
        or key == "observer_context"
        or key == "data"
    )


def _source_field_known(key: String) -> Bool:
    """Mirror of _parse_source's accepted keys."""
    return (
        key == "hook"
        or key == "backend"
        or key == "profile_id"
        or key == "measurement"
        or key == "correlation"
    )


def _observer_field_known(key: String) -> Bool:
    """Mirror of _parse_observer's accepted keys."""
    return (
        key == "cpu"
        or key == "pid"
        or key == "tgid"
        or key == "comm"
        or key == "cgroup_id"
        or key == "relation"
    )


def _scope_field_known(key: String) -> Bool:
    """Mirror of _parse_snapshot_scope's accepted keys."""
    return key == "device_id" or key == "profile_id"


def _data_field_known(kind: String, key: String) -> Bool:
    """Mirror of the per-kind _parse_* accepted data keys."""
    if kind == "bounce_attempt":
        return (
            key == "device_id"
            or key == "requested_bytes"
            or key == "forced"
            or key == "operation_id"
        )
    if kind == "map_result":
        return (
            key == "operation_id"
            or key == "success"
            or key == "mapping_id"
            or key == "return_code"
            or key == "mapped_bytes"
        )
    if kind == "unmap":
        return key == "mapping_id"
    if kind == "copy":
        return (
            key == "operation_id"
            or key == "mapping_id"
            or key == "direction"
            or key == "bytes"
        )
    if kind == "sync_request":
        return (
            key == "operation_id"
            or key == "mapping_id"
            or key == "offset"
            or key == "length"
        )
    if kind == "transition_result":
        return (
            key == "region_id"
            or key == "requested_state"
            or key == "success"
            or key == "return_code"
            or key == "offset"
            or key == "length"
            or key == "address_space"
            or key == "resolution"
            or key == "generation"
        )
    if kind == "pool_sample":
        return (
            key == "pool_id"
            or key == "used_bytes"
            or key == "capacity_bytes"
            or key == "unit"
            or key == "allocator"
            or key == "unit_bytes"
            or key == "hiwater_bytes"
            or key == "reason"
        )
    if kind == "gap":
        return (
            key == "channel"
            or key == "lost_count"
            or key == "reason"
            or key == "window_start_ns"
            or key == "window_end_ns"
        )
    if kind == "marker":
        return key == "text"
    if kind == "counter_snapshot":
        return (
            key == "counter_id"
            or key == "epoch"
            or key == "scope"
            or key == "value"
            or key == "unit"
        )
    return False


def _type_rows() -> List[String]:
    """Accepted JSON value shapes as ctx,kind,key,lead rows.

    Mirrors the value parser each _parse_* function applies per
    key: s string, b boolean, n number, o object, S string-or-null,
    N number-or-null. A truncated value whose first byte cannot
    grow into its shape is definitively invalid. The reports lane
    checks these rows against the parsers in both directions
    (f4-key-mirror).
    """
    var out = List[String]()
    out.append(String("top,,schema_version,s"))
    out.append(String("top,,session_id,s"))
    out.append(String("top,,seq,s"))
    out.append(String("top,,ts_ns,s"))
    out.append(String("top,,kind,s"))
    out.append(String("top,,source,o"))
    out.append(String("top,,observer_context,o"))
    out.append(String("top,,data,o"))
    out.append(String("source,,hook,s"))
    out.append(String("source,,backend,s"))
    out.append(String("source,,profile_id,s"))
    out.append(String("source,,measurement,s"))
    out.append(String("source,,correlation,s"))
    out.append(String("observer,,cpu,n"))
    out.append(String("observer,,pid,n"))
    out.append(String("observer,,tgid,n"))
    out.append(String("observer,,comm,s"))
    out.append(String("observer,,cgroup_id,s"))
    out.append(String("observer,,relation,s"))
    out.append(String("scope,,device_id,S"))
    out.append(String("scope,,profile_id,s"))
    out.append(String("data,bounce_attempt,device_id,s"))
    out.append(String("data,bounce_attempt,requested_bytes,s"))
    out.append(String("data,bounce_attempt,forced,b"))
    out.append(String("data,bounce_attempt,operation_id,s"))
    out.append(String("data,map_result,operation_id,s"))
    out.append(String("data,map_result,success,b"))
    out.append(String("data,map_result,mapping_id,S"))
    out.append(String("data,map_result,return_code,N"))
    out.append(String("data,map_result,mapped_bytes,S"))
    out.append(String("data,unmap,mapping_id,S"))
    out.append(String("data,copy,operation_id,s"))
    out.append(String("data,copy,mapping_id,S"))
    out.append(String("data,copy,direction,s"))
    out.append(String("data,copy,bytes,s"))
    out.append(String("data,sync_request,operation_id,s"))
    out.append(String("data,sync_request,mapping_id,S"))
    out.append(String("data,sync_request,offset,s"))
    out.append(String("data,sync_request,length,s"))
    out.append(String("data,transition_result,region_id,s"))
    out.append(String("data,transition_result,requested_state,s"))
    out.append(String("data,transition_result,success,b"))
    out.append(String("data,transition_result,return_code,N"))
    out.append(String("data,transition_result,offset,s"))
    out.append(String("data,transition_result,length,s"))
    out.append(String("data,transition_result,address_space,s"))
    out.append(String("data,transition_result,resolution,s"))
    out.append(String("data,transition_result,generation,n"))
    out.append(String("data,pool_sample,pool_id,s"))
    out.append(String("data,pool_sample,used_bytes,S"))
    out.append(String("data,pool_sample,capacity_bytes,S"))
    out.append(String("data,pool_sample,unit,s"))
    out.append(String("data,pool_sample,allocator,s"))
    out.append(String("data,pool_sample,unit_bytes,s"))
    out.append(String("data,pool_sample,hiwater_bytes,S"))
    out.append(String("data,pool_sample,reason,s"))
    out.append(String("data,gap,channel,s"))
    out.append(String("data,gap,lost_count,S"))
    out.append(String("data,gap,reason,s"))
    out.append(String("data,gap,window_start_ns,s"))
    out.append(String("data,gap,window_end_ns,s"))
    out.append(String("data,marker,text,s"))
    out.append(String("data,counter_snapshot,counter_id,s"))
    out.append(String("data,counter_snapshot,epoch,s"))
    out.append(String("data,counter_snapshot,scope,o"))
    out.append(String("data,counter_snapshot,value,s"))
    out.append(String("data,counter_snapshot,unit,s"))
    return out^


def _expected_lead(
    rows: List[String], ctx: String, kind: String, key: String
) -> String:
    """Look up one field's expected JSON shape code, or ""."""
    for i in range(len(rows)):
        var parts = rows[i].split(String(","))
        if (
            len(parts) == 4
            and String(parts[0]) == ctx
            and String(parts[1]) == kind
            and String(parts[2]) == key
        ):
            return String(parts[3])
    return String("")


def _lead_ok(lead: String, fb: UInt8) -> Bool:
    """True when a truncated value's first byte can still grow valid."""
    if lead == "s":
        return fb == UInt8(0x22)
    if lead == "b":
        return fb == UInt8(0x74) or fb == UInt8(0x66)
    if lead == "n":
        return fb == UInt8(0x2D) or (
            fb >= UInt8(0x30) and fb <= UInt8(0x39)
        )
    if lead == "o":
        return fb == UInt8(0x7B)
    if lead == "S":
        return fb == UInt8(0x22) or fb == UInt8(0x6E)
    if lead == "N":
        return (
            fb == UInt8(0x2D)
            or (fb >= UInt8(0x30) and fb <= UInt8(0x39))
            or fb == UInt8(0x6E)
        )
    return True


def _span_bytes(data: List[UInt8], start: Int, end: Int) -> List[UInt8]:
    """Copy one byte span out of a tail buffer."""
    var out = List[UInt8]()
    var i = start
    while i < end:
        out.append(data[i])
        i += 1
    return out^


def _decode_span(span: List[UInt8]) raises -> String:
    """Decode one complete string token; the span is exact."""
    var scan = Scanner(span)
    scan.skip_ws()
    var out = scan.parse_string()
    scan.skip_ws()
    if not scan.at_end():
        raise ValidationError("span", "trailing data")
    return out^


def _ctx_known(ctx: String, kind: String, key: String) -> Bool:
    """True when key is accepted in this nested object context."""
    if ctx == "source":
        return _source_field_known(key)
    if ctx == "observer":
        return _observer_field_known(key)
    if ctx == "scope":
        return _scope_field_known(key)
    if ctx == "data":
        return _data_field_known(kind, key)
    return True


def _walk_keys(
    data: List[UInt8],
    members: List[TailMember],
    ctx: String,
    kind: String,
    depth: Int,
    rows: List[String],
) -> Bool:
    """True when complete keys in one nested object prove rejection.

    Checks duplicates and unknown fields for every complete key,
    screens truncated values against their expected JSON shape,
    direct-parses complete objects where the schema is known, and
    recurses into the rest. Complete scalar values are left to the
    completed-subdocument parse; only key and value shape are
    judged here.
    """
    var seen = Dict[String, Bool]()
    for m in members:
        var key: String
        try:
            key = _decode_span(_span_bytes(data, m.key_start, m.key_end))
        except:
            return True
        if key in seen:
            return True
        seen[key] = True
        if ctx != "" and not _ctx_known(ctx, kind, key):
            return True
        if m.val_verdict == TAIL_INVALID:
            return True
        var has_val = m.val_start < len(data)
        var is_obj = has_val and data[m.val_start] == UInt8(0x7B)
        var is_arr = has_val and data[m.val_start] == UInt8(0x5B)
        if (
            ctx != ""
            and m.val_verdict == TAIL_INCOMPLETE
            and has_val
        ):
            var lead = _expected_lead(rows, ctx, kind, key)
            if lead != "" and not _lead_ok(lead, data[m.val_start]):
                return True
        if m.val_verdict == TAIL_COMPLETE:
            if not is_obj:
                continue
            if (
                ctx == "data"
                and key == "scope"
                and kind == "counter_snapshot"
            ):
                var dummy = Event()
                try:
                    var scan = Scanner(
                        _span_bytes(data, m.val_start, m.val_end)
                    )
                    _parse_snapshot_scope(scan, dummy)
                except:
                    return True
                continue
            if ctx == "":
                var sub = List[TailMember]()
                var p = m.val_start
                var v = tail_scan_members(
                    data, p, depth + 1, MAX_DEPTH_DEFAULT, sub
                )
                if v == TAIL_INVALID:
                    return True
                if _walk_keys(data, sub, String(""), String(""), depth + 1, rows):
                    return True
                continue
            return True
        if is_arr and ctx != "":
            return True
        if not is_obj:
            continue
        if ctx == "data" and key == "scope" and kind == "counter_snapshot":
            var sub = List[TailMember]()
            var p = m.val_start
            var v = tail_scan_members(
                data, p, depth + 1, MAX_DEPTH_DEFAULT, sub
            )
            if v == TAIL_INVALID:
                return True
            # Scope rows carry an empty kind: passing the data kind
            # here would miss every shape lookup below.
            if _walk_keys(
                data, sub, String("scope"), String(""), depth + 1, rows
            ):
                return True
            continue
        if ctx == "":
            var sub = List[TailMember]()
            var p = m.val_start
            var v = tail_scan_members(
                data, p, depth + 1, MAX_DEPTH_DEFAULT, sub
            )
            if v == TAIL_INVALID:
                return True
            if _walk_keys(data, sub, String(""), String(""), depth + 1, rows):
                return True
            continue
        return True
    return False


def _completed_bytes(
    data: List[UInt8],
    members: List[TailMember],
    depth: Int,
    mut over_depth: Bool,
) -> List[UInt8]:
    """Rebuild one object from its complete members, recursively.

    Complete values copy verbatim; incomplete objects rebuild from
    their own complete members; anything else truncated drops out.
    The result holds no partial token, so parsing it can only fail
    on violations already present in the tail bytes.
    """
    var out = List[UInt8]()
    out.append(UInt8(0x7B))
    var first = True
    for m in members:
        var use_sub = False
        var sub = List[UInt8]()
        if m.val_verdict == TAIL_COMPLETE:
            pass
        elif (
            m.val_start < len(data)
            and data[m.val_start] == UInt8(0x7B)
        ):
            var sub_members = List[TailMember]()
            var p = m.val_start
            var v = tail_scan_members(
                data, p, depth + 1, MAX_DEPTH_DEFAULT, sub_members
            )
            if v == TAIL_INVALID:
                over_depth = True
                return List[UInt8]()
            sub = _completed_bytes(data, sub_members, depth + 1, over_depth)
            if over_depth:
                return List[UInt8]()
            use_sub = True
        else:
            continue
        if not first:
            out.append(UInt8(0x2C))
        first = False
        var i = m.key_start
        while i < m.key_end:
            out.append(data[i])
            i += 1
        out.append(UInt8(0x3A))
        if use_sub:
            for b in sub:
                out.append(b)
        else:
            var j = m.val_start
            while j < m.val_end:
                out.append(data[j])
                j += 1
    out.append(UInt8(0x7D))
    return out^


def _parse_all_kinds(span: List[UInt8]) -> Bool:
    """True when complete data bytes parse under some event kind."""
    var kinds = List[String]()
    kinds.append(String("bounce_attempt"))
    kinds.append(String("map_result"))
    kinds.append(String("unmap"))
    kinds.append(String("copy"))
    kinds.append(String("sync_request"))
    kinds.append(String("transition_result"))
    kinds.append(String("pool_sample"))
    kinds.append(String("gap"))
    kinds.append(String("marker"))
    kinds.append(String("counter_snapshot"))
    for i in range(len(kinds)):
        var dummy = Event()
        try:
            _parse_data_span(kinds[i], span, dummy)
            return True
        except:
            pass
    return False


def partial_record_definitive(data: List[UInt8], session_id: String) -> Bool:
    """True when a truncated tail proves the record is invalid.

    The tail classified TAIL_INCOMPLETE: clean truncation so far as
    JSON syntax can tell. This scan looks further: complete keys
    are checked for duplicates, unknown fields, and session match;
    complete nested objects are parsed with the real schema
    validators; and the complete members rebuild a subdocument
    whose parse reuses every value rule. Only a "missing field"
    failure is inconclusive (members may have followed the cut);
    any other failure, on bytes fully present, is definitive.
    """
    var p = 0
    while p < len(data):
        var b = data[p]
        if (
            b == UInt8(0x20)
            or b == UInt8(0x09)
            or b == UInt8(0x0A)
            or b == UInt8(0x0D)
        ):
            p += 1
        else:
            break
    if p >= len(data) or data[p] != UInt8(0x7B):
        return True
    var members = List[TailMember]()
    var verdict = tail_scan_members(data, p, 0, MAX_DEPTH_DEFAULT, members)
    if verdict == TAIL_INVALID:
        return True
    var rows = _type_rows()
    var seen = Dict[String, Bool]()
    var keys = List[String]()
    var kind = String("")
    var has_kind = False
    var session = String("")
    var has_session = False
    for m in members:
        var key: String
        try:
            key = _decode_span(_span_bytes(data, m.key_start, m.key_end))
        except:
            return True
        if key in seen:
            return True
        seen[key] = True
        keys.append(key)
        if not _top_field_known(key):
            return True
        if m.val_verdict == TAIL_INCOMPLETE and m.val_start < len(data):
            var lead = _expected_lead(
                rows, String("top"), String(""), key
            )
            if lead != "" and not _lead_ok(lead, data[m.val_start]):
                return True
        if key == "kind" and m.val_verdict == TAIL_COMPLETE:
            try:
                kind = _decode_span(
                    _span_bytes(data, m.val_start, m.val_end)
                )
            except:
                return True
            has_kind = True
        if key == "session_id" and m.val_verdict == TAIL_COMPLETE:
            try:
                session = _decode_span(
                    _span_bytes(data, m.val_start, m.val_end)
                )
            except:
                return True
            has_session = True
    if has_session and session != session_id:
        return True
    for i in range(len(members)):
        var m = members[i]
        var key = keys[i]
        if m.val_verdict == TAIL_INVALID:
            return True
        var has_val = m.val_start < len(data)
        var is_obj = has_val and data[m.val_start] == UInt8(0x7B)
        var is_arr = has_val and data[m.val_start] == UInt8(0x5B)
        if m.val_verdict == TAIL_COMPLETE:
            if not is_obj and not is_arr:
                continue
            var span = _span_bytes(data, m.val_start, m.val_end)
            if key == "source":
                var dummy = Event()
                try:
                    var scan = Scanner(span)
                    _parse_source(scan, dummy)
                except:
                    return True
                continue
            if key == "observer_context":
                var dummy = Event()
                try:
                    var scan = Scanner(span)
                    _parse_observer(scan, dummy)
                except:
                    return True
                continue
            if key == "data" and not is_arr:
                if has_kind:
                    var dummy = Event()
                    try:
                        _parse_data_span(kind, span, dummy)
                    except:
                        return True
                elif not _parse_all_kinds(span):
                    return True
                continue
            return True
        if not is_obj:
            continue
        var sub = List[TailMember]()
        var sp = m.val_start
        var sv = tail_scan_members(data, sp, 1, MAX_DEPTH_DEFAULT, sub)
        if sv == TAIL_INVALID:
            return True
        var child = String("")
        var child_kind = String("")
        if key == "source":
            child = String("source")
        elif key == "observer_context":
            child = String("observer")
        elif key == "data" and has_kind:
            child = String("data")
            child_kind = kind
        if _walk_keys(data, sub, child, child_kind, 1, rows):
            return True
    var over_depth = False
    var sub = _completed_bytes(data, members, 0, over_depth)
    if over_depth:
        return True
    try:
        _ = parse_event(sub)
        return False
    except e:
        if String(e).find(String("missing field")) != -1:
            return False
        return True
