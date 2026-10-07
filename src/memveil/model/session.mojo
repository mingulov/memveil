# SPDX-License-Identifier: GPL-3.0-or-later

"""Typed capture session: session.json, format 0.1.0.

The parser validates the whole document against the frozen session
schema: required fields, const values, enum membership, string
lengths, array item caps, and no unknown or duplicated keys. The
observation window must satisfy start <= end; an empty window is
valid and simply matches no event. Device IDs must be unique within
the catalog.
"""

from memveil.jsonscan import Scanner
from memveil.model.common import (
    MaybeString,
    array_is_empty,
    array_next,
    expect_colon,
    object_is_empty,
    object_next,
    parse_maybe_string,
    parse_u64_field,
)
from memveil.model.regions import (
    RegionObservation,
    check_region_space,
    check_region_state,
)
from memveil.model.validate import (
    ValidationError,
    check_bounded_text,
    check_opaque_id,
    checked_add,
)

comptime MAX_EVIDENCE_ITEMS = 64
comptime MAX_DEVICES = 4096
comptime MAX_REGION_OBSERVATIONS = 4096
comptime MAX_HOOKS = 32
comptime MAX_EVIDENCE_REFS = 32
comptime SESSION_SCHEMA_VERSION = "0.1.0"
comptime PRODUCT_NAME = "memveil"


struct EvidenceItem(ImplicitlyCopyable):
    """One environment evidence record."""

    var item_type: String
    var source: String
    var interpretation: String

    def __init__(out self):
        self.item_type = String("")
        self.source = String("")
        self.interpretation = String("")


struct DeviceEntry(ImplicitlyCopyable):
    """One catalogued device."""

    var device_id: String
    var name: String
    var has_driver: Bool
    var driver: String
    var driver_present: Bool
    var identity_status: String

    def __init__(out self):
        self.device_id = String("")
        self.name = String("")
        self.has_driver = False
        self.driver = String("")
        self.driver_present = False
        self.identity_status = String("")


struct Capability(Copyable):
    """One producer capability claim."""

    var status: String
    var reason: String
    var hooks: List[String]
    var has_profile_id: Bool
    var profile_id: String

    def __init__(out self):
        self.status = String("")
        self.reason = String("")
        self.hooks = List[String]()
        self.has_profile_id = False
        self.profile_id = String("")

    def __copyinit__(mut self, existing: Self):
        self.status = existing.status
        self.reason = existing.reason
        self.hooks = existing.hooks.copy()
        self.has_profile_id = existing.has_profile_id
        self.profile_id = existing.profile_id


struct Channel(Copyable):
    """One session quality channel claim."""

    var status: String
    var has_loss_count: Bool
    var loss_count: UInt64
    var scope: String
    var reason: String
    var evidence_refs: List[String]

    def __init__(out self):
        self.status = String("")
        self.has_loss_count = False
        self.loss_count = UInt64(0)
        self.scope = String("")
        self.reason = String("")
        self.evidence_refs = List[String]()

    def __copyinit__(mut self, existing: Self):
        self.status = existing.status
        self.has_loss_count = existing.has_loss_count
        self.loss_count = existing.loss_count
        self.scope = existing.scope
        self.reason = existing.reason
        self.evidence_refs = existing.evidence_refs.copy()


def _check_env_mode(v: String) raises:
    if (
        v == "none"
        or v == "sev"
        or v == "sev_es"
        or v == "sev_snp"
        or v == "tdx"
        or v == "unknown"
    ):
        return
    raise ValidationError("environment.mode", "bad enum")


def _check_detection(v: String) raises:
    if v == "kernel_reported" or v == "unverified" or v == "conflicting":
        return
    raise ValidationError("environment.detection", "bad enum")


def _check_asserted_mode(v: String) raises:
    if (
        v == "none"
        or v == "sev"
        or v == "sev_es"
        or v == "sev_snp"
        or v == "tdx"
        or v == "unknown"
    ):
        return
    raise ValidationError("environment.asserted_mode", "bad enum")


def _check_attestation(v: String) raises:
    if v == "not_performed" or v == "external_verified" or v == "failed":
        return
    raise ValidationError("environment.attestation", "bad enum")


def _check_capture_mode(v: String) raises:
    if v == "live" or v == "synthetic":
        return
    raise ValidationError("capture.mode", "bad enum")


def _check_end_reason(v: String) raises:
    if (
        v == "duration"
        or v == "size_limit"
        or v == "signal"
        or v == "error"
        or v == "unknown"
    ):
        return
    raise ValidationError("capture.end_reason", "bad enum")


def _check_identity_status(v: String) raises:
    if v == "resolved" or v == "unresolved" or v == "exhausted":
        return
    raise ValidationError("device.identity_status", "bad enum")


def _check_capability_status(v: String) raises:
    if (
        v == "verified"
        or v == "partial"
        or v == "unavailable"
        or v == "disabled"
    ):
        return
    raise ValidationError("capability.status", "bad enum")


def _check_channel_status(v: String) raises:
    if (
        v == "complete_for_scope"
        or v == "partial"
        or v == "unavailable"
        or v == "not_applicable"
    ):
        return
    raise ValidationError("channel.status", "bad enum")


def _parse_evidence_item(mut scan: Scanner) raises -> EvidenceItem:
    scan.begin_object()
    var out = EvidenceItem()
    var has_type = False
    var has_source = False
    var has_interp = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "evidence_item")
            if key == "type":
                if has_type:
                    raise ValidationError("evidence_item.type", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 64, "evidence_item.type")
                out.item_type = v
                has_type = True
            elif key == "source":
                if has_source:
                    raise ValidationError("evidence_item.source", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 256, "evidence_item.source")
                out.source = v
                has_source = True
            elif key == "interpretation":
                if has_interp:
                    raise ValidationError(
                        "evidence_item.interpretation", "duplicate"
                    )
                var v = scan.parse_string()
                check_bounded_text(v, 0, 1024, "evidence_item.interpretation")
                out.interpretation = v
                has_interp = True
            else:
                raise ValidationError("evidence_item", "unknown evidence_item field")
            if not object_next(scan, "evidence_item"):
                break
    scan.end_object()
    if not has_type or not has_source or not has_interp:
        raise ValidationError("evidence_item", "missing field")
    return out^


def _parse_device(mut scan: Scanner) raises -> DeviceEntry:
    scan.begin_object()
    var out = DeviceEntry()
    var has_id = False
    var has_name = False
    var has_driver = False
    var has_status = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "device")
            if key == "device_id":
                if has_id:
                    raise ValidationError("device.device_id", "duplicate")
                var v = scan.parse_string()
                try:
                    check_opaque_id(v)
                except e:
                    raise ValidationError("device.device_id", String(e))
                out.device_id = v
                has_id = True
            elif key == "name":
                if has_name:
                    raise ValidationError("device.name", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 0, 256, "device.name")
                out.name = v
                has_name = True
            elif key == "driver":
                if has_driver:
                    raise ValidationError("device.driver", "duplicate")
                var m = parse_maybe_string(scan)
                out.driver_present = True
                if m.has:
                    check_bounded_text(m.value, 1, 128, "device.driver")
                    out.driver = m.value
                    out.has_driver = True
                has_driver = True
            elif key == "identity_status":
                if has_status:
                    raise ValidationError("device.identity_status", "duplicate")
                var v = scan.parse_string()
                _check_identity_status(v)
                out.identity_status = v
                has_status = True
            else:
                raise ValidationError("device", "unknown device field")
            if not object_next(scan, "device"):
                break
    scan.end_object()
    if not has_id or not has_name or not has_status:
        raise ValidationError("device", "missing field")
    return out^


def _parse_hooks(mut scan: Scanner) raises -> List[String]:
    scan.begin_array()
    var out = List[String]()
    if not array_is_empty(scan):
        while True:
            scan.skip_ws()
            var v = scan.parse_string()
            check_bounded_text(v, 1, 256, "capability.hooks[]")
            out.append(v)
            if len(out) > MAX_HOOKS:
                raise ValidationError("capability.hooks", "too many items")
            if not array_next(scan, "capability.hooks"):
                break
    scan.end_array()
    return out^


def _parse_capability(mut scan: Scanner, what: String) raises -> Capability:
    scan.begin_object()
    var out = Capability()
    var has_status = False
    var has_reason = False
    var has_hooks = False
    var has_profile = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, what)
            if key == "status":
                if has_status:
                    raise ValidationError(what + ".status", "duplicate")
                var v = scan.parse_string()
                _check_capability_status(v)
                out.status = v
                has_status = True
            elif key == "reason":
                if has_reason:
                    raise ValidationError(what + ".reason", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 512, what + ".reason")
                out.reason = v
                has_reason = True
            elif key == "hooks":
                if has_hooks:
                    raise ValidationError(what + ".hooks", "duplicate")
                out.hooks = _parse_hooks(scan)
                has_hooks = True
            elif key == "profile_id":
                if has_profile:
                    raise ValidationError(what + ".profile_id", "duplicate")
                var m = parse_maybe_string(scan)
                if m.has:
                    check_bounded_text(m.value, 1, 128, what + ".profile_id")
                    out.profile_id = m.value
                    out.has_profile_id = True
                has_profile = True
            else:
                raise ValidationError(what, "unknown capability field")
            if not object_next(scan, what):
                break
    scan.end_object()
    if not has_status or not has_reason or not has_hooks:
        raise ValidationError(what, "missing field")
    return out^


def _parse_channel(mut scan: Scanner, what: String) raises -> Channel:
    scan.begin_object()
    var out = Channel()
    var has_status = False
    var has_loss = False
    var has_scope = False
    var has_reason = False
    var has_refs = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, what)
            if key == "status":
                if has_status:
                    raise ValidationError(what + ".status", "duplicate")
                var v = scan.parse_string()
                _check_channel_status(v)
                out.status = v
                has_status = True
            elif key == "loss_count":
                if has_loss:
                    raise ValidationError(what + ".loss_count", "duplicate")
                scan.skip_ws()
                if scan.peek() == UInt8(0x6E):
                    scan.parse_null()
                else:
                    out.loss_count = parse_u64_field(scan, what + ".loss_count")
                    out.has_loss_count = True
                has_loss = True
            elif key == "scope":
                if has_scope:
                    raise ValidationError(what + ".scope", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 256, what + ".scope")
                out.scope = v
                has_scope = True
            elif key == "reason":
                if has_reason:
                    raise ValidationError(what + ".reason", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 512, what + ".reason")
                out.reason = v
                has_reason = True
            elif key == "evidence_refs":
                if has_refs:
                    raise ValidationError(what + ".evidence_refs", "duplicate")
                scan.begin_array()
                if not array_is_empty(scan):
                    while True:
                        scan.skip_ws()
                        var v = scan.parse_string()
                        check_bounded_text(v, 1, 256, what + ".evidence_refs[]")
                        out.evidence_refs.append(v)
                        if len(out.evidence_refs) > MAX_EVIDENCE_REFS:
                            raise ValidationError(
                                what + ".evidence_refs", "too many items"
                            )
                        if not array_next(scan, what + ".evidence_refs"):
                            break
                scan.end_array()
                has_refs = True
            else:
                raise ValidationError(what, "unknown channel field")
            if not object_next(scan, what):
                break
    scan.end_object()
    if not has_status or not has_loss or not has_scope or not has_reason:
        raise ValidationError(what, "missing field")
    return out^


def _parse_region_observation(mut scan: Scanner) raises -> RegionObservation:
    """Parse one baseline region observation with full detail kept."""
    scan.begin_object()
    var out = RegionObservation()
    var has_region = False
    var has_state = False
    var has_offset = False
    var has_length = False
    var has_space = False
    var has_prov = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "region_observation")
            if key == "region_id":
                if has_region:
                    raise ValidationError("region_id", "duplicate")
                var v = scan.parse_string()
                try:
                    check_opaque_id(v)
                except e:
                    raise ValidationError("region_id", String(e))
                out.region_id = v
                has_region = True
            elif key == "state":
                if has_state:
                    raise ValidationError("state", "duplicate")
                var v = scan.parse_string()
                check_region_state(v)
                out.state = v
                has_state = True
            elif key == "offset":
                if has_offset:
                    raise ValidationError("offset", "duplicate")
                out.offset = parse_u64_field(scan, "region_observation.offset")
                has_offset = True
            elif key == "length":
                if has_length:
                    raise ValidationError("length", "duplicate")
                out.length = parse_u64_field(scan, "region_observation.length")
                has_length = True
            elif key == "address_space":
                if has_space:
                    raise ValidationError("address_space", "duplicate")
                var v = scan.parse_string()
                check_region_space(v)
                out.address_space = v
                has_space = True
            elif key == "provenance":
                if has_prov:
                    raise ValidationError("provenance", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 512, "region_observation.provenance")
                out.provenance = v
                has_prov = True
            else:
                raise ValidationError("region_observation", "unknown region_observation field")
            if not object_next(scan, "region_observation"):
                break
    scan.end_object()
    if (
        not has_region
        or not has_state
        or not has_offset
        or not has_length
        or not has_space
        or not has_prov
    ):
        raise ValidationError("region_observation", "missing field")
    try:
        _ = checked_add(out.offset, out.length)
    except:
        raise ValidationError("region_observation", "span overflows")
    return out^


def _parse_environment(mut scan: Scanner, mut out: Session) raises:
    scan.begin_object()
    var has_mode = False
    var has_detection = False
    var has_asserted = False
    var has_attestation = False
    var has_evidence = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "environment")
            if key == "mode":
                if has_mode:
                    raise ValidationError("environment.mode", "duplicate")
                var v = scan.parse_string()
                _check_env_mode(v)
                out.env_mode = v
                has_mode = True
            elif key == "detection":
                if has_detection:
                    raise ValidationError("environment.detection", "duplicate")
                var v = scan.parse_string()
                _check_detection(v)
                out.env_detection = v
                has_detection = True
            elif key == "asserted_mode":
                if has_asserted:
                    raise ValidationError(
                        "environment.asserted_mode", "duplicate"
                    )
                var m = parse_maybe_string(scan)
                out.asserted_mode_present = True
                if m.has:
                    _check_asserted_mode(m.value)
                    out.asserted_mode = m.value
                    out.has_asserted_mode = True
                has_asserted = True
            elif key == "attestation":
                if has_attestation:
                    raise ValidationError(
                        "environment.attestation", "duplicate"
                    )
                var v = scan.parse_string()
                _check_attestation(v)
                out.env_attestation = v
                has_attestation = True
            elif key == "evidence":
                if has_evidence:
                    raise ValidationError("environment.evidence", "duplicate")
                scan.begin_array()
                if not array_is_empty(scan):
                    while True:
                        scan.skip_ws()
                        out.evidence.append(_parse_evidence_item(scan))
                        if len(out.evidence) > MAX_EVIDENCE_ITEMS:
                            raise ValidationError(
                                "environment.evidence", "too many items"
                            )
                        if not array_next(scan, "environment.evidence"):
                            break
                scan.end_array()
                has_evidence = True
            else:
                raise ValidationError("environment", "unknown environment field")
            if not object_next(scan, "environment"):
                break
    scan.end_object()
    if (
        not has_mode
        or not has_detection
        or not has_attestation
        or not has_evidence
    ):
        raise ValidationError("environment", "missing field")


struct _Capture(ImplicitlyCopyable):
    var mode: String
    var window_start_ns: UInt64
    var window_end_ns: UInt64
    var has_baseline_start_ns: Bool
    var baseline_start_ns: UInt64
    var has_filter_device: Bool
    var filter_device: String
    var finalized: Bool
    var has_end_reason: Bool
    var end_reason: String

    def __init__(out self):
        self.mode = String("")
        self.window_start_ns = UInt64(0)
        self.window_end_ns = UInt64(0)
        self.has_baseline_start_ns = False
        self.baseline_start_ns = UInt64(0)
        self.has_filter_device = False
        self.filter_device = String("")
        self.finalized = False
        self.has_end_reason = False
        self.end_reason = String("")


def _parse_window(mut scan: Scanner) raises -> _Capture:
    scan.begin_object()
    var out = _Capture()
    var has_start = False
    var has_end = False
    var has_baseline = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "window")
            if key == "start_ns":
                if has_start:
                    raise ValidationError("window.start_ns", "duplicate")
                out.window_start_ns = parse_u64_field(scan, "window.start_ns")
                has_start = True
            elif key == "end_ns":
                if has_end:
                    raise ValidationError("window.end_ns", "duplicate")
                out.window_end_ns = parse_u64_field(scan, "window.end_ns")
                has_end = True
            elif key == "baseline_start_ns":
                if has_baseline:
                    raise ValidationError(
                        "window.baseline_start_ns", "duplicate"
                    )
                out.baseline_start_ns = parse_u64_field(
                    scan, "window.baseline_start_ns"
                )
                out.has_baseline_start_ns = True
                has_baseline = True
            else:
                raise ValidationError("window", "unknown window field")
            if not object_next(scan, "window"):
                break
    scan.end_object()
    if not has_start or not has_end:
        raise ValidationError("window", "missing field")
    return out^


def _parse_filters(mut scan: Scanner) raises -> MaybeString:
    scan.begin_object()
    var out = MaybeString()
    var has_device = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "filters")
            if key == "device":
                if has_device:
                    raise ValidationError("filters.device", "duplicate")
                out = parse_maybe_string(scan)
                if out.has:
                    check_bounded_text(
                        out.value, 1, 256, "filters.device"
                    )
                has_device = True
            else:
                raise ValidationError("filters", "unknown filters field")
            if not object_next(scan, "filters"):
                break
    scan.end_object()
    return out^


def _parse_capture(mut scan: Scanner) raises -> _Capture:
    scan.begin_object()
    var out = _Capture()
    var has_mode = False
    var has_window = False
    var has_filters = False
    var has_finalized = False
    var has_reason = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "capture")
            if key == "mode":
                if has_mode:
                    raise ValidationError("capture.mode", "duplicate")
                var v = scan.parse_string()
                _check_capture_mode(v)
                out.mode = v
                has_mode = True
            elif key == "window":
                if has_window:
                    raise ValidationError("capture.window", "duplicate")
                var w = _parse_window(scan)
                out.window_start_ns = w.window_start_ns
                out.window_end_ns = w.window_end_ns
                out.has_baseline_start_ns = w.has_baseline_start_ns
                out.baseline_start_ns = w.baseline_start_ns
                has_window = True
            elif key == "filters":
                if has_filters:
                    raise ValidationError("capture.filters", "duplicate")
                var m = _parse_filters(scan)
                if m.has:
                    out.filter_device = m.value
                    out.has_filter_device = True
                has_filters = True
            elif key == "finalized":
                if has_finalized:
                    raise ValidationError("capture.finalized", "duplicate")
                scan.skip_ws()
                out.finalized = scan.parse_bool()
                has_finalized = True
            elif key == "end_reason":
                if has_reason:
                    raise ValidationError("capture.end_reason", "duplicate")
                var m = parse_maybe_string(scan)
                if m.has:
                    _check_end_reason(m.value)
                    out.end_reason = m.value
                    out.has_end_reason = True
                has_reason = True
            else:
                raise ValidationError("capture", "unknown capture field")
            if not object_next(scan, "capture"):
                break
    scan.end_object()
    if not has_mode or not has_window or not has_filters or not has_finalized:
        raise ValidationError("capture", "missing field")
    if out.window_start_ns > out.window_end_ns:
        raise ValidationError("window", "start after end")
    if (
        out.has_baseline_start_ns
        and out.baseline_start_ns > out.window_start_ns
    ):
        raise ValidationError("window", "baseline after start")
    return out^


def _parse_device_catalog(mut scan: Scanner) raises -> List[DeviceEntry]:
    scan.begin_object()
    var out = List[DeviceEntry]()
    var has_devices = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "device_catalog")
            if key == "devices":
                if has_devices:
                    raise ValidationError("device_catalog.devices", "duplicate")
                scan.begin_array()
                if not array_is_empty(scan):
                    while True:
                        scan.skip_ws()
                        out.append(_parse_device(scan))
                        if len(out) > MAX_DEVICES:
                            raise ValidationError(
                                "device_catalog.devices", "too many items"
                            )
                        if not array_next(scan, "device_catalog.devices"):
                            break
                scan.end_array()
                has_devices = True
            else:
                raise ValidationError("device_catalog", "unknown device_catalog field")
            if not object_next(scan, "device_catalog"):
                break
    scan.end_object()
    if not has_devices:
        raise ValidationError("device_catalog", "missing field")
    for i in range(len(out)):
        for j in range(i):
            if out[i].device_id == out[j].device_id:
                raise ValidationError(
                    "device_catalog.devices", "duplicate device_id"
                )
    return out^


struct _Baseline(Copyable, Movable):
    var complete: Bool
    var region_count: Int
    var regions: List[RegionObservation]

    def __init__(out self):
        self.complete = False
        self.region_count = 0
        self.regions = List[RegionObservation]()


def _parse_baseline(mut scan: Scanner) raises -> _Baseline:
    scan.begin_object()
    var out = _Baseline()
    var has_complete = False
    var has_regions = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "baseline")
            if key == "complete":
                if has_complete:
                    raise ValidationError("baseline.complete", "duplicate")
                scan.skip_ws()
                out.complete = scan.parse_bool()
                has_complete = True
            elif key == "region_observations":
                if has_regions:
                    raise ValidationError(
                        "baseline.region_observations", "duplicate"
                    )
                scan.begin_array()
                if not array_is_empty(scan):
                    while True:
                        scan.skip_ws()
                        var one = _parse_region_observation(scan)
                        out.regions.append(one^)
                        out.region_count += 1
                        if out.region_count > MAX_REGION_OBSERVATIONS:
                            raise ValidationError(
                                "baseline.region_observations",
                                "too many items",
                            )
                        if not array_next(
                            scan, "baseline.region_observations"
                        ):
                            break
                scan.end_array()
                has_regions = True
            else:
                raise ValidationError("baseline", "unknown baseline field")
            if not object_next(scan, "baseline"):
                break
    scan.end_object()
    if not has_complete or not has_regions:
        raise ValidationError("baseline", "missing field")
    return out^


struct Session(Copyable):
    """One validated capture session header."""

    var session_id: String
    var has_boot_id: Bool
    var boot_id: String
    var synthetic: Bool
    var product_name: String
    var product_version: String
    var has_build: Bool
    var build: String
    var env_mode: String
    var env_detection: String
    var has_asserted_mode: Bool
    var asserted_mode: String
    var asserted_mode_present: Bool
    var env_attestation: String
    var evidence: List[EvidenceItem]
    var capture_mode: String
    var window_start_ns: UInt64
    var window_end_ns: UInt64
    var has_baseline_start_ns: Bool
    var baseline_start_ns: UInt64
    var has_filter_device: Bool
    var filter_device: String
    var finalized: Bool
    var has_end_reason: Bool
    var end_reason: String
    var devices: List[DeviceEntry]
    var baseline_complete: Bool
    var baseline_region_count: Int
    var baseline_regions: List[RegionObservation]
    var cap_bounce_attempts: Capability
    var cap_mapping_lifecycle: Capability
    var cap_copy_bytes: Capability
    var cap_sync_requests: Capability
    var cap_conversion_results: Capability
    var cap_region_state: Capability
    var cap_pool_stats: Capability
    var cap_task_context: Capability
    var q_detail: Channel
    var q_aggregate: Channel
    var q_correlation: Channel
    var q_baseline: Channel
    var q_terminal: Channel

    def __init__(out self):
        self.session_id = String("")
        self.has_boot_id = False
        self.boot_id = String("")
        self.synthetic = False
        self.product_name = String("")
        self.product_version = String("")
        self.has_build = False
        self.build = String("")
        self.env_mode = String("")
        self.env_detection = String("")
        self.has_asserted_mode = False
        self.asserted_mode = String("")
        self.asserted_mode_present = False
        self.env_attestation = String("")
        self.evidence = List[EvidenceItem]()
        self.capture_mode = String("")
        self.window_start_ns = UInt64(0)
        self.window_end_ns = UInt64(0)
        self.has_baseline_start_ns = False
        self.baseline_start_ns = UInt64(0)
        self.has_filter_device = False
        self.filter_device = String("")
        self.finalized = False
        self.has_end_reason = False
        self.end_reason = String("")
        self.devices = List[DeviceEntry]()
        self.baseline_complete = False
        self.baseline_region_count = 0
        self.baseline_regions = List[RegionObservation]()
        self.cap_bounce_attempts = Capability()
        self.cap_mapping_lifecycle = Capability()
        self.cap_copy_bytes = Capability()
        self.cap_sync_requests = Capability()
        self.cap_conversion_results = Capability()
        self.cap_region_state = Capability()
        self.cap_pool_stats = Capability()
        self.cap_task_context = Capability()
        self.q_detail = Channel()
        self.q_aggregate = Channel()
        self.q_correlation = Channel()
        self.q_baseline = Channel()
        self.q_terminal = Channel()

    def __copyinit__(mut self, existing: Self):
        self.session_id = existing.session_id
        self.has_boot_id = existing.has_boot_id
        self.boot_id = existing.boot_id
        self.synthetic = existing.synthetic
        self.product_name = existing.product_name
        self.product_version = existing.product_version
        self.has_build = existing.has_build
        self.build = existing.build
        self.env_mode = existing.env_mode
        self.env_detection = existing.env_detection
        self.has_asserted_mode = existing.has_asserted_mode
        self.asserted_mode = existing.asserted_mode
        self.asserted_mode_present = existing.asserted_mode_present
        self.env_attestation = existing.env_attestation
        self.evidence = existing.evidence.copy()
        self.capture_mode = existing.capture_mode
        self.window_start_ns = existing.window_start_ns
        self.window_end_ns = existing.window_end_ns
        self.has_baseline_start_ns = existing.has_baseline_start_ns
        self.baseline_start_ns = existing.baseline_start_ns
        self.has_filter_device = existing.has_filter_device
        self.filter_device = existing.filter_device
        self.finalized = existing.finalized
        self.has_end_reason = existing.has_end_reason
        self.end_reason = existing.end_reason
        self.devices = existing.devices.copy()
        self.baseline_complete = existing.baseline_complete
        self.baseline_region_count = existing.baseline_region_count
        self.baseline_regions = existing.baseline_regions.copy()
        self.cap_bounce_attempts = existing.cap_bounce_attempts.copy()
        self.cap_mapping_lifecycle = existing.cap_mapping_lifecycle.copy()
        self.cap_copy_bytes = existing.cap_copy_bytes.copy()
        self.cap_sync_requests = existing.cap_sync_requests.copy()
        self.cap_conversion_results = existing.cap_conversion_results.copy()
        self.cap_region_state = existing.cap_region_state.copy()
        self.cap_pool_stats = existing.cap_pool_stats.copy()
        self.cap_task_context = existing.cap_task_context.copy()
        self.q_detail = existing.q_detail.copy()
        self.q_aggregate = existing.q_aggregate.copy()
        self.q_correlation = existing.q_correlation.copy()
        self.q_baseline = existing.q_baseline.copy()
        self.q_terminal = existing.q_terminal.copy()


def _parse_product(mut scan: Scanner, mut out: Session) raises:
    scan.begin_object()
    var has_name = False
    var has_version = False
    var has_build = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "product")
            if key == "name":
                if has_name:
                    raise ValidationError("product.name", "duplicate")
                var v = scan.parse_string()
                if v != PRODUCT_NAME:
                    raise ValidationError("product.name", "bad const")
                out.product_name = v
                has_name = True
            elif key == "version":
                if has_version:
                    raise ValidationError("product.version", "duplicate")
                var v = scan.parse_string()
                check_bounded_text(v, 1, 64, "product.version")
                out.product_version = v
                has_version = True
            elif key == "build":
                if has_build:
                    raise ValidationError("product.build", "duplicate")
                var m = parse_maybe_string(scan)
                if m.has:
                    check_bounded_text(m.value, 0, 128, "product.build")
                    out.build = m.value
                    out.has_build = True
                has_build = True
            else:
                raise ValidationError("product", "unknown product field")
            if not object_next(scan, "product"):
                break
    scan.end_object()
    if not has_name or not has_version:
        raise ValidationError("product", "missing field")


def _parse_capabilities(mut scan: Scanner, mut out: Session) raises:
    scan.begin_object()
    var seen = List[String]()
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "capabilities")
            for prior in seen:
                if prior == key:
                    raise ValidationError("capabilities", "duplicate member")
            seen.append(key)
            if key == "bounce_attempts":
                out.cap_bounce_attempts = _parse_capability(
                    scan, "capabilities.bounce_attempts"
                )
            elif key == "mapping_lifecycle":
                out.cap_mapping_lifecycle = _parse_capability(
                    scan, "capabilities.mapping_lifecycle"
                )
            elif key == "copy_bytes":
                out.cap_copy_bytes = _parse_capability(
                    scan, "capabilities.copy_bytes"
                )
            elif key == "sync_requests":
                out.cap_sync_requests = _parse_capability(
                    scan, "capabilities.sync_requests"
                )
            elif key == "conversion_results":
                out.cap_conversion_results = _parse_capability(
                    scan, "capabilities.conversion_results"
                )
            elif key == "region_state":
                out.cap_region_state = _parse_capability(
                    scan, "capabilities.region_state"
                )
            elif key == "pool_stats":
                out.cap_pool_stats = _parse_capability(
                    scan, "capabilities.pool_stats"
                )
            elif key == "task_context":
                out.cap_task_context = _parse_capability(
                    scan, "capabilities.task_context"
                )
            else:
                raise ValidationError("capabilities", "unknown capability")
            if not object_next(scan, "capabilities"):
                break
    scan.end_object()
    if len(seen) != 8:
        raise ValidationError("capabilities", "missing field")


def _parse_quality(mut scan: Scanner, mut out: Session) raises:
    scan.begin_object()
    var seen = List[String]()
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "quality")
            for prior in seen:
                if prior == key:
                    raise ValidationError("quality", "duplicate member")
            seen.append(key)
            if key == "detail":
                out.q_detail = _parse_channel(scan, "quality.detail")
            elif key == "aggregate":
                out.q_aggregate = _parse_channel(scan, "quality.aggregate")
            elif key == "correlation":
                out.q_correlation = _parse_channel(scan, "quality.correlation")
            elif key == "baseline":
                out.q_baseline = _parse_channel(scan, "quality.baseline")
            elif key == "terminal":
                out.q_terminal = _parse_channel(scan, "quality.terminal")
            else:
                raise ValidationError("quality", "unknown quality channel")
            if not object_next(scan, "quality"):
                break
    scan.end_object()
    if len(seen) != 5:
        raise ValidationError("quality", "missing field")


def parse_session(data: List[UInt8]) raises -> Session:
    """Parse and validate one session.json document."""
    var scan = Scanner(data)
    scan.skip_ws()
    scan.begin_object()
    var out = Session()
    var has_version = False
    var has_session = False
    var has_boot = False
    var has_synthetic = False
    var has_product = False
    var has_env = False
    var has_capture = False
    var has_catalog = False
    var has_baseline = False
    var has_caps = False
    var has_quality = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "session")
            if key == "schema_version":
                if has_version:
                    raise ValidationError("schema_version", "duplicate")
                var v = scan.parse_string()
                if v != SESSION_SCHEMA_VERSION:
                    raise ValidationError("schema_version", "bad const")
                has_version = True
            elif key == "session_id":
                if has_session:
                    raise ValidationError("session_id", "duplicate")
                var v = scan.parse_string()
                try:
                    check_opaque_id(v)
                except e:
                    raise ValidationError("session_id", String(e))
                out.session_id = v
                has_session = True
            elif key == "boot_id":
                if has_boot:
                    raise ValidationError("boot_id", "duplicate")
                var v = scan.parse_string()
                try:
                    check_opaque_id(v)
                except e:
                    raise ValidationError("boot_id", String(e))
                out.boot_id = v
                out.has_boot_id = True
                has_boot = True
            elif key == "synthetic":
                if has_synthetic:
                    raise ValidationError("synthetic", "duplicate")
                scan.skip_ws()
                out.synthetic = scan.parse_bool()
                has_synthetic = True
            elif key == "product":
                if has_product:
                    raise ValidationError("product", "duplicate")
                _parse_product(scan, out)
                has_product = True
            elif key == "environment":
                if has_env:
                    raise ValidationError("environment", "duplicate")
                _parse_environment(scan, out)
                has_env = True
            elif key == "capture":
                if has_capture:
                    raise ValidationError("capture", "duplicate")
                var c = _parse_capture(scan)
                out.capture_mode = c.mode
                out.window_start_ns = c.window_start_ns
                out.window_end_ns = c.window_end_ns
                out.has_baseline_start_ns = c.has_baseline_start_ns
                out.baseline_start_ns = c.baseline_start_ns
                out.has_filter_device = c.has_filter_device
                out.filter_device = c.filter_device
                out.finalized = c.finalized
                out.has_end_reason = c.has_end_reason
                out.end_reason = c.end_reason
                has_capture = True
            elif key == "device_catalog":
                if has_catalog:
                    raise ValidationError("device_catalog", "duplicate")
                out.devices = _parse_device_catalog(scan)
                has_catalog = True
            elif key == "baseline":
                if has_baseline:
                    raise ValidationError("baseline", "duplicate")
                var b = _parse_baseline(scan)
                out.baseline_complete = b.complete
                out.baseline_region_count = b.region_count
                out.baseline_regions = b.regions.copy()
                has_baseline = True
            elif key == "capabilities":
                if has_caps:
                    raise ValidationError("capabilities", "duplicate")
                _parse_capabilities(scan, out)
                has_caps = True
            elif key == "quality":
                if has_quality:
                    raise ValidationError("quality", "duplicate")
                _parse_quality(scan, out)
                has_quality = True
            else:
                raise ValidationError("session", "unknown session field")
            if not object_next(scan, "session"):
                break
    scan.end_object()
    if (
        not has_version
        or not has_session
        or not has_synthetic
        or not has_product
        or not has_env
        or not has_capture
        or not has_catalog
        or not has_baseline
        or not has_caps
        or not has_quality
    ):
        raise ValidationError("session", "missing field")
    if out.synthetic != (out.capture_mode == "synthetic"):
        raise ValidationError("synthetic", "contradicts capture mode")
    scan.skip_ws()
    if not scan.at_end():
        raise ValidationError("session", "trailing data")
    return out^
