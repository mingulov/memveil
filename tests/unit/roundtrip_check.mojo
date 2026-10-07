# SPDX-License-Identifier: GPL-3.0-or-later

"""Fixture round-trip checker (writer lane tool, not shipped).

Usage: roundtrip_check.mojo <events.ndjson|session.json>
Exit 0 when every record survives parse/encode/reparse with
struct equality; 1 on any mismatch; 2 on unparseable input
or unrepresentable state (baseline regions). The lane maps
exit 2 to the expected-fail list of intentionally-invalid
fixtures; everything else must exit 0.
"""

from std.sys import argv, exit

from memveil.model.encode import encode_event, encode_session
from memveil.model.event import Event, parse_event
from memveil.model.session import (
    Capability,
    Channel,
    Session,
    parse_session,
)
from memveil.platform.reader import read_host_file


comptime _FILE_CAP = 67108864


def _split_lines(data: List[UInt8]) -> List[List[UInt8]]:
    var out = List[List[UInt8]]()
    var cur = List[UInt8]()
    for i in range(len(data)):
        if data[i] == UInt8(0x0A):
            out.append(cur.copy())
            cur = List[UInt8]()
        else:
            cur.append(data[i])
    if len(cur) > 0:
        out.append(cur^)
    return out^


def _is_blank(line: List[UInt8]) -> Bool:
    for i in range(len(line)):
        var b = line[i]
        if (
            b != UInt8(0x20)
            and b != UInt8(0x09)
            and b != UInt8(0x0D)
        ):
            return False
    return True


def events_equal(a: Event, b: Event) -> Bool:
    if (
        a.session_id != b.session_id
        or a.seq != b.seq
        or a.ts_ns != b.ts_ns
        or a.kind != b.kind
        or a.source_hook != b.source_hook
        or a.source_backend != b.source_backend
        or a.source_profile_id != b.source_profile_id
        or a.source_measurement != b.source_measurement
        or a.source_correlation != b.source_correlation
    ):
        return False
    if (
        a.has_observer != b.has_observer
        or a.has_cpu != b.has_cpu
        or a.cpu != b.cpu
        or a.has_pid != b.has_pid
        or a.pid != b.pid
        or a.has_tgid != b.has_tgid
        or a.tgid != b.tgid
        or a.has_comm != b.has_comm
        or a.comm != b.comm
        or a.has_cgroup_id != b.has_cgroup_id
        or a.cgroup_id != b.cgroup_id
    ):
        return False
    var x = a.bounce
    var y = b.bounce
    if (
        x.device_id != y.device_id
        or x.requested_bytes != y.requested_bytes
        or x.forced != y.forced
        or x.operation_id != y.operation_id
    ):
        return False
    var mx = a.map_result
    var my = b.map_result
    if (
        mx.operation_id != my.operation_id
        or mx.success != my.success
        or mx.has_mapping_id != my.has_mapping_id
        or mx.mapping_id != my.mapping_id
        or mx.has_return_code != my.has_return_code
        or mx.return_code != my.return_code
        or mx.has_mapped_bytes != my.has_mapped_bytes
        or mx.mapped_bytes != my.mapped_bytes
    ):
        return False
    if (
        a.unmap.has_mapping_id != b.unmap.has_mapping_id
        or a.unmap.mapping_id != b.unmap.mapping_id
    ):
        return False
    var cx = a.copy
    var cy = b.copy
    if (
        cx.operation_id != cy.operation_id
        or cx.has_mapping_id != cy.has_mapping_id
        or cx.mapping_id != cy.mapping_id
        or cx.direction != cy.direction
        or cx.bytes != cy.bytes
    ):
        return False
    var sx = a.sync
    var sy = b.sync
    if (
        sx.operation_id != sy.operation_id
        or sx.has_mapping_id != sy.has_mapping_id
        or sx.mapping_id != sy.mapping_id
        or sx.offset != sy.offset
        or sx.length != sy.length
    ):
        return False
    var tx = a.transition
    var ty = b.transition
    if (
        tx.region_id != ty.region_id
        or tx.requested_state != ty.requested_state
        or tx.success != ty.success
        or tx.has_return_code != ty.has_return_code
        or tx.return_code != ty.return_code
        or tx.offset != ty.offset
        or tx.length != ty.length
        or tx.has_address_space != ty.has_address_space
        or tx.address_space != ty.address_space
        or tx.has_resolution != ty.has_resolution
        or tx.resolution != ty.resolution
    ):
        return False
    var px = a.pool
    var py = b.pool
    if (
        px.pool_id != py.pool_id
        or px.has_used != py.has_used
        or px.used_bytes != py.used_bytes
        or px.has_capacity != py.has_capacity
        or px.capacity_bytes != py.capacity_bytes
        or px.unit != py.unit
    ):
        return False
    var gx = a.gap
    var gy = b.gap
    if (
        gx.channel != gy.channel
        or gx.has_lost_count != gy.has_lost_count
        or gx.lost_count != gy.lost_count
        or gx.reason != gy.reason
        or gx.window_start_ns != gy.window_start_ns
        or gx.window_end_ns != gy.window_end_ns
    ):
        return False
    if a.marker.text != b.marker.text:
        return False
    var nx = a.snapshot
    var ny = b.snapshot
    if (
        nx.counter_id != ny.counter_id
        or nx.epoch != ny.epoch
        or nx.has_scope_device != ny.has_scope_device
        or nx.scope_device_id != ny.scope_device_id
        or nx.scope_profile_id != ny.scope_profile_id
        or nx.value != ny.value
        or nx.unit != ny.unit
    ):
        return False
    return True


def _caps_equal(a: Capability, b: Capability) -> Bool:
    if (
        a.status != b.status
        or a.reason != b.reason
        or a.has_profile_id != b.has_profile_id
        or a.profile_id != b.profile_id
        or len(a.hooks) != len(b.hooks)
    ):
        return False
    for i in range(len(a.hooks)):
        if a.hooks[i] != b.hooks[i]:
            return False
    return True


def _channels_equal(a: Channel, b: Channel) -> Bool:
    if (
        a.status != b.status
        or a.has_loss_count != b.has_loss_count
        or a.loss_count != b.loss_count
        or a.scope != b.scope
        or a.reason != b.reason
        or len(a.evidence_refs) != len(b.evidence_refs)
    ):
        return False
    for i in range(len(a.evidence_refs)):
        if a.evidence_refs[i] != b.evidence_refs[i]:
            return False
    return True


def sessions_equal(a: Session, b: Session) -> Bool:
    if (
        a.session_id != b.session_id
        or a.has_boot_id != b.has_boot_id
        or a.boot_id != b.boot_id
        or a.synthetic != b.synthetic
        or a.product_name != b.product_name
        or a.product_version != b.product_version
        or a.has_build != b.has_build
        or a.build != b.build
        or a.env_mode != b.env_mode
        or a.env_detection != b.env_detection
        or a.has_asserted_mode != b.has_asserted_mode
        or a.asserted_mode != b.asserted_mode
        or a.asserted_mode_present != b.asserted_mode_present
        or a.env_attestation != b.env_attestation
        or a.capture_mode != b.capture_mode
        or a.window_start_ns != b.window_start_ns
        or a.window_end_ns != b.window_end_ns
        or a.has_baseline_start_ns != b.has_baseline_start_ns
        or a.baseline_start_ns != b.baseline_start_ns
        or a.has_filter_device != b.has_filter_device
        or a.filter_device != b.filter_device
        or a.finalized != b.finalized
        or a.has_end_reason != b.has_end_reason
        or a.end_reason != b.end_reason
        or a.baseline_complete != b.baseline_complete
        or a.baseline_region_count != b.baseline_region_count
    ):
        return False
    if len(a.evidence) != len(b.evidence):
        return False
    for i in range(len(a.evidence)):
        var x = a.evidence[i]
        var y = b.evidence[i]
        if (
            x.item_type != y.item_type
            or x.source != y.source
            or x.interpretation != y.interpretation
        ):
            return False
    if len(a.devices) != len(b.devices):
        return False
    for i in range(len(a.devices)):
        var x = a.devices[i]
        var y = b.devices[i]
        if (
            x.device_id != y.device_id
            or x.name != y.name
            or x.has_driver != y.has_driver
            or x.driver != y.driver
            or x.driver_present != y.driver_present
            or x.identity_status != y.identity_status
        ):
            return False
    if len(a.baseline_regions) != len(b.baseline_regions):
        return False
    for i in range(len(a.baseline_regions)):
        var x = a.baseline_regions[i]
        var y = b.baseline_regions[i]
        if (
            x.region_id != y.region_id
            or x.state != y.state
            or x.offset != y.offset
            or x.length != y.length
            or x.address_space != y.address_space
            or x.provenance != y.provenance
        ):
            return False
    if (
        not _caps_equal(a.cap_bounce_attempts, b.cap_bounce_attempts)
        or not _caps_equal(
            a.cap_mapping_lifecycle, b.cap_mapping_lifecycle
        )
        or not _caps_equal(a.cap_copy_bytes, b.cap_copy_bytes)
        or not _caps_equal(a.cap_sync_requests, b.cap_sync_requests)
        or not _caps_equal(
            a.cap_conversion_results, b.cap_conversion_results
        )
        or not _caps_equal(a.cap_region_state, b.cap_region_state)
        or not _caps_equal(a.cap_pool_stats, b.cap_pool_stats)
        or not _caps_equal(a.cap_task_context, b.cap_task_context)
    ):
        return False
    if (
        not _channels_equal(a.q_detail, b.q_detail)
        or not _channels_equal(a.q_aggregate, b.q_aggregate)
        or not _channels_equal(a.q_correlation, b.q_correlation)
        or not _channels_equal(a.q_baseline, b.q_baseline)
        or not _channels_equal(a.q_terminal, b.q_terminal)
    ):
        return False
    return True


def _text_bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        out.append(raw[i])
    return out^


def run(path: String) raises -> Int:
    """Round-trip one file; 0 clean, 1 mismatch, 2 unparseable."""
    var data: List[UInt8]
    try:
        data = read_host_file(path, "roundtrip input", _FILE_CAP)
    except:
        print("roundtrip: cannot read " + path)
        return 2
    if path.find(String("session.json")) != -1:
        var first: Session
        try:
            first = parse_session(data)
        except:
            print("roundtrip: " + path + ": session unparseable")
            return 2
        var text: String
        try:
            text = encode_session(first)
        except e:
            print(
                "roundtrip: "
                + path
                + ": unrepresentable: "
                + e.message
            )
            return 2
        var second: Session
        try:
            second = parse_session(_text_bytes(text))
        except:
            print(
                "roundtrip: " + path + ": reparse of output failed"
            )
            return 1
        if not sessions_equal(first, second):
            print("roundtrip: " + path + ": session mismatch")
            return 1
        print("roundtrip: " + path + ": session clean")
        return 0
    if path.find(String("events.ndjson")) != -1:
        var lines = _split_lines(data)
        var count = 0
        var lineno = 0
        for i in range(len(lines)):
            lineno += 1
            if len(lines[i]) == 0 or _is_blank(lines[i]):
                continue
            var first: Event
            try:
                first = parse_event(lines[i])
            except:
                print(
                    "roundtrip: "
                    + path
                    + ": line "
                    + String(lineno)
                    + " unparseable"
                )
                return 2
            var text: String
            try:
                text = encode_event(first)
            except e:
                print(
                    "roundtrip: "
                    + path
                    + ": line "
                    + String(lineno)
                    + " unrepresentable: "
                    + e.message
                )
                return 2
            var second: Event
            try:
                second = parse_event(_text_bytes(text))
            except:
                print(
                    "roundtrip: "
                    + path
                    + ": line "
                    + String(lineno)
                    + " reparse failed"
                )
                return 1
            if not events_equal(first, second):
                print(
                    "roundtrip: "
                    + path
                    + ": line "
                    + String(lineno)
                    + " mismatch"
                )
                return 1
            count += 1
        print(
            "roundtrip: "
            + path
            + ": "
            + String(count)
            + " events clean"
        )
        return 0
    print("roundtrip: want events.ndjson or session.json: " + path)
    return 2


def main() raises:
    var args = argv()
    if len(args) != 2:
        print("usage: roundtrip_check.mojo <events.ndjson|session.json>")
        exit(2)
    var code = 0
    try:
        code = run(args[1])
    except:
        print("roundtrip: internal error on " + args[1])
        exit(1)
    exit(code)
