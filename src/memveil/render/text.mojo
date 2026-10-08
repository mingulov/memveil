# SPDX-License-Identifier: GPL-3.0-or-later

"""Plain-text report renderer.

Every echoed value passes through escape_text, so control bytes in
metadata (device names, drivers, reasons) can neither break the
line layout nor smuggle terminal sequences: newline, tab, and return
become literal backslash sequences, other C0 bytes and DEL become
U+FFFD, and printable text including multibyte characters passes
through untouched.
"""

from memveil.model.metric import Metric
from memveil.model.report import Report
from memveil.model.session import Channel
from memveil.model.validate import format_u64
from memveil.render.filter import resolve_device_filter
from memveil.render.context import measured_duration, recorded_value


def escape_text(s: String) raises -> String:
    var raw = s.as_bytes()
    var out = List[UInt8]()
    for i in range(len(raw)):
        var b = raw[i]
        if b == UInt8(0x0A):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x6E))
        elif b == UInt8(0x09):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x74))
        elif b == UInt8(0x0D):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x72))
        elif b < UInt8(0x20) or b == UInt8(0x7F):
            out.append(UInt8(0xEF))
            out.append(UInt8(0xBF))
            out.append(UInt8(0xBD))
        else:
            out.append(b)
    return String(from_utf8=Span(out))


def _dims_text(has_device: Bool, device: String, has_pool: Bool, pool: String) raises -> String:
    if has_device and has_pool:
        return (
            "{device="
            + escape_text(device)
            + ", pool="
            + escape_text(pool)
            + "}"
        )
    if has_device:
        return "{device=" + escape_text(device) + "}"
    if has_pool:
        return "{pool=" + escape_text(pool) + "}"
    return String("")


def _channel_block(label: String, ch: Channel) raises -> String:
    var out = String("  ")
    out += label
    out += ": "
    out += escape_text(ch.status)
    out += " loss="
    if ch.has_loss_count:
        out += format_u64(ch.loss_count)
    else:
        out += "unknown"
    out += "\n    scope: "
    out += escape_text(ch.scope)
    out += "\n    reason: "
    out += escape_text(ch.reason)
    out += "\n"
    return out


def _shown(m: Metric, device_filter: String) -> Bool:
    """True when the row survives the display device filter."""
    if device_filter == "":
        return True
    if not m.has_device_id:
        return True
    return m.device_id == device_filter


def render_text(rep: Report, device_filter: String = "") raises -> String:
    """Render the report as plain text, one trailing newline."""
    var filt = resolve_device_filter(rep.devices, device_filter)
    var out = String("memveil report ")
    out += escape_text(rep.session_id)
    if rep.synthetic:
        out += " (synthetic, engine "
    else:
        out += " (live, engine "
    out += escape_text(rep.engine_version)
    out += ")\n"
    out += "window: ["
    out += format_u64(rep.window_start_ns)
    out += ","
    out += format_u64(rep.window_end_ns)
    out += ")\n"
    out += "duration: "
    out += measured_duration(rep)
    out += "\n"
    out += "environment: mode="
    out += escape_text(rep.env.mode)
    out += " detection="
    out += escape_text(rep.env.detection)
    out += " attestation="
    out += escape_text(rep.env.attestation)
    if rep.env.has_asserted_mode:
        out += " asserted="
        out += escape_text(rep.env.asserted_mode)
    out += " evidence="
    out += String(len(rep.env.evidence))
    out += "\n"
    for source in [String("kernel.release"), String("profile.decision"), String("measurement_scope")]:
        out += "recorded "
        out += source
        out += ": "
        out += escape_text(recorded_value(rep.env.evidence, source))
        out += "\n"
    out += "devices ("
    out += String(len(rep.devices))
    out += "):\n"
    for i in range(len(rep.devices)):
        var d = rep.devices[i]
        out += "  "
        out += escape_text(d.device_id)
        out += " "
        out += escape_text(d.name)
        out += " driver="
        if d.has_driver:
            out += escape_text(d.driver)
        else:
            out += "none"
        out += " identity="
        out += escape_text(d.identity_status)
        out += "\n"
    out += "quality:\n"
    out += _channel_block(String("detail"), rep.q_detail)
    out += _channel_block(String("aggregate"), rep.q_aggregate)
    out += _channel_block(String("correlation"), rep.q_correlation)
    out += _channel_block(String("baseline"), rep.q_baseline)
    out += _channel_block(String("terminal"), rep.q_terminal)
    var shown = 0
    for i in range(len(rep.metrics)):
        if _shown(rep.metrics[i], filt):
            shown += 1
    out += "metrics ("
    out += String(shown)
    out += "):\n"
    for i in range(len(rep.metrics)):
        var m = rep.metrics[i]
        if not _shown(m, filt):
            continue
        out += "  "
        out += escape_text(m.name)
        out += _dims_text(
            m.has_device_id, m.device_id, m.has_pool_id, m.pool_id
        )
        out += " = "
        if m.has_value:
            out += format_u64(m.value)
        else:
            out += "unavailable"
        out += " "
        out += escape_text(m.unit)
        out += " ["
        out += escape_text(m.measurement)
        out += ", "
        out += escape_text(m.coverage)
        out += ", "
        out += escape_text(m.confidence)
        if m.has_aggregation:
            out += ", "
            out += escape_text(m.aggregation)
        out += "]\n    scope: "
        out += escape_text(m.scope)
        out += "\n    notes: "
        out += escape_text(m.notes)
        out += "\n"
    if len(rep.findings) == 0:
        out += "findings: none\n"
    else:
        out += "findings ("
        out += String(len(rep.findings))
        out += "):\n"
        for i in range(len(rep.findings)):
            out += "  ["
            out += escape_text(rep.findings[i].severity)
            out += "] "
            out += escape_text(rep.findings[i].code)
            out += ": "
            out += escape_text(rep.findings[i].explanation)
            out += "\n    scope: "
            out += escape_text(rep.findings[i].scope)
            out += "\n    limitations: "
            out += escape_text(rep.findings[i].limitations)
            out += "\n    refs: "
            for ri in range(len(rep.findings[i].evidence_refs)):
                if ri > 0:
                    out += ", "
                out += escape_text(rep.findings[i].evidence_refs[ri])
            out += "\n"
    out += "limitations ("
    out += String(len(rep.limitations))
    out += "):\n"
    for i in range(len(rep.limitations)):
        out += "  - "
        out += escape_text(rep.limitations[i])
        out += "\n"
    return out
