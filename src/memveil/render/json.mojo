# SPDX-License-Identifier: GPL-3.0-or-later

"""JSON report renderer: schema-valid report v0.1.0 output.

Every string passes through escape_json, which emits the quoted JSON
literal with short escapes for quote, backslash, and common controls
and \\u00XX for the rest; valid multibyte UTF-8 passes through raw.
Numbers stay canonical decimal strings; absent optionals stay absent
while explicit nulls echo as null (asserted_mode, driver), so the
report matches the session exactly; evidence_refs are omitted when
empty.
"""

from memveil.model.report import Report
from memveil.model.session import Channel
from memveil.model.validate import format_u64
from memveil.render.filter import resolve_device_filter

comptime REPORT_SCHEMA_VERSION = "0.1.0"


def _hex_nibble(v: Int) -> UInt8:
    if v < 10:
        return UInt8(0x30 + v)
    return UInt8(0x61 + v - 10)


def escape_json(s: String) raises -> String:
    """Render s as one quoted JSON string literal."""
    var raw = s.as_bytes()
    var out = List[UInt8]()
    out.append(UInt8(0x22))
    for i in range(len(raw)):
        var b = raw[i]
        if b == UInt8(0x22):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x22))
        elif b == UInt8(0x5C):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x5C))
        elif b == UInt8(0x0A):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x6E))
        elif b == UInt8(0x09):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x74))
        elif b == UInt8(0x0D):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x72))
        elif b == UInt8(0x08):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x62))
        elif b == UInt8(0x0C):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x66))
        elif b < UInt8(0x20) or b == UInt8(0x7F):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x75))
            out.append(UInt8(0x30))
            out.append(UInt8(0x30))
            out.append(_hex_nibble(Int(b) // 16))
            out.append(_hex_nibble(Int(b) % 16))
        else:
            out.append(b)
    out.append(UInt8(0x22))
    return String(from_utf8=Span(out))


def _channel_json(label: String, ch: Channel, level: Int) raises -> String:
    var pad = String("")
    for _ in range(level):
        pad += "  "
    var inner = pad + "  "
    var out = pad + escape_json(label) + ": {\n"
    out += inner + '"status": ' + escape_json(ch.status) + ",\n"
    out += inner + '"loss_count": '
    if ch.has_loss_count:
        out += '"' + format_u64(ch.loss_count) + '"'
    else:
        out += "null"
    out += ",\n"
    out += inner + '"scope": ' + escape_json(ch.scope) + ",\n"
    out += inner + '"reason": ' + escape_json(ch.reason)
    if len(ch.evidence_refs) > 0:
        out += ",\n" + inner + '"evidence_refs": ['
        for i in range(len(ch.evidence_refs)):
            if i > 0:
                out += ", "
            out += escape_json(ch.evidence_refs[i])
        out += "]"
    out += "\n" + pad + "}"
    return out


def render_json(rep: Report, device_filter: String = "") raises -> String:
    """Render the report as pretty JSON per report-v0.1.0.schema.json."""
    var filt = resolve_device_filter(rep.devices, device_filter)
    var out = String("{\n")
    out += '  "schema_version": "' + REPORT_SCHEMA_VERSION + '",\n'
    out += "  \"session_id\": " + escape_json(rep.session_id) + ",\n"
    if rep.synthetic:
        out += "  \"synthetic\": true,\n"
    else:
        out += "  \"synthetic\": false,\n"
    out += "  \"engine_version\": " + escape_json(rep.engine_version) + ",\n"
    out += '  "environment": {\n'
    out += '    "mode": ' + escape_json(rep.env.mode) + ",\n"
    out += '    "detection": ' + escape_json(rep.env.detection) + ",\n"
    if rep.env.asserted_mode_present:
        out += '    "asserted_mode": '
        if rep.env.has_asserted_mode:
            out += escape_json(rep.env.asserted_mode)
        else:
            out += "null"
        out += ",\n"
    out += '    "attestation": ' + escape_json(rep.env.attestation) + ",\n"
    if len(rep.env.evidence) == 0:
        out += '    "evidence": []\n'
    else:
        out += '    "evidence": [\n'
        for i in range(len(rep.env.evidence)):
            var e = rep.env.evidence[i]
            out += '      {"type": ' + escape_json(e.item_type)
            out += ', "source": ' + escape_json(e.source)
            out += ', "interpretation": ' + escape_json(e.interpretation)
            out += "}"
            if i + 1 < len(rep.env.evidence):
                out += ","
            out += "\n"
        out += "    ]\n"
    out += "  },\n"
    out += '  "device_catalog": {\n'
    if len(rep.devices) == 0:
        out += '    "devices": []\n'
    else:
        out += '    "devices": [\n'
        for i in range(len(rep.devices)):
            var d = rep.devices[i]
            out += '      {"device_id": ' + escape_json(d.device_id)
            out += ', "name": ' + escape_json(d.name)
            if d.driver_present:
                out += ', "driver": '
                if d.has_driver:
                    out += escape_json(d.driver)
                else:
                    out += "null"
            out += ', "identity_status": ' + escape_json(d.identity_status)
            out += "}"
            if i + 1 < len(rep.devices):
                out += ","
            out += "\n"
        out += "    ]\n"
    out += "  },\n"
    out += '  "quality": {\n'
    out += _channel_json(String("detail"), rep.q_detail, 2) + ",\n"
    out += _channel_json(String("aggregate"), rep.q_aggregate, 2) + ",\n"
    out += _channel_json(String("correlation"), rep.q_correlation, 2) + ",\n"
    out += _channel_json(String("baseline"), rep.q_baseline, 2) + ",\n"
    out += _channel_json(String("terminal"), rep.q_terminal, 2) + "\n"
    out += "  },\n"
    var shown = 0
    for i in range(len(rep.metrics)):
        var probe = rep.metrics[i]
        if filt == "" or not probe.has_device_id:
            shown += 1
        elif probe.device_id == filt:
            shown += 1
    if shown == 0:
        out += '  "metrics": [],\n'
    else:
        out += '  "metrics": [\n'
        var emitted = 0
        for i in range(len(rep.metrics)):
            var m = rep.metrics[i]
            if filt != "" and m.has_device_id:
                if m.device_id != filt:
                    continue
            out += '    {"name": ' + escape_json(m.name)
            out += ', "value": '
            if m.has_value:
                out += '"' + format_u64(m.value) + '"'
            else:
                out += "null"
            out += ', "unit": ' + escape_json(m.unit)
            out += ', "measurement": ' + escape_json(m.measurement)
            out += ', "coverage": ' + escape_json(m.coverage)
            out += ', "aggregation": '
            if m.has_aggregation:
                out += escape_json(m.aggregation)
            else:
                out += "null"
            out += ', "sample_count": '
            if m.has_sample_count:
                out += '"' + format_u64(m.sample_count) + '"'
            else:
                out += "null"
            out += ', "dimensions": {"device_id": '
            if m.has_device_id:
                out += escape_json(m.device_id)
            else:
                out += "null"
            out += ', "pool_id": '
            if m.has_pool_id:
                out += escape_json(m.pool_id)
            else:
                out += "null"
            out += '}, "scope": ' + escape_json(m.scope)
            out += ', "notes": ' + escape_json(m.notes)
            out += "}"
            emitted += 1
            if emitted < shown:
                out += ","
            out += "\n"
        out += "  ],\n"
    if len(rep.findings) == 0:
        out += '  "findings": [],\n'
    else:
        out += '  "findings": [\n'
        for i in range(len(rep.findings)):
            out += '    {"code": ' + escape_json(rep.findings[i].code)
            out += ', "severity": ' + escape_json(rep.findings[i].severity)
            out += ', "explanation": ' + escape_json(rep.findings[i].explanation)
            out += ', "evidence_refs": ['
            for ri in range(len(rep.findings[i].evidence_refs)):
                if ri > 0:
                    out += ", "
                out += escape_json(rep.findings[i].evidence_refs[ri])
            out += '], "scope": ' + escape_json(rep.findings[i].scope)
            out += ', "limitations": ' + escape_json(rep.findings[i].limitations)
            out += "}"
            if i + 1 < len(rep.findings):
                out += ","
            out += "\n"
        out += "  ],\n"
    if len(rep.limitations) == 0:
        out += '  "limitations": []\n'
    else:
        out += '  "limitations": [\n'
        for i in range(len(rep.limitations)):
            out += "    " + escape_json(rep.limitations[i])
            if i + 1 < len(rep.limitations):
                out += ","
            out += "\n"
        out += "  ]\n"
    out += "}\n"
    return out
