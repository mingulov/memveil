# SPDX-License-Identifier: GPL-3.0-or-later

"""Markdown report renderer: tables for devices, quality, metrics.

Free-text cells (names, drivers, scopes, reasons, notes, findings,
limitations, metric names, dimension values, units) pass through
escape_markdown: controls are neutralized first, then
HTML-significant characters (&, <, >) become entities so hostile
metadata cannot inject tags or comments, and Markdown-active
punctuation (backslash, pipe, star, underscore, brackets, backtick)
is backslash-escaped so tables and formatting cannot break.
Fixed-vocabulary tokens (channels, statuses, measurements,
coverages, confidences, severities, codes) render verbatim;
their character sets are inert in table cells.
"""

from memveil.model.report import Report
from memveil.model.session import Channel
from memveil.model.validate import format_u64
from memveil.render.filter import resolve_device_filter
from memveil.render.context import measured_duration, recorded_value
from memveil.render.text import escape_text


def _append_entity(mut out: List[UInt8], word: String):
    out.append(UInt8(0x26))
    var raw = word.as_bytes()
    for i in range(len(raw)):
        out.append(raw[i])
    out.append(UInt8(0x3B))


def escape_markdown(s: String) raises -> String:
    var clean = escape_text(s)
    var raw = clean.as_bytes()
    var out = List[UInt8]()
    for i in range(len(raw)):
        var b = raw[i]
        if b == UInt8(0x26):
            _append_entity(out, String("amp"))
        elif b == UInt8(0x3C):
            _append_entity(out, String("lt"))
        elif b == UInt8(0x3E):
            _append_entity(out, String("gt"))
        else:
            if (
                b == UInt8(0x5C)
                or b == UInt8(0x7C)
                or b == UInt8(0x2A)
                or b == UInt8(0x5F)
                or b == UInt8(0x5B)
                or b == UInt8(0x5D)
                or b == UInt8(0x60)
            ):
                out.append(UInt8(0x5C))
            out.append(b)
    return String(from_utf8=Span(out))


def _dims_cell(has_device: Bool, device: String, has_pool: Bool, pool: String) raises -> String:
    if has_device and has_pool:
        return (
            "device="
            + escape_markdown(device)
            + ", pool="
            + escape_markdown(pool)
        )
    if has_device:
        return "device=" + escape_markdown(device)
    if has_pool:
        return "pool=" + escape_markdown(pool)
    return String("all")


def _quality_row(label: String, ch: Channel) raises -> String:
    var out = String("| ")
    out += label
    out += " | "
    out += ch.status
    out += " | "
    if ch.has_loss_count:
        out += format_u64(ch.loss_count)
    else:
        out += "unknown"
    out += " | "
    out += escape_markdown(ch.scope)
    out += " | "
    out += escape_markdown(ch.reason)
    out += " |\n"
    return out


def render_markdown(rep: Report, device_filter: String = "") raises -> String:
    """Render the report as Markdown, one trailing newline."""
    var filt = resolve_device_filter(rep.devices, device_filter)
    var out = String("# Memveil report `")
    out += escape_text(rep.session_id)
    out += "`\n\n"
    if rep.synthetic:
        out += "- synthetic: yes\n"
    else:
        out += "- synthetic: no\n"
    out += "- engine: "
    out += escape_text(rep.engine_version)
    out += "\n- window: ["
    out += format_u64(rep.window_start_ns)
    out += ","
    out += format_u64(rep.window_end_ns)
    out += ")\n- duration: "
    out += measured_duration(rep)
    out += "\n- environment: mode="
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
    for source in [String("kernel.release"), String("profile.decision"), String("measurement_scope")]:
        out += "\n- recorded "
        out += escape_markdown(source)
        out += ": "
        out += escape_markdown(recorded_value(rep.env.evidence, source))
    out += "\n- devices: "
    out += String(len(rep.devices))
    out += "\n\n## Devices\n\n"
    out += "| device_id | name | driver | identity |\n"
    out += "| --- | --- | --- | --- |\n"
    for i in range(len(rep.devices)):
        var d = rep.devices[i]
        out += "| "
        out += escape_markdown(d.device_id)
        out += " | "
        out += escape_markdown(d.name)
        out += " | "
        if d.has_driver:
            out += escape_markdown(d.driver)
        else:
            out += "none"
        out += " | "
        out += escape_text(d.identity_status)
        out += " |\n"
    out += "\n## Quality\n\n"
    out += "| channel | status | loss | scope | reason |\n"
    out += "| --- | --- | --- | --- | --- |\n"
    out += _quality_row(String("detail"), rep.q_detail)
    out += _quality_row(String("aggregate"), rep.q_aggregate)
    out += _quality_row(String("correlation"), rep.q_correlation)
    out += _quality_row(String("baseline"), rep.q_baseline)
    out += _quality_row(String("terminal"), rep.q_terminal)
    out += "\n## Metrics\n\n"
    out += "| name | dimensions | value | unit | measurement | coverage | confidence | scope | notes |\n"
    out += "| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
    for i in range(len(rep.metrics)):
        var m = rep.metrics[i]
        if filt != "" and m.has_device_id:
            if m.device_id != filt:
                continue
        out += "| "
        out += escape_markdown(m.name)
        out += " | "
        out += _dims_cell(
            m.has_device_id, m.device_id, m.has_pool_id, m.pool_id
        )
        out += " | "
        if m.has_value:
            out += format_u64(m.value)
        else:
            out += "unavailable"
        out += " | "
        out += escape_markdown(m.unit)
        out += " | "
        out += escape_text(m.measurement)
        out += " | "
        out += escape_text(m.coverage)
        out += " | "
        out += escape_text(m.confidence)
        out += " | "
        out += escape_markdown(m.scope)
        out += " | "
        out += escape_markdown(m.notes)
        out += " |\n"
    out += "\n## Findings\n\n"
    if len(rep.findings) == 0:
        out += "none\n"
    else:
        out += "| severity | code | explanation | scope | limitations | refs |\n"
        out += "| --- | --- | --- | --- | --- | --- |\n"
        for i in range(len(rep.findings)):
            out += "| "
            out += escape_text(rep.findings[i].severity)
            out += " | "
            out += escape_text(rep.findings[i].code)
            out += " | "
            out += escape_markdown(rep.findings[i].explanation)
            out += " | "
            out += escape_markdown(rep.findings[i].scope)
            out += " | "
            out += escape_markdown(rep.findings[i].limitations)
            out += " | "
            for ri in range(len(rep.findings[i].evidence_refs)):
                if ri > 0:
                    out += ", "
                out += escape_markdown(rep.findings[i].evidence_refs[ri])
            out += " |\n"
    out += "\n## Limitations\n\n"
    for i in range(len(rep.limitations)):
        out += "- "
        out += escape_markdown(rep.limitations[i])
        out += "\n"
    return out
