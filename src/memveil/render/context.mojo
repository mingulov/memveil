# SPDX-License-Identifier: GPL-3.0-or-later

"""Captured context only; these strings never admit the current host."""

from memveil.model.report import Report
from memveil.model.session import EvidenceItem
from memveil.model.validate import format_u64


def recorded_value(evidence: List[EvidenceItem], source: String) -> String:
    """Keep conflicting captured interpretations explicit, before escaping."""
    var values = List[String]()
    for item in evidence:
        if item.item_type != "provenance" or item.source != source:
            continue
        var seen = False
        for value in values:
            if value == item.interpretation:
                seen = True
        if not seen:
            values.append(item.interpretation)
    if len(values) == 0:
        return String("unavailable (no captured provenance)")
    if len(values) == 1:
        if values[0] == "":
            return String("unavailable (empty captured provenance)")
        return values[0]
    return String("conflicting captured values: ") + String("; ").join(values)


def measured_duration(rep: Report) -> String:
    """Exact seconds and nanoseconds, including a replay prefix window."""
    if rep.window_end_ns < rep.window_start_ns:
        return String("unavailable (invalid recorded window)")
    var duration = rep.window_end_ns - rep.window_start_ns
    var seconds, remainder = divmod(duration, UInt64(1_000_000_000))
    var fraction = format_u64(remainder)
    while fraction.byte_length() < 9:
        fraction = String("0") + fraction
    return (
        format_u64(seconds) + String(".") + fraction
        + String(" s (") + format_u64(duration) + String(" ns)")
    )
