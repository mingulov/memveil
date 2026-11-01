# SPDX-License-Identifier: GPL-3.0-or-later
"""Transient finite symbol ranges; neither input nor addresses are exported."""
from memveil.model.journal_event import caller_label
from memveil.model.validate import ValidationError


@fieldwise_init
struct CallerRange(ImplicitlyCopyable):
    var start: UInt64
    var end: UInt64
    var ambiguous: Bool


def _address(value: StringSlice) raises -> UInt64:
    if value.byte_length() != 16:
        raise ValidationError("caller source", "invalid symbol shape")
    var out = UInt64(0)
    for b in value.as_bytes():
        var digit = Int(b) - 48
        if b >= 97 and b <= 102:
            digit = Int(b) - 87
        elif b >= 65 and b <= 70:
            digit = Int(b) - 55
        elif b < 48 or b > 57:
            raise ValidationError("caller source", "invalid symbol shape")
        out = (out << 4) | UInt64(digit)
    return out


def resolve_caller_ranges(source: String, stable_owned_module: Bool) raises -> List[CallerRange]:
    if source.byte_length() > 16777216:
        raise ValidationError("caller source", "input bound")
    var lines = source.split("\n")
    if len(lines) > 262144:
        raise ValidationError("caller source", "line bound")
    var out = List[CallerRange](length=10, fill=CallerRange(0, 0, False))
    var seen = List[Int](length=10, fill=0)
    var aliases = List[Int](length=10, fill=0)
    for line in lines:
        if line.byte_length() == 0:
            continue
        var parts = line.split(" ")
        if len(parts) < 3 or len(parts) > 4:
            raise ValidationError("caller source", "invalid symbol shape")
        var addr = _address(parts[0])
        var label = String(parts[2])
        if len(parts) == 4:
            label += " " + String(parts[3])
        for i in range(10):
            if i < 2 and not stable_owned_module:
                continue
            if label == caller_label(i + 1) and addr != 0:
                seen[i] += 1
                out[i].start = addr
    for line in lines:
        if line.byte_length() == 0:
            continue
        var parts = line.split(" ")
        var addr = _address(parts[0])
        for i in range(10):
            var start = out[i].start
            if start == 0:
                continue
            if addr == start:
                aliases[i] += 1
                out[i].ambiguous = aliases[i] > 1
            if addr > start and (out[i].end == 0 or addr < out[i].end):
                out[i].end = addr
    for i in range(10):
        if seen[i] != 1 or out[i].end <= out[i].start:
            out[i] = CallerRange(0, 0, False)
    return out^


def encode_caller_range(value: CallerRange) -> List[UInt8]:
    var out = List[UInt8]()
    var values: List[UInt64] = [value.start, value.end, UInt64(value.ambiguous)]
    for v in values:
        for i in range(8):
            out.append(UInt8((v >> UInt64(i * 8)) & 255))
    return out^
