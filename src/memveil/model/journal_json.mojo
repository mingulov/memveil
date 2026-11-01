# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded closed-object helpers for the journal's typed metadata."""
from memveil.jsonscan import Scanner
from memveil.model.common import object_is_empty, object_next, expect_colon, parse_maybe_u64, parse_maybe_string, MaybeU64
from memveil.model.validate import ValidationError, format_u64


def fields(mut scan: Scanner, names: String) raises -> Dict[String, List[UInt8]]:
    var allowed = names.split(",")
    var out = Dict[String, List[UInt8]]()
    scan.begin_object()
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            var known = False
            for name in allowed:
                if key == name:
                    known = True
            if not known or key in out:
                raise ValidationError("journal", "unknown or duplicate field")
            expect_colon(scan, "journal")
            var start = scan.offset()
            scan.skip_value()
            out[key] = scan.span_bytes(start, scan.offset())
            if not object_next(scan, "journal"):
                break
    scan.end_object()
    if len(out) != len(allowed):
        raise ValidationError("journal", "missing field")
    return out^


def text(data: List[UInt8], nullable: Bool = False) raises -> String:
    var scan = Scanner(data)
    scan.skip_ws()
    if nullable:
        var value = parse_maybe_string(scan)
        if value.has and value.value == "":
            raise ValidationError("journal", "empty nullable string")
        return value.value
    return scan.parse_string()


def uint(data: List[UInt8]) raises -> MaybeU64:
    var scan = Scanner(data)
    return parse_maybe_u64(scan)


def required_uint(data: List[UInt8]) raises -> UInt64:
    var result = uint(data)
    if not result.has:
        raise ValidationError("journal", "unexpected null count")
    return result.value


def native_int(data: List[UInt8]) raises -> Int32:
    var scan = Scanner(data)
    scan.skip_ws()
    var value = scan.parse_int()
    if value < -2147483648 or value > 2147483647:
        raise ValidationError("journal", "native int32 range")
    return Int32(value)


def boolean(data: List[UInt8]) raises -> Bool:
    var scan = Scanner(data)
    scan.skip_ws()
    return scan.parse_bool()


def null_value(data: List[UInt8]) raises:
    var scan = Scanner(data)
    scan.skip_ws()
    scan.parse_null()


def quoted(value: String) -> String:
    var out = String('"')
    for cp in value.codepoint_slices():
        var s = String(cp)
        if s == '"' or s == "\\":
            out += "\\" + s
        elif s == "\n":
            out += "\\n"
        elif s == "\r":
            out += "\\r"
        elif s == "\t":
            out += "\\t"
        else:
            var bytes = s.as_bytes()
            if len(bytes) == 1 and bytes[0] < 32:
                var hexes = String("0123456789abcdef")
                out += "\\u00" + String(hexes[byte=Int(bytes[0]) // 16]) + String(hexes[byte=Int(bytes[0]) % 16])
            else:
                out += s
    return out + '"'


def nullable_text(value: String) -> String:
    return String("null") if value == "" else quoted(value)


def nullable_uint(value: MaybeU64) -> String:
    return quoted(format_u64(value.value)) if value.has else String("null")


def member(key: String, value: String) -> String:
    return quoted(key) + ":" + value


def object_text(parts: List[String]) -> String:
    var out = String("{")
    for i in range(len(parts)):
        if i:
            out += ","
        out += parts[i]
    return out + "}"
