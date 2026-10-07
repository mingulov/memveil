# SPDX-License-Identifier: GPL-3.0-or-later

"""Checked duration parsing for CLI options.

Accepted shapes: a strict decimal count of seconds with an
optional unit suffix: ``s`` (seconds), ``m`` (minutes), or ``h``
(hours). Bare digits mean seconds, matching the capture
options. The digits share the capture rules: 1..20 digits, no
leading zeros, no zero, overflow refused. Results are integer
nanoseconds.
"""

comptime _NS_PER_S = UInt64(1000000000)
comptime _NS_PER_M = UInt64(60000000000)
comptime _NS_PER_H = UInt64(3600000000000)


@fieldwise_init
struct DurationError(Copyable, Writable):
    """One duration parse failure."""

    var message: String


def parse_duration_ns(text: String) raises -> UInt64:
    """Parse DURATION to nanoseconds with refused overflow."""
    var raw = text.as_bytes()
    var n = len(raw)
    if n == 0 or n > 21:
        raise DurationError("bad duration: " + text)
    var mult = _NS_PER_S
    var digits = n
    var last = raw[n - 1]
    if last == UInt8(0x73) or last == UInt8(0x6D) or last == UInt8(0x68):
        digits = n - 1
        if last == UInt8(0x6D):
            mult = _NS_PER_M
        elif last == UInt8(0x68):
            mult = _NS_PER_H
    if digits == 0 or digits > 20:
        raise DurationError("bad duration: " + text)
    if raw[0] < UInt8(0x31) or raw[0] > UInt8(0x39):
        raise DurationError("bad duration: " + text)
    var v = UInt64(0)
    for i in range(digits):
        var b = raw[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise DurationError("bad duration: " + text)
        var d = UInt64(Int(b) - 0x30)
        if v > (u64max() - d) // UInt64(10):
            raise DurationError("bad duration: " + text)
        v = v * UInt64(10) + d
    if v > u64max() // mult:
        raise DurationError("duration overflows nanoseconds")
    return v * mult


def u64max() -> UInt64:
    return ~UInt64(0)
