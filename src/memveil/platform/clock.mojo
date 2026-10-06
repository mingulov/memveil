"""Monotonic clock and time-namespace guard for record.

MonoClock implements ClockSource over clock_gettime
(CLOCK_MONOTONIC) and nanosleep. Signals stay blocked
during record, so the sleep never EINTRs. The timens
check refuses virtualized clocks: any nonzero integer
token in timens_offsets is an offset.
"""

from std.ffi import external_call

from memveil.capture.collector import ClockSource
from memveil.platform.reader import read_host_file

comptime _CLOCK_MONOTONIC = 1


struct MonoClock(ClockSource):
    """CLOCK_MONOTONIC nanoseconds plus settle sleeps."""

    def __init__(out self):
        pass

    def now(mut self) -> UInt64:
        var ts = List[UInt8]()
        for _ in range(16):
            ts.append(UInt8(0))
        var rc = external_call["clock_gettime", Int32](
            Int32(_CLOCK_MONOTONIC), Span(ts).unsafe_ptr()
        )
        if Int(rc) != 0:
            return UInt64(0)
        var sec = UInt64(0)
        var nsec = UInt64(0)
        for i in range(8):
            sec |= UInt64(ts[i]) << UInt64(8 * i)
            nsec |= UInt64(ts[8 + i]) << UInt64(8 * i)
        return sec * UInt64(1000000000) + nsec

    def sleep_ms(mut self, ms: Int):
        var clamped = ms
        if clamped < 0:
            clamped = 0
        var req = List[UInt8]()
        for _ in range(16):
            req.append(UInt8(0))
        var sec = UInt64(clamped // 1000)
        var nsec = UInt64((clamped % 1000) * 1000000)
        for i in range(8):
            req[i] = UInt8((sec >> UInt64(8 * i)) & UInt64(0xFF))
            req[8 + i] = UInt8(
                (nsec >> UInt64(8 * i)) & UInt64(0xFF)
            )
        var rem = List[UInt8]()
        for _ in range(16):
            rem.append(UInt8(0))
        _ = external_call["nanosleep", Int32](
            Span(req).unsafe_ptr(), Span(rem).unsafe_ptr()
        )


def _is_integer_token(body: Span[UInt8, _], lo: Int, hi: Int) -> Bool:
    var start = lo
    if start < hi and body[start] == UInt8(0x2D):
        start += 1
    if start >= hi:
        return False
    for i in range(start, hi):
        var b = body[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            return False
    return True


def _token_is_nonzero(body: Span[UInt8, _], lo: Int, hi: Int) -> Bool:
    for i in range(lo, hi):
        var b = body[i]
        if b >= UInt8(0x31) and b <= UInt8(0x39):
            return True
    return False


def timens_has_offset(body: Span[UInt8, _]) -> Bool:
    """True when timens_offsets carries a nonzero integer token.

    Clock names and blank runs are skipped; only integer
    tokens count, and only when a nonzero digit appears.
    """
    var total = len(body)
    var i = 0
    while i < total:
        var b = body[i]
        if (
            b == UInt8(0x20)
            or b == UInt8(0x09)
            or b == UInt8(0x0A)
            or b == UInt8(0x0D)
        ):
            i += 1
            continue
        var lo = i
        while i < total:
            var c = body[i]
            if (
                c == UInt8(0x20)
                or c == UInt8(0x09)
                or c == UInt8(0x0A)
                or c == UInt8(0x0D)
            ):
                break
            i += 1
        if _is_integer_token(body, lo, i) and _token_is_nonzero(
            body, lo, i
        ):
            return True
    return False


struct TimensOut(Copyable, Movable):
    """One timens read (offset valid only when ok)."""

    var ok: Bool
    var offset: Bool
    var message: String

    def __init__(out self):
        self.ok = False
        self.offset = False
        self.message = String("")


def check_timens_live() -> TimensOut:
    """Read /proc/self/timens_offsets and look for an offset.

    An unreadable file refuses admission: the clock cannot
    be proven clean. Supported kernels (7.0+) always carry
    this file when time namespaces exist.
    """
    var out = TimensOut()
    try:
        var raw = read_host_file(
            String("/proc/self/timens_offsets"),
            String("timens"),
            4096,
        )
        out.ok = True
        out.offset = timens_has_offset(Span(raw))
        return out^
    except e:
        out.ok = False
        out.message = String(e)
        return out^
