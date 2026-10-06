"""Bounded JSON scanner over raw bytes.

The reader parses session and event documents with a
schema-directed cursor, never a generic DOM, so every allocation
stays proportional to an explicit input bound. This module owns the
lowest layer: string, scalar, and structural scanning with validated
UTF-8 output and a hard nesting-depth cap. It also owns the tail
classifier, which tells complete, truncated, and corrupt final
records apart without raising.
"""

comptime MAX_DEPTH_DEFAULT = 64

comptime TAIL_COMPLETE = 0
comptime TAIL_INCOMPLETE = 1
comptime TAIL_INVALID = 2


@fieldwise_init
struct ScanError(Copyable, Writable):
    """One scanner failure with its byte offset."""

    var offset: Int
    var message: String


struct Scanner:
    """Cursor over one bounded JSON document."""

    var _data: List[UInt8]
    var _pos: Int
    var _depth: Int
    var max_depth: Int

    def __init__(out self, text: String, max_depth: Int = MAX_DEPTH_DEFAULT):
        self._data = List[UInt8]()
        self._pos = 0
        self._depth = 0
        self.max_depth = max_depth
        for b in text.as_bytes():
            self._data.append(b)

    def __init__(
        out self, data: List[UInt8], max_depth: Int = MAX_DEPTH_DEFAULT
    ):
        self._data = List[UInt8]()
        self._pos = 0
        self._depth = 0
        self.max_depth = max_depth
        for b in data:
            self._data.append(b)

    def at_end(self) -> Bool:
        return self._pos >= len(self._data)

    def offset(self) -> Int:
        return self._pos

    def skip_ws(mut self):
        while self._pos < len(self._data):
            var b = self._data[self._pos]
            if (
                b == UInt8(0x20)
                or b == UInt8(0x09)
                or b == UInt8(0x0A)
                or b == UInt8(0x0D)
            ):
                self._pos += 1
            else:
                break

    def peek(self) raises -> UInt8:
        if self._pos >= len(self._data):
            raise ScanError(self._pos, "unexpected end of input")
        return self._data[self._pos]

    def expect_byte(mut self, want: UInt8) raises:
        var got = self._take()
        if got != want:
            raise ScanError(
                self._pos - 1,
                "expected byte " + String(Int(want)),
            )

    def parse_bool(mut self) raises -> Bool:
        if self._pos + 4 <= len(self._data) and self._match_word("true"):
            return True
        if self._pos + 5 <= len(self._data) and self._match_word("false"):
            return False
        raise ScanError(self._pos, "bad boolean")

    def _match_word(mut self, word: String) raises -> Bool:
        var wb = word.as_bytes()
        if self._pos + len(wb) > len(self._data):
            return False
        for i in range(len(wb)):
            if self._data[self._pos + i] != wb[i]:
                return False
        self._pos += len(wb)
        return True

    def parse_null(mut self) raises:
        if self._pos + 4 <= len(self._data) and self._match_word("null"):
            return
        raise ScanError(self._pos, "bad null")

    def parse_int(mut self) raises -> Int64:
        var neg = False
        if self._pos < len(self._data) and self._data[self._pos] == UInt8(0x2D):
            neg = True
            self._pos += 1
        if self._pos >= len(self._data):
            raise ScanError(self._pos, "bad integer")
        var first = self._data[self._pos]
        if first < UInt8(0x30) or first > UInt8(0x39):
            raise ScanError(self._pos, "bad integer")
        if first == UInt8(0x30):
            self._pos += 1
            if self._pos < len(self._data):
                var nxt = self._data[self._pos]
                if nxt >= UInt8(0x30) and nxt <= UInt8(0x39):
                    raise ScanError(self._pos, "leading zero")
            return Int64(0)
        var acc = UInt64(0)
        while self._pos < len(self._data):
            var b = self._data[self._pos]
            if b < UInt8(0x30) or b > UInt8(0x39):
                break
            var digit = UInt64(Int(b) - 0x30)
            if acc > (UInt64(0xFFFFFFFFFFFFFFFF) - digit) // UInt64(10):
                raise ScanError(self._pos, "integer overflow")
            acc = acc * UInt64(10) + digit
            self._pos += 1
        if not neg and acc > UInt64(9223372036854775807):
            raise ScanError(self._pos, "integer overflow")
        if neg and acc > UInt64(9223372036854775808):
            raise ScanError(self._pos, "integer overflow")
        if not neg:
            return Int64(acc)
        if acc == UInt64(9223372036854775808):
            return Int64(-9223372036854775807) - Int64(1)
        return -Int64(acc)

    def begin_object(mut self) raises:
        self.skip_ws()
        self._expect(UInt8(0x7B))
        self._depth += 1
        if self._depth > self.max_depth:
            raise ScanError(self._pos, "nesting too deep")

    def end_object(mut self) raises:
        self.skip_ws()
        self._expect(UInt8(0x7D))
        self._depth -= 1

    def begin_array(mut self) raises:
        self.skip_ws()
        self._expect(UInt8(0x5B))
        self._depth += 1
        if self._depth > self.max_depth:
            raise ScanError(self._pos, "nesting too deep")

    def end_array(mut self) raises:
        self.skip_ws()
        self._expect(UInt8(0x5D))
        self._depth -= 1

    def span_bytes(self, start: Int, end: Int) raises -> List[UInt8]:
        """Copy bytes [start, end): one skipped value's source span."""
        if start < 0 or end < start or end > len(self._data):
            raise ScanError(start, "bad span")
        var out = List[UInt8]()
        for i in range(start, end):
            out.append(self._data[i])
        return out^

    def skip_value(mut self) raises:
        """Skip one JSON value structurally, enforcing the depth cap.

        Strings are fully validated; numbers are consumed by charset
        only, since every skipped span of interest is re-parsed
        semantically afterwards.
        """
        self.skip_ws()
        var c = self.peek()
        if c == UInt8(0x22):
            _ = self.parse_string()
        elif c == UInt8(0x7B):
            self.begin_object()
            self.skip_ws()
            if self.peek() != UInt8(0x7D):
                while True:
                    self.skip_ws()
                    _ = self.parse_string()
                    self.skip_ws()
                    self._expect(UInt8(0x3A))
                    self.skip_value()
                    self.skip_ws()
                    var s = self.peek()
                    if s == UInt8(0x2C):
                        self._expect(UInt8(0x2C))
                    elif s == UInt8(0x7D):
                        break
                    else:
                        raise ScanError(self._pos, "want , or }")
            self.end_object()
        elif c == UInt8(0x5B):
            self.begin_array()
            self.skip_ws()
            if self.peek() != UInt8(0x5D):
                while True:
                    self.skip_value()
                    self.skip_ws()
                    var s = self.peek()
                    if s == UInt8(0x2C):
                        self._expect(UInt8(0x2C))
                    elif s == UInt8(0x5D):
                        break
                    else:
                        raise ScanError(self._pos, "want , or ]")
            self.end_array()
        elif c == UInt8(0x74) or c == UInt8(0x66):
            _ = self.parse_bool()
        elif c == UInt8(0x6E):
            self.parse_null()
        else:
            self._skip_number()

    def _skip_number(mut self) raises:
        var c = self.peek()
        if (
            c != UInt8(0x2D)
            and (c < UInt8(0x30) or c > UInt8(0x39))
        ):
            raise ScanError(self._pos, "bad value")
        while self._pos < len(self._data):
            var b = self._data[self._pos]
            if (
                (b >= UInt8(0x30) and b <= UInt8(0x39))
                or b == UInt8(0x2D)
                or b == UInt8(0x2B)
                or b == UInt8(0x2E)
                or b == UInt8(0x65)
                or b == UInt8(0x45)
            ):
                self._pos += 1
            else:
                break

    def _take(mut self) raises -> UInt8:
        if self._pos >= len(self._data):
            raise ScanError(self._pos, "unexpected end of input")
        var b = self._data[self._pos]
        self._pos += 1
        return b

    def _expect(mut self, want: UInt8) raises:
        var got = self._take()
        if got != want:
            raise ScanError(
                self._pos - 1,
                "expected byte " + String(Int(want)),
            )

    def _take_hex4(mut self) raises -> Int:
        var value = 0
        for _ in range(4):
            var b = self._take()
            var digit = -1
            if b >= UInt8(0x30) and b <= UInt8(0x39):
                digit = Int(b) - 0x30
            elif b >= UInt8(0x41) and b <= UInt8(0x46):
                digit = Int(b) - 0x41 + 10
            elif b >= UInt8(0x61) and b <= UInt8(0x66):
                digit = Int(b) - 0x61 + 10
            if digit < 0:
                raise ScanError(self._pos - 1, "bad hex digit")
            value = value * 16 + digit
        return value

    def _emit_utf8(mut self, mut out: List[UInt8], cp: Int) raises:
        if cp < 0 or cp > 0x10FFFF:
            raise ScanError(self._pos, "code point out of range")
        if cp >= 0xD800 and cp <= 0xDFFF:
            raise ScanError(self._pos, "lone surrogate")
        if cp < 0x80:
            out.append(UInt8(cp))
        elif cp < 0x800:
            out.append(UInt8(0xC0 | (cp >> 6)))
            out.append(UInt8(0x80 | (cp & 0x3F)))
        elif cp < 0x10000:
            out.append(UInt8(0xE0 | (cp >> 12)))
            out.append(UInt8(0x80 | ((cp >> 6) & 0x3F)))
            out.append(UInt8(0x80 | (cp & 0x3F)))
        else:
            out.append(UInt8(0xF0 | (cp >> 18)))
            out.append(UInt8(0x80 | ((cp >> 12) & 0x3F)))
            out.append(UInt8(0x80 | ((cp >> 6) & 0x3F)))
            out.append(UInt8(0x80 | (cp & 0x3F)))

    def _parse_escape(mut self, mut out: List[UInt8]) raises:
        var e = self._take()
        if e == UInt8(0x22):  # "
            out.append(UInt8(0x22))
        elif e == UInt8(0x5C):  # backslash
            out.append(UInt8(0x5C))
        elif e == UInt8(0x2F):  # /
            out.append(UInt8(0x2F))
        elif e == UInt8(0x62):  # b
            out.append(UInt8(0x08))
        elif e == UInt8(0x66):  # f
            out.append(UInt8(0x0C))
        elif e == UInt8(0x6E):  # n
            out.append(UInt8(0x0A))
        elif e == UInt8(0x72):  # r
            out.append(UInt8(0x0D))
        elif e == UInt8(0x74):  # t
            out.append(UInt8(0x09))
        elif e == UInt8(0x75):  # u
            var unit = self._take_hex4()
            if unit >= 0xD800 and unit <= 0xDBFF:
                self._expect(UInt8(0x5C))
                self._expect(UInt8(0x75))
                var low = self._take_hex4()
                if low < 0xDC00 or low > 0xDFFF:
                    raise ScanError(self._pos, "bad low surrogate")
                var cp = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                self._emit_utf8(out, cp)
            else:
                self._emit_utf8(out, unit)
        else:
            raise ScanError(self._pos - 1, "bad escape")

    def parse_string(mut self) raises -> String:
        """Parse one JSON string; the cursor must sit on its quote."""
        self._expect(UInt8(0x22))
        var out = List[UInt8]()
        while True:
            var b = self._take()
            if b == UInt8(0x22):
                break
            if b == UInt8(0x5C):
                self._parse_escape(out)
            elif b < UInt8(0x20):
                raise ScanError(self._pos - 1, "control in string")
            else:
                out.append(b)
        try:
            return String(from_utf8=Span(out))
        except:
            raise ScanError(self._pos, "invalid utf-8 in string")


def _tail_is_ws(b: UInt8) -> Bool:
    return (
        b == UInt8(0x20)
        or b == UInt8(0x09)
        or b == UInt8(0x0A)
        or b == UInt8(0x0D)
    )


def _tail_skip_ws(data: List[UInt8], mut pos: Int):
    while pos < len(data) and _tail_is_ws(data[pos]):
        pos += 1


def _tail_expect(data: List[UInt8], mut pos: Int, want: UInt8) -> Int:
    if pos >= len(data):
        return TAIL_INCOMPLETE
    if data[pos] != want:
        return TAIL_INVALID
    pos += 1
    return TAIL_COMPLETE


def _tail_string(data: List[UInt8], mut pos: Int) -> Int:
    pos += 1
    while True:
        if pos >= len(data):
            return TAIL_INCOMPLETE
        var b = data[pos]
        if b == UInt8(0x22):
            pos += 1
            return TAIL_COMPLETE
        if b == UInt8(0x5C):
            var esc = _tail_escape(data, pos)
            if esc != TAIL_COMPLETE:
                return esc
            continue
        if b < UInt8(0x20):
            return TAIL_INVALID
        if b < UInt8(0x80):
            pos += 1
            continue
        var uni = _tail_utf8(data, pos)
        if uni != TAIL_COMPLETE:
            return uni


def _tail_escape(data: List[UInt8], mut pos: Int) -> Int:
    pos += 1
    if pos >= len(data):
        return TAIL_INCOMPLETE
    var e = data[pos]
    pos += 1
    if (
        e == UInt8(0x22)
        or e == UInt8(0x5C)
        or e == UInt8(0x2F)
        or e == UInt8(0x62)
        or e == UInt8(0x66)
        or e == UInt8(0x6E)
        or e == UInt8(0x72)
        or e == UInt8(0x74)
    ):
        return TAIL_COMPLETE
    if e != UInt8(0x75):
        return TAIL_INVALID
    for _ in range(4):
        if pos >= len(data):
            return TAIL_INCOMPLETE
        var h = data[pos]
        var ok = (h >= UInt8(0x30) and h <= UInt8(0x39)) or (
            h >= UInt8(0x41) and h <= UInt8(0x46)
        ) or (h >= UInt8(0x61) and h <= UInt8(0x66))
        if not ok:
            return TAIL_INVALID
        pos += 1
    return TAIL_COMPLETE


def _tail_utf8(data: List[UInt8], mut pos: Int) -> Int:
    var b0 = data[pos]
    var want: Int
    var lo = UInt8(0x80)
    var hi = UInt8(0xBF)
    if b0 >= UInt8(0xC2) and b0 <= UInt8(0xDF):
        want = 1
    elif b0 == UInt8(0xE0):
        want = 2
        lo = UInt8(0xA0)
    elif b0 >= UInt8(0xE1) and b0 <= UInt8(0xEC):
        want = 2
    elif b0 == UInt8(0xED):
        want = 2
        hi = UInt8(0x9F)
    elif b0 >= UInt8(0xEE) and b0 <= UInt8(0xEF):
        want = 2
    elif b0 == UInt8(0xF0):
        want = 3
        lo = UInt8(0x90)
    elif b0 >= UInt8(0xF1) and b0 <= UInt8(0xF3):
        want = 3
    elif b0 == UInt8(0xF4):
        want = 3
        hi = UInt8(0x8F)
    else:
        return TAIL_INVALID
    pos += 1
    for i in range(want):
        if pos >= len(data):
            return TAIL_INCOMPLETE
        var c = data[pos]
        var floor = UInt8(0x80)
        var ceil = UInt8(0xBF)
        if i == 0:
            floor = lo
            ceil = hi
        if c < floor or c > ceil:
            return TAIL_INVALID
        pos += 1
    return TAIL_COMPLETE


def _tail_number(data: List[UInt8], mut pos: Int) -> Int:
    if data[pos] == UInt8(0x2D):
        pos += 1
        if pos >= len(data):
            return TAIL_INCOMPLETE
    var first = data[pos]
    if first < UInt8(0x30) or first > UInt8(0x39):
        return TAIL_INVALID
    if first == UInt8(0x30):
        pos += 1
    else:
        while pos < len(data):
            var d = data[pos]
            if d < UInt8(0x30) or d > UInt8(0x39):
                break
            pos += 1
    if pos < len(data):
        var nxt = data[pos]
        if first == UInt8(0x30) and nxt >= UInt8(0x30) and nxt <= UInt8(
            0x39
        ):
            return TAIL_INVALID
    if pos < len(data) and data[pos] == UInt8(0x2E):
        pos += 1
        if pos >= len(data):
            return TAIL_INCOMPLETE
        if data[pos] < UInt8(0x30) or data[pos] > UInt8(0x39):
            return TAIL_INVALID
        while pos < len(data):
            var d = data[pos]
            if d < UInt8(0x30) or d > UInt8(0x39):
                break
            pos += 1
    if pos < len(data) and (
        data[pos] == UInt8(0x65) or data[pos] == UInt8(0x45)
    ):
        pos += 1
        if pos >= len(data):
            return TAIL_INCOMPLETE
        if data[pos] == UInt8(0x2B) or data[pos] == UInt8(0x2D):
            pos += 1
            if pos >= len(data):
                return TAIL_INCOMPLETE
        if pos >= len(data):
            return TAIL_INCOMPLETE
        if data[pos] < UInt8(0x30) or data[pos] > UInt8(0x39):
            return TAIL_INVALID
        while pos < len(data):
            var d = data[pos]
            if d < UInt8(0x30) or d > UInt8(0x39):
                break
            pos += 1
    return TAIL_COMPLETE


def _tail_literal(
    data: List[UInt8], mut pos: Int, word: List[UInt8]
) -> Int:
    for i in range(len(word)):
        if pos >= len(data):
            return TAIL_INCOMPLETE
        if data[pos] != word[i]:
            return TAIL_INVALID
        pos += 1
    return TAIL_COMPLETE


def _tail_value(
    data: List[UInt8], mut pos: Int, depth: Int, max_depth: Int
) -> Int:
    if pos >= len(data):
        return TAIL_INCOMPLETE
    var b = data[pos]
    if b == UInt8(0x22):
        return _tail_string(data, pos)
    if b == UInt8(0x7B):
        return _tail_object(data, pos, depth, max_depth)
    if b == UInt8(0x5B):
        return _tail_array(data, pos, depth, max_depth)
    if b == UInt8(0x74):
        var want = List[UInt8]()
        want.append(UInt8(0x74))
        want.append(UInt8(0x72))
        want.append(UInt8(0x75))
        want.append(UInt8(0x65))
        return _tail_literal(data, pos, want)
    if b == UInt8(0x66):
        var want = List[UInt8]()
        want.append(UInt8(0x66))
        want.append(UInt8(0x61))
        want.append(UInt8(0x6C))
        want.append(UInt8(0x73))
        want.append(UInt8(0x65))
        return _tail_literal(data, pos, want)
    if b == UInt8(0x6E):
        var want = List[UInt8]()
        want.append(UInt8(0x6E))
        want.append(UInt8(0x75))
        want.append(UInt8(0x6C))
        want.append(UInt8(0x6C))
        return _tail_literal(data, pos, want)
    if b == UInt8(0x2D) or (b >= UInt8(0x30) and b <= UInt8(0x39)):
        return _tail_number(data, pos)
    return TAIL_INVALID


def _tail_object(
    data: List[UInt8], mut pos: Int, depth: Int, max_depth: Int
) -> Int:
    if depth + 1 > max_depth:
        return TAIL_INVALID
    pos += 1
    _tail_skip_ws(data, pos)
    if pos >= len(data):
        return TAIL_INCOMPLETE
    if data[pos] == UInt8(0x7D):
        pos += 1
        return TAIL_COMPLETE
    while True:
        if pos >= len(data):
            return TAIL_INCOMPLETE
        if data[pos] != UInt8(0x22):
            return TAIL_INVALID
        var key = _tail_string(data, pos)
        if key != TAIL_COMPLETE:
            return key
        _tail_skip_ws(data, pos)
        var colon = _tail_expect(data, pos, UInt8(0x3A))
        if colon != TAIL_COMPLETE:
            return colon
        _tail_skip_ws(data, pos)
        var val = _tail_value(data, pos, depth + 1, max_depth)
        if val != TAIL_COMPLETE:
            return val
        _tail_skip_ws(data, pos)
        if pos >= len(data):
            return TAIL_INCOMPLETE
        if data[pos] == UInt8(0x2C):
            pos += 1
            _tail_skip_ws(data, pos)
            continue
        if data[pos] == UInt8(0x7D):
            pos += 1
            return TAIL_COMPLETE
        return TAIL_INVALID


def _tail_array(
    data: List[UInt8], mut pos: Int, depth: Int, max_depth: Int
) -> Int:
    if depth + 1 > max_depth:
        return TAIL_INVALID
    pos += 1
    _tail_skip_ws(data, pos)
    if pos >= len(data):
        return TAIL_INCOMPLETE
    if data[pos] == UInt8(0x5D):
        pos += 1
        return TAIL_COMPLETE
    while True:
        var val = _tail_value(data, pos, depth + 1, max_depth)
        if val != TAIL_COMPLETE:
            return val
        _tail_skip_ws(data, pos)
        if pos >= len(data):
            return TAIL_INCOMPLETE
        if data[pos] == UInt8(0x2C):
            pos += 1
            _tail_skip_ws(data, pos)
            continue
        if data[pos] == UInt8(0x5D):
            pos += 1
            return TAIL_COMPLETE
        return TAIL_INVALID


struct TailMember(ImplicitlyCopyable):
    """One object member with key/value byte spans and verdicts."""

    var key_start: Int
    var key_end: Int
    var key_verdict: Int
    var val_start: Int
    var val_end: Int
    var val_verdict: Int

    def __init__(out self):
        self.key_start = 0
        self.key_end = 0
        self.key_verdict = TAIL_INVALID
        self.val_start = 0
        self.val_end = 0
        self.val_verdict = TAIL_INVALID


def tail_scan_members(
    data: List[UInt8],
    mut pos: Int,
    depth: Int,
    max_depth: Int,
    mut out: List[TailMember],
) -> Int:
    """Scan one object's members, recording complete-key spans.

    pos must be at `{`. Members whose key token is complete append
    to out, even when the colon or value is cut off (with an empty
    or partial value span); the scan stops at the first incomplete
    key, the closing brace, or a definite syntax error, and returns
    the object verdict. Depth accounting matches _tail_object
    exactly, so verdicts agree with classify_tail on the same bytes.
    """
    if depth + 1 > max_depth:
        return TAIL_INVALID
    pos += 1
    _tail_skip_ws(data, pos)
    if pos >= len(data):
        return TAIL_INCOMPLETE
    if data[pos] == UInt8(0x7D):
        pos += 1
        return TAIL_COMPLETE
    while True:
        if pos >= len(data):
            return TAIL_INCOMPLETE
        if data[pos] != UInt8(0x22):
            return TAIL_INVALID
        var m = TailMember()
        m.key_start = pos
        m.key_verdict = _tail_string(data, pos)
        m.key_end = pos
        if m.key_verdict != TAIL_COMPLETE:
            return m.key_verdict
        _tail_skip_ws(data, pos)
        var colon = _tail_expect(data, pos, UInt8(0x3A))
        if colon != TAIL_COMPLETE:
            # The key is complete even though its value never
            # starts: expose it so duplicate/unknown-key checks see
            # it, with an empty value span.
            m.val_start = pos
            m.val_end = pos
            m.val_verdict = TAIL_INCOMPLETE
            out.append(m^)
            return colon
        _tail_skip_ws(data, pos)
        m.val_start = pos
        m.val_verdict = _tail_value(data, pos, depth + 1, max_depth)
        m.val_end = pos
        var verdict = m.val_verdict
        out.append(m^)
        if verdict != TAIL_COMPLETE:
            return verdict
        _tail_skip_ws(data, pos)
        if pos >= len(data):
            return TAIL_INCOMPLETE
        if data[pos] == UInt8(0x2C):
            pos += 1
            _tail_skip_ws(data, pos)
            continue
        if data[pos] == UInt8(0x7D):
            pos += 1
            return TAIL_COMPLETE
        return TAIL_INVALID


def classify_tail(
    data: List[UInt8], max_depth: Int = MAX_DEPTH_DEFAULT
) -> Int:
    """Classify final-record bytes without raising.

    Returns TAIL_COMPLETE when the bytes hold exactly one JSON
    value, TAIL_INCOMPLETE when the bytes could still grow into
    one (input ended mid-value), and TAIL_INVALID for definite
    corruption. Framing only: complete values may still fail
    schema validation downstream, and surrogate pairing is not
    checked here.
    """
    var pos = 0
    _tail_skip_ws(data, pos)
    if pos >= len(data):
        return TAIL_INVALID
    var val = _tail_value(data, pos, 0, max_depth)
    if val != TAIL_COMPLETE:
        return val
    _tail_skip_ws(data, pos)
    if pos >= len(data):
        return TAIL_COMPLETE
    return TAIL_INVALID
