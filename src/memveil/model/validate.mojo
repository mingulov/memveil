"""Shared scalar validators for the frozen v0.1.0 contracts.

Canonical u64 strings, opaque identifiers, and bounded text appear in
every capture document; one implementation serves the session, event,
and report layers so all three refuse the same malformed input.
"""


@fieldwise_init
struct ValidationError(Copyable, Writable):
    """One scalar validation failure naming its field."""

    var what: String
    var message: String


def parse_u64(text: String) raises -> UInt64:
    """Parse a canonical u64 decimal string.

    Accepts ``0`` or a non-zero digit followed by up to 19 more
    digits, then range-checks 0..18446744073709551615. Anything else
    raises: empty input, signs, leading zeros, non-digits, overlong
    digit runs, and overflow.
    """
    var raw = text.as_bytes()
    var n = len(raw)
    if n == 0:
        raise ValidationError("u64", "empty value")
    if n > 20:
        raise ValidationError("u64", "too many digits")
    if n > 1 and raw[0] == UInt8(0x30):
        raise ValidationError("u64", "leading zero")
    var acc = UInt64(0)
    for i in range(n):
        var b = raw[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise ValidationError("u64", "non-digit")
        var digit = UInt64(Int(b) - 0x30)
        if acc > (UInt64(0xFFFFFFFFFFFFFFFF) - digit) // UInt64(10):
            raise ValidationError("u64", "overflow")
        acc = acc * UInt64(10) + digit
    return acc


def _is_id_start(b: UInt8) -> Bool:
    return (
        (b >= UInt8(0x41) and b <= UInt8(0x5A))
        or (b >= UInt8(0x61) and b <= UInt8(0x7A))
        or (b >= UInt8(0x30) and b <= UInt8(0x39))
        or b == UInt8(0x5F)
    )


def _is_id_rest(b: UInt8) -> Bool:
    return _is_id_start(b) or b == UInt8(0x2E) or b == UInt8(0x2D)


def check_opaque_id(text: String) raises:
    """Accept ``[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`` only.

    The pattern is pure ASCII, so a byte scan decides it: any
    multibyte sequence fails the character classes.
    """
    var raw = text.as_bytes()
    var n = len(raw)
    if n == 0:
        raise ValidationError("opaque_id", "empty value")
    if n > 128:
        raise ValidationError("opaque_id", "too long")
    if not _is_id_start(raw[0]):
        raise ValidationError("opaque_id", "bad first character")
    for i in range(1, n):
        if not _is_id_rest(raw[i]):
            raise ValidationError("opaque_id", "bad character")


def format_u64(v: UInt64) -> String:
    """Canonical decimal rendering: no sign, no leading zeros."""
    return String(v)


def checked_add(a: UInt64, b: UInt64) raises -> UInt64:
    """Add with overflow refused instead of wrapped."""
    if b > UInt64(0xFFFFFFFFFFFFFFFF) - a:
        raise ValidationError("add", "overflow")
    return a + b


def check_bounded_text(text: String, min_len: Int, max_len: Int, what: String) raises:
    """Check code-point length against a schema min/max length.

    JSON Schema string lengths count characters, not UTF-8 bytes, so
    a 64-code-point multibyte value passes a maxLength of 64.
    """
    var n = text.count_codepoints()
    if n < min_len:
        raise ValidationError(what, "too short")
    if n > max_len:
        raise ValidationError(what, "too long")
