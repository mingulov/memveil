"""Shared schema-directed parse helpers.

Session and event parsing share nullable-scalar handling and the
object/array stepping pattern. Every helper rejects unknown input;
nothing is skipped or defaulted silently.
"""

from memveil.jsonscan import Scanner, ScanError
from memveil.model.validate import ValidationError, parse_u64


struct MaybeString(ImplicitlyCopyable):
    """A nullable JSON string: absent and null both clear `has`."""

    var has: Bool
    var value: String

    def __init__(out self):
        self.has = False
        self.value = String("")


struct MaybeU64(ImplicitlyCopyable):
    """A nullable canonical-u64 JSON string."""

    var has: Bool
    var value: UInt64

    def __init__(out self):
        self.has = False
        self.value = UInt64(0)


def parse_maybe_string(mut scan: Scanner) raises -> MaybeString:
    """Parse a JSON string or null at the cursor."""
    var out = MaybeString()
    scan.skip_ws()
    if scan.peek() == UInt8(0x6E):
        scan.parse_null()
        return out^
    out.value = scan.parse_string()
    out.has = True
    return out^


def parse_maybe_u64(mut scan: Scanner) raises -> MaybeU64:
    """Parse a canonical-u64 JSON string or null at the cursor."""
    var out = MaybeU64()
    scan.skip_ws()
    if scan.peek() == UInt8(0x6E):
        scan.parse_null()
        return out^
    var text = scan.parse_string()
    try:
        out.value = parse_u64(text)
    except e:
        raise ValidationError("u64", String(e))
    out.has = True
    return out^


struct MaybeI64(ImplicitlyCopyable):
    """A nullable JSON integer: absent and null both clear `has`."""

    var has: Bool
    var value: Int64

    def __init__(out self):
        self.has = False
        self.value = Int64(0)


def parse_maybe_int(mut scan: Scanner) raises -> MaybeI64:
    """Parse a JSON integer or null at the cursor."""
    var out = MaybeI64()
    scan.skip_ws()
    if scan.peek() == UInt8(0x6E):
        scan.parse_null()
        return out^
    out.value = scan.parse_int()
    out.has = True
    return out^


def parse_u64_field(mut scan: Scanner, what: String) raises -> UInt64:
    """Parse a required canonical-u64 JSON string field value."""
    var text = scan.parse_string()
    try:
        return parse_u64(text)
    except e:
        raise ValidationError(what, String(e))


def object_is_empty(mut scan: Scanner) raises -> Bool:
    """True when the cursor sits on an empty object's closer."""
    scan.skip_ws()
    return scan.peek() == UInt8(0x7D)


def object_next(mut scan: Scanner, what: String) raises -> Bool:
    """Consume an object separator; True means another field follows."""
    scan.skip_ws()
    var c = scan.peek()
    if c == UInt8(0x2C):
        scan.expect_byte(UInt8(0x2C))
        return True
    if c == UInt8(0x7D):
        return False
    raise ScanError(scan.offset(), "want , or } in " + what)


def array_is_empty(mut scan: Scanner) raises -> Bool:
    """True when the cursor sits on an empty array's closer."""
    scan.skip_ws()
    return scan.peek() == UInt8(0x5D)


def array_next(mut scan: Scanner, what: String) raises -> Bool:
    """Consume an array separator; True means another item follows."""
    scan.skip_ws()
    var c = scan.peek()
    if c == UInt8(0x2C):
        scan.expect_byte(UInt8(0x2C))
        return True
    if c == UInt8(0x5D):
        return False
    raise ScanError(scan.offset(), "want , or ] in " + what)


def expect_colon(mut scan: Scanner, what: String) raises:
    """Consume the colon between an object key and its value."""
    scan.skip_ws()
    if scan.peek() != UInt8(0x3A):
        raise ScanError(scan.offset(), "want : in " + what)
    scan.expect_byte(UInt8(0x3A))
    scan.skip_ws()
