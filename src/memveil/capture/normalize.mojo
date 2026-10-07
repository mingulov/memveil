# SPDX-License-Identifier: GPL-3.0-or-later

"""Attempt payload decode and normalization.

Decodes the 98-byte product payloads produced by the swiotlb
attempt probe, assigns stable per-capture device ids, and maps
decoded fields onto normalized attempt records.

Byte layout, check order, and reason vocabulary mirror
bpf/include/memveil_events.h. The attempts lane diffs this
decoder against the C reference over the same corpus, so any
intentional contract change must update the header, the corpus,
and both decoders together.
"""

from memveil.model.validate import format_u64
from memveil.platform.reader import is_valid_utf8


comptime PAYLOAD_LEN = 98
comptime NAME_MAX = 63
comptime DEVICE_MAX = 4096

comptime _MAGIC = 0x3741564D
comptime _VERSION = 1
comptime _FLAG_FORCE = 1

comptime _OFF_MAGIC = 0
comptime _OFF_VERSION = 4
comptime _OFF_FLAGS = 6
comptime _OFF_SEQ = 8
comptime _OFF_KTIME = 16
comptime _OFF_SIZE = 24
comptime _OFF_NAME_LEN = 32
comptime _OFF_NAME = 34


@fieldwise_init
struct DecodeError(Copyable, Writable):
    """One payload decode rejection naming its reason."""

    var reason: String
    var fatal: Bool


@fieldwise_init
struct NormalizeError(Copyable, Writable):
    """One normalization rejection.

    Fatal rejections (device-table exhaustion) abort the capture;
    non-fatal ones (bad UTF-8) drop one event and count it.
    """

    var reason: String
    var fatal: Bool


@fieldwise_init
struct DecodedAttempt(Copyable, Movable):
    """One decoded payload: raw fields, no identity assigned."""

    var size: UInt64
    var seq: UInt64
    var ktime: UInt64
    var name_len: Int
    var force: Bool
    var name: List[UInt8]


@fieldwise_init
struct NormalizedAttempt(Copyable, Movable):
    """One normalized attempt ready for the event writer."""

    var device_id: String
    var requested_bytes: UInt64
    var forced: Bool
    var operation_id: String
    var ts_ns: UInt64


def _le16(raw: List[UInt8], off: Int) -> UInt16:
    return UInt16(raw[off]) | (UInt16(raw[off + 1]) << 8)


def _le32(raw: List[UInt8], off: Int) -> UInt32:
    var v = UInt32(raw[off])
    v |= UInt32(raw[off + 1]) << 8
    v |= UInt32(raw[off + 2]) << 16
    v |= UInt32(raw[off + 3]) << 24
    return v


def _le64(raw: List[UInt8], off: Int) -> UInt64:
    var v = UInt64(0)
    for i in range(8):
        v |= UInt64(raw[off + i]) << UInt64(8 * i)
    return v


def decode_payload(raw: List[UInt8]) raises DecodeError -> DecodedAttempt:
    """Decode and strictly validate one product payload.

    Check order matches mv_decode_payload: length, magic,
    version, flags, name length, NUL terminator, interior NUL,
    then zero padding. Raises DecodeError with the shared
    reason vocabulary on any rejection.
    """
    if len(raw) < PAYLOAD_LEN:
        raise DecodeError("PAY_SHORT", True)
    if len(raw) > PAYLOAD_LEN:
        raise DecodeError("PAY_LONG", True)
    if _le32(raw, _OFF_MAGIC) != UInt32(_MAGIC):
        raise DecodeError("PAY_MAGIC", True)
    if _le16(raw, _OFF_VERSION) != UInt16(_VERSION):
        raise DecodeError("PAY_VERSION", True)
    var flags = _le16(raw, _OFF_FLAGS)
    if flags & ~UInt16(_FLAG_FORCE) != UInt16(0):
        raise DecodeError("PAY_FLAGS", True)
    var name_len = Int(_le16(raw, _OFF_NAME_LEN))
    if name_len > NAME_MAX:
        raise DecodeError("PAY_NAMELEN", True)
    if raw[_OFF_NAME + name_len] != UInt8(0):
        raise DecodeError("PAY_NUL", True)
    for i in range(name_len):
        if raw[_OFF_NAME + i] == UInt8(0):
            raise DecodeError("PAY_NUL", True)
    for i in range(name_len + 1, NAME_MAX + 1):
        if raw[_OFF_NAME + i] != UInt8(0):
            raise DecodeError("PAY_PAD", True)
    var name = List[UInt8]()
    for i in range(name_len):
        name.append(raw[_OFF_NAME + i])
    var out = DecodedAttempt(
        _le64(raw, _OFF_SIZE),
        _le64(raw, _OFF_SEQ),
        _le64(raw, _OFF_KTIME),
        name_len,
        flags & UInt16(_FLAG_FORCE) != UInt16(0),
        name^,
    )
    return out^


def bytes_to_hex(data: List[UInt8]) -> String:
    """Render bytes as lowercase hex with no separator."""
    var digits = String("0123456789abcdef")
    var out = String("")
    for i in range(len(data)):
        var b = Int(data[i])
        out += String(digits[byte=b >> 4])
        out += String(digits[byte=b & 0xF])
    return out^


def device_id_for(n: Int) -> String:
    """Render a 1-based device number as d000001-style id."""
    var digits = String(n)
    var out = String("d")
    var need = 6 - digits.byte_length()
    while need > 0:
        out += String("0")
        need -= 1
    return out + digits


def _hex_val(b: UInt8) -> Int:
    var v = Int(b)
    if v >= 0x30 and v <= 0x39:
        return v - 0x30
    if v >= 0x61 and v <= 0x66:
        return v - 0x61 + 10
    return -1


def _is_hex(b: UInt8) -> Bool:
    var v = Int(b)
    if v >= 0x30 and v <= 0x39:
        return True
    if v >= 0x61 and v <= 0x66:
        return True
    if v >= 0x41 and v <= 0x46:
        return True
    return False


def is_pci_scope(name: String) -> Bool:
    """True for canonical PCI name scope DDDD:BB:DD.F.

    Exactly twelve ASCII bytes: four hex digits, colon, two
    hex digits, colon, two hex digits, dot, one hex digit.
    Anything else (interface names, address-shaped blobs,
    paths) is not an admittable scope.
    """
    var raw = name.as_bytes()
    if len(raw) != 12:
        return False
    for i in range(4):
        if not _is_hex(raw[i]):
            return False
    if raw[4] != UInt8(0x3A):
        return False
    if not _is_hex(raw[5]) or not _is_hex(raw[6]):
        return False
    if raw[7] != UInt8(0x3A):
        return False
    if not _is_hex(raw[8]) or not _is_hex(raw[9]):
        return False
    if raw[10] != UInt8(0x2E):
        return False
    return _is_hex(raw[11])


def admitted_name(name: String) -> String:
    """Persistable catalog name: PCI scope or opaque marker.

    Interning keeps exact bytes so distinct devices stay
    distinct; only the human-readable label degrades.
    """
    if is_pci_scope(name):
        return name
    return String("unresolved")


def hex_to_bytes(text: String) raises NormalizeError -> List[UInt8]:
    """Strict inverse of bytes_to_hex (lowercase, even length).

    Table keys are produced by bytes_to_hex, so a violation
    means memory corruption, never caller input.
    """
    var raw = text.as_bytes()
    if len(raw) % 2 != 0:
        raise NormalizeError("INTERNAL", True)
    var out = List[UInt8]()
    for i in range(0, len(raw), 2):
        var hi = _hex_val(raw[i])
        var lo = _hex_val(raw[i + 1])
        if hi < 0 or lo < 0:
            raise NormalizeError("INTERNAL", True)
        out.append(UInt8(hi * 16 + lo))
    return out^


@fieldwise_init
struct CatalogEntry(Copyable, Movable):
    """One interned device: first-seen id plus admitted name."""

    var device_id: String
    var name: String


struct DeviceTable(Movable):
    """Per-capture device interning: raw name bytes to d000001 ids.

    Keys are hex renderings so arbitrary (even non-UTF8) names
    intern without lossy decoding. Assignment order is first-seen
    order starting at 1; past DEVICE_MAX distinct names the table
    raises a fatal EXHAUSTED rejection.
    """

    var _index: Dict[String, Int]
    var _order: List[String]
    var _next: Int

    def __init__(out self):
        self._index = Dict[String, Int]()
        self._order = List[String]()
        self._next = 1

    def len(self) -> Int:
        return len(self._index)

    def device_for(
        mut self, name: List[UInt8]
    ) raises NormalizeError -> String:
        var key = bytes_to_hex(name)
        if key in self._index:
            return device_id_for(self._index.get(key, 0))
        if len(self._index) >= DEVICE_MAX:
            raise NormalizeError("EXHAUSTED", True)
        var fresh = self._next
        self._next += 1
        self._index[key] = fresh
        self._order.append(key)
        return device_id_for(fresh)

    def entries(self) raises NormalizeError -> List[CatalogEntry]:
        """First-seen-ordered catalog (== device_id order).

        Only valid-UTF8 names reach the table through
        normalize_attempt; anything else here is fatal.
        """
        var out = List[CatalogEntry]()
        for i in range(len(self._order)):
            var key = self._order[i]
            var num = self._index.get(key, 0)
            if num <= 0:
                raise NormalizeError("INTERNAL", True)
            var raw = hex_to_bytes(key)
            var name: String
            try:
                name = String(from_utf8=Span(raw))
            except:
                raise NormalizeError("INTERNAL", True)
            var shown = admitted_name(name^)
            out.append(CatalogEntry(device_id_for(num), shown^))
        return out^


def normalize_attempt(
    decoded: DecodedAttempt, mut table: DeviceTable
) raises NormalizeError -> NormalizedAttempt:
    """Map one decoded payload onto a normalized attempt record.

    UTF-8 is checked before interning so a rejected name never
    consumes a device id. Raises NormalizeError("UTF8", fatal=False)
    for non-UTF8 names and propagates fatal table exhaustion.
    """
    if not is_valid_utf8(decoded.name):
        raise NormalizeError("UTF8", False)
    var device_id = table.device_for(decoded.name)
    var out = NormalizedAttempt(
        device_id^,
        decoded.size,
        decoded.force,
        String("op") + format_u64(decoded.seq),
        decoded.ktime,
    )
    return out^
