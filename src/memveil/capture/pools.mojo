# SPDX-License-Identifier: GPL-3.0-or-later

"""Profile-selected pool sampler core.

The sampler reads only admitted allocator fields on admitted
profiles and converts slots or pages to bytes only with a
verified unit size and checked arithmetic. A denied read, an
unknown unit size, or an overflow yields an unavailable sample
with a reason, never a zero that would fake an empty pool.

The default-pool counter reader below covers exactly three
debugfs counter files; transient/dynamic pools are not sampled.
"""

from memveil.model.validate import (
    ValidationError,
    check_opaque_id,
    parse_u64,
)
from memveil.platform.reader import (
    E_ABSENT,
    E_DENIED,
    EvidenceError,
    EvidenceReader,
    read_evidence,
)


comptime POOL_SWIOTLB_USED = "/sys/kernel/debug/swiotlb/io_tlb_used"
comptime POOL_SWIOTLB_NSLABS = "/sys/kernel/debug/swiotlb/io_tlb_nslabs"
comptime POOL_SWIOTLB_HIWATER = (
    "/sys/kernel/debug/swiotlb/io_tlb_used_hiwater"
)
comptime POOL_SWIOTLB_ALLOCATOR = "swiotlb"
comptime POOL_SWIOTLB_UNIT = 2048
comptime POOL_SWIOTLB_POOL_ID = "swiotlb-default"
comptime _COUNTER_CAP = 64


@fieldwise_init
struct PoolSamplerError(Copyable, Writable):
    """One sampler input failure."""

    var message: String


def check_field_admitted(field: String, admitted: List[String]) raises:
    """Accept only allowlisted allocator field names."""
    for i in range(len(admitted)):
        if admitted[i] == field:
            return
    raise PoolSamplerError("field not admitted: " + field)


def slots_to_bytes(
    slots: UInt64, unit_size: UInt64, has_unit_size: Bool
) raises -> UInt64:
    """Convert allocator units to bytes with a verified size.

    Raises without a verified positive size or on overflow.
    """
    if not has_unit_size or unit_size == UInt64(0):
        raise PoolSamplerError("unverified unit size")
    if slots > u64max() // unit_size:
        raise PoolSamplerError("unit conversion overflow")
    return slots * unit_size


def u64max() -> UInt64:
    return ~UInt64(0)


struct PoolCounterRead(ImplicitlyCopyable):
    """One default-pool counter read with per-half status.

    Each half is known or it is not; reason names the first
    failure in used/capacity/hiwater order, and stays empty
    when all three halves are known.
    """

    var has_used: Bool
    var used_slots: UInt64
    var has_cap: Bool
    var cap_slots: UInt64
    var has_hiwater: Bool
    var hiwater_slots: UInt64
    var reason: String

    def __init__(out self):
        self.has_used = False
        self.used_slots = UInt64(0)
        self.has_cap = False
        self.cap_slots = UInt64(0)
        self.has_hiwater = False
        self.hiwater_slots = UInt64(0)
        self.reason = String("")


def _parse_counter(raw: List[UInt8]) raises -> UInt64:
    """Parse one debugfs counter: digits plus one trailing newline.

    Byte-exact: anything else raises, and the digit run goes
    through the canonical u64 parser, so leading zeros and
    overflow raise too.
    """
    var end = len(raw)
    if end > 0 and raw[end - 1] == UInt8(0x0A):
        end -= 1
    if end == 0 or end > 20:
        raise PoolSamplerError("counter shape")
    var digits = List[UInt8]()
    for i in range(end):
        var b = raw[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise PoolSamplerError("counter not a number")
        digits.append(b)
    try:
        var text = String(from_utf8=Span(digits))
        return parse_u64(text)
    except e:
        raise PoolSamplerError(String(e))


def _read_counter(
    reader: EvidenceReader, path: String
) -> Tuple[Bool, UInt64, String]:
    """Read one counter file; failures become a reason string."""
    var raw: List[UInt8]
    try:
        raw = read_evidence(reader, path, _COUNTER_CAP)
    except e:
        if e.code == E_ABSENT:
            return (False, UInt64(0), String("absent"))
        # E_DENIED and any other read failure both mean the
        # content is unreadable, which absence cannot prove.
        return (False, UInt64(0), String("denied"))
    try:
        return (True, _parse_counter(raw), String(""))
    except:
        return (False, UInt64(0), String("unparseable"))


def read_pool_counters(reader: EvidenceReader) -> PoolCounterRead:
    """Sample the default SWIOTLB pool counters; never raises.

    Absent, denied, and unparseable files yield unknown halves
    with a reason, never zeros. The hiwater file needs
    track_hiwater and a reset discipline the sampler does not
    perform; its value is historical, and analysis scopes it
    as allocator-lifetime with an unproved reset epoch.
    """
    var out = PoolCounterRead()
    var used = _read_counter(reader, POOL_SWIOTLB_USED)
    out.has_used = used[0]
    out.used_slots = used[1]
    var cap = _read_counter(reader, POOL_SWIOTLB_NSLABS)
    out.has_cap = cap[0]
    out.cap_slots = cap[1]
    var water = _read_counter(reader, POOL_SWIOTLB_HIWATER)
    out.has_hiwater = water[0]
    out.hiwater_slots = water[1]
    if not used[0]:
        out.reason = used[2]
    elif not cap[0]:
        out.reason = cap[2]
    elif not water[0]:
        out.reason = water[2]
    return out^


def sample_default_pool(
    reader: EvidenceReader, pool_id: String, unit_size: UInt64
) -> NormalizedPoolSample:
    """Sample, convert, and normalize the default pool; never raises.

    The unit size is caller-supplied (the live collector passes
    the kernel-fixed slot size); a conversion overflow yields an
    unavailable sample rather than a wrapped number.
    """
    var counters = read_pool_counters(reader)
    try:
        return normalize_pool_sample(
            pool_id,
            counters.has_used,
            counters.used_slots,
            counters.has_cap,
            counters.cap_slots,
            unit_size,
            True,
            String("swiotlb debugfs"),
            POOL_SWIOTLB_ALLOCATOR,
            counters.has_hiwater,
            counters.hiwater_slots,
            counters.reason,
        )
    except:
        var out = NormalizedPoolSample()
        out.pool_id = pool_id
        out.allocator = POOL_SWIOTLB_ALLOCATOR
        out.reason = String("unparseable")
        out.notes = String(
            "counter value unusable as bytes from swiotlb debugfs"
        )
        return out^


struct NormalizedPoolSample(ImplicitlyCopyable):
    """One normalized pool reading with byte units or reasons."""

    var pool_id: String
    var has_used_bytes: Bool
    var used_bytes: UInt64
    var has_capacity_bytes: Bool
    var capacity_bytes: UInt64
    var unit: String
    var allocator: String
    var has_unit_bytes: Bool
    var unit_bytes: UInt64
    var has_hiwater_bytes: Bool
    var hiwater_bytes: UInt64
    var reason: String
    var notes: String

    def __init__(out self):
        self.pool_id = String("")
        self.has_used_bytes = False
        self.used_bytes = UInt64(0)
        self.has_capacity_bytes = False
        self.capacity_bytes = UInt64(0)
        self.unit = String("bytes")
        self.allocator = String("")
        self.has_unit_bytes = False
        self.unit_bytes = UInt64(0)
        self.has_hiwater_bytes = False
        self.hiwater_bytes = UInt64(0)
        self.reason = String("")
        self.notes = String("")


def normalize_pool_sample(
    pool_id: String,
    has_used_slots: Bool,
    used_slots: UInt64,
    has_cap_slots: Bool,
    cap_slots: UInt64,
    unit_size: UInt64,
    has_unit_size: Bool,
    source: String,
    allocator: String,
    has_hw_slots: Bool,
    hw_slots: UInt64,
    reason: String,
) raises -> NormalizedPoolSample:
    """Normalize one raw pool reading.

    Pool ids are generation-scoped opaque tokens: successive
    generations of one source name sample under distinct ids so
    streaks never span a pool re-creation. Missing halves stay
    unavailable with a reason; conversion overflow raises. The
    allocator names the sampled scope, unit_bytes records the
    verified conversion basis, and hiwater carries the
    allocator-lifetime high-water mark when the read succeeded.
    """
    try:
        check_opaque_id(pool_id)
    except e:
        raise PoolSamplerError(String(e))
    if source == "":
        raise PoolSamplerError("empty source")
    try:
        check_opaque_id(allocator)
    except e:
        raise PoolSamplerError(String(e))
    if reason != "" and reason != "denied" and reason != "absent" \
            and reason != "unparseable":
        raise PoolSamplerError("bad reason: " + reason)
    if has_unit_size and unit_size == UInt64(0):
        raise PoolSamplerError("unit size must be positive")
    var out = NormalizedPoolSample()
    out.pool_id = pool_id
    out.allocator = allocator
    out.reason = reason
    if has_unit_size:
        out.unit_bytes = unit_size
        out.has_unit_bytes = True
    if has_used_slots:
        out.used_bytes = slots_to_bytes(
            used_slots, unit_size, has_unit_size
        )
        out.has_used_bytes = True
    else:
        out.notes = String("usage unavailable from " + source)
    if has_cap_slots:
        out.capacity_bytes = slots_to_bytes(
            cap_slots, unit_size, has_unit_size
        )
        out.has_capacity_bytes = True
    else:
        if out.notes != "":
            out.notes += "; "
        out.notes += "capacity unavailable from " + source
    if has_hw_slots:
        out.hiwater_bytes = slots_to_bytes(
            hw_slots, unit_size, has_unit_size
        )
        out.has_hiwater_bytes = True
    return out^
