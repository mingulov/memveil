# SPDX-License-Identifier: GPL-3.0-or-later

"""Profile-selected pool sampler core.

The sampler reads only admitted allocator fields on admitted
profiles and converts slots or pages to bytes only with a
verified unit size and checked arithmetic. A denied read, an
unknown unit size, or an overflow yields an unavailable sample
with a reason, never a zero that would fake an empty pool.
"""

from memveil.model.validate import ValidationError, check_opaque_id


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


struct NormalizedPoolSample(ImplicitlyCopyable):
    """One normalized pool reading with byte units or reasons."""

    var pool_id: String
    var has_used_bytes: Bool
    var used_bytes: UInt64
    var has_capacity_bytes: Bool
    var capacity_bytes: UInt64
    var unit: String
    var notes: String

    def __init__(out self):
        self.pool_id = String("")
        self.has_used_bytes = False
        self.used_bytes = UInt64(0)
        self.has_capacity_bytes = False
        self.capacity_bytes = UInt64(0)
        self.unit = String("bytes")
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
) raises -> NormalizedPoolSample:
    """Normalize one raw pool reading.

    Pool ids are generation-scoped opaque tokens: successive
    generations of one source name sample under distinct ids so
    streaks never span a pool re-creation. Missing halves stay
    unavailable with a reason; conversion overflow raises.
    """
    try:
        check_opaque_id(pool_id)
    except e:
        raise PoolSamplerError(String(e))
    if source == "":
        raise PoolSamplerError("empty source")
    var out = NormalizedPoolSample()
    out.pool_id = pool_id
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
    return out^
