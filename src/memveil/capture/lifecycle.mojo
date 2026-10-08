# SPDX-License-Identifier: GPL-3.0-or-later

"""Lifecycle/copy wire decode and the v1 laboratory ledger.

Decodes the 36-byte MVLC and 48-byte MVCP records produced by the
swiotlb lifecycle and copy probes. Byte layout, check order, and
reason vocabulary mirror bpf/include/memveil_events.h; any
intentional contract change must update the header, the corpus, and
both decoders together. Decode and ledger only: collector attach,
multi-channel packaging, profile admission, and live qualification
are separate pending work.

The v1 wire carries no device or mapping identity, so the ledger
counts per-event facts only: map outcomes, unmaps, sync requests,
and executed bytes summed over KNOWN copy records. It never pairs a
map with an unmap, never infers a lifetime, and reports lifetimes
as explicitly unavailable with a reason.
"""

from memveil.capture.normalize import DecodeError
from memveil.model.validate import checked_add, format_u64

comptime LC_LEN = 36
comptime CP_LEN = 48

comptime _LC_MAGIC = 0x434C564D
comptime _CP_MAGIC = 0x5043564D
comptime _VERSION = 1

comptime _LC_KIND_MAP = 1
comptime _LC_KIND_UNMAP = 2
comptime _LC_FLAG_OK = 1
comptime _LC_FLAG_SKIP_SYNC = 2

comptime _CP_KIND_SYNC = 1
comptime _CP_KIND_COPY = 2
comptime _CP_FLAG_TO_DEVICE = 1
comptime _CP_FLAG_KNOWN = 2
comptime _CP_FLAG_CLAMPED = 4
comptime _CP_FLAG_EARLY_ZERO = 8
comptime _CP_REASON_NONE = 0
comptime _CP_REASON_NOT_COPY = 4

comptime _OFF_MAGIC = 0
comptime _OFF_VERSION = 4
comptime _OFF_KIND = 6
comptime _OFF_FLAGS = 8
comptime _OFF_DIR = 10
comptime _OFF_SEQ = 12
comptime _OFF_KTIME = 20
comptime _OFF_SIZE = 28
comptime _CP_OFF_REQUESTED = 28
comptime _CP_OFF_EFFECTIVE = 36
comptime _CP_OFF_REASON = 44


@fieldwise_init
struct DecodedLifecycle(Copyable, Movable):
    """One decoded MVLC record: map result or unmap fact."""

    var kind: UInt16
    var ok: Bool
    var skip_sync: Bool
    var dir: UInt16
    var seq: UInt64
    var ktime: UInt64
    var size: UInt64


@fieldwise_init
struct DecodedCopy(Copyable, Movable):
    """One decoded MVCP record: sync request or executed copy."""

    var kind: UInt16
    var to_device: Bool
    var known: Bool
    var clamped: Bool
    var early_zero: Bool
    var dir: UInt16
    var reason: UInt16
    var seq: UInt64
    var ktime: UInt64
    var requested: UInt64
    var effective: UInt64


@fieldwise_init
struct EffectiveOut(ImplicitlyCopyable):
    """Replicated swiotlb_bounce length outcome."""

    var effective: UInt64
    var clamped: Bool
    var early_zero: Bool


def _lc_le16(raw: List[UInt8], off: Int) -> UInt16:
    return UInt16(raw[off]) | (UInt16(raw[off + 1]) << 8)


def _lc_le32(raw: List[UInt8], off: Int) -> UInt32:
    var v = UInt32(raw[off])
    v |= UInt32(raw[off + 1]) << 8
    v |= UInt32(raw[off + 2]) << 16
    v |= UInt32(raw[off + 3]) << 24
    return v


def _lc_le64(raw: List[UInt8], off: Int) -> UInt64:
    var v = UInt64(0)
    for i in range(8):
        v |= UInt64(raw[off + i]) << UInt64(8 * i)
    return v


def decode_lifecycle(raw: List[UInt8]) raises DecodeError -> DecodedLifecycle:
    """Decode and strictly validate one MVLC record.

    Check order matches mv_decode_lifecycle: length, magic,
    version, kind, flags, direction. Raises DecodeError with
    the shared reason vocabulary on any rejection.
    """
    if len(raw) < LC_LEN:
        raise DecodeError("PAY_SHORT", True)
    if len(raw) > LC_LEN:
        raise DecodeError("PAY_LONG", True)
    if _lc_le32(raw, _OFF_MAGIC) != UInt32(_LC_MAGIC):
        raise DecodeError("PAY_MAGIC", True)
    if _lc_le16(raw, _OFF_VERSION) != UInt16(_VERSION):
        raise DecodeError("PAY_VERSION", True)
    var kind = _lc_le16(raw, _OFF_KIND)
    if kind != UInt16(_LC_KIND_MAP) and kind != UInt16(_LC_KIND_UNMAP):
        raise DecodeError("PAY_KIND", True)
    var flags = _lc_le16(raw, _OFF_FLAGS)
    if flags & ~UInt16(_LC_FLAG_OK | _LC_FLAG_SKIP_SYNC) != UInt16(0):
        raise DecodeError("PAY_FLAGS", True)
    var dir = _lc_le16(raw, _OFF_DIR)
    if dir > UInt16(2):
        raise DecodeError("PAY_DIR", True)
    var out = DecodedLifecycle(
        kind,
        flags & UInt16(_LC_FLAG_OK) != UInt16(0),
        flags & UInt16(_LC_FLAG_SKIP_SYNC) != UInt16(0),
        dir,
        _lc_le64(raw, _OFF_SEQ),
        _lc_le64(raw, _OFF_KTIME),
        _lc_le64(raw, _OFF_SIZE),
    )
    return out^


def decode_copy(raw: List[UInt8]) raises DecodeError -> DecodedCopy:
    """Decode and strictly validate one MVCP record.

    Check order matches mv_decode_copy: length, magic, version,
    kind, flags, direction, then the known/reason cross rules
    (known pins NONE; sync pins NOT_COPY; an unknown copy must
    name a real failure reason). Raises DecodeError with the
    shared reason vocabulary on any rejection.
    """
    if len(raw) < CP_LEN:
        raise DecodeError("PAY_SHORT", True)
    if len(raw) > CP_LEN:
        raise DecodeError("PAY_LONG", True)
    if _lc_le32(raw, _OFF_MAGIC) != UInt32(_CP_MAGIC):
        raise DecodeError("PAY_MAGIC", True)
    if _lc_le16(raw, _OFF_VERSION) != UInt16(_VERSION):
        raise DecodeError("PAY_VERSION", True)
    var kind = _lc_le16(raw, _OFF_KIND)
    if kind != UInt16(_CP_KIND_SYNC) and kind != UInt16(_CP_KIND_COPY):
        raise DecodeError("PAY_KIND", True)
    var flags = _lc_le16(raw, _OFF_FLAGS)
    if flags & ~UInt16(
        _CP_FLAG_TO_DEVICE | _CP_FLAG_KNOWN | _CP_FLAG_CLAMPED | _CP_FLAG_EARLY_ZERO
    ) != UInt16(0):
        raise DecodeError("PAY_FLAGS", True)
    var dir = _lc_le16(raw, _OFF_DIR)
    if dir > UInt16(2) or (kind == UInt16(_CP_KIND_COPY) and dir == UInt16(0)):
        raise DecodeError("PAY_DIR", True)
    var reason = _lc_le16(raw, _CP_OFF_REASON)
    if reason > UInt16(_CP_REASON_NOT_COPY):
        raise DecodeError("PAY_REASON", True)
    var known = flags & UInt16(_CP_FLAG_KNOWN) != UInt16(0)
    if known:
        if reason != UInt16(_CP_REASON_NONE):
            raise DecodeError("PAY_REASON", True)
    elif kind == UInt16(_CP_KIND_SYNC):
        if reason != UInt16(_CP_REASON_NOT_COPY):
            raise DecodeError("PAY_REASON", True)
    elif reason == UInt16(_CP_REASON_NONE) or reason == UInt16(_CP_REASON_NOT_COPY):
        raise DecodeError("PAY_REASON", True)
    var out = DecodedCopy(
        kind,
        flags & UInt16(_CP_FLAG_TO_DEVICE) != UInt16(0),
        known,
        flags & UInt16(_CP_FLAG_CLAMPED) != UInt16(0),
        flags & UInt16(_CP_FLAG_EARLY_ZERO) != UInt16(0),
        dir,
        reason,
        _lc_le64(raw, _OFF_SEQ),
        _lc_le64(raw, _OFF_KTIME),
        _lc_le64(raw, _CP_OFF_REQUESTED),
        _lc_le64(raw, _CP_OFF_EFFECTIVE),
    )
    return out^


def effective_bytes(
    size: UInt64, tlb_offset: Int64, alloc_size: UInt64, orig_valid: Bool
) -> EffectiveOut:
    """Replicate the swiotlb_bounce length rule for cross-checks.

    Mirrors mv_effective_bytes: an invalid slot copies nothing
    (hook early return); otherwise the request clamps to
    alloc_size - tlb_offset with the hook's signed offset math
    (negative offsets are valid and widen the room). Saturates
    instead of wrapping.
    """
    if not orig_valid:
        return EffectiveOut(UInt64(0), False, True)
    var room: UInt64
    if tlb_offset < Int64(0):
        # Same formula as mv_effective_bytes, including INT64_MIN:
        # tlb_offset + 1 cannot overflow, so its negation fits and
        # the +1 widening lands exactly at 2**63; no special case.
        var widen = UInt64(-(tlb_offset + 1)) + UInt64(1)
        if widen > ~UInt64(0) - alloc_size:
            room = ~UInt64(0)
        else:
            room = alloc_size + widen
    elif UInt64(tlb_offset) >= alloc_size:
        room = UInt64(0)
    else:
        room = alloc_size - UInt64(tlb_offset)
    if size > room:
        return EffectiveOut(room, True, False)
    return EffectiveOut(size, False, False)


struct LifecycleLedger:
    """Per-event lifecycle/copy facts without map/unmap pairing.

    Every successful map mints one opaque generation id; an
    unmap never claims to close a specific map. The open
    estimate is maps minus unmaps saturated at zero, and
    lifetimes stay explicitly unavailable until a wire with
    mapping identity exists. Totals use checked u64
    arithmetic: a note that would overflow raises and changes
    nothing.
    """

    var maps_ok: UInt64
    var maps_ok_bytes: UInt64
    var maps_failed: UInt64
    var unmaps: UInt64
    var unmaps_bytes: UInt64
    var unmaps_skip_sync: UInt64
    var sync_requests: UInt64
    var copies_known: UInt64
    var copies_known_effective_bytes: UInt64
    var copies_unknown: UInt64

    def __init__(out self):
        self.maps_ok = UInt64(0)
        self.maps_ok_bytes = UInt64(0)
        self.maps_failed = UInt64(0)
        self.unmaps = UInt64(0)
        self.unmaps_bytes = UInt64(0)
        self.unmaps_skip_sync = UInt64(0)
        self.sync_requests = UInt64(0)
        self.copies_known = UInt64(0)
        self.copies_known_effective_bytes = UInt64(0)
        self.copies_unknown = UInt64(0)

    def note_lifecycle(mut self, d: DecodedLifecycle) raises -> String:
        """Count one lifecycle record; mint a generation per map.

        Returns the new opaque generation id for a successful
        map, or the empty string for failed maps and unmaps
        (which never pair and never mint). Raises without
        changing the ledger if any total would exceed u64.
        """
        if d.kind == UInt16(_LC_KIND_MAP):
            if d.ok:
                var count = checked_add(self.maps_ok, UInt64(1))
                var total = checked_add(self.maps_ok_bytes, d.size)
                self.maps_ok = count
                self.maps_ok_bytes = total
                return String("lc-") + format_u64(d.seq)
            self.maps_failed = checked_add(self.maps_failed, UInt64(1))
            return String("")
        var ucount = checked_add(self.unmaps, UInt64(1))
        var utotal = checked_add(self.unmaps_bytes, d.size)
        var scount = self.unmaps_skip_sync
        if d.skip_sync:
            scount = checked_add(self.unmaps_skip_sync, UInt64(1))
        self.unmaps = ucount
        self.unmaps_bytes = utotal
        self.unmaps_skip_sync = scount
        return String("")

    def note_copy(mut self, d: DecodedCopy) raises:
        """Count one copy record; sum effective bytes when KNOWN.

        Sync requests and unknown copies never contribute
        executed bytes; unknown copies count separately so a
        quiet effective total cannot hide missing evidence.
        Raises without changing the ledger if any total would
        exceed u64.
        """
        if d.kind == UInt16(_CP_KIND_SYNC):
            self.sync_requests = checked_add(self.sync_requests, UInt64(1))
            return
        if d.known:
            var count = checked_add(self.copies_known, UInt64(1))
            var total = checked_add(
                self.copies_known_effective_bytes, d.effective
            )
            self.copies_known = count
            self.copies_known_effective_bytes = total
        else:
            self.copies_unknown = checked_add(self.copies_unknown, UInt64(1))

    def open_estimate(self) -> UInt64:
        """Maps minus unmaps, saturated: never a pairing claim."""
        if self.maps_ok >= self.unmaps:
            return self.maps_ok - self.unmaps
        return UInt64(0)

    def lifetimes_available(self) -> Bool:
        """v1 has no mapping identity, so never."""
        return False

    def lifetimes_reason(self) -> String:
        return String(
            "v1 wire carries no mapping identity;"
            " map/unmap pairing unavailable"
        )
