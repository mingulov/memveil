# SPDX-License-Identifier: GPL-3.0-or-later

"""Lifecycle/copy wire decode, Event mapping, and the ledger.

Decodes the 44-byte MVLC v2 and 48-byte MVCP v1 records produced
by the swiotlb lifecycle and copy probes. Byte layout, check
order, and reason vocabulary mirror
bpf/include/memveil_events.h; any intentional contract change
must update the header, the corpus, and both decoders together.
Decode, Event mapping, and ledger only: collector attach,
multi-channel packaging, profile admission, and live
qualification are separate work.

MVLC v2 carries an opaque mapping generation (0 = unknown);
the ledger pairs map/unmap only on nonzero generations and
reports lifetimes as eligible-but-incomplete after misses,
loss, or an invalid epoch. MVCP carries no identity: copy
and sync records never pair. Normalized unknown-identity
Events flow through the correlation registry, which labels
them unpaired with an explicit cause.
"""

from memveil.capture.normalize import DecodeError, NormalizeError
from memveil.model.event import Event
from memveil.model.validate import checked_add, format_u64

comptime LC_LEN = 44
comptime CP_LEN = 48

# Frozen probe hook identities shared by normalization,
# registry admission, and session capabilities: one
# definition so admission can never skew from emission.
comptime HOOK_MAP_RESULT = "fexit:swiotlb_tbl_map_single"
comptime HOOK_UNMAP = "fentry:__swiotlb_tbl_unmap_single"
comptime HOOK_SYNC_DEVICE = "fentry:__swiotlb_sync_single_for_device"
comptime HOOK_SYNC_CPU = "fentry:__swiotlb_sync_single_for_cpu"
comptime HOOK_BOUNCE = "fentry:swiotlb_bounce"

comptime _LC_MAGIC = 0x434C564D
comptime _CP_MAGIC = 0x5043564D
comptime _LC_VERSION = 2
comptime _CP_VERSION = 1

comptime _LC_KIND_MAP = 1
comptime _LC_KIND_UNMAP = 2
comptime _LC_FLAG_OK = 1
comptime _LC_FLAG_SKIP_SYNC = 2
comptime _LC_FLAG_GEN_MISS = 4
comptime _LC_FLAG_GEN_UNASSIGNED = 8
comptime _LC_GEN_MAX = UInt64(0xFFFFFFFFFFFFFFFE)

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
comptime _LC_OFF_GEN = 36
comptime _CP_OFF_REQUESTED = 28
comptime _CP_OFF_EFFECTIVE = 36
comptime _CP_OFF_REASON = 44


@fieldwise_init
struct DecodedLifecycle(Copyable, Movable):
    """One decoded MVLC v2 record: map result or unmap fact."""

    var kind: UInt16
    var ok: Bool
    var skip_sync: Bool
    var dir: UInt16
    var seq: UInt64
    var ktime: UInt64
    var size: UInt64
    var gen: UInt64


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
    """Decode and strictly validate one MVLC v2 record.

    Check order matches mv_decode_lifecycle: header guard,
    magic, version (v1 bytes fail here, not on length),
    length, kind, flags, direction, flag/generation
    coupling, generation range. Raises DecodeError with
    the shared reason vocabulary on any rejection.
    """
    if len(raw) < _OFF_VERSION + 2:
        raise DecodeError("PAY_SHORT", True)
    if _lc_le32(raw, _OFF_MAGIC) != UInt32(_LC_MAGIC):
        raise DecodeError("PAY_MAGIC", True)
    if _lc_le16(raw, _OFF_VERSION) != UInt16(_LC_VERSION):
        raise DecodeError("PAY_VERSION", True)
    if len(raw) < LC_LEN:
        raise DecodeError("PAY_SHORT", True)
    if len(raw) > LC_LEN:
        raise DecodeError("PAY_LONG", True)
    var kind = _lc_le16(raw, _OFF_KIND)
    if kind != UInt16(_LC_KIND_MAP) and kind != UInt16(_LC_KIND_UNMAP):
        raise DecodeError("PAY_KIND", True)
    var flags = _lc_le16(raw, _OFF_FLAGS)
    if flags & ~UInt16(
        _LC_FLAG_OK | _LC_FLAG_SKIP_SYNC | _LC_FLAG_GEN_MISS | _LC_FLAG_GEN_UNASSIGNED
    ) != UInt16(0):
        raise DecodeError("PAY_FLAGS", True)
    var dir = _lc_le16(raw, _OFF_DIR)
    if dir > UInt16(2):
        raise DecodeError("PAY_DIR", True)
    var gen = _lc_le64(raw, _LC_OFF_GEN)
    var miss = flags & UInt16(_LC_FLAG_GEN_MISS) != UInt16(0)
    var unassigned = flags & UInt16(_LC_FLAG_GEN_UNASSIGNED) != UInt16(0)
    if kind == UInt16(_LC_KIND_MAP):
        if flags & ~UInt16(_LC_FLAG_OK | _LC_FLAG_GEN_UNASSIGNED) != UInt16(0):
            raise DecodeError("PAY_FLAGS", True)
        var ok = flags & UInt16(_LC_FLAG_OK) != UInt16(0)
        if ok:
            if unassigned != (gen == UInt64(0)):
                raise DecodeError("PAY_FLAGS", True)
        elif flags != UInt16(0) or gen != UInt64(0):
            raise DecodeError("PAY_FLAGS", True)
    else:
        if flags & ~UInt16(
            _LC_FLAG_OK | _LC_FLAG_SKIP_SYNC | _LC_FLAG_GEN_MISS
        ) != UInt16(0):
            raise DecodeError("PAY_FLAGS", True)
        if miss != (gen == UInt64(0)):
            raise DecodeError("PAY_FLAGS", True)
    if gen != UInt64(0) and gen > _LC_GEN_MAX:
        raise DecodeError("PAY_RANGE", True)
    var out = DecodedLifecycle(
        kind,
        flags & UInt16(_LC_FLAG_OK) != UInt16(0),
        flags & UInt16(_LC_FLAG_SKIP_SYNC) != UInt16(0),
        dir,
        _lc_le64(raw, _OFF_SEQ),
        _lc_le64(raw, _OFF_KTIME),
        _lc_le64(raw, _OFF_SIZE),
        gen,
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
    if _lc_le16(raw, _OFF_VERSION) != UInt16(_CP_VERSION):
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
    """Per-event lifecycle/copy facts plus wire-gen pairing scope.

    Wire generations render as gen-N tokens; the ledger
    counts unknown identities (unassigned maps, missed
    unmaps) separately so they can never hide inside a
    paired total. The open estimate stays maps minus unmaps
    saturated at zero and is never a pairing claim; pairing
    itself lives in the correlation registry. Totals use
    checked u64 arithmetic: a note that would overflow
    raises and changes nothing.
    """

    var maps_ok: UInt64
    var maps_ok_bytes: UInt64
    var maps_failed: UInt64
    var maps_unassigned: UInt64
    var unmaps: UInt64
    var unmaps_bytes: UInt64
    var unmaps_skip_sync: UInt64
    var unmaps_gen_miss: UInt64
    var sync_requests: UInt64
    var copies_known: UInt64
    var copies_known_effective_bytes: UInt64
    var copies_unknown: UInt64
    var saw_wire_gen: Bool

    def __init__(out self):
        self.maps_ok = UInt64(0)
        self.maps_ok_bytes = UInt64(0)
        self.maps_failed = UInt64(0)
        self.maps_unassigned = UInt64(0)
        self.unmaps = UInt64(0)
        self.unmaps_bytes = UInt64(0)
        self.unmaps_skip_sync = UInt64(0)
        self.unmaps_gen_miss = UInt64(0)
        self.sync_requests = UInt64(0)
        self.copies_known = UInt64(0)
        self.copies_known_effective_bytes = UInt64(0)
        self.copies_unknown = UInt64(0)
        self.saw_wire_gen = False

    def note_lifecycle(mut self, d: DecodedLifecycle) raises -> String:
        """Count one lifecycle record; report its wire token.

        Returns the gen-N token for a known-generation map,
        or the empty string for failed maps, unassigned maps,
        and all unmaps (unknown identities never mint and
        never pair here). Raises without changing the ledger
        if any total would exceed u64.
        """
        if d.kind == UInt16(_LC_KIND_MAP):
            if d.ok:
                var count = checked_add(self.maps_ok, UInt64(1))
                var total = checked_add(self.maps_ok_bytes, d.size)
                var unassigned = self.maps_unassigned
                if d.gen == UInt64(0):
                    unassigned = checked_add(
                        self.maps_unassigned, UInt64(1)
                    )
                else:
                    self.saw_wire_gen = True
                self.maps_ok = count
                self.maps_ok_bytes = total
                self.maps_unassigned = unassigned
                if d.gen == UInt64(0):
                    return String("")
                return _wire_gen_token(d.gen)
            self.maps_failed = checked_add(self.maps_failed, UInt64(1))
            return String("")
        var ucount = checked_add(self.unmaps, UInt64(1))
        var utotal = checked_add(self.unmaps_bytes, d.size)
        var scount = self.unmaps_skip_sync
        if d.skip_sync:
            scount = checked_add(self.unmaps_skip_sync, UInt64(1))
        var miss = self.unmaps_gen_miss
        if d.gen == UInt64(0):
            miss = checked_add(self.unmaps_gen_miss, UInt64(1))
        else:
            self.saw_wire_gen = True
        self.unmaps = ucount
        self.unmaps_bytes = utotal
        self.unmaps_skip_sync = scount
        self.unmaps_gen_miss = miss
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
        """Eligible once any wire generation is observed."""
        return self.saw_wire_gen

    def lifetimes_reason(self) -> String:
        if self.saw_wire_gen:
            return String(
                "wire generations present; map/unmap pairing"
                " eligible (misses and loss still caveat"
                " completeness)"
            )
        return String(
            "no wire mapping identity observed;"
            " pairing unavailable"
        )


def _record_id(seq: UInt64) -> String:
    """Mint one record-local id; never kernel identity."""
    return String("lc-") + format_u64(seq)


def _wire_gen_token(gen: UInt64) -> String:
    """Render one wire generation as an opaque mapping token."""
    return String("gen-") + format_u64(gen)


def normalize_lifecycle_event(d: DecodedLifecycle) -> Event:
    """Map one decoded MVLC v2 record onto a normalized Event.

    Kind, timestamp, per-probe hook name, and payload are set;
    the collector stamps the capture-derived source block
    (session, seq, profile, measurement) and runs the
    correlation registry before persisting. Every v2 record
    carries the wire discriminator (has_wire_generation is
    always True); known generations render as gen-N mapping
    tokens, while unassigned maps and missed unmaps carry no
    mapping id with an explicit wire_identity status. A
    failed map carries no identity at all.
    """
    var ev = Event()
    ev.ts_ns = d.ktime
    if d.kind == UInt16(_LC_KIND_MAP):
        ev.kind = String("map_result")
        ev.source_hook = String(HOOK_MAP_RESULT)
        ev.source_backend = String("tracing")
        ev.map_result.operation_id = _record_id(d.seq)
        ev.map_result.success = d.ok
        ev.map_result.has_wire_generation = True
        ev.map_result.wire_generation = d.gen
        if d.ok:
            ev.map_result.has_mapped_bytes = True
            ev.map_result.mapped_bytes = d.size
            if d.gen != UInt64(0):
                ev.map_result.has_mapping_id = True
                ev.map_result.mapping_id = _wire_gen_token(d.gen)
                ev.map_result.has_wire_identity = True
                ev.map_result.wire_identity = String("known")
            else:
                ev.map_result.has_wire_identity = True
                ev.map_result.wire_identity = String("unassigned")
        return ev^
    ev.kind = String("unmap")
    ev.source_hook = String(HOOK_UNMAP)
    ev.source_backend = String("tracing")
    ev.unmap.has_wire_generation = True
    ev.unmap.wire_generation = d.gen
    if d.gen != UInt64(0):
        ev.unmap.has_mapping_id = True
        ev.unmap.mapping_id = _wire_gen_token(d.gen)
        ev.unmap.has_wire_identity = True
        ev.unmap.wire_identity = String("known")
    else:
        ev.unmap.has_wire_identity = True
        ev.unmap.wire_identity = String("miss")
    return ev^


def normalize_copy_event(
    d: DecodedCopy
) raises NormalizeError -> Event:
    """Map one decoded MVCP record onto a normalized Event.

    Sync requests become sync_request events with unobserved
    offset (the _single_ API admits sub-range syncs and the
    record observes no offset, so has_offset stays False);
    the emitting probe follows from the to_device flag,
    which only the for_device probe sets. KNOWN copies
    become copy events with executed (never requested)
    bytes; an unknown copy raises non-fatal UNKNOWN_COPY so
    the collector drops exactly that record instead of
    persisting an invented length.
    """
    var ev = Event()
    ev.ts_ns = d.ktime
    if d.kind == UInt16(_CP_KIND_SYNC):
        ev.kind = String("sync_request")
        if d.to_device:
            ev.source_hook = String(HOOK_SYNC_DEVICE)
        else:
            ev.source_hook = String(HOOK_SYNC_CPU)
        ev.source_backend = String("tracing")
        ev.sync.operation_id = _record_id(d.seq)
        ev.sync.has_mapping_id = True
        ev.sync.mapping_id = _record_id(d.seq)
        ev.sync.has_offset = False
        ev.sync.length = d.requested
        return ev^
    if not d.known:
        raise NormalizeError("UNKNOWN_COPY", False)
    ev.kind = String("copy")
    ev.source_hook = String(HOOK_BOUNCE)
    ev.source_backend = String("tracing")
    ev.copy.operation_id = _record_id(d.seq)
    if d.to_device:
        ev.copy.direction = String("original_to_bounce")
    else:
        ev.copy.direction = String("bounce_to_original")
    ev.copy.bytes = d.effective
    return ev^
