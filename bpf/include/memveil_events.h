/* SPDX-License-Identifier: GPL-2.0-or-later */

/* MemVeil swiotlb attempt event layout and shared pure logic.
 *
 * This header compiles for BPF (--target=bpf) and for the host C
 * test/reference build. The pure functions (bounds validation,
 * payload decode) are THE SAME CODE in both: BPF calls them on
 * probe-read bytes, the reference calls them on memcpy'd bytes.
 * Only the context walk (probe_read vs memcpy) and the map/ring
 * plumbing differ, and those adapters are review-compared.
 *
 * Reason vocabulary (shared with the corpus and the Mojo decoder):
 *   OK, CTX_SHORT, CTX_LOC_OOB, CTX_DLEN_ZERO, CTX_DLEN_BIG,
 *   CTX_NUL_MISSING, CTX_NUL_EARLY, CTX_FORCE_BAD, CTX_TABLE_BAD,
 *   PAY_SHORT, PAY_LONG, PAY_MAGIC, PAY_VERSION, PAY_FLAGS,
 *   PAY_NAMELEN, PAY_NUL, PAY_PAD,
 *   PAY_KIND, PAY_DIR, PAY_REASON, PAY_RANGE.
 *
 * Lifecycle v2 (MVLC) records carry an opaque u64 mapping
 * generation assigned by the lifecycle BPF object; 0 means
 * unknown and 1..GEN_MAX are assignable. Copy (MVCP) v1
 * records carry no identity: pairing map/unmap across
 * events uses lifecycle generations only.
 */
#ifndef MEMVEIL_EVENTS_H
#define MEMVEIL_EVENTS_H

#ifdef __BPF__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
typedef int64_t __s64;
#endif

/* Product payload: exactly 98 bytes, little-endian, packed. */
#define MV_PAYLOAD_LEN 98
#define MV_MAGIC 0x3741564Du /* "MVA7" */
#define MV_VERSION 1u
#define MV_FLAG_FORCE 0x1u
#define MV_NAME_MAX 63u

#define MV_OFF_MAGIC 0u
#define MV_OFF_VERSION 4u
#define MV_OFF_FLAGS 6u
#define MV_OFF_SEQ 8u
#define MV_OFF_KTIME 16u
#define MV_OFF_SIZE 24u
#define MV_OFF_NAME_LEN 32u
#define MV_OFF_NAME 34u

/* Tracepoint context bounds (swiotlb_bounced, format id 382). */
#define MV_CTX_FIXED 41u /* end of last fixed field (force@40:1) */
#define MV_CTX_READ_CAP 512u /* dynamic extent must fit inside this */

/* Load-time trace-offset table: userspace probes the live
 * format and installs one entry before attach, so
 * offset-drifted kernels stay collectable. The program
 * fails closed on a missing, zero, or inconsistent
 * table: the firing counts as rejected, never misread. */
#define MV_OFF_TABLE_MAGIC 0x35464D4Du /* "MFO5" */
#define MV_OFF_TABLE_VERSION 1u
#define MV_FIXED_MAX 128u /* tabled extents and floor stay inside this */
#define MV_OFFSETS_TABLE_LEN 24u
struct mv_offsets {
    __u32 magic; /* must equal MV_OFF_TABLE_MAGIC */
    __u16 version; /* must equal MV_OFF_TABLE_VERSION */
    __u16 reserved0;
    __u32 loc_off; /* dev_name __data_loc slot */
    __u32 size_off; /* size u64 slot */
    __u32 force_off; /* force byte slot */
    __u32 fixed_end; /* dynamic-data floor over live fixed fields */
};

/* Counter map indices (mv_counts, ARRAY of 6 u64). */
#define MV_CNT_OBSERVED 0u
#define MV_CNT_OBSERVED_BYTES 1u
#define MV_CNT_EMITTED 2u
#define MV_CNT_EMITTED_BYTES 3u
#define MV_CNT_SUBMIT_FAIL 4u
#define MV_CNT_FLAGS 5u
#define MV_CNT_LEN 6u

/* Flag word bits (sticky; any set bit invalidates the epoch).
 * BYTE_COVERAGE is not a wrap: the tabled size read failed
 * (missing/invalid offset table or a short size slot),
 * so one firing's size is unknowable and the byte aggregate
 * can never cover it. */
#define MV_FLAG_OBSERVED_WRAP (1ULL << 0)
#define MV_FLAG_OBSERVED_BYTES_WRAP (1ULL << 1)
#define MV_FLAG_EMITTED_WRAP (1ULL << 2)
#define MV_FLAG_EMITTED_BYTES_WRAP (1ULL << 3)
#define MV_FLAG_SUBMIT_WRAP (1ULL << 4)
#define MV_FLAG_BYTE_COVERAGE (1ULL << 5)
#define MV_FLAG_ARGCNT (1ULL << 6)

enum mv_reason {
    MV_OK = 0,
    MV_CTX_SHORT,
    MV_CTX_LOC_OOB,
    MV_CTX_DLEN_ZERO,
    MV_CTX_DLEN_BIG,
    MV_CTX_NUL_MISSING,
    MV_CTX_NUL_EARLY,
    MV_CTX_FORCE_BAD,
    MV_CTX_TABLE_BAD,
    MV_PAY_SHORT,
    MV_PAY_LONG,
    MV_PAY_MAGIC,
    MV_PAY_VERSION,
    MV_PAY_FLAGS,
    MV_PAY_NAMELEN,
    MV_PAY_NUL,
    MV_PAY_PAD,
    MV_PAY_KIND,
    MV_PAY_DIR,
    MV_PAY_REASON,
    MV_PAY_RANGE
};

/* Decoded attempt fields (host struct, not wire layout). */
struct mv_attempt {
    __u64 seq;
    __u64 ktime;
    __u64 size;
    __u16 name_len;
    __u8 force;
    __u8 name[64];
};

static __inline __u16 mv_read_le16(const __u8 *p)
{
    return (__u16)((__u16)p[0] | ((__u16)p[1] << 8));
}

static __inline __u32 mv_read_le32(const __u8 *p)
{
    return (__u32)p[0] | ((__u32)p[1] << 8) | ((__u32)p[2] << 16) |
           ((__u32)p[3] << 24);
}

static __inline __u64 mv_read_le64(const __u8 *p)
{
    return (__u64)p[0] | ((__u64)p[1] << 8) | ((__u64)p[2] << 16) |
           ((__u64)p[3] << 24) | ((__u64)p[4] << 32) |
           ((__u64)p[5] << 40) | ((__u64)p[6] << 48) |
           ((__u64)p[7] << 56);
}

/* Validate a __data_loc pair against a dynamic-data floor, the
 * name cap, the read cap, and the available context length.
 * Check order is part of the contract: length faults precede
 * extent faults. */
static __inline enum mv_reason mv_validate_loc_floor(__u32 off, __u32 dlen,
                                                     __u32 ctx_len,
                                                     __u32 floor)
{
    if (dlen == 0)
        return MV_CTX_DLEN_ZERO;
    if (dlen > MV_NAME_MAX + 1)
        return MV_CTX_DLEN_BIG;
    if (off < floor)
        return MV_CTX_LOC_OOB;
    if (off + dlen > MV_CTX_READ_CAP)
        return MV_CTX_LOC_OOB;
    if (off + dlen > ctx_len)
        return MV_CTX_LOC_OOB;
    return MV_OK;
}

/* Pinned-floor variant: identical behavior to the original
 * single-floor check, kept for the host reference build. */
static __inline enum mv_reason mv_validate_loc(__u32 off, __u32 dlen,
                                               __u32 ctx_len)
{
    return mv_validate_loc_floor(off, dlen, ctx_len, MV_CTX_FIXED);
}

/* Validate one installed offset table the way the program
 * does: magic, version, per-extent caps, dynamic-floor
 * cap, pairwise overlap among the tabled extents and
 * the common_type anchor, and floor coverage over
 * every tabled extent. Shared so the host reference
 * mirrors the program. */
static __inline enum mv_reason
mv_validate_offsets(const struct mv_offsets *tab)
{
    __u32 loc_off, size_off, force_off, fixed_end;
    __u32 loc_end, size_end, force_end;

    if (tab->magic != MV_OFF_TABLE_MAGIC)
        return MV_CTX_TABLE_BAD;
    if (tab->version != MV_OFF_TABLE_VERSION)
        return MV_CTX_TABLE_BAD;
    loc_off = tab->loc_off;
    size_off = tab->size_off;
    force_off = tab->force_off;
    fixed_end = tab->fixed_end;
    if (loc_off > MV_FIXED_MAX - 4)
        return MV_CTX_TABLE_BAD;
    if (size_off > MV_FIXED_MAX - 8)
        return MV_CTX_TABLE_BAD;
    if (force_off > MV_FIXED_MAX - 1)
        return MV_CTX_TABLE_BAD;
    if (fixed_end > MV_FIXED_MAX)
        return MV_CTX_TABLE_BAD;
    loc_end = loc_off + 4;
    size_end = size_off + 8;
    force_end = force_off + 1;
    /* The common_type anchor pins the trace-entry header
     * at ctx+0: no tabled extent may read header bytes
     * as a consumed field. Each tabled width is
     * positive, so off < 2 is exactly overlap with
     * the @0:2 anchor. */
    if (loc_off < 2)
        return MV_CTX_TABLE_BAD;
    if (size_off < 2)
        return MV_CTX_TABLE_BAD;
    if (force_off < 2)
        return MV_CTX_TABLE_BAD;
    if (loc_off < size_end && size_off < loc_end)
        return MV_CTX_TABLE_BAD;
    if (loc_off < force_end && force_off < loc_end)
        return MV_CTX_TABLE_BAD;
    if (size_off < force_end && force_off < size_end)
        return MV_CTX_TABLE_BAD;
    /* The dynamic floor must cover every tabled
     * extent: dynamic data must never start inside
     * a fixed slot. */
    if (fixed_end < loc_end || fixed_end < size_end ||
        fixed_end < force_end)
        return MV_CTX_TABLE_BAD;
    return MV_OK;
}

/* Decode and strictly validate one product payload. */
static __inline enum mv_reason mv_decode_payload(const __u8 *buf,
                                                 __u32 len,
                                                 struct mv_attempt *out)
{
    __u16 name_len;
    __u32 i;

    if (len < MV_PAYLOAD_LEN)
        return MV_PAY_SHORT;
    if (len > MV_PAYLOAD_LEN)
        return MV_PAY_LONG;
    if (mv_read_le32(buf + MV_OFF_MAGIC) != MV_MAGIC)
        return MV_PAY_MAGIC;
    if (mv_read_le16(buf + MV_OFF_VERSION) != MV_VERSION)
        return MV_PAY_VERSION;
    if (mv_read_le16(buf + MV_OFF_FLAGS) & ~MV_FLAG_FORCE)
        return MV_PAY_FLAGS;
    name_len = mv_read_le16(buf + MV_OFF_NAME_LEN);
    if (name_len > MV_NAME_MAX)
        return MV_PAY_NAMELEN;
    if (buf[MV_OFF_NAME + name_len] != 0)
        return MV_PAY_NUL;
    for (i = 0; i < MV_NAME_MAX; i++) {
        if (i >= name_len)
            break;
        if (buf[MV_OFF_NAME + i] == 0)
            return MV_PAY_NUL;
    }
    for (i = name_len + 1; i <= MV_NAME_MAX; i++) {
        if (buf[MV_OFF_NAME + i] != 0)
            return MV_PAY_PAD;
    }
    out->seq = mv_read_le64(buf + MV_OFF_SEQ);
    out->ktime = mv_read_le64(buf + MV_OFF_KTIME);
    out->size = mv_read_le64(buf + MV_OFF_SIZE);
    out->name_len = name_len;
    out->force =
        (__u8)(mv_read_le16(buf + MV_OFF_FLAGS) & MV_FLAG_FORCE);
    for (i = 0; i <= MV_NAME_MAX; i++) {
        if (i < name_len)
            out->name[i] = buf[MV_OFF_NAME + i];
        else
            out->name[i] = 0;
    }
    return MV_OK;
}

/* Pinned wire offsets: any layout change must update the header,
 * the corpus, and both decoders together. */
_Static_assert(MV_PAYLOAD_LEN == 98, "payload length");
_Static_assert(MV_NAME_MAX == 63, "name cap");
_Static_assert(MV_OFF_MAGIC == 0, "magic offset");
_Static_assert(MV_OFF_VERSION == 4, "version offset");
_Static_assert(MV_OFF_FLAGS == 6, "flags offset");
_Static_assert(MV_OFF_SEQ == 8, "seq offset");
_Static_assert(MV_OFF_KTIME == 16, "ktime offset");
_Static_assert(MV_OFF_SIZE == 24, "size offset");
_Static_assert(MV_OFF_NAME_LEN == 32, "name_len offset");
_Static_assert(MV_OFF_NAME == 34, "name offset");
_Static_assert(MV_OFF_NAME + MV_NAME_MAX + 1 == MV_PAYLOAD_LEN,
              "name field ends the payload");
_Static_assert(MV_CTX_FIXED == 41, "dynamic-data floor");
_Static_assert(MV_CTX_READ_CAP == 512, "context read cap");
_Static_assert(sizeof(struct mv_offsets) == 24, "offset table size");
_Static_assert(MV_OFFSETS_TABLE_LEN == 24, "offset table length");
_Static_assert(MV_FIXED_MAX == 128, "fixed-region cap");
_Static_assert(MV_CNT_LEN == 6, "counter map length");

/* Lifecycle v2 record: exactly 44 bytes, little-endian, packed.
 * kind 1 = fexit swiotlb_tbl_map_single (ok = slots found),
 * kind 2 = fentry __swiotlb_tbl_unmap_single (skip_sync from
 * attrs bit 5). dir is the raw enum dma_data_direction value
 * (0..2); 3+ never emits. gen is the opaque mapping
 * generation (0 = unknown, 1..GEN_MAX assignable). MAP + ok
 * requires GEN_UNASSIGNED exactly when gen is 0 and forbids
 * GEN_MISS; failed maps carry flags 0 and gen 0; UNMAP
 * requires GEN_MISS exactly when gen is 0 and forbids
 * GEN_UNASSIGNED. No addresses, no names. */
#define MV_LC_LEN 44
#define MV_LC_MAGIC 0x434C564Du /* "MVLC" */
#define MV_LC_VERSION 2u
#define MV_LC_KIND_MAP 1u
#define MV_LC_KIND_UNMAP 2u
#define MV_LC_FLAG_OK 0x1u
#define MV_LC_FLAG_SKIP_SYNC 0x2u
#define MV_LC_FLAG_GEN_MISS 0x4u
#define MV_LC_FLAG_GEN_UNASSIGNED 0x8u
#define MV_LC_GEN_MAX 0xFFFFFFFFFFFFFFFEULL

#define MV_LC_OFF_MAGIC 0u
#define MV_LC_OFF_VERSION 4u
#define MV_LC_OFF_KIND 6u
#define MV_LC_OFF_FLAGS 8u
#define MV_LC_OFF_DIR 10u
#define MV_LC_OFF_SEQ 12u
#define MV_LC_OFF_KTIME 20u
#define MV_LC_OFF_SIZE 28u
#define MV_LC_OFF_GEN 36u

/* Copy v1 record: exactly 48 bytes, little-endian, packed.
 * kind 1 = sync request (carries no executed bytes by
 * definition; to_device reads as for_device), kind 2 =
 * executed swiotlb_bounce copy with replicated effective
 * bytes. effective is valid only when KNOWN is set; an
 * unknown record must name its reason, and a known record
 * must carry reason NONE. Sync records always carry reason
 * NOT_COPY; copy_exec dir is 1..2 only. Flag 0x10 marks an
 * offset past the allocation (KNOWN copy, never early-zero);
 * flag 0x20 marks a private-pool copy (KNOWN copy only).
 * Unknown copies name one of SLOT_READ, MASK_READ, BOUNDS,
 * LAYOUT, or SHIFT. */
#define MV_CP_LEN 48
#define MV_CP_MAGIC 0x5043564Du /* "MVCP" */
#define MV_CP_VERSION 1u
#define MV_CP_KIND_SYNC 1u
#define MV_CP_KIND_COPY 2u
#define MV_CP_FLAG_TO_DEVICE 0x1u
#define MV_CP_FLAG_KNOWN 0x2u
#define MV_CP_FLAG_CLAMPED 0x4u
#define MV_CP_FLAG_EARLY_ZERO 0x8u
#define MV_CP_FLAG_OFFSET_PAST_ALLOC 0x10u
#define MV_CP_FLAG_PRIVATE_POOL 0x20u
#define MV_CP_REASON_NONE 0u
#define MV_CP_REASON_SLOT_READ 1u
#define MV_CP_REASON_MASK_READ 2u
#define MV_CP_REASON_BOUNDS 3u
#define MV_CP_REASON_NOT_COPY 4u
#define MV_CP_REASON_LAYOUT 5u
#define MV_CP_REASON_SHIFT 6u

#define MV_CP_OFF_MAGIC 0u
#define MV_CP_OFF_VERSION 4u
#define MV_CP_OFF_KIND 6u
#define MV_CP_OFF_FLAGS 8u
#define MV_CP_OFF_DIR 10u
#define MV_CP_OFF_SEQ 12u
#define MV_CP_OFF_KTIME 20u
#define MV_CP_OFF_REQUESTED 28u
#define MV_CP_OFF_EFFECTIVE 36u
#define MV_CP_OFF_REASON 44u

/* Failure sentinel shared by the map hooks: (phys_addr_t)
 * DMA_MAPPING_ERROR, i.e. all bits set. */
#define MV_INVALID_PHYS 0xFFFFFFFFFFFFFFFFULL

/* Decoded lifecycle/copy fields (host structs, not wire). */
struct mv_lifecycle {
    __u16 kind;
    __u8 ok;
    __u8 skip_sync;
    __u16 dir;
    __u64 seq;
    __u64 ktime;
    __u64 size;
    __u64 gen;
};

struct mv_copy {
    __u16 kind;
    __u8 to_device;
    __u8 known;
    __u8 clamped;
    __u8 early_zero;
    __u8 offset_past;
    __u8 private_pool;
    __u16 dir;
    __u16 reason;
    __u64 seq;
    __u64 ktime;
    __u64 requested;
    __u64 effective;
};

/* Slot width shared by the wire helpers and the BPF
 * adapters: one pool slot covers 1 << 11 bytes. */
#define MV_IO_TLB_SHIFT_WIRE 11u

/* One relocated size read matches its local expectation. */
static __inline int mv_layout_ok(__u32 got, __u32 want)
{
    return got == want;
}

/* Slot index over one pool: the span must be exactly nslabs
 * slots wide, else SHIFT; the address must land inside, else
 * BOUNDS. Pure and loop-free for the verifier. */
static __inline __u16 mv_slot_index(__u64 start, __u64 end,
                                   __u64 nslabs, __u64 tlb_addr,
                                   __u64 *idx)
{
    if (end < start)
        return MV_CP_REASON_SHIFT;
    if (nslabs > 0xFFFFFFFFFFFFFFFFULL >> MV_IO_TLB_SHIFT_WIRE)
        return MV_CP_REASON_SHIFT;
    if (end - start != nslabs << MV_IO_TLB_SHIFT_WIRE)
        return MV_CP_REASON_SHIFT;
    if (tlb_addr < start)
        return MV_CP_REASON_BOUNDS;
    *idx = (tlb_addr - start) >> MV_IO_TLB_SHIFT_WIRE;
    if (*idx >= nslabs)
        return MV_CP_REASON_BOUNDS;
    return MV_CP_REASON_NONE;
}

/* Hook tlb_offset math: both masked terms fit in s32, so
 * the signed difference is exact. */
static __inline __s32 mv_tlb_offset(__u64 tlb_addr, __u64 orig_addr,
                                   __u32 min_align_mask)
{
    return (__s32)(tlb_addr & 2047u) -
           (__s32)(orig_addr & min_align_mask & 2047u);
}

/* Replicated swiotlb_bounce length rule: an invalid slot
 * copies nothing (hook early return); otherwise the room is
 * alloc_size - tlb_offset in u64 arithmetic exactly like the
 * hook's alloc_size -= tlb_offset in size_t, including the
 * wrap when the offset runs past the allocation. A wrapped
 * room above the request copies the full size unchecked and
 * unwarned, and offset_past says so. */
struct mv_effective {
    __u64 effective;
    __u8 clamped;
    __u8 early_zero;
    __u8 offset_past;
};

static __inline struct mv_effective mv_effective_bytes(__u64 size,
                                                       __s64 tlb_offset,
                                                       __u64 alloc_size,
                                                       int orig_valid)
{
    struct mv_effective out;
    __u64 room;

    out.effective = 0;
    out.clamped = 0;
    out.early_zero = 0;
    out.offset_past = 0;
    if (!orig_valid) {
        out.early_zero = 1;
        return out;
    }
    room = alloc_size - (__u64)tlb_offset;
    if (size > room) {
        out.effective = room;
        out.clamped = 1;
    } else {
        out.effective = size;
    }
    if (tlb_offset > 0 && (__u64)tlb_offset > alloc_size)
        out.offset_past = 1;
    return out;
}

/* Decode and strictly validate one lifecycle v2 record.
 * Precedence is header-first: a short buffer that cannot
 * hold magic+version fails SHORT; then magic, version (v1
 * bytes fail here, not on length), length, kind, flags,
 * dir, flag/generation coupling, and generation range. */
static __inline enum mv_reason mv_decode_lifecycle(const __u8 *buf,
                                                  __u32 len,
                                                  struct mv_lifecycle *out)
{
    __u16 kind, flags, dir;
    __u64 gen;

    if (len < MV_LC_OFF_VERSION + 2)
        return MV_PAY_SHORT;
    if (mv_read_le32(buf + MV_LC_OFF_MAGIC) != MV_LC_MAGIC)
        return MV_PAY_MAGIC;
    if (mv_read_le16(buf + MV_LC_OFF_VERSION) != MV_LC_VERSION)
        return MV_PAY_VERSION;
    if (len < MV_LC_LEN)
        return MV_PAY_SHORT;
    if (len > MV_LC_LEN)
        return MV_PAY_LONG;
    kind = mv_read_le16(buf + MV_LC_OFF_KIND);
    if (kind != MV_LC_KIND_MAP && kind != MV_LC_KIND_UNMAP)
        return MV_PAY_KIND;
    flags = mv_read_le16(buf + MV_LC_OFF_FLAGS);
    if (flags & ~(__u16)(MV_LC_FLAG_OK | MV_LC_FLAG_SKIP_SYNC |
                         MV_LC_FLAG_GEN_MISS |
                         MV_LC_FLAG_GEN_UNASSIGNED))
        return MV_PAY_FLAGS;
    dir = mv_read_le16(buf + MV_LC_OFF_DIR);
    if (dir > 2)
        return MV_PAY_DIR;
    gen = mv_read_le64(buf + MV_LC_OFF_GEN);
    if (kind == MV_LC_KIND_MAP) {
        if (flags & ~(__u16)(MV_LC_FLAG_OK |
                             MV_LC_FLAG_GEN_UNASSIGNED))
            return MV_PAY_FLAGS;
        if (flags & MV_LC_FLAG_OK) {
            if (((flags & MV_LC_FLAG_GEN_UNASSIGNED) != 0) !=
                (gen == 0))
                return MV_PAY_FLAGS;
        } else {
            if (flags != 0 || gen != 0)
                return MV_PAY_FLAGS;
        }
    } else {
        if (flags & ~(__u16)(MV_LC_FLAG_OK | MV_LC_FLAG_SKIP_SYNC |
                             MV_LC_FLAG_GEN_MISS))
            return MV_PAY_FLAGS;
        if (((flags & MV_LC_FLAG_GEN_MISS) != 0) != (gen == 0))
            return MV_PAY_FLAGS;
    }
    if (gen != 0 && gen > MV_LC_GEN_MAX)
        return MV_PAY_RANGE;
    out->kind = kind;
    out->ok = (__u8)((flags & MV_LC_FLAG_OK) != 0);
    out->skip_sync = (__u8)((flags & MV_LC_FLAG_SKIP_SYNC) != 0);
    out->dir = dir;
    out->seq = mv_read_le64(buf + MV_LC_OFF_SEQ);
    out->ktime = mv_read_le64(buf + MV_LC_OFF_KTIME);
    out->size = mv_read_le64(buf + MV_LC_OFF_SIZE);
    out->gen = gen;
    return MV_OK;
}

/* Decode and strictly validate one copy record. */
static __inline enum mv_reason mv_decode_copy(const __u8 *buf,
                                              __u32 len,
                                              struct mv_copy *out)
{
    __u16 kind, flags, dir, reason;

    if (len < MV_CP_LEN)
        return MV_PAY_SHORT;
    if (len > MV_CP_LEN)
        return MV_PAY_LONG;
    if (mv_read_le32(buf + MV_CP_OFF_MAGIC) != MV_CP_MAGIC)
        return MV_PAY_MAGIC;
    if (mv_read_le16(buf + MV_CP_OFF_VERSION) != MV_CP_VERSION)
        return MV_PAY_VERSION;
    kind = mv_read_le16(buf + MV_CP_OFF_KIND);
    if (kind != MV_CP_KIND_SYNC && kind != MV_CP_KIND_COPY)
        return MV_PAY_KIND;
    flags = mv_read_le16(buf + MV_CP_OFF_FLAGS);
    if (flags & ~(__u16)(MV_CP_FLAG_TO_DEVICE | MV_CP_FLAG_KNOWN |
                         MV_CP_FLAG_CLAMPED | MV_CP_FLAG_EARLY_ZERO |
                         MV_CP_FLAG_OFFSET_PAST_ALLOC |
                         MV_CP_FLAG_PRIVATE_POOL))
        return MV_PAY_FLAGS;
    if ((flags & MV_CP_FLAG_OFFSET_PAST_ALLOC) &&
        (kind != MV_CP_KIND_COPY || !(flags & MV_CP_FLAG_KNOWN) ||
         (flags & MV_CP_FLAG_EARLY_ZERO)))
        return MV_PAY_FLAGS;
    if ((flags & MV_CP_FLAG_PRIVATE_POOL) &&
        (kind != MV_CP_KIND_COPY || !(flags & MV_CP_FLAG_KNOWN)))
        return MV_PAY_FLAGS;
    dir = mv_read_le16(buf + MV_CP_OFF_DIR);
    if (dir > 2 || (kind == MV_CP_KIND_COPY && dir == 0))
        return MV_PAY_DIR;
    reason = mv_read_le16(buf + MV_CP_OFF_REASON);
    if (reason > MV_CP_REASON_SHIFT)
        return MV_PAY_REASON;
    if (flags & MV_CP_FLAG_KNOWN) {
        if (reason != MV_CP_REASON_NONE)
            return MV_PAY_REASON;
    } else if (kind == MV_CP_KIND_SYNC) {
        if (reason != MV_CP_REASON_NOT_COPY)
            return MV_PAY_REASON;
    } else if (reason == MV_CP_REASON_NONE ||
               reason == MV_CP_REASON_NOT_COPY) {
        return MV_PAY_REASON;
    }
    out->kind = kind;
    out->to_device = (__u8)((flags & MV_CP_FLAG_TO_DEVICE) != 0);
    out->known = (__u8)((flags & MV_CP_FLAG_KNOWN) != 0);
    out->clamped = (__u8)((flags & MV_CP_FLAG_CLAMPED) != 0);
    out->early_zero = (__u8)((flags & MV_CP_FLAG_EARLY_ZERO) != 0);
    out->offset_past =
        (__u8)((flags & MV_CP_FLAG_OFFSET_PAST_ALLOC) != 0);
    out->private_pool =
        (__u8)((flags & MV_CP_FLAG_PRIVATE_POOL) != 0);
    out->dir = dir;
    out->reason = reason;
    out->seq = mv_read_le64(buf + MV_CP_OFF_SEQ);
    out->ktime = mv_read_le64(buf + MV_CP_OFF_KTIME);
    out->requested = mv_read_le64(buf + MV_CP_OFF_REQUESTED);
    out->effective = mv_read_le64(buf + MV_CP_OFF_EFFECTIVE);
    return MV_OK;
}

_Static_assert(MV_LC_LEN == 44, "lifecycle record length");
_Static_assert(MV_LC_MAGIC == 0x434C564D, "lifecycle magic");
_Static_assert(MV_LC_OFF_MAGIC == 0, "lifecycle magic offset");
_Static_assert(MV_LC_OFF_VERSION == 4, "lifecycle version offset");
_Static_assert(MV_LC_OFF_KIND == 6, "lifecycle kind offset");
_Static_assert(MV_LC_OFF_FLAGS == 8, "lifecycle flags offset");
_Static_assert(MV_LC_OFF_DIR == 10, "lifecycle dir offset");
_Static_assert(MV_LC_OFF_SEQ == 12, "lifecycle seq offset");
_Static_assert(MV_LC_OFF_KTIME == 20, "lifecycle ktime offset");
_Static_assert(MV_LC_OFF_SIZE == 28, "lifecycle size offset");
_Static_assert(MV_LC_OFF_GEN == 36, "lifecycle gen offset");
_Static_assert(MV_LC_OFF_GEN + 8 == MV_LC_LEN, "lifecycle ends at gen");
_Static_assert(MV_LC_GEN_MAX == 0xFFFFFFFFFFFFFFFEULL,
              "lifecycle gen max");
_Static_assert(MV_CP_LEN == 48, "copy record length");
_Static_assert(MV_CP_MAGIC == 0x5043564D, "copy magic");
_Static_assert(MV_CP_OFF_MAGIC == 0, "copy magic offset");
_Static_assert(MV_CP_OFF_VERSION == 4, "copy version offset");
_Static_assert(MV_CP_OFF_KIND == 6, "copy kind offset");
_Static_assert(MV_CP_OFF_FLAGS == 8, "copy flags offset");
_Static_assert(MV_CP_OFF_DIR == 10, "copy dir offset");
_Static_assert(MV_CP_OFF_SEQ == 12, "copy seq offset");
_Static_assert(MV_CP_OFF_KTIME == 20, "copy ktime offset");
_Static_assert(MV_CP_OFF_REQUESTED == 28, "copy requested offset");
_Static_assert(MV_CP_OFF_EFFECTIVE == 36, "copy effective offset");
_Static_assert(MV_CP_OFF_REASON == 44, "copy reason offset");
_Static_assert(MV_CP_OFF_REASON + 4 == MV_CP_LEN, "copy ends at pad");
_Static_assert(MV_INVALID_PHYS == 0xFFFFFFFFFFFFFFFFULL,
              "map failure sentinel");

#endif /* MEMVEIL_EVENTS_H */
