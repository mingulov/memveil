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
 *   CTX_NUL_MISSING, CTX_NUL_EARLY, CTX_FORCE_BAD,
 *   PAY_SHORT, PAY_LONG, PAY_MAGIC, PAY_VERSION, PAY_FLAGS,
 *   PAY_NAMELEN, PAY_NUL, PAY_PAD.
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

/* Counter map indices (mv_counts, ARRAY of 6 u64). */
#define MV_CNT_OBSERVED 0u
#define MV_CNT_OBSERVED_BYTES 1u
#define MV_CNT_EMITTED 2u
#define MV_CNT_EMITTED_BYTES 3u
#define MV_CNT_SUBMIT_FAIL 4u
#define MV_CNT_FLAGS 5u
#define MV_CNT_LEN 6u

/* Flag word bits (sticky; any set bit invalidates the epoch).
 * BYTE_COVERAGE is not a wrap: the fixed 41-byte read failed,
 * so one firing's size is unknowable and the byte aggregate
 * can never cover it. */
#define MV_FLAG_OBSERVED_WRAP (1ULL << 0)
#define MV_FLAG_OBSERVED_BYTES_WRAP (1ULL << 1)
#define MV_FLAG_EMITTED_WRAP (1ULL << 2)
#define MV_FLAG_EMITTED_BYTES_WRAP (1ULL << 3)
#define MV_FLAG_SUBMIT_WRAP (1ULL << 4)
#define MV_FLAG_BYTE_COVERAGE (1ULL << 5)

enum mv_reason {
    MV_OK = 0,
    MV_CTX_SHORT,
    MV_CTX_LOC_OOB,
    MV_CTX_DLEN_ZERO,
    MV_CTX_DLEN_BIG,
    MV_CTX_NUL_MISSING,
    MV_CTX_NUL_EARLY,
    MV_CTX_FORCE_BAD,
    MV_PAY_SHORT,
    MV_PAY_LONG,
    MV_PAY_MAGIC,
    MV_PAY_VERSION,
    MV_PAY_FLAGS,
    MV_PAY_NAMELEN,
    MV_PAY_NUL,
    MV_PAY_PAD
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

/* Validate a __data_loc pair against the fixed floor, the name cap,
 * the read cap, and the available context length. Check order is
 * part of the contract: length faults precede extent faults. */
static __inline enum mv_reason mv_validate_loc(__u32 off, __u32 dlen,
                                               __u32 ctx_len)
{
    if (dlen == 0)
        return MV_CTX_DLEN_ZERO;
    if (dlen > MV_NAME_MAX + 1)
        return MV_CTX_DLEN_BIG;
    if (off < MV_CTX_FIXED)
        return MV_CTX_LOC_OOB;
    if (off + dlen > MV_CTX_READ_CAP)
        return MV_CTX_LOC_OOB;
    if (off + dlen > ctx_len)
        return MV_CTX_LOC_OOB;
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
_Static_assert(MV_CNT_LEN == 6, "counter map length");

#endif /* MEMVEIL_EVENTS_H */
