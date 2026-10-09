/* SPDX-License-Identifier: GPL-2.0-only */

/* MemVeil swiotlb lifecycle probe.
 *
 * fexit on swiotlb_tbl_map_single (map_result: slots found or
 * not, with the requested size and direction) plus fentry on
 * __swiotlb_tbl_unmap_single (unmap: size, direction, and the
 * skip-sync bit). Emits 36-byte MVLC v1 records on
 * mv_lifecycle. All accounting lives in mv_counts with the
 * same conservation rule as the attempt probe: observed ==
 * emitted + submit_fail while no wrap bit is set.
 *
 * No addresses are read or emitted. An fexit ok=1 means the
 * inner allocator found slots; the outer dma_map_* call may
 * still fail afterwards (outer-failure cleanup then runs a
 * real unmap, which this probe observes as its own event).
 *
 * Build: clang --target=bpf -O2 -g -D__BPF__ -I bpf/include
 *   -I <libbpf-1.7.0>/src -I /usr/include/x86_64-linux-gnu
 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "memveil_events.h"
#include "mv_fentry_types.h"

#ifndef MV_RING_BYTES
#define MV_RING_BYTES 8388608u
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MV_CNT_LEN);
    __type(key, __u32);
    __type(value, __u64);
} mv_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MV_RING_BYTES);
} mv_lifecycle SEC(".maps");

/* Mapping identity: (device, tlb address) -> opaque generation.
 * Keys stay in the kernel; only the generation crosses the
 * ring. 0 is never assigned (unknown); tombstones (value 0)
 * read as misses. */
struct mv_gen_key {
    __u64 dev;
    __u64 tlb;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mv_gen_key);
    __type(value, __u64);
    __uint(max_entries, 32768);
} mv_gen_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} mv_gen_next SEC(".maps");

/* Append-only quarantine: keys whose cleanup failed. Entries
 * are never removed; quarantined keys emit unknown identity
 * until capture end. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mv_gen_key);
    __type(value, __u8);
    __uint(max_entries, 1024);
} mv_gen_quarantine SEC(".maps");

/* Global quarantine: set by direct store (no helper, so the
 * escalation step cannot fail) when even quarantine insert
 * fails. While set, every map diverts and every unmap misses. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} mv_gen_dark SEC(".maps");

#define MV_CAS_RETRIES 8

static __always_inline int mv_dark(void)
{
    __u32 zero = 0;
    __u8 *slot = bpf_map_lookup_elem(&mv_gen_dark, &zero);

    return slot && *slot;
}

static __always_inline int mv_quarantined(const struct mv_gen_key *key)
{
    return bpf_map_lookup_elem(&mv_gen_quarantine, key) != NULL;
}

/* Allocate one generation without wrapping: returns 1 with
 * *gen set, or 0 to divert (terminal, contention, or missing
 * counter). The counter never advances past GEN_MAX, so no
 * value is ever assigned twice. */
static __always_inline int mv_alloc_gen(__u64 *gen)
{
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&mv_gen_next, &zero);
    __u64 v;
    int i;

    if (!counter)
        return 0;
    v = *counter;
    for (i = 0; i < MV_CAS_RETRIES; i++) {
        __u64 old;

        if (v >= MV_LC_GEN_MAX)
            return 0;
        old = __sync_val_compare_and_swap(counter, v, v + 1);
        if (old == v) {
            *gen = v + 1;
            return 1;
        }
        v = old;
    }
    return 0;
}

/* Atomically OR one sticky flag bit. */
static __always_inline void mv_raise(__u64 bit)
{
    __u32 key = MV_CNT_FLAGS;
    __u64 *slot = bpf_map_lookup_elem(&mv_counts, &key);

    if (slot)
        __sync_fetch_and_or(slot, bit);
}

/* Checked submit_fail increment; the wrapped value is never trusted. */
static __always_inline void mv_submit_fail(void)
{
    __u32 key = MV_CNT_SUBMIT_FAIL;
    __u64 *slot = bpf_map_lookup_elem(&mv_counts, &key);
    __u64 old;

    if (!slot)
        return;
    old = __sync_fetch_and_add(slot, 1);
    if (old == 0xFFFFFFFFFFFFFFFFULL)
        mv_raise(MV_FLAG_SUBMIT_WRAP);
}

/* Shared emit path: counts the firing, validates, submits. */
static __always_inline int mv_emit_lc(__u16 kind, __u16 flags, __u64 dir,
                                     __u64 size, __u64 gen)
{
    __u32 key0 = MV_CNT_OBSERVED;
    __u32 key1 = MV_CNT_OBSERVED_BYTES;
    __u32 key2 = MV_CNT_EMITTED;
    __u32 key3 = MV_CNT_EMITTED_BYTES;
    __u32 key5 = MV_CNT_FLAGS;
    __u64 *observed, *observed_bytes, *emitted, *emitted_bytes;
    __u64 *flag_slot;
    __u64 o, b, e, eb;
    __u8 payload[MV_LC_LEN];
    __u32 i;

    observed = bpf_map_lookup_elem(&mv_counts, &key0);
    if (!observed)
        return 0;
    /* Step 1: every firing advances observed first. */
    o = __sync_fetch_and_add(observed, 1);
    if (o == 0xFFFFFFFFFFFFFFFFULL) {
        mv_raise(MV_FLAG_OBSERVED_WRAP);
        mv_submit_fail();
        return 0;
    }
    /* Step 2: an invalid epoch is counted, never emitted. */
    flag_slot = bpf_map_lookup_elem(&mv_counts, &key5);
    if (!flag_slot)
        return 0;
    if (*flag_slot != 0) {
        mv_submit_fail();
        return 0;
    }
    /* Step 3: dir comes from the kernel enum; anything
     * outside 0..2 is rejected, never emitted. */
    if (dir > 2) {
        mv_raise(MV_FLAG_BYTE_COVERAGE);
        mv_submit_fail();
        return 0;
    }
    /* Step 4: the byte aggregate advances before any
     * fallible step (aggregate independence). */
    observed_bytes = bpf_map_lookup_elem(&mv_counts, &key1);
    if (!observed_bytes)
        return 0;
    b = __sync_fetch_and_add(observed_bytes, size);
    if (b > 0xFFFFFFFFFFFFFFFFULL - size) {
        mv_raise(MV_FLAG_OBSERVED_BYTES_WRAP);
        mv_submit_fail();
        return 0;
    }
    /* Step 5: fill the header and submit. */
    __builtin_memset(payload, 0, sizeof(payload));
    payload[0] = (MV_LC_MAGIC & 0xFFu);
    payload[1] = (MV_LC_MAGIC >> 8) & 0xFFu;
    payload[2] = (MV_LC_MAGIC >> 16) & 0xFFu;
    payload[3] = (MV_LC_MAGIC >> 24) & 0xFFu;
    payload[4] = MV_LC_VERSION & 0xFFu;
    payload[5] = (MV_LC_VERSION >> 8) & 0xFFu;
    payload[6] = kind & 0xFFu;
    payload[7] = (kind >> 8) & 0xFFu;
    payload[8] = flags & 0xFFu;
    payload[9] = (flags >> 8) & 0xFFu;
    payload[10] = (__u8)dir;
    payload[11] = 0;
    {
        /* One ktime read: per-byte reads could tear. */
        __u64 ktime = bpf_ktime_get_ns();

        for (i = 0; i < 8; i++) {
            payload[12 + i] = (o >> (8 * i)) & 0xFFu;
            payload[20 + i] = (ktime >> (8 * i)) & 0xFFu;
            payload[28 + i] = (size >> (8 * i)) & 0xFFu;
            payload[36 + i] = (gen >> (8 * i)) & 0xFFu;
        }
    }
    if (bpf_ringbuf_output(&mv_lifecycle, payload, sizeof(payload),
                           0) != 0) {
        mv_submit_fail();
        return 0;
    }
    /* Step 6: once in the ring the event counts as emitted. */
    emitted = bpf_map_lookup_elem(&mv_counts, &key2);
    emitted_bytes = bpf_map_lookup_elem(&mv_counts, &key3);
    if (!emitted || !emitted_bytes)
        return 0;
    e = __sync_fetch_and_add(emitted, 1);
    if (e == 0xFFFFFFFFFFFFFFFFULL)
        mv_raise(MV_FLAG_EMITTED_WRAP);
    eb = __sync_fetch_and_add(emitted_bytes, size);
    if (eb > 0xFFFFFFFFFFFFFFFFULL - size)
        mv_raise(MV_FLAG_EMITTED_BYTES_WRAP);
    return 0;
}

SEC("fexit/swiotlb_tbl_map_single")
int BPF_PROG(mv_map_result, struct device *dev, mv_phys_addr_t orig_addr,
             mv_size_t mapping_size, unsigned int alloc_align_mask,
             enum mv_dma_data_direction dir, unsigned long attrs,
             mv_phys_addr_t ret)
{
    struct mv_gen_key key;
    __u16 flags = 0;
    __u64 gen = 0;
    __u64 assigned = 0;

    (void)ctx;

    (void)orig_addr;
    (void)alloc_align_mask;
    (void)attrs;
    if (ret == MV_INVALID_PHYS)
        return mv_emit_lc(MV_LC_KIND_MAP, 0, (__u64)dir,
                          (mv_size_t)mapping_size, 0);
    key.dev = (__u64)dev;
    key.tlb = (__u64)ret;
    /* Dark or quarantined keys divert without burning a
     * generation; a failed insert diverts too. The emission
     * never claims an identity the table may not hold. */
    if (!mv_dark() && !mv_quarantined(&key) &&
        mv_alloc_gen(&assigned) &&
        bpf_map_update_elem(&mv_gen_table, &key, &assigned,
                            BPF_ANY) == 0) {
        gen = assigned;
        flags |= MV_LC_FLAG_OK;
    } else {
        flags |= MV_LC_FLAG_OK | MV_LC_FLAG_GEN_UNASSIGNED;
    }
    return mv_emit_lc(MV_LC_KIND_MAP, flags, (__u64)dir,
                      (mv_size_t)mapping_size, gen);
}

SEC("fentry/__swiotlb_tbl_unmap_single")
int BPF_PROG(mv_unmap, struct device *dev, mv_phys_addr_t tlb_addr,
             mv_size_t mapping_size, enum mv_dma_data_direction dir,
             unsigned long attrs, struct io_tlb_pool *pool)
{
    struct mv_gen_key key;
    __u16 flags = MV_LC_FLAG_OK;
    __u64 gen = 0;
    __u64 *slot;

    (void)ctx;

    (void)pool;
    /* DMA_ATTR_SKIP_CPU_SYNC is bit 5 (dma-mapping.h). */
    if (attrs & (1UL << 5))
        flags |= MV_LC_FLAG_SKIP_SYNC;
    key.dev = (__u64)dev;
    key.tlb = (__u64)tlb_addr;
    if (!mv_dark() && !mv_quarantined(&key)) {
        slot = bpf_map_lookup_elem(&mv_gen_table, &key);
        if (slot && *slot != 0) {
            gen = *slot;
            if (bpf_map_delete_elem(&mv_gen_table, &key) != 0) {
                /* Delete failed: tombstone, then quarantine,
                 * then global dark. Every tier emits miss so
                 * a stale value can never reach a future
                 * unmap emission. */
                __u64 zero = 0;

                if (bpf_map_update_elem(&mv_gen_table, &key, &zero,
                                        BPF_EXIST) != 0) {
                    __u8 one = 1;

                    if (bpf_map_update_elem(&mv_gen_quarantine, &key,
                                            &one, BPF_ANY) != 0) {
                        __u32 z = 0;
                        __u8 *dark;

                        dark = bpf_map_lookup_elem(&mv_gen_dark, &z);
                        if (dark)
                            *dark = 1;
                    }
                }
                gen = 0;
                flags |= MV_LC_FLAG_GEN_MISS;
            }
        } else {
            flags |= MV_LC_FLAG_GEN_MISS;
        }
    } else {
        flags |= MV_LC_FLAG_GEN_MISS;
    }
    return mv_emit_lc(MV_LC_KIND_UNMAP, flags, (__u64)dir,
                      (mv_size_t)mapping_size, gen);
}

char MV_LICENSE[] SEC("license") = "GPL";
