/* SPDX-License-Identifier: GPL-2.0-only */

/* MemVeil swiotlb copy probe.
 *
 * fentry on __swiotlb_sync_single_for_device,
 * __swiotlb_sync_single_for_cpu (sync requests: direction and
 * length, never executed bytes), plus fentry on
 * swiotlb_bounce (executed copies with replicated effective
 * bytes). Emits 48-byte MVCP v1 records on mv_copies. Byte
 * aggregates cover REQUESTED bytes (observed and emitted in
 * parallel); effective bytes live in the events, summed by
 * consumers only over KNOWN records.
 *
 * Effective-byte replication reads the pool slot the hook
 * itself reads (start/slots/nslabs, then orig_addr and
 * alloc_size) plus dev->dma_parms->min_align_mask, and
 * applies the hook's clamp rule from memveil_events.h. Any
 * failed read degrades that event to unknown-with-reason;
 * the request fact (size, direction) is still emitted.
 *
 * Build: clang --target=bpf -O2 -g -D__BPF__ -I bpf/include
 *   -I <libbpf-1.7.0>/src -I /usr/include/x86_64-linux-gnu
 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_core_read.h>
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
} mv_copies SEC(".maps");

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
static __always_inline int mv_emit_cp(__u16 kind, __u16 base_flags,
                                     __u64 dir, __u64 requested,
                                     __u64 effective, __u16 reason)
{
    __u32 key0 = MV_CNT_OBSERVED;
    __u32 key1 = MV_CNT_OBSERVED_BYTES;
    __u32 key2 = MV_CNT_EMITTED;
    __u32 key3 = MV_CNT_EMITTED_BYTES;
    __u32 key5 = MV_CNT_FLAGS;
    __u64 *observed, *observed_bytes, *emitted, *emitted_bytes;
    __u64 *flag_slot;
    __u64 o, b, e, eb;
    __u8 payload[MV_CP_LEN];
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
     * outside 0..2 is rejected, never emitted, and a
     * copy_exec with dir 0 (bidirectional) is impossible. */
    if (dir > 2 || (kind == MV_CP_KIND_COPY && dir == 0)) {
        mv_raise(MV_FLAG_BYTE_COVERAGE);
        mv_submit_fail();
        return 0;
    }
    /* Step 4: the byte aggregate advances before any
     * fallible step (aggregate independence). Requested
     * bytes keep observed/emitted parallel. */
    observed_bytes = bpf_map_lookup_elem(&mv_counts, &key1);
    if (!observed_bytes)
        return 0;
    b = __sync_fetch_and_add(observed_bytes, requested);
    if (b > 0xFFFFFFFFFFFFFFFFULL - requested) {
        mv_raise(MV_FLAG_OBSERVED_BYTES_WRAP);
        mv_submit_fail();
        return 0;
    }
    /* Step 5: fill the header and submit. */
    __builtin_memset(payload, 0, sizeof(payload));
    payload[0] = (MV_CP_MAGIC & 0xFFu);
    payload[1] = (MV_CP_MAGIC >> 8) & 0xFFu;
    payload[2] = (MV_CP_MAGIC >> 16) & 0xFFu;
    payload[3] = (MV_CP_MAGIC >> 24) & 0xFFu;
    payload[4] = MV_CP_VERSION & 0xFFu;
    payload[5] = (MV_CP_VERSION >> 8) & 0xFFu;
    payload[6] = kind & 0xFFu;
    payload[7] = (kind >> 8) & 0xFFu;
    payload[8] = base_flags & 0xFFu;
    payload[9] = (base_flags >> 8) & 0xFFu;
    payload[10] = (__u8)dir;
    payload[11] = 0;
    {
        /* One ktime read: per-byte reads could tear. */
        __u64 ktime = bpf_ktime_get_ns();

        for (i = 0; i < 8; i++) {
            payload[12 + i] = (o >> (8 * i)) & 0xFFu;
            payload[20 + i] = (ktime >> (8 * i)) & 0xFFu;
            payload[28 + i] = (requested >> (8 * i)) & 0xFFu;
            payload[36 + i] = (effective >> (8 * i)) & 0xFFu;
        }
    }
    payload[44] = reason & 0xFFu;
    payload[45] = (reason >> 8) & 0xFFu;
    if (bpf_ringbuf_output(&mv_copies, payload, sizeof(payload),
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
    eb = __sync_fetch_and_add(emitted_bytes, requested);
    if (eb > 0xFFFFFFFFFFFFFFFFULL - requested)
        mv_raise(MV_FLAG_EMITTED_BYTES_WRAP);
    return 0;
}

SEC("fentry/__swiotlb_sync_single_for_device")
int BPF_PROG(mv_sync_device, struct device *dev, mv_phys_addr_t tlb_addr,
             mv_size_t size, enum mv_dma_data_direction dir,
             struct io_tlb_pool *pool)
{
    (void)ctx;
    (void)dev;
    (void)tlb_addr;
    (void)pool;
    /* A sync request is not a copy: KNOWN stays clear and
     * the reason says so explicitly. */
    return mv_emit_cp(MV_CP_KIND_SYNC, MV_CP_FLAG_TO_DEVICE,
                      (__u64)dir, size, 0, MV_CP_REASON_NOT_COPY);
}

SEC("fentry/__swiotlb_sync_single_for_cpu")
int BPF_PROG(mv_sync_cpu, struct device *dev, mv_phys_addr_t tlb_addr,
             mv_size_t size, enum mv_dma_data_direction dir,
             struct io_tlb_pool *pool)
{
    (void)ctx;
    (void)dev;
    (void)tlb_addr;
    (void)pool;
    return mv_emit_cp(MV_CP_KIND_SYNC, 0, (__u64)dir, size, 0,
                      MV_CP_REASON_NOT_COPY);
}

SEC("fentry/swiotlb_bounce")
int BPF_PROG(mv_bounce, struct device *dev, mv_phys_addr_t tlb_addr,
             mv_size_t size, enum mv_dma_data_direction dir,
             struct io_tlb_pool *pool)
{
    struct device_dma_parameters *parms;
    struct io_tlb_slot *slots, slot;
    struct mv_effective eff;
    unsigned int mask = 0;
    __u64 start, nsl, idx, dir64 = dir;
    __u64 effective = 0;
    __u16 flags, reason = MV_CP_REASON_NONE;
    __s64 off;

    (void)ctx;
    /* The shared emit path rejects dir outside 1..2 for a
     * copy, mirroring the decoder's per-kind rule. */
    flags = dir64 == MV_DMA_TO_DEVICE ? MV_CP_FLAG_TO_DEVICE : 0;
    /* Checked pool header reads: any failure degrades to
     * unknown-with-reason; start/nslabs/slots are trusted
     * only inside the else branch. */
    if (bpf_core_read(&start, sizeof(start), &pool->start) ||
        bpf_core_read(&nsl, sizeof(nsl), &pool->nslabs) ||
        bpf_core_read(&slots, sizeof(slots), &pool->slots)) {
        reason = MV_CP_REASON_SLOT_READ;
    } else if (slots == (struct io_tlb_slot *)0 || nsl == 0) {
        reason = MV_CP_REASON_SLOT_READ;
    } else {
        /* idx is only used on paths where start is trusted. */
        idx = (tlb_addr - start) >> MV_IO_TLB_SHIFT;
        if (tlb_addr < start || idx >= nsl)
            reason = MV_CP_REASON_BOUNDS;
        else if (bpf_probe_read_kernel(&slot, sizeof(slot), slots + idx))
            reason = MV_CP_REASON_SLOT_READ;
        else if (bpf_core_read(&parms, sizeof(parms), &dev->dma_parms))
            reason = MV_CP_REASON_MASK_READ;
        else if (parms &&
                 bpf_core_read(&mask, sizeof(mask),
                               &parms->min_align_mask))
            reason = MV_CP_REASON_MASK_READ;
        else {
            /* The hook's tlb_offset math, verbatim signs: both
             * terms are small, so the signed difference is exact. */
            off = (__s64)(tlb_addr & MV_IO_TLB_MASK) -
                  (__s64)(slot.orig_addr & mask & MV_IO_TLB_MASK);
            eff = mv_effective_bytes(size, off, slot.alloc_size,
                                     slot.orig_addr != MV_INVALID_PHYS);
            flags |= MV_CP_FLAG_KNOWN |
                     (eff.clamped ? MV_CP_FLAG_CLAMPED : 0) |
                     (eff.early_zero ? MV_CP_FLAG_EARLY_ZERO : 0);
            effective = eff.effective;
        }
    }
    return mv_emit_cp(MV_CP_KIND_COPY, flags, dir64, size,
                      effective, reason);
}

char MV_LICENSE[] SEC("license") = "GPL";
