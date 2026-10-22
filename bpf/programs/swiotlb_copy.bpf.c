/* SPDX-License-Identifier: GPL-2.0-only */

/* MemVeil swiotlb copy probe.
 *
 * fentry on __swiotlb_sync_single_for_device,
 * __swiotlb_sync_single_for_cpu (sync requests: direction and
 * length, never executed bytes), plus fentry and fexit on
 * swiotlb_bounce (executed copies with replicated effective
 * bytes). Emits 48-byte MVCP v1 records on mv_copies. Byte
 * aggregates cover REQUESTED bytes (observed and emitted in
 * parallel); effective bytes live in the events, summed by
 * consumers only over KNOWN records.
 *
 * Effective-byte replication reads the pool slot the hook
 * itself reads (start/end/nslabs/slots, then orig_addr and
 * alloc_size) plus dev->dma_parms->min_align_mask, and
 * applies the hook's clamp rule from memveil_events.h. Every
 * relocated width is guarded against its local view, and the
 * pool span must be exactly nslabs slots wide. Any failed
 * read or guard degrades that event to unknown-with-reason;
 * the request fact (size, direction) is still emitted.
 *
 * Each copy is recorded once: entry claims its frame,
 * armed exit records unclaimed calls. Loss stays exact:
 * misses(mv_bounce) + deferred - recovered.
 *
 * Build: clang --target=bpf -O2 -g -D__BPF__ -nostdinc -isystem <clang-resource>/include
 *   -I bpf/include -I <libbpf-1.7.0>/src -I bpf/include/uapi
 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "memveil_events.h"
#include "mv_fentry_types.h"

/* 32 MiB holds the measured dd burst (196,608 records, ~11 MiB). */
#ifndef MV_RING_BYTES
#define MV_RING_BYTES 33554432u
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MV_CNT_LEN);
    __type(key, __u32);
    __type(value, __u64);
} mv_counts SEC(".maps");

/* Claim table: 4096 slots, 8 linear probes per frame. */
#define MV_CLAIM_SLOTS 4096u
#define MV_CLAIM_PROBES 8u

struct mv_claim {
    __u64 frame;
    __u64 id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MV_CLAIM_SLOTS);
    __type(key, __u32);
    __type(value, struct mv_claim);
} mv_claims SEC(".maps");

/* Fallback counters: deferred, recovered, flags, armed. */
#define MV_CP_FB_DEFERRED 0u
#define MV_CP_FB_RECOVERED 1u
#define MV_CP_FB_FLAGS 2u
#define MV_CP_FB_ARMED 3u
#define MV_CP_FB_LEN 4u
#define MV_CP_FB_FLAG_DEFERRED_WRAP (1ULL << 0)
#define MV_CP_FB_FLAG_RECOVERED_WRAP (1ULL << 1)
#define MV_CP_FB_FLAG_FRAME_LOST (1ULL << 2)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MV_CP_FB_LEN);
    __type(key, __u32);
    __type(value, __u64);
} mv_copy_fb SEC(".maps");

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

/* Sticky fallback flag bit. */
static __always_inline void mv_fb_raise(__u64 bit)
{
    __u32 key = MV_CP_FB_FLAGS;
    __u64 *slot = bpf_map_lookup_elem(&mv_copy_fb, &key);

    if (slot)
        __sync_fetch_and_or(slot, bit);
}

/* Deferred count; the wrapped value is never trusted. */
static __always_inline void mv_fb_deferred(void)
{
    __u32 key = MV_CP_FB_DEFERRED;
    __u64 *slot = bpf_map_lookup_elem(&mv_copy_fb, &key);

    if (!slot)
        return;
    if (__sync_fetch_and_add(slot, 1) == 0xFFFFFFFFFFFFFFFFULL)
        mv_fb_raise(MV_CP_FB_FLAG_DEFERRED_WRAP);
}

/* Recovered count; the wrapped value is never trusted. */
static __always_inline void mv_fb_recovered(void)
{
    __u32 key = MV_CP_FB_RECOVERED;
    __u64 *slot = bpf_map_lookup_elem(&mv_copy_fb, &key);

    if (!slot)
        return;
    if (__sync_fetch_and_add(slot, 1) == 0xFFFFFFFFFFFFFFFFULL)
        mv_fb_raise(MV_CP_FB_FLAG_RECOVERED_WRAP);
}

/* Armed only while userspace holds the gate at exactly 1. */
static __always_inline int mv_armed(void)
{
    __u32 key = MV_CP_FB_ARMED;
    __u64 *slot = bpf_map_lookup_elem(&mv_copy_fb, &key);

    if (!slot)
        return 0;
    return *slot == 1;
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
    /* Step 3: dir is the resolved wire encoding; anything
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
int BPF_PROG(mv_sync_device, struct device___mv *dev,
             mv_phys_addr_t tlb_addr, mv_size_t size,
             enum dma_data_direction___mv dir,
             struct io_tlb_pool___mv *pool)
{
    __u16 wdir = 3;

    if (bpf_get_func_arg_cnt(ctx) != MV_ARGS_SYNC) {
        mv_raise(MV_FLAG_ARGCNT);
        return 0;
    }
    (void)dev;
    (void)tlb_addr;
    (void)pool;
    /* A sync request is not a copy: KNOWN stays clear and
     * the reason says so explicitly. */
    mv_wire_dir(dir, &wdir);
    return mv_emit_cp(MV_CP_KIND_SYNC, MV_CP_FLAG_TO_DEVICE,
                      wdir, size, 0, MV_CP_REASON_NOT_COPY);
}

SEC("fentry/__swiotlb_sync_single_for_cpu")
int BPF_PROG(mv_sync_cpu, struct device___mv *dev, mv_phys_addr_t tlb_addr,
             mv_size_t size, enum dma_data_direction___mv dir,
             struct io_tlb_pool___mv *pool)
{
    __u16 wdir = 3;

    if (bpf_get_func_arg_cnt(ctx) != MV_ARGS_SYNC) {
        mv_raise(MV_FLAG_ARGCNT);
        return 0;
    }
    (void)dev;
    (void)tlb_addr;
    (void)pool;
    mv_wire_dir(dir, &wdir);
    return mv_emit_cp(MV_CP_KIND_SYNC, 0, wdir, size, 0,
                      MV_CP_REASON_NOT_COPY);
}

/* Records one executed copy (shared by the fentry and fexit paths). */
static __always_inline int mv_emit_bounce(struct device___mv *dev,
                                          mv_phys_addr_t tlb_addr,
                                          mv_size_t size,
                                          enum dma_data_direction___mv dir,
                                          struct io_tlb_pool___mv *pool)
{
    struct device_dma_parameters___mv *parms;
    struct io_tlb_slot___mv *slots;
    struct io_tlb_mem___mv *mem = 0;
    struct mv_effective eff;
    unsigned int mask = 0;
    bool shared = false;
    __u64 start, end, nsl, idx, orig_addr, alloc_size;
    __u64 effective = 0;
    __u16 wdir = 3;
    __u16 flags, reason = MV_CP_REASON_NONE;
    __s32 off;

    /* The kernel direction resolves to the wire encoding; an
     * unmapped value rides the malformed path below. */
    mv_wire_dir(dir, &wdir);
    flags = wdir == 1 ? MV_CP_FLAG_TO_DEVICE : 0;
    /* Every relocated width must match its local spelling,
     * else the reads below would misinterpret memory. */
    if (!mv_layout_ok(bpf_core_field_size(pool->start), 8) ||
        !mv_layout_ok(bpf_core_field_size(pool->end), 8) ||
        !mv_layout_ok(bpf_core_field_size(pool->nslabs), 8) ||
        !mv_layout_ok(bpf_core_field_size(pool->slots), 8) ||
        !mv_layout_ok(bpf_core_field_size(
                           ((struct io_tlb_slot___mv *)0)->orig_addr),
                      8) ||
        !mv_layout_ok(bpf_core_field_size(
                           ((struct io_tlb_slot___mv *)0)->alloc_size),
                      8) ||
        !mv_layout_ok(bpf_core_field_size(dev->dma_parms), 8) ||
        !mv_layout_ok(bpf_core_field_size(
                           ((struct device_dma_parameters___mv *)0)
                               ->min_align_mask),
                      4)) {
        reason = MV_CP_REASON_LAYOUT;
    } else if (bpf_core_read(&start, sizeof(start),
                             &pool->start) ||
               bpf_core_read(&end, sizeof(end), &pool->end) ||
               bpf_core_read(&nsl, sizeof(nsl), &pool->nslabs) ||
               bpf_core_read(&slots, sizeof(slots),
                             &pool->slots)) {
        reason = MV_CP_REASON_SLOT_READ;
    } else if (slots == (struct io_tlb_slot___mv *)0 || nsl == 0) {
        reason = MV_CP_REASON_SLOT_READ;
    } else {
        reason = mv_slot_index(start, end, nsl, tlb_addr, &idx);
        if (reason == MV_CP_REASON_NONE) {
            /* The stride is relocated, never a literal. */
            __u64 slot_addr = (__u64)slots +
                              idx * bpf_core_type_size(
                                        struct io_tlb_slot___mv);

            if (bpf_core_read(
                    &orig_addr, sizeof(orig_addr),
                    &((struct io_tlb_slot___mv *)slot_addr)->orig_addr) ||
                bpf_core_read(
                    &alloc_size, sizeof(alloc_size),
                    &((struct io_tlb_slot___mv *)slot_addr)->alloc_size))
                reason = MV_CP_REASON_SLOT_READ;
            else if (bpf_core_read(&parms, sizeof(parms),
                                   &dev->dma_parms))
                reason = MV_CP_REASON_MASK_READ;
            else if (parms &&
                     bpf_core_read(&mask, sizeof(mask),
                                   &parms->min_align_mask))
                reason = MV_CP_REASON_MASK_READ;
            else {
                off = mv_tlb_offset(tlb_addr, orig_addr, mask);
                eff = mv_effective_bytes(size, off, alloc_size,
                                         orig_addr !=
                                             MV_INVALID_PHYS);
                flags |= MV_CP_FLAG_KNOWN |
                         (eff.clamped ? MV_CP_FLAG_CLAMPED : 0) |
                         (eff.early_zero ? MV_CP_FLAG_EARLY_ZERO : 0) |
                         (eff.offset_past
                              ? MV_CP_FLAG_OFFSET_PAST_ALLOC
                              : 0);
                effective = eff.effective;
                /* Privacy is a marker, never a verdict: the
                 * toggle reads false on a private pool, and
                 * anything unprovable leaves the flag clear. */
                if (bpf_core_field_exists(dev->dma_io_tlb_mem) &&
                    bpf_core_field_exists(
                        ((struct io_tlb_mem___mv *)0)->cc_shared) &&
                    bpf_core_field_size(
                        ((struct io_tlb_mem___mv *)0)->cc_shared) == 1 &&
                    bpf_core_read(&mem, sizeof(mem),
                                  &dev->dma_io_tlb_mem) == 0 &&
                    mem != 0 &&
                    bpf_core_read(&shared, sizeof(shared),
                                  &mem->cc_shared) == 0 &&
                    !shared)
                    flags |= MV_CP_FLAG_PRIVATE_POOL;
            }
        }
    }
    return mv_emit_cp(MV_CP_KIND_COPY, flags, wdir, size,
                      effective, reason);
}

/* Counts a firing whose copy neither path can record. */
static __always_inline void mv_lost(void)
{
    __u32 key = MV_CNT_OBSERVED;
    __u64 *observed = bpf_map_lookup_elem(&mv_counts, &key);

    if (!observed)
        return;
    if (__sync_fetch_and_add(observed, 1) == 0xFFFFFFFFFFFFFFFFULL)
        mv_raise(MV_FLAG_OBSERVED_WRAP);
    mv_submit_fail();
}

/* Trampoline frame address as a scalar (the verifier forbids hashing ctx). */
static __always_inline __u64 mv_frame(void *ctx)
{
    void *p = ctx;
    __u64 v = 0;

    if (bpf_probe_read_kernel(&v, sizeof(v), &p))
        return 0;
    return v;
}

/* Call id: arguments distinguish successive calls in one frame. */
static __always_inline __u64 mv_call_id(mv_phys_addr_t tlb_addr,
                                        mv_size_t size, __u64 dir)
{
    return tlb_addr ^ (size * 0x9E3779B97F4A7C15ULL) ^ dir;
}

static __always_inline __u32 mv_claim_index(__u64 frame, __u32 i)
{
    return ((__u32)(frame >> 4) ^ (__u32)(frame >> 16)) + i;
}

/* Claims frame's slot for id; 0 when every probed slot is busy. */
static __always_inline int mv_claim(__u64 frame, __u64 id)
{
    struct mv_claim *s;
    __u32 i, k;

    /* A slot holding this frame is stale: live frames are unique. */
    for (i = 0; i < MV_CLAIM_PROBES; i++) {
        k = mv_claim_index(frame, i) & (MV_CLAIM_SLOTS - 1);
        s = bpf_map_lookup_elem(&mv_claims, &k);
        if (!s)
            return 0;
        if (s->frame == frame) {
            s->id = id;
            return 1;
        }
    }
    for (i = 0; i < MV_CLAIM_PROBES; i++) {
        k = mv_claim_index(frame, i) & (MV_CLAIM_SLOTS - 1);
        s = bpf_map_lookup_elem(&mv_claims, &k);
        if (!s)
            return 0;
        if (s->frame == 0 &&
            __sync_val_compare_and_swap(&s->frame, 0, frame) == 0) {
            s->id = id;
            return 1;
        }
    }
    return 0;
}

/* Releases frame's slot; 1 when it held id (mv_bounce recorded this call). */
static __always_inline int mv_release(__u64 frame, __u64 id)
{
    struct mv_claim *s;
    __u32 i, k;
    int mine;

    for (i = 0; i < MV_CLAIM_PROBES; i++) {
        k = mv_claim_index(frame, i) & (MV_CLAIM_SLOTS - 1);
        s = bpf_map_lookup_elem(&mv_claims, &k);
        /* Unreadable table: never record twice. */
        if (!s)
            return 1;
        if (s->frame == frame) {
            mine = s->id == id;
            s->frame = 0;
            return mine;
        }
    }
    return 0;
}

SEC("fentry/swiotlb_bounce")
int BPF_PROG(mv_bounce, struct device___mv *dev, mv_phys_addr_t tlb_addr,
             mv_size_t size, enum dma_data_direction___mv dir,
             struct io_tlb_pool___mv *pool)
{
    __u64 frame;

    if (bpf_get_func_arg_cnt(ctx) != MV_ARGS_BOUNCE) {
        mv_raise(MV_FLAG_ARGCNT);
        return 0;
    }
    frame = mv_frame(ctx);
    /* No frame: count the loss; a live exit may still record it unmatched. */
    if (!frame) {
        mv_fb_raise(MV_CP_FB_FLAG_FRAME_LOST);
        mv_lost();
        return 0;
    }
    /* Table full: count the deferral for mv_bounce_exit. */
    if (!mv_claim(frame, mv_call_id(tlb_addr, size, dir))) {
        mv_fb_deferred();
        return 0;
    }
    return mv_emit_bounce(dev, tlb_addr, size, dir, pool);
}

/* Records the copy when mv_bounce skipped this call or found no free slot. */
SEC("fexit/swiotlb_bounce")
int BPF_PROG(mv_bounce_exit, struct device___mv *dev,
             mv_phys_addr_t tlb_addr, mv_size_t size,
             enum dma_data_direction___mv dir,
             struct io_tlb_pool___mv *pool)
{
    __u64 frame;

    if (bpf_get_func_arg_cnt(ctx) != MV_ARGS_BOUNCE) {
        mv_raise(MV_FLAG_ARGCNT);
        return 0;
    }
    /* Disarmed exit stays out: its recoveries would match no entry miss. */
    if (!mv_armed())
        return 0;
    frame = mv_frame(ctx);

    /* No frame: mv_bounce counted the loss, so never record twice. */
    if (!frame)
        return 0;
    if (mv_release(frame, mv_call_id(tlb_addr, size, dir)))
        return 0;
    mv_fb_recovered();
    return mv_emit_bounce(dev, tlb_addr, size, dir, pool);
}

char MV_LICENSE[] SEC("license") = "GPL";
