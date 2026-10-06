/* SPDX-License-Identifier: GPL-2.0-only */

/* MemVeil swiotlb attempt probe.
 *
 * Tracepoint program on swiotlb:swiotlb_bounced (format id 382).
 * Extracts (size, force, device name) from the trace context,
 * packs the 98-byte product payload, and submits it on the
 * mv_attempts ring. All accounting lives in mv_counts; every
 * firing is counted exactly once across observed / emitted /
 * submit_fail (counter conservation: observed == emitted +
 * submit_fail while no wrap bit is set; byte coverage needs
 * the flags word fully clear).
 *
 * dev_addr and dma_mask are never read: no schema consumer.
 *
 * Build: clang --target=bpf -O2 -g -D__BPF__ -I bpf/include
 *   -I <libbpf-1.7.0>/src -I /usr/include/x86_64-linux-gnu
 * The saturation test build overrides -DMV_RING_BYTES=4096;
 * that object is admissible only under the saturation
 * expectation, never under the production profile.
 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#include "memveil_events.h"

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
} mv_attempts SEC(".maps");

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

SEC("tracepoint/swiotlb/swiotlb_bounced")
int mv_swiotlb_attempt(void *ctx)
{
    __u32 key0 = MV_CNT_OBSERVED;
    __u32 key1 = MV_CNT_OBSERVED_BYTES;
    __u32 key2 = MV_CNT_EMITTED;
    __u32 key3 = MV_CNT_EMITTED_BYTES;
    __u32 key5 = MV_CNT_FLAGS;
    __u64 *observed, *observed_bytes, *emitted, *emitted_bytes;
    __u64 *flags;
    __u64 o, b, e, eb, size;
    __u32 loc, off, dlen, i;
    __u8 fix[MV_CTX_FIXED];
    __u8 payload[MV_PAYLOAD_LEN];
    __u8 force;

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
    flags = bpf_map_lookup_elem(&mv_counts, &key5);
    if (!flags)
        return 0;
    if (*flags != 0) {
        mv_submit_fail();
        return 0;
    }
    /* One fixed read covers loc@8, size@32, and force@40. A
     * short context fails here: the firing's size is
     * unknowable, so the byte aggregate loses coverage
     * (sticky bit) on top of the counted reject. */
    if (bpf_probe_read_kernel(fix, sizeof(fix), ctx) != 0) {
        mv_raise(MV_FLAG_BYTE_COVERAGE);
        mv_submit_fail();
        return 0;
    }
    /* Step 3: the byte aggregate advances before any fallible
     * step (aggregate independence). */
    observed_bytes = bpf_map_lookup_elem(&mv_counts, &key1);
    if (!observed_bytes)
        return 0;
    size = mv_read_le64(fix + 32);
    b = __sync_fetch_and_add(observed_bytes, size);
    if (b > 0xFFFFFFFFFFFFFFFFULL - size) {
        mv_raise(MV_FLAG_OBSERVED_BYTES_WRAP);
        mv_submit_fail();
        return 0;
    }
    /* Step 4: validate the __data_loc pair. The kernel
     * record length is unknown here, so the read cap is
     * the extent oracle and probe_read failure covers
     * actual shortness; both reject identically. */
    loc = mv_read_le32(fix + 8);
    off = loc & 0xFFFFu;
    dlen = (loc >> 16) & 0xFFFFu;
    if (mv_validate_loc(off, dlen, MV_CTX_READ_CAP) != MV_OK) {
        mv_submit_fail();
        return 0;
    }
    /* Step 5: read the name straight into the payload name
     * field, then check NUL placement. dlen is in 1..64
     * here, so the loop and the write stay in bounds. */
    __builtin_memset(payload, 0, sizeof(payload));
    if (bpf_probe_read_kernel(payload + MV_OFF_NAME, dlen,
                              (__u8 *)ctx + off) != 0) {
        mv_submit_fail();
        return 0;
    }
    for (i = 0; i < dlen; i++) {
        __u8 byte = payload[MV_OFF_NAME + i];

        if (i + 1 == dlen) {
            if (byte != 0) {
                mv_submit_fail();
                return 0;
            }
        } else if (byte == 0) {
            mv_submit_fail();
            return 0;
        }
    }
    force = fix[40];
    if (force != 0 && force != 1) {
        mv_submit_fail();
        return 0;
    }
    /* Step 6: fill the header and submit. */
    payload[0] = (MV_MAGIC & 0xFFu);
    payload[1] = (MV_MAGIC >> 8) & 0xFFu;
    payload[2] = (MV_MAGIC >> 16) & 0xFFu;
    payload[3] = (MV_MAGIC >> 24) & 0xFFu;
    payload[4] = MV_VERSION & 0xFFu;
    payload[5] = (MV_VERSION >> 8) & 0xFFu;
    payload[6] = force ? MV_FLAG_FORCE : 0;
    payload[7] = 0;
    {
        /* One ktime read: per-byte reads could tear. */
        __u64 ktime = bpf_ktime_get_ns();

        for (i = 0; i < 8; i++) {
            payload[8 + i] = (o >> (8 * i)) & 0xFFu;
            payload[16 + i] = (ktime >> (8 * i)) & 0xFFu;
            payload[24 + i] = (size >> (8 * i)) & 0xFFu;
        }
    }
    payload[32] = (dlen - 1) & 0xFFu;
    payload[33] = ((dlen - 1) >> 8) & 0xFFu;
    if (bpf_ringbuf_output(&mv_attempts, payload, sizeof(payload),
                           0) != 0) {
        mv_submit_fail();
        return 0;
    }
    /* Step 7: once in the ring the event counts as emitted;
     * a wrap here still counts the event and invalidates
     * only the epoch. */
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

char MV_LICENSE[] SEC("license") = "GPL";
