/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MV_JOURNAL_HOST_TEST
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#endif
#include "memveil_journal_control.h"

#ifndef MV_JOURNAL_HOST_TEST
struct task_struct { __u64 start_boottime; } __attribute__((preserve_access_index));
#define MV_JR_CONTEXT ctx
#else
struct task_struct { __u64 start_boottime; };
#define MV_JR_CONTEXT ((void *)0)
#endif

struct mv_jr_task { __u64 depth, poisoned; };
struct mv_jr_operation { __u64 token, entry_ns; __s32 pages; __u32 direction; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, MV_JR_OPERATION_CAPACITY);
    __type(key, struct mv_journal_key); __type(value, struct mv_jr_task);
} mv_jr_tasks SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, MV_JR_OPERATION_CAPACITY);
    __type(key, struct mv_journal_key); __type(value, struct mv_jr_operation);
} mv_jr_ops SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct mv_jr_control);
} mv_jr_control SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, MV_JR_COUNT_KEYS);
    __type(key, __u32); __type(value, __u64);
} mv_jr_counts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u64);
} mv_jr_sequence SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 10);
    __type(key, __u32); __type(value, struct mv_jr_symbol);
} mv_jr_symbols SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, MV_JR_RING_BYTES);
} mv_journal SEC(".maps");

static __always_inline void mv_jr_overflow(__u32 index)
{
    __u32 k = MV_JR_OVERFLOW;
    __u64 *bits = bpf_map_lookup_elem(&mv_jr_counts, &k);
    if (bits) __sync_fetch_and_or(bits, 1ULL << index);
}

static __always_inline int mv_jr_increment(__u32 index, __u64 ceiling, __u64 *value)
{
    __u64 *v = bpf_map_lookup_elem(&mv_jr_counts, &index);
    if (!v) return 0;
    __u64 old = *v;
    for (int i = 0; i < 16; i++) {
        if (old >= ceiling) return 0;
        __u64 seen = __sync_val_compare_and_swap(v, old, old + 1);
        if (seen == old) { *value = old + 1; return 1; }
        old = seen;
    }
    return 0;
}

static __always_inline void mv_jr_count(__u32 index)
{
    __u64 ignored;
    if (!mv_jr_increment(index, ~0ULL, &ignored)) mv_jr_overflow(index);
}

static __always_inline void mv_jr_release(void)
{
    __u32 key = MV_JR_ACTIVE;
    __u64 *v = bpf_map_lookup_elem(&mv_jr_counts, &key);
    if (v) __sync_fetch_and_sub(v, 1);
}

static __always_inline int mv_jr_key(struct mv_journal_key *key, __u64 epoch)
{
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task || BPF_CORE_READ_INTO(&key->start_boottime, task, start_boottime)) {
        mv_jr_count(MV_JR_IDENTITY_FAILURE);
        return 0;
    }
    key->current_task_pointer = (__u64)task;
    key->epoch = epoch;
    return 1;
}

/* A failed identity read may have hidden a nested callback. Pairing stays
 * unavailable for this object lifetime, including previously retained entries. */
static __always_inline int mv_jr_identity_healthy(void)
{
    __u32 index = MV_JR_IDENTITY_FAILURE;
    __u64 *failures = bpf_map_lookup_elem(&mv_jr_counts, &index);
    return failures && !*failures;
}

static __always_inline void mv_jr_poison(struct mv_journal_key *key, struct mv_jr_task *task)
{
    task->poisoned = 1;
    mv_jr_count(MV_JR_POISONED);
    for (__u32 depth = 1; depth <= MV_JR_NESTING_CAPACITY; depth++) {
        key->depth = depth;
        if (bpf_map_lookup_elem(&mv_jr_ops, key)) {
            if (!bpf_map_delete_elem(&mv_jr_ops, key)) {
                mv_jr_release(); mv_jr_count(MV_JR_CENSORED);
            }
        }
    }
    key->depth = 0;
}

static __always_inline int mv_jr_enter(__u32 direction, __s32 pages)
{
    __u32 zero = 0;
    struct mv_jr_control *control = bpf_map_lookup_elem(&mv_jr_control, &zero);
    if (!control || !control->epoch || !control->observe) return 0;
    __u64 now = bpf_ktime_get_ns();
    int eligible = control->open && now >= control->start_ns;
    if (eligible) mv_jr_count(MV_JR_ENTRIES);
    struct mv_journal_key key = {};
    if (!mv_jr_key(&key, control->epoch) || !mv_jr_identity_healthy()) return 0;
    struct mv_jr_task *task = bpf_map_lookup_elem(&mv_jr_tasks, &key);
    if (!task) {
        struct mv_jr_task empty = {};
        if (bpf_map_update_elem(&mv_jr_tasks, &key, &empty, BPF_NOEXIST)) {
            mv_jr_count(MV_JR_OPERATION_EXHAUSTION); return 0;
        }
        task = bpf_map_lookup_elem(&mv_jr_tasks, &key);
        if (!task) { mv_jr_count(MV_JR_OPERATION_EXHAUSTION); return 0; }
    }
    if (task->depth == ~0ULL) { mv_jr_poison(&key, task); mv_jr_overflow(MV_JR_NESTING_EXHAUSTION); return 0; }
    task->depth++;
    if (task->depth > MV_JR_NESTING_CAPACITY) {
        mv_jr_count(MV_JR_NESTING_EXHAUSTION); mv_jr_poison(&key, task); return 0;
    }
    if (task->poisoned || !eligible) return 0;
    __u64 unused, token;
    if (!mv_jr_increment(MV_JR_ACTIVE, MV_JR_OPERATION_CAPACITY, &unused)) {
        mv_jr_count(MV_JR_OPERATION_EXHAUSTION); mv_jr_poison(&key, task); return 0;
    }
    if (!mv_jr_increment(MV_JR_NEXT_TOKEN, MV_JR_TOKEN_MAX, &token)) {
        mv_jr_release(); control->open = 0; mv_jr_count(MV_JR_TOKEN_EXHAUSTION);
        mv_jr_poison(&key, task); return 0;
    }
    key.depth = (__u32)task->depth;
    struct mv_jr_operation operation = { token, now, pages, direction };
    if (bpf_map_update_elem(&mv_jr_ops, &key, &operation, BPF_NOEXIST)) {
        mv_jr_release(); mv_jr_count(MV_JR_OPERATION_EXHAUSTION); mv_jr_poison(&key, task);
    }
    return 0;
}

static __always_inline void mv_jr_callers(void *ctx, __u16 *status, __u16 *cls, __u16 *label)
{
    __u64 frames[MV_JR_CALLER_FRAME_CAPACITY] = {};
    long size = bpf_get_stack(ctx, frames, sizeof(frames), 0);
    *status = 2;
    if (size < 0) return;
    if (size >= (long)sizeof(frames)) { *status = 4; return; }
    __u16 winner = 0, winning_class = 0;
    int ambiguous = 0;
    for (__u32 frame = 0; frame < MV_JR_CALLER_FRAME_CAPACITY; frame++) {
        if (frame * 8 >= (__u32)size) break;
        for (__u32 index = 0; index < 10; index++) {
            struct mv_jr_symbol *symbol = bpf_map_lookup_elem(&mv_jr_symbols, &index);
            if (!symbol || !symbol->start || frames[frame] < symbol->start || frames[frame] >= symbol->end) continue;
            if (symbol->ambiguous) ambiguous = 1;
            __u16 found = mv_journal_label_class(index + 1);
            if (winner && winning_class != found) ambiguous = 1;
            if (!winner || index + 1 < winner) { winner = index + 1; winning_class = found; }
        }
    }
    if (ambiguous) { *status = 3; return; }
    if (winner) { *status = 1; *cls = winning_class; *label = winner; }
}

static __always_inline void mv_jr_put(__u8 *out, __u64 value, int bytes)
{
    for (int i = 0; i < bytes; i++) out[i] = (__u8)(value >> (8 * i));
}

static __always_inline int mv_jr_exit(void *ctx, __u32 direction, __s32 pages, __s32 result)
{
    __u32 zero = 0;
    struct mv_jr_control *control = bpf_map_lookup_elem(&mv_jr_control, &zero);
    if (!control || !control->epoch || !control->observe) return 0;
    __u64 now = bpf_ktime_get_ns(), token = 0, entry = 0;
    mv_jr_count(MV_JR_EXITS);
    struct mv_journal_key key = {};
    if (mv_jr_key(&key, control->epoch)) {
        struct mv_jr_task *task = bpf_map_lookup_elem(&mv_jr_tasks, &key);
        if (task && task->depth) {
            if (!mv_jr_identity_healthy()) mv_jr_poison(&key, task);
            if (!task->poisoned && task->depth <= MV_JR_NESTING_CAPACITY) {
                key.depth = (__u32)task->depth;
                struct mv_jr_operation *operation = bpf_map_lookup_elem(&mv_jr_ops, &key);
                if (operation) {
                    if (operation->direction == direction && operation->pages == pages && operation->entry_ns <= now) {
                        token = operation->token; entry = operation->entry_ns;
                        if (!bpf_map_delete_elem(&mv_jr_ops, &key)) mv_jr_release();
                        else { token = 0; entry = 0; mv_jr_poison(&key, task); }
                    } else mv_jr_poison(&key, task);
                }
            }
            key.depth = 0;
            task->depth--;
            if (!task->depth) bpf_map_delete_elem(&mv_jr_tasks, &key);
        }
    }
    mv_jr_count(token ? MV_JR_MATCHED : MV_JR_UNMATCHED);
    __u64 *seq = bpf_map_lookup_elem(&mv_jr_sequence, &zero);
    if (!seq || *seq == ~0ULL) { mv_jr_overflow(MV_JR_EXITS); return 0; }
    __u64 sequence = (*seq)++;
    __u16 status = 0, cls = 0, label = 0;
    if (control->callers) mv_jr_callers(ctx, &status, &cls, &label);
    __u8 *wire = bpf_ringbuf_reserve(&mv_journal, MV_JR_LEN, 0);
    if (!wire) { mv_jr_count(MV_JR_RING_DROPS); return 0; }
    __builtin_memset(wire, 0, MV_JR_LEN);
    mv_jr_put(wire, MV_JR_MAGIC, 4); mv_jr_put(wire + 4, 1, 2); mv_jr_put(wire + 6, 1, 2);
    mv_jr_put(wire + 8, token ? 1 : 0, 2); mv_jr_put(wire + 10, direction, 2);
    mv_jr_put(wire + 12, bpf_get_smp_processor_id(), 4); mv_jr_put(wire + 16, sequence, 8);
    mv_jr_put(wire + 24, now, 8); mv_jr_put(wire + 32, control->epoch, 8);
    mv_jr_put(wire + 40, token, 8); mv_jr_put(wire + 48, entry, 8);
    mv_jr_put(wire + 56, (__u32)pages, 4); mv_jr_put(wire + 60, (__u32)result, 4);
    mv_jr_put(wire + 64, status, 2); mv_jr_put(wire + 66, cls, 2); mv_jr_put(wire + 68, label, 2);
    bpf_ringbuf_submit(wire, 0); mv_jr_count(MV_JR_EMITTED);
    return 0;
}

SEC("fentry/set_memory_decrypted")
int BPF_PROG(mv_jr_dec_enter, unsigned long addr, int pages) { (void)addr; (void)MV_JR_CONTEXT; return mv_jr_enter(1, pages); }
SEC("fexit/set_memory_decrypted")
int BPF_PROG(mv_jr_dec_exit, unsigned long addr, int pages, int result) { (void)addr; return mv_jr_exit(MV_JR_CONTEXT, 1, pages, result); }
SEC("fentry/set_memory_encrypted")
int BPF_PROG(mv_jr_enc_enter, unsigned long addr, int pages) { (void)addr; (void)MV_JR_CONTEXT; return mv_jr_enter(2, pages); }
SEC("fexit/set_memory_encrypted")
int BPF_PROG(mv_jr_enc_exit, unsigned long addr, int pages, int result) { (void)addr; return mv_jr_exit(MV_JR_CONTEXT, 2, pages, result); }
char LICENSE[] SEC("license") = "GPL";
