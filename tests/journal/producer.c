/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bpf/include/memveil_journal.h"
#define MV_JOURNAL_HOST_TEST 1
#define SEC(x)
#define __uint(n, v) int (*n)[v]
#define __type(n, t) t *n
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_NOEXIST 1
#define BPF_ANY 0
#define BPF_PROG(n, ...) n(__VA_ARGS__)
static void *bpf_map_lookup_elem(void *, const void *);
static long bpf_map_update_elem(void *, const void *, const void *, unsigned long);
static long bpf_map_delete_elem(void *, const void *);
static void *bpf_get_current_task_btf(void);
static unsigned long long bpf_ktime_get_ns(void);
static unsigned bpf_get_smp_processor_id(void);
static void *bpf_ringbuf_reserve(void *, unsigned long, unsigned long);
static void bpf_ringbuf_submit(void *, unsigned long);
static long bpf_get_stack(void *, void *, unsigned, unsigned long long);
static int read_failed;
#define BPF_CORE_READ_INTO(dst, task, field) (read_failed ? -1 : (*(dst) = (task)->field, 0))
#include "bpf/programs/conversion_journal.bpf.c"

struct slot { int used; struct mv_journal_key key; unsigned char value[64]; };
static struct slot tasks[4096], ops[4096];
static struct mv_jr_control control;
static __u64 counts[MV_JR_COUNT_KEYS], sequence[4];
static struct mv_jr_symbol symbols[10];
static struct task_struct task_storage[4100];
static int task_index, cpu, drop, submissions, fail_insert;
static __u64 now;
static unsigned char wire[MV_JR_LEN];
static struct mv_journal last;
static __u64 stack[16];
static long stack_size;
static int stack_calls;
static struct slot *table(void *map) { return map == &mv_jr_tasks ? tasks : ops; }
static void *bpf_map_lookup_elem(void *map, const void *key) {
    unsigned k;
    if (map == &mv_jr_control) return &control;
    if (map == &mv_jr_counts) { memcpy(&k,key,4); return k < MV_JR_COUNT_KEYS ? &counts[k] : NULL; }
    if (map == &mv_jr_sequence) return &sequence[cpu];
    if (map == &mv_jr_symbols) { memcpy(&k,key,4); return k < 10 ? &symbols[k] : NULL; }
    struct slot *t = table(map);
    for (int i=0;i<4096;i++) if(t[i].used && !memcmp(&t[i].key,key,32)) return t[i].value;
    return NULL;
}
static long bpf_map_update_elem(void *map,const void *key,const void *value,unsigned long flags) {
    (void)flags;
    if (fail_insert) return -1;
    struct slot *t=table(map);
    for(int i=0;i<4096;i++) if(!t[i].used) {
        t[i].used=1; memcpy(&t[i].key,key,32);
        memcpy(t[i].value,value,map==&mv_jr_tasks?sizeof(struct mv_jr_task):sizeof(struct mv_jr_operation)); return 0;
    }
    return -1;
}
static long bpf_map_delete_elem(void *map,const void *key) {
    struct slot *t=table(map);
    for(int i=0;i<4096;i++) if(t[i].used&&!memcmp(&t[i].key,key,32)) { t[i].used=0;return 0; }
    return -1;
}
static void *bpf_get_current_task_btf(void) { return &task_storage[task_index]; }
static unsigned long long bpf_ktime_get_ns(void) { return ++now; }
static unsigned bpf_get_smp_processor_id(void) { return (unsigned)cpu; }
static void *bpf_ringbuf_reserve(void *map,unsigned long size,unsigned long flags) {
    (void)map;(void)flags;assert(size==72);return drop?NULL:wire;
}
static void bpf_ringbuf_submit(void *payload,unsigned long flags) {
    (void)flags;assert(mv_decode_journal(payload,72,&last)==MV_OK);submissions++;
}
static long bpf_get_stack(void *ctx,void *buf,unsigned size,unsigned long long flags) {
    (void)ctx;(void)flags;assert(size==128);stack_calls++;memcpy(buf,stack,128);return stack_size;
}
static void reset(void) {
    memset(tasks,0,sizeof(tasks));memset(ops,0,sizeof(ops));memset(counts,0,sizeof(counts));
    memset(sequence,0,sizeof(sequence));memset(&control,0,sizeof(control));memset(symbols,0,sizeof(symbols));
    memset(stack,0,sizeof(stack));for(int i=0;i<4100;i++)task_storage[i].start_boottime=(__u64)i+1;
    control.epoch=23;control.observe=1;control.open=1;control.start_ns=1;
    task_index=0;cpu=0;drop=0;submissions=0;read_failed=0;fail_insert=0;now=10;stack_size=-1;stack_calls=0;
}
static void enter(int direction,int pages) { mv_jr_enter(direction,pages); }
static void leave(int direction,int pages,int result) { mv_jr_exit(NULL,direction,pages,result); }
int main(void) {
    reset(); enter(1,3);cpu=2;leave(1,3,-5);
    assert(last.matched && last.token==1 && last.cpu==2 && last.pages==3 && last.native_result==-5);
    assert(counts[MV_JR_ENTRIES]==1 && counts[MV_JR_EXITS]==1 && counts[MV_JR_ACTIVE]==0 && stack_calls==0);
    enter(1,4);enter(2,5);leave(2,5,7);assert(last.token==3 && last.native_result==7);leave(1,4,0);assert(last.token==2);
    reset();control.open=0;enter(1,1);leave(1,1,0);assert(!last.matched && counts[MV_JR_ENTRIES]==0);
    reset();enter(1,3);control.open=0;enter(2,8);leave(2,8,0);assert(!last.matched);leave(1,3,0);assert(last.matched);
    reset();leave(2,-2147483647-1,2147483647);assert(!last.matched && last.pages==(-2147483647-1));
    reset();enter(1,3);leave(2,3,0);assert(!last.matched && counts[MV_JR_CENSORED]==1 && counts[MV_JR_ACTIVE]==0);
    reset();enter(1,3);leave(1,4,0);assert(!last.matched && counts[MV_JR_CENSORED]==1);
    reset();for(int i=0;i<9;i++)enter(1,i);for(int i=8;i>=0;i--){leave(1,i,0);assert(!last.matched);}
    assert(counts[MV_JR_CENSORED]==8 && counts[MV_JR_NESTING_EXHAUSTION]==1);enter(1,4);leave(1,4,0);assert(last.matched);
    reset();enter(1,3);drop=1;leave(1,3,0);assert(counts[MV_JR_RING_DROPS]==1 && sequence[0]==1 && counts[MV_JR_ACTIVE]==0);
    drop=0;enter(2,3);leave(2,3,0);assert(last.sequence==1 && submissions==1);
    reset();counts[MV_JR_NEXT_TOKEN]=MV_JR_TOKEN_MAX;enter(1,3);leave(1,3,0);assert(!last.matched&&!control.open&&counts[MV_JR_TOKEN_EXHAUSTION]==1);
    reset();counts[MV_JR_ENTRIES]=UINT64_MAX;enter(1,3);assert(counts[MV_JR_ENTRIES]==UINT64_MAX && counts[MV_JR_OVERFLOW]!=0);
    reset();read_failed=1;enter(1,3);read_failed=0;leave(1,3,0);assert(!last.matched&&counts[MV_JR_IDENTITY_FAILURE]==1);
    reset();enter(1,3);read_failed=1;enter(1,3);read_failed=0;leave(1,3,0);assert(!last.matched);leave(1,3,0);assert(!last.matched);
    reset();enter(1,3);task_storage[0].start_boottime++;leave(1,3,0);assert(!last.matched && counts[MV_JR_ACTIVE]==1);
    reset();fail_insert=1;enter(1,3);fail_insert=0;leave(1,3,0);assert(!last.matched&&counts[MV_JR_OPERATION_EXHAUSTION]==1);
    reset();for(int i=0;i<4096;i++){task_index=i;enter(1,3);}task_index=4096;enter(1,3);leave(1,3,0);assert(!last.matched&&counts[MV_JR_ACTIVE]==4096);
    reset();control.callers=1;enter(1,3);leave(1,3,0);assert(last.caller_status==2 && stack_calls==1);
    symbols[0].start=100;symbols[0].end=110;stack[0]=104;stack_size=8;
    enter(1,3);leave(1,3,0);assert(last.caller_status==1&&last.caller_label==1&&last.caller_class==1);
    symbols[2].start=100;symbols[2].end=110;enter(1,3);leave(1,3,0);assert(last.caller_status==3&&last.caller_label==0);
    stack_size=128;enter(1,3);leave(1,3,0);assert(last.caller_status==4&&last.caller_label==0);
    reset();sequence[0]=UINT64_MAX;leave(1,1,0);assert(submissions==0&&counts[MV_JR_OVERFLOW]);
    reset();control.observe=0;enter(1,1);leave(1,1,0);assert(submissions==0&&counts[MV_JR_ENTRIES]==0);
    reset();mv_jr_dec_enter(0,3);mv_jr_dec_exit(0,3,-5);assert(last.direction==1&&last.native_result==-5);
    mv_jr_enc_enter(0,4);mv_jr_enc_exit(0,4,0);assert(last.direction==2&&last.pages==4);
    puts("journal shipping probe: nesting, migration, limits, loss, signed results, readiness, drain and callers passed (host helpers only)");
}
