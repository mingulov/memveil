// SPDX-License-Identifier: GPL-2.0-only

/* Synthetic CO-RE oracle for the extractor test: never loaded, compiled only. */

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct mvt___a {
    int a;
    long b;
} __attribute__((preserve_access_index));

enum mvt_e___a {
    MVT_X = 1,
};

SEC("tp/x")
int mvt_probe(void *ctx)
{
    struct mvt___a v = { 0, 0 };
    struct mvt___a *p = &v;
    long t = 0;
    __u64 sum;

    (void)ctx;
    t = BPF_CORE_READ(p, b);
    sum = (__u64)bpf_core_field_size(v.b) +
          (__u64)bpf_core_field_exists(v.a) + (__u64)t +
          (__u64)bpf_core_type_size(struct mvt___a) +
          (__u64)bpf_core_enum_value(enum mvt_e___a, MVT_X);
    return (int)(sum & 0xff);
}

char MV_LICENSE[] SEC("license") = "GPL";
