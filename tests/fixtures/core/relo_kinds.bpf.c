/* SPDX-License-Identifier: GPL-3.0-or-later */
/* CO-RE kind coverage fixture: one use of each layout-bearing builtin.
 *
 * Compiled by tools/emit-core-fixtures with the build's exact BPF
 * flags; the committed object feeds the extractor tests. Never
 * loaded: the pointer below is a fixture stand-in, and every
 * builtin result folds into the return so -O2 keeps its record.
 */
#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct mvt_relo {
	__u64 f_read;
	__u32 f_size;
	__u16 f_opt;
} __attribute__((preserve_access_index));

struct mvt_sized {
	__u64 a;
	__u32 b;
} __attribute__((preserve_access_index));

enum mvt_hue {
	MVT_RED = 1,
	MVT_GREEN = 2,
};

char MVT_LICENSE[] SEC("license") = "GPL";

SEC("socket")
int mvt_relo_kinds(void *ctx)
{
	struct mvt_relo *r = (struct mvt_relo *)(void *)ctx;
	__u64 v = 0;
	__u64 tmp = 0;

	if (bpf_core_read(&tmp, sizeof(tmp), &r->f_read))
		return 0;
	v += tmp;
	v += bpf_core_field_size(r->f_size);
	if (bpf_core_field_exists(r->f_opt))
		v += 10;
	if (bpf_core_type_exists(struct mvt_sized))
		v += 100;
	v += bpf_core_type_size(struct mvt_sized);
	if (bpf_core_enum_value_exists(enum mvt_hue, MVT_RED))
		v += 1000;
	v += bpf_core_enum_value(enum mvt_hue, MVT_GREEN);
	return v != 0;
}
