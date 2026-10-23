/* SPDX-License-Identifier: GPL-2.0-only */

/* Negative copy object: doubled slot count, geometry never matches. */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memveil_events.h"
#include "mv_fentry_types.h"
#define mv_slot_index(s, e, n, t, i) mv_slot_index((s), (e), (n) * 2, (t), (i))
#include "swiotlb_copy.bpf.c"
