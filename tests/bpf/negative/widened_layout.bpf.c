/* SPDX-License-Identifier: GPL-2.0-only */

/* Negative copy object: widened local width, copies stay unknown. */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memveil_events.h"
#include "mv_fentry_types.h"
#define mv_layout_ok(got, want) mv_layout_ok((got), (want) == 4 ? 8 : (want))
#include "swiotlb_copy.bpf.c"
