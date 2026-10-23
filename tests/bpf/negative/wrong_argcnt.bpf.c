/* SPDX-License-Identifier: GPL-2.0-only */

/* Negative copy object: wrong hook arity, bounce hooks stay out. */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memveil_events.h"
#include "mv_fentry_types.h"
#undef MV_ARGS_BOUNCE
#define MV_ARGS_BOUNCE 4
#include "swiotlb_copy.bpf.c"
