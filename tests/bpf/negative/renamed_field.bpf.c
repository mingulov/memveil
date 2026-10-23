/* SPDX-License-Identifier: GPL-2.0-only */

/* Negative copy object: pool field renamed, load must refuse. */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define nslabs mvt_nslabs
#include "memveil_events.h"
#include "mv_fentry_types.h"
#include "swiotlb_copy.bpf.c"
