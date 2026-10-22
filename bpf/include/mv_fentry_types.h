/* SPDX-License-Identifier: GPL-2.0-or-later */

/* BPF-only kernel type views for the fentry/fexit adapters.
 *
 * Partial structs under a flavor suffix: only accessed
 * fields are declared, CO-RE relocates their offsets at
 * load, and each relocated width is guarded live against
 * its spelling here. The direction enum resolves through
 * relocations as well; no hook assumes a kernel value.
 * Must never be included by host code.
 */
#ifndef MV_FENTRY_TYPES_H
#define MV_FENTRY_TYPES_H

#ifndef __BPF__
#error "mv_fentry_types.h is BPF-only"
#endif

#include <linux/types.h>
#include <stdbool.h>

#include "memveil_events.h"

typedef __u64 mv_phys_addr_t;
typedef __u64 mv_size_t;

struct io_tlb_slot___mv {
    mv_phys_addr_t orig_addr;
    mv_size_t alloc_size;
} __attribute__((preserve_access_index));

struct io_tlb_pool___mv {
    mv_phys_addr_t start;
    mv_phys_addr_t end;
    unsigned long nslabs;
    struct io_tlb_slot___mv *slots;
} __attribute__((preserve_access_index));

struct device_dma_parameters___mv {
    unsigned int min_align_mask;
} __attribute__((preserve_access_index));

struct io_tlb_mem___mv {
    bool cc_shared;
} __attribute__((preserve_access_index));

struct device___mv {
    struct device_dma_parameters___mv *dma_parms;
    struct io_tlb_mem___mv *dma_io_tlb_mem;
} __attribute__((preserve_access_index));

/* Local direction view: values are placeholders resolved by
 * relocation at load, never trusted as kernel values. */
enum dma_data_direction___mv {
    DMA_BIDIRECTIONAL___mv = 0,
    DMA_TO_DEVICE___mv = 1,
    DMA_FROM_DEVICE___mv = 2,
};

/* Expected hook argument counts (verified live, not assumed). */
#define MV_ARGS_MAP_SINGLE 6
#define MV_ARGS_UNMAP 6
#define MV_ARGS_SYNC 5
#define MV_ARGS_BOUNCE 5

/* DMA_ATTR_SKIP_CPU_SYNC is bit 5 (dma-mapping.h). */
#define MV_DMA_ATTR_SKIP_CPU_SYNC (1UL << 5)

/* Resolve one kernel direction to the wire encoding (TO 1,
 * FROM 2, BIDI 0); 0 when the value matches nothing. */
static __always_inline int mv_wire_dir(int kdir, __u16 *out)
{
    __u64 kdir64;

    if (kdir < 0)
        return 0;
    kdir64 = (__u64)kdir;
    if (kdir64 == bpf_core_enum_value(enum dma_data_direction___mv,
                                      DMA_TO_DEVICE___mv)) {
        *out = 1;
        return 1;
    }
    if (kdir64 == bpf_core_enum_value(enum dma_data_direction___mv,
                                      DMA_FROM_DEVICE___mv)) {
        *out = 2;
        return 1;
    }
    if (kdir64 == bpf_core_enum_value(enum dma_data_direction___mv,
                                      DMA_BIDIRECTIONAL___mv)) {
        *out = 0;
        return 1;
    }
    return 0;
}

#define MV_IO_TLB_SHIFT MV_IO_TLB_SHIFT_WIRE
#define MV_IO_TLB_SIZE 2048u
#define MV_IO_TLB_MASK 2047u

#endif /* MV_FENTRY_TYPES_H */
