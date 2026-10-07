/* SPDX-License-Identifier: GPL-2.0-or-later */

/* BPF-only kernel type views for the fentry/fexit adapters.
 *
 * Partial structs: only accessed fields are declared, and
 * CO-RE relocates their offsets at load. Layouts verified
 * against the 7.0.0-34-generic BTF (io_tlb_slot size 24,
 * io_tlb_pool size 104, device_dma_parameters size 16).
 * Must never be included by host code.
 */
#ifndef MV_FENTRY_TYPES_H
#define MV_FENTRY_TYPES_H

#ifndef __BPF__
#error "mv_fentry_types.h is BPF-only"
#endif

#include <linux/types.h>

typedef __u64 mv_phys_addr_t;
typedef __u64 mv_size_t;

enum mv_dma_data_direction {
    MV_DMA_BIDIRECTIONAL = 0,
    MV_DMA_TO_DEVICE = 1,
    MV_DMA_FROM_DEVICE = 2,
    MV_DMA_NONE = 3,
};

struct device_dma_parameters {
    unsigned int max_segment_size;
    unsigned int min_align_mask;
};

struct device {
    struct device_dma_parameters *dma_parms;
};

struct io_tlb_slot {
    mv_phys_addr_t orig_addr;
    mv_size_t alloc_size;
    unsigned short list;
    unsigned short pad_slots;
};

struct io_tlb_pool {
    mv_phys_addr_t start;
    mv_phys_addr_t end;
    void *vaddr;
    unsigned long nslabs;
    struct io_tlb_slot *slots;
};

#define MV_IO_TLB_SHIFT 11u
#define MV_IO_TLB_SIZE 2048u
#define MV_IO_TLB_MASK 2047u

#endif /* MV_FENTRY_TYPES_H */
