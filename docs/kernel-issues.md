<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Kernel issues seen by memveil

memveil records what the kernel's DMA layer actually does. A kernel or driver bug therefore shows up in the captures and reports. memveil reports it correctly, but a reader can mistake it for memveil losing events. This page lists the kernel issues found so far, how each one shows up in memveil output, and how to tell it apart from capture loss.

## NVMe SGL unmap leak (Linux 6.18 to 6.19-rc7, 6.18.y before 6.18.40)

### What the kernel does

`nvme_unmap_data()` in `drivers/nvme/host/pci.c` calls `nvme_free_sgls()` with its `sge` and `sg_list` arguments swapped. Both have the same type, so the compiler did not catch it. The helper then sees the first data descriptor and unmaps only that one segment. Every other segment of the request is never passed to `dma_unmap_page()`.

- Introduced: f0887e2a52d4 "nvme-pci: create common sgl unmapping helper" (first in v6.18-rc1).
- Fixed: a54afbc8a213 "nvme-pci: DMA unmap the correct regions in nvme_free_sgls" (in v6.19).
- Stable backport: bbf04810b2a0 (in v6.18.40).
- Affected releases, checked against the source at each tag:
  - mainline v6.18-rc1 to v6.19-rc7;
  - stable v6.18 to v6.18.39.
- Not affected: v6.17 and older (no shared helper), v6.18.40 and later, v6.19 and later.

### When the buggy path runs

All of these must hold:

- the device needs explicit DMA unmaps (`dma_need_unmap()` is true). The kernel clears `dma_skip_sync` on a device's first swiotlb mapping, so this holds for any device whose DMA bounces through swiotlb: every device in a SEV-SNP or TDX guest without an IOMMU in between, and any guest booted with `swiotlb=force`;
- the request is not mapped through an IOMMU IOVA (`dma_use_iova()` is false) and is not P2P;
- the NVMe controller supports SGLs, and the request is on an I/O queue;
- the request uses an SGL. That happens when the average segment size is at least `nvme.sgl_threshold` (default 32 KiB), or for passthrough and multi-integrity requests.

### What the guest suffers

The skipped unmaps differ by direction:

- **Reads (DMA_FROM_DEVICE):** the bounce buffer is never copied back to the caller's memory. The caller silently gets stale data. The upstream fix calls the effect "corruption of the NVMe contents".
- **Both directions:** the swiotlb slots behind the skipped segments are never freed. The pool shrinks with every affected request until mappings fail with "swiotlb buffer is full" and I/O errors follow.

In a confidential VM this is data corruption on ordinary NVMe reads, plus a slow loss of the only path DMA can take.

### How it shows up in memveil

Seen in the 6.18.0 row of the kernel matrix (vanilla v6.18, QEMU NVMe, `swiotlb=force`):

- `map_result` and `bounce_attempt` outnumber `unmap` and `sync_request` by the number of leaked segments (54592 against 53952 in the matrix run, so 640 leaked).
- Read maps outnumber `bounce_to_original` copies by the same number.
- The session's `stop.open_mappings` equals that difference (640).
- Pool samples show `used_bytes` rising by the leaked bytes (82313216) and never falling, even after the workload has finished.
- Lifetime metrics in `memveil report`, such as `allocation_byte_microseconds`, grow without bound, because the leaked mappings stay open until the capture ends.

What memveil does not report on such a kernel: loss. The detail loss is 0, the hook liveness equations hold, and an independent bpftrace oracle saw exactly the same in-window events. The missing unmaps never happened in the kernel at all.

### Kernel leak or capture loss?

It is a kernel leak, not memveil loss, when all of these hold:

1. `quality.detail` reports loss 0, or a known loss smaller than the gap;
2. no `hooks silent` or `liveness unverified` suffix appears;
3. `stop.open_mappings` matches the map/unmap gap;
4. pool `used_bytes` stays up after the device goes idle.

If any one fails, treat the gap as capture loss and read the loss reason.

## Beyond this bug

This NVMe bug is one case of a general signature: **mappings that a driver never releases**. Any driver that forgets `dma_unmap_*()` or `dma_sync_*_for_cpu()` on a swiotlb-bounced path produces the same picture: open mappings at stop, pool usage that does not come back, and missing bounce-back copies, which mean stale reads. Under ordinary DMA such a bug can stay invisible. Under swiotlb, which every confidential VM uses, it costs data and pool space. When memveil shows open mappings that outlive the workload, check the driver on that device before suspecting memveil.

Kernels known to show this signature (kept current as the matrix grows):

| Kernel | Device | Cause | memveil row |
| --- | --- | --- | --- |
| v6.18 (and v6.18.1 to v6.18.39 by source) | NVMe with SGL support | f0887e2a52d4, fixed by a54afbc8a213 / bbf04810b2a0 | 6.18.0: 640 open mappings, 82313216 bytes held |
