<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Lifecycle hook freeze (development bundle 0.1.0)

Frozen attach points and source semantics for swiotlb mapping
lifetimes and executed copies. A profile admits these capabilities
only with the exact kernel source, config, BTF, and object bytes
recorded in its narrow bindings; anything else refuses.

## Attach points

All five live in the shipped BPF objects next to the attempt probe.
The tracing attaches resolve by function name through the bridge.

| Probe program | Attach | Kernel function |
| --- | --- | --- |
| `mv_map_result` | fexit | `swiotlb_tbl_map_single` |
| `mv_unmap` | fentry | `__swiotlb_tbl_unmap_single` |
| `mv_sync_device` | fentry | `__swiotlb_sync_single_for_device` |
| `mv_sync_cpu` | fentry | `__swiotlb_sync_single_for_cpu` |
| `mv_bounce` | fentry | `swiotlb_bounce` |

The attempt tracepoint `swiotlb:swiotlb_bounced` is unchanged and
stays the only attempt source.

## Signatures

Argument lists are the kernel function signatures as the probes
read them; the probes never read device names or addresses.

- `swiotlb_tbl_map_single(dev, orig_addr, mapping_size,
  alloc_align_mask, dir, attrs)` returns the bounce address or the
  all-ones mapping-error sentinel. The fexit probe reports
  `mapping_size`, `dir`, and ok = (return != sentinel).
- `__swiotlb_tbl_unmap_single(dev, tlb_addr, mapping_size, dir,
  attrs, pool)` reports `mapping_size`, `dir`, and the skip-sync
  bit read from attrs bit 5 (`DMA_ATTR_SKIP_CPU_SYNC`).
- `__swiotlb_sync_single_for_device(dev, tlb_addr, size, dir,
  pool)` and `__swiotlb_sync_single_for_cpu(...)` report `size`
  and `dir` as sync requests. A sync request is never an executed
  copy and contributes zero executed bytes by definition.
- `swiotlb_bounce(dev, tlb_addr, size, dir, pool)` reports
  `size`, `dir`, and replicated effective bytes (below).

## Effective-byte rule

`mv_bounce` replicates the bytes the hook itself copies: it reads
the pool slot the hook reads (`start`, `slots`, `nslabs`, then
`orig_addr` and `alloc_size`) plus `dev->dma_parms->min_align_mask`,
and applies the hook clamp from `bpf/include/memveil_events.h`.
An invalid slot copies nothing (hook early return, effective 0);
otherwise the request clamps to `alloc_size - tlb_offset` with the
hook signed offset math, where a negative offset widens the room.
Any failed read degrades that event to unknown-with-reason while
the request fact (size, direction) is still emitted.

## Semantic edges

- Clamps: a clamped copy sets the clamped flag; requested and
  effective bytes stay distinct fields.
- Early returns: invalid-slot bounces emit effective 0 with the
  early-zero flag, never silence.
- Skip-sync: unmaps with attrs bit 5 set the skip-sync flag; the
  release fact is still emitted.
- Nested calls: every hook firing emits its own record; nested
  4096 + 1024 copies sum to 5120 effective bytes.
- Interrupt context: firings in any context count and emit like
  any other firing; ordering across CPUs is ring order, not
  causal order.
- Reuse: the v1 wire carries no addresses, so each successful map
  mints a fresh opaque generation and no unmap ever pairs to a
  specific map. Same numeric address reuse is therefore always
  distinct generations, and lifetimes stay unavailable.
- Outer failure: fexit ok means the inner allocator found slots;
  the outer DMA call may still fail afterwards, and its cleanup
  unmap arrives as its own event. Inner success is never a claim
  of final DMA success.

## Explicitly unsupported

- Scatter-gather segments: only the single-mapping hooks above
  are probed; no `*_sg` path is observed.
- Coherent, direct, and non-swiotlb DMA paths: unobserved and
  unclaimed.
- Map/unmap pairing, lifetimes, and per-mapping bytes: no v1
  wire identity exists, so these stay unavailable with reasons.
- Kernels, configs, BTF builds, or object bytes outside the
  admitting profile's narrow bindings: refused, never degraded.
- Other architectures and kernels below the 7.0 floor: no hooks
  are admitted there.
