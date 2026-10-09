<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Lifecycle hook freeze (development bundle 0.1.0)

Frozen attach points and source semantics for swiotlb mapping
lifetimes and executed copies. A profile admits these capabilities
only with the exact kernel source, config, BTF, and object bytes
recorded in its narrow bindings; anything else refuses.

## Attach points

All five have a frozen contract: they compile to
`build/bpf/swiotlb_lifecycle.bpf.o` and `swiotlb_copy.bpf.o`,
and the owner bundle ships all three BPF objects (attempt,
lifecycle, copy). The tracing attaches resolve by function
name through the bridge. Collector integration, multi-channel
packaging, capability-requested profile selection, and live VM
qualification of lifecycle/copy collection are complete; the
`linux-x86_64-7.0.0-34-generic` profile declares both
capabilities supported with the frozen hook sets below.

| Probe program | Attach | Kernel function |
| --- | --- | --- |
| `mv_map_result` | fexit | `swiotlb_tbl_map_single` |
| `mv_unmap` | fentry | `__swiotlb_tbl_unmap_single` |
| `mv_sync_device` | fentry | `__swiotlb_sync_single_for_device` |
| `mv_sync_cpu` | fentry | `__swiotlb_sync_single_for_cpu` |
| `mv_bounce` | fentry | `swiotlb_bounce` |

The attempt tracepoint `swiotlb:swiotlb_bounced` is unchanged and
stays the only attempt source.

## Capability-requested selection

`record` always captures the attempt channel. Extra channels are
opt-in per run:

```sh
memveil record --output DIR --object attempt.bpf.o \
    --capability attempt-trace,mapping-lifecycle,copy-actual \
    --lc-object lifecycle.bpf.o --cp-object copy.bpf.o ...
```

`--capability` takes a comma-separated list without spaces
(default: `attempt-trace`, which is always required).
`mapping-lifecycle` needs `--lc-object` and `copy-actual` needs
`--cp-object`. The winning profile must declare each requested
capability `supported` (or `candidate`) with all named hooks
present, and its narrow note must bind the exact extra object
hashes and ring sizes (`lc_object`, `lc_ring_bytes`,
`cp_object`, `cp_ring_bytes`); anything else refuses with
exit 3 naming the capability, for example
`capability mapping-lifecycle unsupported by <profile-id>` or
`binding failed: mismatch lc_object`. Extra channels never run
partial: without full narrow binding the run refuses instead of
recording an unverified channel.

Each requested extra capability also binds its hooks
one by one: every named hook must be a `tracing` hook whose
(function, attach) pair is a frozen member of that
capability (`mapping-lifecycle` needs exactly the map fexit
plus the unmap fentry; `copy-actual` needs exactly the two
sync fentries plus the bounce fentry) with the exact frozen
signature text, and every frozen member must be named. A
wrong function, a wrong attach point, a missing or extra
hook, or a corrupted signature refuses admission before any
probe attaches. Live signature identity rides the
whole-BTF narrow binding plus CO-RE at load; the profile
text is the auditable document side of that chain, pinned
by profile schema 0.1.1.

## Signatures

Signatures below are frozen against the 7.0.0-34-generic BTF
(`phys_addr_t` is 64-bit, `size_t` is 64-bit,
`dma_data_direction` is 0 BIDIRECTIONAL, 1 TO_DEVICE,
2 FROM_DEVICE, 3 NONE). A profile binds these exact
signatures before it admits the hooks; any mismatch refuses.

```c
phys_addr_t swiotlb_tbl_map_single(struct device *dev,
    phys_addr_t orig_addr, size_t mapping_size,
    unsigned int alloc_align_mask, enum dma_data_direction dir,
    unsigned long attrs);
void __swiotlb_tbl_unmap_single(struct device *dev,
    phys_addr_t tlb_addr, size_t mapping_size,
    enum dma_data_direction dir, unsigned long attrs,
    struct io_tlb_pool *pool);
void __swiotlb_sync_single_for_device(struct device *dev,
    phys_addr_t tlb_addr, size_t size,
    enum dma_data_direction dir, struct io_tlb_pool *pool);
void __swiotlb_sync_single_for_cpu(struct device *dev,
    phys_addr_t tlb_addr, size_t size,
    enum dma_data_direction dir, struct io_tlb_pool *pool);
void swiotlb_bounce(struct device *dev, phys_addr_t tlb_addr,
    size_t size, enum dma_data_direction dir,
    struct io_tlb_pool *mem);
```

Pinned layouts on the same kernel: `io_tlb_pool` size 104
with `slots` at byte 56; `io_tlb_slot` size 24
(`orig_addr`@0, `alloc_size`@8, `list`@16,
`pad_slots`@18); `device_dma_parameters` size 16
(`max_segment_size`@0, `min_align_mask`@4);
`device.dma_parms` at byte 632. The probes declare partial
views of these structs; CO-RE relocates the offsets at load
and load fails closed on mismatch.

Argument lists are the kernel function signatures as the probes
read them. Map and unmap probes use the (device, tlb address)
pair only as a kernel-private table key; sync probes ignore
address arguments; `mv_bounce` reads address metadata (pool
slot fields and `tlb_addr`) internally to replicate the
copied length. No addresses or device names are emitted:
MVLC v2 records carry sizes, directions, flags, and an
opaque mapping generation; MVCP v1 records carry sizes,
directions, flags, and reasons only.

- `swiotlb_tbl_map_single(dev, orig_addr, mapping_size,
  alloc_align_mask, dir, attrs)` returns the bounce address or the
  all-ones mapping-error sentinel. The fexit probe reports
  `mapping_size`, `dir`, ok = (return != sentinel), and the
  mapping generation (freshly assigned on success, 0 with an
  explicit flag when assignment is impossible, 0 on failure).
- `__swiotlb_tbl_unmap_single(dev, tlb_addr, mapping_size, dir,
  attrs, pool)` reports `mapping_size`, `dir`, the skip-sync
  bit read from attrs bit 5 (`DMA_ATTR_SKIP_CPU_SYNC`), and
  the looked-up generation (0 with an explicit miss flag when
  the mapping was never tracked).
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
- Identity: each successful map is assigned a fresh opaque
  generation, so same numeric address reuse yields distinct
  generations. An unmap pairs to its map only on a nonzero
  generation; missed or unassigned identities never pair and
  are counted explicitly. Map-time bounces precede the
  assignment and unmap-time copy-backs follow the release
  lookup, so copy records carry no generation by design.
- Lifetimes: pairing is eligible once wire generations are
  observed; misses, ring loss, and invalid epochs still
  caveat completeness.
- Outer failure: fexit ok means the inner allocator found slots;
  the outer DMA call may still fail afterwards, and its cleanup
  unmap arrives as its own event. Inner success is never a claim
  of final DMA success.

## Explicitly unsupported

- Scatter-gather segments: only the single-mapping hooks above
  are probed. Whether SG paths call these inner helpers is
  unconfirmed on the admitted kernel, so SG attribution and
  segment reconstruction stay unavailable.
- Coherent, direct, and non-swiotlb DMA paths: unobserved and
  unclaimed.
- Copy-to-mapping attribution and per-mapping byte totals: no
  copy identity exists, so copies aggregate as byte facts only.
- Sync ranges: the wire observes no sync offset, so coverage is
  unknown, never assumed whole-mapping.
- Kernels, configs, BTF builds, or object bytes outside the
  admitting profile's narrow bindings: refused, never degraded.
- Other architectures and kernels below the 7.0 floor: no hooks
  are admitted there.
