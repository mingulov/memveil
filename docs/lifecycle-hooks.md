<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Lifecycle hook freeze (development bundle 0.1.0)

Frozen attach points and source semantics for swiotlb mapping
lifetimes and executed copies. A profile admits these capabilities
through one of two lanes: a bound document whose narrow
bindings match the kernel source, config, BTF, and object
bytes exactly, or an unbound reference document whose
tracing interfaces verify against the running kernel (live
tracepoint format, BTF hook signatures, ftrace
attachability). Object statics — program set, map layout,
ring sizes — verify in both lanes; anything else refuses.

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
| `mv_bounce_exit` | fexit | `swiotlb_bounce` |

`mv_bounce_exit` is the recursion fallback for the
`fentry:swiotlb_bounce` hook (same function and signature), not a
separate profile hook; see [Recursion fallback](#recursion-fallback).

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
Each channel's BPF object is discovered beside the
executable or under the system directory; `--lc-object`
and `--cp-object` are optional overrides for non-bundled
objects. The winning profile must declare each requested
capability `supported` (or `candidate`) with all named hooks
present. A bound document must also match the exact extra
object hashes and ring sizes in its narrow note
(`lc_object`, `lc_ring_bytes`, `cp_object`,
`cp_ring_bytes`); an unbound reference document instead
verifies the tracing interfaces live and records measured
identities. Anything else refuses with exit 3 naming the
capability, for example
`capability mapping-lifecycle unsupported by <profile-id>`,
`binding failed: mismatch lc_object`, or
`live check failed: ...`. Extra channels never run
partial: without full binding or a passing live check the
run refuses instead of recording an unverified channel.

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
whole-BTF narrow binding plus CO-RE at load for bound
documents; the live lane compares the same frozen
signatures against the running kernel's BTF instead
(accepting the 7.3 map shape via `signature_alt`). The
profile text is the auditable document side of that chain,
pinned by profile schema 0.1.1.

## Signatures

Signatures below are frozen against the 7.0.0-34-generic BTF
(`phys_addr_t` is 64-bit, `size_t` is 64-bit,
`dma_data_direction` is 0 BIDIRECTIONAL, 1 TO_DEVICE,
2 FROM_DEVICE, 3 NONE). A bound profile binds these exact
signatures before it admits the hooks; the live lane
checks them against the running kernel's BTF instead.
Any mismatch refuses.

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
views of these structs. CO-RE relocates only the member
accesses spelled with bpf_core_read (pool start, nslabs,
slots, dev->dma_parms, min_align_mask); the bulk
io_tlb_slot read keeps its compile-time stride and member
offsets, and enum values, shift/mask constants, and hook
signatures stay frozen. Layout identity therefore rides
the whole-BTF narrow binding, which refuses admission on
any BTF change before load; CO-RE success alone never
establishes it.

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

## Qualified kernel constants

The probes pin these kernel constants; each carries a check,
never a bare assumption:

- `DMA_ATTR_SKIP_CPU_SYNC` is attrs bit 5
  (`MV_DMA_ATTR_SKIP_CPU_SYNC (1UL << 5)`,
  matching `include/linux/dma-mapping.h`). The unmap probe
  reads it from the attrs argument, and the unmap->copy
  liveness equations assert it on the matrix: a wrong bit
  fires them under the reference workload.
- `DMA_MAPPING_ERROR` is all-ones `phys_addr_t`
  (`MV_INVALID_PHYS`). The map fexit probe reports ok only
  when the return differs from that sentinel.
- `phys_addr_t` and `size_t` are 8 bytes on x86-64; the
  frozen signatures above encode that width.
- `IO_TLB_SHIFT` is 11 (`MV_IO_TLB_SHIFT_WIRE`): one pool
  slot covers 1 << 11 bytes. The copy probe checks each
  pool span is exactly nslabs slots wide and degrades the
  event to unknown with reason SHIFT otherwise.
- Copy flags `0x10` (offset past the allocation) and
  `0x20` (private pool) mark known copies only: the first
  when the hook offset ran past the allocation end so the
  full size copied unchecked, the second when the allocator
  toggle proves the pool private. Unknown copies name one
  of SLOT_READ, MASK_READ, BOUNDS, LAYOUT, or SHIFT, where
  LAYOUT means a relocated size read mismatched its local
  expectation.
- The argument-count counter flag is xcounter flag word
  bit 6 (`MV_FLAG_ARGCNT`, sticky). It sets when the
  observed hook argument count differs from the frozen
  signature; like any set flag bit it invalidates the
  epoch and voids the liveness loss for that channel.

## Recursion fallback

On x86 the kernel guards each tracing program with one per-CPU
counter shared by task, softirq and hardirq context. A bounce in
an interrupt (for example NVMe completion unmapping in hardirq)
that lands while `mv_bounce` runs on the interrupted task is
skipped and counted in that program's `recursion_misses`; one
interrupt completing a batch loses the whole batch.

`mv_bounce_exit` recovers those copies. `mv_bounce` claims a
slot in the kernel-private `mv_claims` table keyed by the
trampoline frame address (unique among live calls in any
context) and a call id from `tlb_addr`, `size` and `dir`, then
records the copy. `mv_bounce_exit` releases the claim and
records the copy only when no matching claim exists and the
fallback is armed, so each copy is recorded once. The fentry
program attaches before the fexit program; the armed slot in
`mv_copy_fb` (written after attach, cleared before detach)
keeps a bare exit from counting recoveries, so the gate plus
entry-first order make the count exact. A full probe window
leaves the copy to `mv_bounce_exit` and counts deferred in
`mv_copy_fb`; a call neither program can match counts as
`submit_fail`.

`recursion_missed` charges exact copy loss: misses of every
program except `mv_bounce` and `mv_bounce_exit`, plus
misses(`mv_bounce`) + deferred - recovered. Exit-only misses
never lose a copy. Raw per-program misses with deferred and
recovered persist as session evidence; a negative remainder
contradicts the counters and makes detail loss unknown.

The eight persisted names are `copy.mv_bounce_misses`,
`copy.mv_bounce_exit_misses`, `copy.mv_sync_device_misses`,
`copy.mv_sync_cpu_misses`, `lifecycle.mv_map_result_misses`,
`lifecycle.mv_unmap_misses`, `copy.deferred` and `copy.recovered`.
Arming is a capture gate, not evidence: the armed slot is set
after every copy link attaches and cleared before detach, a
failed arm write refuses the capture, a failed disarm write
leaves copy detail unknown, and a disarmed exit records nothing.

After the end cut, the collector re-reads every recursion
counter and compares it with the first read, which is
never replaced. A detected move marks detail loss unknown
with reason `post-snapshot activity`; an unreadable
re-read marks it unknown with reason `recursion misses
unreadable after settle: ...`. A moved or unreadable attempt
count, or a skipped re-read, also marks the aggregate
loss unknown with its own reason.

A first-read detail failure with a valid attempt count
keeps the count and marks only detail unknown, with
reason `copy detail unreadable: ...` (or `lifecycle
detail unreadable: ...` without a copy channel).

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

## Hook liveness check

After close, the collector judges five one-sided equations
over two windows: forward F from attach to one second
before detach, reverse R from readiness to one second
before detach. Forward equations count causes in F and
effects over the whole run; reverse equations count
effects in R and causes over the whole run. The five are
attempt->map, map->copy, copy->map, unmap->copy, and
copy->unmap, each with a loss term of emitted-minus-tallied
records per channel, so drain-stranded and rejected
records are absorbed, never silent.

Per equation, an empty window or a zero left-hand side is
not exercised; unknown loss or a saturated counter is
unverified; a violated inequality names silent hooks; a
held inequality is verified. Overall precedence is silent
over unverified over verified over not exercised, and a
copy channel without lifecycle stays unverified
regardless. Silent and unverified verdicts append a cause
to detail quality (partial); a verified verdict appends
`; liveness verified` to the lifecycle and copy
capability reasons; an unexercised verdict changes
nothing, so captures whose records predate attach replay
byte-identical.

Channels attach copy, then lifecycle, then attempt, and
detach in the reverse order; inside the copy object the
bounce entry attaches before the bounce exit and the sync
hooks, so a sync record never precedes a live bounce hook.

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
  admitting profile's narrow bindings (or failing the live
  interface checks for an unbound reference): refused, never
  degraded.
- Other architectures and kernels below the 6.11 lifecycle
  floor: no hooks are admitted there.
