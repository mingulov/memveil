<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Worked example: recorded three-channel capture

1,804 real events over 150.175546150 s (150175546150 ns):
208 `bounce_attempt` details, 208 `map_result` plus 208 `unmap`
lifecycle events, 613 `sync_request` and 412 `copy` executed-copy
events, 151 default-pool samples, and 4 counter snapshots.
Recorded live in a disposable guest (kernel 7.0.0-34-generic)
with the packaged `record` verb and all three channels selected
(`attempt-trace,mapping-lifecycle,copy-actual`). The recorded
profile decision names the narrow profile that kernel was
captured under; the 0.1.0 bundle ships reference profiles
only, and this historical capture qualifies no rebuilt
package. The capture ran three workload phases: a 2-operation
oracle phase
(4,096 + 1,024 bytes), a 4-operation fail phase (one failed
outer mapping with a healthy inner allocation and no outer
release), and a real-traffic phase (200/200 pings plus
1,048,576 disk bytes through the swiotlb path).

## Agreement with the independent oracle

The oracle module (0.4.0) logged every scripted operation to
`oracle-phase.log` and `fail-phase.log`. Against those logs:

- Oracle slice: 2 operations, 20 events, exact match.
- Fail slice: 5 maps, 5 unmaps, 8 syncs, 8 copies,
  5 attempts, exact match; the failed outer mapping never
  appears as an outer map, sync, or release, while its inner
  executed copies survive as independent facts.
- Lifetimes: every map pairs with its unmap (208 completed,
  0 open); 208 distinct opaque mapping generations,
  0 unassigned.
- Actual copy facts: 35,002 bytes original-to-bounce and
  24,784 bytes bounce-to-original, summed over every executed
  copy event per direction. The 412 copies carry no mapping
  identity on the wire, so copy attribution stays partial
  while the byte totals persist as global known facts; this
  capture explains executed copying beyond raw attempt
  counts. Mean completed lifetime 48,937,130 ns; peak live
  observed allocation 5,120 bytes; live 0 at close.

Device scope stays honest: the catalog holds `d000001`
(unresolved) and `d000002` (observed name `0000:00:0c.0`),
both identity-unresolved. Mappings were observed in global
scope and are unattributed; nothing here reconstructs a
particular device's DMA from the unattributed global
mappings.

## Provenance

- Recorded with packaged binary sha256
  `e9c9ff3e890e08b2182fc8b6c0fb73c805b740ea7b26a675fa177f3427778030`
  (tarball sha256
  `3fc10d689c0ef359e8e84425441bf353d2abd80c510c87fbd231ed156d78bda6`,
  51 files verified), bridge sha256
  `96666f177fe17336b5e1b15695a2c640d1e7b5cb1069c2041e9377835be5291b`
  (abi-v1), attempt object sha256
  `f7e94e6379e43373ca0cd76b641307df0d7e801df60dd5dd4306e86400d00a8a`,
  lifecycle object sha256
  `769bb7fd59e38a04555c4f80624769ca03dddb5d8d866b2b456b23d6c2b7033a`,
  copy object sha256
  `5322bcf9fb243eb023c2b4fee8d89b523be818c4f757c4984a1410bfe118fcde`,
  oracle module sha256
  `cd96d1ddd5893bf4233ee9c70914a2a38ca00e01746e74221b779a3e13016ecf`.
- Kernel bindings: image sha256
  `7efd88a7facf80874d781ccb2c2421f0aaaa575e3b94760430619e826f490117`,
  build-id `165b9a4f9609ede635b85d0d1241ee95208e4548`,
  config sha256
  `e75c0adab6020e72844d7431cf801a02b94ed32efc251c3b0fb80c021d065180`
  (file), BTF sha256
  `16205476ae9b6d621e056249052a5789d7f22c6a8c27bf291eb787f3bda5090e`,
  tracepoint format sha256
  `7e95fff18d1bd16c18342d821e78680a0126ff84054936fbc641e181810f0b62`.
  Rings 8,388,608 bytes per channel; drain closure proven.
- Detail and aggregate quality are `complete_for_scope` with
  loss 0. Terminal quality stays `partial` (quiescence
  unproven after detach); correlation stays `partial`
  (unpaired copies and syncs excluded from attribution while
  their facts persist). Reports exit 4 by design.
- This is a historical capture and profile decision, not
  qualification of a rebuilt package or the current reader
  host.

Reviewed before inclusion: allowlisted metadata only
(opaque mapping generations, byte counts, lengths,
timestamps, pool samples, observed name scope). No payloads,
keys, raw addresses, command lines, or host identifiers.

## Try it

From the bundle root (or a source checkout, with
`build/memveil` in place of `bin/memveil`):

    bin/memveil report --format text examples/lifecycle-copy
    bin/memveil report --format json examples/lifecycle-copy
    bin/memveil report --format markdown examples/lifecycle-copy
    bin/memveil top examples/lifecycle-copy

Expected: exit 4, `bounce_attempts = 208`,
`copy_original_to_bounce_bytes = 35002`,
`copy_bounce_to_original_bytes = 24784`,
`completed_lifetime_count = 208`, detail loss 0. Text and
Markdown show captured `kernel.release`,
`profile.decision`, `measurement_scope`, and duration
`150.175546150 s (150175546150 ns)`.
