# Independent oracles

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

MemVeil checks itself with oracles that never import reducer code
and never apply reducer math. Each oracle below states what it
proves, what it cannot prove, and how to run it. A passing oracle
proves only its own boundary; read the scope limit before citing
a result.

## Capture validator (`tools/validate-schemas`)

Validates a capture directory against the versioned external
schemas in `schemas/`, then independently recomputes the attempts
slice (counts, bytes, window membership, identity resolution)
from the raw records. Python standard library only.

Scope limits:

- Only the attempts slice is recomputed. Lifecycle, region, and
  pool metrics are schema-checked, not independently recomputed.
- Strict mode requires every mapping reference to resolve
  inside the capture. Partial-capture recovery belongs to the
  product reader, not to this tool.

Run the built-in acceptance suite (49 cases) with no arguments;
validate one capture by passing its directory. The reports lane
runs this tool over generated JSON reports to recompute counts
independently of the renderer.

## Owned-DMA ledger (`tests/vm/oracle_ledger.py`)

Ground truth for live DMA traffic. The test-only kernel module
`tests/kernel/memveil_dma_oracle.c` drives scripted map, sync,
and unmap calls against its own synthetic platform device and
logs every raw call; the harness replays that log into the
ledger, which counts expectations directly from raw entries.
Lifetime quantiles are checked as exact bucket membership of
the true nearest rank, and `compare()` matches a finished JSON
report against the sealed ledger with any mismatch failing
the gate.

Scope limits:

- Scripted traffic only: four transfer sizes (512, 1024, 2048,
  4096 bytes), clean map/unmap cycles, one double sync, and one
  mapping held open until unload.
- The module binds no real hardware, performs no DMA to real
  devices, and refuses to load without `mv_oracle_arm=1`.
  Loading happens only inside the disposable VM gate.

The region oracle (`tests/kernel/memveil_region_oracle.c`)
plays the same role for shared/private conversions: it
converts two of its own contiguous pages with the native
`set_memory_decrypted`/`set_memory_encrypted` APIs, logs every
native return code plus the owned PFN range, and the harness
compares that log against MemVeil's observed conversion
records. It covers owned pages only, never real guest memory.

## Fuzz oracle (`tests/fuzz/run.py`)

Replays deterministically mutated seed captures through the
built report verb. Every case must exit 0, 2, or 4 with no
crash marker on either stream; exit 2 must leave stdout empty
and stderr non-empty; exit 0 and exit 4 must emit valid
JSON.

Scope limits:

- Exit 4 output must parse as JSON but is not schema-checked.
- Mutation covers replay robustness, not kernel semantics.

## Soak gate (`tests/perf/soak.py`)

Replays a 50,000-attempt capture in a loop (default 30
minutes) through the text, Markdown, and JSON renderers plus
one `top` refresh block per cycle, and asserts peak child RSS
stays within 256 MiB.

Scope limits:

- Every cycle asserts exact counts and byte totals in JSON,
  text, and Markdown, the detail-channel quality in JSON,
  and the exact count in the `top` final summary. Deeper
  renderer content is covered by the reports lane goldens
  and the JSON recompute above.

## Native reference extractor (`tests/native/test_attempt_decode.c`)

Decodes attempt wire bytes with a C implementation that
deliberately mirrors the BPF encoder and shares validation
helpers. Agreement between the two is transport evidence that
the bytes survive the ring; it is not an independent
kernel-semantic oracle.

## Which oracle for which claim

| Claim | Oracle |
|---|---|
| A capture directory is well formed and its attempts add up | `tools/validate-schemas` |
| Live DMA counts match driver reality | owned-DMA ledger |
| Observed conversions match native transitions | region oracle |
| Replay never crashes or mis-exits on corrupt input | fuzz oracle |
| Long replays hold counts and memory | soak gate |
| Wire bytes survive the ring intact | native reference extractor |
