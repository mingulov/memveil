<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Measurement windows and terminal evidence

A capture directory holds one measurement window: `session.json`
carries the window bounds plus readiness metadata, and
`events.ndjson` carries the ordered records inside it. This note
defines how a window starts, how it stops, and what the terminal
evidence may claim.

## Startup readiness

Recording begins only after the collector proves readiness:
the BPF object is loaded, every expected map has its admitted
geometry, attachment succeeded, and the first counter read
established the session epoch. Events observed before readiness
are not part of the window and never appear in the capture.

## Stop stages

Stopping runs six stages in order, implemented and
unit-tested by `src/memveil/capture/stop.mojo`:

1. `readiness` — measurement ran under a proved session epoch.
2. `admission-close` — no new writer may begin.
3. `quiescence` — every admitted writer settled (exited its
   callback). This waits for BPF callbacks only.
4. `bounded-drain` — records move to a proved transport
   boundary within the poll budget.
5. `counter-sample` — the final counter cut is read.
6. `finalize` — terminal evidence is written.

The scripted stop budget is 5000 ms of monotonic time,
recorded in the evidence beside the elapsed time. The budget
bounds waiting; a deadline never establishes quiescence.

The live collector close-out does not run this controller
yet. It detaches, sleeps 100 ms, then drains with a 30 s /
100,000-poll budget, declaring quiet when the staged count
is zero and received/malformed hold still across two reads.
There is no wired admission-epoch or active-writer protocol
(the kernel control map is staged, not wired), so the live
drain cannot observe admission-close or callback quiescence.

## Complete versus partial

`complete` requires every stage proved: admission closed,
quiescence observed, drain reached its boundary with no BUSY
record outstanding, and the final counter sample valid. Any
gap — unsettled writers, a missing drain, BUSY at the
boundary, a failed sample, or budget exhaustion — yields
`partial` with a named reason and exit 4, never a silent
complete.

Two separations are load-bearing:

- A quiet ring proves nothing by itself. Zero drained records
  with unsettled writers (or without observed quiescence) is
  partial, not complete. The live collector's drain uses
  exactly this quiet-ring signal, which is why live terminal
  quality stays `partial` ("terminal settlement unproven")
  and live captures exit 4.
- Open logical DMA mappings never block quiescence. The
  controller waits for callbacks, not for logical mappings to
  end; the count of mappings still open travels beside the
  verdict so lifetimes stay censored instead of invented.

The `drain_closure` provenance item has a precisely narrow
meaning: `proven` means only that close-out noted no
deviation (no failed detach, no drain error, no exhausted
budget, no unresolved snapshot). It does not claim the six
stages above; the terminal channel stays `partial` beside it.

## Kernel-side protocol (staged)

`bpf/include/memveil_control.h` inventories the current probe
writers and stages an explicit control map (admission epoch
plus active-writer count). Wiring it into the probe changes
the BPF object and needs a fresh profile qualification first;
until then the consumer-side stages above carry the proof.
