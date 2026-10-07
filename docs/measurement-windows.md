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

Stopping runs six stages in order, implemented by
`src/memveil/capture/stop.mojo` and mirrored by the live
collector close-out:

1. `readiness` — measurement ran under a proved session epoch.
2. `admission-close` — no new writer may begin.
3. `quiescence` — every admitted writer settled (exited its
   callback). This waits for BPF callbacks only.
4. `bounded-drain` — records move to a proved transport
   boundary within the poll budget.
5. `counter-sample` — the final counter cut is read.
6. `finalize` — terminal evidence is written.

The default stop budget is 5000 ms of monotonic time, recorded
in the evidence beside the elapsed time. The budget bounds
waiting; a deadline never establishes quiescence.

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
  partial, not complete.
- Open logical DMA mappings never block quiescence. The
  controller waits for callbacks, not for logical mappings to
  end; the count of mappings still open travels beside the
  verdict so lifetimes stay censored instead of invented.

## Kernel-side protocol (staged)

`bpf/include/memveil_control.h` inventories the current probe
writers and stages an explicit control map (admission epoch
plus active-writer count). Wiring it into the probe changes
the BPF object and needs a fresh profile qualification first;
until then the consumer-side stages above carry the proof.
