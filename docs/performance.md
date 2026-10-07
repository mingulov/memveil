<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Performance envelope

Correctness gates every number below: each run validates
exact counts and quality before any timing is read, and
invalid runs are excluded by name, never averaged in.

## Replay target (measured)

Fixed 600,000-record synthetic capture (214,148,895 bytes,
under the default 256 MiB bound) with independently known
totals, replayed through the built `report` verb:

| Check | Target | Measured |
|---|---|---|
| wall time | ≤ 60 s | 5.5 s |
| peak RSS | ≤ 256 MiB | 123.5 MiB |
| rate | ≥ 10,000/s | 108,405/s |
| counts | exact | exact |

Prefix scaling is linear (100k in 0.9 s, 300k in 2.7 s). A
paced 60 s FIFO stream at 10,000 records/s completes with
exact counts and steady RSS. Runner: 16-core x86-64 Linux
with 59 GiB RAM; rerun `./tools/test perf-replay` for the
receipt on any other runner.

## Live workload protocol (frozen, unarmed)

Per supported workload: 10 s warmup, 60 s measured window,
at least five interleaved baseline/observer pairs per mode
(off, attached-idle, 1 s summary, detailed record,
saturation) on scratch block and virtual network paths
already proved to reach the admitted hooks. Summary-mode
targets: ≤ 5% throughput decrease, ≤ 10% p99 increase. The
comparison math (`tests/perf/compare.py`) is unit-tested
offline; live runs need qualified probes plus a
`MEMVEIL_VM_PERF=1` lease (`perf-workload` skips unarmed).

## Soak

Thirty mixed minutes of replay cycles (all formats plus
top) with a child-RSS watch; every cycle asserts exact
counts and the 256 MiB envelope. A passing soak makes
no always-on-service claim. Run `./tools/test soak`
(`MEMVEIL_SOAK_MINUTES` overrides the 30-minute default).

## Bottleneck notes

Replay is single-stream and parse-bound; no offline
optimization is warranted at 108k records/s against the
10k/s target. Live overhead is unmeasured until the
workload gate arms — no overhead claim is earned yet.
