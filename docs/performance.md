<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Performance envelope

Performance evidence is specific to source, binary, input and environment.
Validate counts and quality before reading timing; exclude invalid runs by
name. Historical development measurements do not qualify a rebuilt package.
See the [support table](support.md#capabilities-by-mode) for the shipping modes.

## Replay protocol and targets

`./tools/test perf-replay` generates a fixed 600,000-record synthetic
capture (214,148,895 bytes, under the default 1 GiB input cap) with
independently known totals. It measures the built `report` verb and verifies
prefix scaling and a paced FIFO stream. Targets are at most 60 seconds,
at most 256 MiB userspace RSS and at least 10,000 records/second, with exact
counts. Earlier documentation reported 5.5 seconds and 123.5 MiB on a
16-core x86-64 runner with 59 GiB RAM; those are historical development
observations, not current-artifact results or a live-path overhead limit.

## Region scaling protocol

`./tools/test perf-region` replays mixed attempt/mapping/
fragmented-region captures with known unions and lifetimes at
doubling big-region sizes up to the admitted 65,536-segment
ceiling, plus one active-mapping ceiling step with a small
fragmented region and 66,000 mappings peaking at 65,535
simultaneously open lifetimes, one slot under the admitted
active-mapping ceiling. Each scale step pairs a large
fragmented region (one shared span with doubling private
holes) with a small region churned after the fragments are
fully built, so every churned update meets the full
fragmented state, plus background mappings held at a
controlled peak of open lifetimes. An independent
interval oracle, itself checked against the pinned region
fixtures, recomputes every union and count; the lane asserts
exact equality first, then the envelope: at most 60 seconds
per scale replay and at most 256 MiB peak RSS, with throughput
reported next to the replay target above. The workload and
envelope are declared at the top of
`tests/perf/region_replay.py`; historical development
measurements do not qualify a rebuilt package.

## Live workload protocol

The laboratory protocol uses 10 seconds warmup, a 60-second measured window
and at least five interleaved baseline/observer pairs per mode on scratch
block and virtual network paths independently proved to reach the hooks.
`./tools/test perf-workload` requires its explicit
`MEMVEIL_VM_PERF=1` lease; an unarmed lane skips, and an armed result proves
only the tested mode and artifact. Offline comparison math and raw probe
traffic do not qualify shipping lifecycle accounting.

`./tools/test perf-overhead` measures product collector cost on the
admitted guest kernel: a fail-fast probe (one summary leg plus one
attached-idle leg) then a 40-leg campaign (5 rounds; every observed
mode paired with its own matched off leg in seeded order) over fixed
scratch block and virtual network workloads. Modes are off (bare
control), attached-idle (a three-channel record held stopped across
the measured window), summary (attempt-trace record), detail
(three-channel record), and undersized-buffer (lab consumers on the
4 KiB test rings). The lane requires its explicit `MEMVEIL_VM_PERF=1`
lease; an unarmed lane skips, and an armed result proves only the
tested modes and artifact. The workload, modes, and envelope are
declared at the top of `tests/perf/overhead.py` and
`tests/vm/overhead_guest.py`.

Summary-mode targets are at most 5% throughput decrease and at most 10% p99
increase on the documented reference workload, with at most 256 MiB peak
userspace RSS per leg and BPF memory reported separately. Detail,
attached-idle, and undersized-buffer ratios report as measured without
thresholds; a summary ratio outside the targets is a declared
limitation, never a silent pass. One measured campaign on source
`f8f0b1a` (binary `d9ebadb7`, narrow 7.0.0-34-generic profile)
qualified 20/20 pairs with at least 10 s warmup and at least 60 s
measured workload inside every collector window: summary ping
throughput missed its target (ratio 0.929) while summary p99
(1.083) and summary dd (1.002) passed, worst per-process peak
RSS was 66.2 MiB with a worst aggregate bound of 96.3 MiB on
the two-consumer lab legs, and every leg's losses stayed
explicitly accounted. Those are historical development
observations, not current-artifact results; a rebuilt package
re-runs the lane.

## Soak

`./tools/test soak` runs 30 mixed minutes of replay cycles across formats
and replay `top`, checking exact counts and child RSS.
`MEMVEIL_SOAK_MINUTES` changes the duration. A passing replay soak makes
no always-on-service claim and does not exercise real collection, writer
settlement or confidential guests. Retain binary and input hashes, the
command, duration, cycle count, RSS, counts, quality and cleanup for each run.
