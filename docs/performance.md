<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Performance envelope

Performance evidence is specific to source, binary, input and environment.
Validate counts and quality before reading timing; exclude invalid runs by
name. Historical development measurements do not qualify a rebuilt package.
See the [support table](support.md#capabilities-by-mode) for the shipping modes.

## Replay protocol and targets

`./tools/test perf-replay` generates a fixed 600,000-record synthetic
capture (214,148,895 bytes, under the default 256 MiB input cap) with
independently known totals. It measures the built `report` verb and verifies
prefix scaling and a paced FIFO stream. Targets are at most 60 seconds,
at most 256 MiB userspace RSS and at least 10,000 records/second, with exact
counts. Earlier documentation reported 5.5 seconds and 123.5 MiB on a
16-core x86-64 runner with 59 GiB RAM; those are historical development
observations, not current-artifact results or a live-path overhead limit.

## Live workload protocol

The laboratory protocol uses 10 seconds warmup, a 60-second measured window
and at least five interleaved baseline/observer pairs per mode on scratch
block and virtual network paths independently proved to reach the hooks.
`./tools/test perf-workload` requires its explicit
`MEMVEIL_VM_PERF=1` lease; an unarmed lane skips, and an armed result proves
only the tested mode and artifact. Offline comparison math and raw probe
traffic do not qualify shipping lifecycle accounting.

Summary-mode targets are at most 5% throughput decrease and at most 10% p99
increase. Live `top` is not implemented, so replay `top` cannot qualify that
mode. Detailed-attempt recording, attached-idle, and saturation results must
be recorded separately. No current-candidate live overhead claim is earned
from historical lane successes.

## Soak

`./tools/test soak` runs 30 mixed minutes of replay cycles across formats
and replay `top`, checking exact counts and child RSS.
`MEMVEIL_SOAK_MINUTES` changes the duration. A passing replay soak makes
no always-on-service claim and does not exercise real collection, writer
settlement or confidential guests. Retain binary and input hashes, the
command, duration, cycle count, RSS, counts, quality and cleanup for each run.
