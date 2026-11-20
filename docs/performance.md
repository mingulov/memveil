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
prefix scaling and paced regular-file reads. Targets are at most 60 seconds,
at most 256 MiB userspace RSS and at least 10,000 records/second, with exact
counts. Earlier documentation reported 5.5 seconds and 123.5 MiB on a
16-core x86-64 runner with 59 GiB RAM; those are historical development
observations, not current-artifact results or a live-path overhead limit.

The default paced leg still reads all 600,000 records over 60 seconds. A test-only
`fread` adapter calls the real reader, counts bytes/newlines in the returned
buffer, and delays return to cumulative monotonic deadlines. It never generates
records or reports and never prebuffers the input; each actual product read is
at most 64 KiB. Independent receipt checks require the same regular-file identity,
exact byte/record totals, reached EOF, bounded requests and the full paced duration.
The product still parses and reduces every record. Exact byte arithmetic and the
256 MiB RSS check also apply to this leg. The adapter's negative controls reject
missing, short, unpaced or unbounded read evidence.

This replaces FIFO use as a benchmark transport; capture inputs are regular files
for all supported versions. No live FIFO replay interface is advertised.
`MEMVEIL_PACED_SECONDS` selects a shorter laboratory variant; qualification uses
the default full 60-second workload. Pacing tests reader behavior under delayed
input delivery and does not qualify live capture or physical storage durability.

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

The region reducer keeps sorted, disjoint intervals separately for each
proved lineage. An update finds its overlap with two binary searches,
replaces that span, and merges adjacent equal states. Only the affected
lineage's tail moves; unrelated lineages are never rebuilt or sorted.
The global segment budget is checked on the merged result before mutation.
Exhaustion still invalidates the affected lineage and excludes its state.
Storage is compacted after a lineage shrinks below half its retained high
water mark, so cycling large lineages cannot accumulate retained capacity.
Arbitrary insertion order can still require a linear tail move; the fixed
scale rows and independent interval/lifetime oracles remain the acceptance
checks. The historical 95.1-second largest-row miss remains a failed
measurement; a new implementation needs fresh exact-artifact evidence.

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

## Exact packaged qualification

Set both `MV_BUNDLE_TARBALL` and `MV_CANDIDATE_MANIFEST` to retained immutable
candidate files, optionally pinning `MV_CANDIDATE_DIGEST`. The qualification
loader verifies the canonical manifest, archive hash, full file closure,
source, toolchain and build receipt before executing anything. Each process
extracts into its own exclusive temporary directory. It never rebuilds the
product. Artifact roles such as deb and rpm resolve beside the candidate
manifest and must match its hashes. Existing `MEMVEIL_BIN`, `MV_DEB`, `MV_RPM`,
library injection and similar product overrides are refused. A fuzz `--binary`
may only name the loader's verified executable. Development runs without these
inputs retain their existing scope; unsupported qualification suites fail
closed.

`tools/test perf-replay`, `perf-region`, `soak`, `privacy`, `fuzz-smoke`,
`fuzz-campaign`, `perf-overhead`, `vm-live-soak`,
`vm-kernels`, `vm-scenarios`, `extracted-robustness`, `package`,
`release-runtime`, `deb` and `rpm-journey` consume the selected bytes. The
extracted robustness suite reuses the supplied archive. Pacing remains
600,000 records over 60 seconds and the region ceiling remains 65,536
segments. Native pacing/oracle helpers retain separate identities; they do
not replace candidate product bytes. The `deb` and `rpm-journey` suites
launch prebuilt executables: run
`tests/support/journey_prep.py .candidate-prep/records/prep.json`
first and
point `MV_JOURNEY_PREP` at its record; dispatch refuses without it and
never invokes a build itself.

`MEMVEIL_VM_PERF=1 tools/test perf-overhead` in candidate mode installs the
verified deb in an ephemeral guest and runs five separately paired baseline
runs for each of `attempt-record-summary`, actual `live-top-1s`, no-stack
`journal-summary`, and `journal-callers-detail`. Summary targets remain at
most 5% throughput decrease and 10% p99 increase. Caller-enabled journal
detail is reported separately. Live top must cover the measured window with
one-second refreshes: adjacent refreshes must remain within 0.5–1.5 seconds,
both window edges within 1.5 seconds, and at least 59 refreshes for a
sixty-second window. Missing middle intervals or startup bursts fail. Missing
or unadmitted requested journal support skips its row with a recorded reason;
an attach refusal is never a performance pass.

`perf-workload` is DEFERRED under qualification inputs: the sealed
candidate carries no retired perf-workload guest inputs, so dispatch
skips the suite with its recorded reason instead of executing it. It
remains a laboratory consumer measurement in development runs only; it
never executes against candidate bytes and never produces a
product-summary receipt.

Installed campaign workload units are a 16 MiB direct scratch read and 32
paced packets to the guest's emulated peer, run concurrently. Each leg warms
for ten seconds and measures for at least sixty. Throughput counts completed
bytes/packets over wall time. p99 is the nearest-rank latency of those
complete operations, including helper process overhead; it is not per-request
device or per-packet latency. The exact same protocol runs in each paired
baseline.

`MEMVEIL_VM_LIVE_SOAK=1 tools/test vm-live-soak` requires the same candidate
inputs. It runs repeated one-minute captures with concurrent scratch block
and peer-network traffic for at least thirty measured active minutes, then
one 4,260-second live capture whose pool samples must span more than seventy
minutes. Readiness, warmup, reporting and cleanup time never count toward
the thirty-minute total; campaign wall time is reported separately. The pool
case uses one 16 KiB direct read and one peer packet per second so it
exercises the full sampling duration within the default event-byte budget; it
is not an overhead measurement. The first 4,096 periodic pool samples must
demonstrate timed coverage. After that routine cap, quiet sampling
legitimately stops persisting records. A separately identified intrusive
pool-only `strace` oracle therefore checks positive reads of the exact
used/capacity debugfs paths through the measured post-cap interval, excluding
finalization. Each label needs at least 4,096 reads; gaps above three seconds
or bursts below half a second fail. Trace delivery must remain within 250 ms.
The tracer, parser, candidate executable, process start identity and guest
nonce are bound in the receipt. Raw trace lines remain in bounded memory;
only labels, positive byte counts and monotonic receive timestamps are
retained. The oracle is never attached on overhead legs and proves read
cadence, not pressure behavior. The repeated-capture case retains the mixed
workload specified above. It records all quality channels, stop facts,
process RSS/FD samples, BPF program/map/link inventories, installed byte
identities, capture hashes and cleanup. Userspace RSS remains bounded by
256 MiB; map memory is reported separately and unknown map memory stays null.
Captures and progress remain in the exported evidence directory. Failed
captures and checkpoints are retained with bounded, allowlisted exports and
failure observations. Independent cleanup/export failures do not replace the
original product exit; export failure leaves the owned local evidence in a
second host-backed evidence directory. Failure exports are explicitly
unverified. This is distinct from the offline replay `soak` suite.

Live campaigns require the pinned VM tool versions, KVM, root in the
isolated guest, and the exclusive suite lease. The host root remains
read-only; package installation uses guest overlays, the scratch NVMe image
is created for that one run, and cleanup addresses only the owned guest
process group and scratch image. Unarmed live soak exits 77. Armed missing
prerequisites, capture refusal, quality/loss failures or cleanup failures
fail the campaign. An ordinary guest receipt makes no confidential-platform
qualification claim.
