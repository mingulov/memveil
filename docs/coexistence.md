<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Running MemVeil alongside other observers

MemVeil records SWIOTLB bounce activity through its own BPF
programs and output directory; it shares nothing with other
tracing tools except the kernel facilities they each attach to.
Joint operation below is listed only where it was actually run
and both tools finalized cleanly. Anything unlisted is untested
with MemVeil, not implied-safe.

## Qualified: MemVeil + KryProbe (kcrypto)

KryProbe (Linux runtime cryptographic observer,
`github.com:mingulov/kryprobe`, qualified at `7896a5a`) was run
concurrently with MemVeil 0.1.0 (`84339ac`) on x86-64 Linux
7.0.0-34-generic: process isolation, independent crypto/disk
workloads, and five interleaved 60 s performance rounds. Every
run finalized on both sides with zero integrity-counter loss on
KryProbe's side.

Recipe (root; separate output directories are required):

```bash
memveil record --output ./mv-capture \
    --object ./swiotlb_attempt.bpf.o --duration 60 &
```

```bash
kryprobe report --system --duration 60 --format json \
    --out ./kry-capture/report.jsonl &
wait
```

Run the first command, then the second, in one shell: two
background jobs and one `wait`, so both 60 s windows align.

Notes:

- KryProbe exits 3 with a `partial` verdict listing exactly
  `capture-integrity` and `completion` as missing. That is its
  documented healthy shape for this version, not a coexistence
  failure — provided every integrity counter in `report.jsonl`
  is zero. Any nonzero counter or any other `missing` entry
  fails the run; do not attribute it to MemVeil without
  reproducing KryProbe alone first.
- Keep the captures' windows aligned (same `--duration`,
  started together) so per-tool timelines stay comparable.
  Compare each tool against its own baseline only: MemVeil byte
  counts and KryProbe operation observations share units with
  nothing.
- Two MemVeil instances recording concurrently to distinct
  directories are likewise qualified.

## Not qualified

- MemVeil + p11scope and MemVeil + osslscope: attempted, but the
  reference tool reported its own native PARTIAL verdict in this
  environment (reproduced with the reference tool running
  alone), so the pairings are not qualified and no recipe is
  given. A missing reference tool is reported as not-tested,
  never silently treated as passing.
- Any other observer, any other kernel, or any other KryProbe
  revision: untested.
