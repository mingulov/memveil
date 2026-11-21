<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Lifecycle/copy stress consumer and pair runner

Test-only replacement for the retired `mv_consume` consumer plus
the stress-only pair runner. The runner resolves two named
lifecycle/copy object pairs (pre-change baseline, current
candidate), passes those paths to the same Rust consumer, and
compares identity-miss behavior across the pair. Product code
is untouched; compat logic for the retired maps lives in this
harness only and never weakens the shipping gates.

## Files

- `Cargo.toml`, `Cargo.lock`, `src/` — the `stress-consume`
  binary (crate `memveil-stress-consumer`). One pinned Aya
  loader (`aya 0.14.0`, `aya-obj 0.3.0`, locked) drives both
  object families; decoding reuses the shared
  `memveil-ebpf-common` wire decoders plus the retired
  consumer's semantic relation checks.
  - `src/layout.rs` — offline ELF probe: family selection by
    exact map-set match (the legacy lifecycle set keeps the
    retired `mv_gen_quarantine`/`mv_gen_dark` maps) plus the
    exact program set per channel.
  - `src/btf.rs` — minimal kernel-BTF reader resolving the
    copy-channel field table installed before attach.
  - `src/main.rs` — CLI, live consume flow, and the offline
    `--self-check` / `--verify-layout` / `--replay` /
    `--resolve-copy-table` surfaces.
- `stress_core.py` — pinned pairs and candidate binding,
  host byte verification, input manifest plus stamps, wire
  test vectors, and the pure leg judge and pair comparison.
- `stress_guest.py` — in-guest flow for one boot: per-leg
  identity controls, a quiet phase, and a paced overlap
  phase with per-vCPU flood legs and bpftrace counts.
- `../test_stress_consumer.py` — the runner: unarmed
  offline self-test by default; the armed pair run needs
  `MEMVEIL_VM_STRESS=1` and the live-VM lease.

## Consumer CLI

```
stress-consume [--expect-sha256 HEX] [--expect-family aya|c]
    <elf> <ring> <prog:symbol,...> <seconds> <out>
stress-consume --self-check
stress-consume --verify-layout <elf> <ring>
stress-consume --replay <wire> <ring> <out> --counts o,ob,e,eb,f,fl
stress-consume --resolve-copy-table [--btf PATH]
```

`<ring>` is `mv_lifecycle` or `mv_copies`; sites must name
exactly the channel program set. Exit 0 on a healthy window,
77 on privilege denial (EPERM anywhere, EACCES at attach;
load-time EACCES fails closed), 2 on usage errors, 1 on
anything else (including an unhealthy retained window).

Event lines keep the laboratory grammar (`lc ...`, `cp ...`,
one closing `summary ...`), preserving emitted generations,
ordinals, and receive order; the summary derives from actual
ring reads, delivery outcomes, and `mv_counts` snapshots.

## Runner CLI

```
python3 tests/vm/test_stress_consumer.py [--self-test]
python3 tests/vm/test_stress_consumer.py \
    --inputs baseline=LC,CP --inputs c9=LC,CP --out DIR
```

Unarmed (default, no lease): the offline suite — pinned-byte
verification, consumer build, both layouts, wrong-pair and
malformed-wire refusals, replay determinism, judge and
comparison unit cases, manifest checks. Armed (prepared, not
run here): one pinned boot with both legs, host re-derivation
of every verdict, stamped receipts under `--out`.

## Live procedure (scheduled separately)

With the exclusive VM lease held: build the consumer,
materialize and verify both pairs, write the input manifest,
boot one guest, run baseline then candidate with fresh maps
per leg (controls, 200-op quiet, 2000-op paced plus flood),
verify both oracle logs, block deltas, and workload overlap,
require identity closure and two-ring conservation per leg,
both miss rates at or under 0.5, and the candidate ratio at
or under baseline. A higher candidate ratio is a regression
even under the ceiling; an empty or incomplete window leaves
the pair blocked, never passed.
