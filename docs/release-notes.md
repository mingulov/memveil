<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil 0.1.0 release notes (development bundle)

Status: **pre-release development bundle**. No version tag exists;
`0.1.0` names the bundle layout, not a supported release. The
supported configuration is exactly `docs/support.md`; anything
outside it is unbound or refused. Counts below are the final
re-gate evidence at this revision.

## What this bundle contains

- `record`: SWIOTLB bounce-attempt capture with attach-anchored
  window/deadline, debugfs pool sampling (capacity/used/high-water),
  and fail-closed admission (profile binding, bridge, privilege).
- `report` / `top`: offline replay with exact-replay accounting:
  current/peak/cumulative exposure, exposure byte-time, mapping
  lifetimes (mean/p50/p95), per-device and per-direction splits,
  region lineage with generations, per-metric evidence confidence
  (`high` / `medium`; `proxy` is reserved, no emitter yet).
- `doctor`: passive environment probe (no privileges needed).
- Machine-readable outputs: text, JSON, Markdown; JSON schemas
  `schemas/{session,event,report}-v0.1.0.schema.json` with a
  52-case self-oracle (`tools/validate-schemas`).
- Ubuntu 22.04+ offline floor, 24.04+ recording floor; see
  `docs/support.md` for the full envelope.

## Verification (final re-gate, 2026-10-07)

- Test suites: 51 PASS / 3 SKIP / 0 FAIL across 54 lanes, plus
  the 3 commit-gated packaging lanes below. The 3 skips need
  confidential-computing silicon (unavailable here) and are
  reported as skipped, never as success.
- Live VM gates (KVM/virtme-ng, kernel 7.0.0-34-generic, all
  armed): lifecycle, copy semantics, real I/O, stop races,
  saturation, cleanup, oracle comparison, and perf workload —
  all PASS. Soak: 916 cycles in 30.0 min, peak 28636 KiB.
- Coexistence: MemVeil alone, two instances, and MemVeil +
  KryProbe qualified live (see `docs/coexistence.md`);
  p11scope/osslscope pairings not qualified, no recipe given.
- Sanitizers: 0 ASan/UBSan findings on the native bridge
  (instrumented build, privileged native suite 7/7).
- Packaging: owner bundle + clean-room replay + release-runtime
  lanes PASS on `84339ac`; final-HEAD re-run pending (this
  commit adds docs only; bundle bytes unaffected).

## Known limitations

- One validated profile: `linux-x86_64-7.0.0-34-generic`. Other
  kernels run partial or refuse; older kernels (< 7.0) are
  unsupported, not degraded.
- No confidential-computing qualification: SNP/TDX behavior is
  unobserved (no silicon in the test environment). Captures from
  ordinary VMs carry `proxy`-capable evidence only where an
  emitter exists; no proxy emitter ships yet, so nothing is
  silently upgraded.
- Pool high-water reset epoch is declared, not proven: the sampler
  never resets the kernel counter, so equal values across captures
  share one allocator lifetime only when no reset happened between
  them (see `docs/privacy.md` and the report invariant notes).
  The pool reader covers exactly the three documented debugfs
  files; transient/dynamic pools are out of scope.
- `StopController` is unit-tested but not wired into the live
  collector (drains up to 30 s); terminal quality stays partial
  (exit 4) until the stop protocol is proven on the exact profile.
- CI workflows are defined but have never executed (need runners).
- Coexistence recipes: published only for qualified pairings (TBD).

## Compatibility

Report/event/session schemas are `v0.1.0`; compatibility rules live
in `docs/format-compatibility.md`. Capture directories are
self-describing (session.json + events.ndjson) and replay without
the recording host.
