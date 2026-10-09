<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil 0.1.0 release notes (development bundle)

Status: **attempt/lifecycle/copy development preview**. The version names
development bytes and schema compatibility, not a qualified full release.
The [capability table](support.md#capabilities-by-mode) is the support
contract for shipping collection, offline analysis, and laboratory work.

## What this bundle contains

- `record`: SWIOTLB bounce-attempt capture, requested bytes, attach-anchored
  window/deadline, and optional readable default-pool capacity/used/high-water
  samples at start and close, plus opt-in mapping-lifecycle and copy-actual
  channels on the admitted profile. Admission checks profile bindings, bridge,
  and privilege. Attempts are not outer DMA successes or actual copies.
- `report`: offline text/JSON/Markdown analysis. Lifecycle, copy, and mapping
  reducers consume the shipped channels on the admitted profile; region and
  pool reducers work only when input supplies their evidence. Allocation
  occupancy and byte-time are distinct from sharing lifetime.
- `top DIR`: periodic summaries of finished-capture replay prefixes.
  Live summary remains required work.
- Human reports expose captured kernel/profile/scope and exact window
  duration. Missing/conflicting provenance remains explicit; an unbound
  capture remains unbound. Full hashes stay available in session/JSON.
- Passive `doctor`, versioned schemas in `schemas/`, standalone build/test
  wrappers and source/runtime tarball packaging with licenses and manifests.

## Evidence scope

Earlier development receipts and CI successes apply to their recorded
revisions, binaries, BPF objects and environments. They are historical
evidence, not a final re-gate of every later candidate. Laboratory lifecycle,
copy and oracle lanes compare decoded probe records or synthetic translated
reports; see [oracles](oracles.md). Shipping lifecycle/copy qualification
comes from the shipped-record VM gates on the admitted profile, not from
these laboratory comparisons. Historical replay/performance and coexistence
experiments likewise do not establish current-candidate live overhead or
pairing support; see [performance](performance.md) and
[coexistence](coexistence.md).

For a candidate, retain exact source and dependency revisions, source/runtime
archive hashes, manifest verification, observed toolchain, binary/BPF/profile
identities, commands, expected/actual results and cleanup. Compiler-free
offline replay is a packaging boundary; collection additionally needs its
exact bound profile/environment and independent live oracle. Source-export
builds may produce different BPF bytes and fail the existing narrow binding.
Do not silently rewrite a profile hash to make them admitted.

## Open release gates and limits

- Periodic pressure sampling, live summary, proven writer settlement,
  and their independent operational qualification remain open. The
  original lifecycle-qualified preview and full confidential first
  release are not complete.
- No real SNP/TDX qualification. Offline region analysis and ordinary-Linux
  conversion calls do not prove a confidential transition. No attestation
  is performed, and observations are not host-access verdicts.
- Two default-pool boundary samples cannot diagnose sustained pressure.
  The sampler never resets high-water; equal values share an allocator
  lifetime only if no reset occurred. Dynamic pools are outside the reader's
  scope; see [privacy](privacy.md).
- Live terminal quality stays partial: a finalized capture and a
  quiet ring do not prove writer settlement. The wired close-out
  (5,000 ms budget, bounded drain, counter sample, finalize)
  stamps `stop` evidence; live runs stay partial with
  `quiescence unproven` until the kernel protocol proves
  settlement. `record` exits 4 for a finalized capture.
- CPU targets and ELF linkage minima are compatibility prerequisites,
  not tests of every claimed platform. See [support](support.md).

## Compatibility

Report schemas are `v0.1.0`, event/session schemas `v0.1.1`;
reader rules live in
[format compatibility](format-compatibility.md). Captures are self-describing
and replay without the recording host or native bridge. JSON metric meanings,
integer values and exit policy are unchanged by the human-context correction.
