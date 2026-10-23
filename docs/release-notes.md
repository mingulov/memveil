<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil 0.1.0 release notes (development bundle)

Status: **attempt/lifecycle/copy development preview**. The version names
development bytes and schema compatibility, not a qualified full release.
The [capability table](support.md#capabilities-by-mode) is the support
contract for shipping collection, offline analysis, and laboratory work.

## What this bundle contains

- `record`: SWIOTLB bounce-attempt capture, requested bytes, attach-anchored
  window/deadline, and readable default-pool capacity/used/high-water
  samples at start, on a best-effort 1 s cadence (cap 4,096), and close,
  plus opt-in mapping-lifecycle and copy-actual channels on the admitted
  profile. Admission checks profile bindings, bridge, and privilege.
  Attempts are not outer DMA successes or actual copies.
- `report`: offline text/JSON/Markdown analysis. Lifecycle, copy, and mapping
  reducers consume the shipped channels on the admitted profile; region and
  pool reducers work only when input supplies their evidence. Allocation
  occupancy and byte-time are distinct from sharing lifetime.
- `top DIR`: periodic summaries of finished-capture replay prefixes.
  `top --output` observes live with provisional prefixes; the final
  answer always equals a replay of the retained capture.
- Human reports expose captured kernel/profile/scope and exact window
  duration. Missing/conflicting provenance remains explicit; an unbound
  capture remains unbound. Full hashes stay available in session/JSON.
- Passive `doctor`, and source/runtime tarball packaging with licenses
  and manifests. The runtime tarball ships the binary, runtime closure,
  BPF objects, profiles, docs, and example; versioned schemas in
  `schemas/` and the standalone build/test wrappers stay in the
  source tree.

## Evidence scope

Release bundle identities: binary sha256
`42c4f0a44d4391b4b71cafe7df8e7f9341a17385cb535fcc14f77e26bf40437a`
(`.deb` sha256
`9494ee0d2a84bbe632191225b397e9749373521fe28b045c78b8ccd5ab0c885c`).
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
builds may produce different BPF bytes and fail recorded bindings.
Do not silently rewrite a profile hash to make them admitted.

## Open release gates and limits

- Periodic pressure sampling, live summary, proven writer settlement,
  and their independent operational qualification remain open. The
  original lifecycle-qualified preview and full confidential first
  release are not complete.
- No real SNP/TDX qualification. Offline region analysis and ordinary-Linux
  conversion calls do not prove a confidential transition. No attestation
  is performed, and observations are not host-access verdicts.
- SEV-SNP guests are detected through the `vmpl` node
  (`/sys/devices/system/cpu/sev/vmpl` beside the sev-guest
  node), fixture-proven; live-proven only after the
  controller's AWS run with this build.
- Pool samples are best-effort reads (start, 1 s cadence capped at
  4,096 with missed ticks skipped, close) and cannot alone diagnose
  sustained pressure. The sampler never resets high-water; equal values
  share an allocator lifetime only if no reset occurred. Dynamic pools
  are outside the reader's scope; see [privacy](privacy.md).
- Live terminal quality stays partial: a finalized capture and a
  quiet ring do not prove writer settlement. The wired close-out
  (detach, 100 ms settle, bounded drain, 100 confirmation polls,
  counter sample, finalize) stamps `stop` evidence with the 5,000 ms
  budget as a completeness threshold; live runs stay partial with
  `quiescence unproven` because no kernel protocol proves settlement.
  `record` exits 4 for a finalized capture, and `report`/`top` exit 0
  only with complete terminal evidence.
- CPU targets and ELF linkage minima are compatibility prerequisites,
  not tests of every claimed platform. See [support](support.md).
- Sustained saturation drains about 153,000 records/s
  (3,118,447 records in 20.33 s on a 4-vCPU guest). A
  busy capture above the 1 GiB default needs
  `report --max-events-bytes` to replay.
- Rows that refuse, with their codes: 5.15 is below the
  6.0 floor; 6.0 through 6.10 refuse lifecycle and copy
  (need 6.11); BTF-less kernels refuse lifecycle and
  copy (`btf-absent-config`); confidentiality lockdown
  refuses everything.
- The 6.0, 6.10, 6.11, and 6.12.0 rows finalize their
  main capture with exact oracle counts but fail the
  busy stop check: the saturated runs stop at the
  4,194,304-record cap with bytes below the 4 GiB cap,
  which the gate does not accept. Attempt loss
  before 6.7 is a lower bound.
- The 6.18.0 kernel leaves several hundred read maps
  unmapped (640 then 384 across runs); the product
  reports them open and the oracle agrees on every
  channel, but the map/unmap invariant and byte checks
  fail, so the row is not qualified. This is a
  [known kernel issue](kernel-issues.md), not capture
  loss.
- The rt busy aggregate falls outside the oracle after
  a slow finalization, and the 6.12, 6.18, and debian13
  busy rows fail closed on oracle sample gaps over 1 s
  at the window edge. Main captures on all four rows
  are exact.
- `forced` mirrors the kernel's swiotlb force bit and is
  not a confidential-guest signal; see
  [privacy](privacy.md).
- The BTF-less row proves attempt counts only; bytes
  stay unproven.
- Passive doctor can read `ready (load not checked)`
  while the memcg precheck reports `memcg-headroom`
  unknown; only `doctor --load-check` or a record proves
  the load fits. Detection scenarios pass 10 of 12 on
  the 7.0 guest: `nocaps` cannot execute under
  `capsh --drop` in the guest, and the `memcg` limit
  does not block the load probe, so neither gate is
  proven live for this bundle.

## Compatibility

Current output versions are report `v0.1.1` and
session `v0.1.2`; events stay at `v0.1.1`. Readers still
accept the retained session `v0.1.1` contract (frozen;
without correlation relations), while report readers
require `v0.1.1` - the `v0.1.0` report schema file stays
for reference only. Full reader rules live in
[format compatibility](format-compatibility.md). Captures are self-describing
and replay without the recording host or native bridge. JSON metric meanings,
integer values and exit policy are unchanged by the human-context correction.
