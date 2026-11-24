<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil 0.2.0 release notes (development bundle)

Status: **attempt/lifecycle/copy development preview**. The version names
development bytes and schema compatibility, not a qualified full release.
The [capability table](support.md#capabilities-by-mode) is the support
contract for shipping collection, offline analysis, and laboratory work.

0.2.0 rebuilds the userspace in Rust: collection, CLI, and reporting
come from the Cargo workspace, the BPF loader is statically linked,
and the inspection objects are embedded in the binary. The 0.1.0
bundle notes below stay as the history of that prerelease.

## Known issues

> **What this RnD release is — and is not**
>
> MemVeil 0.2.0 is a research-and-development preview for
> explaining SWIOTLB bounce behaviour from inside an ordinary
> x86-64 Linux guest. It records bounce *attempts* (try-counts
> and requested bytes), mapping lifetimes, and executed bounce
> copies, and replays captures offline. Read this before relying
> on any number it prints:
>
> - **Not qualified on confidential VMs.** Collection is not
>   qualified on AMD SEV-SNP, Intel TDX, or Hyper-V confidential
>   guests. One historical SEV-SNP run exists (older binary);
>   TDX has not been run. Ordinary-Linux results do not transfer.
>   MemVeil performs **no attestation** and its output is **not evidence about what a host or hypervisor did or could read**, and not a verdict on guest confidentiality.
>   `doctor`'s guest line (e.g. `guest: snp`) is a kernel-reported
>   signal, not platform proof.
> - **Attempts are not copies, and inner success is not DMA
>   success.** `bounce_attempts` counts tries; only the copy
>   channel reports bytes actually copied. A successful inner
>   allocation can still be followed by outer DMA failure.
>   **Unmapping is not erasure or re-privatization**: an
>   unmap/release ends a mapping lifetime; it says nothing about
>   later accessibility of the underlying pages.
> - **Exit 0 does not mean a complete measurement.** `record`,
>   `report`, and `top` exit 0 for valid output with *partial*
>   evidence (live terminal quality is partial by design). Read
>   the `verdict:` line, or pass `--strict` in scripts (exit 4
>   unless the verdict is `complete`). Rows shown as
>   `unavailable`/`withheld` mean "not measured" — never zero.
>   "No findings" means no diagnostic fired, not that the
>   condition was absent.
> - **Only the exact tested artifact is tested.** Kernel-matrix
>   results name one binary by hash (see release notes); the
>   matrix ran bundle mode of the canonical binary, byte-identical
>   to the `.deb` install (all three package binaries share one
>   sha256). Rows
>   not listed as PASS for this build were not run on this build.
>   A machine-local `qualify` receipt records that a smoke
>   capture worked on one host; it is not release qualification
>   and does not hash the memveil executable — re-run `qualify`
>   after any reinstall. Pool samples cannot diagnose sustained
>   pressure, and saturation (~153k records/s, lower pre-6.7)
>   degrades to partial/unknown rather than blocking.
> - **Metadata only, with fingerprints.** Captures contain
>   allowlisted measurement metadata only — no payload bytes,
>   keys, PINs, content hashes, raw addresses, full command
>   lines, or environment dumps (the shipped collector also never
>   writes process names/ids; the format reserves a
>   never-rendered execution-context block for other producers —
>   check a foreign capture before sharing it). Captures *do*
>   contain a per-boot identifier, device PCI names, and
>   kernel/build hashes: share a capture like you would share a
>   `dmesg` — deliberately, not anonymously.
> - **Privilege.** Recording needs root in the initial user
>   namespace (BPF load + tracefs); there is no supported
>   capabilities-only mode. Replay (`report`, `top DIR`) and
>   passive `doctor` are unprivileged and make no network
>   connections. This is an RnD prerelease: verify downloads with
>   the signed `SHA256SUMS.txt`; build from source if you need a
>   stronger chain — signed release custody returns at 1.x.

**Exit 0 does not mean complete measurement. Read the `verdict:` line, or pass `--strict` in scripts.**

Finalized session 0.1.4 captures now bind and verify literal event bytes,
counts, kinds and contiguous sequences. Report 0.1.4 exposes verified
bytes/events. Finalized corruption returns 2 with or without partial mode.
Legacy input remains readable with unverified arithmetic and no complete
channels; normal mode returns 0 and strict mode returns 4. This source change
does not qualify older packaged artifacts. See [capture integrity](capture-integrity.md).

New captures allocate a synced 17 MiB finalization reserve and publish a durable
empty checkpoint before readiness, then checkpoint every 10 seconds or 1,000
committed events. With no final session, `report --allow-partial DIR` verifies
and reports only the checkpoint prefix, returning 4. Final evidence always wins;
a corrupt final session never falls back. SIGHUP stops orderly and a lost final
stdout summary preserves the durable capture's exit and reports its path on
stderr. Full-filesystem and hard-power-cut qualification remain open; these
source changes do not qualify older packages.

One canonical binary: the bundle, `.deb`, and `.rpm`
binaries are byte-identical (sha256
`6fa00bfba2bbff4aecd5b8185a6d736b7170f12fbe26754fd51b97750395275d`);
matrix ran bundle mode of it, byte-identical to the
`.deb` install (matrix mode + binary hash per row in
`evidence/matrix/*/artifacts.json` in the evidence archive;
retained-`.deb` install journey receipt privately retained).

## What this bundle contains

- `record`: SWIOTLB bounce-attempt capture, requested bytes, attach-anchored
  window/deadline, and readable default-pool capacity/used/high-water
  samples at start, on a best-effort 1 s cadence (4,096 routine,
  then pressurized-only up to 64), and close,
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

The release payload is asserted per package by the
packaging suites: the engine binary plus the three BPF
inspection objects of the `.deb`, the `.rpm`, and the
runtime tarball, with payload-manifest and SPDX checks
over each. In-payload license texts cover compliance;
no committed byte-pin manifest exists (the collected
manifest's shape stands in until requalification pins
release bytes). Each artifact's `MANIFEST.json` binds
its own verified bytes.

The `.deb` entry set is the kernel-matrix-tested one. The
matrix ran bundle mode of the sealed 0.2.0 build (seal
`08bdeaed2e8646c28b1a6dda760ae9071f603816ab8e219600cb465749b890c9`,
source `bdf641c36addc345f3fb6d8bf925059c6f1fa714`)
whose `/usr/bin/memveil` is sha256
`6fa00bfba2bbff4aecd5b8185a6d736b7170f12fbe26754fd51b97750395275d`.
The AWS SEV-SNP run installed the older 0.1.0 `.deb`
(`ae2d3c13...`, historical — see the [support
appendix](support.md#historical-appendix-010-matrix-superseded)).
The sealed artifacts, all from the one seal:

| Artifact | sha256 | Size |
| --- | --- | --- |
| `memveil-0.2.0.tar.gz` | `1421538887f8fc7673b5edcb55c6633ff6febec6d21257a181fcab4cd20d863e` | 1826844 |
| `memveil_0.2.0-1_amd64.deb` | `45e0085508fa24b5b1033616ee64e4ef576b6aa05db766fe33bc75e5fd3f9d6e` | 1273512 |
| `memveil-0.2.0-1.fc44.x86_64.rpm` | `439a32ee2f2fa11ce0636f5eccba52fac6bde098871178513bfd4389f00df0b7` | 1385858 |
| `memveil-source.tar.gz` | `b8226ace8d843d3cc06c2a94a0f243f889f762b9d564d90ed8cfa3cfcdd52280` | 3375252 |
| `memveil.spdx.json` | `3e253dd3b88ac9a41c9c6e1f1c0b74e0b611ce94492ec5ff348aa3a1f0ccee86` | 213354 |
| `memveil.provenance.json` | `62139c3687c0ab3de4714577d025209822b69e37e2ad7007856c9af6df4e6c6e` | 1638 |
| `qualification.json` | `44df17ac0897b102f96265b1bce9faf840868dad75a34851e699c682ed4ea058` | 758 |
| `qualification-evidence.tar.gz` | `16d320ff6ad15d20fd9c1fc3b9f6dc9f2c21000109c218310f4de7b8036cc7fe` | 303131684 |
| `tested-payload.sha256` | `5dff6a1737eca7fa7e80b2a0260e48657fc9340271f60e021d422014159de99a` | 37696 |

These hashes are re-verified by the T5 campaign's
pre-VM gates (6/6 match `candidate.json`) and the
release lists them in `SHA256SUMS.txt`.
The T8 full-repeat campaign completed the full 20-row matrix,
so this prerelease carries the full export (table above):
`tested-payload.sha256` (312 entries over bundle, `.deb` and
`.rpm`), `qualification.json` binding both gate receipts, and
`qualification-evidence.tar.gz` with the 20 row receipts.
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
- Confidential scope is one exact run, not a qualification: a
  single SEV-SNP guest run exists (AWS c6a.large, Ubuntu
  7.0.0-1014-aws) and no TDX guest was run. The confidential
  gates are incomplete, no attestation is performed, offline
  region analysis and ordinary-Linux conversion calls do not
  prove a confidential transition, and observations are not
  host-access verdicts.
- SEV-SNP guests are detected through the `vmpl` node
  (`/sys/devices/system/cpu/sev/vmpl` beside the sev-guest
  node), fixture-proven and live-proven on that AWS guest: doctor
  reports `sev-vmpl:0`, matching the kernel's "SNP running at VMPL0".
- Pool samples are best-effort reads (start, 1 s cadence with
  4,096 routine samples then pressurized-only persists up to 64,
  missed ticks skipped, close) and cannot alone diagnose
  sustained pressure. The sampler never resets high-water; equal values
  share an allocator lifetime only if no reset occurred. Dynamic pools
  are outside the reader's scope; see [privacy](privacy.md).
- Live terminal quality stays partial: a finalized capture and a
  quiet ring do not prove writer settlement. The wired close-out
  (detach, 100 ms settle, bounded drain, 100 confirmation polls,
  counter sample, finalize) stamps `stop` evidence with the 5,000 ms
  budget as a completeness threshold; live runs stay partial with
  `quiescence unproven` because no kernel protocol proves settlement.
  `record`, `report`, and `top` exit 0 for a finalized capture with
  that partial verdict; `--strict` exits 4 unless the verdict is
  `complete`.
- CPU targets and ELF linkage minima are compatibility prerequisites,
  not tests of every claimed platform. See [support](support.md).
- Sustained saturation drains about 153,000 records/s
  (3,118,447 records in 20.33 s on a 4-vCPU guest). A
  busy capture above the 1 GiB default needs
  `report --max-events-bytes` to replay.
- Rows that refuse, with their codes: 6.0 and 6.6 refuse
  lifecycle and copy (need 6.11); BTF-less kernels
  refuse lifecycle and copy (`btf-absent-config`);
  confidentiality lockdown refuses everything (T5 row
  receipts `evidence/matrix/6.0/receipt.json`,
  `evidence/matrix/6.6/receipt.json`,
  `evidence/matrix/6.12.114-nobtf/receipt.json`,
  `evidence/matrix/7.0.14-lockdown/receipt.json`).
- Saturated busy runs can stop at the 4,194,304-record
  cap with bytes below the 4 GiB cap, which the gate
  accepts as a filled budget (no T5 row stopped at the
  cap; 6.11 stopped there in the earlier 0.1.0 run).
  Main-window captures can lose a few map or copy events
  to BPF trampoline recursion; memveil counts them as
  `recursion_missed` and reports detail partial (T5 7.0
  row: map SHORT-COVERED, 73 events declared as loss —
  `evidence/matrix/7.0/receipt.json`). Attempt loss before 6.7 is a lower bound:
  the 6.0 and 6.6 rows report partial with the
  lower-bound label in detail and aggregate.
- The 6.18.0 kernel leaves read maps unmapped (640,
  384, and 1152 across 0.1.0 runs); the product reports
  them open with the kernel-left-open note and the
  oracle agrees on every channel. This is a
  [known kernel issue](kernel-issues.md), not capture
  loss. 6.18.0 was not re-run in T5.
- The aggregate attempt claim covers the attempt
  hook's attached interval, stated in the aggregate
  scope text; the busy path allows a 2 s oracle edge
  gap while the main path keeps 1 s, and rows whose
  oracle samples stall fail closed.
- `forced` mirrors the kernel's swiotlb force bit and is
  not a confidential-guest signal; see
  [privacy](privacy.md).
- The BTF-less row proves attempt counts only; bytes
  stay unproven (`evidence/matrix/6.12.114-nobtf/receipt.json`).
- Passive doctor can read `ready (load not checked)`
  while the memcg precheck reports `memcg-headroom`
  unknown; only `doctor --load-check` or a record proves
  the load fits. Detection-scenario contract: 12/12 legs
  green on 3 sealed-bytes runs, with formal row receipt
  privately retained (run `20261123T121047Z`,
  receipt
  `f4d4a677c98da9cfc8351f0af41e7d9b5af54299f04a612ac247635e11dba611`;
  judge 12/12, validate/rederive/`--verify-out` PASS).

## Compatibility

Product `0.2.0` is not a format version: session, event,
and report `0.1.4` remains the write format (event
`0.1.2` unchanged). Current output versions are report
`0.1.4`, session `0.1.4`, and event `0.1.2`. Readers accept frozen session `0.1.1`/`0.1.2`/`0.1.3`/`0.1.4` and event
`0.1.1`/`0.1.2`. Reports are output only; there is no report-input reader.
Retained report schemas are reference contracts. Doctor emits `0.1.1`,
profiles accept `0.1.1`/`0.1.2`, and receipts remain `0.1.0`.

Session/report `0.1.4` implement integrity with event `0.1.2`
unchanged. Session/event/report `0.2.0` are reserved for a conversion
request/result journal. Journal versions are planned,
not implemented or admitted. The hardened 0.2.0 ordinary-Linux
preview does not qualify confidential collection; a later release must
earn real SNP I/O and owned conversion/reversion evidence for its exact
packaged bytes.
The broader 0.3.0 security milestone remains separate.

Normal successful `record`, `report` and `top` output returns 0 even with
partial evidence; `--strict` returns 4 unless complete. Current legacy tail
recovery follows that rule, while unfinalized checkpoint recovery
always returns 4. Corrupt finalized integrity input returns 2 even
with the partial flag. Full current and planned reader rules live in
[format compatibility](format-compatibility.md) and the
[integrity exit table](capture-integrity.md#reader-and-report-behavior).
Captures replay offline without the recording host or native bridge. Current
legacy data has no integrity verification; arithmetic is not authenticity.

## Support

RnD prerelease; supported until the next 0.x; report
issues with your `memveil version` output plus the seal
ID above.
