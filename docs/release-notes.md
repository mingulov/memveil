<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil 0.1.0 release notes (development bundle)

Status: **attempt/lifecycle/copy development preview**. The version names
development bytes and schema compatibility, not a qualified full release.
The [capability table](support.md#capabilities-by-mode) is the support
contract for shipping collection, offline analysis, and laboratory work.

## Known issues

Finalized session 0.1.4 captures now bind and verify literal event bytes,
counts, kinds and contiguous sequences. Report 0.1.4 exposes verified
bytes/events. Finalized corruption returns 2 with or without partial mode.
Legacy input remains readable with unverified arithmetic and no complete
channels; normal mode returns 0 and strict mode returns 4. This source change
does not qualify older packaged artifacts. See [capture integrity](capture-integrity.md).

Crash recovery remains open:

- An abnormal stop leaves a capture that cannot be read.
  `session.json` is written only when record finishes normally.
  SIGPIPE (for example `memveil record ... | head`), SIGHUP,
  SIGKILL or a full disk leave only `events.ndjson`, and
  `report` (also with `--allow-partial`) exits 2. Run record
  with stdout to a file or terminal, stop it with SIGINT or
  SIGTERM, and keep free space beyond the size cap.

Also note: the `.rpm` and the runtime tarball carry builds of
the same source as the `.deb` but not byte-identical binaries;
only the `.deb` binary was run on the kernel matrix.

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

The release payload is pinned per package in
`packaging/tested-payload.sha256`: the engine binary, the
libbpf-mojo bridge, and the three BPF objects of the
`.deb`, the `.rpm`, and the runtime tarball. The release
workflow refuses to publish unless every package carries
exactly its pinned bytes, and publishes the collected
manifest (`PACKAGED-SHA256.txt`), the SBOM
(`memveil.spdx.json`), and the checksums (`SHA256SUMS.txt`)
with signed build provenance for the set.

The `.deb` entry set is the kernel-matrix-tested one. The
matrix and the AWS SEV-SNP run installed the 0.1.0 `.deb`
whose `/usr/bin/memveil` is sha256
`ae2d3c13ddad4c093317b90b0e2975cc388ff8566ae8bd4d0c13b7e9ecb2ae5e`.
The `.rpm` and the runtime tarball are built from the same
tree and pass their own install lanes, but each install
layout needs its own RUNPATH, so their binaries carry
different hashes and were not run on the kernel matrix.
Package hashes change with every build (the `.deb`
changelog records the commit and build date); the release
lists them in `SHA256SUMS.txt`.
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
- Rows that refuse, with their codes: 5.15 is below the
  6.0 floor; 6.0 through 6.10 refuse lifecycle and copy
  (need 6.11); BTF-less kernels refuse lifecycle and
  copy (`btf-absent-config`); confidentiality lockdown
  refuses everything.
- Saturated busy runs can stop at the 4,194,304-record
  cap with bytes below the 4 GiB cap (6.11 in the
  release run; 6.0, 6.10, and 6.12.0 in earlier runs),
  which the gate accepts as a filled budget. Main-window
  captures can lose a few map or copy events to BPF
  trampoline recursion; memveil counts them as
  `recursion_missed` and reports detail partial (5 to 222
  events on five rows of the release run). Attempt loss before 6.7 is a lower bound:
  the 6.0 and 6.6 rows report partial with the
  lower-bound label in detail and aggregate.
- The 6.18.0 kernel leaves read maps unmapped (640,
  384, and 1152 across runs); the product reports them
  open with the kernel-left-open note and the oracle
  agrees on every channel. This is a
  [known kernel issue](kernel-issues.md), not capture
  loss.
- The aggregate attempt claim covers the attempt
  hook's attached interval, stated in the aggregate
  scope text; the busy path allows a 2 s oracle edge
  gap while the main path keeps 1 s, and rows whose
  oracle samples stall fail closed.
- `forced` mirrors the kernel's swiotlb force bit and is
  not a confidential-guest signal; see
  [privacy](privacy.md).
- The BTF-less row proves attempt counts only; bytes
  stay unproven.
- Passive doctor can read `ready (load not checked)`
  while the memcg precheck reports `memcg-headroom`
  unknown; only `doctor --load-check` or a record proves
  the load fits. Detection scenarios pass 12 of 12 on
  the 7.0 guest, including the `setpriv` capability
  drop and the calibrated `memcg` refusal.

## Compatibility

Current output versions are report `0.1.4`, session `0.1.4`, and event
`0.1.2`. Readers accept frozen session `0.1.1`/`0.1.2`/`0.1.3`/`0.1.4` and event
`0.1.1`/`0.1.2`. Reports are output only; there is no report-input reader.
Retained report schemas are reference contracts. Doctor emits `0.1.1`,
profiles accept `0.1.1`/`0.1.2`, and receipts remain `0.1.0`.

Session/report `0.1.4` implement integrity with event `0.1.2`
unchanged. Session/event/report `0.2.0` are reserved for a conversion
request/result journal. Journal versions and checkpoint recovery are planned,
not implemented or admitted. The planned hardened 0.1.1 ordinary-Linux
preview does not qualify confidential collection; 0.2.0 must earn real SNP
I/O and owned conversion/reversion evidence for its exact packaged bytes.
The broader 0.3.0 security milestone remains separate.

Normal successful `record`, `report` and `top` output returns 0 even with
partial evidence; `--strict` returns 4 unless complete. Current legacy tail
recovery follows that rule, while planned unfinalized checkpoint recovery
will always return 4. Corrupt finalized integrity input returns 2 even
with the partial flag. Full current and planned reader rules live in
[format compatibility](format-compatibility.md) and the
[integrity exit table](capture-integrity.md#reader-and-report-behavior).
Captures replay offline without the recording host or native bridge. Current
legacy data has no integrity verification; arithmetic is not authenticity.
