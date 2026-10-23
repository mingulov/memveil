<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil support envelope (development bundle 0.1.0)

## Capabilities by mode

This is an attempt/lifecycle/copy development preview. `0.1.0`
is a development version; it does not mean the original
lifecycle-qualified preview or full confidential first release
has passed its gates.

| Capability | Shipping collection | Offline/laboratory boundary |
| --- | --- | --- |
| Bounce attempts/requested bytes | `swiotlb_bounced` attempts on an admitted profile; attempts are not successful DMA or actual copies | Report and replay `top` reduce captured attempts/counters without adding alternative measurements |
| Default-pool capacity/used/high-water | Readable debugfs samples at start, on a best-effort 1 s cadence (cap 4,096; missed ticks skipped), and close; unreadable reads persist as unavailable, never failed runs | Pool reducers require matching generation/scope; samples are opportunistic reads with possible gaps, so they cannot establish sustained pressure alone |
| Allocation occupancy, copy, sync, lifetimes | Qualified on any covered kernel through the live interface checks (see Kernel generations), or per host by a machine-local `local-auto` receipt from `memveil qualify`; collect with `--capability` (with `--lc-object`/`--cp-object` as optional overrides). Exact bindings and live checks refuse anything else | Offline reducers accept corresponding records; laboratory probes and scripted DMA comparisons do not qualify packaged lifecycle collection |
| Private/shared state and physical unions | No qualified shipping source | Offline region/baseline reducers and laboratory conversion probes; ordinary-Linux APIs do not prove confidential transitions |
| Summary | `top --output DIR [--object PATH]` observes live under the same admission as `record`, retaining the capture while printing prefix summaries (provisional; the final answer always equals a replay of the retained capture); startup/collection refusals exit 3 | `top DIR` replays prefixes of a finished capture |
| Joint observers/two instances | No current-candidate qualification | Historical experiments only; see [coexistence](coexistence.md) |
| SNP/TDX | No real confidential-guest qualification | Missing hardware evidence stays open; synthetic/offline tests are separate |

Rows without evidence remain unavailable with reasons. Allocation
release reduces observed occupancy, not persistent sharing state;
allocation byte-time is not a measured sharing lifetime. Absence of a
pressure finding is not evidence of absent pressure.

## Requirements

Collection needs all of these on the recording host; `memveil
doctor --load-check` is the authoritative check, and passive
doctor leaves the load verdict at `ready (load not checked)`.

- Kernel BTF: built with `CONFIG_DEBUG_INFO_BTF=y` and
  readable at `/sys/kernel/btf/vmlinux`. Check with
  `test -r /sys/kernel/btf/vmlinux` and the running config
  (`/proc/config.gz` or the matching `/boot/config-*`).
- Tracing support: `CONFIG_FTRACE=y` and
  `CONFIG_BPF_EVENTS=y` in the running config.
- ftrace enabled: `kernel.ftrace_enabled=1`
  (`cat /proc/sys/kernel/ftrace_enabled`).
- tracefs mounted at `/sys/kernel/tracing`
  (`mount | grep tracefs`).
- Lockdown below `confidentiality`
  (`cat /sys/kernel/security/lockdown`); `integrity` is fine.
- Privilege: `CAP_BPF` plus `CAP_PERFMON`, or
  `CAP_SYS_ADMIN` (root in the initial user namespace).
- Memory-cgroup headroom for the BPF maps (see the map
  sizes under Resource defaults); the memcg precheck
  reports `unknown` when outer limits are not visible.
- glibc 2.38 or later for the native bridge.

Known out of reach: Kata, CoCo, Contrast, and AKS
kernel-uvm guests (no BTF; some also lack `FTRACE` or
`KPROBES`), RHEL 9 (kernel 5.14, below the 6.0 floor),
and Debian 12, AL2023, and RHEL 9 userlands below the
glibc floor. External BTF files and a kprobe fallback
are not provided.

## Limits

- Passive doctor can read `ready (load not checked)`
  while the memcg precheck reports `memcg-headroom`
  unknown; only `doctor --load-check` or a record proves
  the load fits.
- Sustained saturation drains about 153,000 records/s
  (3,118,447 records in 20.33 s on a 4-vCPU guest);
  beyond it detail loss reads unknown and quality
  partial, never complete. On 6.0 through 6.6 the
  saturated runs instead report a partial lower bound,
  and 6.10 and later bind strictly; see the release
  notes.
- `forced` mirrors the kernel's swiotlb force bit and is
  not a confidential-guest signal (see
  [privacy](privacy.md)).
- The 7.0 scenario guest admits, and all 12 detection
  scenarios pass: every negative refuses correctly,
  `nocaps` drops every capability through `setpriv`
  (CapEff 0 in the dropped child), and `memcg` refuses
  `load-enomem` under its calibrated limit.
- `libbpf-mojo` 0.2.0 declares a 7.0 kernel minimum;
  below 7.0 this repository's booted matrix is the
  qualification.

## Configuration and artifact admission

- Two reference profiles (x86-64, kernel floors 7.0 and
  6.0). Recording admission checks the live interfaces
  (BTF signatures, tracepoint format, ftrace
  attachability), not just the release string, and refuses
  when a time-namespace offset is present. A bound document
  additionally checks exact kernel-image hash/build ID,
  config hash and config source, BTF, event-format, and
  object bindings; a rebuilt BPF object can fail those
  bindings. Building/packaging/offline replay does
  not earn collection qualification. A machine-local receipt
  from `memveil qualify` admits a bound reference profile as
  `local-auto`: the document needs covering identity,
  grammar bindings matching the live host, and recorded
  format text (see the
  [bound-reference recipe](profiles.md)); the shipped
  reference is an unbound
  inspection record and planning refuses it. A receipt
  binds one kernel, one profile document, and the exact
  artifacts and workload that produced it, and never
  claims `validated`. Only manifest-listed documents are
  visible: register a new reference file in the active
  profiles directory's `manifest.txt` first. Without
  `--profile`, the first validated profile passing full
  binding wins, then the first reference profile whose
  receipt verifies, else the first covering profile
  records with partial diagnostics; an explicit `--profile` that fails binding
  refuses, as do requested extra channels without full
  narrow binding. `record` re-verifies the receipt at
  every start; a kernel, object, bridge, or profile change loses
  `local-auto` admission until the profile's recorded
  bindings are refreshed and `qualify` re-proves the
  host, with attempt-only recording falling back to
  partial diagnostics.
- x86-64-v2 baseline. The binary carries its runtime closure
  plus the native bridge in `lib/`. Offline verbs (help,
  version, doctor, report, replay `top`) need libc, libm,
  libdl, and the dynamic loader from the host; `record` and
  live `top` additionally load the bridge, which needs libelf
  and libz. `libpthread` and `libzstd` are permitted by the
  loader allowlist but unused; the manifest's
  `system_libraries` records that allowlist, a superset of
  the per-verb needs above. Compiler-free offline consumption
  has been tested
  on Ubuntu 26.04.1 (glibc 2.43) for specific development artifacts.
  Observed linkage minima are glibc 2.35 for the offline closure and
  glibc 2.38 for the bridge. These minima and the CPU build target
  do not qualify Ubuntu 22.04/24.04, every later userland, or every
  x86-64-v2 CPU; each advertised environment needs an exact-artifact test.
- Profiles resolve from the executable location
  (`<root>/bin/memveil` reads `<root>/profiles`), never from
  the caller's working directory. The bridge and BPF
  objects resolve the same way (`<root>/lib`,
  `<root>/bpf`) before the system paths, so no
  environment setup is needed and plain `sudo` works.

## Kernel generations

Admission is by live interface checks (BTF signatures,
tracepoint format, ftrace attachability), never by trusting
the release string. One prebuilt probe set covers every row;
no rebuild on the device.

Booted 2026-10-23 with the 0.1.0 release bundle
(binary sha256 `4c9332d1...`, full hash in the
[release notes](release-notes.md)). Every row passes;
`PASS` rows are support claims and refused
capabilities stay measured observations recorded with
their exact refusal codes. Evidence: `matrix/<lock
id>` per row. Three rows needed a same-binary re-boot:
the btf/nobtf oracle stalled over a second at a window
edge, and the first 6.18.0 guest was SIGKILLed before
it produced output; the preserved failures sit beside
the passing rows.

| Lock id | Booted release | attempt-trace | mapping-lifecycle | copy-actual | Row |
| --- | --- | --- | --- | --- | --- |
| 5.15 | 5.15.223-0515223-generic | refused (`floor`) | refused (`floor`) | refused (`floor`) | PASS |
| 6.0 | 6.0.19-060019-generic | available | refused (`floor`) | refused (`floor`) | PASS (attempt-only; aggregate partial lower bound; busy stops at the 4,194,304-record cap) |
| 6.6 | 6.6.160-0606160-generic | available | refused (`floor`) | refused (`floor`) | PASS (attempt-only; aggregate partial lower bound) |
| 6.10 | 6.10.14-061014-generic | available | refused (`floor`) | refused (`floor`) | PASS (attempt-only; busy stops at the 4,194,304-record cap, SHORT-COVERED) |
| 6.11 | 6.11.11-061111-generic | available | available | available | PASS (busy stops at the 4,194,304-record cap) |
| 6.12.0 | 6.12.0-061200-generic | available | available | available | PASS (busy stops at the 4,194,304-record cap) |
| 6.12.114-btf | 6.12.114-mv-6.12.114-btf | available | available | available | PASS |
| 6.12.114-debug | 6.12.114-mv-6.12.114-debug | available | available | available | PASS |
| 6.12.114-nobtf | 6.12.114-mv-6.12.114-nobtf | available | refused (`btf-absent-config`) | refused (`btf-absent-config`) | PASS (counts only; busy SHORT-COVERED) |
| 6.12.114-rt | 6.12.114-mv-6.12.114-rt | available | available | available | PASS (main SHORT-COVERED) |
| 6.12 | 6.12.114-0612114-generic | available | available | available | PASS |
| 6.18.0 | 6.18.0-061800-generic | available | available | available | PASS (kernel leaves read maps unmapped; product reports them open with the kernel-left-open note; see [kernel issues](kernel-issues.md)) |
| 6.18 | 6.18.58-061858-generic | available | available | available | PASS |
| 7.0.14-lockdown | 7.0.14-070014-generic | refused (`lockdown-confidentiality`) | refused (`lockdown-confidentiality`) | refused (`lockdown-confidentiality`) | PASS |
| 7.0 | 7.0.14-070014-generic | available | available | available | PASS |
| 7.1 | 7.1.13-070113-generic | available | available | available | PASS |
| 7.2 | 7.2.6-070206-generic | available | available | available | PASS |
| 7.3-rc3 | 7.3.0-070300rc3-generic | available | available | available | PASS |
| 7.3 | 7.3.0-mv-7.3 | available | available | available | PASS |
| debian13 | 6.12.107+deb13-amd64 | available | available | available | FAIL (busy oracle gap over 1 s at window end; main all EXACT) |

Notes:

- The nobtf row asserts counts only: attempt counts are
  oracle-proven while bytes stay unproven (no hist
  triggers in the built config). Its busy verdict is a
  strict SHORT-COVERED bound with declared omits.
- A positive `stop.open_mappings` count means the
  kernel never released those mappings, not that the
  product lost their unmaps; see
  [kernel issues](kernel-issues.md).
- 7.3 changes one detail: `swiotlb_tbl_map_single`
  takes `attrs` as a pointer (present since rc1,
  verified through rc3, the newest 7.3 in the lock).
  The shipped probe never reads map-side `attrs`
  (`fexit` map ignores it; `unmap` still passes it by
  value), so the same object serves both shapes and the
  signature check accepts either. If a future probe
  reads map-side `attrs`, this row must be revisited.
- Release candidates and mainline snapshots parse to
  their triple (`7.3.0-rc2` is 7.3.0) and are admitted
  by the same live checks. They are moving targets: a
  newer rc that changes a shape is refused fail-closed
  with the exact diff, never silently admitted.
- Trying a 7.4 pre-alpha means two checks: the source
  check above (re-fetch mainline
  `kernel/dma/swiotlb.c` and the trace header, diff the
  five hooks plus the tracepoint fields), then a boot
  check (run `doctor` and `record` on the new kernel).
  Admission without the boot check is not a support
  claim.
- Admission is not qualification: booted matrix evidence
  stays on the tested kernel and artifact. Other
  builds additionally need a machine-local `local-auto`
  receipt from `memveil qualify` plus the independent
  oracle comparison before results are trusted.

### Boot verification

The lock `tests/vm/kernels.lock.json` pins one newest
mainline build per generation with its expected verdicts,
artifact hashes, and oracle tool versions. Run the lane
and read the per-row verdicts from the summary; any row
that disagrees with the table above keeps failing with
its evidence attached, and the table stays unchanged
until the product or the lock is fixed on purpose.

Rerun with a built deb (the tool refuses to overwrite an
existing evidence dir, so start from a fresh one):

```sh
./tools/build
./tools/package-deb
rm -rf build/vm/kernels
MV_DEB=dist/memveil_0.1.0-1_amd64.deb \
  MEMVEIL_VM_KERNELS=1 ./tools/test vm-kernels
```

`tools/kernel-matrix --all --out DIR` runs the same
matrix directly (one evidence dir per kernel plus a
summary table; sharing one `DIR` across runs merges
rows by kernel id). Each guest boots with forced
swiotlb and a read-only emulated NVMe disk, at most 4
vCPUs. The run holds the VM resource lock
(`build/vm/suite.lock`, nonblocking, one guest at a
time) for its whole duration.

Environment:

- `MV_DEB` or `MV_KERNELS_BUNDLE`: binary under test
  (exactly one; the lane needs one when armed).
- `MV_KERNELS_OUT`: evidence parent dir
  (default `build/vm/kernels`).
- `MV_KERNELS_DISK`: NVMe backing image (default
  `build/vm/kernel-matrix-disk.img`, outside the
  evidence dir).
- `MV_HOST_CPUS`: host CPU set for the guest
  processes through `taskset` (for example `0-7`);
  unset runs without `taskset`.

`tools/kernel-matrix --scenarios --kernels 7.0 --out DIR`
runs the detection-scenario lane on the 7.0 row: twelve
scenarios that prove refusal codes and remedies
(`MEMVEIL_VM_SCENARIOS` arms the `vm-scenarios` lane with
`MV_DEB` pointing at the deb). Lockdown and BTF absence
are covered by their matrix rows instead of scenarios.
All twelve pass on the 7.0 guest with this bundle.

| Scenario | Record outcome | Remedy family |
| --- | --- | --- |
| base | finalizes (exit 4) | none, ready path |
| neg-renamed | `verifier-rejected` (exit 3) | verifier lines |
| neg-layout | finalizes with `copy.unknown_layout` | object binding |
| neg-shift | finalizes with `copy.unknown_shift` | object binding |
| neg-argcnt | finalizes with an argument count mismatch | object binding |
| nonroot | `tracefs-denied` (exit 3) | privilege |
| nocaps | `load-eperm` (exit 3) | privilege |
| ftrace-off | `ftrace-disabled` (exit 3) | ftrace enablement |
| tracefs-unmounted | `tracefs-not-mounted` (exit 3) | tracefs mount |
| btf-empty | `btf-truncated` (exit 3) | kernel BTF build |
| btf-truncated | `btf-truncated` (exit 3) | kernel BTF build |
| memcg | `load-enomem` (exit 3) | memcg headroom |

## Permissions

| Verb   | Needs                                      | Refusal looks like                    |
|--------|--------------------------------------------|---------------------------------------|
| doctor | none (passive)                             | exit 3 with per-hook reasons          |
| report | read access to the capture directory       | exit 2 on invalid input               |
| top    | replay: read access to the capture directory; live: root like `record` | replay: exit 2 on invalid input; live: exit 3 on refusal |
| record | root: BPF load plus tracefs                | exit 3 naming profile/bridge/privilege|
| qualify | root: smoke capture plus receipt write under the profiles dir | exit 3 with the exact cause |

Captures are created mode 0600 (session, events) inside a mode
0700 directory. A capture recorded under `sudo` is handed
back to the invoking user automatically (failures warn
once with `cannot restore capture ownership` and the
capture stands); a root run outside `sudo` stays
root-owned and still needs a manual handoff before
unprivileged replay. Full privilege
details live in `permissions.md`; surprises go to
`troubleshooting.md`.

## Resource defaults

- `--duration` 60 s; `--max-events-bytes` 1 GiB, the
  replay default, so a default capture always reports (allowed
  128 KiB..4 GiB, minus a 64 KiB closing reserve); at most
  4,194,304 attempt records; ring buffers of 8 MiB for
  attempt and 32 MiB each for lifecycle and copy (72 MiB
  with all three channels); the bridge and BPF objects are discovered
  (explicit `--bridge`/`--object` win verbatim;
  `LMB_NATIVE_LIB` is honored only when unprivileged;
  then the executable-relative bundle path, then the
  system path; objects have no environment step). A
  missing-everywhere object refuses with exit 3 `no
  object: pass --object PATH`; requested extra channels
  refuse with `no object: pass --lc-object PATH` and
  `no object: pass --cp-object PATH`.
  Extra channels are opt-in per run (`--capability`,
  with `--lc-object`/`--cp-object` as optional
  overrides); see
  [lifecycle hooks](lifecycle-hooks.md#capability-requested-selection).
- Report caps: 64 KiB per record, 16 MiB session file,
  1 GiB events total by default, 16 MiB rendered output,
  JSON depth 64, and 4,194,304 tracked identities. Only the
  events cap is raisable (up to 4 GiB): a capture recorded
  with a larger `--max-events-bytes` replays with the same
  value on both replay verbs; the record and
  session caps accept their default or lower (a higher value
  is refused with exit 2). `--allow-partial` drops only a
  clean truncated unterminated tail and reports the loss
  instead of failing; a parsable record missing its newline
  and any corrupt tail stay invalid (exit 2).
- Wired close-out: detach, a 100 ms settle sleep, a bounded
  drain (30 s / 100,000 polls, unsettled exits marked busy),
  100 confirmation polls, a counter sample, and finalize,
  stamping session 0.1.1 `stop` evidence. The 5,000 ms budget
  is a completeness threshold, not a shutdown deadline:
  overrunning it finalizes partial. Quiescence is never
  observed on the live path (no kernel protocol proves
  writers settled), so live terminal quality stays partial
  with the stop-linked reason; exit 0 additionally requires
  complete terminal evidence. A failed stdout write exits 1,
  never silent success; a blocked pipe may wait without a
  timeout.

## Exit codes

- `record`: 4 finalized (including zero-event and signal
  stops), 3 cannot start, 2 usage error, 1 error/unfinalizable.
- `report`: 0 sufficient (complete terminal evidence plus
  every other gate), 4 materially incomplete, 2 invalid,
  1 internal failure (rendering, oversize output, stdout
  write).
- `top` replay: same as `report`, judged on the final
  summary. Live `top` adds 3 for startup/collection refusal
  (admission, bridge/profile/privilege, signal preparation)
  and 1 for runtime failures; printed prefixes stand when
  the run fails.
- `doctor`: 0 attempt-trace available, 3 unavailable/unknown,
  2 usage/internal error, 1 stdout write failed.
- `qualify`: 0 minted, 3 cannot-qualify (planning or smoke
  refusal), 2 usage error, 1 internal failure (unreadable
  objects, mint/publish failure).

Exit codes never stand alone: every non-zero outcome carries a
structured reason (stderr diagnostic, JSON field, or both).
Diagnostics are best-effort when standard error itself is
broken: a `record` refusal then keeps exit 3 without its
diagnostic.

## Unsupported (explicitly out of scope)

Older kernels (< 6.0, see the generations matrix);
shipping region (laboratory probes
and offline reducers do not supply this shipping capability);
sharing transitions and
physical unions (rendered unavailable, never inferred);
SNP/TDX or any attestation verdict; joint runs with other
observers; multi-profile fleets. Doctor verdicts are passive
observations, not host-access decisions. The capability table
above is the support contract; sustained-pressure diagnosis
stays unqualified even though periodic sampling ships.

On the admitted profile, mapping lifecycle and actual copy
bytes ship from the collector; pool pressure, conversion
requests, region state, and diagnostic findings still reduce
offline over captures that carry the corresponding events or
baseline observations. Rows without their source stay null
with reasons, never zero.

Human reports show recorded `kernel.release`, `profile.decision`,
`measurement_scope`, and exact duration from the report window.
Missing or conflicting recorded provenance is explicit; unbound
remains unbound. These are captured claims, never admission decisions
about the reader's host. Full evidence/hashes remain in session/JSON.
