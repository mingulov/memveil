<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil support envelope (development bundle 0.1.0)

## Capabilities by mode

This is an attempt-capture development preview. `0.1.0` is a
development version; it does not mean the original lifecycle-qualified
preview or full confidential first release has passed its gates.

| Capability | Shipping collection | Offline/laboratory boundary |
| --- | --- | --- |
| Bounce attempts/requested bytes | `swiotlb_bounced` attempts on an admitted profile; attempts are not successful DMA or actual copies | Report and replay `top` reduce captured attempts/counters without adding alternative measurements |
| Default-pool capacity/used/high-water | Optional readable debugfs samples at start and close only | Pool reducers require matching generation/scope; two boundary samples cannot establish sustained pressure |
| Allocation occupancy, copy, sync, lifetimes | No qualified shipping source | Offline reducers accept corresponding records; laboratory probes and scripted DMA comparisons do not qualify packaged lifecycle collection |
| Private/shared state and physical unions | No qualified shipping source | Offline region/baseline reducers and laboratory conversion probes; ordinary-Linux APIs do not prove confidential transitions |
| Summary | No live `top` | `top DIR` replays prefixes of a finished capture |
| Joint observers/two instances | No current-candidate qualification | Historical experiments only; see [coexistence](coexistence.md) |
| SNP/TDX | No real confidential-guest qualification | Missing hardware evidence stays open; synthetic/offline tests are separate |

Rows without evidence remain unavailable with reasons. Allocation
release reduces observed occupancy, not persistent sharing state;
allocation byte-time is not a measured sharing lifetime. Absence of a
pressure finding is not evidence of absent pressure.

## Configuration and artifact admission

- One narrow profile with historical attempt evidence:
  `linux-x86_64-7.0.0-34-generic` (x86-64, kernel floor 7.0).
  Recording admission checks exact config/BTF/event-format/object
  bindings, not just the release string. A rebuilt BPF object can
  fail the shipped binding; building/packaging/offline replay does
  not earn collection qualification. Other inputs are unbound
  (partial diagnostics) or refused.
- x86-64-v2 baseline. The binary carries five Mojo runtime
  libraries plus the native bridge in `lib/`; the host must
  supply libc, libm, libdl, libelf, libz, libzstd, and the
  dynamic loader. Compiler-free offline consumption has been tested
  on Ubuntu 26.04.1 (glibc 2.43) for specific development artifacts.
  Observed linkage minima are glibc 2.35 for the offline closure and
  glibc 2.38 for the bridge. These minima and the CPU build target
  do not qualify Ubuntu 22.04/24.04, every later userland, or every
  x86-64-v2 CPU; each advertised environment needs an exact-artifact test.
- Profiles resolve from the executable location
  (`<root>/bin/memveil` reads `<root>/profiles`), never from
  the caller's working directory.

## Permissions

| Verb   | Needs                                      | Refusal looks like                    |
|--------|--------------------------------------------|---------------------------------------|
| doctor | none (passive)                             | exit 3 with per-hook reasons          |
| report | read access to the capture directory       | exit 2 on invalid input               |
| top    | read access to the capture directory       | exit 2 on invalid input               |
| record | root: BPF load plus tracefs                | exit 3 naming profile/bridge/privilege|

Captures are created mode 0600 (session, events) inside a mode
0700 directory. Recording as root leaves a root-owned capture;
copy it elsewhere before unprivileged replay. Full privilege
details live in `permissions.md`; surprises go to
`troubleshooting.md`.

## Resource defaults

- `--duration` 60 s; `--max-events-bytes` 1 GiB (allowed
  128 KiB..4 GiB); ring buffer 8 MiB; BPF object and bridge
  passed explicitly (`--object`, `--bridge`/`LMB_NATIVE_LIB`).
  Extra channels are opt-in per run (`--capability` with
  `--lc-object`/`--cp-object`); see
  [lifecycle hooks](lifecycle-hooks.md#capability-requested-selection).
- Report caps: 64 KiB per record, 16 MiB session file,
  256 MiB events total by default. Only the events cap is
  raisable (up to 4 GiB); the record and session caps accept
  their default or lower (a higher value is refused with
  exit 2). `--allow-partial` drops a truncated final record
  and reports the loss instead of failing.
- Staged stop-protocol budget 5,000 ms (`StopController` is
  unit-tested but not yet wired into the live collector, which
  drains up to 30 s instead); terminal quality stays partial
  (exit 4) until the stop protocol is proven on the exact
  profile. A blocked stdout fails loudly (exit 1), never as
  silent success.

## Exit codes

- `record`: 4 finalized (including zero-event and signal
  stops), 3 cannot start, 2 usage error, 1 error/unfinalizable.
- `report`: 0 sufficient, 4 materially incomplete, 2 invalid,
  1 stdout write failed.
- `top`: same as `report`, judged on the final summary.
- `doctor`: 0 attempt-trace available, 3 unavailable/unknown,
  2 usage/internal error, 1 stdout write failed.

Exit codes never stand alone: every non-zero outcome carries a
structured reason (stderr diagnostic, JSON field, or both),
except when standard error itself is broken: with no channel
to carry a diagnostic the run exits 1 without one.

## Unsupported (explicitly out of scope)

Older kernels (< 7.0); shipping lifecycle, copy, sync, region,
periodic pool sampling and live summary (laboratory probes and
offline reducers do not supply these shipping capabilities);
sharing transitions and
physical unions (rendered unavailable, never inferred);
SNP/TDX or any attestation verdict; joint runs with other
observers; multi-profile fleets. Doctor verdicts are passive
observations, not host-access decisions.

Mapping lifecycle, actual copy bytes, pool pressure,
conversion requests, region state, and diagnostic findings
reduce offline over captures that carry the corresponding
events or baseline observations; rows without their source
stay null with reasons, never zero.

Human reports show recorded `kernel.release`, `profile.decision`,
`measurement_scope`, and exact duration from the report window.
Missing or conflicting recorded provenance is explicit; unbound
remains unbound. These are captured claims, never admission decisions
about the reader's host. Full evidence/hashes remain in session/JSON.
