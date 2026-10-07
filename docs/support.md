<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil support envelope (development bundle 0.1.0)

## Tested configuration

- One validated semantic profile: `linux-x86_64-7.0.0-34-generic`
  (x86-64, kernel floor 7.0). Any other kernel runs unbound
  (partial diagnostics) or refuses admission.
- x86-64-v2 baseline. The binary carries five Mojo runtime
  libraries plus the native bridge in `lib/`; the host must
  supply libc, libm, libdl, libelf, libz, libzstd, and the
  dynamic loader. Tested userland: Ubuntu 26.04 (glibc 2.43).
  Offline floor (`report`, `doctor`): glibc >= 2.35, so
  Ubuntu 22.04 LTS and later. Recording floor: glibc >= 2.38
  (the native bridge), so Ubuntu 24.04 LTS and later; older
  userlands fail to load the bridge.
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

Older kernels (< 7.0); live lifecycle, copy, sync, region,
and pool collection (the probes are not qualified, so live
captures carry attempts only); sharing transitions and
physical unions (rendered unavailable, never inferred);
SNP/TDX or any attestation verdict; joint runs with other
observers; multi-profile fleets. Doctor verdicts are passive
observations, not host-access decisions.

Mapping lifecycle, actual copy bytes, pool pressure,
conversion requests, region state, and diagnostic findings
reduce offline over captures that carry the corresponding
events or baseline observations; rows without their source
stay null with reasons, never zero.
