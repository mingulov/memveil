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
| record | root: BPF load plus tracefs                | exit 3 naming profile/bridge/privilege|

Captures are created mode 0600 (session, events) inside a mode
0700 directory. Recording as root leaves a root-owned capture;
copy it elsewhere before unprivileged replay.

## Resource defaults

- `--duration` 60 s; `--max-events-bytes` 1 GiB (allowed
  128 KiB..4 GiB); ring buffer 8 MiB; BPF object and bridge
  passed explicitly (`--object`, `--bridge`/`LMB_NATIVE_LIB`).
- Report caps: 64 KiB per record, 16 MiB session file, 4 GiB
  total work. `--allow-partial` drops a truncated final record
  and reports the loss instead of failing.

## Exit codes

- `record`: 4 finalized (including zero-event and signal
  stops), 3 cannot start, 2 usage error, 1 error/unfinalizable.
- `report`: 0 sufficient, 4 materially incomplete, 2 invalid.
- `doctor`: 0 attempt-trace available, 3 unavailable/unknown,
  2 usage/internal error.

Exit codes never stand alone: every non-zero outcome carries a
structured reason (stderr diagnostic, JSON field, or both).

## Unsupported (explicitly out of scope)

Older kernels (< 7.0); mapping lifecycle, actual copy bytes,
sharing transitions, and physical unions (rendered
unavailable, never inferred); SNP/TDX or any attestation
verdict; joint runs with other observers; multi-profile
fleets. Doctor verdicts are passive observations, not
host-access decisions.
