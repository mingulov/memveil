<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Troubleshooting

Start with `memveil doctor`: it reports what this host can and
cannot do without attaching anything. `record` refusals name
the first failing gate in validation order (see
`permissions.md`); fix that gate before suspecting a later one.

## `record` refuses

| stderr | Meaning | Fix |
|---|---|---|
| `no bridge` | no `--bridge` / `LMB_NATIVE_LIB` | point at `lib/libbpf_mojo.so.1`; under `sudo`, use `sudo -E` or `--bridge` |
| `unknown --profile: ...` | typo or unshipped id | drop `--profile` for auto-select, or check `profiles/manifest.txt` |
| `object unreadable` | `--object` path missing | point at the shipped `bpf/swiotlb_attempt.bpf.o` |
| `object refused: ...` | file is not a usable BPF object | use the shipped object; ELFs from other tools are refused |
| `format unreadable` | tracefs not readable here | run as root on a kernel the profile covers |
| `binding failed: ...` | hook bindings do not hold | the profile does not match this kernel; stay unbound or pick the validated profile |
| `cannot load profiles: ...` | shipped profiles unreadable | keep `profiles/` beside `bin/` (`<root>/bin/memveil` reads `<root>/profiles`); profiles resolve from the executable, never the working directory |

A refused run exits 3 and creates nothing: there is no partial
capture to clean up.

## Reports look wrong

- Exit 4 on a healthy capture is normal: terminal quality is
  partial by design until the stop protocol is proven on the
  exact profile (`measurement-windows.md`). Exit 0 means
  sufficient evidence, exit 2 means invalid input.
- Zeros versus unavailable: a valid empty capture replays
  `bounce_attempts = 0`; rows without their event source
  render `unavailable` with a reason, never zero. If a row
  you expect is unavailable, the capture carries no such
  source (live captures carry attempts only).
- Truncated input: `report` exits 2 on a torn final record;
  rerun with `--allow-partial` to drop the torn tail and
  report the loss instead (`format-compatibility.md`).
- `top` is slow on long windows: it sleeps `--interval`
  (minimum `1s`) between refreshes, so a ten-second window
  takes about ten seconds. The final summary matches
  `report` on the same capture.

## Startup and loading failures

- `memveil` prints nothing and exits 1: stdout is blocked
  (closed pipe, full disk). Free the sink and rerun; output
  is never silently dropped.
- `record` cannot load the bridge on an older userland: the
  native bridge needs glibc >= 2.38 (Ubuntu 24.04 LTS or
  later); `report`, `top`, and `doctor` work from glibc 2.35
  (`support.md`).
- `doctor` exits 3: collection is unavailable or unknown on
  this host. Read its per-hook reasons; they name the exact
  missing piece (BTF, tracefs, profile coverage).
