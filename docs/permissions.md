<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Permissions and privilege separation

Summary table in `support.md`; this page gives the details.
`doctor`, `report`, and `top` never need privilege. Only
`record` loads BPF, and only `record` needs root.

## Per-verb requirements

| Verb | Needs | Touches |
|---|---|---|
| `doctor` | none (passive) | reads sysfs/debugfs state, never attaches |
| `report` | read access to the capture directory | reads `session.json` + `events.ndjson` |
| `top` | read access to the capture directory | same as `report`, repeatedly |
| `record` | root: BPF load, tracefs, BTF read | creates the capture directory, attaches probes |

`record` resolves its inputs explicitly: `--object` names the BPF
object, `--bridge` (or `LMB_NATIVE_LIB`) names the native bridge
library, and `--profile` optionally pins one semantic profile.
Profiles resolve from the executable location
(`<root>/bin/memveil` reads `<root>/profiles`), never from the
working directory. Without `--profile`, the first validated
profile passing full identity binding wins, else the first
covering profile runs partial; an explicit `--profile` that
fails binding refuses.

## Capture ownership and file modes

Captures are created mode `0700` (directory) with mode `0600`
files (`session.json`, `events.ndjson`). Recording as root
leaves a root-owned capture; hand it to your user before
unprivileged replay:

    sudo cp -r /tmp/cap1 ~/cap1 && sudo chown -R $USER ~/cap1
    ./bin/memveil report --format text ~/cap1

`record` never follows an existing output path: the output
directory must not exist, and a refused run creates nothing.

## Running under sudo

`sudo` may drop the environment carrying `LMB_NATIVE_LIB`.
Either preserve it (`sudo -E`) or pass the bridge directly:

    sudo ./bin/memveil record --bridge $PWD/lib/libbpf_mojo.so.1 \
        --object $PWD/bpf/swiotlb_attempt.bpf.o --output /tmp/cap1

## Refusal catalog

Every refusal exits 3, prints one stderr line, and leaves no
capture directory. `record` validates in gate order and names
the first failing gate, so a later problem hides behind an
earlier refusal:

1. Usage and `--max-events-bytes` budget (exit 2 for usage,
   exit 3 for an out-of-range budget).
2. Bridge presence: `no bridge` when neither `--bridge` nor
   `LMB_NATIVE_LIB` names one.
3. Profiles load: `cannot load profiles: ...` when the
   shipped `profiles/` cannot be read.
4. Explicit `--profile`: `unknown --profile: <id>`, or
   `profile does not cover this kernel`.
5. Coverage: `no profile covers this kernel` without
   `--profile`.
6. Object: `object unreadable` (missing path),
   `object refused: ...` (not a BPF object),
   `object ring too large`.
7. Hook admission: `format unreadable` (tracefs not
   readable, the usual unprivileged refusal),
   `layout: ...`, `bad hook site`.
8. Binding: `binding failed: ...`.
9. Live collection: bridge load, attach, and privilege
   failures surface as sanitized diagnostics once every
   gate above passes.

`doctor` reports the same availability passively (exit 3 with
per-hook reasons) without attaching anything. See
`troubleshooting.md` when a refusal surprises you.
