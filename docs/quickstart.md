<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil quickstart (development bundle 0.1.0)

MemVeil captures swiotlb bounce **attempts**, mapping **lifetimes**,
and executed **copies** on x86-64 Linux and replays them offline as
text, JSON, or Markdown. Attempts are try-counts; actual copies come
from the copy channel. This bundle runs from any directory: no
compiler, Pixi, network, or source checkout needed. The
[capability table](support.md#capabilities-by-mode) distinguishes the
shipping collector, offline reducers and laboratory probes.
Lifecycle/copy collection is qualified on one narrow profile or a
machine-local receipt from step 3; a full
confidential release is not yet qualified. The host supplies libc,
libm, libdl, and the dynamic loader for offline use, plus libelf
and libz for recording; see the support envelope for the exact
floor and tested OS.

System packages install the same layout instead: see
[installed packages](install.md) for the `.deb`/`.rpm`
install, use, and uninstall flow.

## 1. Extract and check the version

    tar -xzf memveil-0.1.0.tar.gz
    cd memveil-0.1.0
    ./bin/memveil version        # memveil-0.1.0, exit 0
    ./bin/memveil help           # verb list, exit 0

`MANIFEST.json` records the sha256 of every payload file plus the
source revisions; re-hash any file to confirm it.

## 2. Inspect the host (unprivileged, passive)

    ./bin/memveil doctor         # exit 0 ready, 3 unavailable, 2 error

Doctor loads no BPF and changes nothing. It reports the kernel
floor check, guest signals, the selected semantic profile, and
per-capability reasons. The narrow `7.0.0-34-generic` x86-64 profile has
VM-gate attempt, lifecycle, and copy evidence; exact
config/BTF/event-format/object bindings must also hold. A rebuilt
object can fail the binding even on that kernel.
Each unavailable capability carries a `fix:` line naming the
next action (`--json` renders the same report as JSON).
Passive availability is not actual attachment or qualification. A `denied
(privilege)` hook means: re-run under `sudo` for collection, or
stay unprivileged and replay the shipped example (step 6); step 5
needs a capture of your own.

## 3. Qualify this machine (privileged, once per kernel and objects)

When `doctor` selects the reference profile with `unknown` or
`unavailable` capabilities, prove this host directly.
Qualification needs a reference profile *bound* to this
host: covering identity, an identity note whose
config/BTF/format/image bindings match the live machine,
and the recorded hook format text. The shipped reference
document is an unbound inspection record, so automatic
selection refuses it with the exact cause:

    memveil qualify: profile linux-x86_64-7.0-reference bindings unparseable: narrow note: want 8 or 12 fields

Preparing the bound document is a one-per-kernel task
done from a source checkout; follow the
[bound-reference recipe](profiles.md)
for the exact authoring steps, then run everything below
from the bundle, selecting that document explicitly.
Register it once in the active profiles directory's
`manifest.txt` (one file name per line, no blank lines
or duplicates), including under a `--profiles-dir`
override: only manifest-listed documents are visible to
`doctor` and automatic `record`, so an unlisted receipt
stays invisible. No environment setup is needed: the
bridge and BPF objects are discovered from the bundle
beside the executable, so plain `sudo` works:

    echo my-host.json >> "$PWD/profiles/manifest.txt"
    sudo ./bin/memveil qualify --output /tmp/q1 \
        --profile "$PWD/profiles/my-host.json"

Qualification runs a 3-second smoke capture (attach, poll,
detach; no traffic required) and, when the channels prove
out, publishes a machine-local `local-auto` receipt.
Expected: `qualify: local-auto <profile> caps=attempt-trace
receipt=...`, exit 0. The receipt lands under
`profiles/receipts/` beside the binary, or under
`--profiles-dir DIR/receipts/` when given; `record`,
`doctor`, and live `top` must then use the same
`--profiles-dir`. A
receipt never claims `validated`: it binds one kernel,
one profile document, and the exact artifacts and
workload that produced it. Re-running `doctor` still
reports the receipt as explicitly bridge-unchecked
with exit 3: the passive path performs no bridge
binding, so only `record` and live `top` — which verify
bridge admission at every start — admit the receipt as
`local-auto`. Exit 3 names the exact cause (planning
or smoke refusal, or the unchecked receipt); exit 2
is a usage error; exit 1 is an internal failure
(unreadable objects, mint/publish failure).
`--object` and `--bridge` are optional overrides for
non-bundled artifacts; without them each object is
discovered beside the executable or under the system
directory, and the bridge additionally honors
`LMB_NATIVE_LIB` when unprivileged (under `sudo` the
environment is ignored). When no object is found
anywhere, qualify refuses with exit 3 `no object: pass
--object PATH`.

Extra channels qualify the same way, with their objects
discovered from the bundle:

    sudo ./bin/memveil qualify --output /tmp/q3 \
        --capability attempt-trace,mapping-lifecycle,copy-actual \
        --profile "$PWD/profiles/my-host.json"

(`--lc-object` and `--cp-object` override discovery
for non-bundled objects.)

After any kernel, object, bridge, or profile change the receipt
goes stale: refresh the profile's recorded bindings from
the new host first, then re-run `qualify`. `doctor` still
names receipt mismatches its passive checks can see
(another kernel, profile, note, or artifact binding);
only when those preceding checks pass does the receipt
stay bridge-unchecked (doctor performs no bridge
binding, so it cannot confirm or deny bridge drift).
`record` re-verifies the receipt — including bridge
admission — at every start and names the drift there,
with a stale receipt losing `local-auto` admission and
attempt-only recording falling back to partial diagnostics.

## 4. Record one capture (privileged)

Recording needs root (BPF load plus tracefs). The bridge
and BPF object are discovered from the bundle beside the
executable, so no flags or environment setup are needed
and plain `sudo` works:

    sudo ./bin/memveil record --output /tmp/cap1 --duration 10

Expected: `ready session=...`, then `end=duration
outcome=finalized exit=4`.
Exit 4 indicates finalized output with incomplete terminal evidence,
including zero-event and signal stops. Exit 3 names the refusal reason (profile, bridge,
privilege); exit 2 is a usage error; exit 1 is an error.
When no object is found anywhere, the refusal is `no
object: pass --object PATH`. `--object` and `--bridge`
are optional overrides for non-bundled artifacts;
without them the bridge resolves from `LMB_NATIVE_LIB`
when unprivileged (ignored under `sudo`), then beside
the executable, then the system path, and each BPF
object resolves beside the executable or under the
system directory.

On the admitted profile, the lifecycle and copy channels are
opt-in per run, with their objects discovered from the
bundle:

    sudo ./bin/memveil record --output /tmp/cap3 \
        --capability attempt-trace,mapping-lifecycle,copy-actual \
        --duration 10

(`--lc-object` and `--cp-object` override discovery
for non-bundled objects.)

Anything but the exact bound kernel and objects refuses with
exit 3 instead of recording an unverified channel. On a
qualified host the receipt admits the channel as `local-auto`;
a stale receipt loses that admission until step 3 is re-run,
with attempt-only recording falling back to partial.

Captures are written mode 0700/0600. A capture recorded
under `sudo` is handed back to the invoking user
automatically, so replay it in place. Only when the
restore cannot run (a root shell without sudo's
identity variables, or a `cannot restore capture
ownership` warning on stderr), hand the capture to your
user before the unprivileged replay below:

    sudo cp -r /tmp/cap1 ~/cap1 && sudo chown -R $USER ~/cap1
    chmod 700 ~/cap1 && chmod 600 ~/cap1/*

For the opt-in capture, replay `/tmp/cap3` in place, or
hand off `~/cap3` the same way and replay that with the
step 5 commands.

An idle machine usually records zero attempts with complete
counter snapshots: a valid-empty capture, visibly different
from an unavailable one. See `examples/real-capture/README.md`
for a capture with 30 real events.

## 5. Replay offline (unprivileged)

    ./bin/memveil report --format text /tmp/cap1
    ./bin/memveil report --format json /tmp/cap1
    ./bin/memveil report --format markdown /tmp/cap1

(If step 4 handed the capture off to `~/cap1`, replay that
path instead.)

Report reads local files only: no BPF, no BTF, no libbpf, no
network. Copy the capture directory to another machine (or
another user) and the same commands reproduce the same report.
Exit 0 means sufficient evidence; exit 4 means usable but
materially incomplete (the worked example exits 4 because
terminal settlement is unproven by design); exit 2 is invalid
input.

Empty is not unavailable: an idle capture reports
`bounce_attempts = 0` with complete detail quality, while rows
without their event source render `unavailable` with a reason.
A torn final record exits 2; rerun with `--allow-partial` to
drop the torn tail and report the loss instead (exit 4). See
`troubleshooting.md` for both recoveries.

## 6. Worked example

    ./bin/memveil report --format text examples/real-capture

Thirty real bounce attempts, fully lossless detail, with the
provenance and limitations each rendered beside the numbers.
The captured kernel/profile decision and measured scope are historical
claims about that capture, not admission of the current reader host.
Duration uses the recorded window with exact integer arithmetic; JSON
retains full provenance hashes. Missing or conflicting values remain explicit.

    ./bin/memveil top --interval 1s examples/real-capture

This replays a finished capture in periodic prefixes; it does not follow a
new workload live. Each summary shows its own measured prefix duration.

## Limits in one paragraph

Attempt collection with default-pool samples at start, on a
best-effort 1 s cadence (cap 4,096), and close when debugfs
is readable. Opportunistic samples with possible gaps cannot
diagnose sustained pressure alone; no pressure finding does
not mean no pressure. Lifecycle and executed copies are
qualified on the one admitted profile or a machine-local
receipt only; sharing transitions and
physical unions are unavailable, never inferred. One narrow bound
profile plus per-host receipts, with no broad kernel qualification.
Captures are written mode
0600. There is no configuration file, daemon, or network
access. Replay needs nothing live (see `performance.md` for
targets and historical development measurements). Open mappings
are live state, never automatic leaks (`resource-limits.md`).
Findings are observations, not host-access or attestation
verdicts (`support.md`). See `support.md` for the tested
envelope and `privacy.md` for exactly what a capture contains.
