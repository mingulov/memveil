<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil quickstart (development bundle 0.1.0)

MemVeil captures swiotlb bounce **attempts**, mapping **lifetimes**,
and executed **copies** on x86-64 Linux and replays them offline as
text, JSON, or Markdown. Attempts are try-counts; actual copies come
from the copy channel. This bundle runs from any directory: no
compiler, Pixi, network, or source checkout needed. The
[capability table](support.md#capabilities-by-mode) distinguishes the
shipping collector, offline reducers and laboratory probes.
Lifecycle/copy collection is qualified on one narrow profile; a full
confidential release is not yet qualified. The host supplies libc,
libm, libdl, and the dynamic loader for offline use, plus libelf
and libz for recording; see the support envelope for the exact
floor and tested OS.

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
Passive availability is not actual attachment or qualification. A `denied
(privilege)` hook means: re-run under `sudo` for collection, or
stay unprivileged and replay the shipped example (step 5); step 4
needs a capture of your own.

## 3. Record one capture (privileged)

Recording needs root (BPF load plus tracefs), the bundled BPF
object, and the native bridge:

    export LMB_NATIVE_LIB="$PWD/lib/libbpf_mojo.so.1"
    sudo -E ./bin/memveil record --output /tmp/cap1 \
        --object "$PWD/bpf/swiotlb_attempt.bpf.o" --duration 10

(`sudo -E` preserves `LMB_NATIVE_LIB`; or pass
`--bridge "$PWD/lib/libbpf_mojo.so.1"` instead.) Expected: `ready
session=...`, then `end=duration outcome=finalized exit=4`.
Exit 4 indicates finalized output with incomplete terminal evidence,
including zero-event and signal stops. Exit 3 names the refusal reason (profile, bridge,
privilege); exit 2 is a usage error; exit 1 is an error.

On the admitted profile, the lifecycle and copy channels are
opt-in per run:

    sudo -E ./bin/memveil record --output /tmp/cap3 \
        --object "$PWD/bpf/swiotlb_attempt.bpf.o" \
        --capability attempt-trace,mapping-lifecycle,copy-actual \
        --lc-object "$PWD/bpf/swiotlb_lifecycle.bpf.o" \
        --cp-object "$PWD/bpf/swiotlb_copy.bpf.o" --duration 10

Anything but the exact bound kernel and objects refuses with
exit 3 instead of recording an unverified channel.

Captures are root-owned (mode 0700/0600), so hand yours to your
user before the unprivileged replay below:

    sudo cp -r /tmp/cap1 ~/cap1 && sudo chown -R $USER ~/cap1
    chmod 700 ~/cap1 && chmod 600 ~/cap1/*

For the opt-in capture, hand off `/tmp/cap3` the same way and
replay `~/cap3` with the step 4 commands:

    sudo cp -r /tmp/cap3 ~/cap3 && sudo chown -R $USER ~/cap3
    chmod 700 ~/cap3 && chmod 600 ~/cap3/*

An idle machine usually records zero attempts with complete
counter snapshots: a valid-empty capture, visibly different
from an unavailable one. See `examples/real-capture/README.md`
for a capture with 30 real events.

## 4. Replay offline (unprivileged)

    ./bin/memveil report --format text ~/cap1
    ./bin/memveil report --format json ~/cap1
    ./bin/memveil report --format markdown ~/cap1

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

## 5. Worked example

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
qualified on the one admitted profile only; sharing transitions and
physical unions are unavailable, never inferred. One narrow bound
profile, with no broad kernel qualification.
Captures are written mode
0600. There is no configuration file, daemon, or network
access. Replay needs nothing live (see `performance.md` for
targets and historical development measurements). Open mappings
are live state, never automatic leaks (`resource-limits.md`).
Findings are observations, not host-access or attestation
verdicts (`support.md`). See `support.md` for the tested
envelope and `privacy.md` for exactly what a capture contains.
