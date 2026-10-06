# MemVeil quickstart (development bundle 0.1.0)

MemVeil captures swiotlb bounce **attempts** (try-counts, not copies)
on x86-64 Linux and replays them offline as text, JSON, or Markdown.
This bundle runs from any directory: no compiler, Pixi, network, or
source checkout needed.

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
per-capability reasons. Only kernel `7.0.0-34-generic` on x86-64
is validated; anything else runs unbound or refuses. A `denied
(privilege)` hook means: re-run under `sudo` for collection, or
stay unprivileged for replay (step 4).

## 3. Record one capture (privileged)

Recording needs root (BPF load plus tracefs), the bundled BPF
object, and the native bridge:

    export LMB_NATIVE_LIB=$PWD/lib/libbpf_mojo.so.1
    sudo -E ./bin/memveil record --output /tmp/cap1 \
        --object $PWD/bpf/swiotlb_attempt.bpf.o --duration 10

(`sudo -E` preserves `LMB_NATIVE_LIB`; or pass
`--bridge $PWD/lib/libbpf_mojo.so.1` instead.) Expected: `ready
session=...`, then `end=duration outcome=finalized exit=4`.
Exit 4 is the normal finalized code, including zero-event and
signal stops. Exit 3 names the refusal reason (profile, bridge,
privilege); exit 2 is a usage error; exit 1 is an error.

The capture is root-owned (mode 0700/0600), so hand it to your
user before the unprivileged replay below:

    sudo cp -r /tmp/cap1 ~/cap1 && sudo chown -R $USER ~/cap1
    chmod 700 ~/cap1 && chmod 600 ~/cap1/*

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

## 5. Worked example

    ./bin/memveil report --format text examples/real-capture

Thirty real bounce attempts, fully lossless detail, with the
provenance and limitations each rendered beside the numbers.

## Limits in one paragraph

Attempt counts only: lifecycle, actual copy bytes, sharing
transitions, and physical unions are unavailable, never
inferred. One validated kernel. Captures are written mode
0600. There is no configuration file, daemon, or network
access. See `support.md` for the tested envelope and
`privacy.md` for exactly what a capture contains.
