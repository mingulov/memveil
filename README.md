<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# memveil

Attempt capture for swiotlb bounce analysis on x86-64 Linux:
record real `swiotlb_bounced` tracepoint activity into a
self-describing capture directory, then replay it offline as
text, JSON, or Markdown. Counts are attempts (try-counts with
requested bytes), never inferred copies. Mapping lifecycle,
actual copy bytes, pool pressure, and diagnostic findings
reduce offline over captures that carry the corresponding
events.

Status: development bundle 0.1.0. One validated profile
(`linux-x86_64-7.0.0-34-generic`). Live lifecycle probes
are not qualified, so live captures carry attempts only;
sharing transitions and physical unions are unavailable,
never inferred. No release or packaging-format decision has
been made yet.

## Use (from the bundle)

    tar -xzf memveil-0.1.0.tar.gz && cd memveil-0.1.0
    ./bin/memveil doctor                            # passive host check
    export LMB_NATIVE_LIB=$PWD/lib/libbpf_mojo.so.1
    sudo -E ./bin/memveil record --output /tmp/cap1 \
        --object $PWD/bpf/swiotlb_attempt.bpf.o --duration 10
    # If sudo drops the environment, pass the bridge directly:
    # sudo ./bin/memveil record --bridge $PWD/lib/libbpf_mojo.so.1 ...
    sudo cp -r /tmp/cap1 ~/cap1 && sudo chown -R $USER ~/cap1
    ./bin/memveil report --format text ~/cap1       # unprivileged replay
    ./bin/memveil top --interval 1s ~/cap1          # periodic summaries

`docs/quickstart.md` walks the five-minute test;
`docs/support.md` states the tested envelope and exit codes;
`docs/privacy.md` lists exactly what a capture contains.
`docs/permissions.md` details privilege separation and the
record refusal gates; `docs/troubleshooting.md` is the
symptom-to-fix index.
`examples/real-capture` is a reviewed 30-event capture with
expected outputs.

## Build and test (from source)

Pinned Mojo 1.1.0 toolchain via pixi; see `docs/build.md` and
`toolchain.lock.json`. The native bridge comes from the pinned
vendored `libbpf-mojo` source archive (`third_party/`), never
a sibling checkout; `LMB_PACKAGE` overrides it with another
hash-verified tarball.

    ./tools/build                                    # build everything
    ./tools/test --help                              # list suites
    LMB_PACKAGE=third_party/libbpf-mojo-0.2.2.tar.gz ./tools/test buildcache
    LMB_PACKAGE=... ./tools/package                  # owner bundle + MANIFEST

`report`, `top`, and `doctor` work without the bridge library;
only `record` loads it (lazily, at session open).

## Licensing

MemVeil is GPL-3.0-or-later (`LICENSE`), except the eBPF
program (`bpf/programs/swiotlb_attempt.bpf.c`, GPL-2.0-only),
the BPF/userspace shared header
(`bpf/include/memveil_events.h`, GPL-2.0-or-later), and the
test-only oracle kernel module
(`tests/kernel/memveil_dma_oracle.c` and its makefile,
GPL-2.0-only); texts in `LICENSES/`. Every source file
carries an SPDX header.
Redistributed third-party components, with their staged
license texts, are listed in `THIRD-PARTY-NOTICES.md`. The
owner bundle stages all of these plus the pinned
libbpf-mojo's own texts; `MANIFEST.json` records the
first-party license map under `first_party`.
