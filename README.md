<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# memveil

Attempt, lifecycle, and copy capture for swiotlb bounce analysis
on x86-64 Linux: record real `swiotlb_bounced` tracepoint
activity, mapping lifetimes, and executed copies into a
self-describing capture directory, then replay it offline as
text, JSON, or Markdown. Attempt counts are try-counts with
requested bytes; actual copies come from the copy channel.
Pool pressure and diagnostic findings reduce offline over
captures that carry the corresponding events.

Status: attempt/lifecycle/copy development bundle 0.1.0, with runnable
build, test, and tarball packaging wrappers. The shipping collector
records attempts, mapping lifetimes, and executed copies on the
admitted profile, plus optional readable default-pool start/end samples.
`top` replays finished captures; a live summary is still missing.
Laboratory probes and offline reducers do not qualify shipping
collection, successful DMA, sustained pressure, or
confidential-memory collection. The original lifecycle preview and
full confidential first-release gates remain open.

The [support table](docs/support.md#capabilities-by-mode) defines the
capabilities by mode. One narrow profile,
`linux-x86_64-7.0.0-34-generic`, has VM-gate attempt, lifecycle,
and copy evidence; admission also requires its exact
config/BTF/object bindings.
A rebuilt package or matching kernel name alone earns no qualification.

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
    ./bin/memveil top --interval 1s ~/cap1          # finished-capture replay

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
vendored `libbpf-mojo` library bundle (`third_party/`): bridge
library, Mojo wrappers, and C header, never a sibling checkout;
`LMB_PACKAGE` overrides it with another hash-verified tarball.

    ./tools/build                                    # build everything
    ./tools/test --help                              # list suites
    LMB_PACKAGE=third_party/libbpf-mojo-0.1.0.tar.gz ./tools/test buildcache
    LMB_PACKAGE=... ./tools/package                  # owner bundle + MANIFEST

`report`, `top`, and `doctor` work without the bridge library;
only `record` loads it (lazily, at session open).

## Licensing

MemVeil is GPL-3.0-or-later (`LICENSE`), except the eBPF
programs (`bpf/programs/swiotlb_attempt.bpf.c`,
`bpf/programs/swiotlb_lifecycle.bpf.c`,
`bpf/programs/swiotlb_copy.bpf.c`, GPL-2.0-only),
the BPF/userspace shared headers
(`bpf/include/memveil_events.h` and
`bpf/include/mv_fentry_types.h`, GPL-2.0-or-later;
`bpf/include/memveil_control.h`, GPL-2.0-only), and the
test-only oracle kernel modules
(`tests/kernel/memveil_dma_oracle.c`,
`tests/kernel/memveil_region_oracle.c`, and
`tests/kernel/Makefile`, GPL-2.0-only); texts in
`LICENSES/`. Every source file carries an SPDX header.
Redistributed third-party components, with their staged
license texts, are listed in `THIRD-PARTY-NOTICES.md`. The
owner bundle stages all of these plus the pinned
libbpf-mojo's own texts; `MANIFEST.json` records the
first-party license map under `first_party`.
