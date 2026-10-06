# memveil

Attempt capture for swiotlb bounce analysis on x86-64 Linux:
record real `swiotlb_bounced` tracepoint activity into a
self-describing capture directory, then replay it offline as
text, JSON, or Markdown. Counts are attempts (try-counts with
requested bytes), never inferred copies.

Status: development bundle 0.1.0. One validated profile
(`linux-x86_64-7.0.0-34-generic`). Mapping lifecycle, actual
copy bytes, sharing transitions, and physical unions are
unavailable, never inferred. No release, packaging format, or
license decision has been made yet.

## Use (from the bundle)

    tar -xzf memveil-0.1.0.tar.gz && cd memveil-0.1.0
    ./bin/memveil doctor                            # passive host check
    export LMB_NATIVE_LIB=$PWD/lib/libbpf_mojo.so.1
    sudo -E ./bin/memveil record --output /tmp/cap1 \
        --object $PWD/bpf/swiotlb_attempt.bpf.o --duration 10
    sudo cp -r /tmp/cap1 ~/cap1 && sudo chown -R $USER ~/cap1
    ./bin/memveil report --format text ~/cap1       # unprivileged replay

`docs/quickstart.md` walks the five-minute test;
`docs/support.md` states the tested envelope and exit codes;
`docs/privacy.md` lists exactly what a capture contains.
`examples/real-capture` is a reviewed 30-event capture with
expected outputs.

## Build and test (from source)

Pinned Mojo 1.1.0 toolchain via pixi; see `docs/build.md` and
`toolchain.lock.json`. The native bridge comes from a pinned
`libbpf-mojo` source archive (`LMB_PACKAGE`), never a sibling
checkout.

    ./tools/build                                    # build everything
    LMB_PACKAGE=/path/to/libbpf-mojo-0.2.0.tar.gz ./tools/test <suite>
    ./tools/test --help                              # list suites
    LMB_PACKAGE=... ./tools/package                  # owner bundle + MANIFEST

`report` and `doctor` work without the bridge library; only
`record` loads it (lazily, at session open).
