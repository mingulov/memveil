# Toolchain BPF objects for the offline suites

`swiotlb_attempt.bpf.o`, `swiotlb_lifecycle.bpf.o`, and
`swiotlb_copy.bpf.o` are real compiler outputs for the BPF
target, built from the current sources with the pinned
nightly toolchain and linker the build script uses. Debug
paths are remapped to a fixed prefix, so the files carry no
machine-specific bytes. Suites that must run without a
build tree parse these instead of the build outputs.

Rebuild (from the repository root, with the pinned nightly,
its `rust-src` component, and the pinned linker on `PATH`;
flags mirror the build script's child invocation):

    env -u RUSTUP_TOOLCHAIN -u RUSTC \
      -u RUSTC_WORKSPACE_WRAPPER -u RUSTC_WRAPPER \
      CARGO_ENCODED_RUSTFLAGS="-C<US>linker=bpf-linker<US>-C<US>debuginfo=2<US>-C<US>link-arg=--btf<US>-C<US>target-cpu=v3<US>--remap-path-prefix=$HOME=/build-prefix" \
      rustup run nightly-2026-05-20 cargo build --locked --release \
      --target bpfel-unknown-none -Z build-std=core \
      --manifest-path crates/ebpf/Cargo.toml \
      --target-dir /tmp/aya-fixture-target

(`<US>` is the ASCII unit separator, `\x1f`.) The three
`release/memveil-ebpf-{attempt,lifecycle,copy}` artifacts
are the new files. Before committing, check that the bytes
contain no home-directory path and that the minter parses
the `mv_lifecycle`/`mv_copies` rings from them.
