<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Toolchain BPF objects for the offline suites

`swiotlb_attempt.bpf.o`, `swiotlb_lifecycle.bpf.o`, and
`swiotlb_copy.bpf.o` are real compiler outputs for the BPF
target, built from the current sources with the pinned
nightly toolchain and linker the build script uses. Debug
paths are remapped to fixed prefixes, so the files carry no
machine-specific bytes. Suites that must run without a
build tree parse these instead of the build outputs.

Rebuild (from the repository root, with the pinned nightly,
its `rust-src` component, and the pinned linker on `PATH`;
flags mirror the build script's child invocation, plus two
path remaps: the home directory first, then the checkout
root, which must stay last so checkout paths land under
`/build-root` instead of leaking the checkout location):

    US=$(printf '\037')
    env -u RUSTUP_TOOLCHAIN -u RUSTC \
      -u RUSTC_WORKSPACE_WRAPPER -u RUSTC_WRAPPER \
      CARGO_ENCODED_RUSTFLAGS="-C${US}linker=bpf-linker${US}-C${US}debuginfo=2${US}-C${US}link-arg=--btf${US}-C${US}target-cpu=v3${US}--remap-path-prefix=$HOME=/build-prefix${US}--remap-path-prefix=$(pwd)=/build-root" \
      rustup run nightly-2026-05-20 cargo build --locked --release \
      --target bpfel-unknown-none -Z build-std=core \
      --manifest-path crates/ebpf/Cargo.toml \
      --target-dir /tmp/aya-fixture-target

The three `release/memveil-ebpf-{attempt,lifecycle,copy}`
artifacts are the new files. Before committing, check with
`strings` plus `grep` that the bytes contain no checkout,
home-directory, user, or host path, and that the minter
parses the `mv_lifecycle`/`mv_copies` rings from them.
