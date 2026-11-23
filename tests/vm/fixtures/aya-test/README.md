<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Saturation-test BPF objects (4 KiB rings)

`swiotlb_lifecycle-test.bpf.o` and `swiotlb_copy-test.bpf.o`
are real compiler outputs for the BPF target, built from the
current sources with the `test-ring` feature (4 KiB
lifecycle/copy rings instead of the production 32 MiB) and
the pinned nightly toolchain and linker the build script
uses. Every other map and program is identical to the
production objects in `../aya/`, so the saturation flood
leg exhausts the ring instead of assuming loss accounting.
Debug paths are remapped to fixed prefixes, so the files
carry no machine-specific bytes. Test-only fixtures, never
shipped: the digests are pinned by the battery core, and the
consumer loader admits the 4 KiB geometry explicitly.

Rebuild (from the repository root, with the pinned nightly,
its `rust-src` component, and the pinned linker on `PATH`;
flags mirror the `../aya/README.md` recipe plus the
feature, plus two path remaps: the home directory first,
then the checkout root, which must stay last so checkout
paths land under `/build-root` instead of leaking the
checkout location):

    US=$(printf '\037')
    env -u RUSTUP_TOOLCHAIN -u RUSTC \
      -u RUSTC_WORKSPACE_WRAPPER -u RUSTC_WRAPPER \
      CARGO_ENCODED_RUSTFLAGS="-C${US}linker=bpf-linker${US}-C${US}debuginfo=2${US}-C${US}link-arg=--btf${US}-C${US}target-cpu=v3${US}--remap-path-prefix=$HOME=/build-prefix${US}--remap-path-prefix=$(pwd)=/build-root" \
      rustup run nightly-2026-05-20 cargo build --locked --release \
      --features test-ring \
      --target bpfel-unknown-none -Z build-std=core \
      --manifest-path crates/ebpf/Cargo.toml \
      --target-dir /tmp/aya-test-target

The `release/memveil-ebpf-{lifecycle,copy}` artifacts are
the new files. Before committing, check with `strings` plus
`grep` that the bytes contain no checkout, home-directory,
user, or host path; that the consumer `--verify-layout`
probe reports family `aya` with the ring map at 4096
entries and every other row identical to the `../aya/`
object; and that rebuilding twice yields identical bytes.
