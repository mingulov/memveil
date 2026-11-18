//! Build script: compiles `crates/ebpf` for the BPF target with the pinned
//! nightly toolchain and publishes the ELF path as `DEP_MEMVEIL_EBPF_PATH`.
//!
//! `aya_build::build_ebpf` is deliberately not used: it resolves the eBPF
//! crate by package name inside *this* workspace, but `crates/ebpf` is not a
//! member (it pins its own `[workspace]` so the `#![no_std]` BPF binary is
//! never built for the host). Instead this script shells out to the pinned
//! nightly cargo directly and copies the artifact into `OUT_DIR`.
//!
//! The path is exposed via `cargo::rustc-env=DEP_MEMVEIL_EBPF_PATH=...` so the
//! crate's own library, binaries, and integration tests can read it with
//! `env!`. (A `links`-metadata `DEP_` variable would only reach downstream
//! build scripts, which this root package has none of.)

use std::{env, path::PathBuf, process::Command};

/// Nightly that builds the eBPF crate; must match
/// `crates/ebpf/rust-toolchain.toml`.
const BPF_TOOLCHAIN: &str = "nightly-2026-05-20";

fn main() {
    println!("cargo::rerun-if-changed=crates/ebpf/src");
    println!("cargo::rerun-if-changed=crates/ebpf/Cargo.toml");
    println!("cargo::rerun-if-changed=crates/ebpf/Cargo.lock");
    println!("cargo::rerun-if-changed=crates/ebpf/rust-toolchain.toml");
    println!("cargo::rerun-if-changed=crates/ebpf-common/src");
    println!("cargo::rerun-if-changed=crates/ebpf-common/Cargo.toml");

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));

    let target = "bpfel-unknown-none";
    let mut cmd = Command::new("cargo");
    cmd.arg(format!("+{BPF_TOOLCHAIN}"));
    // The `+toolchain` override must win: a leaked `RUSTUP_TOOLCHAIN` or host
    // `RUSTC` override would otherwise build with the host toolchain.
    cmd.env_remove("RUSTUP_TOOLCHAIN");
    cmd.env_remove("RUSTC");
    // Clippy/coverage wrappers are host-only: the pinned nightly has no
    // clippy-driver, so inheriting them breaks the BPF build under
    // `cargo clippy`.
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");
    cmd.env_remove("RUSTC_WRAPPER");
    cmd.args([
        "build",
        "--locked",
        "--release",
        "--target",
        target,
        "-Z",
        "build-std=core",
        "--manifest-path",
    ])
    .arg(manifest_dir.join("crates/ebpf/Cargo.toml"))
    .arg("--target-dir")
    .arg(out_dir.join("ebpf-target"));

    // Link with bpf-linker and keep BTF: fentry/fexit attach needs it.
    let mut flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    for flag in [
        "-C",
        "linker=bpf-linker",
        "-C",
        "debuginfo=2",
        "-C",
        "link-arg=--btf",
    ] {
        if !flags.is_empty() {
            flags.push('\u{1f}');
        }
        flags.push_str(flag);
    }
    cmd.env("CARGO_ENCODED_RUSTFLAGS", flags);

    let status = cmd
        .status()
        .expect("spawning pinned nightly cargo for crates/ebpf");
    assert!(
        status.success(),
        "building crates/ebpf with {BPF_TOOLCHAIN} failed: {status}"
    );

    let built = out_dir
        .join("ebpf-target")
        .join(target)
        .join("release/memveil-ebpf");
    let dest = out_dir.join("memveil-ebpf");
    std::fs::copy(&built, &dest)
        .unwrap_or_else(|error| panic!("copying {} to OUT_DIR: {error}", built.display()));
    println!("cargo::rustc-env=DEP_MEMVEIL_EBPF_PATH={}", dest.display());
}
