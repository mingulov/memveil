//! Build script: compiles the three `crates/ebpf` channel bins for the BPF
//! target with the pinned nightly toolchain and publishes each ELF path as
//! `DEP_MEMVEIL_EBPF_{ATTEMPT,LIFECYCLE,COPY}_PATH`.
//!
//! `aya_build::build_ebpf` is deliberately not used: it resolves the eBPF
//! crate by package name inside *this* workspace, but `crates/ebpf` is not a
//! member (it pins its own `[workspace]` so the `#![no_std]` BPF binaries are
//! never built for the host). Instead this script shells out to the pinned
//! nightly cargo directly and copies each artifact into `OUT_DIR`.
//!
//! The paths are exposed via `cargo::rustc-env=DEP_MEMVEIL_EBPF_<CH>_PATH=...`
//! so the crate's own library, binaries, and integration tests can read them
//! with `env!`. (A `links`-metadata `DEP_` variable would only reach
//! downstream build scripts, which this root package has none of.)
//!
//! Prerequisite: `bpf-linker` 0.10.4 on PATH. Install it with
//! `cargo install bpf-linker --version 0.10.4 --locked`.

use std::{env, path::PathBuf, process::Command};

/// Nightly that builds the eBPF crate; must match
/// `crates/ebpf/rust-toolchain.toml`.
const BPF_TOOLCHAIN: &str = "nightly-2026-05-20";

/// (channel, `DEP_MEMVEIL_EBPF_<CH>_PATH` suffix): one BPF object per
/// channel, mirroring the C 3-object design.
const CHANNELS: [(&str, &str); 3] = [
    ("attempt", "ATTEMPT"),
    ("lifecycle", "LIFECYCLE"),
    ("copy", "COPY"),
];

fn main() {
    println!("cargo::rerun-if-changed=crates/ebpf/src");
    println!("cargo::rerun-if-changed=crates/ebpf/src/bin");
    println!("cargo::rerun-if-changed=crates/ebpf/src/common.rs");
    println!("cargo::rerun-if-changed=crates/ebpf/Cargo.toml");
    println!("cargo::rerun-if-changed=crates/ebpf/Cargo.lock");
    println!("cargo::rerun-if-changed=crates/ebpf/rust-toolchain.toml");
    println!("cargo::rerun-if-changed=crates/ebpf-common/src");
    println!("cargo::rerun-if-changed=crates/ebpf-common/Cargo.toml");

    // Preflight: fail early with an actionable message when the linker is
    // missing. Local probe only, so it cannot break offline rebuilds.
    let linker_ok = Command::new("bpf-linker")
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success());
    assert!(
        linker_ok,
        "bpf-linker 0.10.4 is required on PATH: \
         run `cargo install bpf-linker --version 0.10.4 --locked`"
    );

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
    //
    // target-cpu=v3: a *consumed* fetch-add result (old value kept for
    // wrap detection) needs BPF CPU v3, i.e. kernels >= 5.12. MemVeil's
    // floors (attempts 6.0, lifecycle/copy 6.11) are all above that, so
    // v3 is matrix-compatible; non-fetch add/or and CAS lower on any CPU.
    let mut flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    for flag in [
        "-C",
        "linker=bpf-linker",
        "-C",
        "debuginfo=2",
        "-C",
        "link-arg=--btf",
        "-C",
        "target-cpu=v3",
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

    for (channel, dep_suffix) in CHANNELS {
        let built = out_dir
            .join("ebpf-target")
            .join(target)
            .join(format!("release/memveil-ebpf-{channel}"));
        let dest = out_dir.join(format!("memveil-ebpf-{channel}"));
        std::fs::copy(&built, &dest)
            .unwrap_or_else(|error| panic!("copying {} to OUT_DIR: {error}", built.display()));
        println!(
            "cargo::rustc-env=DEP_MEMVEIL_EBPF_{dep_suffix}_PATH={}",
            dest.display()
        );
    }
}
