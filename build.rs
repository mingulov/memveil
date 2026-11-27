// SPDX-License-Identifier: GPL-3.0-or-later
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
//!
//! The script also publishes each artifact's SHA-256 as
//! `DEP_MEMVEIL_EBPF_<CH>_DIGEST`, hashed from the same
//! `OUT_DIR` copy the crate embeds, so the packager can bind
//! inspection copies to the exact bytes the binary runs
//! (an occurrence search cannot tell planted bytes apart
//! from the runtime bytes).

// Reuse the crate's dependency-free SHA-256 rather than a
// second implementation or a new build dependency.
#[path = "src/platform/hash.rs"]
mod hash;

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

/// Nightly that builds the eBPF crate; must equal the `channel` in
/// `crates/ebpf/rust-toolchain.toml`. Equality is asserted in `main` by
/// parsing that file, so drift fails the build instead of silently mixing
/// a direct cargo invocation with the pinned nightly.
const BPF_TOOLCHAIN: &str = "nightly-2026-05-20";

/// (channel, `DEP_MEMVEIL_EBPF_<CH>_PATH` suffix): one BPF object per
/// channel; the journal channel rides the same Aya build.
const CHANNELS: [(&str, &str); 4] = [
    ("attempt", "ATTEMPT"),
    ("lifecycle", "LIFECYCLE"),
    ("copy", "COPY"),
    ("journal", "JOURNAL"),
];

/// Read the `channel = "..."` value from a `rust-toolchain.toml`. Minimal
/// line scan (no TOML parser in a build script): matches a `channel` key
/// before the first `=` and strips one layer of double quotes.
fn read_toolchain_channel(path: &Path) -> String {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    for line in text.lines() {
        let mut parts = line.splitn(2, '=');
        if parts.next().is_some_and(|key| key.trim() == "channel")
            && let Some(value) = parts.next()
        {
            return value.trim().trim_matches('"').to_owned();
        }
    }
    panic!("no `channel = ...` line in {}", path.display())
}

fn main() {
    // Runtime CPU floor: the shipped engine must carry a loadable
    // x86-64-v3 requirement (GNU_PROPERTY_X86_ISA_1_NEEDED) so the
    // glibc loader refuses older CPUs before any constructor runs.
    // Code generation stays at the compiler default; only the link
    // adds the declaration. The repository cargo config links this
    // target with GNU ld (rust-lld ignores `-z x86-64-v*`), and the
    // packager refuses any binary without the mark, so an unmarked
    // build can never seal. Other targets keep their default link:
    // the flag is x86-64-ELF-only.
    if env::var("TARGET").as_deref() == Ok("x86_64-unknown-linux-gnu") {
        println!("cargo::rustc-link-arg=-Wl,-z,x86-64-v3");
    }
    // NOTE (candidate qualification): this child eBPF build runs in the
    // fixture-prep phase only (tests/support/journey_prep.py builds the
    // journey executables once and records them). Qualification itself
    // launches those recorded executables directly and never invokes
    // cargo, so no product build runs behind a sealed verdict. The
    // library embeds the objects via include_bytes!(env!(
    // DEP_MEMVEIL_EBPF_*)), which is why the prep build must exist
    // before qualification, not why qualification would rebuild.
    println!("cargo::rerun-if-changed=crates/ebpf/src");
    println!("cargo::rerun-if-changed=crates/ebpf/src/bin");
    println!("cargo::rerun-if-changed=crates/ebpf/src/common.rs");
    println!("cargo::rerun-if-changed=crates/ebpf/Cargo.toml");
    println!("cargo::rerun-if-changed=crates/ebpf/Cargo.lock");
    println!("cargo::rerun-if-changed=crates/ebpf/rust-toolchain.toml");
    println!("cargo::rerun-if-changed=crates/ebpf-common/src");
    println!("cargo::rerun-if-changed=crates/ebpf-common/Cargo.toml");
    // The child invocation inherits the encoded rustflags below, so a flag
    // change must rebuild the BPF objects. Watch both spellings: cargo
    // derives the encoded form from `RUSTFLAGS`, and either may be the one
    // the caller actually changed. The effective set also reads the dotted
    // config spelling and the home config location, so those rerun too;
    // config files print their own watches once probed below.
    println!("cargo::rerun-if-env-changed=RUSTFLAGS");
    println!("cargo::rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo::rerun-if-env-changed=CARGO_BUILD_RUSTFLAGS");
    println!("cargo::rerun-if-env-changed=CARGO_HOME");
    // The home-directory remap below derives from HOME, so a HOME change
    // must rebuild the BPF objects too.
    println!("cargo::rerun-if-env-changed=HOME");

    // Preflight: fail early with an actionable message when the linker is
    // missing or the wrong version. Local probe only, so it cannot break
    // offline rebuilds. Limitation: no rerun trigger watches the external
    // binary, so a bare bpf-linker swap alone does not rerun the build.
    let version = Command::new("bpf-linker")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    // `bpf-linker --version` prints `bpf-linker 0.10.4`; match the exact
    // token so 0.10.40 or a prefixed 10.10.4 cannot slip through.
    let linker_ok = version
        .split_whitespace()
        .any(|token| token.strip_prefix('v').unwrap_or(token) == "0.10.4");
    assert!(
        linker_ok,
        "bpf-linker 0.10.4 is required on PATH (got {version:?}): \
         run `cargo install bpf-linker --version 0.10.4 --locked`"
    );

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));

    // The eBPF crate pins its own toolchain file; the `rustup run`
    // selection below must name the same nightly. Parse and compare so
    // the two cannot drift apart unnoticed.
    let toolchain_file = manifest_dir.join("crates/ebpf/rust-toolchain.toml");
    let pinned_channel = read_toolchain_channel(&toolchain_file);
    assert_eq!(
        pinned_channel,
        BPF_TOOLCHAIN,
        "BPF_TOOLCHAIN ({BPF_TOOLCHAIN}) disagrees with {} ({pinned_channel}): \
         update both together",
        toolchain_file.display()
    );

    let target = "bpfel-unknown-none";
    // The child cargo must be the pinned nightly, selected through rustup.
    // `$CARGO` is deliberately NOT the vehicle: under rustup it names the
    // real toolchain cargo binary, which rejects the `+toolchain` override
    // (`no such command`), so it cannot select the pinned nightly. A bare
    // `cargo` would depend on PATH resolving to the rustup proxy. `rustup
    // run` states the requirement directly and fails loudly when rustup is
    // absent (the old `+toolchain` spelling needed it too).
    let mut cmd = Command::new("rustup");
    cmd.args(["run", BPF_TOOLCHAIN, "cargo"]);
    // The pinned toolchain must win: a leaked `RUSTUP_TOOLCHAIN` or host
    // `RUSTC` override would otherwise build with the host toolchain.
    cmd.env_remove("RUSTUP_TOOLCHAIN");
    cmd.env_remove("RUSTC");
    // Clippy wrappers are host-toolchain-bound: host `cargo clippy` exports
    // its own clippy-driver path via `RUSTC_WORKSPACE_WRAPPER`, and the
    // pinned-nightly child fails hard (exit 101, "cannot find a built-in
    // macro") when it inherits the host driver — reproduced: no wrapper
    // exits 0, stable-driver wrapper exits 101, pinned-nightly-driver
    // wrapper exits 0. Strip both so the child never inherits them.
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
    // Known non-fatal noise: each link warns `unable to open LLVM shared
    // lib .../libLLVM-22-rust-1.97.0-nightly.so: dlopen failed`. That file
    // is a 43-byte GNU ld script (`INPUT(libLLVM.so.22...)`), not an ELF
    // object, and bpf-linker 0.10.4 dlopens the script name instead of the
    // real library. Links still succeed with BTF intact; re-check if the
    // linker or nightly pin ever moves.
    //
    // target-cpu=v3: a *consumed* fetch-add result (old value kept for
    // wrap detection) needs BPF CPU v3, i.e. kernels >= 5.12. MemVeil's
    // floors (attempts 6.0, lifecycle/copy 6.11) are all above that, so
    // v3 is matrix-compatible; non-fetch add/or and CAS lower on any CPU.
    // The child honors the flag set Cargo itself would use: the encoded
    // spelling when set, else RUSTFLAGS when set (a set-but-empty channel
    // still shadows the rest), else the config layer carried forward so
    // this export shadows nothing. The linker flags extend that set, the
    // remap pair lands exactly once at the end, and everything leaves
    // through the encoded channel alone.
    let proc_env =
        memveil_remap_flags::process_env().unwrap_or_else(|err| panic!("remap flags: {err}"));
    let effective = memveil_remap_flags::effective_rustflags(&proc_env, &manifest_dir)
        .unwrap_or_else(|err| panic!("remap flags: {err}"));
    for probed in &effective.config_files {
        println!("cargo::rerun-if-changed={}", probed.display());
    }
    let mut flags = effective.flags;
    flags.extend(
        [
            "-C",
            "linker=bpf-linker",
            "-C",
            "debuginfo=2",
            "-C",
            "link-arg=--btf",
            "-C",
            "target-cpu=v3",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    // Debug paths baked into the shipped objects must not name the build
    // machine: remap the home directory first, then the checkout root
    // last, so checkout paths land under /build-root. Same pair the
    // offline fixtures are rebuilt with (see
    // tests/vm/fixtures/aya/README.md); a missing or empty HOME
    // contributes no remap.
    let home = proc_env.get("HOME").map(String::as_str).unwrap_or("");
    memveil_remap_flags::append_remaps(&mut flags, home, &manifest_dir);
    cmd.env("CARGO_ENCODED_RUSTFLAGS", flags.join("\u{1f}"));
    cmd.env_remove("RUSTFLAGS");

    let status = cmd.status().unwrap_or_else(|error| {
        panic!("spawning `rustup run {BPF_TOOLCHAIN} cargo` for crates/ebpf: {error} (is rustup on PATH?)")
    });
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
        // Digest of the staged copy the crate embeds (not the
        // build-tree original): the manifest the binary dumps
        // must name exactly the bytes `embedded_object` serves.
        let staged = std::fs::read(&dest)
            .unwrap_or_else(|error| panic!("hashing {}: {error}", dest.display()));
        println!(
            "cargo::rustc-env=DEP_MEMVEIL_EBPF_{dep_suffix}_DIGEST={}",
            hash::sha256_hex(&staged)
        );
    }
}
