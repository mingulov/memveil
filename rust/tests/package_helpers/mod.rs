// SPDX-License-Identifier: GPL-3.0-or-later
// Shared across six test binaries, each using a subset: per-binary
// dead-code analysis would otherwise fail `-D warnings`.
#![allow(dead_code)]
//! Shared helpers for the Rust packaging test suites.
//!
//! The `package_*.rs` integration suites build the three release
//! packages (tarball, .deb, .rpm) through `rust/scripts/package-*`
//! and assert artifact parity with the Mojo-tree packaging gates.
//! This module owns path discovery, tool probes, package builds
//! (shared across test binaries through lock files under
//! `target/package-test/`), ELF inspection, archive listing, and
//! the payload-manifest collect/check plus SPDX emit ports used
//! by `package_payload.rs`.
//!
//! Every cargo invocation strips `RUSTUP_TOOLCHAIN` so the
//! repository pin (1.100.0) wins over ambient overrides.

pub mod journey;
pub mod payload;
pub mod sbom;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// Shipped BPF object file names (inspection copies).
pub const BPF_OBJECTS: [&str; 3] = [
    "swiotlb_attempt.bpf.o",
    "swiotlb_lifecycle.bpf.o",
    "swiotlb_copy.bpf.o",
];

/// FHS payload members pinned literally, as root-relative paths:
/// every member outside the lib/ closure extras, the docs/profiles
/// mirrors, and format-only files. The single source both the .deb
/// and the .rpm fixed-set gates consume, so the two formats cannot
/// drift (the .rpm maps each entry to its /-rooted form).
pub const FHS_FIXED_FILES: [&str; 30] = [
    "usr/bin/memveil",
    "usr/lib/memveil/libgcc_s.so.1",
    "usr/lib/memveil/swiotlb_attempt.bpf.o",
    "usr/lib/memveil/swiotlb_lifecycle.bpf.o",
    "usr/lib/memveil/swiotlb_copy.bpf.o",
    "usr/share/doc/memveil/copyright",
    "usr/share/doc/memveil/LICENSE",
    "usr/share/doc/memveil/THIRD-PARTY-NOTICES.md",
    "usr/share/doc/memveil/LICENSES/GPL-2.0-only.txt",
    "usr/share/doc/memveil/LICENSES/GPL-2.0-or-later.txt",
    "usr/share/doc/memveil/LICENSES/GPL-2.0.txt",
    "usr/share/doc/memveil/licenses/GPL-3.0.txt",
    "usr/share/doc/memveil/licenses/RUNTIME.LIBRARY.EXCEPTION",
    "usr/share/memveil/docs/examples/real-capture/README.md",
    "usr/share/memveil/docs/examples/real-capture/events.ndjson",
    "usr/share/memveil/docs/examples/real-capture/session.json",
    "usr/share/memveil/docs/examples/lifecycle-copy/README.md",
    "usr/share/memveil/docs/examples/lifecycle-copy/events.ndjson",
    "usr/share/memveil/docs/examples/lifecycle-copy/session.json",
    "usr/share/memveil/docs/examples/lifecycle-copy/oracle-phase.log",
    "usr/share/memveil/docs/examples/lifecycle-copy/fail-phase.log",
    "usr/share/man/man1/memveil.1",
    "usr/share/man/man1/memveil-record.1",
    "usr/share/man/man1/memveil-report.1",
    "usr/share/man/man1/memveil-top.1",
    "usr/share/man/man1/memveil-doctor.1",
    "usr/share/man/man1/memveil-qualify.1",
    "usr/share/man/man1/memveil-bind-profile.1",
    "usr/share/bash-completion/completions/memveil",
    "usr/share/zsh/vendor-completions/_memveil",
];

/// Root of the Rust workspace (`rust/`).
pub fn rust_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Repository root (parent of `rust/` while the rewrite lives there).
pub fn repo_root() -> PathBuf {
    rust_dir()
        .parent()
        .expect("rust/ has a parent")
        .to_path_buf()
}

/// Directory holding the packaging scripts.
pub fn scripts_dir() -> PathBuf {
    rust_dir().join("scripts")
}

/// Directory holding the packaging templates and spec.
pub fn packaging_dir() -> PathBuf {
    rust_dir().join("packaging")
}

/// Cargo target directory honoring `CARGO_TARGET_DIR`.
pub fn target_dir() -> PathBuf {
    std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| rust_dir().join("target"))
}

/// Release binary path.
pub fn release_binary() -> PathBuf {
    target_dir().join("release").join("memveil")
}

/// Shared work directory for built packages and fixtures.
pub fn work_dir() -> PathBuf {
    target_dir().join("package-test")
}

/// Output root for built packages.
///
/// Normal runs share one root (outputs are built once and
/// never deleted, so parallel readers are safe). Rebuild
/// runs scope outputs per process: rebuilding shared files
/// in place would race readers in sibling test binaries.
pub fn out_root() -> PathBuf {
    if rebuild_requested() {
        work_dir().join(format!("rebuild-{}", std::process::id()))
    } else {
        work_dir()
    }
}

/// Mojo-tree fixture inputs (read-only): binary behavior vectors.
pub fn fixtures_dir() -> PathBuf {
    repo_root().join("tests").join("fixtures")
}

/// Mojo-tree valid-empty capture (read-only).
pub fn valid_empty_dir() -> PathBuf {
    repo_root()
        .join("tests")
        .join("package")
        .join("valid-empty")
}

/// True when `REBUILD` requests fresh packages.
pub fn rebuild_requested() -> bool {
    std::env::var("MV_RUSTPKG_REBUILD").as_deref() == Ok("1")
}

/// True when `name` resolves on PATH.
pub fn tool_present(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Run a command, panicking only when it cannot spawn.
pub fn run(cmd: &str, args: &[&str], cwd: Option<&Path>) -> Output {
    let mut command = Command::new(cmd);
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|err| panic!("cannot run {cmd}: {err}"))
}

/// Run a command with `RUSTUP_TOOLCHAIN` stripped (repo pin wins).
pub fn run_unpinned(cmd: &str, args: &[&str], cwd: Option<&Path>) -> Output {
    let mut command = Command::new(cmd);
    command.args(args);
    command.env_remove("RUSTUP_TOOLCHAIN");
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|err| panic!("cannot run {cmd}: {err}"))
}

/// Stdout of a command that must succeed.
pub fn run_ok(cmd: &str, args: &[&str], cwd: Option<&Path>) -> String {
    let out = run(cmd, args, cwd);
    assert!(
        out.status.success(),
        "{cmd} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// SHA-256 of a file, via `sha256sum` (python3 fallback).
pub fn sha256_file(path: &Path) -> String {
    if tool_present("sha256sum") {
        let out = run_ok("sha256sum", &[&path_to_str(path)], None);
        return out.split_whitespace().next().unwrap_or("").to_string();
    }
    let probe =
        format!("import hashlib; print(hashlib.sha256(open({path:?}, 'rb').read()).hexdigest())");
    run_ok("python3", &["-c", &probe], None).trim().to_string()
}

fn path_to_str(path: &Path) -> String {
    path.to_str().expect("path is UTF-8").to_string()
}

/// Exclusive mkdir lock shared across test binaries.
pub struct DirLock {
    path: PathBuf,
}

impl DirLock {
    /// Acquire `work_dir()/locks/<name>` (waits up to ~10 minutes).
    pub fn acquire(name: &str) -> DirLock {
        let dir = work_dir().join("locks");
        fs::create_dir_all(&dir).expect("locks dir");
        let path = dir.join(name);
        for _ in 0..120 {
            match fs::create_dir(&path) {
                Ok(()) => return DirLock { path },
                Err(_) => std::thread::sleep(std::time::Duration::from_secs(5)),
            }
        }
        panic!("cannot acquire package-test lock {name}");
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

/// Ensure the release binary exists (builds it when missing).
pub fn ensure_release_binary() -> PathBuf {
    let binary = release_binary();
    let stale = !binary.is_file() || (rebuild_requested() && !BINARY_READY.load(Ordering::SeqCst));
    if stale {
        let _lock = DirLock::acquire("cargo-build");
        let stale =
            !binary.is_file() || (rebuild_requested() && !BINARY_READY.load(Ordering::SeqCst));
        if stale {
            let out = run_unpinned(
                "cargo",
                &["build", "--release", "--locked", "--offline"],
                Some(&rust_dir()),
            );
            assert!(
                out.status.success(),
                "cargo build --release failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    BINARY_READY.store(true, Ordering::SeqCst);
    assert!(binary.is_file(), "release binary missing");
    let version = run_ok(binary.to_str().unwrap(), &["version"], None);
    assert!(version.starts_with("memveil-"), "bad version: {version}");
    binary
}

/// Engine version from the release binary (`0.1.0`).
pub fn engine_version() -> String {
    let binary = ensure_release_binary();
    let version = run_ok(binary.to_str().unwrap(), &["version"], None);
    version
        .trim()
        .strip_prefix("memveil-")
        .expect("version prefix")
        .to_string()
}

/// Cargo version under the repo pin (proof string, e.g. `1.100.0`).
pub fn pinned_cargo_version() -> String {
    let out = run_unpinned("cargo", &["--version"], Some(&rust_dir()));
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.split_whitespace()
        .nth(1)
        .expect("cargo version token")
        .to_string()
}

/// rustc version under the repo pin.
pub fn pinned_rustc_version() -> String {
    let out = run_unpinned("rustc", &["--version"], Some(&rust_dir()));
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.split_whitespace()
        .nth(1)
        .expect("rustc version token")
        .to_string()
}

/// OUT_DIR holding the three `memveil-ebpf-*` build artifacts.
///
/// Several build-script output dirs can hold copies (flag-set
/// churn); all complete sets must agree byte-for-byte, and the
/// newest wins. Divergent sets fail closed.
pub fn bpf_out_dir() -> PathBuf {
    let base = target_dir().join("release").join("build").join("memveil");
    let mut hits = Vec::new();
    let entries = fs::read_dir(&base).expect("release build dir readable");
    for entry in entries.flatten() {
        let out = entry.path().join("out");
        if out.join("memveil-ebpf-attempt").is_file()
            && out.join("memveil-ebpf-lifecycle").is_file()
            && out.join("memveil-ebpf-copy").is_file()
        {
            hits.push(out);
        }
    }
    assert!(!hits.is_empty(), "no BPF OUT_DIR under {}", base.display());
    hits.sort();
    let first = &hits[0];
    for other in &hits[1..] {
        for channel in ["attempt", "lifecycle", "copy"] {
            let name = format!("memveil-ebpf-{channel}");
            assert_eq!(
                sha256_file(&first.join(&name)),
                sha256_file(&other.join(&name)),
                "divergent BPF sets: {} vs {}",
                first.display(),
                other.display()
            );
        }
    }
    hits.into_iter()
        .max_by_key(|dir| {
            fs::metadata(dir.join("memveil-ebpf-attempt"))
                .and_then(|info| info.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        })
        .unwrap()
}

/// Pinned pristine input clone for this process.
static PINNED_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Pristine clone of the checkout at HEAD (clean-tree packaging root).
///
/// Tests package from this clone so uncommitted worktree state
/// (including files from concurrent work) never trips the
/// packager's clean-tree gate. The clone is content-addressed
/// by HEAD and pinned per process: a concurrent commit mid-run
/// can only add a new clone dir, never mutate or invalidate
/// this process's inputs, so every suite stays self-consistent.
pub fn pristine_root() -> PathBuf {
    PINNED_ROOT.get_or_init(clone_for_head).clone()
}

fn clone_for_head() -> PathBuf {
    let head = run_ok("git", &["rev-parse", "HEAD"], Some(&repo_root()));
    let head = head.trim().to_string();
    let dest = work_dir().join(format!("inputs-{}", &head[..12]));
    // The marker lives beside the clone: inside it, the clone
    // would never look clean to the packager's gate.
    let marker = work_dir().join(format!("inputs-{}.head", &head[..12]));
    let fresh = clone_matches(&dest, &marker, &head);
    if !fresh {
        let _lock = DirLock::acquire("inputs-clone");
        if clone_matches(&dest, &marker, &head) {
            return dest;
        }
        let _ = fs::remove_dir_all(&dest);
        fs::create_dir_all(work_dir()).expect("work dir");
        let out = run(
            "git",
            &[
                "clone",
                "--quiet",
                repo_root().to_str().unwrap(),
                dest.to_str().unwrap(),
            ],
            None,
        );
        assert!(
            out.status.success(),
            "clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Pin exactly the read HEAD: the branch may have moved
        // between the rev-parse above and the clone.
        let pinned = run(
            "git",
            &[
                "-C",
                dest.to_str().unwrap(),
                "checkout",
                "--quiet",
                "--detach",
                &head,
            ],
            None,
        );
        assert!(
            pinned.status.success(),
            "clone pin failed: {}",
            String::from_utf8_lossy(&pinned.stderr)
        );
        fs::write(&marker, format!("{head}\n")).expect("marker");
    }
    dest
}

/// True when a clone dir holds exactly `head`, cleanly.
fn clone_matches(dest: &std::path::Path, marker: &std::path::Path, head: &str) -> bool {
    if !(dest.join(".git").is_dir()
        && marker.is_file()
        && fs::read_to_string(marker)
            .map(|text| text.trim() == head)
            .unwrap_or(false))
    {
        return false;
    }
    let status = run("git", &["status", "--short"], Some(dest));
    if !(status.status.success() && String::from_utf8_lossy(&status.stdout).trim().is_empty()) {
        return false;
    }
    let actual = run("git", &["rev-parse", "HEAD"], Some(dest));
    actual.status.success() && String::from_utf8_lossy(&actual.stdout).trim() == head
}

/// Built tarball bundle plus the tarball path.
pub struct TarballSet {
    /// Extracted bundle directory (`dist/memveil-<version>/`).
    pub bundle: PathBuf,
    /// The `.tar.gz` archive.
    pub tarball: PathBuf,
}

static TARBALL_READY: AtomicBool = AtomicBool::new(false);
static DEB_READY: AtomicBool = AtomicBool::new(false);
static RPM_READY: AtomicBool = AtomicBool::new(false);
static BINARY_READY: AtomicBool = AtomicBool::new(false);

/// HEAD this process packages from (pinned clone, read once).
static PINNED_HEAD: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn pinned_head() -> String {
    PINNED_HEAD
        .get_or_init(|| {
            let root = pristine_root();
            run_ok("git", &["rev-parse", "HEAD"], Some(&root))
                .trim()
                .to_string()
        })
        .clone()
}

/// True when an artifact was built from this generation's HEAD.
fn artifact_fresh(name: &str) -> bool {
    fs::read_to_string(out_root().join(format!("{name}.head")))
        .map(|text| text.trim() == pinned_head())
        .unwrap_or(false)
}

/// Record that an artifact finished building for this generation.
fn mark_artifact_built(name: &str) {
    let root = out_root();
    fs::create_dir_all(&root).expect("out root");
    fs::write(
        root.join(format!("{name}.head")),
        format!("{}\n", pinned_head()),
    )
    .expect("generation marker");
}

/// Ensure the tarball package exists; build it through the script.
///
/// Rebuild mode rebuilds once per process: every call
/// rebuilding would trample readers in sibling threads.
pub fn ensure_tarball() -> TarballSet {
    let version = engine_version();
    let out_dir = out_root().join("tarball");
    let bundle = out_dir.join(format!("memveil-{version}"));
    let tarball = out_dir.join(format!("memveil-{version}.tar.gz"));
    let present =
        bundle.join("MANIFEST.json").is_file() && tarball.is_file() && artifact_fresh("tarball");
    if present && (!rebuild_requested() || TARBALL_READY.load(Ordering::SeqCst)) {
        return TarballSet { bundle, tarball };
    }
    let _lock = DirLock::acquire("pkg-tarball");
    let present =
        bundle.join("MANIFEST.json").is_file() && tarball.is_file() && artifact_fresh("tarball");
    if present && (!rebuild_requested() || TARBALL_READY.load(Ordering::SeqCst)) {
        return TarballSet { bundle, tarball };
    }
    let binary = ensure_release_binary();
    let script = scripts_dir().join("package-tarball.py");
    let out = run(
        "python3",
        &[
            script.to_str().unwrap(),
            "--root",
            pristine_root().to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--bpf-dir",
            bpf_out_dir().to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        out.status.success(),
        "package-tarball.py failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(bundle.join("MANIFEST.json").is_file());
    assert!(tarball.is_file());
    TARBALL_READY.store(true, Ordering::SeqCst);
    mark_artifact_built("tarball");
    TarballSet { bundle, tarball }
}

/// Ensure the .deb exists (built from the shared bundle).
pub fn ensure_deb() -> PathBuf {
    let version = engine_version();
    let out_dir = out_root().join("deb");
    let deb = out_dir.join(format!("memveil_{version}-1_amd64.deb"));
    if deb.is_file()
        && artifact_fresh("deb")
        && (!rebuild_requested() || DEB_READY.load(Ordering::SeqCst))
    {
        return deb;
    }
    let _lock = DirLock::acquire("pkg-deb");
    if deb.is_file()
        && artifact_fresh("deb")
        && (!rebuild_requested() || DEB_READY.load(Ordering::SeqCst))
    {
        return deb;
    }
    let set = ensure_tarball();
    let script = scripts_dir().join("package-deb.py");
    let out = run(
        "python3",
        &[
            script.to_str().unwrap(),
            "--bundle",
            set.bundle.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        out.status.success(),
        "package-deb.py failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(deb.is_file());
    DEB_READY.store(true, Ordering::SeqCst);
    mark_artifact_built("deb");
    deb
}

/// Built .rpm in an out dir, if exactly one matches.
fn find_rpm(out_dir: &std::path::Path, version: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(out_dir).ok()?;
    let mut rpms: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(&format!("memveil-{version}-")) && name.ends_with(".rpm")
                })
        })
        .collect();
    rpms.sort();
    if rpms.len() == 1 { rpms.pop() } else { None }
}

/// Ensure the .rpm exists (built from the shared bundle).
pub fn ensure_rpm() -> PathBuf {
    let version = engine_version();
    let out_dir = out_root().join("rpm");
    if (!rebuild_requested() || RPM_READY.load(Ordering::SeqCst))
        && artifact_fresh("rpm")
        && let Some(rpm) = find_rpm(&out_dir, &version)
    {
        return rpm;
    }
    let _lock = DirLock::acquire("pkg-rpm");
    if (!rebuild_requested() || RPM_READY.load(Ordering::SeqCst))
        && artifact_fresh("rpm")
        && let Some(rpm) = find_rpm(&out_dir, &version)
    {
        return rpm;
    }
    let set = ensure_tarball();
    let script = scripts_dir().join("package-rpm.py");
    let work = out_root().join("rpm-work");
    let out = run(
        "python3",
        &[
            script.to_str().unwrap(),
            "--work",
            work.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--bundle",
            set.bundle.to_str().unwrap(),
            "--root",
            pristine_root().to_str().unwrap(),
        ],
        None,
    );
    assert!(
        out.status.success(),
        "package-rpm.py failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let entries = fs::read_dir(&out_dir).expect("rpm out dir");
    let mut rpms: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(&format!("memveil-{version}-")) && name.ends_with(".rpm")
                })
        })
        .collect();
    rpms.sort();
    assert_eq!(rpms.len(), 1, "want one rpm: {rpms:?}");
    RPM_READY.store(true, Ordering::SeqCst);
    mark_artifact_built("rpm");
    rpms.pop().unwrap()
}

/// Fresh scratch directory under `target/package-test/tmp/`.
pub fn scratch(name: &str) -> PathBuf {
    let dest = work_dir().join("tmp").join(format!(
        "{name}-{}-{}",
        std::process::id(),
        scratch_counter()
    ));
    let _ = fs::remove_dir_all(&dest);
    fs::create_dir_all(&dest).expect("scratch");
    dest
}

fn scratch_counter() -> u64 {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

/// `readelf -d` NEEDED entries of an ELF file.
pub fn readelf_needed(path: &Path) -> Vec<String> {
    let text = run_ok("readelf", &["-d", path_to_str(path).as_str()], None);
    let mut names = Vec::new();
    for line in text.lines() {
        if line.contains("(NEEDED)") && line.contains('[') {
            let name = line
                .split('[')
                .nth(1)
                .unwrap_or("")
                .split(']')
                .next()
                .unwrap_or("");
            names.push(name.to_string());
        }
    }
    names
}

/// `readelf -d` full dynamic section text.
pub fn readelf_dynamic(path: &Path) -> String {
    run_ok("readelf", &["-d", path_to_str(path).as_str()], None)
}

/// Non-`$ORIGIN` RUNPATH/RPATH entries (empty means relocatable).
pub fn runpath_abspaths(dynamic: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in dynamic.lines() {
        let Some(start) = line
            .find("Library runpath: [")
            .or_else(|| line.find("Library rpath: ["))
        else {
            continue;
        };
        let rest = &line[start..];
        let Some(open) = rest.find('[') else { continue };
        let Some(close) = rest.find(']') else {
            continue;
        };
        for entry in rest[open + 1..close].split(':') {
            if !entry.is_empty() && !entry.starts_with("$ORIGIN") {
                found.push(entry.to_string());
            }
        }
    }
    found
}

/// Max `GLIBC_x.y` need across ELF files.
pub fn glibc_floor(paths: &[PathBuf]) -> (u32, u32) {
    let mut floor = (0u32, 0u32);
    for path in paths {
        let text = run_ok("readelf", &["-V", path_to_str(path).as_str()], None);
        for need in parse_glibc_floor(&text) {
            floor = floor.max(need);
        }
    }
    assert_ne!(floor, (0, 0), "no GLIBC need in {paths:?}");
    floor
}

/// Every `GLIBC_x.y` token in `readelf -V` output.
pub fn parse_glibc_floor(text: &str) -> Vec<(u32, u32)> {
    let mut needs = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find("GLIBC_") {
        rest = &rest[pos + 6..];
        let mut digits = String::new();
        for ch in rest.chars() {
            if ch.is_ascii_digit() || ch == '.' {
                digits.push(ch);
            } else {
                break;
            }
        }
        let mut parts = digits.split('.');
        if let (Some(major), Some(minor)) = (parts.next(), parts.next())
            && let (Ok(major), Ok(minor)) = (major.parse(), minor.parse())
        {
            needs.push((major, minor));
        }
    }
    needs
}

/// True when the ELF header names X86-64.
pub fn is_x86_64(path: &Path) -> bool {
    run_ok("readelf", &["-h", path_to_str(path).as_str()], None).contains("X86-64")
}

/// True when `readelf -S` lists a `.symtab` section.
pub fn has_symtab(path: &Path) -> bool {
    run_ok("readelf", &["-S", path_to_str(path).as_str()], None).contains("] .symtab")
}

/// True when `readelf -S` lists any `.debug_` section.
pub fn has_debug(path: &Path) -> bool {
    run_ok("readelf", &["-S", path_to_str(path).as_str()], None).contains(".debug_")
}

/// ELF `e_machine` from the file header.
pub fn elf_machine(path: &Path) -> u16 {
    let bytes = fs::read(path).expect("read elf");
    assert!(bytes.len() >= 20 && bytes[0..4] == *b"\x7fELF");
    u16::from_le_bytes([bytes[18], bytes[19]])
}

/// One `tar -tzvf` member.
pub struct TarMember {
    /// Archive path.
    pub name: String,
    /// Mode string (`-rwxr-xr-x`).
    pub mode: String,
    /// Owner string (`root/root`).
    pub owner: String,
    /// True for directories.
    pub is_dir: bool,
}

/// Members of a gzip tarball with modes and owners.
pub fn tar_members(tarball: &Path) -> Vec<TarMember> {
    let text = run_ok(
        "tar",
        &["--numeric-owner", "-tzvf", path_to_str(tarball).as_str()],
        None,
    );
    let mut members = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert!(parts.len() >= 6, "tar line: {line}");
        let name = parts[parts.len() - 1].to_string();
        let is_dir = parts[0].starts_with('d');
        members.push(TarMember {
            name,
            mode: parts[0].to_string(),
            owner: parts[1].to_string(),
            is_dir,
        });
    }
    members
}

/// `(files, dirs)` from `dpkg-deb -c`, paths without `./`.
pub fn deb_listing(deb: &Path) -> (BTreeMap<String, (String, String)>, BTreeSet<String>) {
    let text = run_ok("dpkg-deb", &["-c", path_to_str(deb).as_str()], None);
    let mut files = BTreeMap::new();
    let mut dirs = BTreeSet::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert!(parts.len() >= 6, "deb line: {line}");
        let path = parts[parts.len() - 1]
            .strip_prefix("./")
            .expect("deb ./ prefix")
            .to_string();
        if parts[0].starts_with('d') {
            dirs.insert(path.trim_end_matches('/').to_string());
        } else {
            assert!(!path.ends_with('/'), "file: {line}");
            files.insert(path, (parts[0].to_string(), parts[1].to_string()));
        }
    }
    assert!(!files.is_empty(), "empty .deb");
    (files, dirs)
}

/// One control field via `dpkg-deb -f`.
pub fn deb_field(deb: &Path, name: &str) -> String {
    run_ok("dpkg-deb", &["-f", path_to_str(deb).as_str(), name], None)
}

/// Extract the .deb payload into a fresh scratch dir.
pub fn deb_extract(deb: &Path, name: &str) -> PathBuf {
    let dest = scratch(name);
    run_ok(
        "dpkg-deb",
        &["-x", path_to_str(deb).as_str(), dest.to_str().unwrap()],
        None,
    );
    dest
}

/// Control-tarball members via `dpkg-deb --ctrl-tarfile | tar -t`.
pub fn deb_control_members(deb: &Path) -> Vec<String> {
    let ctrl = run(
        "dpkg-deb",
        &["--ctrl-tarfile", path_to_str(deb).as_str()],
        None,
    );
    assert!(ctrl.status.success());
    let mut tar = Command::new("tar");
    tar.arg("-t")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = tar.spawn().expect("spawn tar");
    use std::io::Write;
    let wrote = child
        .stdin
        .as_mut()
        .expect("tar stdin")
        .write_all(&ctrl.stdout);
    drop(child.stdin.take());
    assert!(wrote.is_ok(), "write ctrl tarball");
    let out = child.wait_with_output().expect("tar wait");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| {
            line.trim()
                .trim_start_matches("./")
                .trim_start_matches('/')
                .to_string()
        })
        .filter(|line| !line.is_empty())
        .collect()
}

/// `rpm -qp` with a scratch dbpath (never touches the system db).
pub fn rpm_query(rpm: &Path, db: &Path, args: &[&str]) -> Output {
    let mut full = vec!["--dbpath", db.to_str().unwrap()];
    full.extend(args);
    full.push(rpm.to_str().unwrap());
    run("rpm", &full, None)
}

/// `rpm -qlp` file list.
pub fn rpm_listing(rpm: &Path, db: &Path) -> Vec<String> {
    let out = rpm_query(rpm, db, &["-qlp"]);
    assert!(
        out.status.success(),
        "rpm -qlp: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "rpm stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

/// Extract the .rpm payload via `rpm2cpio | cpio -idm`.
pub fn rpm_extract(rpm: &Path, name: &str) -> PathBuf {
    let dest = scratch(name);
    let dump = run("rpm2cpio", &[path_to_str(rpm).as_str()], None);
    assert!(dump.status.success());
    let mut cpio = Command::new("cpio");
    cpio.args(["-idm", "--quiet"])
        .current_dir(&dest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cpio.spawn().expect("spawn cpio");
    use std::io::Write;
    // cpio exits at the archive trailer, possibly before
    // trailing padding bytes arrive: a late write may hit
    // EPIPE after a successful extract, so the exit status
    // (not the write result) decides success.
    let _ = child
        .stdin
        .as_mut()
        .expect("cpio stdin")
        .write_all(&dump.stdout);
    // Drop stdin before waiting so cpio sees EOF promptly.
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("cpio wait");
    assert!(
        out.status.success(),
        "cpio: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    dest
}

/// Evaluate a Python expression over JSON file `d`; return raw stdout.
pub fn json_probe(path: &Path, expr: &str) -> String {
    let probe = format!(
        "import json; d = json.load(open({path:?})); v = ({expr}); \
         print(json.dumps(v, sort_keys=True) if not isinstance(v, str) else v)"
    );
    run_ok("python3", &["-c", &probe], None).trim().to_string()
}

/// Cargo.lock packages via stdlib TOML: `(name, version, source, checksum)`.
pub fn cargo_lock_packages(lock: &Path) -> Vec<(String, String, String, String)> {
    let probe = "import json, tomllib; d = tomllib.load(open(ARG, 'rb')); \
        print(json.dumps([[p.get('name'), p.get('version'), p.get('source') or '', \
        p.get('checksum') or ''] for p in d.get('package', [])]))"
        .replace("ARG", &format!("{lock:?}"));
    let text = run_ok("python3", &["-c", &probe], None);
    parse_string_table(&text)
}

/// Parse a JSON `[[s, s, ...], ...]` table without dependencies.
pub fn parse_string_table(text: &str) -> Vec<(String, String, String, String)> {
    let mut rows = Vec::new();
    for row in text
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split("], [")
    {
        let clean = row.trim().trim_start_matches('[').trim_end_matches(']');
        let mut cells = Vec::new();
        let mut current = String::new();
        let mut in_string = false;
        let mut escaped = false;
        for ch in clean.chars() {
            if escaped {
                current.push(ch);
                escaped = false;
            } else if ch == '\\' && in_string {
                escaped = true;
            } else if ch == '"' {
                in_string = !in_string;
            } else if ch == ',' && !in_string {
                cells.push(std::mem::take(&mut current).trim().to_string());
            } else {
                current.push(ch);
            }
        }
        cells.push(current.trim().to_string());
        if cells.len() == 4 {
            rows.push((
                cells[0].clone(),
                cells[1].clone(),
                cells[2].clone(),
                cells[3].clone(),
            ));
        }
    }
    rows
}

/// JSON string literal with escaping.
pub fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ` (via `date -u`).
pub fn utc_now() -> String {
    run_ok("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"], None)
        .trim()
        .to_string()
}
