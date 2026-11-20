// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared privileged install-journey legs for the FHS suites.
//!
//! The .deb and .rpm install journeys drive the same installed
//! tree (`/usr/bin/memveil`, `/usr/lib/memveil`,
//! `/var/lib/memveil`), and cargo runs test binaries in
//! parallel: every privileged journey holds `install_lock()`
//! across the whole install/run/uninstall cycle so the two
//! formats can never install over each other. The per-format
//! tests own only their package-manager verbs (install,
//! verify, uninstall, and the package-absent preflight
//! probe); everything between install and teardown lives
//! here, so the two formats cannot drift.
//!
//! The journey contract, both formats: fresh-state prelude
//! (package absent, receipts fresh, else refuse naming the
//! cause), install, manager verify, receipts-dir state,
//! loader closure (ldd plus the private libgcc through the
//! FHS RUNPATH — the load proof; there is no bridge dlopen
//! in the Rust package), version, zero-flag doctor,
//! zero-env record probe, privileged qualify (a bridgeless
//! refusal leg plus a bridged receipt leg through the
//! installed inspection objects), uninstall, and residue
//! check. Teardown always runs.

use super::DirLock;
use super::run;
use super::run_ok;
use super::scratch;
use super::sha256_file;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// Installed receipts directory both formats share.
pub const RECEIPTS: &str = "/var/lib/memveil/receipts";

/// Installed private library directory both formats share.
pub const INSTALLED_LIB: &str = "/usr/lib/memveil";

/// Installed binary both formats share.
pub const INSTALLED_BIN: &str = "/usr/bin/memveil";

/// True when passwordless sudo works (privileged journeys need it).
pub fn have_passwordless_sudo() -> bool {
    run("sudo", &["-n", "true"], None).status.success()
}

/// True when `MV_RUSTPKG_JOURNEY=0` opts out of privileged journeys.
pub fn journey_opted_out() -> bool {
    std::env::var("MV_RUSTPKG_JOURNEY").as_deref() == Ok("0")
}

/// Cross-process install lock: held across install/run/uninstall.
pub fn install_lock() -> DirLock {
    DirLock::acquire("install-journey")
}

/// Retained receipt names in a receipts dir (missing dir: none).
pub fn retained_receipts(receipts: &Path) -> Vec<String> {
    match fs::read_dir(receipts) {
        Err(_) => Vec::new(),
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .flatten()
                .map(|e| e.file_name().to_str().unwrap().to_string())
                .collect();
            names.sort();
            names
        }
    }
}

/// Fresh-state prelude, shared half: refuse retained receipts,
/// naming the survivors. The per-format test probes package
/// absence first (manager-specific), then calls this. Returns
/// the pre-run names (always empty: anything else refuses).
pub fn refuse_retained_receipts(receipts: &str) -> BTreeSet<String> {
    let names = retained_receipts(Path::new(receipts));
    assert!(
        names.is_empty(),
        "refusing install: {receipts} holds retained receipts ({})",
        names.join(", ")
    );
    BTreeSet::new()
}

/// Freshly installed receipts dir: present, 0755 root:root, empty.
pub fn assert_receipts_installed(receipts: &str) {
    assert!(Path::new(receipts).is_dir(), "receipts dir missing");
    use std::os::unix::fs::MetadataExt;
    let info = fs::metadata(receipts).unwrap();
    assert_eq!(info.mode() & 0o7777, 0o755, "{:o}", info.mode());
    assert_eq!(info.uid(), 0);
    assert_eq!(info.gid(), 0);
    assert_eq!(
        fs::read_dir(receipts).unwrap().count(),
        0,
        "fresh install ships receipts"
    );
}

/// Loader closure: ldd resolves everything, and the private
/// libgcc resolves through the FHS RUNPATH (the load proof;
/// there is no bridge dlopen in the Rust package).
pub fn assert_loader_closure() {
    let ldd = run_ok("/usr/bin/ldd", &[INSTALLED_BIN], None);
    assert!(!ldd.contains("not found"), "{ldd}");
    // ldd prints the un-normalized $ORIGIN expansion
    // (/usr/bin/../lib/...), so match the suffix both the
    // raw and the normalized form share.
    assert!(ldd.contains("lib/memveil/libgcc_s.so.1"), "{ldd}");
}

/// Zero-flag doctor (exit 0 or 3, nonempty stdout) plus the
/// exact installed version.
pub fn assert_doctor_and_version(version: &str) {
    let doctor = run(INSTALLED_BIN, &["doctor"], None);
    assert!(doctor.status.code() == Some(0) || doctor.status.code() == Some(3));
    assert!(!String::from_utf8_lossy(&doctor.stdout).trim().is_empty());
    let got = run_ok(INSTALLED_BIN, &["version"], None);
    assert_eq!(got.trim(), format!("memveil-{version}"));
}

/// Zero-environment record probe: discovery must never fail
/// (none of the resolution diagnostics), and the exit/capture
/// accounting is exact: a refusal (3) prints a diagnostic and
/// leaves no capture dir, a run (0/4) leaves one.
pub fn record_probe(tmp: &Path) {
    let cap = tmp.join("cap");
    let record = std::process::Command::new(INSTALLED_BIN)
        .args([
            "record",
            "--output",
            cap.to_str().unwrap(),
            "--duration",
            "1",
        ])
        .current_dir(tmp)
        .env_clear()
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("record");
    let stderr = String::from_utf8_lossy(&record.stderr);
    for missing in [
        "no bridge",
        "no object",
        "missing --object",
        "cannot load profiles",
        "cannot resolve profiles",
    ] {
        assert!(!stderr.contains(missing), "{stderr}");
    }
    assert!(
        record.status.code() == Some(0)
            || record.status.code() == Some(3)
            || record.status.code() == Some(4),
        "{stderr}"
    );
    if record.status.code() == Some(3) {
        assert!(!stderr.trim().is_empty());
        assert!(!cap.exists(), "refused record left a capture dir");
    } else {
        assert!(
            cap.exists(),
            "exit {} left no capture dir",
            record.status.code().unwrap_or(-1)
        );
    }
}

/// Scratch capture dirs the qualify legs use, plus whether each
/// pre-existed (teardown removes only what the journey created).
/// Compute before the guarded section so teardown always knows
/// the paths even when a leg fails midway.
pub struct QualifyScratch {
    /// Bridgeless-leg capture dir.
    pub qcap: PathBuf,
    /// True when `qcap` pre-existed the journey.
    pub qcap_existed: bool,
    /// Bridged-leg capture dir.
    pub qcap2: PathBuf,
    /// True when `qcap2` pre-existed the journey.
    pub qcap2_existed: bool,
}

impl QualifyScratch {
    /// Capture dirs under `tmp`, recording pre-existence.
    pub fn under(tmp: &Path) -> QualifyScratch {
        let qcap = tmp.join("qcap");
        let qcap2 = tmp.join("qcap2");
        QualifyScratch {
            qcap_existed: qcap.exists(),
            qcap2_existed: qcap2.exists(),
            qcap,
            qcap2,
        }
    }
}

/// Privileged qualify through the installed inspection copies:
/// a bridgeless refusal leg (exit 1 + the exact bridge-unbound
/// diagnostic, minting nothing) plus a bridged success leg
/// (exit 0, exactly one receipt, every binding hash pinned).
/// Qualify requires an explicit --object (it snapshots file
/// bytes; embedded bytes have no pathname), so the journey
/// qualifies through the installed objects instead of
/// zero-flag discovery. Whether zero-flag qualify should
/// resolve the FHS copies is a runtime-behavior decision
/// owned by the binary suites, not the packaging suites.
pub fn qualify_legs(tmp: &Path, scratch_dirs: &QualifyScratch, receipts: &str) {
    let lib = INSTALLED_LIB;
    // Bridgeless leg: the refusal contract. No --bridge is
    // passed, discovery finds no native bridge in the
    // package, and the finalized smoke must exit 1 with the
    // exact bridge-unbound diagnostic, minting nothing. The
    // leftover capture dir corroborates that the smoke
    // attached and ran before the bridge gate stopped
    // minting (a plan refusal would exit 3 with no smoke).
    let owned = vec![
        "sudo".to_string(),
        "-n".to_string(),
        INSTALLED_BIN.to_string(),
        "qualify".to_string(),
        "--output".to_string(),
        scratch_dirs.qcap.to_str().unwrap().to_string(),
        "--object".to_string(),
        format!("{lib}/swiotlb_attempt.bpf.o"),
        "--lc-object".to_string(),
        format!("{lib}/swiotlb_lifecycle.bpf.o"),
        "--cp-object".to_string(),
        format!("{lib}/swiotlb_copy.bpf.o"),
    ];
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let qualify = run(refs[0], &refs[1..], Some(tmp));
    println!(
        "journey qualify exit: {}",
        qualify.status.code().unwrap_or(-1)
    );
    assert_eq!(
        qualify.status.code(),
        Some(1),
        "bridgeless smoke must refuse with exit 1: {}",
        String::from_utf8_lossy(&qualify.stderr)
    );
    let stderr = String::from_utf8_lossy(&qualify.stderr);
    assert!(
        stderr.contains(
            "memveil qualify: smoke bridge unbound: bridge identity unbound for this smoke"
        ),
        "bridgeless smoke diagnostic changed: {stderr}"
    );
    assert!(
        !scratch_dirs.qcap_existed && scratch_dirs.qcap.is_dir(),
        "bridgeless smoke left no capture dir"
    );
    assert_eq!(
        fs::read_dir(receipts).unwrap().count(),
        0,
        "refused qualify left receipts"
    );
    // Explicit-bridge leg: the success contract. The
    // installed package ships no native bridge library, so
    // no production bridge artifact exists on the journey
    // host; the test mints a fixture file with fixed bytes
    // instead. The bridge override only binds receipts
    // through the admission hash of the exercised bytes
    // (the loader links statically and never loads the path
    // for smoke identity), so the fixture exercises the
    // exact production path of an explicit --bridge
    // artifact while letting the test pin the expected
    // binding hash.
    let fixture = tmp.join("bridge-fixture.so");
    fs::write(&fixture, b"MEMVEIL-JOURNEY-BRIDGE-FIXTURE-v1\n").unwrap();
    let owned = vec![
        "sudo".to_string(),
        "-n".to_string(),
        INSTALLED_BIN.to_string(),
        "qualify".to_string(),
        "--output".to_string(),
        scratch_dirs.qcap2.to_str().unwrap().to_string(),
        "--object".to_string(),
        format!("{lib}/swiotlb_attempt.bpf.o"),
        "--lc-object".to_string(),
        format!("{lib}/swiotlb_lifecycle.bpf.o"),
        "--cp-object".to_string(),
        format!("{lib}/swiotlb_copy.bpf.o"),
        "--bridge".to_string(),
        fixture.to_str().unwrap().to_string(),
    ];
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let bridged = run(refs[0], &refs[1..], Some(tmp));
    println!(
        "journey bridged qualify exit: {}",
        bridged.status.code().unwrap_or(-1)
    );
    assert_eq!(
        bridged.status.code(),
        Some(0),
        "bridged smoke failed: {}",
        String::from_utf8_lossy(&bridged.stderr)
    );
    let stdout = String::from_utf8_lossy(&bridged.stdout);
    assert!(
        stdout.contains("receipt=/var/lib/memveil/receipts/"),
        "{stdout}"
    );
    assert!(stdout.contains("caps=attempt-trace"), "{stdout}");
    // The minted receipt must verify: shape pins plus
    // bindings to the exact exercised bytes (the fixture
    // bridge and the installed inspection objects). No CLI
    // verify verb exists, so the test parses the receipt and
    // pins every binding hash directly.
    let published: Vec<String> = fs::read_dir(receipts)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .collect();
    assert_eq!(published.len(), 1, "exit 0 must mint one receipt");
    let marker = "receipt=";
    let at = stdout.find(marker).expect("stdout names the receipt");
    let path = stdout[at + marker.len()..]
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(path, format!("{receipts}/{}", published[0]));
    let bridge_sha = sha256_file(&fixture);
    let attempt_sha = sha256_file(Path::new(&format!("{lib}/swiotlb_attempt.bpf.o")));
    let lc_sha = sha256_file(Path::new(&format!("{lib}/swiotlb_lifecycle.bpf.o")));
    let cp_sha = sha256_file(Path::new(&format!("{lib}/swiotlb_copy.bpf.o")));
    let probe = format!(
        "import json; rec = json.load(open({path:?})); \
         assert rec['schema_version'] == '0.1.0', rec; \
         assert rec['kind'] == 'memveil-qualification-receipt', rec; \
         assert rec['grade'] == 'local-auto', rec; \
         assert rec['capabilities']['attempt-trace']['status'] == 'qualified', \
         rec['capabilities']; \
         assert rec['workload']['kind'] == 'smoke', rec['workload']; \
         art = rec['artifacts']; \
         assert art['bridge'] == 'sha256:{bridge_sha}', art; \
         objs = art['objects']; \
         assert objs['attempt'] == 'sha256:{attempt_sha}', objs; \
         assert objs['lifecycle'] == 'sha256:{lc_sha}', objs; \
         assert objs['copy'] == 'sha256:{cp_sha}', objs; \
         print('receipt-ok')"
    );
    let text = run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("receipt-ok"), "{text}");
}

/// Teardown: remove run residue (receipts the legs minted).
/// Uninstall itself is the per-format test's verb.
pub fn clear_receipts(receipts: &str) {
    if let Ok(entries) = fs::read_dir(receipts) {
        for entry in entries.flatten() {
            let _ = run(
                "sudo",
                &["-n", "rm", "-f", entry.path().to_str().unwrap()],
                None,
            );
        }
    }
}

/// Teardown: remove a qualify capture dir the journey created.
pub fn remove_qualify_scratch(scratch_dirs: &QualifyScratch) {
    if !scratch_dirs.qcap_existed && scratch_dirs.qcap.exists() {
        let _ = run(
            "sudo",
            &["-n", "rm", "-rf", scratch_dirs.qcap.to_str().unwrap()],
            None,
        );
    }
    if !scratch_dirs.qcap2_existed && scratch_dirs.qcap2.exists() {
        let _ = run(
            "sudo",
            &["-n", "rm", "-rf", scratch_dirs.qcap2.to_str().unwrap()],
            None,
        );
    }
}

/// Post-uninstall: none of the shared install roots may survive.
pub fn assert_no_residue() {
    for path in [
        "/usr/lib/memveil",
        "/usr/share/memveil",
        "/usr/share/doc/memveil",
        "/var/lib/memveil",
    ] {
        assert!(!Path::new(path).exists(), "residue: {path}");
    }
}

/// Fresh journey scratch dir plus qualify capture records.
pub fn journey_scratch(name: &str) -> (PathBuf, QualifyScratch) {
    let tmp = scratch(name);
    let dirs = QualifyScratch::under(&tmp);
    (tmp, dirs)
}

/// Installed-closure leg (candidate mode only): the installed
/// tree must equal the verified candidate files closure,
/// through the packager's own predicate. Missing, tampered,
/// aliased, and extra members refuse.
pub fn assert_installed_closure(root: &Path) {
    assert!(
        super::candidate_mode(),
        "installed-closure check needs candidate inputs"
    );
    let script = super::scripts_dir()
        .join("package-deb.py")
        .to_str()
        .unwrap()
        .to_string();
    let text = super::loader_probe(
        &[
            "import importlib.util",
            &format!("spec = importlib.util.spec_from_file_location('pkgdeb', {script:?})"),
            "pkgdeb = importlib.util.module_from_spec(spec)",
            "spec.loader.exec_module(pkgdeb)",
            "pkgdeb.verify_installed(sys.argv[1], selected.manifest)",
            "print('closure-ok')",
        ],
        &[root.to_str().unwrap()],
    );
    assert!(text.contains("closure-ok"), "{text}");
}
