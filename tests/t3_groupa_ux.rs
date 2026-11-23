// SPDX-License-Identifier: GPL-3.0-or-later
//! CLI surface oracles: usage integrity, lone-install profiles, parser core.
//!
//! Process-level pins for the T3 group-A batch, through the built
//! binary only: no VMs, no privileged commands, no admission past
//! parse (the record legs fail at parse or at the profiles gate, so
//! they never collect, even as root).

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_memveil"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Spawn with a bounded retry on ETXTBSY only.
///
/// Under parallel load a sibling thread's still-pre-exec child can hold an
/// inherited write fd to a freshly-copied binary at our exec instant (POSIX
/// fork-inheritance race; fd tables are process-global, CLOEXEC applies only
/// at exec). Holders normally exec within milliseconds, but a wedged box can
/// stall a fresh fork for seconds, so the budget spans 6 s; every other spawn
/// error panics immediately, and persistent ETXTBSY still panics (reporting
/// the retry count). Same pattern as `spawn_output` in
/// `tests/package_helpers/mod.rs`.
fn spawn_output(command: &mut Command) -> Output {
    let mut tries = 0;
    loop {
        match command.output() {
            Ok(out) => return out,
            Err(err) if err.raw_os_error() == Some(26) && tries < 600 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(err) if tries > 0 => {
                panic!("run binary: {err} (after {tries} ETXTBSY retries)")
            }
            Err(err) => panic!("run binary: {err}"),
        }
    }
}

fn run(bin: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(bin);
    command.args(args).current_dir(repo_root());
    spawn_output(&mut command)
}

fn run_os(bin: &Path, args: &[OsString]) -> Output {
    let mut command = Command::new(bin);
    command.args(args).current_dir(repo_root());
    spawn_output(&mut command)
}

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("memveil-t3a-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

// --- T3.1: usage integrity ---

#[test]
fn t31_no_args_stderr_equals_help_stdout() {
    let bare = run(&bin(), &[]);
    assert_eq!(bare.status.code(), Some(2));
    assert!(bare.stdout.is_empty());
    let help = run(&bin(), &["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(help.stderr.is_empty());
    assert_eq!(bare.stderr, help.stdout);
}

#[test]
fn t31_bogus_verb_stderr_equals_help_stdout() {
    let bogus = run(&bin(), &["bogus-verb"]);
    assert_eq!(bogus.status.code(), Some(2));
    assert!(bogus.stdout.is_empty());
    let help = run(&bin(), &["--help"]);
    assert_eq!(bogus.stderr, help.stdout);
}

#[test]
fn t31_top_raw_live_usage_equals_top_help() {
    // An undecodable live word prints top usage to stderr; it must
    // equal `top --help` stdout byte for byte.
    let raw = run_os(
        &bin(),
        &[
            OsString::from("top"),
            OsString::from("--output"),
            OsString::from_vec(b"o\xff".to_vec()),
        ],
    );
    assert_eq!(raw.status.code(), Some(2));
    assert!(raw.stdout.is_empty());
    let help = run(&bin(), &["top", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert_eq!(raw.stderr, help.stdout);
}

// --- T3.2: lone-install profiles error ---

fn lone_binary() -> PathBuf {
    let dir = tmp_dir("lone");
    let lone = dir.join("lone");
    std::fs::copy(bin(), &lone).expect("copy binary");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&lone, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    lone
}

#[test]
fn t32_lone_binary_doctor_and_record() {
    let lone = lone_binary();
    let prefix = lone
        .parent()
        .expect("temp parent")
        .to_str()
        .expect("utf-8")
        .to_string();
    let manifest = format!("{prefix}/../profiles/manifest.txt");
    // Doctor names the searched manifest plus the fix, exit 3.
    let out = run(&lone, &["doctor"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!(
            "memveil doctor: no profiles found: {manifest} does not exist\n\
             memveil doctor: fix: run the packaged layout (profiles/ beside bin/), \
             or pass --profiles-dir DIR\n"
        )
    );
    // Record prints its own two lines, exits 3, leaves no directory.
    let cap = lone.parent().expect("temp parent").join("cap-x");
    let cap_str = cap.to_str().expect("utf-8").to_string();
    let out = run(&lone, &["record", "--output", &cap_str, "--duration", "10"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!(
            "memveil record: no profiles found: {manifest} does not exist\n\
             memveil record: fix: run the packaged layout (profiles/ beside bin/), \
             or pass --profiles-dir DIR\n"
        )
    );
    assert!(!cap.exists(), "refused record left a capture dir");
    let _ = std::fs::remove_dir_all(lone.parent().expect("temp parent"));
}

#[test]
fn t32_packaged_layout_unchanged() {
    let out = run(&bin(), &["doctor", "--profiles-dir", "profiles"]);
    assert!(out.status.code() == Some(0) || out.status.code() == Some(3));
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("memveil doctor (passive, live evidence)\n"));
    assert!(!stdout.contains("no profiles found"));
}

// --- T3.5: parser core ---

const VALID_IDS: &str =
    "attempt-trace, mapping-lifecycle, copy-actual, conversion-observe, conversion-journal, all";

#[test]
fn t35_report_flag_eq() {
    // `--format=json` runs the full pipeline, not the usage error.
    let dir = repo_root()
        .join("tests/fixtures/reader/sealed-complete")
        .to_str()
        .expect("utf-8")
        .to_string();
    let out = run(
        &bin(),
        &["report", "--format=json", "--long-lived-after=90s", &dir],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("{\n  \"schema_version\""), "{stdout}");
}

#[test]
fn t35_record_flag_eq_and_duration_parse() {
    // Both inline forms parse: the run fails on the later --bogus,
    // never on --output= or the 10s duration. Parse-time failure
    // means no admission and no output directory, even as root.
    let dir = tmp_dir("eq");
    let cap = dir.join("cap-eq").to_str().expect("utf-8").to_string();
    let out = run(
        &bin(),
        &[
            "record",
            &format!("--output={cap}"),
            "--duration=10s",
            "--bogus",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(out.stderr, b"memveil record: unknown option: --bogus\n");
    assert!(!dir.join("cap-eq").exists());
    // Spaced `10s` parses too (same grammar, shared with top live).
    let out = run(
        &bin(),
        &["record", "--output", &cap, "--duration", "10s", "--bogus"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stderr, b"memveil record: unknown option: --bogus\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t35_capability_invalid_lists_valid_ids() {
    // Both verbs exit 2 and teach the vocabulary.
    let out = run(
        &bin(),
        &[
            "doctor",
            "--capability",
            "bogus",
            "--profiles-dir",
            "profiles",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("memveil doctor: unknown capability: bogus; valid capabilities: {VALID_IDS}\n")
    );
    let dir = tmp_dir("caps");
    let cap = dir.join("cap").to_str().expect("utf-8").to_string();
    let out = run(
        &bin(),
        &[
            "record",
            "--profiles-dir",
            "profiles",
            "--output",
            &cap,
            "--capability",
            "bogus",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("memveil record: unknown capability: bogus; valid capabilities: {VALID_IDS}\n")
    );
    assert!(!dir.join("cap").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t35_help_verb_routes() {
    for verb in [
        "record",
        "report",
        "top",
        "doctor",
        "qualify",
        "bind-profile",
    ] {
        let via_help = run(&bin(), &["help", verb]);
        assert_eq!(via_help.status.code(), Some(0), "help {verb}");
        assert!(via_help.stderr.is_empty(), "help {verb}");
        let via_flag = run(&bin(), &[verb, "--help"]);
        assert_eq!(via_flag.status.code(), Some(0), "{verb} --help");
        assert_eq!(via_help.stdout, via_flag.stdout, "help {verb} bytes");
    }
    // Bare and unknown help keep the top-level text.
    let bare = run(&bin(), &["help"]);
    let top = run(&bin(), &["--help"]);
    assert_eq!(bare.stdout, top.stdout);
    let bogus = run(&bin(), &["help", "bogus"]);
    assert_eq!(bogus.status.code(), Some(0));
    assert_eq!(bogus.stdout, top.stdout);
}

// --- T3.7: doctor next step ---

#[test]
fn t37_doctor_text_next_and_grouped_remedy() {
    // Live admission decides the exit; the shape rides along: an
    // unavailable doctor ends with exactly one next: line, remedy
    // blocks never repeat, and a ready doctor carries no next:.
    let out = run(&bin(), &["doctor", "--profiles-dir", "profiles"]);
    assert!(out.status.code() == Some(0) || out.status.code() == Some(3));
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.ends_with('\n'));
    let fixes: Vec<&str> = stdout
        .lines()
        .filter(|l| l.starts_with("    fix "))
        .collect();
    let mut unique = fixes.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(fixes.len(), unique.len(), "remedy blocks repeat: {fixes:?}");
    let nexts: Vec<&str> = stdout.lines().filter(|l| l.starts_with("next: ")).collect();
    if out.status.code() == Some(3) {
        assert_eq!(nexts.len(), 1, "{stdout}");
        assert!(
            stdout.ends_with("next: sudo memveil record --output /tmp/cap1 --duration 10\n")
                || stdout.ends_with("next: memveil report examples/real-capture\n"),
            "{stdout}"
        );
    } else {
        assert!(nexts.is_empty(), "{stdout}");
    }
}

#[test]
fn spawn_retries_transient_txtbsy() {
    // A sibling's still-pre-exec child can hold an inherited write fd to a
    // freshly-copied binary at our exec instant (ETXTBSY); run() must ride
    // through the transient instead of panicking. Deterministic: the holder
    // rendezvous guarantees the first spawn attempt hits the busy window.
    // Same pin as `spawn_retries_transient_txtbsy` in
    // `tests/package_tarball.rs`.
    let dir = tmp_dir("txtbsy-pin");
    let target = dir.join("probe");
    std::fs::copy("/bin/true", &target).expect("copy probe");
    let held_path = target.clone();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(&held_path)
            .expect("hold probe");
        tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        drop(held);
    });
    rx.recv().unwrap();
    let out = run(&target, &[]);
    assert!(out.status.success(), "spawn must survive transient ETXTBSY");
    handle.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t37_doctor_json_carries_no_text_additions() {
    // The text-only additions (next:, translations, guest note)
    // never leak into the JSON report.
    let out = run(&bin(), &["doctor", "--json", "--profiles-dir", "profiles"]);
    assert!(out.status.code() == Some(0) || out.status.code() == Some(3));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("next: "), "{stdout}");
    assert!(
        !stdout.contains("not attested, not a platform qualification"),
        "{stdout}"
    );
    assert!(!stdout.contains("guest device "), "{stdout}");
}
