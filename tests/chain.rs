// SPDX-License-Identifier: GPL-3.0-or-later
//! Cross-module chain: one capture through analyze, render, and replay.
//!
//! The per-verb suites pin each boundary in isolation; these tests drive the
//! whole path through the public CLI and assert the end-to-end contract:
//! every render of the same capture agrees on the session identity, the
//! verified byte count, and the bounce total, and the replayed final block
//! is byte-identical to the text report.
//!
//! `capture_report_top_chain` runs offline over a checked-in fixture.
//! `record_report_top_live_chain` records a real 2 s capture first and needs
//! `MEMVEIL_CHAIN_LIVE=1` plus root with BTF and the Aya attempt object;
//! without them it reports SKIP.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_memveil"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run memveil")
}

/// Fresh per-test scratch directory: pid + nanos + counter nonce, and any
/// stale directory at that path is cleared instead of reused.
fn workdir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "memveil-chain-{}-{nanos:x}-{nonce}-{tag}",
        std::process::id()
    ));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("clear stale workdir");
    }
    std::fs::create_dir_all(&dir).expect("create workdir");
    dir
}

/// Body of the last `--- refresh` block: everything after its header line.
fn final_block(stdout: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(stdout);
    let blocks: Vec<&str> = text.split("--- refresh ").collect();
    assert!(blocks.len() >= 2, "top prints at least a final block");
    let last = blocks[blocks.len() - 1];
    let body = last.split_once('\n').expect("header line").1;
    body.as_bytes().to_vec()
}

/// Byte-shape all three renders share: exit 0, silent stderr, newline end.
fn check_render_shape(out: &Output, what: &str) -> String {
    assert_eq!(out.status.code(), Some(0), "{what} exit");
    assert!(out.stderr.is_empty(), "{what} stderr");
    assert!(!out.stdout.is_empty(), "{what} stdout");
    assert!(out.stdout.ends_with(b"\n"), "{what} trailing newline");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn capture_report_top_chain() {
    let dir = repo_root()
        .join("tests/fixtures/reader/sealed-complete")
        .to_string_lossy()
        .into_owned();
    // Leg 1: analyze + render the text report.
    let text = check_render_shape(&run(&["report", dir.as_str()]), "report text");
    assert!(
        text.contains("bounce_attempts = 3 count"),
        "text bounce total"
    );
    assert!(text.contains("attempts-3-session"), "text session id");
    assert!(
        text.contains("verified bytes=1155, events=3"),
        "text verified bytes"
    );
    // Leg 2: the JSON render of the same capture.
    let json = check_render_shape(
        &run(&["report", "--format", "json", dir.as_str()]),
        "report json",
    );
    assert!(json.starts_with("{\n"), "json opens");
    assert!(json.ends_with("}\n"), "json closes");
    assert!(
        json.contains("\"session_id\": \"attempts-3-session\""),
        "json session id"
    );
    assert!(
        json.contains("\"verified_bytes\": \"1155\""),
        "json verified bytes"
    );
    assert!(
        json.contains("\"bounce_attempts\", \"value\": \"3\""),
        "json bounce total"
    );
    // Leg 3: the Markdown render of the same capture.
    let markdown = check_render_shape(
        &run(&["report", "--format", "markdown", dir.as_str()]),
        "report markdown",
    );
    assert!(
        markdown.starts_with("# Memveil report `attempts-3-session`"),
        "markdown title"
    );
    assert!(
        markdown.contains("| bounce\\_attempts | all | 3 | count |"),
        "markdown bounce total"
    );
    // Leg 4: replay the capture; the final block is the text report.
    let top = run(&["top", "--interval", "1s", dir.as_str()]);
    assert_eq!(top.status.code(), Some(0), "top exit");
    assert!(top.stderr.is_empty(), "top stderr");
    assert_eq!(
        final_block(&top.stdout),
        text.as_bytes(),
        "replayed final block equals the report"
    );
    // End-to-end: all four legs agree on identity, bytes, and total.
    for (what, body) in [
        ("text", text.as_str()),
        ("json", json.as_str()),
        ("markdown", markdown.as_str()),
        (
            "top",
            std::str::from_utf8(&top.stdout).expect("top stdout is UTF-8"),
        ),
    ] {
        assert!(body.contains("attempts-3-session"), "{what} session id");
        assert!(body.contains("1155"), "{what} verified bytes");
    }
}

/// Root check for the live leg: BPF load needs privilege.
fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn record_report_top_live_chain() {
    if std::env::var("MEMVEIL_CHAIN_LIVE").as_deref() != Ok("1") {
        eprintln!("SKIP record_report_top_live_chain: set MEMVEIL_CHAIN_LIVE=1 as root");
        return;
    }
    if !is_root() {
        eprintln!("SKIP record_report_top_live_chain: needs root for BPF load");
        return;
    }
    if !Path::new("/sys/kernel/btf/vmlinux").is_file() {
        eprintln!("SKIP record_report_top_live_chain: host BTF missing");
        return;
    }
    let root = repo_root();
    let aya_obj = PathBuf::from(env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH"));
    let profiles = root.join("profiles");
    for (tag, path) in [("Aya object", &aya_obj), ("profiles dir", &profiles)] {
        if !path.exists() {
            eprintln!(
                "SKIP record_report_top_live_chain: {tag} missing: {}",
                path.display()
            );
            return;
        }
    }
    let work = workdir("live");
    let cap = work.join("cap");
    // Leg 0: record a real 2 s capture. No --bridge: an empty
    // bridge is the normal case for record (the loader links
    // statically); the install journeys cover the
    // explicit-bridge path.
    let record = run(&[
        "record",
        "--duration",
        "2",
        "--output",
        cap.to_str().expect("tmp path is UTF-8"),
        "--object",
        aya_obj.to_str().expect("object path is UTF-8"),
        "--profiles-dir",
        profiles.to_str().expect("profiles path is UTF-8"),
    ]);
    if record.status.code() != Some(0) {
        eprintln!(
            "record failed, capture kept at {}:\n{}",
            work.display(),
            String::from_utf8_lossy(&record.stderr)
        );
        panic!("live record exit {}", record.status);
    }
    assert!(cap.join("session.json").is_file(), "record mints session");
    assert!(cap.join("events.ndjson").is_file(), "record mints events");
    let dir = cap.to_string_lossy().into_owned();
    // Legs 1-3: every render reads the live capture.
    let text = check_render_shape(&run(&["report", dir.as_str()]), "live text");
    let json = check_render_shape(
        &run(&["report", "--format", "json", dir.as_str()]),
        "live json",
    );
    assert!(json.starts_with("{\n"), "live json opens");
    let markdown = check_render_shape(
        &run(&["report", "--format", "markdown", dir.as_str()]),
        "live markdown",
    );
    assert!(
        markdown.starts_with("# Memveil report `"),
        "live markdown title"
    );
    // Leg 4: replay agrees byte-for-byte with the text report.
    let top = run(&["top", "--interval", "1s", dir.as_str()]);
    assert_eq!(top.status.code(), Some(0), "live top exit");
    assert_eq!(
        final_block(&top.stdout),
        text.as_bytes(),
        "live replayed final block equals the report"
    );
    let _ = std::fs::remove_dir_all(&work);
}
