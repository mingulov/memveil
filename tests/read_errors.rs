// SPDX-License-Identifier: GPL-3.0-or-later
//! Capture-open failures print cause plus remedy and exit 2.
//!
//! Table over verbs and bad inputs: a missing path, a regular
//! file, an empty directory, a foreign-owned directory (via
//! an LD_PRELOAD owner shim, unprivileged), and staged captures
//! with an unreadable member (session, events, checkpoint)
//! each refuse with a cause line naming the problem and a fix
//! line naming the remedy. Failures without a remedy keep
//! today's single line.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_memveil"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The owner shim, compiled once per test process.
///
/// A pid-suffixed scratch dir keeps parallel test processes
/// from racing one another on the output file.
fn owner_shim() -> &'static Path {
    static SHIM: OnceLock<PathBuf> = OnceLock::new();
    SHIM.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("mv-fakeeuid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("shim scratch dir");
        let src = repo_root().join("tests/shim/fakeeuid.c");
        let out = dir.join("fakeeuid.so");
        let status = Command::new("cc")
            .arg("-shared")
            .arg("-fPIC")
            .arg("-O1")
            .arg("-o")
            .arg(&out)
            .arg(&src)
            .status()
            .expect("run cc for the owner shim");
        assert!(status.success(), "cc builds the owner shim");
        out
    })
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mv-read-errors-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

struct Case {
    /// Short case name for failure messages.
    name: &'static str,
    /// Capture path spelling for the missing-input case.
    missing: bool,
    /// Write a regular file instead of a directory.
    file: bool,
    /// Run under the foreign-owner shim.
    foreign_owner: bool,
    /// Stage a capture and chmod this member 000 (None: no staging).
    unreadable_member: Option<&'static str>,
    /// Stage a recovery layout (checkpoint plus events, no session).
    recovery: bool,
    /// Expected cause text after the prefix.
    cause: &'static str,
    /// Expected remedy text after the fix prefix.
    fix: &'static str,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "missing",
            missing: true,
            file: false,
            foreign_owner: false,
            unreadable_member: None,
            recovery: false,
            cause: "capture directory does not exist",
            fix: "check the path spelling and retry with an existing capture directory",
        },
        Case {
            name: "file",
            missing: false,
            file: true,
            foreign_owner: false,
            unreadable_member: None,
            recovery: false,
            cause: "capture path is not a directory",
            fix: "pass a capture directory (a directory holding session.json and events.ndjson)",
        },
        Case {
            name: "empty",
            missing: false,
            file: false,
            foreign_owner: false,
            unreadable_member: None,
            recovery: false,
            cause: "not a memveil capture: expected session.json/events.ndjson",
            fix: "pass a capture directory (session.json and events.ndjson)",
        },
        Case {
            name: "foreign-owner",
            missing: false,
            file: false,
            foreign_owner: true,
            unreadable_member: None,
            recovery: false,
            cause: "capture directory not owned by reader",
            fix: "take ownership as the reading user (for example: sudo chown -R $(id -u):$(id -g) DIR)",
        },
        Case {
            name: "unreadable-events",
            missing: false,
            file: false,
            foreign_owner: false,
            unreadable_member: Some("events.ndjson"),
            recovery: false,
            cause: "events.ndjson: unreadable (permission denied)",
            fix: "check read access to the capture member and retry",
        },
        Case {
            name: "unreadable-session",
            missing: false,
            file: false,
            foreign_owner: false,
            unreadable_member: Some("session.json"),
            recovery: false,
            cause: "session.json: unreadable (permission denied)",
            fix: "check read access to the capture member and retry",
        },
        Case {
            name: "unreadable-checkpoint",
            missing: false,
            file: false,
            foreign_owner: false,
            unreadable_member: Some("checkpoint.json"),
            recovery: true,
            cause: "checkpoint.json: unreadable (permission denied)",
            fix: "check read access to the capture member and retry",
        },
    ]
}

/// Stage a capture with one member chmodded 000: a denied
/// member exists, so the open names the denial, never the
/// missing-capture cause.
fn stage_unreadable(dir: &Path, member: &str, recovery: bool) {
    use std::os::unix::fs::PermissionsExt;
    if recovery {
        std::fs::write(dir.join("checkpoint.json"), b"{}").expect("write checkpoint");
        std::fs::write(dir.join("events.ndjson"), b"").expect("write events");
    } else {
        let attempts = repo_root().join("tests/fixtures/attempts");
        std::fs::copy(attempts.join("session.json"), dir.join("session.json"))
            .expect("copy session");
        std::fs::copy(attempts.join("events.ndjson"), dir.join("events.ndjson"))
            .expect("copy events");
    }
    std::fs::set_permissions(dir.join(member), std::fs::Permissions::from_mode(0o000))
        .expect("chmod member");
}

#[test]
fn open_failures_print_cause_and_fix() {
    for verb in ["report", "top"] {
        for case in cases() {
            if case.unreadable_member.is_some() {
                // Root reads through file modes, so the denial
                // cases only run unprivileged.
                // SAFETY: pure id query.
                if unsafe { libc::geteuid() } == 0 {
                    eprintln!("SKIP {} {verb}: requires non-root", case.name);
                    continue;
                }
            }
            let dir = scratch(case.name);
            let target = if case.missing {
                dir.join("no-such-capture-xyz")
                    .to_string_lossy()
                    .into_owned()
            } else if case.file {
                let file = dir.join("plain-file");
                std::fs::write(&file, b"not a capture\n").expect("write file");
                file.to_string_lossy().into_owned()
            } else {
                if let Some(member) = case.unreadable_member {
                    stage_unreadable(&dir, member, case.recovery);
                }
                dir.to_string_lossy().into_owned()
            };
            let mut cmd = Command::new(bin());
            cmd.arg(verb).arg(&target);
            if case.foreign_owner {
                cmd.env("LD_PRELOAD", owner_shim());
            }
            let out = cmd.output().expect("run memveil");
            assert_eq!(out.status.code(), Some(2), "{} {verb}: exit", case.name);
            assert!(out.stdout.is_empty(), "{} {verb}: stdout silent", case.name);
            let want = format!(
                "memveil {verb}: cannot read capture: {}\nmemveil {verb}: fix: {}\n",
                case.cause, case.fix
            );
            assert_eq!(
                String::from_utf8_lossy(&out.stderr),
                want,
                "{} {verb}: cause plus fix",
                case.name
            );
        }
    }
}

#[test]
fn unremedied_failures_stay_single_line() {
    // A mid-stream parse failure carries caller bytes and has no
    // remedy: one scrubbed line, no fix line.
    let dir = repo_root().join("tests/fixtures/reader/badkind");
    for verb in ["report", "top"] {
        let out = Command::new(bin())
            .arg(verb)
            .arg(&dir)
            .output()
            .expect("run memveil");
        assert_eq!(out.status.code(), Some(2), "{verb}: exit");
        assert!(out.stdout.is_empty(), "{verb}: stdout silent");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.stderr.iter().filter(|b| **b == b'\n').count(),
            1,
            "{verb}: one line"
        );
        assert!(!err.contains("fix: "), "{verb}: no remedy");
    }
}
