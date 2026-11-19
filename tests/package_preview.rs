// SPDX-License-Identifier: GPL-3.0-or-later
//! Preview-qualification port: release binary behaviors plus docs audit.
//!
//! Ports `tests/package/test_preview.py` onto the release binary
//! (the same bytes the packages ship): every supported command,
//! the boundary negatives, and the claim-vs-receipt audit over
//! the shipped user docs. Bundle assembly stays owned by the
//! packaging suites; this suite qualifies behavior.

#[path = "package_helpers/mod.rs"]
mod package_helpers;

use package_helpers as h;
use std::fs;

fn run(args: &[&str]) -> std::process::Output {
    let binary = h::ensure_release_binary();
    h::run(binary.to_str().unwrap(), args, None)
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn preview_commands() {
    let binary = h::ensure_release_binary();
    println!(
        "preview: binary {} sha256 {:.16}...",
        binary.display(),
        h::sha256_file(&binary)
    );
    let out = run(&["help"]);
    assert!(
        out.status.success() && stdout(&out).contains("usage:"),
        "help"
    );
    let out = run(&["version"]);
    assert!(
        out.status.success() && !stdout(&out).trim().is_empty(),
        "version"
    );
    println!("preview: version {}", stdout(&out).trim());
    for args in [&["doctor"][..], &["doctor", "--json"][..]] {
        let out = run(args);
        assert!(
            out.status.code() == Some(0) || out.status.code() == Some(3),
            "doctor {args:?}"
        );
    }
}

#[test]
fn preview_report_flows() {
    let tmp = h::scratch("preview");
    let fixtures = h::fixtures_dir();
    let empty = h::valid_empty_dir();
    // Denial: an unusable object refuses with a diagnostic.
    let nope = tmp.join("nope");
    let out = run(&[
        "record",
        "--output",
        nope.to_str().unwrap(),
        "--object",
        fixtures.join("elf").join("ok.o").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(3), "denial");
    assert!(!stderr(&out).is_empty(), "denial-stderr");
    // Known-empty capture.
    let out = run(&["report", empty.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "empty: {}", stderr(&out));
    assert!(
        stdout(&out).contains("bounce_attempts = 0 count"),
        "empty-zeros"
    );
    assert!(
        stdout(&out).contains("successful_allocations = unavailable"),
        "empty-null"
    );
    // Attempts flow plus strictness.
    let attempts = fixtures.join("attempts").to_str().unwrap().to_string();
    assert_eq!(run(&["report", &attempts]).status.code(), Some(0), "report");
    assert_eq!(
        run(&["report", "--strict", &attempts]).status.code(),
        Some(4),
        "report-strict"
    );
    assert_eq!(
        run(&["top", "--interval", "60s", &attempts]).status.code(),
        Some(0),
        "top"
    );
    let partial = fixtures
        .join("reader")
        .join("partial-tail")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        run(&["report", "--allow-partial", &partial]).status.code(),
        Some(0),
        "partial"
    );
}

#[test]
fn preview_boundary_negatives() {
    let reader = h::fixtures_dir().join("reader");
    for name in [
        "compat-major",
        "badkind",
        "size-over",
        "adv-bad-utf8",
        "adv-nul",
        "adv-reversed-seq",
        "overflow",
        "corrupt-tail",
    ] {
        let dir = reader.join(name).to_str().unwrap().to_string();
        let args: Vec<&str> = if name == "corrupt-tail" {
            vec!["report", "--allow-partial", &dir]
        } else {
            vec!["report", &dir]
        };
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "neg-{name}");
        assert!(stdout(&out).is_empty(), "neg-{name} printed stdout");
    }
}

const FORBIDDEN_CLAIMS: [&str; 11] = [
    "always-on",
    "complete terminal coverage",
    "fully qualified",
    "proves confidentiality",
    "attestation",
    "tamper-proof",
    "bank-grade",
    "no live `top`",
    "live summary remains required work",
    "not yet wired",
    "not wired into the live collector",
];

#[test]
fn preview_docs_claim_audit() {
    // Audited bytes are the shipped bytes: docs stage from the
    // pristine packaging root.
    let root = h::pristine_root();
    let mut docs = vec![root.join("README.md")];
    let mut stack = vec![root.join("docs")];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<std::path::PathBuf> = fs::read_dir(&dir)
            .expect("docs")
            .flatten()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".md"))
            {
                docs.push(path);
            }
        }
    }
    assert!(docs.len() >= 5, "{} docs", docs.len());
    for path in &docs {
        let text = fs::read_to_string(path).unwrap();
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        for claim in FORBIDDEN_CLAIMS {
            if claim == "always-on" {
                let bad: Vec<&str> = text
                    .lines()
                    .filter(|l| {
                        l.to_lowercase().contains("always-on")
                            && !l.to_lowercase().contains("no always-on")
                    })
                    .collect();
                assert!(bad.is_empty(), "claim-{rel}-always-on: {bad:?}");
            } else if claim == "attestation" {
                let bad: Vec<&str> = text
                    .lines()
                    .filter(|l| {
                        l.to_lowercase().contains("attestation")
                            && ![
                                "not_performed",
                                "not performed",
                                "any attestation",
                                " no ",
                                " not ",
                                "unsupported",
                            ]
                            .iter()
                            .any(|neg| l.to_lowercase().contains(neg))
                    })
                    .collect();
                assert!(bad.is_empty(), "claim-{rel}-attestation: {bad:?}");
            } else {
                assert!(
                    !text.to_lowercase().contains(claim),
                    "claim-{rel}-{} present",
                    &claim[..12.min(claim.len())]
                );
            }
        }
    }
    let support = fs::read_to_string(root.join("docs").join("support.md")).unwrap();
    for phrase in [
        "partial",
        "out of scope",
        "missed ticks",
        "complete terminal evidence",
    ] {
        assert!(
            support.to_lowercase().contains(phrase),
            "support lacks {phrase}"
        );
    }
}
