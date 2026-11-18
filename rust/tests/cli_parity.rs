// SPDX-License-Identifier: GPL-3.0-or-later
//! CLI parity tests: dispatch, exits, and Mojo byte-equality.
//!
//! Ungated tests pin exit codes and output shapes through the built
//! binary. Tests that diff against the Mojo-built binary need
//! `MEMVEIL_MOJO_BIN` to point at it and pass silently without it,
//! so a plain `cargo test` stays green where Mojo is absent.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_memveil"))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust/ must have a parent directory")
        .to_path_buf()
}

fn fixture(name: &str) -> PathBuf {
    repo_root().join("tests/fixtures/reader").join(name)
}

/// The Mojo-built comparison binary, when the caller provides one.
fn mojo_bin() -> Option<PathBuf> {
    std::env::var_os("MEMVEIL_MOJO_BIN").map(PathBuf::from)
}

fn run(bin: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run binary")
}

fn run_report(bin: &Path, extra: &[&str], dir: &Path) -> Output {
    let dir = dir.to_string_lossy().into_owned();
    let mut args: Vec<&str> = vec!["report"];
    args.extend(extra.iter().copied());
    args.push(dir.as_str());
    run(bin, &args)
}

/// A capture whose render is maximal: 4096 catalog devices (the model
/// cap) with max-length ids, names, and drivers over the sealed
/// events. Both binaries share the same device and metric caps, so
/// no valid capture renders past the 16 MiB tripwire; these cases
/// pin agreement at the size extreme instead.
fn maximal_capture_dir(tag: &str) -> PathBuf {
    let tmp = std::env::temp_dir().join(format!("memveil-cli-max-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("temp capture dir");
    let src = fixture("sealed-complete");
    for name in ["events.ndjson", "provenance.json"] {
        std::fs::copy(src.join(name), tmp.join(name)).expect("copy capture file");
    }
    let session = std::fs::read_to_string(src.join("session.json")).expect("read session");
    let key = "\"devices\": [";
    let open = session.find(key).expect("devices array") + key.len();
    let close = session[open..].find(']').expect("devices end") + open;
    // The sealed entry keeps its events resolvable; the padding
    // fills the catalog to its cap at the field length limits.
    let mut entries = vec![session[open..close].trim().to_string()];
    for i in 0..4095 {
        entries.push(format!(
            "{{\n        \"device_id\": \"d{i:04}{}\",\n        \"name\": \"n{i:05}{}\",\n        \"driver\": \"g{i:04}{}\",\n        \"identity_status\": \"resolved\"\n      }}",
            "x".repeat(123),
            "y".repeat(250),
            "z".repeat(123),
        ));
    }
    let mut out = session[..open].to_string();
    out.push('\n');
    out.push_str(&entries.join(",\n"));
    out.push('\n');
    out.push_str(&session[close..]);
    std::fs::write(tmp.join("session.json"), out).expect("write session");
    tmp
}

#[test]
fn no_verb_prints_usage_to_stderr() {
    let out = run(&bin(), &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with(
        "usage: memveil <record|report|top|doctor|qualify|bind-profile|help|version> [args]\n"
    ));
}

#[test]
fn unknown_verb_prints_usage_to_stderr() {
    let out = run(&bin(), &["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("usage: memveil "));
}

#[test]
fn help_verbs_print_usage_to_stdout() {
    for verb in ["help", "--help", "-h"] {
        let out = run(&bin(), &[verb]);
        assert_eq!(out.status.code(), Some(0), "verb {verb}");
        assert!(out.stderr.is_empty(), "verb {verb}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.starts_with("usage: memveil <record|report"),
            "verb {verb}"
        );
        assert!(text.contains("Run 'memveil report --help' for report options."));
    }
}

#[test]
fn verb_help_flags_exit_zero() {
    for verb in ["record", "report"] {
        for flag in ["--help", "-h"] {
            let out = run(&bin(), &[verb, flag]);
            assert_eq!(out.status.code(), Some(0), "{verb} {flag}");
            assert!(out.stderr.is_empty(), "{verb} {flag}");
            assert!(
                String::from_utf8_lossy(&out.stdout)
                    .starts_with(format!("usage: memveil {verb}").as_str()),
                "{verb} {flag}"
            );
        }
    }
}

#[test]
fn report_missing_dir_exits_two() {
    let out = run(&bin(), &["report"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(out.stderr, b"memveil report: missing capture directory\n");
}

#[test]
fn report_bad_format_exits_two() {
    let dir = fixture("sealed-complete");
    let out = run_report(&bin(), &["--format", "yaml"], &dir);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stderr, b"memveil report: unknown format: yaml\n");
}

#[test]
fn report_bad_duration_exits_two() {
    let dir = fixture("sealed-complete");
    let out = run_report(&bin(), &["--long-lived-after", "bogus"], &dir);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        out.stderr,
        b"memveil report: --long-lived-after DurationError(message=bad duration: bogus)\n"
    );
}

#[test]
fn report_missing_capture_exits_two() {
    let out = run(&bin(), &["report", "tests/fixtures/reader/no-such-dir"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).starts_with("memveil report: cannot read capture: ")
    );
}

#[test]
fn report_sealed_exits() {
    let cases = [
        ("sealed-complete", &[][..], 0),
        ("sealed-empty", &[][..], 0),
        ("sealed-partial", &[][..], 0),
        ("sealed-complete", &["--strict"][..], 0),
        ("sealed-empty", &["--strict"][..], 4),
        ("sealed-partial", &["--strict"][..], 4),
    ];
    for (name, extra, code) in cases {
        let out = run_report(&bin(), extra, &fixture(name));
        assert_eq!(out.status.code(), Some(code), "{name} {extra:?}");
        assert!(out.stderr.is_empty(), "{name} {extra:?}");
        assert!(out.stdout.ends_with(b"\n"), "{name} ends with newline");
    }
}

#[test]
fn report_strict_keeps_full_stdout() {
    let dir = fixture("sealed-partial");
    let plain = run_report(&bin(), &[], &dir);
    let strict = run_report(&bin(), &["--strict"], &dir);
    assert_eq!(plain.status.code(), Some(0));
    assert_eq!(strict.status.code(), Some(4));
    assert_eq!(strict.stdout, plain.stdout);
}

#[test]
fn report_maximal_capture_renders_fully() {
    let dir = maximal_capture_dir("full");
    let out = run_report(&bin(), &[], &dir);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    assert!(
        out.stdout.len() > 2_000_000,
        "maximal render stays large, got {} bytes",
        out.stdout.len()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn record_unknown_option_exits_two() {
    let out = run(&bin(), &["record", "--output", "o", "--bogus"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stderr, b"memveil record: unknown option: --bogus\n");
}

#[test]
fn record_refusal_leaves_no_residue() {
    let tmp = std::env::temp_dir().join(format!("memveil-cli-test-{}", std::process::id()));
    let outdir = tmp.join("newdir");
    let _ = std::fs::remove_dir_all(&tmp);
    let out = run(
        &bin(),
        &[
            "record",
            "--output",
            outdir.to_str().expect("tmp path is UTF-8"),
            "--profiles-dir",
            "/nonexistent-profiles-dir-xyz",
        ],
    );
    assert_eq!(out.status.code(), Some(3));
    assert!(!outdir.exists(), "refusal must not create the output dir");
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("memveil record: "));
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn record_budget_refusal_is_exact() {
    let tmp = std::env::temp_dir().join(format!("memveil-cli-test-{}", std::process::id()));
    for (value, want) in [
        (
            "131071",
            &b"memveil record: budget 131071 below 131072\n"[..],
        ),
        (
            "4294967297",
            &b"memveil record: budget 4294967297 above 4294967296\n"[..],
        ),
    ] {
        let outdir = tmp.join(format!("budget-{value}"));
        let out = run(
            &bin(),
            &[
                "record",
                "--output",
                outdir.to_str().expect("tmp path is UTF-8"),
                "--profiles-dir",
                "/nonexistent-profiles-dir-xyz",
                "--max-events-bytes",
                value,
            ],
        );
        assert_eq!(out.status.code(), Some(3), "budget {value}");
        assert!(out.stdout.is_empty(), "budget {value}");
        assert_eq!(out.stderr, want, "budget {value}");
        assert!(!outdir.exists(), "budget {value} leaves no residue");
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn help_flag_wins_anywhere() {
    for args in [
        vec!["record", "--output", "o", "--help"],
        vec!["record", "-h", "--output", "o"],
        vec!["report", "tests/fixtures/reader/sealed-complete", "--help"],
    ] {
        let out = run(&bin(), &args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(!out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn help_bytes_equal_mojo() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: MEMVEIL_MOJO_BIN unset");
        return;
    };
    for args in [
        vec!["--help"],
        vec!["help"],
        vec!["record", "--help"],
        vec!["report", "--help"],
        vec!["--version"],
    ] {
        let ours = run(&bin(), &args);
        let want = run(&mojo, &args);
        assert_eq!(ours.status.code(), want.status.code(), "{args:?} exit");
        assert_eq!(ours.stdout, want.stdout, "{args:?} stdout bytes");
        assert_eq!(ours.stderr, want.stderr, "{args:?} stderr bytes");
    }
}

#[test]
fn report_bytes_equal_mojo_over_sealed() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: MEMVEIL_MOJO_BIN unset");
        return;
    };
    for name in ["sealed-complete", "sealed-empty", "sealed-partial"] {
        for extra in [
            vec![],
            vec!["--strict"],
            vec!["--format", "json"],
            vec!["--format", "markdown"],
            vec!["--format", "json", "--strict"],
        ] {
            let dir = fixture(name);
            let ours = run_report(&bin(), &extra, &dir);
            let want = run_report(&mojo, &extra, &dir);
            assert_eq!(
                ours.status.code(),
                want.status.code(),
                "{name} {extra:?} exit"
            );
            assert_eq!(ours.stdout, want.stdout, "{name} {extra:?} stdout bytes");
            assert_eq!(ours.stderr, want.stderr, "{name} {extra:?} stderr bytes");
        }
    }
}

#[test]
fn report_maximal_bytes_equal_mojo() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: MEMVEIL_MOJO_BIN unset");
        return;
    };
    let dir = maximal_capture_dir("mojo");
    let ours = run_report(&bin(), &[], &dir);
    let want = run_report(&mojo, &[], &dir);
    assert_eq!(ours.status.code(), want.status.code(), "maximal exit");
    assert_eq!(ours.stdout, want.stdout, "maximal stdout bytes");
    assert_eq!(ours.stderr, want.stderr, "maximal stderr bytes");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_errors_equal_mojo() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: MEMVEIL_MOJO_BIN unset");
        return;
    };
    let dir = fixture("sealed-complete").to_string_lossy().into_owned();
    for args in [
        vec!["report"],
        vec!["report", "--format", "yaml", dir.as_str()],
        vec!["report", "--long-lived-after", "bogus", dir.as_str()],
        vec!["report", "--max-line-bytes", "65537", dir.as_str()],
        vec!["report", "tests/fixtures/reader/no-such-dir"],
        vec!["record", "--output", "o", "--bogus"],
        vec!["record"],
        vec!["frobnicate"],
    ] {
        let ours = run(&bin(), &args);
        let want = run(&mojo, &args);
        assert_eq!(ours.status.code(), want.status.code(), "{args:?} exit");
        assert_eq!(ours.stdout, want.stdout, "{args:?} stdout bytes");
        assert_eq!(ours.stderr, want.stderr, "{args:?} stderr bytes");
    }
}
