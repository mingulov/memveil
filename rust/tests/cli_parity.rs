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
    for verb in [
        "record",
        "report",
        "top",
        "doctor",
        "qualify",
        "bind-profile",
    ] {
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
        vec!["top", "--help"],
        vec!["doctor", "--help"],
        vec!["qualify", "--help"],
        vec!["bind-profile", "--help"],
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

fn run_top(bin: &Path, extra: &[&str], dir: &Path) -> Output {
    let dir = dir.to_string_lossy().into_owned();
    let mut args: Vec<&str> = vec!["top", "--interval", "1s"];
    args.extend(extra.iter().copied());
    args.push(dir.as_str());
    run(bin, &args)
}

fn lifecycle(name: &str) -> PathBuf {
    repo_root().join("tests/fixtures/lifecycle").join(name)
}

fn final_block(stdout: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(stdout);
    let blocks: Vec<&str> = text.split("--- refresh ").collect();
    assert!(blocks.len() >= 2, "top prints at least a final block");
    let last = blocks[blocks.len() - 1];
    let body = last.split_once('\n').expect("header line").1;
    body.as_bytes().to_vec()
}

#[test]
fn top_replay_prefix_equivalence() {
    // The final top block renders the same rows as report with the
    // same policy, so the final block body equals report stdout.
    for dir in [lifecycle("lifecycle-nested"), lifecycle("open-at-end")] {
        let top = run_top(&bin(), &[], &dir);
        assert_eq!(top.status.code(), Some(0));
        assert!(top.stderr.is_empty());
        let rep = run_report(&bin(), &[], &dir);
        assert_eq!(rep.status.code(), Some(0));
        assert_eq!(final_block(&top.stdout), rep.stdout);
    }
}

#[test]
fn top_replay_blocks_and_integrity() {
    // Window [1e9, 2.5e9) with 1s interval: boundary 2e9 + final.
    let dir = lifecycle("lifecycle-nested");
    let out = run_top(&bin(), &[], &dir);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    let blocks: Vec<&str> = text
        .split("--- refresh ")
        .filter(|b| !b.trim().is_empty())
        .collect();
    assert_eq!(blocks.len(), 2);
    assert!(blocks[1].contains("successful_allocations = 1"));
    assert!(blocks[0].contains("integrity: unverified replay prefix"));
    assert!(blocks[1].contains("integrity: legacy_unverified"));
    // The 2.0s refresh excludes the unmap at 2.3s: the mapping is
    // still open at the first boundary.
    assert!(blocks[0].contains("open_mappings = 1"));
    assert!(blocks[0].contains("live_observed_allocation_bytes = 4096"));
    assert!(!blocks[0].contains("completed_lifetime_count = 1"));
}

#[test]
fn top_device_filter_warns_once() {
    let dir = lifecycle("lifecycle-nested");
    let out = run_top(&bin(), &["--device", "nope"], &dir);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains("{device="));
    assert!(stdout.contains("bounce_attempts = 1"));
    assert!(stdout.contains("[device: nope]"));
    assert_eq!(stderr.matches("matches no known device").count(), 1);
    assert!(stderr.contains("memveil top: --device 'nope' matches no known device\n"));
    // Resolving ids and catalog names stay quiet.
    for filt in ["dev-1", "testdev0"] {
        let hit = run_top(&bin(), &["--device", filt], &dir);
        assert_eq!(hit.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&hit.stdout).contains("{device=dev-1}"));
        assert!(!String::from_utf8_lossy(&hit.stderr).contains("matches no known device"));
    }
}

#[test]
fn top_hostile_filter_stays_escaped() {
    let hostile = "a\x1b[2J\nb\tc\rd\x07e\x7ff";
    let esc = "a�[2J\\nb\\tc\\rd�e�f";
    let dir = lifecycle("lifecycle-nested").to_string_lossy().into_owned();
    let out = run(
        &bin(),
        &["top", "--interval", "1s", "--device", hostile, &dir],
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr)
            .matches("matches no known device")
            .count(),
        1
    );
    assert!(!out.stdout.contains(&0x1b));
    assert!(!out.stderr.contains(&0x1b));
    assert!(!out.stdout.contains(&0x7f));
    assert!(!out.stderr.contains(&0x7f));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!(
        "--- refresh 1 @ 2000000000 ns --- [device: {esc}]"
    )));
    assert!(stdout.contains(&format!(
        "--- refresh 2 @ 2500000000 ns --- [device: {esc}]"
    )));
}

#[test]
fn top_compact_blocks() {
    let dir = lifecycle("lifecycle-nested");
    let out = run_top(&bin(), &["--compact"], &dir);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    let blocks: Vec<&str> = text
        .split("--- refresh ")
        .filter(|b| !b.trim().is_empty())
        .collect();
    assert_eq!(blocks.len(), 2);
    assert!(blocks[1].contains("verdict: "));
    assert!(blocks[1].contains("attempts: "));
    assert!(blocks[1].contains("detail: "));
    assert!(blocks[1].contains("terminal: "));
    assert!(blocks[1].contains("findings: "));
    assert!(!text.contains("memveil report "));
    assert!(!text.contains("metrics ("));
}

#[test]
fn top_strict_keeps_full_stdout() {
    let dir = fixture("sealed-partial");
    let plain = run_top(&bin(), &[], &dir);
    let strict = run_top(&bin(), &["--strict"], &dir);
    assert_eq!(plain.status.code(), Some(0));
    assert_eq!(strict.status.code(), Some(4));
    assert_eq!(strict.stdout, plain.stdout);
}

#[test]
fn top_long_lived_policy() {
    let open = lifecycle("open-at-end");
    let plain = run_top(&bin(), &[], &open);
    assert_eq!(plain.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("LONG_LIVED_ALLOCATION"));
    let found = run_top(&bin(), &["--long-lived-after", "1s"], &open);
    assert_eq!(found.status.code(), Some(0));
    let text = String::from_utf8_lossy(&found.stdout);
    assert!(text.contains("LONG_LIVED_ALLOCATION"));
    assert!(text.contains("not a leak"));
    let nested = lifecycle("lifecycle-nested");
    let unknown = run_top(&bin(), &["--long-lived-after", "1s"], &nested);
    assert_eq!(unknown.status.code(), Some(0));
    let text = String::from_utf8_lossy(&unknown.stdout);
    assert!(text.contains("LONG_LIVED_NOT_EVALUATED"));
    assert!(text.contains("No open mappings at the horizon"));
}

#[test]
fn top_sigint_finishes_final() {
    use std::process::{Command, Stdio};
    use std::time::Duration;
    let dir = lifecycle("lifecycle-nested").to_string_lossy().into_owned();
    let mut child = Command::new(bin())
        .args(["top", "--interval", "1s", &dir])
        .current_dir(repo_root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn top");
    // One boundary refresh sleeps a full interval before the final,
    // so the process is guaranteed to be sleeping at 0.5s.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().expect("poll").is_none(),
        "top exited before the signal"
    );
    let pid = child.id() as i32;
    // SAFETY: SIGINT to the spawned child only.
    let rc = unsafe { libc::kill(pid, libc::SIGINT) };
    assert_eq!(rc, 0);
    let out = child.wait_with_output().expect("reap");
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("successful_allocations = 1"));
}

#[test]
fn top_live_mode_refusals() {
    let tmp = std::env::temp_dir().join(format!("memveil-top-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let live_out = tmp.join("cap");
    let live_str = live_out.to_str().expect("tmp path is UTF-8");
    let nested = lifecycle("lifecycle-nested").to_string_lossy().into_owned();
    // Replay DIR plus live --output refuses.
    let out = run(&bin(), &["top", &nested, "--output", live_str]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("replay") && err.contains("live"), "{err}");
    // Live durations parse through the shared record parser.
    let out = run(&bin(), &["top", "--output", live_str, "--duration", "nope"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("bad decimal: nope"));
    // Replay refuses live-only flags.
    let out = run(&bin(), &["top", &nested, "--profiles-dir", "/alt/profiles"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("live options need --output"));
    // Collection budgets refuse before any write.
    let out = run(
        &bin(),
        &["top", "--output", live_str, "--max-events-bytes", "5"],
    );
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stderr, b"memveil top: budget 5 below 131072\n");
    assert!(!live_out.exists());
    // Unavailable collection refuses cleanly with no escape bytes.
    let out = run(
        &bin(),
        &[
            "top",
            "--output",
            live_str,
            "--object",
            "tests/fixtures/elf/ok.o",
        ],
    );
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("memveil top:"));
    assert!(!out.stdout.contains(&0x1b));
    assert!(!out.stderr.contains(&0x1b));
    assert!(!live_out.exists());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn top_bytes_equal_mojo_over_fixtures() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: MEMVEIL_MOJO_BIN unset");
        return;
    };
    let nested = lifecycle("lifecycle-nested");
    let open = lifecycle("open-at-end");
    let escape = fixture("escape");
    let sel = fixture("selection-retained");
    let cases: Vec<(&Path, Vec<&str>)> = vec![
        (&nested, vec![]),
        (&nested, vec!["--device", "dev-1"]),
        (&nested, vec!["--device", "testdev0"]),
        (&nested, vec!["--device", "nope"]),
        (&nested, vec!["--compact"]),
        (&nested, vec!["--strict"]),
        (&nested, vec!["--long-lived-after", "1s"]),
        (&open, vec![]),
        (&open, vec!["--long-lived-after", "1s"]),
        (&escape, vec![]),
        (&sel, vec![]),
        (&sel, vec!["--device", "nope"]),
    ];
    for (dir, extra) in cases {
        let ours = run_top(&bin(), &extra, dir);
        let want = run_top(&mojo, &extra, dir);
        assert_eq!(
            ours.status.code(),
            want.status.code(),
            "{dir:?} {extra:?} exit"
        );
        assert_eq!(ours.stdout, want.stdout, "{dir:?} {extra:?} stdout bytes");
        assert_eq!(ours.stderr, want.stderr, "{dir:?} {extra:?} stderr bytes");
    }
}

#[test]
fn doctor_text_shape() {
    // Live admission depends on host state, so the exit rides in
    // {0, 3} while the report shape and stream split stay exact.
    let out = run(&bin(), &["doctor", "--profiles-dir", "profiles"]);
    assert!(out.status.code() == Some(0) || out.status.code() == Some(3));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("memveil doctor (passive, live evidence)\n"));
    assert!(stdout.contains("verdict: "));
    assert!(stdout.contains("summary: "));
    assert!(stdout.ends_with('\n'));
}

#[test]
fn doctor_json_shape_and_schema() {
    let out = run(&bin(), &["doctor", "--json", "--profiles-dir", "profiles"]);
    assert!(out.status.code() == Some(0) || out.status.code() == Some(3));
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"schema_version\": \"0.1.1\""));
    assert!(stdout.contains("\"mode\": \"passive\""));
    // Oracle check: the emitted JSON validates against the schema.
    let tmp = std::env::temp_dir().join(format!("memveil-doctor-{}.json", std::process::id()));
    std::fs::write(&tmp, &out.stdout).expect("write doctor json");
    let schema = repo_root().join("schemas/doctor-v0.1.1.schema.json");
    let check = std::process::Command::new("python3")
        .arg("-c")
        .arg("import json,jsonschema,sys; jsonschema.validate(json.load(open(sys.argv[1])), json.load(open(sys.argv[2])))")
        .arg(&tmp)
        .arg(schema)
        .output()
        .expect("run jsonschema");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn doctor_usage_errors() {
    for args in [
        vec!["doctor", "--bogus"],
        vec!["doctor", "--profiles-dir"],
        vec!["doctor", "--capability"],
        vec![
            "doctor",
            "--capability",
            "attempt-trace,nope",
            "--profiles-dir",
            "profiles",
        ],
    ] {
        let out = run(&bin(), &args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).starts_with("memveil doctor: "),
            "{args:?}"
        );
    }
    let out = run(
        &bin(),
        &[
            "doctor",
            "--capability",
            "attempt-trace,nope",
            "--profiles-dir",
            "profiles",
        ],
    );
    assert_eq!(out.stderr, b"memveil doctor: unknown capability: nope\n");
}

#[test]
fn qualify_bind_usage_errors() {
    for args in [
        vec!["qualify"],
        vec!["qualify", "--bogus", "--output", "o"],
        vec!["qualify", "--output"],
        vec!["bind-profile"],
        vec!["bind-profile", "--output", "x", "--bogus"],
        vec!["bind-profile", "--output", "x", "stray"],
        vec!["bind-profile", "--output", "x", "--profile-id"],
    ] {
        let out = run(&bin(), &args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    let out = run(&bin(), &["qualify"]);
    assert_eq!(out.stderr, b"memveil qualify: missing --output\n");
    let out = run(&bin(), &["bind-profile", "--output", "x", "stray"]);
    assert_eq!(
        out.stderr,
        b"memveil bind-profile: unexpected argument: stray\n"
    );
}

#[test]
fn qualify_no_object_refusal() {
    let tmp = std::env::temp_dir().join(format!("memveil-qual-{}", std::process::id()));
    let outdir = tmp.join("cap");
    let out = run(
        &bin(),
        &[
            "qualify",
            "--output",
            outdir.to_str().expect("tmp path is UTF-8"),
        ],
    );
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(
        out.stderr,
        b"memveil qualify: no object: pass --object PATH\n"
    );
    assert!(!outdir.exists());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn bind_refusals() {
    let tmp = std::env::temp_dir().join(format!("memveil-bind-{}", std::process::id()));
    let out = tmp.join("x.json");
    let path = out.to_str().expect("tmp path is UTF-8");
    // Unknown base profile refuses.
    let refused = run(
        &bin(),
        &[
            "bind-profile",
            "--output",
            path,
            "--profile",
            "no-such-id",
            "--profiles-dir",
            "profiles",
        ],
    );
    assert_eq!(refused.status.code(), Some(3));
    assert_eq!(
        refused.stderr,
        b"memveil bind-profile: unknown --profile: no-such-id\n"
    );
    // A bad profile id is a usage error.
    let misused = run(
        &bin(),
        &["bind-profile", "--output", path, "--profile-id", "bad id"],
    );
    assert_eq!(misused.status.code(), Some(2));
    assert_eq!(
        misused.stderr,
        b"memveil bind-profile: bad --profile-id: bad id\n"
    );
    // Capabilities without a record channel refuse.
    for cap in ["bogus-cap", "conversion-observe"] {
        let bad = run(
            &bin(),
            &["bind-profile", "--output", path, "--capability", cap],
        );
        assert_eq!(bad.status.code(), Some(3), "cap {cap}");
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn task2_errors_equal_mojo() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: MEMVEIL_MOJO_BIN unset");
        return;
    };
    let nested = lifecycle("lifecycle-nested").to_string_lossy().into_owned();
    let open = lifecycle("open-at-end").to_string_lossy().into_owned();
    for args in [
        vec!["top"],
        vec!["top", "--interval", "nope", nested.as_str()],
        vec!["top", "--nope", nested.as_str()],
        vec!["top", "--long-lived-after", "0s", nested.as_str()],
        vec!["top", "--compact", "--device", "d", nested.as_str()],
        vec!["top", "--max-events-bytes", "64", nested.as_str()],
        vec!["top", "--max-line-bytes", "99999999", nested.as_str()],
        vec!["top", nested.as_str(), "--output", "o"],
        vec!["top", "--output", "o", "--allow-partial"],
        vec!["top", "--output", "o", "--duration", "nope"],
        vec!["top", nested.as_str(), "--profiles-dir", "/alt"],
        vec!["top", "--output", "o", "--max-events-bytes", "5"],
        vec!["top", "--interval", "1s", "--allow-partial", open.as_str()],
        vec!["doctor", "--bogus"],
        vec!["doctor", "--profiles-dir"],
        vec!["doctor", "--capability"],
        vec![
            "doctor",
            "--capability",
            "attempt-trace,nope",
            "--profiles-dir",
            "profiles",
        ],
        vec!["qualify"],
        vec!["qualify", "--bogus", "--output", "o"],
        vec!["qualify", "--output"],
        vec!["qualify", "--output", "o", "--capability", "bogus"],
        vec!["qualify", "--output", "o"],
        vec!["bind-profile"],
        vec!["bind-profile", "--output", "x", "--bogus"],
        vec!["bind-profile", "--output", "x", "stray"],
        vec!["bind-profile", "--output", "x", "--profile-id"],
        vec!["bind-profile", "--output", "x", "--profile-id", "bad id"],
        vec![
            "bind-profile",
            "--output",
            "x",
            "--profile",
            "no-such-id",
            "--profiles-dir",
            "profiles",
        ],
        vec!["bind-profile", "--output", "x", "--capability", "bogus-cap"],
        vec![
            "bind-profile",
            "--output",
            "x",
            "--capability",
            "conversion-observe",
        ],
        vec![
            "bind-profile",
            "--output",
            "x",
            "--object",
            "tests/fixtures/elf/ok.o",
            "--profiles-dir",
            "profiles",
        ],
    ] {
        let ours = run(&bin(), &args);
        let want = run(&mojo, &args);
        assert_eq!(ours.status.code(), want.status.code(), "{args:?} exit");
        assert_eq!(ours.stdout, want.stdout, "{args:?} stdout bytes");
        assert_eq!(ours.stderr, want.stderr, "{args:?} stderr bytes");
    }
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
