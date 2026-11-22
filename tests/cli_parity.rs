// SPDX-License-Identifier: GPL-3.0-or-later
//! CLI parity tests: dispatch, exits, and output shapes.
//!
//! Ungated tests pin exit codes and output shapes through the built
//! binary. The Mojo byte-equality differentials below retired at
//! the cutover (no Mojo binary exists anymore) and skip
//! permanently with cause; byte-identical behavior stays pinned
//! by the fixture and golden tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_memveil"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    repo_root().join("tests/fixtures/reader").join(name)
}

/// The Mojo-built comparison binary: permanently retired at the
/// cutover (no Mojo binary exists anymore). Kept returning None
/// so the differentials below skip with cause instead of
/// disappearing silently.
fn mojo_bin() -> Option<PathBuf> {
    None
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

/// A checkpoint-recovery capture: verified prefix, no final session.
///
/// Derived from sealed-complete by retiring the final session into a
/// checkpoint generation, so both binaries recover the same verified
/// prefix under --allow-partial and demand the flag without it.
fn checkpoint_capture_dir(tag: &str) -> PathBuf {
    let tmp = std::env::temp_dir().join(format!("memveil-cli-ckpt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("temp capture dir");
    let src = fixture("sealed-complete");
    std::fs::copy(src.join("events.ndjson"), tmp.join("events.ndjson")).expect("copy events");
    let session = std::fs::read_to_string(src.join("session.json")).expect("read session");
    let retired = session.replacen("\"finalized\": true", "\"finalized\": false", 1);
    assert_ne!(retired, session, "sealed session carries finalized:true");
    let checkpoint = retired.replacen(
        "\"end_reason\": \"duration\"",
        "\"end_reason\": \"checkpoint\",\n    \"checkpoint_generation\": \"1\"",
        1,
    );
    assert_ne!(
        checkpoint, retired,
        "sealed session carries end_reason:duration"
    );
    std::fs::write(tmp.join("checkpoint.json"), checkpoint).expect("write checkpoint");
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
fn report_checkpoint_recovery_exits() {
    let dir = checkpoint_capture_dir("shape");
    // Without the flag the verified-prefix demand names it.
    let demand = run_report(&bin(), &[], &dir);
    assert_eq!(demand.status.code(), Some(2));
    assert!(demand.stdout.is_empty());
    assert_eq!(
        demand.stderr,
        b"memveil report: cannot read capture: no final session; verified checkpoint prefix 1155 bytes; use --allow-partial to recover\n"
    );
    // With the flag the recovery renders and exits 4.
    let out = run_report(&bin(), &["--allow-partial"], &dir);
    assert_eq!(out.status.code(), Some(4));
    assert!(out.stderr.is_empty());
    assert!(out.stdout.ends_with(b"\n"));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("checkpoint_prefix (verified bytes=1155")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_long_lived_flag_sensitive() {
    let dir = lifecycle("open-at-end");
    let plain = run_report(&bin(), &[], &dir);
    assert_eq!(plain.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("LONG_LIVED_ALLOCATION"));
    let found = run_report(&bin(), &["--long-lived-after", "1s"], &dir);
    assert_eq!(found.status.code(), Some(0));
    assert!(found.stderr.is_empty());
    let text = String::from_utf8_lossy(&found.stdout);
    assert!(text.contains("LONG_LIVED_ALLOCATION"));
    assert!(text.contains("not a leak"));
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
fn help_bytes_pinned_rust() {
    // Pinned Rust reality (no Mojo oracle): every --help plus
    // --version byte-pinned. Help prose describes the shipped
    // product (embedded objects, linked loader, explicit-only
    // minting); any wording change re-pins here deliberately.
    const TOP_HELP: &str = r#"usage: memveil <record|report|top|doctor|qualify|bind-profile|help|version> [args]

Attempt/lifecycle/copy capture, live and offline summaries, passive host check. Verbs:
  record    capture bounce attempts and optional lifecycle/copy channels into a directory.
  report    read one capture and print metrics.
  top       observe live or replay one capture with periodic summaries.
  doctor    inspect the host passively and print capability.
  qualify   prove this host and mint a local-auto receipt.
  bind-profile mint a bound profile document for this host.
  help      print this text.
  version   print the engine version.

Run 'memveil record --help' for record options.
Run 'memveil report --help' for report options.
Run 'memveil top --help' for top options.
Run 'memveil doctor --help' for doctor options.
Run 'memveil qualify --help' for qualify options.
Run 'memveil bind-profile --help' for bind options.
"#;
    const HELP_VERB: &str = r#"usage: memveil <record|report|top|doctor|qualify|bind-profile|help|version> [args]

Attempt/lifecycle/copy capture, live and offline summaries, passive host check. Verbs:
  record    capture bounce attempts and optional lifecycle/copy channels into a directory.
  report    read one capture and print metrics.
  top       observe live or replay one capture with periodic summaries.
  doctor    inspect the host passively and print capability.
  qualify   prove this host and mint a local-auto receipt.
  bind-profile mint a bound profile document for this host.
  help      print this text.
  version   print the engine version.

Run 'memveil record --help' for record options.
Run 'memveil report --help' for report options.
Run 'memveil top --help' for top options.
Run 'memveil doctor --help' for doctor options.
Run 'memveil qualify --help' for qualify options.
Run 'memveil bind-profile --help' for bind options.
"#;
    const RECORD_HELP: &str = r#"usage: memveil record --output DIR [--object PATH]
       [--duration SEC] [--max-events-bytes N]
       [--bridge PATH] [--profile ID|PATH]
       [--profiles-dir DIR] [--capability IDS]
       [--lc-object PATH] [--cp-object PATH]
       [--device NAME] [--strict]

Capture swiotlb bounce attempts into DIR. SEC defaults
to 60; N defaults to 1073741824 (1 GiB, the replay
default) and must lie in 131072..4294967296; a larger
capture replays with the same --max-events-bytes.
Without --bridge, the statically linked loader runs
and bridge-bound receipt checks stay unverified: a
local-auto receipt that needs a bridge hash refuses
as bridge-unchecked. Without --object, --lc-object,
or --cp-object, each channel loads its embedded
object bytes; explicit paths win verbatim.
Without --profile, the first validated profile passing
full identity binding wins, then the first reference
profile whose receipt verifies, else the first covering
reference profile verifies its interfaces live; an
explicit --profile that fails binding (or the live
check) refuses. Diagnostics go to stderr.

--capability selects extra channels as a comma-separated
list without spaces (default: attempt-trace, which is
always required). mapping-lifecycle uses --lc-object
and copy-actual uses --cp-object when given, else the
embedded object for that channel; the winning profile
must declare each requested capability supported (or
candidate) and either bind the matching object bytes
or pass the live check, else the run refuses naming
the capability. Extra channels never run partial:
without full narrow binding or a passing live check
the run refuses.

--device NAME keeps only the bounce attempts whose
observed device name is exactly NAME (a literal
exact match: no glob, prefix, or case folding).
Lifecycle/copy records and global counters, pool
samples, and conversions are always retained, and
the selector is recorded in the session capture
filters with its dropped-attempt count.

--strict exits 4 unless the record verdict is complete.

Exit 0 for a finalized capture (including zero-event
and signal stops; completeness rides in the session
verdict), 4 under --strict unless the verdict is
complete, 3 when the run cannot start, 2 on
usage errors, 1 on error or unfinalizable output.
"#;
    const REPORT_HELP: &str = r#"usage: memveil report [--format text|json|markdown] [--allow-partial]
       [--strict] [--long-lived-after DURATION] [--max-line-bytes N]
       [--max-session-bytes N] [--max-events-bytes N] DIR

Read the capture in DIR, reduce its events to metrics,
and print one report on stdout. Diagnostics go to stderr.
Counts always cover the whole capture window.

  --format NAME     text (default), json, or markdown.
  --allow-partial   recover a verified checkpoint prefix, or
                    allow a truncated legacy final record.
  --strict          exit 4 unless the report verdict is
                    complete.
  --long-lived-after DURATION
                    enable the informational long-lived
                    finding past this open age. DURATION is
                    a decimal count with optional unit s,
                    m, or h (bare digits mean seconds).
  --max-line-bytes N
                    per-record cap, at most 65536.
  --max-session-bytes N
                    session file cap, at most 16777216.
  --max-events-bytes N
                    total work cap, at most 4294967296.

Exit 0 for a rendered report (completeness rides in the
verdict field), 4 under --strict unless the verdict is
complete, and 4 for checkpoint recovery. Invalid input or
usage exits 2; corrupt final captures are never recovered.
"#;
    const TOP_VERB_HELP: &str = r#"usage: memveil top [--interval DURATION] [--device NAME]
       [--strict] [--compact] [--long-lived-after DURATION]
       [--allow-partial] [--max-line-bytes N]
       [--max-session-bytes N] [--max-events-bytes N] DIR
   or: memveil top --output DIR [--object PATH]
       [--duration SEC] [--max-events-bytes N]
       [--bridge PATH] [--profile ID|PATH]
       [--profiles-dir DIR] [--capability IDS]
       [--lc-object PATH] [--cp-object PATH]
       [--interval DURATION] [--device NAME]
       [--strict] [--compact] [--long-lived-after DURATION]

Replay the capture in DIR, printing one text summary per
interval of capture time plus a final full-window report.
With --output, observe the live system instead, retaining
the capture in DIR while printing the same summaries.
Live collection resolves absent --bridge, --object,
--lc-object, and --cp-object paths as memveil record
does: embedded objects and the linked loader unless
explicit paths name files. Refreshes cover events in
consumption order; a disordered event below a printed
horizon reaches the final summary only, never a
revised refresh.
Diagnostics go to stderr.

  --interval DURATION
                    wall sleep between refreshes, default 1s.
  --device NAME     show only this device's per-device rows
                    (exact device id or catalog name);
                    analysis still covers the whole capture.
                    Blocks name the active filter; a filter
                    matching no device warns once.
  --long-lived-after DURATION
                    enable the informational long-lived
                    finding past this open age.
  --strict          exit 4 unless the final verdict is
                    complete (live mode also runs the
                    collection strictly).
  --compact         print the short verdict-plus-headlines
                    block instead of the full report per
                    refresh; cannot combine with --device.

DURATION is a decimal count with optional unit s, m, or h
(bare digits mean seconds); zero and overflow are refused.

Exit 0 for printed summaries (completeness rides in the
verdict field), 4 under --strict unless the verdict is
complete, 2 for invalid input or usage. Live mode
adds 3 for unavailable collection and 1 for errors.
"#;
    const DOCTOR_HELP: &str = r#"usage: memveil doctor [--json] [--profiles-dir DIR] [--capability LIST] [--object PATH] [--lc-object PATH] [--cp-object PATH] [--bridge PATH] [--load-check]

Judge every requested capability through record admission
and print one environment and capability report on stdout.
Diagnostics go to stderr. Exit 0 when the requested
capabilities are available, 3 when requested collection
is unavailable or unknown, 2 on usage or internal errors.
Profiles resolve from the executable location, never from
the caller's working directory.
Passive by default: no BPF load, no bridge access;
--load-check loads every requested object without attaching.

  --json            print the doctor-v0.1.1 JSON report.
  --profiles-dir DIR  profiles directory (default: executable-relative).
  --capability LIST   comma-separated capability ids, or all (default all).
  --object PATH       attempt channel object (default: embedded).
  --lc-object PATH    lifecycle channel object (default: embedded).
  --cp-object PATH    copy channel object (default: embedded).
  --bridge PATH       bridge file hashed into load-check receipt binding (default: linked loader).
  --load-check        load every requested object without attaching.
"#;
    const QUALIFY_HELP: &str = r#"usage: memveil qualify --output DIR [--object PATH]
       [--bridge PATH] [--profile ID|PATH]
       [--profiles-dir DIR] [--capability IDS]
       [--lc-object PATH] [--cp-object PATH]

Run a short smoke capture into DIR and, when it
proves the requested channels, publish a
machine-local local-auto receipt under
<profiles-dir>/receipts (/var/lib/memveil/receipts
for an installed package). --object and --bridge are
required explicit files: without --object the run
refuses before the smoke, and the receipt binds both
hashes. The smoke loads explicit files only, never
embedded bytes. The smoke attaches, polls, and
detaches once; an idle ring is honest success and
still qualifies.
Receipts never claim
validated. Diagnostics go to stderr.

--capability selects channels as a comma-separated
list without spaces (default: attempt-trace, which
is always required). mapping-lifecycle needs
--lc-object and copy-actual needs --cp-object when
those channels are wanted, else the run refuses
before the smoke.
"#;
    const BIND_HELP: &str = r#"usage: memveil bind-profile --output PATH [--profile ID|PATH]
       [--profiles-dir DIR] [--object PATH] [--lc-object PATH]
       [--cp-object PATH] [--capability LIST] [--profile-id ID]

Mint a bound reference-unvalidated profile document for
this host: hook definitions come from the covering
reference, identity bindings and tracepoint format text
are measured live. Register the minted file first in
the profiles manifest, then run qualify against it.
Format text and the kernel image need root reads; run
under sudo when they deny the current user.
Attempt-trace is the mandatory base channel; extra
channels bind together (both objects required) with
the canonical ring sizes, verified live at qualify.
Minted documents carry no BTF layouts: signature and
smoke checks still apply, layout pins do not.
--object is required: without it the run refuses.
Extra channels need --lc-object and --cp-object
together.
"#;
    const VERSION_OUT: &str = r#"memveil-0.1.1
"#;
    let cases: &[(&[&str], &str, i32)] = &[
        (&["--help"], TOP_HELP, 0),
        (&["help"], HELP_VERB, 0),
        (&["record", "--help"], RECORD_HELP, 0),
        (&["report", "--help"], REPORT_HELP, 0),
        (&["top", "--help"], TOP_VERB_HELP, 0),
        (&["doctor", "--help"], DOCTOR_HELP, 0),
        (&["qualify", "--help"], QUALIFY_HELP, 0),
        (&["bind-profile", "--help"], BIND_HELP, 0),
        (&["--version"], VERSION_OUT, 0),
    ];
    for (args, want, code) in cases {
        let out = run(&bin(), args);
        assert_eq!(out.status.code(), Some(*code), "{args:?} exit");
        assert!(out.stderr.is_empty(), "{args:?} stderr");
        assert_eq!(out.stdout, want.as_bytes(), "{args:?} stdout bytes");
    }
}

#[test]
fn report_bytes_equal_mojo_over_sealed() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: Mojo control retired at cutover");
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
        eprintln!("skip: Mojo control retired at cutover");
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
fn report_long_lived_bytes_equal_mojo() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: Mojo control retired at cutover");
        return;
    };
    let open = lifecycle("open-at-end");
    let nested = lifecycle("lifecycle-nested");
    let cases: Vec<(&Path, Vec<&str>)> = vec![
        (&open, vec!["--long-lived-after", "1s"]),
        (&nested, vec!["--long-lived-after", "1s"]),
    ];
    for (dir, extra) in cases {
        let ours = run_report(&bin(), &extra, dir);
        let want = run_report(&mojo, &extra, dir);
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
fn checkpoint_bytes_equal_mojo() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: Mojo control retired at cutover");
        return;
    };
    let dir = checkpoint_capture_dir("mojo");
    for extra in [vec![], vec!["--allow-partial"]] {
        let ours = run_report(&bin(), &extra, &dir);
        let want = run_report(&mojo, &extra, &dir);
        assert_eq!(
            ours.status.code(),
            want.status.code(),
            "report {extra:?} exit"
        );
        assert_eq!(ours.stdout, want.stdout, "report {extra:?} stdout bytes");
        assert_eq!(ours.stderr, want.stderr, "report {extra:?} stderr bytes");
    }
    let ours = run_top(&bin(), &["--allow-partial"], &dir);
    let want = run_top(&mojo, &["--allow-partial"], &dir);
    assert_eq!(ours.status.code(), want.status.code(), "top exit");
    assert_eq!(ours.stdout, want.stdout, "top stdout bytes");
    assert_eq!(ours.stderr, want.stderr, "top stderr bytes");
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
    // Live durations parse through the shared record parser: one
    // duration grammar everywhere, so the error matches report/top.
    let out = run(&bin(), &["top", "--output", live_str, "--duration", "nope"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("--duration DurationError(message=bad duration: nope)")
    );
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
        eprintln!("skip: Mojo control retired at cutover");
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
    assert_eq!(
        out.stderr,
        b"memveil doctor: unknown capability: nope; valid capabilities: attempt-trace, mapping-lifecycle, copy-actual, conversion-observe, conversion-journal, all\n"
    );
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
        eprintln!("skip: Mojo control retired at cutover");
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
    ] {
        let ours = run(&bin(), &args);
        let want = run(&mojo, &args);
        assert_eq!(ours.status.code(), want.status.code(), "{args:?} exit");
        assert_eq!(ours.stdout, want.stdout, "{args:?} stdout bytes");
        assert_eq!(ours.stderr, want.stderr, "{args:?} stderr bytes");
    }
    // The bind success path mints its output file, so it runs
    // against a temp dir: the shared path keeps both binaries
    // byte-comparable while the repo root stays clean.
    let bind_tmp = std::env::temp_dir().join(format!("memveil-cli-bind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&bind_tmp);
    std::fs::create_dir_all(&bind_tmp).expect("bind temp dir");
    let bind_out = bind_tmp.join("x").to_string_lossy().into_owned();
    let args = [
        "bind-profile",
        "--output",
        bind_out.as_str(),
        "--object",
        "tests/fixtures/elf/ok.o",
        "--profiles-dir",
        "profiles",
    ];
    let ours = run(&bin(), &args);
    let want = run(&mojo, &args);
    assert_eq!(ours.status.code(), want.status.code(), "{args:?} exit");
    assert_eq!(ours.stdout, want.stdout, "{args:?} stdout bytes");
    assert_eq!(ours.stderr, want.stderr, "{args:?} stderr bytes");
    assert!(
        !repo_root().join("x").exists(),
        "parity suite must not mint ./x"
    );
    let _ = std::fs::remove_dir_all(&bind_tmp);
}

#[test]
fn report_errors_equal_mojo() {
    let Some(mojo) = mojo_bin() else {
        eprintln!("skip: Mojo control retired at cutover");
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
