// SPDX-License-Identifier: GPL-3.0-or-later
//! memveil record: admitted attempt capture, optional channels.
//!
//! `run_record` implements `record --duration SEC --max-events-bytes
//! N --output DIR [--object PATH] [--bridge PATH] [--profile ID]
//! [--capability IDS] [--lc-object PATH] [--cp-object PATH]
//! [--device NAME] [--strict]` against
//! the live host. `run_record_with` is the same flow against an
//! explicit evidence root and profiles directory (plus an
//! optional literal `--device NAME` attempt selector), so
//! tests drive fixtures through the identical code path. Admission and
//! collection run through the shared collection service; this
//! module owns only record argument parsing, usage, dispatch, and
//! rendering.
//!
//! Exit codes: 0 = finalized (NORMAL including zero-event runs,
//! signal stops, and known-loss runs; completeness rides in the
//! session verdict); 4 = --strict run whose record verdict is not
//! complete; 3 = cannot start
//! (diagnostic, no residual directory); 2 = usage (fixable via
//! argv); 1 = error or unfinalizable. Only a broken standard
//! error escapes as a failure.

use crate::capture::collector::{EXIT_ERROR, EXIT_INVALID, EXIT_REFUSAL};
use crate::capture::live::LiveWriter;
use crate::capture::run::{RecordOptions, repair_warning_for, run_collector_with};
#[cfg(test)]
use crate::cli::doctor::default_profiles_dir;
use crate::cli::doctor::resolve_profiles_dir;
use crate::cli::report::{
    CliError, EXIT_INTERNAL, EXIT_OK, final_capture_summary, refusal_stderr_lines,
    sanitize_diagnostic, write_stderr, write_stderr_trusted,
};
use crate::platform::stdout::write_stdout;

/// Usage text for the record verb.
pub fn record_usage() -> String {
    concat!(
        "usage: memveil record --output DIR [--object PATH]\n",
        "       [--duration SEC] [--max-events-bytes N]\n",
        "       [--bridge PATH] [--profile ID|PATH]\n",
        "       [--profiles-dir DIR] [--capability IDS]\n",
        "       [--lc-object PATH] [--cp-object PATH]\n",
        "       [--device NAME] [--strict]\n",
        "\n",
        "Capture swiotlb bounce attempts into DIR. SEC defaults\n",
        "to 60; N defaults to 1073741824 (1 GiB, the replay\n",
        "default) and must lie in 131072..4294967296; a larger\n",
        "capture replays with the same --max-events-bytes.\n",
        "Without --bridge, the native bridge is discovered:\n",
        "LMB_NATIVE_LIB when unprivileged,\n",
        "then beside the executable, then the system path.\n",
        "Without --object, --lc-object, or --cp-object, each\n",
        "BPF object is discovered beside the executable or\n",
        "under the system directory, else the run refuses.\n",
        "Without --profile, the first validated profile passing\n",
        "full identity binding wins, then the first reference\n",
        "profile whose receipt verifies, else the first covering\n",
        "reference profile verifies its interfaces live; an\n",
        "explicit --profile that fails binding (or the live\n",
        "check) refuses. Diagnostics go to stderr.\n",
        "\n",
        "--capability selects extra channels as a comma-separated\n",
        "list without spaces (default: attempt-trace, which is\n",
        "always required). mapping-lifecycle uses --lc-object\n",
        "and copy-actual uses --cp-object when given, else the\n",
        "discovered object for that channel; the winning profile\n",
        "must declare each requested capability supported (or\n",
        "candidate) and either bind the matching object bytes\n",
        "or pass the live check, else the run refuses naming\n",
        "the capability. Extra channels never run partial:\n",
        "without full narrow binding or a passing live check\n",
        "the run refuses.\n",
        "\n",
        "--device NAME keeps only the bounce attempts whose\n",
        "observed device name is exactly NAME (a literal\n",
        "exact match: no glob, prefix, or case folding).\n",
        "Lifecycle/copy records and global counters, pool\n",
        "samples, and conversions are always retained, and\n",
        "the selector is recorded in the session capture\n",
        "filters with its dropped-attempt count.\n",
        "\n",
        "--strict exits 4 unless the record verdict is complete.\n",
        "\n",
        "Exit 0 for a finalized capture (including zero-event\n",
        "and signal stops; completeness rides in the session\n",
        "verdict), 4 under --strict unless the verdict is\n",
        "complete, 3 when the run cannot start, 2 on\n",
        "usage errors, 1 on error or unfinalizable output.\n",
    )
    .to_string()
}

fn is_option(text: &str) -> bool {
    text.as_bytes().first() == Some(&0x2d)
}

/// Strict decimal: no leading zeros, 1..2^64-1.
fn parse_decimal_u64(text: &str) -> Result<u64, CliError> {
    let raw = text.as_bytes();
    if raw.is_empty() || raw.len() > 20 {
        return Err(CliError {
            message: format!("bad decimal: {text}"),
        });
    }
    if raw[0] < 0x31 || raw[0] > 0x39 {
        return Err(CliError {
            message: format!("bad decimal: {text}"),
        });
    }
    let mut v: u64 = 0;
    for &b in raw {
        if !b.is_ascii_digit() {
            return Err(CliError {
                message: format!("bad decimal: {text}"),
            });
        }
        let d = u64::from(b - 0x30);
        if v > (u64::MAX - d) / 10 {
            return Err(CliError {
                message: format!("bad decimal: {text}"),
            });
        }
        v = v * 10 + d;
    }
    Ok(v)
}

/// Parse record arguments without the leading verb.
pub fn parse_record_args(args: &[String]) -> Result<RecordOptions, CliError> {
    let mut opts = RecordOptions::default();
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--duration" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--duration needs a value".to_string(),
                });
            }
            opts.duration_s = parse_decimal_u64(&args[i + 1])?;
            i += 2;
        } else if tok == "--max-events-bytes" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--max-events-bytes needs a value".to_string(),
                });
            }
            let v = parse_decimal_u64(&args[i + 1])?;
            if v > i64::MAX as u64 {
                return Err(CliError {
                    message: "--max-events-bytes too large".to_string(),
                });
            }
            opts.max_events_bytes = v;
            i += 2;
        } else if tok == "--output" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--output needs a value".to_string(),
                });
            }
            if args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--output needs a value".to_string(),
                });
            }
            opts.output = args[i + 1].clone();
            i += 2;
        } else if tok == "--object" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--object needs a value".to_string(),
                });
            }
            if args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--object needs a value".to_string(),
                });
            }
            opts.object = args[i + 1].clone();
            i += 2;
        } else if tok == "--bridge" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--bridge needs a value".to_string(),
                });
            }
            if args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--bridge needs a value".to_string(),
                });
            }
            opts.bridge = args[i + 1].clone();
            opts.has_bridge = true;
            i += 2;
        } else if tok == "--profile" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--profile needs a value".to_string(),
                });
            }
            if args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--profile needs a value".to_string(),
                });
            }
            opts.profile = args[i + 1].clone();
            opts.has_profile = true;
            i += 2;
        } else if tok == "--profiles-dir" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--profiles-dir needs a value".to_string(),
                });
            }
            if args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--profiles-dir needs a value".to_string(),
                });
            }
            opts.profiles_dir = args[i + 1].clone();
            opts.has_profiles_dir = true;
            i += 2;
        } else if tok == "--lc-object" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--lc-object needs a value".to_string(),
                });
            }
            if args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--lc-object needs a value".to_string(),
                });
            }
            opts.lc_object = args[i + 1].clone();
            i += 2;
        } else if tok == "--cp-object" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--cp-object needs a value".to_string(),
                });
            }
            if args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--cp-object needs a value".to_string(),
                });
            }
            opts.cp_object = args[i + 1].clone();
            i += 2;
        } else if tok == "--capability" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--capability needs a value".to_string(),
                });
            }
            if args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--capability needs a value".to_string(),
                });
            }
            opts.capabilities = args[i + 1].clone();
            i += 2;
        } else if tok == "--device" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--device needs a value".to_string(),
                });
            }
            if args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--device needs a value".to_string(),
                });
            }
            if args[i + 1].chars().count() > 256 {
                return Err(CliError {
                    message: "--device must be 1..256 characters".to_string(),
                });
            }
            opts.device = args[i + 1].clone();
            opts.has_device = true;
            i += 2;
        } else if tok == "--strict" {
            opts.strict = true;
            i += 1;
        } else if is_option(tok) {
            return Err(CliError {
                message: format!("unknown option: {tok}"),
            });
        } else {
            return Err(CliError {
                message: format!("unexpected argument: {tok}"),
            });
        }
    }
    if opts.output.is_empty() {
        return Err(CliError {
            message: "missing --output".to_string(),
        });
    }
    Ok(opts)
}

/// Report one cannot-start failure; return EXIT_REFUSAL.
fn record_failed(detail: &str) -> i64 {
    let line = format!("memveil record: {}\n", sanitize_diagnostic(detail));
    match write_stderr(&line) {
        Ok(()) => EXIT_REFUSAL,
        Err(_) => EXIT_INTERNAL,
    }
}

/// Report one usage failure; return EXIT_INVALID.
fn record_misused(detail: &str) -> i64 {
    let line = format!("memveil record: {}\n", sanitize_diagnostic(detail));
    match write_stderr(&line) {
        Ok(()) => EXIT_INVALID,
        Err(_) => EXIT_INTERNAL,
    }
}

/// One stdout summary line for a run that reached an end reason.
fn record_done_line(end_reason: &str, outcome: &str, exit_code: i64) -> String {
    format!("record: end={end_reason} outcome={outcome} exit={exit_code}")
}

/// Run the record flow against explicit roots; return exit code.
///
/// `root` is the evidence root ("" for the live host) and
/// `profiles_dir` holds `manifest.txt`. Absent bridge
/// and object paths are discovered (explicit user input
/// wins verbatim and is never root-joined). Refusals print
/// one diagnostic and exit 3 before any BPF or output
/// resource exists.
pub fn run_record_with(root: &str, profiles_dir: &str, opts: RecordOptions) -> i64 {
    let mut writer = LiveWriter::new();
    let output = opts.output.clone();
    let result = run_collector_with(root, profiles_dir, opts, &mut writer);
    if result.outcome == "finalized" {
        // A published capture lands root-owned under sudo;
        // hand it to the invoking user. Warn-only: the
        // capture stands whatever ownership repair does.
        let repair_line = repair_warning_for(&output, &writer);
        if !repair_line.is_empty() {
            let _ = write_stderr(&repair_line);
        }
    }
    if result.exit_code == EXIT_ERROR || result.exit_code == EXIT_REFUSAL {
        let lines = refusal_stderr_lines("record", &result.diagnostic, &result.code, &result.fix);
        // lines[0] is the diagnostic; only it can embed
        // caller paths, so only it honors the scrub flag.
        for (i, line) in lines.iter().enumerate() {
            if result.trusted || i > 0 {
                let _ = write_stderr_trusted(line);
            } else {
                let _ = write_stderr(line);
            }
        }
    }
    if result.end_reason.is_empty() {
        return result.exit_code;
    }
    let done = record_done_line(&result.end_reason, &result.outcome, result.exit_code);
    // Both outcomes have durably published the final session.
    if result.outcome == "finalized" || result.outcome == "error" {
        return final_capture_summary(&format!("{done}\n"), &output, result.exit_code);
    }
    match write_stdout(&format!("{done}\n")) {
        Ok(()) => result.exit_code,
        Err(_) => {
            let _ = write_stderr("memveil record: cannot write stdout\n");
            EXIT_ERROR
        }
    }
}

/// Run the record verb; return the process exit code.
///
/// `args` excludes the program name and the record word.
/// Profiles resolve from the kernel-resolved binary path,
/// never from argv[0] or the working directory.
pub fn run_record(args: &[String]) -> i64 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        match write_stdout(&record_usage()) {
            Ok(()) => return EXIT_OK,
            Err(_) => {
                let _ = write_stderr("memveil record: cannot write stdout\n");
                return EXIT_ERROR;
            }
        }
    }
    let opts = match parse_record_args(args) {
        Ok(opts) => opts,
        Err(e) => return record_misused(&e.message),
    };
    let profiles_dir = if opts.has_profiles_dir {
        opts.profiles_dir.clone()
    } else {
        match resolve_profiles_dir() {
            Ok(dir) => dir,
            Err(e) => {
                return record_failed(&format!("cannot resolve profiles location: {}", e.message));
            }
        }
    };
    run_record_with("", &profiles_dir, opts)
}

#[cfg(test)]
mod tests {
    use super::{default_profiles_dir, parse_record_args, record_done_line, record_usage};

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn base(extra: &[&str]) -> Vec<String> {
        let mut words = vec!["--output", "out", "--object", "obj.o"];
        words.extend(extra.iter());
        args(&words)
    }

    #[test]
    fn record_args_defaults() {
        let opts = parse_record_args(&base(&[])).expect("base parses");
        assert_eq!(opts.output, "out");
        assert_eq!(opts.object, "obj.o");
        assert_eq!(opts.lc_object, "");
        assert_eq!(opts.cp_object, "");
        assert_eq!(opts.capabilities, "");
        assert_eq!(opts.profiles_dir, "");
        assert!(!opts.has_profiles_dir);
        assert_eq!(opts.duration_s, 60);
        assert_eq!(opts.max_events_bytes, 1073741824);
        assert!(!opts.has_bridge);
        assert!(!opts.has_profile);
        assert_eq!(opts.device, "");
        assert!(!opts.has_device);
        assert!(!opts.strict);
    }

    #[test]
    fn record_args_profiles_dir() {
        let opts =
            parse_record_args(&base(&["--profiles-dir", "qd"])).expect("profiles dir parses");
        assert_eq!(opts.profiles_dir, "qd");
        assert!(opts.has_profiles_dir);
        let err = parse_record_args(&base(&["--profiles-dir", ""]))
            .expect_err("empty profiles dir rejects");
        assert_eq!(err.message, "--profiles-dir needs a value");
        let err = parse_record_args(&args(&["--output", "o", "--profiles-dir"]))
            .expect_err("missing value rejects");
        assert_eq!(err.message, "--profiles-dir needs a value");
    }

    #[test]
    fn record_args_channels() {
        let opts = parse_record_args(&base(&[
            "--lc-object",
            "lc.o",
            "--cp-object",
            "cp.o",
            "--capability",
            "attempt-trace,mapping-lifecycle,copy-actual",
        ]))
        .expect("channels parse");
        assert_eq!(opts.lc_object, "lc.o");
        assert_eq!(opts.cp_object, "cp.o");
        assert_eq!(
            opts.capabilities,
            "attempt-trace,mapping-lifecycle,copy-actual"
        );
        for flag in ["--lc-object", "--cp-object", "--capability"] {
            let err = parse_record_args(&base(&[flag, ""])).expect_err("empty value rejects");
            assert_eq!(err.message, format!("{flag} needs a value"));
        }
    }

    #[test]
    fn record_args_bridge_profile_object() {
        let opts = parse_record_args(&base(&[
            "--bridge",
            "br.so",
            "--profile",
            "prof",
            "--duration",
            "3600",
            "--strict",
        ]))
        .expect("bridge/profile parse");
        assert_eq!(opts.bridge, "br.so");
        assert!(opts.has_bridge);
        assert_eq!(opts.profile, "prof");
        assert!(opts.has_profile);
        assert_eq!(opts.duration_s, 3600);
        assert!(opts.strict);
        for flag in ["--object", "--bridge", "--profile", "--output"] {
            let err = parse_record_args(&base(&[flag, ""])).expect_err("empty rejects");
            assert_eq!(err.message, format!("{flag} needs a value"));
        }
    }

    #[test]
    fn record_args_object_optional() {
        let opts = parse_record_args(&args(&["--output", "out"])).expect("objectless parses");
        assert_eq!(opts.output, "out");
        assert_eq!(opts.object, "");
    }

    #[test]
    fn record_args_device() {
        let opts = parse_record_args(&base(&["--device", "0000:00:1f.2"])).expect("device parses");
        assert_eq!(opts.device, "0000:00:1f.2");
        assert!(opts.has_device);
        let plain = parse_record_args(&base(&[])).expect("base parses");
        assert_eq!(plain.device, "");
        assert!(!plain.has_device);
        let literal =
            parse_record_args(&base(&["--device", " dev*0? "])).expect("glob bytes stay literal");
        assert_eq!(literal.device, " dev*0? ");
    }

    #[test]
    fn record_args_device_length() {
        let err = parse_record_args(&base(&["--device", ""])).expect_err("empty rejects");
        assert_eq!(err.message, "--device needs a value");
        let long = "d".repeat(257);
        let err = parse_record_args(&base(&["--device", long.as_str()])).expect_err("257 rejects");
        assert_eq!(err.message, "--device must be 1..256 characters");
        let max = "d".repeat(256);
        let opts = parse_record_args(&base(&["--device", max.as_str()])).expect("256 parses");
        assert_eq!(opts.device, max);
        // The bound counts characters, not bytes.
        let wide = "é".repeat(256);
        assert_eq!(wide.chars().count(), 256);
        let opts =
            parse_record_args(&base(&["--device", wide.as_str()])).expect("256 wide chars parse");
        assert_eq!(opts.device, wide);
        let too_wide = "é".repeat(257);
        let err = parse_record_args(&base(&["--device", too_wide.as_str()]))
            .expect_err("257 wide chars reject");
        assert_eq!(err.message, "--device must be 1..256 characters");
    }

    #[test]
    fn record_args_duration_edges() {
        let opts = parse_record_args(&base(&["--duration", "7"])).expect("duration parses");
        assert_eq!(opts.duration_s, 7);
        for bad in ["0", "00", "abc", "12x", "18446744073709551616"] {
            let err =
                parse_record_args(&base(&["--duration", bad])).expect_err("bad duration rejects");
            assert_eq!(err.message, format!("bad decimal: {bad}"));
        }
        let err = parse_record_args(&args(&["--output", "o", "--duration"]))
            .expect_err("missing value rejects");
        assert_eq!(err.message, "--duration needs a value");
    }

    #[test]
    fn record_args_max_events_edges() {
        let opts =
            parse_record_args(&base(&["--max-events-bytes", "131072"])).expect("floor parses");
        assert_eq!(opts.max_events_bytes, 131072);
        let opts = parse_record_args(&base(&["--max-events-bytes", "9223372036854775807"]))
            .expect("i64max parses");
        assert_eq!(opts.max_events_bytes, 9223372036854775807);
        let err = parse_record_args(&base(&["--max-events-bytes", "9223372036854775808"]))
            .expect_err("past i64max rejects");
        assert_eq!(err.message, "--max-events-bytes too large");
        let err = parse_record_args(&base(&["--max-events-bytes", "0"])).expect_err("zero rejects");
        assert_eq!(err.message, "bad decimal: 0");
    }

    #[test]
    fn record_args_usage_failures() {
        let err = parse_record_args(&args(&[])).expect_err("empty rejects");
        assert_eq!(err.message, "missing --output");
        let err = parse_record_args(&args(&["--output", "o", "--bogus"]))
            .expect_err("unknown option rejects");
        assert_eq!(err.message, "unknown option: --bogus");
        let err =
            parse_record_args(&args(&["--output", "o", "stray"])).expect_err("positional rejects");
        assert_eq!(err.message, "unexpected argument: stray");
    }

    #[test]
    fn summary_line_shape() {
        assert_eq!(
            record_done_line("complete", "finalized", 0),
            "record: end=complete outcome=finalized exit=0"
        );
        assert_eq!(
            record_done_line("signal", "error", 1),
            "record: end=signal outcome=error exit=1"
        );
    }

    #[test]
    fn profiles_dir_vectors() {
        assert_eq!(default_profiles_dir("build/memveil"), "build/../profiles");
        assert_eq!(
            default_profiles_dir("/opt/mv/bin/memveil"),
            "/opt/mv/bin/../profiles"
        );
        assert_eq!(
            default_profiles_dir("/usr/bin/memveil"),
            "/usr/share/memveil/profiles"
        );
        assert_eq!(default_profiles_dir("memveil"), "profiles");
        assert_eq!(default_profiles_dir("/memveil"), "/../profiles");
    }

    #[test]
    fn record_usage_shape() {
        let text = record_usage();
        assert!(text.starts_with("usage: memveil record --output DIR [--object PATH]"));
        assert!(text.contains("[--object PATH]"));
        assert!(text.contains("discover"));
        assert!(text.contains("LMB_NATIVE_LIB"));
        assert!(text.contains("--device NAME"));
        assert!(text.contains("literal"));
        assert!(text.ends_with("usage errors, 1 on error or unfinalizable output.\n"));
    }
}
