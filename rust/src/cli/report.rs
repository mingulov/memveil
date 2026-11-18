// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline report command: read one capture, reduce, render, exit.
//!
//! The report verb wires the reader, the composed analyzer, and the
//! renderers into one offline pipeline. It never collects: no kernel,
//! device, or native-bridge import is needed to use it.
//!
//! Exit codes are exact: 0 means a valid finalized report was rendered,
//! 4 means checkpoint recovery or incomplete evidence under --strict,
//! and 2 means invalid input or usage. A rendering
//! failure on an accepted report is an internal error and exits 1.
//! An oversized render exits 2 via report_failed, mirroring invalid input.

use crate::analysis::diagnostics::diagnose_report;
use crate::analysis::engine::Analyzer;
use crate::capture::reader::{
    DEFAULT_MAX_EVENTS_BYTES, DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_SESSION_BYTES, ReaderLimits,
    read_capture,
};
use crate::cli::durations::parse_duration_ns;
use crate::model::report::{Report, apply_checkpoint, apply_integrity};
use crate::platform::stdout::write_stdout;
use crate::render::render::render;
use crate::render::text::escape_text;

/// Error exit, shared with the collector.
pub use crate::capture::collector::EXIT_ERROR;
/// Internal failure: rendering or output broke on accepted input.
pub use crate::capture::collector::EXIT_ERROR as EXIT_INTERNAL;
/// Invalid input or usage.
pub use crate::capture::collector::EXIT_INVALID;
/// Clean exit: a valid finalized report was rendered.
pub use crate::capture::collector::EXIT_OK;
/// Checkpoint recovery, or incomplete evidence under --strict.
pub use crate::capture::collector::EXIT_PARTIAL as EXIT_INCOMPLETE;
/// Refusal: collection, qualification, or minting cannot start.
pub use crate::capture::collector::EXIT_REFUSAL;
/// Largest report body ever printed (16 MiB).
pub const MAX_RENDERED_BYTES: usize = 16777216;

/// One command-line usage failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    /// Failure detail.
    pub message: String,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// One standard-error write failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StderrError {
    /// Failure detail, including the errno number.
    pub message: String,
}

impl std::fmt::Display for StderrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StderrError {}

/// Refuse to print a report larger than `limit` bytes.
pub fn check_rendered_size(text: &str, limit: usize) -> Result<(), CliError> {
    if text.len() > limit {
        return Err(CliError {
            message: "report exceeds size limit".to_string(),
        });
    }
    Ok(())
}

/// Parsed report arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportOptions {
    /// Output format: text, json, or markdown.
    pub format: String,
    /// Recover a verified checkpoint prefix or truncated legacy tail.
    pub allow_partial: bool,
    /// Exit 4 unless the report verdict is complete.
    pub strict: bool,
    /// True when --long-lived-after was passed.
    pub has_long_lived_after: bool,
    /// Informational long-lived finding threshold in nanoseconds.
    pub long_lived_after_ns: u64,
    /// Capture directory to read.
    pub dir: String,
    /// Per-record byte cap.
    pub max_line_bytes: usize,
    /// Session-file byte cap.
    pub max_session_bytes: usize,
    /// Total work byte cap.
    pub max_events_bytes: usize,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            format: "text".to_string(),
            allow_partial: false,
            strict: false,
            has_long_lived_after: false,
            long_lived_after_ns: 0,
            dir: String::new(),
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            max_session_bytes: DEFAULT_MAX_SESSION_BYTES,
            max_events_bytes: DEFAULT_MAX_EVENTS_BYTES,
        }
    }
}

/// Name only successfully retained output paths, escaping their control bytes.
pub fn write_capture_location(path: &str, receipt: &str) -> Result<(), StderrError> {
    let mut note = format!(
        "memveil: cannot write stdout; capture retained at {}",
        escape_text(path)
    );
    if !receipt.is_empty() {
        note.push_str("; receipt=");
        note.push_str(&escape_text(receipt));
    }
    note.push('\n');
    write_fd2(note.as_bytes())
}

/// A lost summary cannot undo a durable capture publication.
pub fn final_capture_summary(text: &str, path: &str, capture_exit: i64) -> i64 {
    if write_stdout(text).is_err() {
        let _ = write_capture_location(path, "");
    }
    capture_exit
}

/// Usage text for the report verb.
pub fn report_usage() -> String {
    concat!(
        "usage: memveil report [--format text|json|markdown] [--allow-partial]\n",
        "       [--strict] [--long-lived-after DURATION] [--max-line-bytes N]\n",
        "       [--max-session-bytes N] [--max-events-bytes N] DIR\n",
        "\n",
        "Read the capture in DIR, reduce its events to metrics,\n",
        "and print one report on stdout. Diagnostics go to stderr.\n",
        "Counts always cover the whole capture window.\n",
        "\n",
        "  --format NAME     text (default), json, or markdown.\n",
        "  --allow-partial   recover a verified checkpoint prefix, or\n",
        "                    allow a truncated legacy final record.\n",
        "  --strict          exit 4 unless the report verdict is\n",
        "                    complete.\n",
        "  --long-lived-after DURATION\n",
        "                    enable the informational long-lived\n",
        "                    finding past this open age. DURATION is\n",
        "                    a decimal count with optional unit s,\n",
        "                    m, or h (bare digits mean seconds).\n",
        "  --max-line-bytes N\n",
        "                    per-record cap, at most 65536.\n",
        "  --max-session-bytes N\n",
        "                    session file cap, at most 16777216.\n",
        "  --max-events-bytes N\n",
        "                    total work cap, at most 4294967296.\n",
        "\n",
        "Exit 0 for a rendered report (completeness rides in the\n",
        "verdict field), 4 under --strict unless the verdict is\n",
        "complete, and 4 for checkpoint recovery. Invalid input or\n",
        "usage exits 2; corrupt final captures are never recovered.\n",
    )
    .to_string()
}

/// Escape one untrusted fragment for a single-line diagnostic.
///
/// Newlines, tabs, and returns become literal backslash sequences
/// and other C0 bytes and DEL become U+FFFD, so hostile capture or
/// argument bytes can neither split log lines nor smuggle terminal
/// sequences into stderr. Printable text passes through untouched.
pub fn sanitize_diagnostic(frag: &str) -> String {
    escape_text(frag)
}

/// Strip control bytes from stderr text, keeping newlines.
///
/// Backstop for fixed multi-line diagnostics such as usage: C0
/// bytes other than newline and DEL become U+FFFD while newlines
/// survive, so the layout of trusted text is preserved.
pub fn neutralize_controls(text: &str) -> String {
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        if b == 0x0a {
            out.push(b);
        } else if b < 0x20 || b == 0x7f {
            out.extend_from_slice(&[0xef, 0xbf, 0xbd]);
        } else {
            out.push(b);
        }
    }
    // Only ASCII bytes are rewritten, so UTF-8 validity survives.
    String::from_utf8(out).expect("ascii-only rewrite keeps UTF-8 valid")
}

fn is_scrub_sep(b: u8) -> bool {
    b == 0x20 || b == 0x09 || b == 0x0a || b == 0x0d
}

/// Drop directory components from stderr diagnostics.
///
/// Every whitespace-delimited token keeps only the bytes after
/// its last slash, so loader messages, refused paths, and echoed
/// arguments cannot smuggle home directories or machine layout
/// into logs. Basenames survive as operational identifiers.
/// Adjacent slash tokens merge: a slash token followed past
/// whitespace by another slash token is dropped whole, so
/// middle components of spaced paths (including usernames)
/// never survive as bare words. The rule is deliberately
/// total: any slash token loses its head, so scrubbed lines
/// must not rely on slashes in prose.
pub fn scrub_paths(text: &str) -> String {
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if is_scrub_sep(raw[i]) {
            out.push(raw[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < raw.len() && !is_scrub_sep(raw[i]) {
            i += 1;
        }
        let mut has_slash = false;
        let mut cut = start;
        if let Some(rel) = raw[start..i].iter().rposition(|&b| b == 0x2f) {
            has_slash = true;
            cut = start + rel + 1;
        }
        if has_slash {
            // Peek past whitespace: a slash token there means
            // this token is a spaced path's head; drop it with
            // the gap so no middle component survives.
            let mut k = i;
            while k < raw.len() && is_scrub_sep(raw[k]) {
                k += 1;
            }
            let mut m = k;
            let mut next_slash = false;
            while m < raw.len() && !is_scrub_sep(raw[m]) {
                if raw[m] == 0x2f {
                    next_slash = true;
                    break;
                }
                m += 1;
            }
            if next_slash {
                i = k;
                continue;
            }
        }
        out.extend_from_slice(&raw[cut..i]);
    }
    // Cuts land only after ASCII slashes, so no codepoint splits.
    String::from_utf8(out).expect("slash-only cuts keep UTF-8 valid")
}

/// Refusal stderr lines: diagnostic, reason code, fix.
///
/// Every line carries its verb prefix and newline; the
/// code line appears only for a classified refusal, so
/// legacy selection diagnostics keep one line, and the
/// fix line only when a remedy applies. Fragments are
/// escaped; the write boundary decides scrubbing.
pub fn refusal_stderr_lines(verb: &str, diagnostic: &str, code: &str, fix: &str) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!(
        "memveil {verb}: {}\n",
        sanitize_diagnostic(diagnostic)
    ));
    if !code.is_empty() && code != "profile" {
        out.push(format!(
            "memveil {verb}: code: {}\n",
            sanitize_diagnostic(code)
        ));
    }
    if !fix.is_empty() {
        out.push(format!(
            "memveil {verb}: fix: {}\n",
            sanitize_diagnostic(fix)
        ));
    }
    out
}

/// Raw write(2) on fd 2 with an EINTR retry loop.
fn write_fd2(raw: &[u8]) -> Result<(), StderrError> {
    let total = raw.len();
    let mut off = 0;
    while off < total {
        // SAFETY: fd 2 with a live caller buffer; len counts down
        // from total so the pointer range stays inside `raw`.
        let n =
            unsafe { libc::write(2, raw.as_ptr().cast::<libc::c_void>().add(off), total - off) };
        if n < 0 {
            // SAFETY: errno read on the calling thread right after write.
            let no = unsafe { *libc::__errno_location() };
            if no == libc::EINTR {
                continue;
            }
            return Err(StderrError {
                message: format!("stderr write failed: errno {no}"),
            });
        }
        if n == 0 {
            return Err(StderrError {
                message: "stderr write returned 0".to_string(),
            });
        }
        off += n as usize;
    }
    Ok(())
}

/// Write text to standard error.
///
/// The diagnostic follows the inherited descriptor, never
/// the /dev/stderr path, so environments that rebind that
/// path away from fd 2 cannot swallow it. Control bytes
/// are neutralized and directory components scrubbed at
/// this boundary so no present or future diagnostic can
/// emit raw terminal sequences or filesystem layout. Use
/// it for lines that may embed caller-supplied paths.
pub fn write_stderr(text: &str) -> Result<(), StderrError> {
    write_fd2(neutralize_controls(&scrub_paths(text)).as_bytes())
}

/// Write fixed text to standard error, keeping paths.
///
/// Same fd-2 write, but only control bytes are
/// neutralized: fixed reason, code, and remedy lines
/// keep their paths and commands intact. Callers must
/// never pass caller-supplied paths here.
pub fn write_stderr_trusted(text: &str) -> Result<(), StderrError> {
    write_fd2(neutralize_controls(text).as_bytes())
}

fn is_option(text: &str) -> bool {
    text.as_bytes().first() == Some(&0x2d)
}

/// Strict decimal limit: 1..cap, no leading zeros.
pub(crate) fn parse_limit(text: &str, what: &str, cap: u64) -> Result<usize, CliError> {
    let raw = text.as_bytes();
    if raw.is_empty() || raw.len() > 10 {
        return Err(CliError {
            message: format!("{what} needs a decimal value"),
        });
    }
    if raw[0] < 0x31 || raw[0] > 0x39 {
        return Err(CliError {
            message: format!("{what} needs a decimal value"),
        });
    }
    // Ten digits fit u64 with room; the cap check below decides.
    let mut v: u64 = 0;
    for &b in raw {
        if !b.is_ascii_digit() {
            return Err(CliError {
                message: format!("{what} needs a decimal value"),
            });
        }
        v = v * 10 + u64::from(b - 0x30);
    }
    if v > cap {
        return Err(CliError {
            message: format!("{what} above cap"),
        });
    }
    Ok(v as usize)
}

/// Parse report arguments without the leading verb.
pub fn parse_report_args(args: &[String]) -> Result<ReportOptions, CliError> {
    let mut opts = ReportOptions::default();
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--format" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--format needs a value".to_string(),
                });
            }
            let v = args[i + 1].as_str();
            if v != "text" && v != "json" && v != "markdown" {
                return Err(CliError {
                    message: format!("unknown format: {v}"),
                });
            }
            opts.format = v.to_string();
            i += 2;
        } else if tok == "--allow-partial" {
            opts.allow_partial = true;
            i += 1;
        } else if tok == "--strict" {
            opts.strict = true;
            i += 1;
        } else if tok == "--long-lived-after" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--long-lived-after needs a value".to_string(),
                });
            }
            match parse_duration_ns(&args[i + 1]) {
                Ok(ns) => opts.long_lived_after_ns = ns,
                Err(e) => {
                    return Err(CliError {
                        message: format!("--long-lived-after {e}"),
                    });
                }
            }
            opts.has_long_lived_after = true;
            i += 2;
        } else if tok == "--max-line-bytes" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--max-line-bytes needs a value".to_string(),
                });
            }
            opts.max_line_bytes = parse_limit(&args[i + 1], "--max-line-bytes", 65536)?;
            i += 2;
        } else if tok == "--max-session-bytes" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--max-session-bytes needs a value".to_string(),
                });
            }
            opts.max_session_bytes = parse_limit(&args[i + 1], "--max-session-bytes", 16777216)?;
            i += 2;
        } else if tok == "--max-events-bytes" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--max-events-bytes needs a value".to_string(),
                });
            }
            opts.max_events_bytes = parse_limit(&args[i + 1], "--max-events-bytes", 4294967296)?;
            i += 2;
        } else if is_option(tok) {
            return Err(CliError {
                message: format!("unknown option: {tok}"),
            });
        } else {
            if !opts.dir.is_empty() {
                return Err(CliError {
                    message: "too many arguments".to_string(),
                });
            }
            opts.dir = tok.to_string();
            i += 1;
        }
    }
    if opts.dir.is_empty() {
        return Err(CliError {
            message: "missing capture directory".to_string(),
        });
    }
    Ok(opts)
}

/// Map the report verdict to the process exit code.
///
/// A rendered report is valid no matter what it records, so the
/// normal exit is 0 and completeness rides in the verdict field.
/// Findings and withheld aggregates stay advisory: they never gate
/// the exit. Under --strict only a complete verdict keeps 0; any
/// other verdict (or an unset one) exits 4.
pub fn exit_for_report(rep: &Report, strict: bool) -> i64 {
    if !strict {
        return EXIT_OK;
    }
    if rep.verdict.name == "complete" {
        return EXIT_OK;
    }
    EXIT_INCOMPLETE
}

/// Render a finish-path failure the way the Mojo `String(e)` does.
///
/// The reducer raises a typed analysis error whose default
/// rendering is `AnalysisError(message=...)`; the detail rides
/// through unchanged.
pub(crate) fn analysis_error_text(message: &str) -> String {
    format!("AnalysisError(message={message})")
}

fn report_failed(prefix: &str, detail: &str) -> i64 {
    let line = format!("{prefix}{}\n", sanitize_diagnostic(detail));
    match write_stderr(&line) {
        Ok(()) => EXIT_INVALID,
        Err(_) => EXIT_INTERNAL,
    }
}

/// Run the report verb; return the process exit code.
///
/// `args` excludes the program name and the report word. The rendered
/// report goes to stdout and nothing else does; every diagnostic
/// goes to stderr. A broken standard error maps to exit 1.
pub fn run_report(args: &[String]) -> i64 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        match write_stdout(&report_usage()) {
            Ok(()) => return EXIT_OK,
            Err(_) => {
                let _ = write_stderr("memveil report: cannot write stdout\n");
                return EXIT_INTERNAL;
            }
        }
    }
    let opts = match parse_report_args(args) {
        Ok(opts) => opts,
        Err(e) => return report_failed("memveil report: ", &e.message),
    };
    let mut reader = match read_capture(
        &opts.dir,
        opts.allow_partial,
        ReaderLimits {
            max_session_bytes: opts.max_session_bytes,
            max_line_bytes: opts.max_line_bytes,
            max_events_bytes: opts.max_events_bytes,
        },
    ) {
        Ok(reader) => reader,
        Err(e) => return report_failed("memveil report: cannot read capture: ", &e.message),
    };
    let mut analyzer = Analyzer::new(reader.session.clone());
    loop {
        let more = match reader.has_more() {
            Ok(more) => more,
            Err(e) => {
                return report_failed("memveil report: cannot read capture: ", &e.message);
            }
        };
        if !more {
            break;
        }
        let ev = match reader.next_event() {
            Ok(ev) => ev,
            Err(e) => {
                return report_failed("memveil report: cannot read capture: ", &e.message);
            }
        };
        if let Err(e) = analyzer.consume(&ev) {
            return report_failed("memveil report: cannot reduce capture: ", &e.message);
        }
    }
    let mut rep = match analyzer.finish(reader.session.window_end_ns, reader.partial) {
        Ok(rep) => rep,
        Err(e) => {
            return report_failed("memveil report: ", &analysis_error_text(&e.message));
        }
    };
    apply_integrity(
        &mut rep,
        reader.integrity_verified,
        reader.session.integrity.events_bytes,
        reader.session.integrity.line_count,
    );
    if reader.checkpoint_prefix {
        apply_checkpoint(
            &mut rep,
            reader.session.integrity.events_bytes,
            reader.session.integrity.line_count,
            reader.unverified_bytes,
        );
    }
    diagnose_report(
        &mut rep,
        opts.has_long_lived_after,
        opts.long_lived_after_ns,
    );
    let text = match render(&rep, &opts.format, "") {
        Ok(text) => text,
        Err(_) => {
            let _ = write_stderr("memveil report: internal error: cannot render report\n");
            return EXIT_INTERNAL;
        }
    };
    if let Err(e) = check_rendered_size(&text, MAX_RENDERED_BYTES) {
        return report_failed("memveil report: ", &e.message);
    }
    if write_stdout(&text).is_err() {
        let _ = write_stderr("memveil report: cannot write stdout\n");
        return EXIT_INTERNAL;
    }
    let raw = text.as_bytes();
    if (raw.is_empty() || raw[raw.len() - 1] != 0x0a) && write_stdout("\n").is_err() {
        let _ = write_stderr("memveil report: cannot write stdout\n");
        return EXIT_INTERNAL;
    }
    if reader.checkpoint_prefix {
        return EXIT_INCOMPLETE;
    }
    exit_for_report(&rep, opts.strict)
}

#[cfg(test)]
mod tests {
    use super::{
        EXIT_INCOMPLETE, EXIT_INVALID, EXIT_OK, MAX_RENDERED_BYTES, ReportOptions,
        check_rendered_size, exit_for_report, neutralize_controls, parse_report_args,
        refusal_stderr_lines, report_failed, report_usage, sanitize_diagnostic, scrub_paths,
    };
    use crate::model::report::Report;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn report_defaults() {
        let opts = parse_report_args(&args(&["capdir"])).expect("dir parses");
        assert_eq!(opts.format, "text");
        assert!(!opts.allow_partial);
        assert!(!opts.strict);
        assert!(!opts.has_long_lived_after);
        assert_eq!(opts.dir, "capdir");
        assert_eq!(opts.max_line_bytes, 65536);
        assert_eq!(opts.max_session_bytes, 16777216);
        assert_eq!(opts.max_events_bytes, 1073741824);
        let fresh = ReportOptions::default();
        assert_eq!(fresh.format, "text");
        assert_eq!(fresh.max_events_bytes, 1073741824);
    }

    #[test]
    fn report_all_flags() {
        let opts = parse_report_args(&args(&[
            "--format",
            "json",
            "--allow-partial",
            "--strict",
            "--long-lived-after",
            "90",
            "--max-line-bytes",
            "1024",
            "--max-session-bytes",
            "2048",
            "--max-events-bytes",
            "4096",
            "capdir",
        ]))
        .expect("full flags parse");
        assert_eq!(opts.format, "json");
        assert!(opts.allow_partial);
        assert!(opts.strict);
        assert!(opts.has_long_lived_after);
        assert_eq!(opts.long_lived_after_ns, 90_000_000_000);
        assert_eq!(opts.dir, "capdir");
        assert_eq!(opts.max_line_bytes, 1024);
        assert_eq!(opts.max_session_bytes, 2048);
        assert_eq!(opts.max_events_bytes, 4096);
    }

    #[test]
    fn report_long_lived_units() {
        let opts =
            parse_report_args(&args(&["--long-lived-after", "2m", "d"])).expect("minutes parse");
        assert!(opts.has_long_lived_after);
        assert_eq!(opts.long_lived_after_ns, 120_000_000_000);
    }

    #[test]
    fn report_missing_dir() {
        let err = parse_report_args(&args(&[])).expect_err("empty rejects");
        assert_eq!(err.message, "missing capture directory");
    }

    #[test]
    fn report_too_many_positionals() {
        let err = parse_report_args(&args(&["a", "b"])).expect_err("two dirs reject");
        assert_eq!(err.message, "too many arguments");
    }

    #[test]
    fn report_unknown_option() {
        for tok in ["--bogus", "-x", "-"] {
            let err = parse_report_args(&args(&[tok, "d"])).expect_err("unknown rejects");
            assert_eq!(err.message, format!("unknown option: {tok}"));
        }
    }

    #[test]
    fn report_format_edges() {
        for fmt in ["text", "json", "markdown"] {
            let opts = parse_report_args(&args(&["--format", fmt, "d"])).expect("format parses");
            assert_eq!(opts.format, fmt);
        }
        let err = parse_report_args(&args(&["--format", "yaml", "d"])).expect_err("yaml rejects");
        assert_eq!(err.message, "unknown format: yaml");
        let err = parse_report_args(&args(&["--format"])).expect_err("missing value rejects");
        assert_eq!(err.message, "--format needs a value");
    }

    #[test]
    fn report_long_lived_bad_duration() {
        let err = parse_report_args(&args(&["--long-lived-after", "bogus", "d"]))
            .expect_err("bogus duration rejects");
        assert_eq!(
            err.message,
            "--long-lived-after DurationError(message=bad duration: bogus)"
        );
        let err =
            parse_report_args(&args(&["--long-lived-after"])).expect_err("missing value rejects");
        assert_eq!(err.message, "--long-lived-after needs a value");
    }

    #[test]
    fn report_limit_edges() {
        // At-cap values pass; one past the cap fails.
        let opts =
            parse_report_args(&args(&["--max-line-bytes", "65536", "d"])).expect("line cap parses");
        assert_eq!(opts.max_line_bytes, 65536);
        let err = parse_report_args(&args(&["--max-line-bytes", "65537", "d"]))
            .expect_err("over line cap rejects");
        assert_eq!(err.message, "--max-line-bytes above cap");
        let opts = parse_report_args(&args(&["--max-session-bytes", "16777216", "d"]))
            .expect("session cap parses");
        assert_eq!(opts.max_session_bytes, 16777216);
        let err = parse_report_args(&args(&["--max-session-bytes", "16777217", "d"]))
            .expect_err("over session cap rejects");
        assert_eq!(err.message, "--max-session-bytes above cap");
        let opts = parse_report_args(&args(&["--max-events-bytes", "4294967296", "d"]))
            .expect("events cap parses");
        assert_eq!(opts.max_events_bytes, 4294967296);
        let err = parse_report_args(&args(&["--max-events-bytes", "4294967297", "d"]))
            .expect_err("over events cap rejects");
        assert_eq!(err.message, "--max-events-bytes above cap");
    }

    #[test]
    fn report_limit_bad_decimals() {
        for bad in ["0", "00", "064", "abc", "12x", "", "99999999999"] {
            let err = parse_report_args(&args(&["--max-line-bytes", bad, "d"]))
                .expect_err("bad decimal rejects");
            assert_eq!(err.message, "--max-line-bytes needs a decimal value");
        }
        let err =
            parse_report_args(&args(&["--max-line-bytes"])).expect_err("missing value rejects");
        assert_eq!(err.message, "--max-line-bytes needs a value");
    }

    #[test]
    fn strict_exit_matrix() {
        let mut complete = Report::default();
        complete.verdict.name = "complete".to_string();
        assert_eq!(exit_for_report(&complete, true), 0);
        assert_eq!(exit_for_report(&complete, false), 0);
        let mut partial = Report::default();
        partial.verdict.name = "partial_unknown_loss".to_string();
        assert_eq!(exit_for_report(&partial, true), EXIT_INCOMPLETE);
        assert_eq!(exit_for_report(&partial, false), EXIT_OK);
        let unset = Report::default();
        assert_eq!(unset.verdict.name, "");
        assert_eq!(exit_for_report(&unset, true), EXIT_INCOMPLETE);
        assert_eq!(exit_for_report(&unset, false), EXIT_OK);
        assert_eq!(EXIT_INVALID, 2);
    }

    #[test]
    fn rendered_size_limit() {
        check_rendered_size("tiny", 100).expect("tiny passes");
        check_rendered_size("exact", 5).expect("at-limit passes");
        let err = check_rendered_size("too big", 4).expect_err("over-limit rejects");
        assert_eq!(err.message, "report exceeds size limit");
        assert_eq!(MAX_RENDERED_BYTES, 16777216);
    }

    #[test]
    fn oversize_failure_exits_invalid() {
        // The oversized-render branch delegates to report_failed,
        // so a body past the cap exits 2 with the Mojo stderr
        // line. The descriptor write is process-global, so the
        // write runs in a re-executed child: the parent only
        // checks the child's exit status and captured stderr,
        // and parallel harness output in the parent never
        // observes the line.
        if std::env::var("MEMVEIL_OVERSIZE_EXIT_CHILD").is_ok() {
            let code = report_failed("memveil report: ", "report exceeds size limit");
            std::process::exit(code as i32);
        }
        let exe = std::env::current_exe().expect("test binary path resolves");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("cli::report::tests::oversize_failure_exits_invalid")
            .arg("--nocapture")
            .env("MEMVEIL_OVERSIZE_EXIT_CHILD", "1")
            .output()
            .expect("child re-exec runs");
        assert_eq!(out.status.code(), Some(EXIT_INVALID as i32));
        assert_eq!(out.stderr, b"memveil report: report exceeds size limit\n");
    }

    #[test]
    fn scrub_paths_vectors() {
        assert_eq!(
            scrub_paths("/nonexistent-bridge-dir/nolib.so: cannot open shared object file"),
            "nolib.so: cannot open shared object file"
        );
        assert_eq!(scrub_paths("~/lib/x.so failed"), "x.so failed");
        assert_eq!(scrub_paths("/opt/my dir/x.so: bad"), "x.so: bad");
        assert_eq!(scrub_paths("/home/user name/x.so: bad"), "x.so: bad");
        assert_eq!(scrub_paths("a/b c/d"), "d");
        assert_eq!(scrub_paths("open /a/b then /c/d"), "open b then d");
        assert_eq!(
            scrub_paths("op=open domain=bridge code=2: ok"),
            "op=open domain=bridge code=2: ok"
        );
        assert_eq!(scrub_paths(""), "");
        assert_eq!(scrub_paths("/"), "");
        assert_eq!(scrub_paths("reads/writes"), "writes");
    }

    #[test]
    fn refusal_lines_vectors() {
        let full = refusal_stderr_lines(
            "record",
            "tracefs denied (privilege): /sys/kernel/tracing/events",
            "tracefs-denied",
            "run as root",
        );
        assert_eq!(full.len(), 3);
        assert_eq!(
            full[0],
            "memveil record: tracefs denied (privilege): /sys/kernel/tracing/events\n"
        );
        assert_eq!(full[1], "memveil record: code: tracefs-denied\n");
        assert_eq!(full[2], "memveil record: fix: run as root\n");
        let legacy = refusal_stderr_lines("top", "no profile satisfies", "profile", "");
        assert_eq!(
            legacy,
            vec!["memveil top: no profile satisfies\n".to_string()]
        );
        let plain = refusal_stderr_lines("record", "budget 1 below 131072", "", "");
        assert_eq!(plain.len(), 1);
    }

    #[test]
    fn sanitize_and_neutralize_vectors() {
        let clean = sanitize_diagnostic("opt \u{1b}[2J\nnext\u{7f} é");
        assert!(!clean.as_bytes().contains(&0x1b));
        assert!(clean.contains("\\n"));
        assert!(clean.contains('é'));
        let kept = neutralize_controls("usage:\n  memveil \u{1b} report\n");
        assert!(kept.contains("usage:\n  memveil "));
        assert!(!kept.as_bytes().contains(&0x1b));
        assert!(kept.contains('\u{fffd}'));
        for b in kept.as_bytes() {
            assert!(*b == 0x0a || *b == 0x5c || *b >= 0x20);
        }
    }

    #[test]
    fn report_usage_shape() {
        let text = report_usage();
        assert!(text.starts_with("usage: memveil report [--format text|json|markdown]"));
        assert!(text.contains("--long-lived-after DURATION"));
        assert!(text.contains("at most 4294967296"));
        assert!(text.contains("Exit 0 for a rendered report"));
        assert!(text.ends_with("never recovered.\n"));
    }
}
