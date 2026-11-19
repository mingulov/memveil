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
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

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
    parse_limit_bytes(text.as_bytes(), what, cap)
}

/// Byte-wise [`parse_limit`]: non-UTF-8 values fail exactly like
/// ASCII garbage, because the decimal grammar never echoes its
/// input (Mojo parses argv bytes the same way).
fn parse_limit_bytes(raw: &[u8], what: &str, cap: u64) -> Result<usize, CliError> {
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

/// Raw parse failure: a printable usage error, or silence.
///
/// `Silent` mirrors Mojo's escape-time raise: the diagnostic
/// would embed non-UTF-8 bytes, so the run exits 1 printing
/// nothing instead of lossy-decoding a misleading path.
#[derive(Debug)]
enum OsParseFail {
    /// Emit through `report_failed` (exit 2).
    Message(CliError),
    /// Exit 1 with no output.
    Silent,
}

/// Byte-wise [`parse_report_args`] over raw argv words.
///
/// Flags compare as bytes, values that never echo (`--max-*`)
/// parse as bytes, and values the diagnostics would echo
/// (`--format`, `--long-lived-after`, unknown options) silence
/// the run when they cannot decode. Returns the capture
/// directory positional; the remaining options are validated
/// for error precedence but unused, because the raw path only
/// ever probes the directory.
fn parse_report_args_os(args: &[OsString]) -> Result<OsString, OsParseFail> {
    let mut dir_os = OsString::new();
    let mut has_dir = false;
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_bytes();
        if tok == b"--format" {
            if i + 1 >= args.len() {
                return Err(OsParseFail::Message(CliError {
                    message: "--format needs a value".to_string(),
                }));
            }
            match args[i + 1].to_str() {
                Some(v) if v == "text" || v == "json" || v == "markdown" => {}
                Some(v) => {
                    return Err(OsParseFail::Message(CliError {
                        message: format!("unknown format: {v}"),
                    }));
                }
                // The refusal echoes the value, which cannot decode.
                None => return Err(OsParseFail::Silent),
            }
            i += 2;
        } else if tok == b"--allow-partial" || tok == b"--strict" {
            i += 1;
        } else if tok == b"--long-lived-after" {
            if i + 1 >= args.len() {
                return Err(OsParseFail::Message(CliError {
                    message: "--long-lived-after needs a value".to_string(),
                }));
            }
            let Some(text) = args[i + 1].to_str() else {
                // The duration refusal echoes its input.
                return Err(OsParseFail::Silent);
            };
            match parse_duration_ns(text) {
                Ok(_) => {}
                Err(e) => {
                    return Err(OsParseFail::Message(CliError {
                        message: format!("--long-lived-after {e}"),
                    }));
                }
            }
            i += 2;
        } else if tok == b"--max-line-bytes" {
            if i + 1 >= args.len() {
                return Err(OsParseFail::Message(CliError {
                    message: "--max-line-bytes needs a value".to_string(),
                }));
            }
            match parse_limit_bytes(args[i + 1].as_bytes(), "--max-line-bytes", 65536) {
                Ok(_) => {}
                Err(e) => return Err(OsParseFail::Message(e)),
            }
            i += 2;
        } else if tok == b"--max-session-bytes" {
            if i + 1 >= args.len() {
                return Err(OsParseFail::Message(CliError {
                    message: "--max-session-bytes needs a value".to_string(),
                }));
            }
            match parse_limit_bytes(args[i + 1].as_bytes(), "--max-session-bytes", 16777216) {
                Ok(_) => {}
                Err(e) => return Err(OsParseFail::Message(e)),
            }
            i += 2;
        } else if tok == b"--max-events-bytes" {
            if i + 1 >= args.len() {
                return Err(OsParseFail::Message(CliError {
                    message: "--max-events-bytes needs a value".to_string(),
                }));
            }
            match parse_limit_bytes(args[i + 1].as_bytes(), "--max-events-bytes", 4294967296) {
                Ok(_) => {}
                Err(e) => return Err(OsParseFail::Message(e)),
            }
            i += 2;
        } else if tok.first() == Some(&0x2d) {
            match args[i].to_str() {
                Some(text) => {
                    return Err(OsParseFail::Message(CliError {
                        message: format!("unknown option: {text}"),
                    }));
                }
                // The refusal echoes the token, which cannot decode.
                None => return Err(OsParseFail::Silent),
            }
        } else {
            if has_dir {
                return Err(OsParseFail::Message(CliError {
                    message: "too many arguments".to_string(),
                }));
            }
            dir_os = args[i].clone();
            has_dir = true;
            i += 1;
        }
    }
    if !has_dir {
        return Err(OsParseFail::Message(CliError {
            message: "missing capture directory".to_string(),
        }));
    }
    Ok(dir_os)
}

/// Probe a non-UTF-8 capture directory the way [`read_capture`]
/// opens it, and return the cannot-read detail to emit.
///
/// The probe replays the reader's open sequence with the raw
/// bytes — final-session probe, component-wise directory walk,
/// lock, ownership, member opens, final-absence recheck — so a
/// path the reader would refuse fails here with the reader's
/// exact message. A directory that fully opens is still refused
/// closed: the String-based reader cannot consume non-UTF-8
/// paths, and lossy-decoding would risk opening a wrong
/// U+FFFD-named directory.
fn probe_capture_dir_os(dir: &OsStr) -> String {
    let raw = dir.as_bytes();
    if raw.contains(&0) {
        return "NUL byte in path".to_string();
    }
    // Final-session probe, mirroring read_capture: present means
    // the finalized path, absent means recovery, any other errno
    // refuses.
    let mut session_path = raw.to_vec();
    session_path.extend_from_slice(b"/session.json");
    let session_c = [session_path.as_slice(), b"\0"].concat();
    // SAFETY: NUL-terminated probe path on AT_FDCWD.
    let probe = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            session_c.as_ptr().cast::<libc::c_char>(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0 as libc::c_uint,
        )
    };
    if probe >= 0 {
        // SAFETY: owned probe fd.
        unsafe {
            libc::close(probe);
        }
        // The finalized capture opens: the reader would read on,
        // which raw bytes cannot follow — refuse closed.
        return "capture directory is inaccessible or a symlink".to_string();
    }
    if std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != libc::ENOENT {
        return "cannot establish final session absence".to_string();
    }
    // Component-wise walk, mirroring open_directory: never a
    // symlink, empty and dot components skipped.
    let root_c: &[u8] = if raw.starts_with(b"/") {
        b"/\0"
    } else {
        b".\0"
    };
    // SAFETY: NUL-terminated root on AT_FDCWD.
    let mut fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            root_c.as_ptr().cast::<libc::c_char>(),
            libc::O_DIRECTORY | libc::O_CLOEXEC,
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        return "cannot open capture parent".to_string();
    }
    let mut failed = false;
    for part in raw.split(|b| *b == b'/') {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part.contains(&0) {
            // SAFETY: owned dir fd.
            unsafe {
                libc::close(fd);
            }
            return "NUL in capture path".to_string();
        }
        let name_c = [part, b"\0"].concat();
        // SAFETY: NUL-terminated component on a live dir fd.
        let next = unsafe {
            libc::openat(
                fd,
                name_c.as_ptr().cast::<libc::c_char>(),
                libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0 as libc::c_uint,
            )
        };
        // SAFETY: owned dir fd.
        unsafe {
            libc::close(fd);
        }
        if next < 0 {
            failed = true;
            fd = -1;
            break;
        }
        fd = next;
    }
    if failed {
        return "capture directory is inaccessible or a symlink".to_string();
    }
    // SAFETY: live directory fd.
    let locked = unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) };
    if locked != 0 {
        // SAFETY: owned dir fd.
        unsafe {
            libc::close(fd);
        }
        return "active writer or unavailable capture lock".to_string();
    }
    // SAFETY: zeroed stat outlives the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        // SAFETY: owned dir fd.
        unsafe {
            libc::close(fd);
        }
        return "capture stat failed".to_string();
    }
    // SAFETY: pure id query.
    let euid = unsafe { libc::geteuid() as u64 };
    if st.st_uid as u64 != euid {
        // SAFETY: owned dir fd.
        unsafe {
            libc::close(fd);
        }
        return "capture directory not owned by reader".to_string();
    }
    for name in [b"checkpoint.json".as_slice(), b"events.ndjson".as_slice()] {
        let name_c = [name, b"\0"].concat();
        // SAFETY: NUL-terminated name on the live directory fd.
        let mfd = unsafe {
            libc::openat(
                fd,
                name_c.as_ptr().cast::<libc::c_char>(),
                libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0 as libc::c_uint,
            )
        };
        if mfd < 0 {
            // SAFETY: owned dir fd.
            unsafe {
                libc::close(fd);
            }
            return format!(
                "{}: cannot open regular capture file",
                String::from_utf8_lossy(name)
            );
        }
        // SAFETY: zeroed stat outlives the call.
        let mut mst: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let mrc = unsafe { libc::fstat(mfd, &mut mst) };
        // SAFETY: owned member fd.
        unsafe {
            libc::close(mfd);
        }
        if mrc != 0 {
            // SAFETY: owned dir fd.
            unsafe {
                libc::close(fd);
            }
            return "capture stat failed".to_string();
        }
        if mst.st_mode as u64 & 0o170000 != 0o100000 || mst.st_nlink as u64 != 1 {
            // SAFETY: owned dir fd.
            unsafe {
                libc::close(fd);
            }
            return format!(
                "{}: not a singly linked regular file",
                String::from_utf8_lossy(name)
            );
        }
        if mst.st_uid as u64 != euid {
            // SAFETY: owned dir fd.
            unsafe {
                libc::close(fd);
            }
            return format!("{}: not owned by reader", String::from_utf8_lossy(name));
        }
    }
    // Final-absence recheck, mirroring the recovery verify: a
    // session finalized between the probe and now refuses.
    let final_c = b"session.json\0";
    // SAFETY: NUL-terminated name on the live directory fd.
    let present = unsafe {
        libc::openat(
            fd,
            final_c.as_ptr().cast::<libc::c_char>(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0 as libc::c_uint,
        )
    };
    // SAFETY: owned dir fd.
    unsafe {
        libc::close(fd);
    }
    if present >= 0 {
        // SAFETY: owned probe fd.
        unsafe {
            libc::close(present);
        }
        return "final session appeared during recovery; retry finalized capture".to_string();
    }
    if std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != libc::ENOENT {
        return "cannot establish absence of final session".to_string();
    }
    // Every open the reader performs succeeds: the reader would
    // read on, which raw bytes cannot follow — refuse closed.
    "capture directory is inaccessible or a symlink".to_string()
}

/// Run the report verb over raw argv words; return the exit code.
///
/// Byte-identical to [`run_report`] on UTF-8 input (which it
/// delegates to); non-UTF-8 words follow Mojo's byte-wise
/// argv handling instead of failing as usage.
pub fn run_report_os(args: &[OsString]) -> i64 {
    if args
        .iter()
        .any(|a| a.as_bytes() == b"--help" || a.as_bytes() == b"-h")
    {
        match write_stdout(&report_usage()) {
            Ok(()) => return EXIT_OK,
            Err(_) => {
                let _ = write_stderr("memveil report: cannot write stdout\n");
                return EXIT_INTERNAL;
            }
        }
    }
    let words: Option<Vec<String>> = args
        .iter()
        .map(|a| a.to_str().map(str::to_string))
        .collect();
    if let Some(words) = words {
        return run_report(&words);
    }
    match parse_report_args_os(args) {
        Ok(dir_os) => {
            if dir_os.to_str().is_some() {
                // Unreachable: every non-UTF-8 word except the
                // capture directory fails or silences the parse
                // above, so a parsed UTF-8 directory means all
                // words decoded — which the fast path handled.
                // Fail closed without writing rather than risk a
                // lossy open.
                return EXIT_INTERNAL;
            }
            report_failed(
                "memveil report: cannot read capture: ",
                &probe_capture_dir_os(&dir_os),
            )
        }
        Err(OsParseFail::Message(e)) => report_failed("memveil report: ", &e.message),
        Err(OsParseFail::Silent) => EXIT_INTERNAL,
    }
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
    use std::os::unix::ffi::OsStrExt;

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

    fn os(words: &[&[u8]]) -> Vec<std::ffi::OsString> {
        use std::os::unix::ffi::OsStringExt;
        words
            .iter()
            .map(|w| std::ffi::OsString::from_vec(w.to_vec()))
            .collect()
    }

    fn os_fail_message(words: &[&[u8]]) -> String {
        match super::parse_report_args_os(&os(words)) {
            Err(super::OsParseFail::Message(e)) => e.message,
            Err(super::OsParseFail::Silent) => panic!("{words:?} must fail loudly, not silently"),
            Ok(dir) => panic!("{words:?} must fail, parsed {dir:?}"),
        }
    }

    fn os_is_silent(words: &[&[u8]]) -> bool {
        matches!(
            super::parse_report_args_os(&os(words)),
            Err(super::OsParseFail::Silent)
        )
    }

    #[test]
    fn report_os_echo_sites_silence_non_utf8() {
        // Mojo raises escaping these values and exits 1 with no
        // output; ASCII twins keep their exact messages.
        for words in [
            vec![b"--format".as_slice(), b"\xff".as_slice()],
            vec![b"--format".as_slice(), b"text\xff".as_slice()],
            vec![b"--long-lived-after".as_slice(), b"\xff".as_slice()],
            vec![b"--\xff".as_slice()],
            vec![b"-\xff".as_slice()],
        ] {
            assert!(os_is_silent(&words), "{words:?}");
        }
        assert_eq!(
            os_fail_message(&[b"--format".as_slice(), b"yaml".as_slice()]),
            "unknown format: yaml"
        );
        assert_eq!(
            os_fail_message(&[b"--long-lived-after".as_slice(), b"bogus".as_slice()]),
            "--long-lived-after DurationError(message=bad duration: bogus)"
        );
        assert_eq!(
            os_fail_message(&[b"--bogus".as_slice()]),
            "unknown option: --bogus"
        );
    }

    #[test]
    fn report_os_limits_parse_bytes() {
        // The decimal grammar never echoes, so non-UTF-8 fails
        // exactly like ASCII garbage (live Mojo parity).
        for flag in [
            b"--max-line-bytes".as_slice(),
            b"--max-session-bytes".as_slice(),
            b"--max-events-bytes".as_slice(),
        ] {
            let flag_text = String::from_utf8_lossy(flag).into_owned();
            assert_eq!(
                os_fail_message(&[flag, b"\xff".as_slice(), b"d".as_slice()]),
                format!("{flag_text} needs a decimal value")
            );
            assert_eq!(
                os_fail_message(&[flag, b"12\xff".as_slice(), b"d".as_slice()]),
                format!("{flag_text} needs a decimal value")
            );
        }
        // Valid values still validate (errors keep precedence).
        assert_eq!(
            os_fail_message(&[
                b"--max-line-bytes".as_slice(),
                b"65537".as_slice(),
                b"\xff".as_slice()
            ]),
            "--max-line-bytes above cap"
        );
    }

    #[test]
    fn report_os_positional_rules() {
        // Second positional and missing dir never echo.
        assert_eq!(
            os_fail_message(&[b"d".as_slice(), b"\xff".as_slice()]),
            "too many arguments"
        );
        assert_eq!(
            os_fail_message(&[b"\xff".as_slice(), b"d".as_slice()]),
            "too many arguments"
        );
        assert_eq!(
            os_fail_message(&[b"--strict".as_slice(), b"\xff".as_slice(), b"d".as_slice()]),
            "too many arguments"
        );
        assert_eq!(
            os_fail_message(&[b"--strict".as_slice()]),
            "missing capture directory"
        );
        // A lone non-UTF-8 positional parses to the raw directory.
        let dir = super::parse_report_args_os(&os(&[b"\xff".as_slice()])).expect("dir parses");
        assert_eq!(dir.as_bytes(), b"\xff".as_slice());
        let dir = super::parse_report_args_os(&os(&[
            b"--format".as_slice(),
            b"json".as_slice(),
            b"--strict".as_slice(),
            b"a\xffb".as_slice(),
        ]))
        .expect("valid flags parse");
        assert_eq!(dir.as_bytes(), b"a\xffb".as_slice());
    }

    #[test]
    fn report_os_probe_matches_reader_ascii() {
        // Differential pin: the raw probe returns the reader's own
        // failure detail on every ASCII shape, so non-UTF-8 paths
        // fail exactly the way their ASCII twins do.
        use crate::capture::reader::{ReaderLimits, read_capture};
        use crate::platform::test_support::TestDir;
        let limits = ReaderLimits {
            max_session_bytes: 16777216,
            max_line_bytes: 65536,
            max_events_bytes: 4294967296,
        };
        let tmp = TestDir::create("memveil-report-os-probe").expect("mkdtemp");
        let empty = tmp.path().join("empty");
        std::fs::create_dir(&empty).expect("mkdir empty");
        let file = tmp.path().join("file");
        std::fs::write(&file, b"x".as_slice()).expect("write file");
        for path in [
            "/nonexistent-memveil-report-os-xyz".to_string(),
            "/tmp".to_string(),
            "/etc/hostname".to_string(),
            empty.to_str().expect("utf-8").to_string(),
            file.to_str().expect("utf-8").to_string(),
        ] {
            let want = read_capture(&path, false, limits)
                .expect_err("shape must refuse")
                .message;
            let got = super::probe_capture_dir_os(std::ffi::OsStr::new(&path));
            assert_eq!(got, want, "probe must mirror the reader for {path}");
        }
    }

    #[test]
    fn report_os_probe_non_utf8_shapes() {
        use crate::platform::test_support::TestDir;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        // Nonexistent non-UTF-8 path: the reported case.
        assert_eq!(
            super::probe_capture_dir_os(std::ffi::OsStr::from_bytes(b"\xff")),
            "capture directory is inaccessible or a symlink"
        );
        let tmp = TestDir::create("memveil-report-os-ff").expect("mkdtemp");
        // A non-UTF-8 regular file: session.json under it is ENOTDIR.
        let ff_file = tmp
            .path()
            .join(std::ffi::OsString::from_vec(b"f\xff".to_vec()));
        std::fs::write(&ff_file, b"x").expect("write ff file");
        assert_eq!(
            super::probe_capture_dir_os(ff_file.as_os_str()),
            "cannot establish final session absence"
        );
        // An empty non-UTF-8 directory: recovery opens, checkpoint missing.
        let ff_dir = tmp
            .path()
            .join(std::ffi::OsString::from_vec(b"d\xff".to_vec()));
        std::fs::create_dir(&ff_dir).expect("mkdir ff dir");
        assert_eq!(
            super::probe_capture_dir_os(ff_dir.as_os_str()),
            "checkpoint.json: cannot open regular capture file"
        );
        // A non-UTF-8 directory whose session.json opens is refused
        // closed: the String reader cannot follow raw bytes.
        std::fs::write(ff_dir.join("session.json"), b"{}").expect("write session");
        assert_eq!(
            super::probe_capture_dir_os(ff_dir.as_os_str()),
            "capture directory is inaccessible or a symlink"
        );
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
