// SPDX-License-Identifier: GPL-3.0-or-later
//! Top: periodic summaries over a capture directory or live.
//!
//! Top replays the capture's events through the shared composed analyzer
//! and prints one text summary per refresh: at each interval boundary of
//! capture time plus a final full-window report. The final block renders
//! the same rows and findings as `report` with the same policy, so
//! replay-prefix equivalence holds by construction.
//!
//! With --output, top observes the live system instead: the collector
//! retains the capture while a tee writer folds the same bytes into the
//! shared analyzer and prints event-time refreshes under a provisional
//! session (producer loss explicitly unknown until finalize). The final
//! block replays the retained capture, so the final live answer equals a
//! replay of that capture by construction.
//!
//! Refresh membership follows consumption order, not timestamp order: a
//! refresh at horizon H covers the events consumed so far, and a
//! disordered event with a timestamp below an already-printed horizon is
//! folded into the final summary only. Printed refreshes are never
//! revised, so under disordered input a horizon may exclude an event its
//! timestamp names.
//!
//! The device option is a display filter over per-device rows (exact
//! device id or catalog name); analysis always covers the whole capture.
//! Every block names the active filter, and a filter matching no device
//! rows warns once on stderr. Summaries are line-oriented plain text with
//! escaped fields, safe for non-TTY pipes. Between refreshes top waits the
//! interval in wall time, polling for stops first and every 100 ms; a
//! pending SIGINT/SIGTERM finishes the remaining stream quietly, prints
//! the final summary, and exits with the final report's code.

use std::cell::RefCell;

use crate::ENGINE_VERSION;
use crate::analysis::diagnostics::diagnose_report;
use crate::analysis::engine::Analyzer;
use crate::capture::collector::{EXIT_ERROR, EXIT_REFUSAL};
use crate::capture::reader::{
    CaptureReader, DEFAULT_MAX_EVENTS_BYTES, DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_SESSION_BYTES,
    ReaderLimits, read_capture,
};
use crate::capture::run::{RecordOptions, repair_warning_for, run_collector_with};
use crate::capture::tee::{LiveAnalyzer, RefreshSink, TeeWriter};
use crate::cli::doctor::resolve_profiles_dir;
use crate::cli::durations::parse_duration_ns;
use crate::cli::record::parse_record_args;
use crate::cli::report::{
    CliError, EXIT_INTERNAL, EXIT_INVALID, EXIT_OK, MAX_RENDERED_BYTES, check_rendered_size,
    exit_for_report, refusal_stderr_lines, sanitize_diagnostic, write_capture_location,
    write_stderr, write_stderr_trusted,
};
use crate::model::event::Event;
use crate::model::report::{Report, apply_checkpoint, apply_integrity};
use crate::model::session::Session;
use crate::model::validate::format_u64;
use crate::platform::clock::MonoClock;
use crate::platform::signal::{LiveSignalSource, SignalOut};
use crate::platform::stdout::write_stdout;
use crate::render::filter::device_filter_resolves;
use crate::render::render::render;
use crate::render::text::render_compact;

/// Wall sleep between refreshes, default 1s.
pub const DEFAULT_INTERVAL_NS: u64 = 1_000_000_000;

/// Parsed top arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopOptions {
    /// Wall sleep between refreshes in nanoseconds.
    pub interval_ns: u64,
    /// True when --device was passed.
    pub has_device: bool,
    /// Display filter over per-device rows.
    pub device: String,
    /// Recover a verified checkpoint prefix or truncated legacy tail.
    pub allow_partial: bool,
    /// Exit 4 unless the final verdict is complete.
    pub strict: bool,
    /// Print the short verdict-plus-headlines block per refresh.
    pub compact: bool,
    /// True when --long-lived-after was passed.
    pub has_long_lived_after: bool,
    /// Informational long-lived finding threshold in nanoseconds.
    pub long_lived_after_ns: u64,
    /// Replay capture directory.
    pub dir: String,
    /// Per-record byte cap.
    pub max_line_bytes: usize,
    /// Session-file byte cap.
    pub max_session_bytes: usize,
    /// Total work byte cap.
    pub max_events_bytes: usize,
    /// True when live --output was passed.
    pub has_output: bool,
    /// Live collection options.
    pub live: RecordOptions,
}

impl Default for TopOptions {
    fn default() -> Self {
        Self {
            interval_ns: DEFAULT_INTERVAL_NS,
            has_device: false,
            device: String::new(),
            allow_partial: false,
            strict: false,
            compact: false,
            has_long_lived_after: false,
            long_lived_after_ns: 0,
            dir: String::new(),
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            max_session_bytes: DEFAULT_MAX_SESSION_BYTES,
            max_events_bytes: DEFAULT_MAX_EVENTS_BYTES,
            has_output: false,
            live: RecordOptions::default(),
        }
    }
}

/// Usage text for the top verb.
pub fn top_usage() -> String {
    concat!(
        "usage: memveil top [--interval DURATION] [--device NAME]\n",
        "       [--strict] [--compact] [--long-lived-after DURATION]\n",
        "       [--allow-partial] [--max-line-bytes N]\n",
        "       [--max-session-bytes N] [--max-events-bytes N] DIR\n",
        "   or: memveil top --output DIR [--object PATH]\n",
        "       [--duration SEC] [--max-events-bytes N]\n",
        "       [--bridge PATH] [--profile ID|PATH]\n",
        "       [--profiles-dir DIR] [--capability IDS]\n",
        "       [--lc-object PATH] [--cp-object PATH]\n",
        "       [--interval DURATION] [--device NAME]\n",
        "       [--strict] [--compact] [--long-lived-after DURATION]\n",
        "\n",
        "Replay the capture in DIR, printing one text summary per\n",
        "interval of capture time plus a final full-window report.\n",
        "With --output, observe the live system instead, retaining\n",
        "the capture in DIR while printing the same summaries.\n",
        "Live collection discovers absent --bridge, --object,\n",
        "--lc-object, and --cp-object paths as memveil record\n",
        "does. Refreshes cover events in consumption order; a\n",
        "disordered event below a printed horizon reaches the\n",
        "final summary only, never a revised refresh.\n",
        "Diagnostics go to stderr.\n",
        "\n",
        "  --interval DURATION\n",
        "                    wall sleep between refreshes, default 1s.\n",
        "  --device NAME     show only this device's per-device rows\n",
        "                    (exact device id or catalog name);\n",
        "                    analysis still covers the whole capture.\n",
        "                    Blocks name the active filter; a filter\n",
        "                    matching no device warns once.\n",
        "  --long-lived-after DURATION\n",
        "                    enable the informational long-lived\n",
        "                    finding past this open age.\n",
        "  --strict          exit 4 unless the final verdict is\n",
        "                    complete (live mode also runs the\n",
        "                    collection strictly).\n",
        "  --compact         print the short verdict-plus-headlines\n",
        "                    block instead of the full report per\n",
        "                    refresh; cannot combine with --device.\n",
        "\n",
        "DURATION is a decimal count with optional unit s, m, or h\n",
        "(bare digits mean seconds); zero and overflow are refused.\n",
        "\n",
        "Exit 0 for printed summaries (completeness rides in the\n",
        "verdict field), 4 under --strict unless the verdict is\n",
        "complete, 2 for invalid input or usage. Live mode\n",
        "adds 3 for unavailable collection and 1 for errors.\n",
    )
    .to_string()
}

/// Incremental interval horizons strictly inside (start, end).
///
/// A long window at a small interval names far more horizons than
/// memory could hold as a list, so the cursor yields them one at a
/// time with constant state: peek with has_due, take with pop. The
/// sequence matches materializing every start+k*interval below end,
/// stopping before u64 overflow.
pub struct BoundaryCursor {
    next: u64,
    end: u64,
    interval: u64,
    done: bool,
}

impl BoundaryCursor {
    /// Horizons strictly inside (start, end) at interval cadence.
    pub fn new(start_ns: u64, end_ns: u64, interval_ns: u64) -> Self {
        let mut cur = Self {
            next: 0,
            end: end_ns,
            interval: interval_ns,
            done: true,
        };
        if interval_ns == 0 || end_ns <= start_ns {
            return cur;
        }
        let b = start_ns.wrapping_add(interval_ns);
        if b < start_ns {
            return cur;
        }
        if b >= end_ns {
            return cur;
        }
        cur.next = b;
        cur.done = false;
        cur
    }

    /// True when the next horizon is due at ts.
    pub fn has_due(&self, ts: u64) -> bool {
        !self.done && ts >= self.next
    }

    /// Take the next horizon and advance; call only when due.
    pub fn pop(&mut self) -> u64 {
        let h = self.next;
        if h > u64::MAX - self.interval {
            self.done = true;
        } else {
            let b = h + self.interval;
            if b >= self.end {
                self.done = true;
            } else {
                self.next = b;
            }
        }
        h
    }
}

fn is_option(text: &str) -> bool {
    text.as_bytes().first() == Some(&0x2d)
}

/// True for record-flow flags, parsed by the shared parser.
fn is_live_flag(tok: &str) -> bool {
    matches!(
        tok,
        "--output"
            | "--object"
            | "--bridge"
            | "--profile"
            | "--profiles-dir"
            | "--capability"
            | "--lc-object"
            | "--cp-object"
            | "--duration"
            | "--max-events-bytes"
    )
}

/// Strict decimal limit: 1..cap, no leading zeros.
fn parse_limit(text: &str, what: &str, cap: u64) -> Result<usize, CliError> {
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

fn parse_duration_opt(text: &str, what: &str) -> Result<u64, CliError> {
    match parse_duration_ns(text) {
        Ok(ns) => Ok(ns),
        Err(e) => Err(CliError {
            message: format!("{what} {e}"),
        }),
    }
}

/// Parse top arguments without the leading verb.
pub fn parse_top_args(args: &[String]) -> Result<TopOptions, CliError> {
    let mut opts = TopOptions::default();
    let mut live_args: Vec<String> = Vec::new();
    let mut stashed_max_events = String::new();
    let mut has_stash = false;
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--interval" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--interval needs a value".to_string(),
                });
            }
            opts.interval_ns = parse_duration_opt(&args[i + 1], "--interval")?;
            i += 2;
        } else if tok == "--device" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--device needs a value".to_string(),
                });
            }
            opts.has_device = true;
            opts.device = args[i + 1].clone();
            i += 2;
        } else if tok == "--long-lived-after" {
            if i + 1 >= args.len() {
                return Err(CliError {
                    message: "--long-lived-after needs a value".to_string(),
                });
            }
            opts.has_long_lived_after = true;
            opts.long_lived_after_ns = parse_duration_opt(&args[i + 1], "--long-lived-after")?;
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
            stashed_max_events = args[i + 1].clone();
            has_stash = true;
            i += 2;
        } else if tok == "--allow-partial" {
            opts.allow_partial = true;
            i += 1;
        } else if tok == "--strict" {
            opts.strict = true;
            i += 1;
        } else if tok == "--compact" {
            opts.compact = true;
            i += 1;
        } else if is_live_flag(tok) {
            if tok == "--output" {
                opts.has_output = true;
            }
            live_args.push(tok.to_string());
            if i + 1 < args.len() {
                live_args.push(args[i + 1].clone());
                i += 2;
            } else {
                i += 1;
            }
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
    if opts.allow_partial && opts.has_output {
        return Err(CliError {
            message: "--allow-partial requires replay DIR".to_string(),
        });
    }
    if !opts.dir.is_empty() && opts.has_output {
        return Err(CliError {
            message: "cannot combine replay DIR with live --output".to_string(),
        });
    }
    if opts.compact && opts.has_device {
        return Err(CliError {
            message: "--compact does not take --device".to_string(),
        });
    }
    if opts.dir.is_empty() && !opts.has_output {
        return Err(CliError {
            message: "missing capture directory".to_string(),
        });
    }
    if !opts.has_output && !live_args.is_empty() {
        return Err(CliError {
            message: "live options need --output DIR".to_string(),
        });
    }
    if opts.has_output {
        if has_stash {
            live_args.push("--max-events-bytes".to_string());
            live_args.push(stashed_max_events);
        }
        opts.live = parse_record_args(&live_args)?;
        opts.live.strict = opts.strict;
    } else if has_stash {
        opts.max_events_bytes = parse_limit(&stashed_max_events, "--max-events-bytes", 4294967296)?;
    }
    Ok(opts)
}

fn top_failed(prefix: &str, detail: &str) -> i64 {
    let line = format!("{prefix}{}\n", sanitize_diagnostic(detail));
    match write_stderr(&line) {
        Ok(()) => EXIT_INVALID,
        Err(_) => EXIT_INTERNAL,
    }
}

/// Render a finish-path failure the way the source `String(e)` does.
///
/// Finishing raises a typed analysis error whose default rendering
/// is `AnalysisError(message=...)`; the detail rides through
/// unchanged. Consume-path failures stay bare: consume raises only
/// the generic error whose string form is its message.
fn analysis_error_text(message: &str) -> String {
    format!("AnalysisError(message={message})")
}

/// Reducer surface behind top's replay loops.
///
/// Production runs over [`Analyzer`], mapping its typed errors to
/// their messages; each arm then renders its own prefix. Tests stub
/// this trait to fail `consume` on demand: no capture file can
/// trigger a consume failure, because the event parser rejects the
/// only file-spellable violation (a copy without an observed
/// measurement) at read time.
trait TopReducer {
    /// Fold one event; the message renders bare on the consume path.
    fn consume(&mut self, ev: &Event) -> Result<(), String>;
    /// Reduce the stream so far; failures stay internal.
    fn snapshot(&mut self, horizon_ns: u64, partial: bool) -> Result<Report, String>;
    /// Reduce the whole capture; failures render wrapped.
    fn finish(&mut self, end_ns: u64, partial: bool) -> Result<Report, String>;
}

impl TopReducer for Analyzer {
    fn consume(&mut self, ev: &Event) -> Result<(), String> {
        Analyzer::consume(self, ev).map_err(|e| e.message)
    }

    fn snapshot(&mut self, horizon_ns: u64, partial: bool) -> Result<Report, String> {
        Analyzer::snapshot(self, horizon_ns, partial).map_err(|e| e.message)
    }

    fn finish(&mut self, end_ns: u64, partial: bool) -> Result<Report, String> {
        Analyzer::finish(self, end_ns, partial).map_err(|e| e.message)
    }
}

/// Block-header annotation naming the active device filter.
///
/// Empty without a filter, so unfiltered output stays byte for byte
/// unchanged; otherwise ` [device: <escaped>]`. The filter shows as
/// given, not as resolved: a catalog name stays a name even though
/// rows carry ids. The value is diagnostic-escaped, so hostile bytes
/// can neither split the header line nor smuggle terminal sequences
/// into stdout.
pub fn filter_header_suffix(filt: &str) -> String {
    if filt.is_empty() {
        return String::new();
    }
    format!(" [device: {}]", sanitize_diagnostic(filt))
}

/// Warn-once latch for one top run's device selection.
///
/// Replay refreshes and live prefixes share one policy: the first
/// block whose report has no matching device rows warns on stderr,
/// and later blocks stay silent whether or not they match, while
/// matching rows always print. The warning never fails the run: a
/// dead filter hides device rows but leaves global rows, findings,
/// and the exit code alone.
pub struct FilterWatch {
    filt: String,
    warned: bool,
}

impl FilterWatch {
    /// A latch over the run's device selection.
    pub fn new(opts: &TopOptions) -> Self {
        Self {
            filt: if opts.has_device {
                opts.device.clone()
            } else {
                String::new()
            },
            warned: false,
        }
    }

    /// Warning line once when filt matches no rows.
    ///
    /// Empty without a filter, once the filter resolves, or once the
    /// run already warned. The warning is a stderr diagnostic, so it
    /// never fails the run.
    pub fn warn_for(&mut self, rep: &Report) -> String {
        if self.warned || self.filt.is_empty() {
            return String::new();
        }
        if device_filter_resolves(rep, &self.filt) {
            return String::new();
        }
        self.warned = true;
        format!(
            "memveil top: --device '{}' matches no known device\n",
            sanitize_diagnostic(&self.filt)
        )
    }
}

/// Print one refresh block.
///
/// Every byte goes through the checked stdout writer: a short write
/// or error reports on stderr and fails, so a blocked stdout fails
/// the run instead of printing success. The header names the active
/// device filter, if any.
fn print_block(text: &str, seq: i64, horizon_ns: u64, filt: &str) -> Result<(), ()> {
    let mut head = format!("--- refresh {seq} @ {} ns ---", format_u64(horizon_ns));
    head += &filter_header_suffix(filt);
    head.push('\n');
    if write_stdout(&head).is_err() || write_stdout(text).is_err() {
        let _ = write_stderr("memveil top: cannot write stdout\n");
        return Err(());
    }
    let raw = text.as_bytes();
    if (raw.is_empty() || raw[raw.len() - 1] != 0x0a) && write_stdout("\n").is_err() {
        let _ = write_stderr("memveil top: cannot write stdout\n");
        return Err(());
    }
    Ok(())
}

/// Diagnose one refresh report under the run's policy.
fn diagnose_block(rep: &mut Report, has_long_lived_after: bool, long_lived_after_ns: u64) {
    diagnose_report(rep, has_long_lived_after, long_lived_after_ns);
}

/// Render one refresh body: compact headlines or full text.
///
/// Compact headlines are global-only; the caller refuses --compact
/// with --device, so filt is always empty here in compact mode.
fn render_block(rep: &Report, compact: bool, filt: &str) -> Result<String, ()> {
    if compact {
        return Ok(render_compact(rep));
    }
    render(rep, "text", filt).map_err(|_| ())
}

/// Diagnose, render, and print one refresh block.
///
/// Shared by replay refreshes and the live sink: one policy for every
/// printed block. Returns the exit code: 0 printed, 2 oversized.
/// Render and stdout failures return Err.
fn emit_report(
    rep: &mut Report,
    filt: &str,
    has_long_lived_after: bool,
    long_lived_after_ns: u64,
    seq: i64,
    horizon_ns: u64,
    compact: bool,
) -> Result<i64, ()> {
    diagnose_block(rep, has_long_lived_after, long_lived_after_ns);
    let text = render_block(rep, compact, filt)?;
    if check_rendered_size(&text, MAX_RENDERED_BYTES).is_err() {
        return Ok(top_failed("memveil top: ", "report exceeds size limit"));
    }
    print_block(&text, seq, horizon_ns, filt)?;
    Ok(0)
}

/// Render and print one refresh.
///
/// Warns through the run's shared latch before printing; replay and
/// live share the FilterWatch policy, so a dead filter warns once
/// per run.
fn snapshot_block<A: TopReducer>(
    analyzer: &mut A,
    opts: &TopOptions,
    horizon_ns: u64,
    seq: i64,
    watch: &mut FilterWatch,
) -> i64 {
    let mut rep = match analyzer.snapshot(horizon_ns, false) {
        Ok(rep) => rep,
        Err(_) => return EXIT_INTERNAL,
    };
    apply_integrity(&mut rep, false, 0, 0);
    rep.integrity_context = "replay prefix".to_string();
    let line = watch.warn_for(&rep);
    if !line.is_empty() {
        let _ = write_stderr(&line);
    }
    match emit_report(
        &mut rep,
        &watch.filt,
        opts.has_long_lived_after,
        opts.long_lived_after_ns,
        seq,
        horizon_ns,
        opts.compact,
    ) {
        Ok(rc) => rc,
        Err(_) => EXIT_INTERNAL,
    }
}

/// RefreshSink that prints numbered diagnosed text blocks.
///
/// Block numbering starts at one and rises per accepted refresh. A
/// refused emission still consumes its number, but refusals fail the
/// run, so the gap never prints. The device filter shares the replay
/// warn-once latch: a filter matching no known device warns on stderr
/// once, since every prefix would otherwise print global-only blocks
/// with no hint the filter is dead.
pub struct StdoutSink {
    watch: FilterWatch,
    has_long_lived_after: bool,
    long_lived_after_ns: u64,
    compact: bool,
    seq: i64,
}

impl StdoutSink {
    /// A sink over the run's options.
    pub fn new(opts: &TopOptions) -> Self {
        Self {
            watch: FilterWatch::new(opts),
            has_long_lived_after: opts.has_long_lived_after,
            long_lived_after_ns: opts.long_lived_after_ns,
            compact: opts.compact,
            seq: 0,
        }
    }
}

impl RefreshSink for StdoutSink {
    fn emit(&mut self, mut rep: Report, horizon_ns: u64) -> bool {
        apply_integrity(&mut rep, false, 0, 0);
        rep.integrity_context = "live stream".to_string();
        self.seq += 1;
        let line = self.watch.warn_for(&rep);
        if !line.is_empty() {
            let _ = write_stderr(&line);
        }
        match emit_report(
            &mut rep,
            &self.watch.filt,
            self.has_long_lived_after,
            self.long_lived_after_ns,
            self.seq,
            horizon_ns,
            self.compact,
        ) {
            Ok(rc) => rc == 0,
            Err(_) => false,
        }
    }
}

/// The composed analyzer behind the tee's shared-trait surface.
///
/// The tee folds through `LiveAnalyzer`; the engine's snapshot takes
/// `&mut`, so the adapter holds it behind a RefCell. Borrows never
/// nest: each fold or snapshot completes before the next begins.
struct TopLiveAnalyzer {
    inner: RefCell<Analyzer>,
}

impl LiveAnalyzer for TopLiveAnalyzer {
    fn new(session: Session) -> Self {
        Self {
            inner: RefCell::new(Analyzer::new(session)),
        }
    }

    fn consume(&mut self, event: Event) -> Result<(), String> {
        self.inner
            .borrow_mut()
            .consume(&event)
            .map_err(|e| e.message)
    }

    fn snapshot(&self, horizon_ns: u64, finalized: bool) -> Result<Report, String> {
        self.inner
            .borrow_mut()
            .snapshot(horizon_ns, finalized)
            .map_err(|e| e.message)
    }
}

/// Provisional live session: unclaimed values the tee stamps.
///
/// Real collection, nothing finalized, no capture filter (live records
/// every device; --device stays a display filter), no baseline (the
/// collector attests none either). Producer channels are
/// scope-complete with explicitly unknown loss: correlation and
/// baseline surface verbatim when their streams show no gaps, and the
/// merge rebuilds every other scope and reason, so the provisional
/// wording below is user-visible in every prefix and must stay honest.
/// Region and conversion caps stay unadmitted, matching the collector,
/// which attests no region source; revisit when conversion collection
/// lands.
fn live_template() -> Session {
    let mut s = Session {
        product_name: "memveil".to_string(),
        product_version: ENGINE_VERSION.to_string(),
        env_mode: "unknown".to_string(),
        env_detection: "unverified".to_string(),
        env_attestation: "not_performed".to_string(),
        capture_mode: "live".to_string(),
        window_end_ns: u64::MAX,
        ..Session::default()
    };
    for q in [
        &mut s.q_detail,
        &mut s.q_aggregate,
        &mut s.q_correlation,
        &mut s.q_terminal,
    ] {
        q.status = "complete_for_scope".to_string();
        q.has_loss_count = false;
        q.scope = "live prefix".to_string();
        q.reason = "provisional: producer loss unknown until finalize".to_string();
    }
    s.q_baseline.status = "not_applicable".to_string();
    s.q_baseline.scope = "attempt metrics".to_string();
    s.q_baseline.reason = "Attempt metrics need no baseline.".to_string();
    s
}

/// Replay the retained capture as the final live block.
///
/// Prefix numbering continues: the final block is refresh shown + 1
/// over the finalized session, so the final live answer equals a
/// replay of the retained capture by construction. The replay covers
/// the collection budget: live mode routes --max-events-bytes to the
/// writer, so replaying with the smaller replay cap alone would
/// refuse a capture the run just admitted.
fn finish_live(dir: &str, opts: &TopOptions, shown: usize, capture_exit: i64) -> i64 {
    let mut events_cap = opts.max_events_bytes;
    if opts.live.max_events_bytes as usize > events_cap {
        events_cap = opts.live.max_events_bytes as usize;
    }
    let mut reader = match read_capture(
        dir,
        false,
        ReaderLimits {
            max_session_bytes: opts.max_session_bytes,
            max_line_bytes: opts.max_line_bytes,
            max_events_bytes: events_cap,
        },
    ) {
        Ok(reader) => reader,
        Err(e) => return top_failed("memveil top: cannot read capture: ", &e.message),
    };
    let mut analyzer = Analyzer::new(reader.session.clone());
    let mut watch = FilterWatch::new(opts);
    if shown > 0 {
        // Printed prefixes already carried the warn-once latch
        // through the sink, so the final block never warns twice.
        // Only a prefix-less run can reach its final block with the
        // filter still unevaluated.
        watch.warned = true;
    }
    finish_after_signal(
        &mut reader,
        &mut analyzer,
        opts,
        shown as i64,
        &mut watch,
        capture_exit,
        dir,
    )
}

/// Observe the live system; return the process exit code.
///
/// Admission and collection reuse the record flow through a tee
/// writer that prints event-time refreshes; the final block replays
/// the retained capture, so the final live answer always equals a
/// replay of that capture. Refusals name their reason on stderr and
/// create nothing; printed prefixes stand when the run fails.
pub fn run_top_live(opts: &TopOptions) -> i64 {
    let profiles_dir = if opts.live.has_profiles_dir {
        opts.live.profiles_dir.clone()
    } else {
        match resolve_profiles_dir() {
            Ok(dir) => dir,
            Err(e) => {
                let _ = write_stderr(&format!(
                    "memveil top: cannot resolve profiles location: {}\n",
                    sanitize_diagnostic(&e.message)
                ));
                return EXIT_REFUSAL;
            }
        }
    };
    let template = live_template();
    let sink = StdoutSink::new(opts);
    let mut writer =
        TeeWriter::<StdoutSink, TopLiveAnalyzer>::new(template, opts.interval_ns, sink);
    let result = run_collector_with("", &profiles_dir, opts.live.clone(), &mut writer);
    if result.outcome == "finalized" {
        // A published capture lands root-owned under sudo; hand it to
        // the invoking user. Warn-only: the capture stands whatever
        // ownership repair does.
        let repair_line = repair_warning_for(&opts.live.output, &writer);
        if !repair_line.is_empty() {
            let _ = write_stderr(&repair_line);
        }
    }
    if result.exit_code == EXIT_ERROR || result.exit_code == EXIT_REFUSAL {
        let lines = refusal_stderr_lines("top", &result.diagnostic, &result.code, &result.fix);
        // lines[0] is the diagnostic; only it can embed caller
        // paths, so only it honors the scrub flag.
        for (i, line) in lines.iter().enumerate() {
            if result.trusted || i > 0 {
                let _ = write_stderr_trusted(line);
            } else {
                let _ = write_stderr(line);
            }
        }
        return result.exit_code;
    }
    finish_live(
        &opts.live.output,
        opts,
        writer.emission_count(),
        result.exit_code,
    )
}

/// Run the top verb; return the process exit code.
///
/// `args` excludes the program name and the top word. Summaries go to
/// stdout and nothing else does; every diagnostic goes to stderr.
/// Only a broken standard error escapes as a failure.
pub fn run_top(args: &[String]) -> i64 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        match write_stdout(&top_usage()) {
            Ok(()) => return EXIT_OK,
            Err(_) => {
                let _ = write_stderr("memveil top: cannot write stdout\n");
                return EXIT_INTERNAL;
            }
        }
    }
    let opts = match parse_top_args(args) {
        Ok(opts) => opts,
        Err(e) => return top_failed("memveil top: ", &e.message),
    };
    if opts.has_output {
        return run_top_live(&opts);
    }
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
        Err(e) => return top_failed("memveil top: cannot read capture: ", &e.message),
    };
    let mut signal = LiveSignalSource::new();
    let armed = signal.setup();
    if !armed.ok {
        let _ = write_stderr(&format!(
            "memveil top: cannot arm signals: {}\n",
            sanitize_diagnostic(&armed.message)
        ));
        return EXIT_INTERNAL;
    }
    let mut analyzer = Analyzer::new(reader.session.clone());
    let mut clock = MonoClock::new();
    let mut cursor = BoundaryCursor::new(
        reader.session.window_start_ns,
        reader.session.window_end_ns,
        opts.interval_ns,
    );
    let seq = 0;
    let mut watch = FilterWatch::new(&opts);
    let code = drain(
        &mut reader,
        &mut analyzer,
        &opts,
        &mut signal,
        &mut clock,
        &mut cursor,
        seq,
        &mut watch,
    );
    signal.teardown();
    code
}

const WAIT_SLICE_MS: i64 = 100;

/// One-at-a-time ≤100 ms slices for a refresh wait.
///
/// A huge interval names far more slices than memory could hold as a
/// list, so the cursor yields them one at a time with constant state:
/// check with has_more, take with take. The sequence matches splitting
/// the total into 100 ms slices with a short final slice.
pub struct WaitSlices {
    left: i64,
}

impl WaitSlices {
    /// Slices covering total_ms.
    pub fn new(total_ms: i64) -> Self {
        Self {
            left: total_ms.max(0),
        }
    }

    /// True while an untaken slice remains.
    pub fn has_more(&self) -> bool {
        self.left > 0
    }

    /// Take the next slice; call only when due.
    pub fn take(&mut self) -> i64 {
        let mut s = self.left;
        if s > WAIT_SLICE_MS {
            s = WAIT_SLICE_MS;
        }
        self.left -= s;
        s
    }
}

/// Poll-first interruptible wait; returns the last state.
///
/// The first poll runs before any sleep, then each slice sleeps and
/// re-polls, so a stop lands within about one slice no matter how long
/// the interval is.
fn wait_interval(clock: &mut MonoClock, signal: &mut LiveSignalSource, total_ms: i64) -> SignalOut {
    let mut got = signal.check();
    if got.state != "none" {
        return got;
    }
    let mut slices = WaitSlices::new(total_ms);
    while slices.has_more() {
        clock.sleep_ms(slices.take());
        got = signal.check();
        if got.state != "none" {
            return got;
        }
    }
    got
}

/// Report a signal-check failure; always exits internal.
fn signal_failed(message: &str) -> i64 {
    let _ = write_stderr(&format!(
        "memveil top: signal check failed: {}\n",
        sanitize_diagnostic(message)
    ));
    EXIT_INTERNAL
}

/// Stream events, refreshing at each boundary, then finish.
#[allow(clippy::too_many_arguments)]
fn drain<A: TopReducer>(
    reader: &mut CaptureReader,
    analyzer: &mut A,
    opts: &TopOptions,
    signal: &mut LiveSignalSource,
    clock: &mut MonoClock,
    cursor: &mut BoundaryCursor,
    mut seq: i64,
    watch: &mut FilterWatch,
) -> i64 {
    loop {
        let more = match reader.has_more() {
            Ok(more) => more,
            Err(e) => return top_failed("memveil top: cannot read capture: ", &e.message),
        };
        if !more {
            break;
        }
        let ev = match reader.next_event() {
            Ok(ev) => ev,
            Err(e) => return top_failed("memveil top: cannot read capture: ", &e.message),
        };
        let ts = ev.ts_ns;
        // Every boundary the event crosses renders BEFORE the event is
        // consumed: a refresh at horizon H covers [start, H), so the
        // crossing event belongs to the next refresh, never the one
        // it triggers. Boundaries only advance, so a nonmonotonic
        // event below an already rendered horizon renders nothing
        // further.
        //
        // A stop observed mid-refresh only latches a flag: the
        // signalfd record is consumed by the wait's polls, but the
        // crossing event still folds first so the final summary
        // covers every pulled event.
        let mut stopped = false;
        let wait_ms = (opts.interval_ns / 1_000_000) as i64;
        while cursor.has_due(ts) && !stopped {
            let horizon = cursor.pop();
            seq += 1;
            let rc = snapshot_block(analyzer, opts, horizon, seq, watch);
            if rc != 0 {
                return rc;
            }
            let wait = wait_interval(clock, signal, wait_ms);
            if wait.state == "error" {
                return signal_failed(&wait.message);
            }
            stopped = wait.state != "none";
        }
        if let Err(message) = analyzer.consume(&ev) {
            return top_failed("memveil top: cannot reduce capture: ", &message);
        }
        if stopped {
            return finish_after_signal(reader, analyzer, opts, seq, watch, -1, "");
        }
        if let Some(outcome) = poll_signal(reader, analyzer, opts, signal, seq, watch) {
            return outcome;
        }
    }
    seq += 1;
    let mut rep = match analyzer.finish(reader.session.window_end_ns, false) {
        Ok(rep) => rep,
        Err(message) => return top_failed("memveil top: ", &analysis_error_text(&message)),
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
    let line = watch.warn_for(&rep);
    if !line.is_empty() {
        let _ = write_stderr(&line);
    }
    diagnose_block(
        &mut rep,
        opts.has_long_lived_after,
        opts.long_lived_after_ns,
    );
    let text = match render_block(&rep, opts.compact, &watch.filt) {
        Ok(text) => text,
        Err(_) => {
            let _ = write_stderr("memveil top: internal error: cannot render report\n");
            return EXIT_INTERNAL;
        }
    };
    if check_rendered_size(&text, MAX_RENDERED_BYTES).is_err() {
        return top_failed("memveil top: ", "report exceeds size limit");
    }
    if print_block(&text, seq, reader.session.window_end_ns, &watch.filt).is_err() {
        return EXIT_INTERNAL;
    }
    if reader.checkpoint_prefix {
        return 4;
    }
    exit_for_report(&rep, opts.strict)
}

/// Handle a pending stop signal; None means keep going.
fn poll_signal<A: TopReducer>(
    reader: &mut CaptureReader,
    analyzer: &mut A,
    opts: &TopOptions,
    signal: &mut LiveSignalSource,
    seq: i64,
    watch: &mut FilterWatch,
) -> Option<i64> {
    let got = signal.check();
    if got.state == "none" {
        return None;
    }
    if got.state == "error" {
        return Some(signal_failed(&got.message));
    }
    Some(finish_after_signal(
        reader, analyzer, opts, seq, watch, -1, "",
    ))
}

/// Drain the rest quietly, print the final summary and code.
fn finish_after_signal<A: TopReducer>(
    reader: &mut CaptureReader,
    analyzer: &mut A,
    opts: &TopOptions,
    seq: i64,
    watch: &mut FilterWatch,
    capture_exit: i64,
    retained_path: &str,
) -> i64 {
    loop {
        let more = match reader.has_more() {
            Ok(more) => more,
            Err(e) => return top_failed("memveil top: cannot read capture: ", &e.message),
        };
        if !more {
            break;
        }
        let ev = match reader.next_event() {
            Ok(ev) => ev,
            Err(e) => return top_failed("memveil top: cannot read capture: ", &e.message),
        };
        if let Err(message) = analyzer.consume(&ev) {
            return top_failed("memveil top: cannot reduce capture: ", &message);
        }
    }
    let mut rep = match analyzer.finish(reader.session.window_end_ns, false) {
        Ok(rep) => rep,
        Err(message) => return top_failed("memveil top: ", &analysis_error_text(&message)),
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
    let line = watch.warn_for(&rep);
    if !line.is_empty() {
        let _ = write_stderr(&line);
    }
    diagnose_block(
        &mut rep,
        opts.has_long_lived_after,
        opts.long_lived_after_ns,
    );
    let text = match render_block(&rep, opts.compact, &watch.filt) {
        Ok(text) => text,
        Err(_) => {
            let _ = write_stderr("memveil top: internal error: cannot render report\n");
            return EXIT_INTERNAL;
        }
    };
    if print_block(&text, seq + 1, reader.session.window_end_ns, &watch.filt).is_err() {
        if capture_exit >= 0 {
            let _ = write_capture_location(retained_path, "");
            return capture_exit;
        }
        return EXIT_INTERNAL;
    }
    if reader.checkpoint_prefix {
        return 4;
    }
    exit_for_report(&rep, opts.strict)
}

#[cfg(test)]
mod tests {
    use super::{
        BoundaryCursor, FilterWatch, StdoutSink, TopOptions, WaitSlices, diagnose_block, drain,
        filter_header_suffix, finish_after_signal, finish_live, live_template, parse_top_args,
        run_top, snapshot_block, top_usage, wait_interval,
    };
    use crate::analysis::engine::Analyzer;
    use crate::capture::reader::{ReaderLimits, read_capture};
    use crate::capture::tee::RefreshSink;
    use crate::model::event::Event;
    use crate::model::metric::{Finding, Metric};
    use crate::model::report::{Report, apply_integrity};
    use crate::model::session::{DeviceEntry, Session};
    use crate::model::validate::format_u64;
    use crate::platform::clock::MonoClock;
    use crate::platform::reader::read_host_file;
    use crate::platform::signal::LiveSignalSource;
    use crate::platform::test_support::{TestDir, repo_root};
    use crate::render::filter::device_filter_resolves;
    use crate::render::render::render;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn repo(path: &str) -> String {
        repo_root().join(path).to_str().expect("utf-8").to_string()
    }

    #[test]
    fn top_defaults() {
        let opts = parse_top_args(&args(&["capdir"])).expect("dir parses");
        assert_eq!(opts.interval_ns, 1_000_000_000);
        assert!(!opts.has_device);
        assert!(!opts.has_long_lived_after);
        assert_eq!(opts.dir, "capdir");
        assert!(!opts.allow_partial);
        assert!(!opts.strict);
        assert!(!opts.compact);
        assert!(!opts.has_output);
        assert_eq!(opts.max_line_bytes, 65536);
        assert_eq!(opts.max_session_bytes, 16777216);
        assert_eq!(opts.max_events_bytes, 1073741824);
    }

    #[test]
    fn top_flags() {
        let opts = parse_top_args(&args(&[
            "--interval",
            "2s",
            "--device",
            "d000001",
            "--long-lived-after",
            "1m",
            "capdir",
        ]))
        .expect("flags parse");
        assert_eq!(opts.interval_ns, 2_000_000_000);
        assert!(opts.has_device);
        assert_eq!(opts.device, "d000001");
        assert!(opts.has_long_lived_after);
        assert_eq!(opts.long_lived_after_ns, 60_000_000_000);
    }

    #[test]
    fn top_arg_errors() {
        let err = parse_top_args(&[]).expect_err("empty rejects");
        assert_eq!(err.message, "missing capture directory");
        let err = parse_top_args(&args(&["--interval", "nope", "capdir"]))
            .expect_err("bad interval rejects");
        assert!(err.message.starts_with("--interval "), "{}", err.message);
        let err = parse_top_args(&args(&["--nope", "capdir"])).expect_err("unknown rejects");
        assert_eq!(err.message, "unknown option: --nope");
        let err = parse_top_args(&args(&["a", "b"])).expect_err("two dirs reject");
        assert_eq!(err.message, "too many arguments");
        let err = parse_top_args(&args(&["--long-lived-after", "0s", "capdir"]))
            .expect_err("zero long-lived rejects");
        assert!(
            err.message.starts_with("--long-lived-after "),
            "{}",
            err.message
        );
    }

    #[test]
    fn top_live_object_optional() {
        let opts = parse_top_args(&args(&["--output", "out"])).expect("live parses");
        assert!(opts.has_output);
        assert_eq!(opts.live.output, "out");
        assert_eq!(opts.live.object, "");
    }

    #[test]
    fn top_live_matrix() {
        // Replay DIR plus live --output refuses.
        let err = parse_top_args(&args(&["capdir", "--output", "out"]))
            .expect_err("replay plus live rejects");
        assert_eq!(err.message, "cannot combine replay DIR with live --output");
        // --allow-partial is replay-only.
        let err = parse_top_args(&args(&["--output", "out", "--allow-partial"]))
            .expect_err("live partial rejects");
        assert_eq!(err.message, "--allow-partial requires replay DIR");
        // --compact refuses --device.
        let err = parse_top_args(&args(&["--compact", "--device", "d", "capdir"]))
            .expect_err("compact plus device rejects");
        assert_eq!(err.message, "--compact does not take --device");
        // Live flags without --output refuse.
        let err = parse_top_args(&args(&["--profiles-dir", "/alt", "capdir"]))
            .expect_err("replay profiles-dir rejects");
        assert_eq!(err.message, "live options need --output DIR");
        // Live --duration errors surface from the shared parser.
        let err = parse_top_args(&args(&["--output", "out", "--duration", "nope"]))
            .expect_err("bad live duration rejects");
        assert_eq!(err.message, "bad decimal: nope");
        // --strict flows into the live record options.
        let opts = parse_top_args(&args(&["--output", "out", "--strict"])).expect("parses");
        assert!(opts.strict);
        assert!(opts.live.strict);
    }

    #[test]
    fn top_live_profiles_dir() {
        let opts = parse_top_args(&args(&[
            "--output",
            "out",
            "--profiles-dir",
            "/alt/profiles",
        ]))
        .expect("parses");
        assert!(opts.has_output);
        assert!(opts.live.has_profiles_dir);
        assert_eq!(opts.live.profiles_dir, "/alt/profiles");
    }

    #[test]
    fn top_replay_refuses_profiles_dir() {
        let err = parse_top_args(&args(&["--profiles-dir", "/alt/profiles", "capdir"]))
            .expect_err("replay profiles-dir rejects");
        assert!(
            err.message.contains("live options need --output"),
            "{}",
            err.message
        );
    }

    #[test]
    fn top_usage_shape() {
        let text = top_usage();
        assert!(text.contains("[--object PATH]"));
        assert!(text.contains("discover"));
        assert!(text.contains("[--profiles-dir DIR]"));
        assert!(text.starts_with("usage: memveil top [--interval DURATION]"));
    }

    #[test]
    fn boundaries() {
        let mut cur = BoundaryCursor::new(0, 2_300_000_000, 1_000_000_000);
        assert!(!cur.has_due(999_999_999));
        assert!(cur.has_due(1_000_000_000));
        assert_eq!(cur.pop(), 1_000_000_000);
        assert!(!cur.has_due(1_999_999_999));
        assert!(cur.has_due(2_000_000_000));
        assert_eq!(cur.pop(), 2_000_000_000);
        assert!(!cur.has_due(u64::MAX));
        let none = BoundaryCursor::new(500, 500, 1_000_000_000);
        assert!(!none.has_due(u64::MAX));
        let short = BoundaryCursor::new(0, 999, 1_000_000_000);
        assert!(!short.has_due(u64::MAX));
        let zero = BoundaryCursor::new(0, 2_300_000_000, 0);
        assert!(!zero.has_due(u64::MAX));
    }

    #[test]
    fn cursor_streams_long_window() {
        let mut cur = BoundaryCursor::new(0, u64::MAX, 1);
        assert!(!cur.has_due(0));
        assert!(cur.has_due(1));
        assert_eq!(cur.pop(), 1);
        assert_eq!(cur.pop(), 2);
        assert_eq!(cur.pop(), 3);
        assert!(cur.has_due(4));
    }

    #[test]
    fn wait_slices_bounded() {
        let mut parts = WaitSlices::new(250);
        assert!(parts.has_more());
        assert_eq!(parts.take(), 100);
        assert!(parts.has_more());
        assert_eq!(parts.take(), 100);
        assert!(parts.has_more());
        assert_eq!(parts.take(), 50);
        assert!(!parts.has_more());
        assert!(!WaitSlices::new(0).has_more());
        assert!(!WaitSlices::new(-5).has_more());
        let mut hour = WaitSlices::new(3_600_000);
        let mut count = 0;
        let mut total = 0;
        while hour.has_more() {
            let s = hour.take();
            assert!(s <= 100);
            count += 1;
            total += s;
        }
        assert_eq!(count, 36000);
        assert_eq!(total, 3600000);
    }

    #[test]
    fn wait_slices_stream_huge() {
        let mut big = WaitSlices::new(1_000_000_000_000);
        assert!(big.has_more());
        assert_eq!(big.take(), 100);
        assert_eq!(big.take(), 100);
        assert_eq!(big.take(), 100);
        assert!(big.has_more());
    }

    #[test]
    fn wait_interval_quiet_waits_full() {
        let mut clock = MonoClock::new();
        let mut src = LiveSignalSource::new();
        assert!(src.setup().ok);
        let got = wait_interval(&mut clock, &mut src, 0);
        assert_eq!(got.state, "none");
        src.teardown();
    }

    #[test]
    fn wait_interval_polls_before_sleep() {
        // A raise() in a multithreaded harness could land on a sibling
        // thread, so the pending-signal case runs isolated in a child.
        if std::env::var("MEMVEIL_TOP_WAIT_CHILD").is_ok() {
            let mut clock = MonoClock::new();
            let mut src = LiveSignalSource::new();
            assert!(src.setup().ok);
            // SAFETY: libc raise of SIGINT to this single-threaded child.
            unsafe {
                libc::raise(libc::SIGINT);
            }
            let got = wait_interval(&mut clock, &mut src, 3_600_000);
            src.teardown();
            std::process::exit(i32::from(got.state != "pending"));
        }
        let exe = std::env::current_exe().expect("test binary path resolves");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("cli::top::tests::wait_interval_polls_before_sleep")
            .arg("--nocapture")
            .env("MEMVEIL_TOP_WAIT_CHILD", "1")
            .output()
            .expect("child re-exec runs");
        assert_eq!(out.status.code(), Some(0));
    }

    fn sink_attempt(op: &str, seq: u64, ts: u64) -> Event {
        Event {
            session_id: "sinkprobe".to_string(),
            seq,
            ts_ns: ts,
            kind: "bounce_attempt".to_string(),
            source_hook: "h".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            bounce: crate::model::event::BounceAttempt {
                device_id: "d1".to_string(),
                requested_bytes: 4096,
                operation_id: op.to_string(),
                ..crate::model::event::BounceAttempt::default()
            },
            ..Event::default()
        }
    }

    fn sink_report(horizon: u64) -> Report {
        let mut s = live_template();
        s.window_start_ns = 100;
        s.window_end_ns = u64::MAX;
        let mut a = Analyzer::new(s);
        a.consume(&sink_attempt("op1", 0, 100)).expect("consume");
        a.consume(&sink_attempt("op2", 1, 200)).expect("consume");
        a.snapshot(horizon, false).expect("snapshot")
    }

    fn sink_report_dev(horizon: u64) -> Report {
        let mut s = live_template();
        s.window_start_ns = 100;
        s.window_end_ns = u64::MAX;
        let mut a = Analyzer::new(s);
        a.consume(&sink_attempt("op1", 0, 100)).expect("consume");
        let mut e1 = sink_attempt("op2", 1, 200);
        e1.bounce.device_id = "d2".to_string();
        a.consume(&e1).expect("consume");
        a.snapshot(horizon, false).expect("snapshot")
    }

    fn block_want(seq: i64, horizon: u64, filt: &str) -> String {
        let mut oracle = sink_report(horizon);
        apply_integrity(&mut oracle, false, 0, 0);
        oracle.integrity_context = "live stream".to_string();
        diagnose_block(&mut oracle, false, 0);
        let text = render(&oracle, "text", filt).expect("render");
        let mut head = format!("--- refresh {seq} @ {} ns ---", format_u64(horizon));
        if !filt.is_empty() {
            head.push_str(&format!(" [device: {filt}]"));
        }
        head.push('\n');
        let mut want = head + &text;
        let raw = text.as_bytes();
        if raw.is_empty() || raw[raw.len() - 1] != 0x0a {
            want.push('\n');
        }
        want
    }

    /// Run one stdout-capturing child of this test binary; the child
    /// redirects its own descriptors into the scratch dir and asserts.
    fn run_child(test: &str, scratch: &TestDir) {
        let exe = std::env::current_exe().expect("test binary path resolves");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg(format!("cli::top::tests::{test}"))
            .arg("--nocapture")
            .env("MEMVEIL_TOP_CHILD", test)
            .env("MEMVEIL_TOP_SCRATCH", scratch.as_str())
            .output()
            .expect("child re-exec runs");
        assert_eq!(
            out.status.code(),
            Some(0),
            "child {test}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn child_scratch() -> Option<String> {
        std::env::var("MEMVEIL_TOP_SCRATCH").ok()
    }

    fn redirect_fd(fd: i32, path: &str) -> i32 {
        use std::os::unix::io::AsRawFd;
        // SAFETY: dup of a live test descriptor.
        let saved = unsafe { libc::dup(fd) };
        assert!(saved >= 0);
        let file = std::fs::File::create(path).expect("scratch file");
        // SAFETY: dup2 onto the stdio descriptor, then close ours.
        let moved = unsafe { libc::dup2(file.as_raw_fd(), fd) };
        assert!(moved >= 0);
        saved
    }

    fn restore_fd(fd: i32, saved: i32) {
        // SAFETY: restore the saved descriptor, then close it.
        unsafe {
            libc::dup2(saved, fd);
            libc::close(saved);
        }
    }

    fn read_scratch(path: &str) -> String {
        String::from_utf8(read_host_file(path, "out", 1048576).expect("read back")).expect("utf-8")
    }

    #[test]
    fn sink_emits_numbered_block() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let opts = TopOptions::default();
            let mut sink = StdoutSink::new(&opts);
            let rep = sink_report(200);
            let want = block_want(1, 200, "");
            let saved = redirect_fd(1, &out);
            let ok = sink.emit(rep, 200);
            restore_fd(1, saved);
            assert!(ok);
            assert_eq!(read_scratch(&out), want);
            return;
        }
        run_child("sink_emits_numbered_block", &scratch);
    }

    #[test]
    fn sink_device_filter_displays() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let opts = TopOptions {
                has_device: true,
                device: "d1".to_string(),
                ..TopOptions::default()
            };
            let mut sink = StdoutSink::new(&opts);
            let rep = sink_report(200);
            let want = block_want(1, 200, "d1");
            let saved = redirect_fd(1, &out);
            let ok = sink.emit(rep, 200);
            restore_fd(1, saved);
            assert!(ok);
            assert_eq!(read_scratch(&out), want);
            return;
        }
        run_child("sink_device_filter_displays", &scratch);
    }

    #[test]
    fn sink_seq_increments() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let opts = TopOptions::default();
            let mut sink = StdoutSink::new(&opts);
            let first = sink_report(100);
            let second = sink_report(200);
            let want = block_want(1, 100, "") + &block_want(2, 200, "");
            let saved = redirect_fd(1, &out);
            let ok0 = sink.emit(first, 100);
            let ok1 = sink.emit(second, 200);
            restore_fd(1, saved);
            assert!(ok0);
            assert!(ok1);
            assert_eq!(read_scratch(&out), want);
            return;
        }
        run_child("sink_seq_increments", &scratch);
    }

    #[test]
    fn sink_filter_matches_replay_render() {
        // The live sink and the replay block printer share the
        // diagnose-plus-render path; only the stream label differs.
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let live_out = format!("{dir}/live.txt");
            let replay_out = format!("{dir}/replay.txt");
            let opts = TopOptions {
                has_device: true,
                device: "d1".to_string(),
                ..TopOptions::default()
            };
            let mut sink = StdoutSink::new(&opts);
            let rep = sink_report_dev(200);
            let saved = redirect_fd(1, &live_out);
            let ok = sink.emit(rep, 200);
            restore_fd(1, saved);
            assert!(ok);
            let mut s = live_template();
            s.window_start_ns = 100;
            s.window_end_ns = u64::MAX;
            let mut a = Analyzer::new(s);
            a.consume(&sink_attempt("op1", 0, 100)).expect("consume");
            let mut e1 = sink_attempt("op2", 1, 200);
            e1.bounce.device_id = "d2".to_string();
            a.consume(&e1).expect("consume");
            let mut watch = FilterWatch::new(&opts);
            let saved2 = redirect_fd(1, &replay_out);
            let rc = snapshot_block(&mut a, &opts, 200, 1, &mut watch);
            restore_fd(1, saved2);
            assert_eq!(rc, 0);
            let live_text = read_scratch(&live_out);
            let replay_text = read_scratch(&replay_out);
            assert!(live_text.contains("integrity: unverified live stream"));
            assert!(replay_text.contains("integrity: unverified replay prefix"));
            assert!(!live_text.contains("legacy_unverified"));
            assert!(!live_text.contains("checkpoint_prefix"));
            assert!(!live_text.contains(": complete_for_scope loss="));
            assert!(!live_text.contains(", complete_for_scope,"));
            assert_eq!(
                live_text.replace("unverified live stream", "unverified replay prefix"),
                replay_text
            );
            return;
        }
        run_child("sink_filter_matches_replay_render", &scratch);
    }

    fn live_prefix_report() -> Report {
        let mut s = live_template();
        s.window_start_ns = 100;
        s.window_end_ns = u64::MAX;
        let mut a = Analyzer::new(s);
        a.consume(&sink_attempt("op1", 0, 100)).expect("consume");
        a.snapshot(200, false).expect("snapshot")
    }

    #[test]
    fn live_refresh_header_lines() {
        let text = render(&live_prefix_report(), "text", "").expect("render");
        for want in [
            "(live, engine ",
            "window: [100,200)",
            "duration: 0.000000100 s (100 ns)",
            "environment: mode=unknown detection=unverified attestation=not_performed evidence=0",
            "recorded kernel.release: unavailable (no captured provenance)",
            "recorded profile.decision: unavailable (no captured provenance)",
            "recorded measurement_scope: unavailable (no captured provenance)",
        ] {
            assert!(text.contains(want), "missing {want}");
        }
        let md = render(&live_prefix_report(), "markdown", "").expect("render");
        for want in [
            "- synthetic: no",
            "- window: [100,200)",
            "- duration: 0.000000100 s (100 ns)",
            "- environment: mode=unknown detection=unverified attestation=not_performed evidence=0",
            "- recorded kernel.release: unavailable (no captured provenance)",
            "- recorded profile.decision: unavailable (no captured provenance)",
            "- recorded measurement\\_scope: unavailable (no captured provenance)",
        ] {
            assert!(md.contains(want), "missing {want}");
        }
    }

    #[test]
    fn sink_full_stdout_refuses() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let opts = TopOptions::default();
            let mut sink = StdoutSink::new(&opts);
            let rep = sink_report(200);
            // SAFETY: dup of fd 1 in this single-purpose child.
            let saved = unsafe { libc::dup(1) };
            assert!(saved >= 0);
            let full = std::fs::File::create("/dev/full").expect("open /dev/full");
            use std::os::unix::io::AsRawFd;
            // SAFETY: dup2 /dev/full onto fd 1.
            let moved = unsafe { libc::dup2(full.as_raw_fd(), 1) };
            assert!(moved >= 0);
            let ok = sink.emit(rep, 200);
            restore_fd(1, saved);
            assert!(!ok);
            return;
        }
        run_child("sink_full_stdout_refuses", &scratch);
    }

    #[test]
    fn live_template_provisional() {
        let s = live_template();
        assert_eq!(s.capture_mode, "live");
        assert!(!s.synthetic);
        assert!(!s.finalized);
        assert!(!s.has_filter_device);
        assert!(!s.baseline_complete);
        assert_eq!(s.baseline_region_count, 0);
        assert!(s.baseline_regions.is_empty());
        assert_eq!(s.window_start_ns, 0);
        assert_eq!(s.window_end_ns, u64::MAX);
        for q in [&s.q_detail, &s.q_aggregate, &s.q_correlation, &s.q_terminal] {
            assert_eq!(q.status, "complete_for_scope");
            assert!(!q.has_loss_count);
            assert_eq!(q.scope, "live prefix");
            assert_eq!(
                q.reason,
                "provisional: producer loss unknown until finalize"
            );
        }
        assert_eq!(s.q_baseline.status, "not_applicable");
        assert_eq!(s.q_baseline.scope, "attempt metrics");
        assert_eq!(s.q_baseline.reason, "Attempt metrics need no baseline.");
        assert_eq!(s.product_name, "memveil");
        assert!(!s.product_version.is_empty());
    }

    #[test]
    fn finish_live_forwards_byte_budget() {
        // The final live replay covers the collection budget, not
        // just the replay cap.
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let cap = repo("tests/fixtures/attempts");
            let events =
                read_host_file(&format!("{cap}/events.ndjson"), "events", 1048576).expect("events");
            let size = events.len();
            assert!(size > 64);
            let opts = TopOptions {
                max_events_bytes: size / 2,
                live: crate::capture::run::RecordOptions {
                    max_events_bytes: (size * 2) as u64,
                    ..crate::capture::run::RecordOptions::default()
                },
                ..TopOptions::default()
            };
            let saved = redirect_fd(1, &out);
            let rc = finish_live(&cap, &opts, 0, 0);
            restore_fd(1, saved);
            assert_eq!(rc, 0);
            assert!(read_scratch(&out).starts_with("--- refresh 1 @ "));
            return;
        }
        run_child("finish_live_forwards_byte_budget", &scratch);
    }

    #[test]
    fn sink_warns_once_for_unknown_device() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let err = format!("{dir}/err.txt");
            let opts = TopOptions {
                has_device: true,
                device: "nope".to_string(),
                ..TopOptions::default()
            };
            let mut sink = StdoutSink::new(&opts);
            let rep0 = sink_report_dev(300);
            let rep1 = sink_report_dev(400);
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err);
            let r0 = sink.emit(rep0, 300);
            let r1 = sink.emit(rep1, 400);
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert!(r0);
            assert!(r1);
            assert!(read_scratch(&out).starts_with("--- refresh 1 @ "));
            assert_eq!(
                read_scratch(&err),
                "memveil top: --device 'nope' matches no known device\n"
            );
            return;
        }
        run_child("sink_warns_once_for_unknown_device", &scratch);
    }

    #[test]
    fn sink_known_device_filter_is_quiet() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let err = format!("{dir}/err.txt");
            let opts = TopOptions {
                has_device: true,
                device: "d2".to_string(),
                ..TopOptions::default()
            };
            let mut sink = StdoutSink::new(&opts);
            let rep = sink_report_dev(300);
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err);
            let ok = sink.emit(rep, 300);
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert!(ok);
            assert_eq!(read_scratch(&err), "");
            return;
        }
        run_child("sink_known_device_filter_is_quiet", &scratch);
    }

    #[test]
    fn filter_resolves_catalog_id_and_name() {
        let mut rep = Report::default();
        rep.devices.push(DeviceEntry {
            device_id: "d9".to_string(),
            name: "disk9".to_string(),
            ..DeviceEntry::default()
        });
        assert!(device_filter_resolves(&rep, ""));
        assert!(device_filter_resolves(&rep, "d9"));
        assert!(device_filter_resolves(&rep, "disk9"));
        assert!(!device_filter_resolves(&rep, "nope"));
    }

    #[test]
    fn filter_resolves_observed_metric_id() {
        let rep = sink_report_dev(300);
        assert!(device_filter_resolves(&rep, "d1"));
        assert!(device_filter_resolves(&rep, "d2"));
        assert!(!device_filter_resolves(&rep, "nope"));
    }

    fn refresh_session() -> Session {
        let mut s = Session {
            session_id: "refresh".to_string(),
            synthetic: true,
            product_version: "0.0.0".to_string(),
            env_mode: "unknown".to_string(),
            env_detection: "unverified".to_string(),
            env_attestation: "not_performed".to_string(),
            capture_mode: "replay".to_string(),
            window_start_ns: 100,
            window_end_ns: 1000,
            finalized: true,
            ..Session::default()
        };
        for q in [
            &mut s.q_detail,
            &mut s.q_aggregate,
            &mut s.q_correlation,
            &mut s.q_terminal,
        ] {
            q.status = "complete_for_scope".to_string();
            q.has_loss_count = true;
            q.loss_count = 0;
            q.scope = "sc".to_string();
            q.reason = "rs".to_string();
        }
        s.q_baseline.status = "not_applicable".to_string();
        s.q_baseline.scope = "sc".to_string();
        s.q_baseline.reason = "rs".to_string();
        s
    }

    fn refresh_map(op: &str, mapping: &str, ts: u64, seq: u64) -> Event {
        Event {
            session_id: "refresh".to_string(),
            seq,
            ts_ns: ts,
            kind: "map_result".to_string(),
            source_hook: "h".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            map_result: crate::model::event::MapResult {
                operation_id: op.to_string(),
                success: true,
                has_mapping_id: true,
                mapping_id: mapping.to_string(),
                has_mapped_bytes: true,
                mapped_bytes: 4096,
                ..crate::model::event::MapResult::default()
            },
            ..Event::default()
        }
    }

    fn refresh_pool(pool: &str, seq: u64, ts: u64) -> Event {
        Event {
            session_id: "refresh".to_string(),
            seq,
            ts_ns: ts,
            kind: "pool_sample".to_string(),
            source_hook: "h".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            pool: crate::model::event::PoolSample {
                pool_id: pool.to_string(),
                has_used: true,
                used_bytes: 900,
                has_capacity: true,
                capacity_bytes: 1000,
                unit: "bytes".to_string(),
                ..crate::model::event::PoolSample::default()
            },
            ..Event::default()
        }
    }

    fn refresh_find(rows: &[Metric], name: &str) -> Metric {
        rows.iter()
            .find(|m| m.name == name && !m.has_device_id && !m.has_pool_id)
            .unwrap_or_else(|| panic!("metric not found: {name}"))
            .clone()
    }

    fn refresh_find_pool(rows: &[Metric], name: &str, pool: &str) -> Metric {
        rows.iter()
            .find(|m| m.name == name && m.has_pool_id && m.pool_id == pool)
            .unwrap_or_else(|| panic!("pool metric not found: {name}"))
            .clone()
    }

    #[test]
    fn refresh_snapshots_preserve_later_facts() {
        let mut probed = Analyzer::new(refresh_session());
        probed
            .consume(&sink_attempt("op1", 0, 100))
            .expect("consume");
        probed
            .consume(&refresh_map("op1", "m1", 150, 1))
            .expect("consume");
        probed
            .consume(&refresh_pool("p1", 2, 160))
            .expect("consume");
        probed
            .consume(&refresh_pool("p1", 3, 170))
            .expect("consume");
        probed.snapshot(300, false).expect("snapshot");
        probed.snapshot(500, true).expect("snapshot");
        probed
            .consume(&refresh_pool("p1", 4, 180))
            .expect("consume");
        probed.snapshot(700, false).expect("snapshot");
        let fin = probed.finish(1000, false).expect("finish");
        let mut fresh = Analyzer::new(refresh_session());
        fresh
            .consume(&sink_attempt("op1", 0, 100))
            .expect("consume");
        fresh
            .consume(&refresh_map("op1", "m1", 150, 1))
            .expect("consume");
        fresh.consume(&refresh_pool("p1", 2, 160)).expect("consume");
        fresh.consume(&refresh_pool("p1", 3, 170)).expect("consume");
        fresh.consume(&refresh_pool("p1", 4, 180)).expect("consume");
        let want = fresh.finish(1000, false).expect("finish");
        assert_eq!(fin.metrics.len(), want.metrics.len());
        for (got, exp) in fin.metrics.iter().zip(want.metrics.iter()) {
            assert_eq!(got.name, exp.name);
            assert_eq!(got.has_value, exp.has_value);
            if got.has_value {
                assert_eq!(got.value, exp.value);
            }
            assert_eq!(got.coverage, exp.coverage);
        }
        let live = refresh_find(&fin.metrics, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 4096);
        let streak = refresh_find_pool(&fin.metrics, "pool_pressure_samples", "p1");
        assert_eq!(streak.value, 3);
    }

    #[test]
    fn filter_suffix_clean() {
        assert_eq!(filter_header_suffix(""), "");
        assert_eq!(filter_header_suffix("d1"), " [device: d1]");
    }

    fn hostile_filter() -> String {
        String::from_utf8(vec![
            0x61, 0x1b, 0x5b, 0x32, 0x4a, 0x0a, 0x62, 0x09, 0x63, 0x0d, 0x64, 0x07, 0x65, 0x7f,
            0x66,
        ])
        .expect("utf-8")
    }

    fn hostile_escaped() -> String {
        "a�[2J\\nb\\tc\\rd�e�f".to_string()
    }

    #[test]
    fn filter_suffix_escapes_controls() {
        assert_eq!(
            filter_header_suffix(&hostile_filter()),
            format!(" [device: {}]", hostile_escaped())
        );
    }

    #[test]
    fn sink_header_displays_filter() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let opts = TopOptions {
                has_device: true,
                device: "d1".to_string(),
                ..TopOptions::default()
            };
            let mut sink = StdoutSink::new(&opts);
            let rep = sink_report(200);
            let saved = redirect_fd(1, &out);
            let ok = sink.emit(rep, 200);
            restore_fd(1, saved);
            assert!(ok);
            let text = read_scratch(&out);
            let head = text.split('\n').next().expect("header");
            assert_eq!(head, "--- refresh 1 @ 200 ns --- [device: d1]");
            return;
        }
        run_child("sink_header_displays_filter", &scratch);
    }

    #[test]
    fn sink_header_escapes_hostile_filter() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let err = format!("{dir}/err.txt");
            let opts = TopOptions {
                has_device: true,
                device: hostile_filter(),
                ..TopOptions::default()
            };
            let mut sink = StdoutSink::new(&opts);
            let rep = sink_report(200);
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err);
            let ok = sink.emit(rep, 200);
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert!(ok);
            let text = read_scratch(&out);
            let head = text.split('\n').next().expect("header");
            assert_eq!(
                head,
                format!("--- refresh 1 @ 200 ns --- [device: {}]", hostile_escaped())
            );
            assert!(!text.as_bytes().contains(&0x1b));
            assert!(!text.as_bytes().contains(&0x7f));
            assert_eq!(
                read_scratch(&err),
                format!(
                    "memveil top: --device '{}' matches no known device\n",
                    hostile_escaped()
                )
            );
            return;
        }
        run_child("sink_header_escapes_hostile_filter", &scratch);
    }

    fn snapshot_analyzer() -> Analyzer {
        let mut s = live_template();
        s.window_start_ns = 100;
        s.window_end_ns = u64::MAX;
        let mut a = Analyzer::new(s);
        a.consume(&sink_attempt("op1", 0, 100)).expect("consume");
        a.consume(&sink_attempt("op2", 1, 200)).expect("consume");
        a
    }

    #[test]
    fn replay_header_displays_filter() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let opts = TopOptions {
                has_device: true,
                device: "d1".to_string(),
                ..TopOptions::default()
            };
            let mut a = snapshot_analyzer();
            let mut watch = FilterWatch::new(&opts);
            let saved = redirect_fd(1, &out);
            let rc = snapshot_block(&mut a, &opts, 200, 1, &mut watch);
            restore_fd(1, saved);
            assert_eq!(rc, 0);
            let text = read_scratch(&out);
            let head = text.split('\n').next().expect("header");
            assert_eq!(head, "--- refresh 1 @ 200 ns --- [device: d1]");
            return;
        }
        run_child("replay_header_displays_filter", &scratch);
    }

    #[test]
    fn replay_warns_once_for_unknown_device() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let err = format!("{dir}/err.txt");
            let opts = TopOptions {
                has_device: true,
                device: "nope".to_string(),
                ..TopOptions::default()
            };
            let mut a = snapshot_analyzer();
            let mut watch = FilterWatch::new(&opts);
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err);
            let r0 = snapshot_block(&mut a, &opts, 150, 1, &mut watch);
            let r1 = snapshot_block(&mut a, &opts, 200, 2, &mut watch);
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert_eq!(r0, 0);
            assert_eq!(r1, 0);
            let text = read_scratch(&out);
            assert!(text.contains("--- refresh 1 @ 150 ns --- [device: nope]"));
            assert!(text.contains("--- refresh 2 @ 200 ns --- [device: nope]"));
            assert!(!text.contains("{device="));
            assert!(text.contains("bounce_attempts = 2"));
            assert_eq!(
                read_scratch(&err),
                "memveil top: --device 'nope' matches no known device\n"
            );
            return;
        }
        run_child("replay_warns_once_for_unknown_device", &scratch);
    }

    #[test]
    fn replay_known_device_filter_is_quiet() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let err = format!("{dir}/err.txt");
            let opts = TopOptions {
                has_device: true,
                device: "d1".to_string(),
                ..TopOptions::default()
            };
            let mut a = snapshot_analyzer();
            let mut watch = FilterWatch::new(&opts);
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err);
            let rc = snapshot_block(&mut a, &opts, 200, 1, &mut watch);
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert_eq!(rc, 0);
            assert!(read_scratch(&out).contains("{device=d1}"));
            assert_eq!(read_scratch(&err), "");
            return;
        }
        run_child("replay_known_device_filter_is_quiet", &scratch);
    }

    #[test]
    fn replay_later_match_shows_rows() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let err = format!("{dir}/err.txt");
            let opts = TopOptions {
                has_device: true,
                device: "d2".to_string(),
                ..TopOptions::default()
            };
            let mut s = live_template();
            s.window_start_ns = 100;
            s.window_end_ns = u64::MAX;
            let mut a = Analyzer::new(s);
            a.consume(&sink_attempt("op1", 0, 100)).expect("consume");
            let mut watch = FilterWatch::new(&opts);
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err);
            let r0 = snapshot_block(&mut a, &opts, 150, 1, &mut watch);
            let mut e1 = sink_attempt("op2", 1, 200);
            e1.bounce.device_id = "d2".to_string();
            a.consume(&e1).expect("consume");
            let r1 = snapshot_block(&mut a, &opts, 250, 2, &mut watch);
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert_eq!(r0, 0);
            assert_eq!(r1, 0);
            let text = read_scratch(&out);
            let parts: Vec<&str> = text.split("--- refresh ").collect();
            assert_eq!(parts.len(), 3);
            assert!(!parts[1].contains("{device="));
            assert!(parts[2].contains("{device=d2}"));
            assert_eq!(
                read_scratch(&err),
                "memveil top: --device 'd2' matches no known device\n"
            );
            return;
        }
        run_child("replay_later_match_shows_rows", &scratch);
    }

    #[test]
    fn sink_later_match_shows_rows() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let err = format!("{dir}/err.txt");
            let opts = TopOptions {
                has_device: true,
                device: "d2".to_string(),
                ..TopOptions::default()
            };
            let mut sink = StdoutSink::new(&opts);
            let rep0 = sink_report(300);
            let rep1 = sink_report_dev(400);
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err);
            let r0 = sink.emit(rep0, 300);
            let r1 = sink.emit(rep1, 400);
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert!(r0);
            assert!(r1);
            let text = read_scratch(&out);
            let parts: Vec<&str> = text.split("--- refresh ").collect();
            assert_eq!(parts.len(), 3);
            assert!(!parts[1].contains("{device="));
            assert!(parts[2].contains("{device=d2}"));
            assert_eq!(
                read_scratch(&err),
                "memveil top: --device 'd2' matches no known device\n"
            );
            return;
        }
        run_child("sink_later_match_shows_rows", &scratch);
    }

    #[test]
    fn watch_exact_id_and_name_are_quiet() {
        let mut rep = Report::default();
        rep.devices.push(DeviceEntry {
            device_id: "d9".to_string(),
            name: "disk9".to_string(),
            ..DeviceEntry::default()
        });
        let mut opts = TopOptions {
            has_device: true,
            device: "d9".to_string(),
            ..TopOptions::default()
        };
        let mut w0 = FilterWatch::new(&opts);
        assert_eq!(w0.warn_for(&rep), "");
        opts.device = "disk9".to_string();
        let mut w1 = FilterWatch::new(&opts);
        assert_eq!(w1.warn_for(&rep), "");
        opts.device = "nope".to_string();
        let mut w2 = FilterWatch::new(&opts);
        assert_eq!(
            w2.warn_for(&rep),
            "memveil top: --device 'nope' matches no known device\n"
        );
        assert_eq!(w2.warn_for(&rep), "");
    }

    #[test]
    fn watch_control_byte_name_matches_exactly() {
        let mut rep = Report::default();
        rep.devices.push(DeviceEntry {
            device_id: "d9".to_string(),
            name: hostile_filter(),
            ..DeviceEntry::default()
        });
        let opts = TopOptions {
            has_device: true,
            device: hostile_filter(),
            ..TopOptions::default()
        };
        let mut watch = FilterWatch::new(&opts);
        assert_eq!(watch.warn_for(&rep), "");
    }

    #[test]
    fn sink_filtered_block_keeps_global_findings() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let opts = TopOptions {
                has_device: true,
                device: "d1".to_string(),
                ..TopOptions::default()
            };
            let mut sink = StdoutSink::new(&opts);
            let mut rep = sink_report_dev(200);
            rep.findings.push(Finding {
                code: "PROBE_FINDING".to_string(),
                severity: "informational".to_string(),
                explanation: "probe".to_string(),
                evidence_refs: Vec::new(),
                scope: "global".to_string(),
                limitations: "none".to_string(),
            });
            let saved = redirect_fd(1, &out);
            let ok = sink.emit(rep, 200);
            restore_fd(1, saved);
            assert!(ok);
            let text = read_scratch(&out);
            let head = text.split('\n').next().expect("header");
            assert_eq!(head, "--- refresh 1 @ 200 ns --- [device: d1]");
            assert!(text.contains("PROBE_FINDING"));
            return;
        }
        run_child("sink_filtered_block_keeps_global_findings", &scratch);
    }

    #[test]
    fn finish_live_warns_without_prefixes() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let err = format!("{dir}/err.txt");
            let cap = repo("tests/fixtures/attempts");
            let opts = TopOptions {
                has_device: true,
                device: "nope".to_string(),
                ..TopOptions::default()
            };
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err);
            let rc = finish_live(&cap, &opts, 0, 0);
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert_eq!(rc, 0);
            let text = read_scratch(&out);
            assert!(text.contains("[device: nope]"));
            assert!(!text.contains("{device="));
            assert_eq!(
                read_scratch(&err),
                "memveil top: --device 'nope' matches no known device\n"
            );
            return;
        }
        run_child("finish_live_warns_without_prefixes", &scratch);
    }

    fn unobserved_copy() -> Event {
        Event {
            session_id: "attempts-3-session".to_string(),
            seq: 1,
            ts_ns: 1100000000,
            kind: "copy".to_string(),
            source_hook: "synthetic-test-adapter:copy".to_string(),
            source_backend: "synthetic".to_string(),
            source_profile_id: "synthetic-lifecycle-1".to_string(),
            source_measurement: "derived".to_string(),
            source_correlation: "direct".to_string(),
            ..Event::default()
        }
    }

    /// Reducer stub that fails every consume with a mappings-style message.
    ///
    /// Both replay loops take any reducer behind the module's narrow
    /// trait, so this drives the real consume arms without a capture
    /// file: no file can carry a consume violation past the event
    /// parser. Snapshot and finish panic when reached, so a loop that
    /// consults the reducer out of order fails loudly.
    struct FailingReducer {
        message: String,
    }

    impl super::TopReducer for FailingReducer {
        fn consume(&mut self, _ev: &Event) -> Result<(), String> {
            Err(self.message.clone())
        }

        fn snapshot(&mut self, _horizon_ns: u64, _partial: bool) -> Result<Report, String> {
            panic!("snapshot must not run before the failing consume");
        }

        fn finish(&mut self, _end_ns: u64, _partial: bool) -> Result<Report, String> {
            panic!("finish must not run after the failed consume");
        }
    }

    #[test]
    fn consume_failure_renders_bare_message() {
        // The mappings reducer rejects executed copies without an
        // observed measurement with a bare generic error (Mojo
        // analysis/mappings.mojo consume raises Error, whose string
        // form is the message alone), so top's consume arms print
        // the message without the AnalysisError(...) wrapper the
        // finish arms use. No capture file can carry that violation
        // past the event parser, so the stub drives both real arms
        // (drain and finish_after_signal) with the exact trigger
        // message pinned below.
        let mut probe = Analyzer::new(live_template());
        let message = probe
            .consume(&unobserved_copy())
            .expect_err("unobserved copy fails")
            .message;
        assert_eq!(message, "executed copies require observed measurement");

        let scratch = TestDir::create("memveil-top-consume").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let cap = repo("tests/fixtures/attempts");
            let opts = TopOptions::default();
            let limits = ReaderLimits {
                max_session_bytes: opts.max_session_bytes,
                max_line_bytes: opts.max_line_bytes,
                max_events_bytes: opts.max_events_bytes,
            };
            let want = format!("memveil top: cannot reduce capture: {message}\n");

            // Drain arm: no refresh is due before the first event,
            // so the failing consume is the first reducer call.
            let out = format!("{dir}/drain-out.txt");
            let err_path = format!("{dir}/drain-err.txt");
            let mut reader = read_capture(&cap, false, limits).expect("fixture reads");
            let mut stub = FailingReducer {
                message: message.clone(),
            };
            let mut signal = LiveSignalSource::new();
            let mut clock = MonoClock::new();
            let mut cursor = BoundaryCursor::new(0, 0, 1);
            let mut watch = FilterWatch::new(&opts);
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err_path);
            let rc = drain(
                &mut reader,
                &mut stub,
                &opts,
                &mut signal,
                &mut clock,
                &mut cursor,
                0,
                &mut watch,
            );
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert_eq!(rc, crate::cli::report::EXIT_INVALID);
            let stderr = read_scratch(&err_path);
            assert_eq!(stderr, want);
            assert!(!stderr.contains("AnalysisError("), "{stderr}");
            assert_eq!(read_scratch(&out), "");

            // Finish-after-signal arm: same failure, same bytes.
            let out = format!("{dir}/finish-out.txt");
            let err_path = format!("{dir}/finish-err.txt");
            let mut reader = read_capture(&cap, false, limits).expect("fixture reads");
            let mut stub = FailingReducer {
                message: message.clone(),
            };
            let mut watch = FilterWatch::new(&opts);
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err_path);
            let rc = finish_after_signal(&mut reader, &mut stub, &opts, 0, &mut watch, -1, "");
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert_eq!(rc, crate::cli::report::EXIT_INVALID);
            let stderr = read_scratch(&err_path);
            assert_eq!(stderr, want);
            assert!(!stderr.contains("AnalysisError("), "{stderr}");
            assert_eq!(read_scratch(&out), "");
            return;
        }
        run_child("consume_failure_renders_bare_message", &scratch);
    }

    #[test]
    fn unobserved_copy_rejected_at_read() {
        // The shared event parser rejects the violating line at read
        // time (Mojo model/event.mojo copy gate), so a capture file
        // carrying an unobserved copy fails the read in both
        // implementations with the exact bytes below, verified
        // against build/mojo-memveil-compare. The consume arms
        // themselves are pinned by consume_failure_renders_bare_message.
        let scratch = TestDir::create("memveil-top-consume").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let cap = format!("{dir}/cap");
            std::fs::create_dir_all(&cap).expect("capture dir");
            let session = repo("tests/fixtures/attempts/session.json");
            std::fs::copy(&session, format!("{cap}/session.json")).expect("session copy");
            let line = "{\"schema_version\": \"0.1.1\", \"session_id\": \"attempts-3-session\", \"seq\": \"1\", \"ts_ns\": \"1100000000\", \"kind\": \"copy\", \"source\": {\"hook\": \"synthetic-test-adapter:copy\", \"backend\": \"synthetic\", \"profile_id\": \"synthetic-lifecycle-1\", \"measurement\": \"derived\", \"correlation\": \"direct\"}, \"data\": {\"operation_id\": \"op-10\", \"mapping_id\": \"m-1\", \"direction\": \"original_to_bounce\", \"bytes\": \"4096\"}}\n";
            std::fs::write(format!("{cap}/events.ndjson"), line).expect("events write");
            let out = format!("{dir}/out.txt");
            let err_path = format!("{dir}/err.txt");
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err_path);
            let rc = run_top(std::slice::from_ref(&cap));
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            // The shared event parser rejects the violating line at
            // read time (Mojo model/event.mojo copy gate), so the
            // consume arm is unreachable from any capture file and
            // the Mojo binary cannot render it either: both fail the
            // read with these exact bytes, verified against
            // build/mojo-memveil-compare.
            assert_eq!(rc, crate::cli::report::EXIT_INVALID);
            let want = "memveil top: cannot read capture: line 1: ValidationError(what=copy.source.measurement, message=executed copies require observed measurement)\n";
            assert_eq!(read_scratch(&err_path), want);
            assert_eq!(read_scratch(&out), "");
            if let Some(bin) = std::env::var_os("MEMVEIL_MOJO_BIN") {
                let mojo = std::process::Command::new(&bin)
                    .arg("top")
                    .arg(&cap)
                    .output()
                    .expect("mojo top runs");
                assert_eq!(mojo.status.code(), Some(rc as i32));
                assert_eq!(mojo.stderr, want.as_bytes());
                assert!(mojo.stdout.is_empty());
            } else {
                eprintln!("skip: MEMVEIL_MOJO_BIN unset");
            }
            return;
        }
        run_child("unobserved_copy_rejected_at_read", &scratch);
    }

    #[test]
    fn finish_live_silent_after_prefixes() {
        let scratch = TestDir::create("memveil-top-sink").expect("scratch");
        if std::env::var("MEMVEIL_TOP_CHILD").is_ok() {
            let dir = child_scratch().expect("scratch env");
            let out = format!("{dir}/out.txt");
            let err = format!("{dir}/err.txt");
            let cap = repo("tests/fixtures/attempts");
            let opts = TopOptions {
                has_device: true,
                device: "nope".to_string(),
                ..TopOptions::default()
            };
            let saved_out = redirect_fd(1, &out);
            let saved_err = redirect_fd(2, &err);
            let rc = finish_live(&cap, &opts, 1, 0);
            restore_fd(1, saved_out);
            restore_fd(2, saved_err);
            assert_eq!(rc, 0);
            assert_eq!(read_scratch(&err), "");
            return;
        }
        run_child("finish_live_silent_after_prefixes", &scratch);
    }
}
