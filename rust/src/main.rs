// SPDX-License-Identifier: GPL-3.0-or-later
//! MemVeil command line: capture, offline inspection, passive doctor.

use memveil::ENGINE_VERSION;
use memveil::capture::collector::EXIT_REFUSAL;
use memveil::cli::record::run_record;
use memveil::cli::report::{EXIT_INTERNAL, EXIT_INVALID, EXIT_OK, run_report, write_stderr};
use memveil::platform::signal::{ensure_inherited_signal_block, ignore_sigpipe};
use memveil::platform::stdout::write_stdout;
use std::process::ExitCode;

/// Usage text for the memveil program.
fn top_usage() -> String {
    concat!(
        "usage: memveil <record|report|top|doctor|qualify|bind-profile|help|version> [args]\n",
        "\n",
        "Attempt/lifecycle/copy capture, live and offline summaries, passive host check. Verbs:\n",
        "  record    capture bounce attempts and optional lifecycle/copy channels into a directory.\n",
        "  report    read one capture and print metrics.\n",
        "  top       observe live or replay one capture with periodic summaries.\n",
        "  doctor    inspect the host passively and print capability.\n",
        "  qualify   prove this host and mint a local-auto receipt.\n",
        "  bind-profile mint a bound profile document for this host.\n",
        "  help      print this text.\n",
        "  version   print the engine version.\n",
        "\n",
        "Run 'memveil record --help' for record options.\n",
        "Run 'memveil report --help' for report options.\n",
        "Run 'memveil top --help' for top options.\n",
        "Run 'memveil doctor --help' for doctor options.\n",
        "Run 'memveil qualify --help' for qualify options.\n",
        "Run 'memveil bind-profile --help' for bind options.\n",
    )
    .to_string()
}

/// Report a top-level stdout failure; exit 1.
fn stdout_failed() -> ! {
    let _ = write_stderr("memveil: cannot write stdout\n");
    std::process::exit(EXIT_INTERNAL as i32)
}

fn main() -> ExitCode {
    if !ignore_sigpipe() {
        let _ = write_stderr("memveil: cannot ignore SIGPIPE\n");
        return ExitCode::from(EXIT_INTERNAL as u8);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        let _ = write_stderr(&top_usage());
        return ExitCode::from(EXIT_INVALID as u8);
    }
    let verb = args[0].as_str();
    if verb == "help" || verb == "--help" || verb == "-h" {
        match write_stdout(&top_usage()) {
            Ok(()) => return ExitCode::from(EXIT_OK as u8),
            Err(_) => stdout_failed(),
        }
    }
    if verb == "version" || verb == "--version" {
        match write_stdout(&format!("{ENGINE_VERSION}\n")) {
            Ok(()) => return ExitCode::from(EXIT_OK as u8),
            Err(_) => stdout_failed(),
        }
    }
    // Extension point: top, doctor, qualify, and bind-profile
    // dispatch arms land here once those verbs exist; until
    // then unknown verbs print usage to stderr and exit 2.
    if verb != "report" && verb != "record" {
        let _ = write_stderr(&top_usage());
        return ExitCode::from(EXIT_INVALID as u8);
    }
    let rest = args[1..].to_vec();
    // Extension point: top and qualify join record here; every
    // collector-driving verb needs all runtime threads to
    // inherit blocked stop signals, otherwise a SIGINT lands
    // in a worker and never reaches signalfd.
    if verb == "record" {
        let full: Vec<String> = std::env::args().collect();
        let note = ensure_inherited_signal_block(&full);
        if !note.is_empty() {
            let _ = write_stderr(&format!("memveil {verb}: {note}\n"));
            return ExitCode::from(EXIT_REFUSAL as u8);
        }
    }
    let code = if verb == "record" {
        run_record(&rest)
    } else {
        run_report(&rest)
    };
    ExitCode::from(code as u8)
}
