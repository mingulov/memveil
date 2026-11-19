// SPDX-License-Identifier: GPL-3.0-or-later
//! MemVeil command line: capture, offline inspection, passive doctor.

use memveil::ENGINE_VERSION;
use memveil::capture::collector::EXIT_REFUSAL;
use memveil::cli::bind::run_bind;
use memveil::cli::doctor::run_doctor_os;
use memveil::cli::qualify::run_qualify;
use memveil::cli::record::run_record;
use memveil::cli::report::{EXIT_INTERNAL, EXIT_INVALID, EXIT_OK, run_report_os, write_stderr};
use memveil::cli::top::{run_top, run_top_os};
use memveil::platform::runtime::embedded_manifest;
use memveil::platform::signal::{ensure_inherited_signal_block, ignore_sigpipe};
use memveil::platform::stdout::write_stdout;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
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

/// Top-level dispatch decision over raw argv words (minus argv[0]).
enum Dispatch {
    /// Print usage to stderr; exit 2.
    InvalidUsage,
    /// Print usage to stdout; exit 0.
    Help,
    /// Print the engine version to stdout; exit 0.
    Version,
    /// Print the embedded BPF manifest to stdout; exit 0.
    ///
    /// Hidden packager surface (kept out of usage text):
    /// one `channel digest` line per channel, naming the
    /// build-baked SHA-256 of the bytes `embedded_object`
    /// serves.
    EmbeddedManifest,
    /// Run one verb with decoded UTF-8 arguments. `raw` is the
    /// byte-exact argv tail (verb word plus rest) the signal
    /// re-exec forwards; decoded `rest` never reaches `execv`.
    Run {
        verb: String,
        rest: Vec<String>,
        raw: Vec<OsString>,
    },
    /// Run one byte-wise verb with raw argv words.
    RunOs { verb: String, rest: Vec<OsString> },
}

/// Classify raw argv words without panicking on non-UTF-8 bytes.
///
/// Linux passes arbitrary bytes, and `std::env::args()` panics on
/// undecodable words. The dispatcher compares byte-wise like the Mojo
/// original: an undecodable verb matches nothing and falls through to
/// usage (exit 2), while `help` and `version` ignore trailing words
/// before any further decoding, undecodable ones included. `report`
/// and `doctor` take raw words and handle undecodable bytes the way
/// Mojo does (open the raw path, silence an unrenderable echo);
/// `top` replays raw words the same way but keeps live
/// collection on text. Every other subcommand takes text, so a
/// consumed word that cannot decode is a normal usage error
/// (exit 2), never a panic.
/// One exception, matching Mojo's per-verb pre-parse scan: when
/// any word is `--help` or `-h`, help wins over undecodable
/// siblings and the verb runs (it prints help and returns before
/// consuming any word), so undecodable words decode lossily for
/// the verb. The signal re-exec still forwards the raw words:
/// lossy decoding can expand one ignored word past
/// `MAX_ARG_STRLEN` (44,000 `0xff` bytes become 132,000) and
/// trip `E2BIG` before help ever runs, while the Mojo `argv()`
/// preserves raw bytes and its re-exec succeeds.
fn dispatch(raw: &[OsString]) -> Dispatch {
    let verb_os = match raw.first() {
        None => return Dispatch::InvalidUsage,
        Some(word) => word,
    };
    let verb = match verb_os.to_str() {
        None => return Dispatch::InvalidUsage,
        Some(word) => word,
    };
    if verb == "help" || verb == "--help" || verb == "-h" {
        return Dispatch::Help;
    }
    // `version` ignores trailing arguments and always prints the
    // engine version (parity with the Mojo dispatcher, which takes
    // the same branch before argument parsing): extra words after
    // `memveil --version` are accepted, not an error.
    if verb == "version" || verb == "--version" {
        return Dispatch::Version;
    }
    // Hidden packager probe: trailing words are ignored like
    // `version`, before any further decoding.
    if verb == "--embedded-manifest" {
        return Dispatch::EmbeddedManifest;
    }
    if verb == "report" || verb == "doctor" {
        return Dispatch::RunOs {
            verb: verb.to_string(),
            rest: raw[1..].to_vec(),
        };
    }
    match verb {
        "record" | "top" | "qualify" | "bind-profile" => {}
        _ => return Dispatch::InvalidUsage,
    }
    // Mojo's per-verb entry scans every word for --help/-h before
    // parsing, with a byte-wise comparison an undecodable sibling
    // never trips. Detect that here, before UTF-8 decoding, and
    // forward lossily: the verb prints help and returns before
    // consuming any word, so the lossy words are never used.
    let help_wins = raw[1..]
        .iter()
        .any(|word| word.as_bytes() == b"--help" || word.as_bytes() == b"-h");
    let mut rest = Vec::with_capacity(raw.len().saturating_sub(1));
    for arg in &raw[1..] {
        match arg.to_str() {
            Some(text) => rest.push(text.to_string()),
            None if help_wins => rest.push(arg.to_string_lossy().into_owned()),
            None if verb == "top" => {
                // Replay opens the raw directory like Mojo; a live
                // run keeps text words and stays a usage error.
                return Dispatch::RunOs {
                    verb: verb.to_string(),
                    rest: raw[1..].to_vec(),
                };
            }
            None => return Dispatch::InvalidUsage,
        }
    }
    Dispatch::Run {
        verb: verb.to_string(),
        rest,
        raw: raw.to_vec(),
    }
}

fn main() -> ExitCode {
    if !ignore_sigpipe() {
        let _ = write_stderr("memveil: cannot ignore SIGPIPE\n");
        return ExitCode::from(EXIT_INTERNAL as u8);
    }
    let raw: Vec<OsString> = std::env::args_os().skip(1).collect();
    match dispatch(&raw) {
        Dispatch::InvalidUsage => {
            let _ = write_stderr(&top_usage());
            ExitCode::from(EXIT_INVALID as u8)
        }
        Dispatch::Help => match write_stdout(&top_usage()) {
            Ok(()) => ExitCode::from(EXIT_OK as u8),
            Err(_) => stdout_failed(),
        },
        Dispatch::Version => match write_stdout(&format!("{ENGINE_VERSION}\n")) {
            Ok(()) => ExitCode::from(EXIT_OK as u8),
            Err(_) => stdout_failed(),
        },
        Dispatch::EmbeddedManifest => {
            let mut text = String::new();
            for (channel, digest) in embedded_manifest() {
                text.push_str(channel);
                text.push(' ');
                text.push_str(digest);
                text.push('\n');
            }
            match write_stdout(&text) {
                Ok(()) => ExitCode::from(EXIT_OK as u8),
                Err(_) => stdout_failed(),
            }
        }
        Dispatch::RunOs { verb, rest } => {
            let code = if verb == "doctor" {
                run_doctor_os(&rest)
            } else if verb == "top" {
                run_top_os(&rest)
            } else {
                run_report_os(&rest)
            };
            ExitCode::from(code as u8)
        }
        Dispatch::Run { verb, rest, raw } => run_text_verb(&verb, &rest, &raw),
    }
}

/// Run one decoded-text verb: the signal guard, then the verb.
fn run_text_verb(verb: &str, rest: &[String], raw: &[OsString]) -> ExitCode {
    // Every collector-driving verb needs all runtime threads to
    // inherit blocked stop signals, otherwise a SIGINT lands in a
    // worker and never reaches signalfd. The guard applies to the
    // help path too, exactly as the Mojo entry does (a preset
    // sentinel with an unblocked mask refuses even --help).
    if verb == "record" || verb == "top" || verb == "qualify" {
        // The re-exec guard resolves /proc/self/exe for argv[0] and
        // only forwards words from index 1 on, so element 0 is a
        // placeholder and the raw verb and rest words follow.
        // Raw bytes are required here, never the decoded rest:
        // see the dispatch note on lossy E2BIG expansion.
        let mut full = Vec::with_capacity(raw.len() + 1);
        full.push(OsString::new());
        full.extend(raw.iter().cloned());
        let note = ensure_inherited_signal_block(&full);
        if !note.is_empty() {
            let _ = write_stderr(&format!("memveil {verb}: {note}\n"));
            return ExitCode::from(EXIT_REFUSAL as u8);
        }
    }
    // Dispatch guarantees one of the four text verbs here;
    // report, doctor, and undecodable top run through the raw arm above.
    let code = if verb == "record" {
        run_record(rest)
    } else if verb == "top" {
        run_top(rest)
    } else if verb == "qualify" {
        run_qualify(rest)
    } else {
        run_bind(rest)
    };
    ExitCode::from(code as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn os(words: &[&[u8]]) -> Vec<OsString> {
        words
            .iter()
            .map(|w| OsString::from_vec(w.to_vec()))
            .collect()
    }

    fn is_invalid(raw: &[OsString]) -> bool {
        matches!(dispatch(raw), Dispatch::InvalidUsage)
    }

    fn is_help(raw: &[OsString]) -> bool {
        matches!(dispatch(raw), Dispatch::Help)
    }

    fn is_version(raw: &[OsString]) -> bool {
        matches!(dispatch(raw), Dispatch::Version)
    }

    fn is_manifest(raw: &[OsString]) -> bool {
        matches!(dispatch(raw), Dispatch::EmbeddedManifest)
    }

    #[test]
    fn empty_and_unknown_verbs_are_invalid_usage() {
        assert!(is_invalid(&[]));
        assert!(is_invalid(&os(&[b"bogus-verb"])));
        assert!(is_invalid(&os(&[b"bogus-verb", b"\xff"])));
    }

    #[test]
    fn undecodable_verb_falls_through_to_usage() {
        // Mojo compares argv byte-wise: a verb that matches nothing
        // prints usage and exits 2 instead of panicking.
        assert!(is_invalid(&os(&[b"\xff"])));
        assert!(is_invalid(&os(&[b"rep\xffrt"])));
        assert!(is_invalid(&os(&[b"\xff", b"report"])));
    }

    #[test]
    fn help_ignores_trailing_words_before_decoding() {
        for verb in [b"help".as_slice(), b"--help", b"-h"] {
            assert!(is_help(&os(&[verb])));
            assert!(is_help(&os(&[verb, b"extra"])));
            assert!(is_help(&os(&[verb, b"\xff"])));
        }
    }

    #[test]
    fn version_ignores_trailing_words_before_decoding() {
        // Parity with the Mojo dispatcher: words after `version`
        // are accepted, never decoded, so even non-UTF-8 bytes
        // print the engine version instead of panicking.
        for verb in [b"version".as_slice(), b"--version"] {
            assert!(is_version(&os(&[verb])));
            assert!(is_version(&os(&[verb, b"extra", b"--bogus"])));
            assert!(is_version(&os(&[verb, b"\xff"])));
        }
    }

    #[test]
    fn embedded_manifest_flag_is_hidden_but_stable() {
        // The packager probe dispatches before decoding and
        // ignores trailing words like `version`, yet stays
        // out of the usage text and disturbs no other verb.
        assert!(is_manifest(&os(&[b"--embedded-manifest"])));
        assert!(is_manifest(&os(&[b"--embedded-manifest", b"extra"])));
        assert!(is_manifest(&os(&[b"--embedded-manifest", b"\xff"])));
        assert!(!top_usage().contains("embedded-manifest"));
        assert!(is_invalid(&os(&[b"--embedded-manifes"])));
        assert!(is_invalid(&os(&[b"--embedded-manifestx"])));
    }

    #[test]
    fn undecodable_consumed_word_is_invalid_usage() {
        // Text subcommands take UTF-8: a consumed non-UTF-8 word is
        // a normal usage error (exit 2), never an args() panic.
        // Report and doctor take raw words (see below), and top
        // replays raw words (see below).
        for verb in [b"record".as_slice(), b"qualify", b"bind-profile"] {
            assert!(is_invalid(&os(&[verb, b"\xff"])), "{verb:?}");
            assert!(
                is_invalid(&os(&[verb, b"--output", b"\xfe\xfd"])),
                "{verb:?}"
            );
        }
    }

    #[test]
    fn help_wins_over_undecodable_siblings() {
        // Mojo's per-verb entry scans every word for --help/-h
        // before parsing with a byte-wise comparison, so an
        // undecodable sibling never blocks help: all four text
        // verbs forward and print help (exit 0) instead of
        // failing usage (exit 2). The flag keeps its bytes and
        // position does not matter.
        for verb in [b"record".as_slice(), b"top", b"qualify", b"bind-profile"] {
            for flag in [b"--help".as_slice(), b"-h"] {
                let shapes: &[&[&[u8]]] = &[
                    &[verb, flag, b"\xff"],
                    &[verb, b"\xff", flag],
                    &[verb, b"\xff", flag, b"\xfe\xfd"],
                ];
                for shape in shapes {
                    match dispatch(&os(shape)) {
                        Dispatch::Run { verb: v, rest, raw } => {
                            assert_eq!(v, String::from_utf8_lossy(verb));
                            let want = String::from_utf8_lossy(flag).into_owned();
                            assert!(rest.contains(&want), "{verb:?} {shape:?}: {rest:?}");
                            // The re-exec tail keeps raw bytes:
                            // the lossy rest never reaches execv.
                            assert_eq!(raw, os(shape), "{verb:?} {shape:?}");
                        }
                        _ => panic!("{verb:?} {shape:?} must dispatch to Run"),
                    }
                }
            }
        }
    }

    #[test]
    fn report_and_doctor_forward_raw_words() {
        // Byte-wise verbs handle undecodable bytes the Mojo way,
        // so dispatch forwards raw words, undecodable ones included.
        for verb in [b"report".as_slice(), b"doctor"] {
            match dispatch(&os(&[verb, b"\xff", b"--flag"])) {
                Dispatch::RunOs { verb: v, rest } => {
                    assert_eq!(v, String::from_utf8_lossy(verb));
                    assert_eq!(rest, os(&[b"\xff", b"--flag"]));
                }
                _ => panic!("{verb:?} must dispatch to RunOs"),
            }
        }
        match dispatch(&os(&[b"doctor"])) {
            Dispatch::RunOs { verb: v, rest } => {
                assert_eq!(v, "doctor");
                assert!(rest.is_empty());
            }
            _ => panic!("bare doctor must dispatch to RunOs"),
        }
    }

    #[test]
    fn top_forwards_raw_words_for_replay() {
        // An undecodable top word replays through raw bytes like
        // Mojo; all-UTF-8 words keep the text path (see below),
        // and --help still wins over undecodable siblings.
        for shape in [
            vec![b"top".as_slice(), b"\xff"],
            vec![b"top", b"--device", b"\xff", b"cap"],
            vec![b"top", b"cap", b"\xfe\xfd"],
        ] {
            match dispatch(&os(&shape)) {
                Dispatch::RunOs { verb, rest } => {
                    assert_eq!(verb, "top");
                    assert_eq!(rest, os(&shape[1..]));
                }
                _ => panic!("{shape:?} must dispatch to RunOs"),
            }
        }
    }

    #[test]
    fn known_verbs_decode_and_forward_rest() {
        for verb in [b"record".as_slice(), b"top", b"qualify", b"bind-profile"] {
            match dispatch(&os(&[verb, b"cap", b"--flag"])) {
                Dispatch::Run { verb: v, rest, raw } => {
                    assert_eq!(v, String::from_utf8_lossy(verb));
                    assert_eq!(rest, vec!["cap".to_string(), "--flag".to_string()]);
                    assert_eq!(raw, os(&[verb, b"cap", b"--flag"]));
                }
                _ => panic!("{verb:?} must dispatch to Run"),
            }
        }
    }

    #[test]
    fn help_path_keeps_max_argstrlen_word_byte_exact() {
        // The re-exec tail must carry the 44,000-byte 0xff word
        // unexpanded: lossy decoding would grow it to 132,000
        // bytes and trip E2BIG before the verb prints help.
        // The verb still runs on the lossy words and returns
        // before consuming any of them.
        let big = vec![0xff; 44_000];
        for verb in [b"record".as_slice(), b"top", b"qualify", b"bind-profile"] {
            let words = os(&[verb, big.as_slice(), b"--help"]);
            match dispatch(&words) {
                Dispatch::Run { verb: v, rest, raw } => {
                    assert_eq!(v, String::from_utf8_lossy(verb), "{verb:?}");
                    assert_eq!(raw, words, "{verb:?}");
                    assert_eq!(raw[1].len(), 44_000, "{verb:?}");
                    assert!(rest.contains(&"--help".to_string()), "{verb:?}");
                }
                _ => panic!("{verb:?} with --help must dispatch to Run"),
            }
        }
    }
}
