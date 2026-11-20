// SPDX-License-Identifier: GPL-3.0-or-later
//! Synthetic seal fixture engine: canned version/help, exit 0.
//!
//! Compiled directly with rustc (no cargo project) by the
//! installed-mapping sealed fixture; the shaped synthetic
//! candidate stages this as bin/memveil so the real packaging
//! scripts (the staged `version` rerun, man generation) and
//! the installed-man leg have runnable bytes. Only the
//! packager-observed surface exists: `version` plus top and
//! per-verb `--help`. Anything else exits 1.

const VERSION: &str = "0.1.0";

const VERBS: [&str; 6] = [
    "record",
    "report",
    "top",
    "doctor",
    "qualify",
    "bind-profile",
];

const TOP_HELP: &str = "\
usage: memveil <record|report|top|doctor|qualify|bind-profile|help|version>

synthetic seal fixture Verbs:
  record synthetic record verb
  report synthetic report verb
  top synthetic top verb
  doctor synthetic doctor verb
  qualify synthetic qualify verb
  bind-profile synthetic bind-profile verb
";

fn verb_help(verb: &str) -> String {
    format!("usage: memveil {verb} [options]\n\nsynthetic {verb} help text\n")
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["version"] => println!("memveil-{VERSION}"),
        ["--help"] => print!("{TOP_HELP}"),
        [verb, "--help"] if VERBS.contains(verb) => print!("{}", verb_help(verb)),
        _ => {
            eprintln!("stub engine: unexpected argv: {argv:?}");
            std::process::exit(1);
        }
    }
}
