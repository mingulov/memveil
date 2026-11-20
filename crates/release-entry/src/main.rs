// SPDX-License-Identifier: GPL-3.0-or-later
//! Release-entry CLI: full payload closure and frozen SBOM emit.
//!
//! Usage:
//!   memveil-release-entry payload-closure --bundle B --deb D --rpm R [--manifest M]
//!   memveil-release-entry sbom-emit --manifest M --bundle B --deb D --rpm R
//!       --lock L --ebpf-lock E --out S
//! `payload-closure` prints the canonical JSON closure to stdout;
//! `sbom-emit` writes the SPDX document once. Exit 0 on success, 1
//! on a verification failure, 2 on invalid usage.

use memveil_release_entry::collect_full;
use memveil_release_entry::emit_frozen;
use memveil_release_entry::manifest_from_bundle;
use memveil_release_entry::render_closure;
use std::collections::BTreeMap;
use std::path::PathBuf;

const USAGE: &str = "usage: memveil-release-entry payload-closure \
    --bundle B --deb D --rpm R [--manifest M]\n       \
    memveil-release-entry sbom-emit --manifest M --bundle B --deb D --rpm R \
    --lock L --ebpf-lock E --out S [--created EPOCH]\n";

fn usage_error(detail: &str) -> ! {
    eprintln!("memveil-release-entry: {detail}\n{USAGE}");
    std::process::exit(2);
}

/// `--flag value` pairs into a map; duplicates and strays fail.
fn flags(argv: &[String]) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let mut rest = argv;
    while let Some((flag, tail)) = rest.split_first() {
        if !flag.starts_with("--") {
            usage_error(&format!("unexpected argument: {flag}"));
        }
        let Some((value, tail)) = tail.split_first() else {
            usage_error(&format!("{flag} needs a value"));
        };
        if value.starts_with("--") || found.contains_key(flag) {
            usage_error(&format!("bad {flag} value"));
        }
        found.insert(flag.clone(), value.clone());
        rest = tail;
    }
    found
}

fn required(flags: &BTreeMap<String, String>, name: &str) -> PathBuf {
    match flags.get(name) {
        Some(value) => PathBuf::from(value),
        None => usage_error(&format!("{name} is required")),
    }
}

fn payload_closure(argv: &[String]) {
    let flags = flags(argv);
    for flag in flags.keys() {
        if !["--bundle", "--deb", "--rpm", "--manifest"].contains(&flag.as_str()) {
            usage_error(&format!("unexpected flag: {flag}"));
        }
    }
    let bundle = required(&flags, "--bundle");
    let deb = required(&flags, "--deb");
    let rpm = required(&flags, "--rpm");
    let text = match flags.get("--manifest") {
        Some(path) => std::fs::read_to_string(path).unwrap_or_else(|err| {
            eprintln!("memveil-release-entry: sbom: cannot read {path}: {err}");
            std::process::exit(1);
        }),
        None => match manifest_from_bundle(&bundle) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("memveil-release-entry: {err}");
                std::process::exit(1);
            }
        },
    };
    match collect_full(&bundle, &deb, &rpm, &text) {
        Ok(entries) => print!("{}", render_closure(&entries)),
        Err(err) => {
            eprintln!("memveil-release-entry: {err}");
            std::process::exit(1);
        }
    }
}

fn sbom_emit(argv: &[String]) {
    let flags = flags(argv);
    for flag in flags.keys() {
        if ![
            "--manifest",
            "--bundle",
            "--deb",
            "--rpm",
            "--lock",
            "--ebpf-lock",
            "--out",
            "--created",
        ]
        .contains(&flag.as_str())
        {
            usage_error(&format!("unexpected flag: {flag}"));
        }
    }
    let result = emit_frozen(
        &required(&flags, "--manifest"),
        &required(&flags, "--bundle"),
        &required(&flags, "--deb"),
        &required(&flags, "--rpm"),
        &required(&flags, "--lock"),
        &required(&flags, "--ebpf-lock"),
        &required(&flags, "--out"),
        flags.get("--created").map(String::as_str),
    );
    if let Err(err) = result {
        eprintln!("memveil-release-entry: {err}");
        std::process::exit(1);
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() >= 2 && (argv[1] == "--help" || argv[1] == "-h") {
        print!("{USAGE}");
        return;
    }
    if argv.len() < 2 {
        usage_error("a subcommand is required");
    }
    match argv[1].as_str() {
        "payload-closure" => payload_closure(&argv[2..]),
        "sbom-emit" => sbom_emit(&argv[2..]),
        other => usage_error(&format!("unknown subcommand: {other}")),
    }
}
