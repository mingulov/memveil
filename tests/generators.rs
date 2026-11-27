// SPDX-License-Identifier: GPL-3.0-or-later
//! Release-profile and doc-generator gates.
//!
//! The release binary builds, reports its version, and ships
//! stripped; `scripts/gen-man.py` embeds the exact `--help`
//! bytes deterministically; `scripts/gen-completions.py`
//! renders static completions cross-pinned against the live CLI
//! surface; `scripts/gen-docs.py` stages both for packaging.
//!
//! The `FROZEN_*` pins below are independent literals: the guards
//! bind them to the live binary first, then to the generator's own
//! sets, so a CLI change fails naming the exact token until the
//! generator and these pins move together. The version string is
//! always read from the binary's own output, never hardcoded.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

const FROZEN_VERBS: [&str; 8] = [
    "record",
    "report",
    "top",
    "doctor",
    "qualify",
    "bind-profile",
    "help",
    "version",
];
const FROZEN_TOP_FLAGS: [&str; 3] = ["--help", "--version", "-h"];
/// Long flags top --help names outside the top-level surface:
/// the Start line's copy-pasteable commands (--output,
/// --duration) and the disclaimer footer's --strict pointer.
/// None of these is a top-level flag (the live guard still
/// binds FROZEN_TOP_FLAGS alone); they are pinned here so a
/// typo'd example token fails naming it.
const FROZEN_TOP_EXAMPLE_FLAGS: [&str; 3] = ["--output", "--duration", "--strict"];
const FROZEN_FLAGS: [(&str, &[&str]); 6] = [
    (
        "record",
        &[
            "--bridge",
            "--capability",
            "--cp-object",
            "--device",
            "--duration",
            "--help",
            "--journal-callers",
            "--journal-object",
            "--lc-object",
            "--max-events-bytes",
            "--object",
            "--output",
            "--profile",
            "--profiles-dir",
            "--strict",
            "-h",
        ],
    ),
    (
        "report",
        &[
            "--allow-partial",
            "--format",
            "--help",
            "--long-lived-after",
            "--max-events-bytes",
            "--max-line-bytes",
            "--max-session-bytes",
            "--strict",
            "-h",
        ],
    ),
    (
        "top",
        &[
            "--allow-partial",
            "--bridge",
            "--capability",
            "--compact",
            "--cp-object",
            "--device",
            "--duration",
            "--full",
            "--help",
            "--interval",
            "--journal-callers",
            "--journal-object",
            "--lc-object",
            "--long-lived-after",
            "--max-events-bytes",
            "--max-line-bytes",
            "--max-session-bytes",
            "--object",
            "--output",
            "--profile",
            "--profiles-dir",
            "--strict",
            "-h",
        ],
    ),
    (
        "doctor",
        &[
            "--bridge",
            "--capability",
            "--cp-object",
            "--help",
            "--json",
            "--lc-object",
            "--load-check",
            "--object",
            "--profiles-dir",
            "-h",
        ],
    ),
    (
        "qualify",
        &[
            "--bridge",
            "--capability",
            "--cp-object",
            "--help",
            "--journal-callers",
            "--journal-object",
            "--lc-object",
            "--object",
            "--output",
            "--profile",
            "--profiles-dir",
            "-h",
        ],
    ),
    (
        "bind-profile",
        &[
            "--capability",
            "--cp-object",
            "--help",
            "--lc-object",
            "--object",
            "--output",
            "--profile",
            "--profile-id",
            "--profiles-dir",
            "-h",
        ],
    ),
];
const FROZEN_FORMAT_VALUES: [&str; 3] = ["text", "json", "markdown"];
const FROZEN_NOVALUE_FLAGS: [&str; 9] = [
    "--help",
    "--allow-partial",
    "--compact",
    "--full",
    "--json",
    "--load-check",
    "--strict",
    "--journal-callers",
    "-h",
];
const MAN_VERBS: [&str; 6] = [
    "record",
    "report",
    "top",
    "doctor",
    "qualify",
    "bind-profile",
];

fn frozen_flags(verb: &str) -> &'static [&'static str] {
    FROZEN_FLAGS
        .iter()
        .find(|(name, _)| *name == verb)
        .map(|(_, flags)| *flags)
        .expect("tabled verb")
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn scripts_dir() -> PathBuf {
    manifest_dir().join("scripts")
}

fn run(bin: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("cannot run {}: {err}", bin.display()))
}

/// The release binary, built once per test process.
///
/// The build remaps build-machine paths out of the output
/// (home first, checkout last under /build-root, the same
/// pair the BPF build script and the packager apply), so the
/// binary this suite leaves behind stays shippable: the
/// packaging suites reuse the release binary as-is, and a
/// bare rebuild here would dirty the bytes they package.
/// Starts from the flag set Cargo itself would use: the
/// encoded spelling when set, else RUSTFLAGS when set (a
/// set-but-empty channel still shadows the rest), else the
/// config layer carried forward so this export shadows
/// nothing. The remap pair lands exactly once at the end and
/// leaves through the encoded channel alone. A missing or
/// empty HOME contributes no remap.
fn release_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let cargo = std::env::var_os("CARGO").expect("CARGO is set by cargo");
        let root = manifest_dir();
        let mut env =
            memveil_remap_flags::process_env().unwrap_or_else(|err| panic!("remap flags: {err}"));
        memveil_remap_flags::remap_build_paths(&mut env, &root)
            .unwrap_or_else(|err| panic!("remap flags: {err}"));
        let encoded = env
            .get("CARGO_ENCODED_RUSTFLAGS")
            .expect("remap exports the encoded channel");
        let status = Command::new(cargo)
            .arg("build")
            .arg("--release")
            .env_remove("RUSTUP_TOOLCHAIN")
            .env("CARGO_ENCODED_RUSTFLAGS", encoded)
            .env_remove("RUSTFLAGS")
            .current_dir(&root)
            .status()
            .expect("run cargo build --release");
        assert!(status.success(), "cargo build --release failed");
        let debug_bin = PathBuf::from(env!("CARGO_BIN_EXE_memveil"));
        let target = debug_bin
            .parent()
            .and_then(Path::parent)
            .expect("target dir above debug binary");
        let bin = target.join("release").join("memveil");
        assert!(bin.is_file(), "release binary missing: {}", bin.display());
        bin
    })
    .clone()
}

fn run_help(bin: &Path, verb: &str) -> String {
    let mut args = Vec::new();
    if !verb.is_empty() {
        args.push(verb);
    }
    args.push("--help");
    let out = run(bin, &args);
    assert_eq!(out.status.code(), Some(0), "{verb:?} --help exits");
    assert!(out.stderr.is_empty(), "{verb:?} --help is quiet");
    let text = String::from_utf8(out.stdout).expect("--help is UTF-8");
    assert!(!text.trim().is_empty(), "{verb:?} --help prints");
    text
}

/// The version string as the binary itself reports it.
fn live_version(bin: &Path) -> String {
    let out = run(bin, &["version"]);
    assert_eq!(out.status.code(), Some(0), "version exits");
    let text = String::from_utf8(out.stdout).expect("version is UTF-8");
    assert!(!text.trim().is_empty(), "version prints");
    text.trim().to_string()
}

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("memveil-generators-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn is_long_start(byte: u8) -> bool {
    byte.is_ascii_lowercase()
}

fn is_long_rest(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte == b'-'
}

/// Long flags in text, mirroring `--[a-z][a-z-]*`.
fn long_flags(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut found = BTreeSet::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if bytes[i] == b'-' && bytes[i + 1] == b'-' && is_long_start(bytes[i + 2]) {
            let mut end = i + 3;
            while end < bytes.len() && is_long_rest(bytes[end]) {
                end += 1;
            }
            found.insert(text[i..end].to_string());
            i = end;
        } else {
            i += 1;
        }
    }
    found
}

/// Value-taking vs bare flags from the usage synopsis: a flag
/// followed by a metavariable takes a value, a flag followed by
/// another flag, a bracket, or nothing stands bare.
fn synopsis_arity(text: &str, verb: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let para = text.split("\n\n").next().unwrap_or("").replace('\n', " ");
    assert!(para.contains("usage:"), "no synopsis for {verb}");
    let bytes = para.as_bytes();
    let mut takes_value = BTreeSet::new();
    let mut bare = BTreeSet::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if bytes[i] == b'-' && bytes[i + 1] == b'-' && is_long_start(bytes[i + 2]) {
            let mut end = i + 3;
            while end < bytes.len() && is_long_rest(bytes[end]) {
                end += 1;
            }
            let boundary =
                end == bytes.len() || bytes[end].is_ascii_whitespace() || bytes[end] == b']';
            let flag = para[i..end].to_string();
            if boundary {
                let rest: Vec<&str> = para[end..].split_whitespace().collect();
                if rest
                    .first()
                    .is_some_and(|word| !word.starts_with(['-', '[', ']']))
                {
                    takes_value.insert(flag);
                } else {
                    bare.insert(flag);
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    (takes_value, bare)
}

/// The closed `--format` enum from the report synopsis bracket.
fn format_values_from_synopsis(text: &str) -> BTreeSet<String> {
    let para = text.split("\n\n").next().unwrap_or("").replace('\n', " ");
    let open = "[--format ";
    let start = para
        .find(open)
        .unwrap_or_else(|| panic!("no [--format ...] bracket in synopsis: {para:?}"))
        + open.len();
    let rest = &para[start..];
    let end = rest
        .find(']')
        .unwrap_or_else(|| panic!("unterminated [--format bracket: {para:?}"));
    rest[..end].split('|').map(str::to_string).collect()
}

fn check_format_values(verb: &str, live: &BTreeSet<String>) {
    let frozen: BTreeSet<&str> = FROZEN_FORMAT_VALUES.into_iter().collect();
    let seen: BTreeSet<&str> = live.iter().map(String::as_str).collect();
    assert!(
        seen == frozen,
        "memveil {verb}: --format offers {seen:?} vs frozen {frozen:?}"
    );
}

fn usage_verbs(top_help: &str) -> BTreeSet<String> {
    let open = "usage: memveil <";
    let start = top_help.find(open).expect("usage line") + open.len();
    let end = top_help[start..].find('>').expect("usage close") + start;
    top_help[start..end]
        .split('|')
        .map(str::to_string)
        .collect()
}

/// The escaping contract `gen-man.py` implements.
fn roff(line: &str) -> String {
    let out = line.replace('\\', "\\(rs");
    if out.starts_with('.') || out.starts_with('\'') {
        format!("\\&{out}")
    } else {
        out
    }
}

fn on_path(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

#[test]
fn release_binary_builds_reports_version_and_is_stripped() {
    let bin = release_bin();
    let dash = run(&bin, &["--version"]);
    assert_eq!(dash.status.code(), Some(0), "--version exits");
    let verb = run(&bin, &["version"]);
    assert_eq!(verb.status.code(), Some(0), "version exits");
    assert!(!dash.stdout.is_empty(), "--version prints");
    assert_eq!(dash.stdout, verb.stdout, "--version and version agree");
    assert_eq!(
        String::from_utf8(dash.stdout).expect("--version is UTF-8"),
        format!("memveil-{}\n", env!("CARGO_PKG_VERSION")),
        "version carries the package version"
    );
    let bin_arg = bin.to_str().expect("release path is UTF-8");
    let file = run(Path::new("file"), &[bin_arg]);
    assert_eq!(file.status.code(), Some(0), "file runs");
    let info = String::from_utf8(file.stdout).expect("file output is UTF-8");
    assert!(
        info.contains("stripped") && !info.contains("not stripped"),
        "release binary is stripped: {info}"
    );
    let ldd = run(Path::new("ldd"), &[bin_arg]);
    assert_eq!(ldd.status.code(), Some(0), "ldd runs");
    let libs = String::from_utf8(ldd.stdout).expect("ldd output is UTF-8");
    assert!(
        !libs.contains("not found"),
        "release closure resolves: {libs}"
    );
}

#[test]
fn frozen_verbs_match_top_help() {
    let bin = release_bin();
    let top_help = run_help(&bin, "");
    let live = usage_verbs(&top_help);
    let frozen: BTreeSet<String> = FROZEN_VERBS.iter().map(ToString::to_string).collect();
    assert_eq!(
        live, frozen,
        "new/renamed verb: live {live:?} vs frozen {frozen:?}"
    );
    // Reverse direction: every long flag top --help names must
    // be frozen, so a newly added top flag fails. --version and
    // -h are bound by the live guard below, not by --help text:
    // top --help spells --help (in the verb pointer line) but
    // never --version, and -h is short. The Start line and the
    // disclaimer footer name verb-level flags, pinned separately.
    let live_flags = long_flags(&top_help);
    let mut want: BTreeSet<String> = FROZEN_TOP_FLAGS.iter().map(ToString::to_string).collect();
    want.remove("--version");
    want.remove("-h");
    want.extend(FROZEN_TOP_EXAMPLE_FLAGS.iter().map(ToString::to_string));
    assert_eq!(
        live_flags, want,
        "top --help names {live_flags:?} vs frozen {want:?}"
    );
    for flag in FROZEN_TOP_FLAGS {
        let out = run(&bin, &[flag]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "top-level {flag} stopped working"
        );
    }
}

#[test]
fn frozen_flags_match_verb_help() {
    // -h is bound by the live guard, not by --help text: it
    // appears in neither the help body nor the synopsis.
    // Verb bodies likewise never spell `--help` literally
    // (unlike top --help, whose per-verb pointers do): --help
    // itself stays bound by run_help's live exit-0 run, -h by
    // short_help_flag_works_live, while the equality below pins
    // the spelled-out remainder; the explicit non-membership
    // fails loudly if a verb body ever names it.
    let bin = release_bin();
    for (verb, _) in FROZEN_FLAGS {
        let live = long_flags(&run_help(&bin, verb));
        assert!(
            !live.contains("--help"),
            "memveil {verb}: body names --help literally: {live:?}"
        );
        let mut want: BTreeSet<String> =
            frozen_flags(verb).iter().map(ToString::to_string).collect();
        want.remove("--help");
        want.remove("-h");
        assert_eq!(
            live, want,
            "memveil {verb}: --help names {live:?} vs frozen {want:?}"
        );
    }
}

#[test]
fn short_help_flag_works_live() {
    let bin = release_bin();
    let top = run(&bin, &["-h"]);
    assert_eq!(top.status.code(), Some(0), "top -h exits");
    for (verb, _) in FROZEN_FLAGS {
        let out = run(&bin, &[verb, "-h"]);
        assert_eq!(out.status.code(), Some(0), "{verb} -h exits");
    }
}

#[test]
fn frozen_value_arity_matches_synopsis() {
    let bin = release_bin();
    let novalue: BTreeSet<&str> = FROZEN_NOVALUE_FLAGS.into_iter().collect();
    for (verb, _) in FROZEN_FLAGS {
        let (takes_value, bare) = synopsis_arity(&run_help(&bin, verb), verb);
        for flag in frozen_flags(verb) {
            if *flag == "--help" || *flag == "-h" {
                continue;
            }
            if novalue.contains(flag) {
                assert!(
                    bare.contains(*flag),
                    "memveil {verb}: frozen-novalue {flag} shows a value"
                );
            } else {
                assert!(
                    takes_value.contains(*flag),
                    "memveil {verb}: {flag} lost its synopsis value"
                );
            }
        }
    }
}

#[test]
fn frozen_format_values_match_synopsis() {
    let bin = release_bin();
    let live = format_values_from_synopsis(&run_help(&bin, "report"));
    check_format_values("report", &live);
}

#[test]
fn format_guard_catches_extra_value() {
    // Negative control for the closed --format enum: an
    // in-memory synopsis offering xml must fail the guard,
    // naming the verb, the flag, and the extra value.
    let live =
        format_values_from_synopsis("usage: memveil report [--format text|json|markdown|xml] DIR");
    assert_eq!(
        live,
        BTreeSet::from([
            "text".to_string(),
            "json".to_string(),
            "markdown".to_string(),
            "xml".to_string(),
        ])
    );
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check_format_values("report", &live);
    }));
    assert!(caught.is_err(), "extra --format value must fail");
    let message = caught
        .unwrap_err()
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    for token in ["report", "--format", "xml"] {
        assert!(message.contains(token), "guard names {token}: {message}");
    }
}

/// Dump the generator's frozen sets through python3 without
/// importing by module name (the script keeps its CLI filename).
fn generator_frozen(script: &Path) -> Vec<(String, Vec<String>)> {
    const PROBE: &str = r#"
import importlib.util
import sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("mvgencomp", sys.argv[1])
spec = importlib.util.spec_from_loader("mvgencomp", loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
print("VERBS=" + ",".join(module.FROZEN_VERBS))
print("TOP=" + ",".join(module.FROZEN_TOP_FLAGS))
for verb in sorted(module.FROZEN_FLAGS):
    print("FLAGS:" + verb + "=" + ",".join(module.FROZEN_FLAGS[verb]))
print("FORMAT=" + ",".join(module.FROZEN_FORMAT_VALUES))
print("NOVALUE=" + ",".join(sorted(module.FROZEN_NOVALUE_FLAGS)))
"#;
    let out = Command::new("python3")
        .arg("-c")
        .arg(PROBE)
        .arg(script)
        .output()
        .expect("python3 runs the frozen-set probe");
    assert_eq!(out.status.code(), Some(0), "probe exits");
    let text = String::from_utf8(out.stdout).expect("probe prints UTF-8");
    text.lines()
        .map(|line| {
            let (key, values) = line.split_once('=').expect("KEY=values line");
            let items = values.split(',').map(str::to_string).collect();
            (key.to_string(), items)
        })
        .collect()
}

#[test]
fn generator_frozen_matches_pins() {
    let script = scripts_dir().join("gen-completions.py");
    assert!(script.is_file(), "missing {}", script.display());
    let dumped = generator_frozen(&script);
    let get = |key: &str| {
        dumped
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, values)| values.clone())
            .unwrap_or_else(|| panic!("probe lacks {key}"))
    };
    let verbs: Vec<String> = FROZEN_VERBS.iter().map(ToString::to_string).collect();
    assert_eq!(get("VERBS"), verbs, "gen-completions verbs drifted");
    let top: Vec<String> = FROZEN_TOP_FLAGS.iter().map(ToString::to_string).collect();
    assert_eq!(get("TOP"), top, "gen-completions top flags drifted");
    for (verb, _) in FROZEN_FLAGS {
        let key = format!("FLAGS:{verb}");
        let want: Vec<String> = frozen_flags(verb).iter().map(ToString::to_string).collect();
        assert_eq!(get(&key), want, "gen-completions flags for {verb} drifted");
    }
    let format: Vec<String> = FROZEN_FORMAT_VALUES
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(get("FORMAT"), format, "--format values drifted");
    let mut novalue: Vec<String> = FROZEN_NOVALUE_FLAGS
        .iter()
        .map(ToString::to_string)
        .collect();
    novalue.sort();
    assert_eq!(get("NOVALUE"), novalue, "novalue flags drifted");
}

fn gen_man(script: &Path, bin: &Path, out: &Path) {
    assert!(script.is_file(), "missing {}", script.display());
    let status = Command::new(script)
        .arg("--binary")
        .arg(bin)
        .arg("--out")
        .arg(out)
        .status()
        .unwrap_or_else(|err| panic!("cannot run {}: {err}", script.display()));
    assert!(status.success(), "gen-man exits");
}

#[test]
fn gen_man_embeds_current_help() {
    let bin = release_bin();
    let script = scripts_dir().join("gen-man.py");
    let dir = tmp_dir("man");
    let out = dir.join("man");
    gen_man(&script, &bin, &out);
    let mut names: Vec<String> = std::fs::read_dir(&out)
        .expect("gen-man writes the out dir")
        .map(|entry| entry.expect("dir entry").file_name())
        .map(|name| name.to_str().expect("UTF-8 name").to_string())
        .collect();
    names.sort();
    let mut want = vec!["memveil.1".to_string()];
    want.extend(MAN_VERBS.iter().map(|verb| format!("memveil-{verb}.1")));
    want.sort();
    assert_eq!(names, want, "gen-man wrote {names:?}");
    let version = live_version(&bin);
    let mut pages = vec![("".to_string(), "memveil.1".to_string())];
    pages.extend(
        MAN_VERBS
            .iter()
            .map(|verb| (verb.to_string(), format!("memveil-{verb}.1"))),
    );
    for (verb, name) in pages {
        let text = std::fs::read_to_string(out.join(&name)).expect("page reads back");
        let title = if verb.is_empty() {
            "MEMVEIL".to_string()
        } else {
            format!("MEMVEIL-{}", verb.to_uppercase())
        };
        // The version lives on the .TH line only: a stray
        // version token anywhere else must not satisfy this pin.
        let head = text.lines().next().unwrap_or("");
        assert_eq!(
            head,
            format!(".TH {title} 1 \"\" \"{version}\" \"User Commands\""),
            "{name} .TH line"
        );
        assert!(
            text.contains("Generated by scripts/gen-man.py"),
            "{name} provenance"
        );
        for line in run_help(&bin, &verb).lines() {
            assert!(
                text.contains(&roff(line)),
                "{name} drifts from --help at {line:?}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gen_man_deterministic() {
    let bin = release_bin();
    let script = scripts_dir().join("gen-man.py");
    let dir = tmp_dir("det");
    let first = dir.join("a");
    let second = dir.join("b");
    gen_man(&script, &bin, &first);
    gen_man(&script, &bin, &second);
    let names: Vec<String> = std::fs::read_dir(&first)
        .expect("first run writes")
        .map(|entry| entry.expect("dir entry").file_name())
        .map(|name| name.to_str().expect("UTF-8 name").to_string())
        .collect();
    assert!(!names.is_empty(), "gen-man wrote nothing");
    for name in &names {
        assert_eq!(
            std::fs::read(first.join(name)).expect("first page"),
            std::fs::read(second.join(name)).expect("second page"),
            "gen-man output for {name} is not deterministic"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn gen_completions(script: &Path, out: &Path) {
    assert!(script.is_file(), "missing {}", script.display());
    let status = Command::new(script)
        .arg("--out")
        .arg(out)
        .status()
        .unwrap_or_else(|err| panic!("cannot run {}: {err}", script.display()));
    assert!(status.success(), "gen-completions exits");
}

#[test]
fn gen_completions_covers_frozen() {
    let script = scripts_dir().join("gen-completions.py");
    let dir = tmp_dir("comp");
    let out = dir.join("comp");
    gen_completions(&script, &out);
    let mut names: Vec<String> = std::fs::read_dir(&out)
        .expect("gen-completions writes the out dir")
        .map(|entry| entry.expect("dir entry").file_name())
        .map(|name| name.to_str().expect("UTF-8 name").to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["_memveil".to_string(), "memveil".to_string()],
        "gen-completions wrote {names:?}"
    );
    let bash = std::fs::read_to_string(out.join("memveil")).expect("bash reads back");
    assert!(
        bash.contains("generated by scripts/gen-completions.py"),
        "bash provenance"
    );
    assert!(bash.contains("complete -F _memveil"), "bash registers");
    let zsh = std::fs::read_to_string(out.join("_memveil")).expect("zsh reads back");
    assert!(zsh.starts_with("#compdef memveil"), "zsh header");
    for verb in FROZEN_VERBS {
        assert!(bash.contains(verb), "bash lacks verb {verb}");
        assert!(zsh.contains(verb), "zsh lacks verb {verb}");
    }
    for flag in FROZEN_TOP_FLAGS {
        assert!(bash.contains(flag), "bash lacks {flag}");
        assert!(zsh.contains(flag), "zsh lacks {flag}");
    }
    for (verb, _) in FROZEN_FLAGS {
        for flag in frozen_flags(verb) {
            assert!(bash.contains(flag), "bash lacks memveil {verb} {flag}");
            assert!(zsh.contains(flag), "zsh lacks memveil {verb} {flag}");
        }
    }
    for value in FROZEN_FORMAT_VALUES {
        assert!(bash.contains(value), "bash lacks --format {value}");
        assert!(zsh.contains(value), "zsh lacks --format {value}");
    }
    if !on_path("bash") {
        eprintln!("skip: bash absent, syntax gate runs where bash exists");
        return;
    }
    let status = Command::new("bash")
        .arg("-n")
        .arg(out.join("memveil"))
        .status()
        .expect("bash -n runs");
    assert!(status.success(), "bash parses the completion");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gen_completions_zsh_format_action() {
    // The zsh _arguments spec for --format must carry the enum
    // as its action (`:name:(values)`): with a single colon zsh
    // parses the values as the message and offers nothing.
    // Exact-form pin; runs without zsh.
    let script = scripts_dir().join("gen-completions.py");
    let dir = tmp_dir("zsh");
    let out = dir.join("comp");
    gen_completions(&script, &out);
    let zsh = std::fs::read_to_string(out.join("_memveil")).expect("zsh reads back");
    assert!(
        zsh.contains("'--format[output format]:format:(text json markdown)'"),
        "zsh --format action: {zsh}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gen_completions_bash_functional() {
    // Drive the generated _memveil function directly: stub out
    // `complete`, set COMP_WORDS/COMP_CWORD, read back COMPREPLY.
    // Proves the completion table, not just file tokens.
    if !on_path("bash") {
        eprintln!("skip: bash absent, functional gate runs where bash exists");
        return;
    }
    let script = scripts_dir().join("gen-completions.py");
    let dir = tmp_dir("bash");
    let out = dir.join("comp");
    gen_completions(&script, &out);
    let driver = dir.join("drive.sh");
    std::fs::write(
        &driver,
        "complete() { :; }\n\
         source \"$1\"\n\
         shift\n\
         cword=\"$1\"\n\
         shift\n\
         COMP_WORDS=(\"$@\")\n\
         COMP_CWORD=\"$cword\"\n\
         COMPREPLY=()\n\
         _memveil\n\
         printf '%s\\n' \"${COMPREPLY[@]}\"\n",
    )
    .expect("driver writes");
    let comp = out.join("memveil");
    let complete = |words: &[&str], cword: u32| {
        let mut cmd = Command::new("bash");
        cmd.arg(&driver).arg(&comp).arg(cword.to_string());
        for word in words {
            cmd.arg(word);
        }
        let done = cmd.output().expect("bash drives the completion");
        assert_eq!(done.status.code(), Some(0), "drive exits");
        let noise = String::from_utf8_lossy(&done.stderr);
        assert!(
            noise.is_empty(),
            "sourcing the completion is quiet: {noise}"
        );
        let text = String::from_utf8(done.stdout).expect("replies are UTF-8");
        let mut replies: Vec<String> = text
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        replies.sort();
        replies
    };
    let sorted = |items: &[&str]| {
        let mut owned: Vec<String> = items.iter().map(ToString::to_string).collect();
        owned.sort();
        owned
    };
    assert_eq!(complete(&["memveil", ""], 1), sorted(&FROZEN_VERBS));
    assert_eq!(complete(&["memveil", "-"], 1), sorted(&FROZEN_TOP_FLAGS));
    assert_eq!(
        complete(&["memveil", "record", "-"], 2),
        sorted(frozen_flags("record"))
    );
    // Every flag-bearing verb gets the full-set case: the
    // hyphenated `bind-profile` stem once emitted an invalid
    // bash identifier (empty completion + `command not found`
    // on source), and `doctor`/`qualify` had no functional
    // coverage at all.
    assert_eq!(
        complete(&["memveil", "bind-profile", "-"], 2),
        sorted(frozen_flags("bind-profile"))
    );
    assert_eq!(
        complete(&["memveil", "doctor", "-"], 2),
        sorted(frozen_flags("doctor"))
    );
    assert_eq!(
        complete(&["memveil", "qualify", "-"], 2),
        sorted(frozen_flags("qualify"))
    );
    assert_eq!(
        complete(&["memveil", "report", "--for"], 2),
        vec!["--format".to_string()]
    );
    // The top --allow-partial token is the one genuine
    // adaptation vs the Mojo completion sets; pin it through
    // the live completion table, not just file tokens.
    assert_eq!(
        complete(&["memveil", "top", "--allow"], 2),
        vec!["--allow-partial".to_string()]
    );
    assert_eq!(
        complete(&["memveil", "report", "--format", ""], 3),
        sorted(&FROZEN_FORMAT_VALUES)
    );
    assert!(complete(&["memveil", "record", "--output", ""], 3).is_empty());
    assert!(complete(&["memveil", "bogus", "--"], 2).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gen_completions_zsh_syntax() {
    if !on_path("zsh") {
        eprintln!("skip: zsh absent, syntax gate runs where zsh exists");
        return;
    }
    let script = scripts_dir().join("gen-completions.py");
    let dir = tmp_dir("zshsyn");
    let out = dir.join("comp");
    gen_completions(&script, &out);
    let status = Command::new("zsh")
        .arg("-n")
        .arg(out.join("_memveil"))
        .status()
        .expect("zsh -n runs");
    assert!(status.success(), "zsh parses the completion");
    let _ = std::fs::remove_dir_all(&dir);
}

fn staged_files(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("{} reads: {err}", dir.display()))
            .map(|entry| entry.expect("dir entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                dirs.push(path);
            } else {
                let name = path
                    .strip_prefix(root)
                    .expect("staged under root")
                    .to_str()
                    .expect("UTF-8 name")
                    .to_string();
                found.push((name, std::fs::read(&path).expect("staged file reads")));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn gen_docs_driver_stages_man_and_completions() {
    let bin = release_bin();
    let driver = scripts_dir().join("gen-docs.py");
    assert!(driver.is_file(), "missing {}", driver.display());
    let dir = tmp_dir("docs");
    let staged = dir.join("staged");
    let status = Command::new(&driver)
        .arg("--binary")
        .arg(&bin)
        .arg("--out")
        .arg(&staged)
        .status()
        .unwrap_or_else(|err| panic!("cannot run {}: {err}", driver.display()));
    assert!(status.success(), "gen-docs exits");
    // The driver stages exactly what the generators emit.
    let expect = dir.join("expect");
    gen_man(&scripts_dir().join("gen-man.py"), &bin, &expect.join("man"));
    gen_completions(
        &scripts_dir().join("gen-completions.py"),
        &expect.join("completions"),
    );
    assert_eq!(
        staged_files(&staged),
        staged_files(&expect),
        "driver stages generator output"
    );
    // The default binary is the release tree beside the sources.
    let defaulted = dir.join("defaulted");
    let status = Command::new(&driver)
        .arg("--out")
        .arg(&defaulted)
        .status()
        .expect("gen-docs with defaults runs");
    assert!(status.success(), "gen-docs defaults exit");
    assert_eq!(
        staged_files(&defaulted),
        staged_files(&expect),
        "default binary stages identically"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
