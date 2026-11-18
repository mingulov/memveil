// SPDX-License-Identifier: GPL-3.0-or-later
//! Tarball gate port: layout, manifest, loader, and gap behaviors.
//!
//! Ports `tests/package/test_release_runtime.py` to run against
//! the Rust-built owner bundle, adjusting only for the known
//! deltas: no `libbpf_mojo.so.1` (the Aya loader links
//! statically), the shipped `.bpf.o` files are inspection
//! copies of the embedded Aya objects, the runtime closure is
//! the single `libgcc_s.so.1`, and provenance binds the Cargo
//! lockfiles instead of the pixi lock.

#[path = "package_helpers/mod.rs"]
mod package_helpers;

use package_helpers as h;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// Docs mirror: every repo `.md` ships byte-identical.
fn repo_doc_files(root: &std::path::Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let base = root.join("docs");
    let mut stack = vec![base.clone()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
            .expect("docs readable")
            .flatten()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                found.insert(
                    path.strip_prefix(&base)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string(),
                );
            }
        }
    }
    found
}

#[test]
fn tarball_layout() {
    let set = h::ensure_tarball();
    let version = h::engine_version();
    assert_eq!(
        set.bundle.file_name().unwrap().to_str().unwrap(),
        format!("memveil-{version}")
    );
    for rel in [
        "bin/memveil",
        "lib/memveil/libgcc_s.so.1",
        "bpf/swiotlb_attempt.bpf.o",
        "bpf/swiotlb_lifecycle.bpf.o",
        "bpf/swiotlb_copy.bpf.o",
        "profiles/manifest.txt",
        "LICENSE",
        "licenses/GPL-3.0.txt",
        "licenses/RUNTIME.LIBRARY.EXCEPTION",
        "THIRD-PARTY-NOTICES.md",
        "MANIFEST.json",
    ] {
        assert!(set.bundle.join(rel).is_file(), "bundle lacks {rel}");
    }
    for rel in ["GPL-2.0-only.txt", "GPL-2.0-or-later.txt", "GPL-2.0.txt"] {
        assert!(
            set.bundle.join("LICENSES").join(rel).is_file(),
            "bundle lacks LICENSES/{rel}"
        );
    }
    for leaf in ["real-capture", "lifecycle-copy"] {
        for name in ["events.ndjson", "session.json"] {
            assert!(
                set.bundle.join("examples").join(leaf).join(name).is_file(),
                "bundle lacks examples/{leaf}/{name}"
            );
        }
    }
    // Known deltas: no bridge, no conda/pixi runtime, no Mojo texts.
    let mut bridge = Vec::new();
    let mut stack = vec![set.bundle.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("bundle readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && (name.contains("libbpf_mojo") || name.contains("mojo-compiler"))
            {
                bridge.push(path);
            }
        }
    }
    assert!(bridge.is_empty(), "bridge residue: {bridge:?}");
    assert!(!set.bundle.join("lib/memveil/libbpf_mojo.so.1").exists());
}

#[test]
fn manifest_identity() {
    let set = h::ensure_tarball();
    let manifest = set.bundle.join("MANIFEST.json");
    let version = h::engine_version();
    assert_eq!(h::json_probe(&manifest, "d['engine_version']"), version);
    assert_eq!(
        h::json_probe(&manifest, "d['bundle']"),
        format!("memveil-{version}")
    );
    // Packages build from the pristine clone: compare against
    // its HEAD, never the live worktree's (sibling commits
    // must not fail this suite).
    let root = h::pristine_root();
    let head = h::run_ok("git", &["rev-parse", "HEAD"], Some(&root));
    assert_eq!(
        h::json_probe(&manifest, "d['memveil_revision']"),
        head.trim()
    );
    assert_eq!(
        h::json_probe(&manifest, "d['qualification']"),
        "unqualified-local-build"
    );
    // Toolchain proof: the repo pin wins over ambient overrides.
    assert_eq!(
        h::json_probe(&manifest, "d['toolchain']['cargo']['version']"),
        "1.100.0"
    );
    assert_eq!(
        h::json_probe(&manifest, "d['toolchain']['cargo']['version']"),
        h::pinned_cargo_version()
    );
    assert_eq!(
        h::json_probe(&manifest, "d['toolchain']['rustc']['version']"),
        h::pinned_rustc_version()
    );
    // Cargo lockfiles bind the dependency inputs.
    let root = h::pristine_root();
    assert_eq!(
        h::json_probe(&manifest, "d['cargo']['lock_sha256']"),
        h::sha256_file(&root.join("rust").join("Cargo.lock"))
    );
    assert_eq!(
        h::json_probe(&manifest, "d['cargo']['ebpf_lock_sha256']"),
        h::sha256_file(
            &root
                .join("rust")
                .join("crates")
                .join("ebpf")
                .join("Cargo.lock")
        )
    );
    let crates = h::json_probe(&manifest, "[c['name'] for c in d['cargo']['crates']]");
    assert!(crates.contains("aya"), "crates: {crates}");
    assert!(
        !crates.contains("memveil"),
        "workspace member leaked: {crates}"
    );
    let ebpf = h::json_probe(&manifest, "[c['name'] for c in d['cargo']['ebpf_crates']]");
    assert!(ebpf.contains("aya-ebpf"), "ebpf crates: {ebpf}");
}

#[test]
fn manifest_files_verify() {
    let set = h::ensure_tarball();
    let manifest = set.bundle.join("MANIFEST.json");
    let probe = format!(
        "import json; d = json.load(open({manifest:?})); \
         [print('%s|%s' % (k, v)) for k, v in sorted(d['files'].items())]"
    );
    let text = h::run_ok("python3", &["-c", &probe], None);
    let lines: Vec<&str> = text.lines().collect();
    assert!(!lines.is_empty(), "manifest files map is empty");
    let mut count = 0;
    for line in lines {
        let (rel, want) = line.split_once('|').expect("rel|sha line");
        let full = set.bundle.join(rel);
        assert!(full.is_file(), "manifest names missing {rel}");
        assert_eq!(h::sha256_file(&full), want, "hash drift: {rel}");
        count += 1;
    }
    assert!(count > 10, "suspiciously few files: {count}");
}

#[test]
fn loader_layout() {
    let set = h::ensure_tarball();
    let binary = set.bundle.join("bin").join("memveil");
    let dynamic = h::readelf_dynamic(&binary);
    assert!(dynamic.contains("$ORIGIN/../lib/memveil"), "{dynamic}");
    assert!(h::runpath_abspaths(&dynamic).is_empty(), "{dynamic}");
    assert!(h::is_x86_64(&binary));
    // NEEDED closure over the manifest's shipped set plus the
    // packager's system allowlist (probed from the script itself).
    let script = h::scripts_dir().join("package-tarball.py");
    let probe = format!(
        "import importlib.util; l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         print('\\n'.join(sorted(m.SYSTEM_ALLOW)))"
    );
    let allow: BTreeSet<String> = h::run_ok("python3", &["-B", "-c", &probe], None)
        .lines()
        .map(str::to_string)
        .collect();
    assert!(allow.contains("libc.so.6"), "{allow:?}");
    let shipped: BTreeSet<String> = fs::read_dir(set.bundle.join("lib").join("memveil"))
        .expect("lib dir")
        .flatten()
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .collect();
    assert!(shipped.contains("libgcc_s.so.1"), "{shipped:?}");
    let mut targets = vec![binary];
    for name in &shipped {
        targets.push(set.bundle.join("lib").join("memveil").join(name));
    }
    for target in &targets {
        for name in h::readelf_needed(target) {
            let leaf = target.file_name().unwrap().to_str().unwrap();
            assert!(
                shipped.contains(&name) || allow.contains(&name),
                "{leaf} needs {name}"
            );
        }
    }
}

#[test]
fn tar_members_normalized_modes() {
    let set = h::ensure_tarball();
    let version = h::engine_version();
    let top = format!("memveil-{version}");
    let members = h::tar_members(&set.tarball);
    assert!(!members.is_empty());
    assert!(
        members
            .iter()
            .any(|m| m.is_dir && m.name.trim_end_matches('/') == top),
        "no top dir member"
    );
    for member in &members {
        assert!(
            member.name == top || member.name.starts_with(&format!("{top}/")),
            "{}",
            member.name
        );
    }
    for member in members.iter().filter(|m| m.is_dir) {
        assert_eq!(member.mode, "drwxr-xr-x", "{}", member.name);
    }
    for member in members.iter().filter(|m| !m.is_dir) {
        if member.name == format!("{top}/bin/memveil") {
            assert_eq!(member.mode, "-rwxr-xr-x", "{}", member.name);
        } else {
            assert!(
                member.mode == "-rw-r--r--" || member.mode == "-rwxr-xr-x",
                "{}: {}",
                member.name,
                member.mode
            );
        }
    }
}

#[test]
fn docs_mirror_sources() {
    let set = h::ensure_tarball();
    let root = h::pristine_root();
    for rel in repo_doc_files(&root) {
        let staged = set.bundle.join("docs").join(&rel);
        assert!(staged.is_file(), "docs lack {rel}");
        assert_eq!(
            fs::read(&staged).unwrap(),
            fs::read(root.join("docs").join(&rel)).unwrap(),
            "docs drift: {rel}"
        );
    }
    for name in ["quickstart.md", "support.md", "privacy.md"] {
        assert!(set.bundle.join("docs").join(name).is_file());
    }
}

#[test]
fn profiles_mirror_sources() {
    let set = h::ensure_tarball();
    let root = h::pristine_root();
    assert_eq!(
        fs::read(set.bundle.join("profiles").join("manifest.txt")).unwrap(),
        fs::read(root.join("profiles").join("manifest.txt")).unwrap()
    );
    let mut staged: Vec<String> = fs::read_dir(set.bundle.join("profiles"))
        .expect("profiles")
        .flatten()
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .collect();
    staged.sort();
    let mut source: Vec<String> = fs::read_dir(root.join("profiles"))
        .expect("source profiles")
        .flatten()
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .filter(|n| n == "manifest.txt" || n.ends_with(".json"))
        .collect();
    source.sort();
    assert_eq!(staged, source);
}

#[test]
fn bpf_objects_match_build_and_stay_unstripped() {
    let set = h::ensure_tarball();
    let out = h::bpf_out_dir();
    for (channel, name) in [
        ("attempt", "swiotlb_attempt.bpf.o"),
        ("lifecycle", "swiotlb_lifecycle.bpf.o"),
        ("copy", "swiotlb_copy.bpf.o"),
    ] {
        let staged = set.bundle.join("bpf").join(name);
        assert_eq!(
            fs::read(&staged).unwrap(),
            fs::read(out.join(format!("memveil-ebpf-{channel}"))).unwrap(),
            "{name} differs from the build artifact"
        );
        assert_eq!(h::elf_machine(&staged), 247, "{name} is not EM_BPF");
        assert!(h::has_symtab(&staged), "{name} lost its symtab");
    }
}

#[test]
fn shipped_lib_stripped() {
    let set = h::ensure_tarball();
    let binary = set.bundle.join("bin").join("memveil");
    let lib = set.bundle.join("lib").join("memveil").join("libgcc_s.so.1");
    for path in [&binary, &lib] {
        assert!(!h::has_symtab(path), "{} keeps a symtab", path.display());
        assert!(!h::has_debug(path), "{} keeps debug", path.display());
    }
}

#[test]
fn permissions() {
    let set = h::ensure_tarball();
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(set.bundle.join("bin").join("memveil"))
        .unwrap()
        .permissions()
        .mode();
    assert_ne!(mode & 0o111, 0, "bin/memveil is not executable");
    let mut bad = Vec::new();
    let mut stack = vec![set.bundle.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("walk").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let mode = fs::metadata(&path).unwrap().permissions().mode();
                if mode & 0o002 != 0 || mode & 0o6000 != 0 {
                    bad.push(
                        path.strip_prefix(&set.bundle)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                    );
                }
            }
        }
    }
    assert!(bad.is_empty(), "privileged bits: {bad:?}");
}

#[test]
fn notices_cover_closure() {
    let set = h::ensure_tarball();
    let text = fs::read_to_string(set.bundle.join("THIRD-PARTY-NOTICES.md")).unwrap();
    for token in ["aya", "libgcc_s.so.1", "GCC-exception", "Cargo.lock"] {
        assert!(text.contains(token), "notices lack {token}");
    }
    assert!(
        text.to_lowercase().contains("no vendored")
            || text.to_lowercase().contains("vendored: none"),
        "notices must state the vendored/patched absence"
    );
    assert!(
        !text.contains("pixi") && !text.contains("libbpf_mojo"),
        "Mojo-tree notices leaked"
    );
}

#[test]
fn top_replays_valid_empty() {
    let set = h::ensure_tarball();
    let binary = set.bundle.join("bin").join("memveil");
    let out = h::run(
        binary.to_str().unwrap(),
        &[
            "top",
            "--interval",
            "1s",
            h::valid_empty_dir().to_str().unwrap(),
        ],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--- refresh"), "{stdout}");
    assert!(stdout.contains("bounce_attempts = 0"), "{stdout}");
}

#[test]
fn unknown_profile_refused() {
    let set = h::ensure_tarball();
    let tmp = h::scratch("unknown-profile");
    let cap = tmp.join("cap");
    let binary = set.bundle.join("bin").join("memveil");
    let out = h::run(
        binary.to_str().unwrap(),
        &[
            "record",
            "--output",
            cap.to_str().unwrap(),
            "--profile",
            "release-runtime-bogus-0",
            "--duration",
            "1",
        ],
        Some(&tmp),
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown --profile"));
    assert!(!cap.exists(), "refused record left a capture dir");
}

#[test]
fn absent_bpf_object_refused() {
    let set = h::ensure_tarball();
    let tmp = h::scratch("absent-object");
    let missing = tmp.join("swiotlb_attempt.bpf.o");
    let cap = tmp.join("cap");
    let binary = set.bundle.join("bin").join("memveil");
    let out = h::run(
        binary.to_str().unwrap(),
        &[
            "record",
            "--output",
            cap.to_str().unwrap(),
            "--object",
            missing.to_str().unwrap(),
            "--duration",
            "1",
        ],
        Some(&tmp),
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("object unreadable"));
    assert!(!cap.exists(), "refused record left a capture dir");
}

#[test]
fn corrupted_libgcc_fails_closed() {
    // Port of the replaced-bridge boundary: the shipped lib is a
    // loader input here, so corrupting it must fail the process
    // (loader error) without producing a capture directory.
    let set = h::ensure_tarball();
    let tmp = h::scratch("corrupt-lib");
    let trial = tmp.join("trial");
    let out = h::run(
        "cp",
        &["-r", set.bundle.to_str().unwrap(), trial.to_str().unwrap()],
        None,
    );
    assert!(out.status.success());
    fs::write(
        trial.join("lib").join("memveil").join("libgcc_s.so.1"),
        b"not an elf",
    )
    .unwrap();
    let cap = tmp.join("cap");
    let binary = trial.join("bin").join("memveil");
    let proc = h::run(
        binary.to_str().unwrap(),
        &[
            "record",
            "--output",
            cap.to_str().unwrap(),
            "--duration",
            "1",
        ],
        Some(&tmp),
    );
    assert!(!proc.status.success(), "corrupted lib still ran");
    assert!(!cap.exists(), "failed record left a capture dir");
}

#[test]
fn bare_env_record_passes_discovery() {
    let set = h::ensure_tarball();
    let tmp = h::scratch("bare-env");
    let cap = tmp.join("cap");
    let binary = set.bundle.join("bin").join("memveil");
    let out = std::process::Command::new(&binary)
        .args([
            "record",
            "--output",
            cap.to_str().unwrap(),
            "--duration",
            "1",
        ])
        .current_dir(&tmp)
        .env_clear()
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run record");
    let stderr = String::from_utf8_lossy(&out.stderr);
    for missing in ["no bridge", "no object", "missing --object"] {
        assert!(!stderr.contains(missing), "{stderr}");
    }
    assert!(
        out.status.code() == Some(0) || out.status.code() == Some(3),
        "{stderr}"
    );
    if out.status.code() == Some(3) {
        assert!(!stderr.trim().is_empty(), "refusal needs a diagnostic");
        assert!(!cap.exists(), "refused record left a capture dir");
    } else {
        assert!(cap.exists(), "exit 0 left no capture dir");
    }
}

#[test]
fn runpath_abspaths_parser() {
    // Pure-helper probe against the script module (no packaging run).
    let script = h::scripts_dir().join("package-tarball.py");
    let probe = format!(
        "import importlib.util; l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         clean = ' 0x1 (RUNPATH) Library runpath: [$ORIGIN/../lib]'; \
         assert m.runpath_abspaths(clean) == [], 'clean flagged'; \
         hidden = ' 0x1 (RUNPATH) Library runpath: [/tmp/stage/lib]'; \
         assert '/home/' not in hidden and '/work/' not in hidden; \
         assert m.runpath_abspaths(hidden) == ['/tmp/stage/lib']; \
         print('parser-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("parser-ok"), "{text}");
}

#[test]
fn validate_tag_rejects() {
    let script = h::scripts_dir().join("package-tarball.py");
    for bad in ["", ".", "..", "../escape", "-leading", "a/b", "back\\slash"] {
        let out = h::run(
            "python3",
            &[
                script.to_str().unwrap(),
                "--root",
                h::pristine_root().to_str().unwrap(),
                "--binary",
                h::ensure_release_binary().to_str().unwrap(),
                "--bpf-dir",
                h::bpf_out_dir().to_str().unwrap(),
                "--out",
                h::scratch("bad-tag").to_str().unwrap(),
                "--tag",
                bad,
            ],
            None,
        );
        assert!(!out.status.success(), "tag {bad:?} accepted");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("bad bundle tag"),
            "tag {bad:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
