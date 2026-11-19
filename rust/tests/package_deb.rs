// SPDX-License-Identifier: GPL-3.0-or-later
//! .deb gate port: FHS payload, control, and install journey.
//!
//! Ports the artifact assertions of `tests/package/test_deb.py`
//! to run against the Rust-built .deb, adjusting only for the
//! known deltas: no `libbpf_mojo.so.1` (single `libgcc_s.so.1`
//! closure), `licenses/` holds the GCC texts only, one
//! generated `THIRD-PARTY-NOTICES.md`, `Depends: libc6` floor
//! only, `X-Memveil-Cargo-Lock` instead of the bridge pin, and
//! no bridge dlopen in the journey (ldd closure plus the
//! RUNPATH-resolved private lib prove loading instead).
//! The generator frozen contract stays owned by the
//! `generators.rs` suite; the spec contract lives in `package_rpm.rs`;
//! the journey-helper unit tests of the Python file tested its
//! own helpers and have no artifact meaning here.

#[path = "package_helpers/mod.rs"]
mod package_helpers;

use package_helpers as h;
use package_helpers::journey as j;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const SHORT_DESC: &str = "swiotlb bounce-attempt capture and offline replay on x86-64 Linux";

const MAN_FILES: [&str; 7] = [
    "usr/share/man/man1/memveil.1",
    "usr/share/man/man1/memveil-record.1",
    "usr/share/man/man1/memveil-report.1",
    "usr/share/man/man1/memveil-top.1",
    "usr/share/man/man1/memveil-doctor.1",
    "usr/share/man/man1/memveil-qualify.1",
    "usr/share/man/man1/memveil-bind-profile.1",
];

const COMPLETION_FILES: [&str; 2] = [
    "usr/share/bash-completion/completions/memveil",
    "usr/share/zsh/vendor-completions/_memveil",
];

const DEB_ONLY_FILES: [&str; 2] = [
    "usr/share/doc/memveil/changelog.Debian.gz",
    "usr/share/lintian/overrides/memveil",
];

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

/// Every member outside lib/ and the docs mirror, from the one
/// shared pin (`package_helpers::FHS_FIXED_FILES`) both FHS formats
/// consume; MAN_FILES/COMPLETION_FILES stay as the content-check
/// subsets below.
fn fixed_files() -> BTreeSet<String> {
    h::FHS_FIXED_FILES.iter().map(ToString::to_string).collect()
}

/// Staged payload ELF files (binary + lib/*.so*).
fn payload_elfs(extracted: &std::path::Path) -> Vec<PathBuf> {
    let libdir = extracted.join("usr").join("lib").join("memveil");
    let mut elfs = vec![extracted.join("usr").join("bin").join("memveil")];
    let mut libs: Vec<PathBuf> = fs::read_dir(&libdir)
        .expect("libdir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".so"))
        })
        .collect();
    libs.sort();
    elfs.extend(libs);
    assert!(elfs.len() > 1, "no shipped ELF to derive a floor from");
    elfs
}

/// Max libc need across the extracted payload (binary + lib/*.so*).
fn payload_glibc_floor(extracted: &std::path::Path) -> (u32, u32) {
    h::glibc_floor(&payload_elfs(extracted))
}

fn repo_tree_files(root: &std::path::Path, subdir: &str, suffix: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let base = root.join(subdir);
    let mut stack = vec![base.clone()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
            .expect("tree")
            .flatten()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(suffix))
            {
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
fn control_fields() {
    let deb = h::ensure_deb();
    let version = h::engine_version();
    assert_eq!(h::deb_field(&deb, "Package").trim(), "memveil");
    assert_eq!(h::deb_field(&deb, "Version").trim(), format!("{version}-1"));
    assert_eq!(h::deb_field(&deb, "Architecture").trim(), "amd64");
    assert_eq!(h::deb_field(&deb, "Section").trim(), "utils");
    assert_eq!(h::deb_field(&deb, "Priority").trim(), "optional");
    let maintainer = h::deb_field(&deb, "Maintainer");
    assert!(!maintainer.trim().is_empty());
    assert!(!maintainer.contains("example.invalid"), "{maintainer}");
    let desc = h::deb_field(&deb, "Description");
    assert_eq!(
        desc.lines().next().unwrap_or("").trim(),
        SHORT_DESC,
        "{desc}"
    );
    assert!(desc.lines().count() > 1, "long description missing");
    let extracted = h::deb_extract(&deb, "deb-control");
    let (major, minor) = payload_glibc_floor(&extracted);
    assert_eq!(
        h::deb_field(&deb, "Depends").trim(),
        format!("libc6 (>= {major}.{minor})")
    );
    let rev = h::deb_field(&deb, "X-Memveil-Revision");
    let rev = rev.trim();
    assert!(
        rev == "export" || (rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit())),
        "{rev}"
    );
    let lock = h::sha256_file(&h::pristine_root().join("rust").join("Cargo.lock"));
    assert_eq!(h::deb_field(&deb, "X-Memveil-Cargo-Lock").trim(), lock);
    let tools = h::deb_field(&deb, "X-Memveil-Build-Tools");
    let tools = tools.trim();
    assert!(
        tools.starts_with("dpkg-deb=") && tools.contains("; patchelf="),
        "{tools}"
    );
    // No bridge pin survives in the Rust package (dpkg-deb -f
    // exits 0 with empty output for an absent field).
    let lmb = h::run(
        "dpkg-deb",
        &["-f", deb.to_str().unwrap(), "X-LMB-Tarball-SHA256"],
        None,
    );
    assert!(lmb.status.success());
    assert!(
        String::from_utf8_lossy(&lmb.stdout).trim().is_empty(),
        "stale bridge field present"
    );
    assert_eq!(
        deb.file_name().unwrap().to_str().unwrap(),
        format!("memveil_{version}-1_amd64.deb")
    );
}

#[test]
fn abi_node_floor() {
    // The toolchain libgcc requires the non-numeric GLIBC_ABI_GNU2_TLS
    // node (first provided by glibc 2.40): the payload must actually
    // carry it (so this derivation is not vacuous), the derived floor
    // must cover its introducing release, and the packager's own parser
    // must map it while failing closed on unknown ABI nodes.
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-abifloor");
    let mut tokens = BTreeSet::new();
    for elf in payload_elfs(&extracted) {
        let text = h::run_ok("readelf", &["-V", elf.to_str().unwrap()], None);
        tokens.extend(h::parse_glibc_abi_tokens(&text));
    }
    assert!(
        tokens.contains("GLIBC_ABI_GNU2_TLS"),
        "payload lost its ABI need: {tokens:?}"
    );
    let floor = payload_glibc_floor(&extracted);
    assert!(
        floor >= (2, 40),
        "floor {floor:?} under-declares the ABI need"
    );
    let script = h::scripts_dir().join("package-deb.py");
    let probe = format!(
        "import importlib.util; l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         assert m.parse_glibc_floor('Name: GLIBC_2.35  Flags: none') == (2, 35); \
         assert m.parse_glibc_floor('Name: GLIBC_ABI_GNU2_TLS  Flags: none') == (2, 40); \
         assert m.parse_glibc_floor('Name: GLIBC_2.35\\nName: GLIBC_ABI_GNU2_TLS') == (2, 40); \
         assert m.parse_glibc_floor('Name: GCC_4.2.0  Flags: none') is None; \
         print('abi-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("abi-ok"), "{text}");
    let probe = format!(
        "import importlib.util; l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         m.parse_glibc_floor('Name: GLIBC_ABI_FUTURE_X  Flags: none')"
    );
    let out = h::run("python3", &["-B", "-c", &probe], None);
    assert!(!out.status.success(), "unknown ABI node passed");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown libc ABI need GLIBC_ABI_FUTURE_X"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn file_list_exact() {
    let deb = h::ensure_deb();
    let (files, _dirs) = h::deb_listing(&deb);
    let root = h::pristine_root();
    let mut profiles: BTreeSet<String> = repo_tree_files(&root, "profiles", ".json")
        .into_iter()
        .map(|rel| format!("usr/share/memveil/profiles/{rel}"))
        .collect();
    profiles.insert("usr/share/memveil/profiles/manifest.txt".to_string());
    let docs: BTreeSet<String> = repo_tree_files(&root, "docs", ".md")
        .into_iter()
        .map(|rel| format!("usr/share/memveil/docs/{rel}"))
        .collect();
    let libs: BTreeSet<String> = files
        .keys()
        .filter(|p| p.starts_with("usr/lib/memveil/"))
        .cloned()
        .collect();
    assert!(libs.contains("usr/lib/memveil/libgcc_s.so.1"), "{libs:?}");
    let bpf: BTreeSet<String> = libs
        .iter()
        .filter(|p| p.ends_with(".bpf.o"))
        .cloned()
        .collect();
    assert_eq!(
        bpf,
        BTreeSet::from(h::BPF_OBJECTS.map(|n| format!("usr/lib/memveil/{n}"))),
        "{libs:?}"
    );
    let rest: BTreeSet<String> = libs.difference(&bpf).cloned().collect();
    assert!(!rest.is_empty(), "no shared libraries shipped");
    for path in &rest {
        let leaf = path.strip_prefix("usr/lib/memveil/").unwrap();
        assert!(!leaf.contains('/'), "{path}");
        assert!(leaf.contains(".so"), "{path}");
        assert!(!path.contains('%') && !path.contains(' '), "{path}");
    }
    // Per-crate notice files, from the same bundle manifest the .deb
    // consumed.
    let set = h::ensure_tarball();
    let bundle_manifest = set.bundle.join("MANIFEST.json");
    let probe = format!(
        "import json; d = json.load(open({bundle_manifest:?}));\n\
         [print(k) for k in sorted(d['files']) if k.startswith('licenses/crates/')]"
    );
    let mut crates_files = BTreeSet::new();
    for rel in h::run_ok("python3", &["-c", &probe], None).lines() {
        crates_files.insert(format!("usr/share/doc/memveil/{rel}"));
    }
    assert!(!crates_files.is_empty(), "bundle carries no crate texts");
    let mut want = fixed_files();
    for name in DEB_ONLY_FILES {
        want.insert(name.to_string());
    }
    want.extend(profiles);
    want.extend(docs);
    want.extend(libs);
    want.extend(crates_files);
    let have: BTreeSet<String> = files.keys().cloned().collect();
    let extra: Vec<&String> = have.difference(&want).collect();
    let missing: Vec<&String> = want.difference(&have).collect();
    assert!(
        extra.is_empty() && missing.is_empty(),
        "extra: {extra:?}; missing: {missing:?}"
    );
}

#[test]
fn modes_owners_no_privilege_bits() {
    let deb = h::ensure_deb();
    let (files, _dirs) = h::deb_listing(&deb);
    // Re-derive modes through the raw listing (dirs and files).
    let text = h::run_ok("dpkg-deb", &["-c", deb.to_str().unwrap()], None);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let (mode, owner) = (parts[0], parts[1]);
        let path = parts[parts.len() - 1].strip_prefix("./").unwrap();
        assert_eq!(owner, "root/root", "{path}");
        if mode.starts_with('d') {
            assert_eq!(mode, "drwxr-xr-x", "{path}");
        } else {
            assert!(mode.starts_with('-'), "{path}: {mode}");
            assert!(!mode.contains('s') && !mode.contains('t'), "{path}: {mode}");
            assert_ne!(mode.chars().nth(8), Some('w'), "{path}: {mode}");
            if path == "usr/bin/memveil" {
                assert_eq!(mode, "-rwxr-xr-x", "{path}");
            } else {
                assert_eq!(mode, "-rw-r--r--", "{path}");
            }
        }
    }
    assert!(files.contains_key("usr/bin/memveil"));
}

#[test]
fn no_maintainer_scripts() {
    let deb = h::ensure_deb();
    let mut members = h::deb_control_members(&deb);
    members.sort();
    assert_eq!(
        members,
        vec!["control".to_string(), "md5sums".to_string()],
        "{members:?}"
    );
}

#[test]
fn md5sums_match_payload() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-md5");
    let ctrl = h::scratch("deb-ctrl");
    h::run_ok(
        "dpkg-deb",
        &["-e", deb.to_str().unwrap(), ctrl.to_str().unwrap()],
        None,
    );
    let mut listed = BTreeSet::new();
    for line in fs::read_to_string(ctrl.join("md5sums")).unwrap().lines() {
        let (digest, path) = line.split_once("  ").expect("md5 line");
        listed.insert((path.to_string(), digest.to_string()));
    }
    let mut actual = BTreeSet::new();
    let mut stack = vec![extracted.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("walk").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let out = h::run_ok("md5sum", &[path.to_str().unwrap()], None);
                let digest = out.split_whitespace().next().unwrap().to_string();
                let rel = path
                    .strip_prefix(&extracted)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                actual.insert((rel, digest));
            }
        }
    }
    assert_eq!(listed, actual);
}

#[test]
fn staged_payload_matches_bundle() {
    // Build-time binding oracle: the packager's own mapping
    // must cover one member per category (binary, closure
    // lib, BPF copy, profiles, docs, worked examples, and
    // every license/notice text), the extracted .deb must
    // satisfy the packager's verify, and a hollow staging
    // must fail it.
    let deb = h::ensure_deb();
    let set = h::ensure_tarball();
    let manifest = set.bundle.join("MANIFEST.json");
    let extracted = h::deb_extract(&deb, "deb-verify");
    let script = h::scripts_dir().join("package-deb.py");
    let probe = format!(
        "import importlib.util; l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         cases = {{'bin/memveil': 'usr/bin/memveil', \
         'lib/memveil/libgcc_s.so.1': 'usr/lib/memveil/libgcc_s.so.1', \
         'bpf/swiotlb_attempt.bpf.o': 'usr/lib/memveil/swiotlb_attempt.bpf.o', \
         'profiles/manifest.txt': 'usr/share/memveil/profiles/manifest.txt', \
         'docs/quickstart.md': 'usr/share/memveil/docs/quickstart.md', \
         'examples/real-capture/session.json': \
         'usr/share/memveil/docs/examples/real-capture/session.json', \
         'LICENSE': 'usr/share/doc/memveil/LICENSE', \
         'THIRD-PARTY-NOTICES.md': 'usr/share/doc/memveil/THIRD-PARTY-NOTICES.md', \
         'LICENSES/GPL-2.0-only.txt': \
         'usr/share/doc/memveil/LICENSES/GPL-2.0-only.txt', \
         'licenses/GPL-3.0.txt': 'usr/share/doc/memveil/licenses/GPL-3.0.txt', \
         'licenses/crates/bytes-1.12.2/LICENSE': \
         'usr/share/doc/memveil/licenses/crates/bytes-1.12.2/LICENSE'}}; \
         bad = [k for k, v in cases.items() if m.installed_file_path(k) != v]; \
         assert not bad, bad; \
         print('mapping-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("mapping-ok"), "{text}");
    let probe = format!(
        "import importlib.util, json; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         manifest = json.load(open({manifest:?})); \
         m.verify_installed({extracted:?}, manifest); \
         print('verify-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("verify-ok"), "{text}");
    let tmp = h::scratch("deb-verify-neg");
    let trial = tmp.join("trial");
    h::run_ok(
        "cp",
        &["-r", extracted.to_str().unwrap(), trial.to_str().unwrap()],
        None,
    );
    fs::remove_file(trial.join("usr").join("bin").join("memveil")).unwrap();
    let probe = format!(
        "import importlib.util, json; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         manifest = json.load(open({manifest:?})); \
         m.verify_installed({trial:?}, manifest)"
    );
    let out = h::run("python3", &["-B", "-c", &probe], None);
    assert!(!out.status.success(), "verify passed a hollow staging");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("usr/bin/memveil"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bpf_objects_unstripped() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-bpf");
    for name in h::BPF_OBJECTS {
        let obj = extracted.join("usr").join("lib").join("memveil").join(name);
        assert_eq!(h::elf_machine(&obj), 247, "{name}");
        assert!(h::has_symtab(&obj), "{name} lost its symtab");
    }
}

#[test]
fn shipped_elf_stripped() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-strip");
    let libdir = extracted.join("usr").join("lib").join("memveil");
    let mut elfs = vec![extracted.join("usr").join("bin").join("memveil")];
    let mut libs: Vec<PathBuf> = fs::read_dir(&libdir)
        .expect("libdir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".so"))
        })
        .collect();
    libs.sort();
    elfs.extend(libs);
    assert!(elfs.len() > 1);
    for path in &elfs {
        assert!(!h::has_symtab(path), "{} keeps a symtab", path.display());
        assert!(!h::has_debug(path), "{} keeps debug", path.display());
    }
}

#[test]
fn bpf_objects_match_build() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-bpfbytes");
    let out = h::bpf_out_dir();
    for (channel, name) in [
        ("attempt", h::BPF_OBJECTS[0]),
        ("lifecycle", h::BPF_OBJECTS[1]),
        ("copy", h::BPF_OBJECTS[2]),
    ] {
        let staged = extracted.join("usr").join("lib").join("memveil").join(name);
        assert_eq!(
            fs::read(&staged).unwrap(),
            fs::read(out.join(format!("memveil-ebpf-{channel}"))).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn no_elf_under_usr_share() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-noelf");
    let mut bad = Vec::new();
    let mut stack = vec![extracted.join("usr").join("share")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("walk").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = fs::read(&path).unwrap();
                if bytes.len() >= 4 && bytes[0..4] == *b"\x7fELF" {
                    bad.push(
                        path.strip_prefix(&extracted)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                    );
                }
            }
        }
    }
    assert!(bad.is_empty(), "{bad:?}");
}

#[test]
fn copyright_points_at_texts() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-copyright");
    let text = fs::read_to_string(
        extracted
            .join("usr")
            .join("share")
            .join("doc")
            .join("memveil")
            .join("copyright"),
    )
    .unwrap();
    for token in [
        "GPL-3.0-or-later",
        "THIRD-PARTY-NOTICES",
        "GPL-2.0-only",
        "/usr/share/common-licenses/GPL-3",
    ] {
        assert!(text.contains(token), "{text}");
    }
    assert!(!text.contains("libbpf-mojo"), "bridge residue: {text}");
}

#[test]
fn changelog_debian() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-changelog");
    let gz = extracted
        .join("usr")
        .join("share")
        .join("doc")
        .join("memveil")
        .join("changelog.Debian.gz");
    let out = h::run("gzip", &["-dc", gz.to_str().unwrap()], None);
    assert!(out.status.success());
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    let first = raw.lines().next().unwrap_or("");
    let version = h::engine_version();
    assert!(
        first.starts_with(&format!("memveil ({version}-1)")) && first.contains("; urgency="),
        "{first}"
    );
    assert!(first.contains("unstable"), "{first}");
    assert!(
        raw.contains(h::deb_field(&deb, "Maintainer").trim()),
        "{raw}"
    );
    assert!(
        raw.contains(h::deb_field(&deb, "X-Memveil-Revision").trim()),
        "{raw}"
    );
    assert!(raw.lines().all(|l| l.len() <= 80), "{raw}");
}

#[test]
fn man_and_completions_present() {
    let deb = h::ensure_deb();
    let (files, dirs) = h::deb_listing(&deb);
    for path in MAN_FILES.iter().chain(COMPLETION_FILES.iter()) {
        assert!(files.contains_key(*path), "missing {path}");
    }
    for dir in [
        "usr/share/man/man1",
        "usr/share/bash-completion/completions",
        "usr/share/zsh/vendor-completions",
    ] {
        assert!(dirs.contains(dir), "{dirs:?}");
    }
    let extracted = h::deb_extract(&deb, "deb-man");
    for path in MAN_FILES {
        let text = fs::read_to_string(extracted.join(path)).unwrap();
        assert!(text.starts_with(".TH MEMVEIL"), "{path}");
        assert!(
            text.contains("Generated by rust/scripts/gen-man.py"),
            "{path}"
        );
        assert!(text.lines().count() > 5, "{path}");
    }
    let bash = fs::read_to_string(extracted.join(COMPLETION_FILES[0])).unwrap();
    assert!(
        bash.contains("generated by rust/scripts/gen-completions.py"),
        "{}",
        &bash[..200.min(bash.len())]
    );
    assert!(bash.contains("complete -F _memveil"));
    let zsh = fs::read_to_string(extracted.join(COMPLETION_FILES[1])).unwrap();
    assert!(
        zsh.starts_with("#compdef memveil"),
        "{}",
        &zsh[..200.min(zsh.len())]
    );
    for verb in FROZEN_VERBS {
        assert!(bash.contains(verb), "bash lacks {verb}");
        assert!(zsh.contains(verb), "zsh lacks {verb}");
    }
}

fn roff(line: &str) -> String {
    let mut out = line.replace('\\', "\\(rs");
    if out.starts_with('.') || out.starts_with('\'') {
        out = format!("\\&{out}");
    }
    out
}

#[test]
fn installed_man_matches_current_help() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-manhelp");
    let binary = h::ensure_release_binary();
    let bin = binary.to_str().unwrap();
    let mut pages = vec![("".to_string(), "memveil.1".to_string())];
    for verb in [
        "record",
        "report",
        "top",
        "doctor",
        "qualify",
        "bind-profile",
    ] {
        pages.push((verb.to_string(), format!("memveil-{verb}.1")));
    }
    for (verb, name) in pages {
        let args: Vec<&str> = if verb.is_empty() {
            vec!["--help"]
        } else {
            vec![&verb, "--help"]
        };
        let out = h::run(bin, &args, None);
        assert!(out.status.success(), "{verb}");
        let help = String::from_utf8_lossy(&out.stdout).into_owned();
        let text = fs::read_to_string(
            extracted
                .join("usr")
                .join("share")
                .join("man")
                .join("man1")
                .join(&name),
        )
        .unwrap();
        for line in help.lines() {
            assert!(
                text.contains(&roff(line)),
                "{name} lacks help line {line:?}"
            );
        }
    }
}

#[test]
fn loader_closure() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-loader");
    let binary = extracted.join("usr").join("bin").join("memveil");
    let dynamic = h::readelf_dynamic(&binary);
    assert!(dynamic.contains("$ORIGIN/../lib/memveil"), "{dynamic}");
    assert!(h::runpath_abspaths(&dynamic).is_empty(), "{dynamic}");
    assert!(h::is_x86_64(&binary));
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
    let libdir = extracted.join("usr").join("lib").join("memveil");
    let mut libs: Vec<PathBuf> = fs::read_dir(&libdir)
        .expect("libdir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".so"))
        })
        .collect();
    libs.sort();
    assert!(!libs.is_empty());
    let shipped: BTreeSet<String> = libs
        .iter()
        .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
        .collect();
    let mut targets = vec![binary];
    targets.extend(libs);
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
fn docs_mirror_repo_and_links_resolve() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-docs");
    let root = h::pristine_root();
    let docs = extracted
        .join("usr")
        .join("share")
        .join("memveil")
        .join("docs");
    for rel in repo_tree_files(&root, "docs", ".md") {
        let staged = docs.join(&rel);
        assert!(staged.is_file(), "{rel}");
        assert_eq!(
            fs::read(&staged).unwrap(),
            fs::read(root.join("docs").join(&rel)).unwrap(),
            "{rel}"
        );
    }
    // Local markdown links resolve inside the installed tree.
    let mut stack = vec![docs.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("walk").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".md"))
            {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            for link in markdown_links(&text) {
                if link.contains("://") || link.starts_with('/') {
                    continue;
                }
                let dest = path.parent().unwrap().join(&link);
                assert!(dest.is_file(), "{} links missing {link}", path.display());
            }
        }
    }
}

/// `](target)` link targets in markdown text (fragment stripped).
fn markdown_links(text: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("](") {
        rest = &rest[open + 2..];
        if let Some(close) = rest.find(')') {
            let mut target = rest[..close].to_string();
            if let Some(hash) = target.find('#') {
                target.truncate(hash);
            }
            if !target.is_empty() {
                links.push(target);
            }
            rest = &rest[close + 1..];
        } else {
            break;
        }
    }
    links
}

#[test]
fn receipts_state_dir_staged() {
    let deb = h::ensure_deb();
    let (files, dirs) = h::deb_listing(&deb);
    assert!(dirs.contains("var/lib/memveil/receipts"), "{dirs:?}");
    assert!(dirs.contains("var/lib/memveil"), "{dirs:?}");
    assert!(
        !files.keys().any(|p| p.starts_with("var/lib/memveil/")),
        "state dir must ship empty"
    );
}

#[test]
fn lintian_gate() {
    if !h::tool_present("lintian") {
        eprintln!(
            "skip: lintian absent on this host (not installed; structural pins assert instead)"
        );
        return;
    }
    let deb = h::ensure_deb();
    let out = h::run("lintian", &[deb.to_str().unwrap()], None);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    println!("{combined}");
    let errors: Vec<&str> = combined.lines().filter(|l| l.starts_with("E:")).collect();
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn lintian_overrides_exact() {
    let deb = h::ensure_deb();
    let extracted = h::deb_extract(&deb, "deb-overrides");
    let text = fs::read_to_string(
        extracted
            .join("usr")
            .join("share")
            .join("lintian")
            .join("overrides")
            .join("memveil"),
    )
    .unwrap();
    let lines: BTreeSet<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    let template =
        fs::read_to_string(h::packaging_dir().join("deb").join("lintian-overrides")).unwrap();
    let want: BTreeSet<String> = template
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    assert!(!want.is_empty());
    assert_eq!(lines, want);
    // The override set pins the known-justified tags line by line.
    let mut tags: BTreeSet<String> = BTreeSet::new();
    for line in &want {
        if line.contains("binary-from-other-architecture") {
            tags.insert("bpf".to_string());
        } else if line.contains("uncompressed-manual-page") {
            tags.insert("man".to_string());
        } else {
            panic!("unjustified override: {line}");
        }
    }
    assert_eq!(tags.len(), 2);
}

/// Fresh-state prelude: package absent (dpkg probe), then the
/// shared retained-receipts refusal. Returns pre-run names.
fn preflight_fresh_state(receipts: &str) -> BTreeSet<String> {
    let probe = h::run("dpkg", &["-s", "memveil"], None);
    assert!(
        !probe.status.success(),
        "memveil is already installed: remove it and rerun"
    );
    j::refuse_retained_receipts(receipts)
}

#[test]
fn journey_refuses_retained_receipts() {
    // Needs no .deb/sudo: the retained-receipts predicate the
    // journey prelude uses must name survivors and pass fresh dirs.
    let tmp = h::scratch("retained");
    let receipts = tmp.join("receipts");
    fs::create_dir(&receipts).unwrap();
    fs::write(
        receipts.join("pre-existing-receipt.json"),
        "{\"profile_id\": \"x\"}\n",
    )
    .unwrap();
    let names = j::retained_receipts(&receipts);
    assert_eq!(names, vec!["pre-existing-receipt.json".to_string()]);
    assert!(j::retained_receipts(&tmp.join("missing")).is_empty());
    let empty = tmp.join("empty");
    fs::create_dir(&empty).unwrap();
    assert!(j::retained_receipts(&empty).is_empty());
}

#[test]
fn install_doctor_uninstall_smoke() {
    if !h::tool_present("dpkg") || !j::have_passwordless_sudo() {
        eprintln!("skip: install smoke needs dpkg plus passwordless sudo");
        return;
    }
    if j::journey_opted_out() {
        eprintln!("skip: MV_RUSTPKG_JOURNEY=0 opts out of the privileged journey");
        return;
    }
    let deb = h::ensure_deb();
    let version = h::engine_version();
    let receipts = j::RECEIPTS;
    let _preexisting = preflight_fresh_state(receipts);
    // Non-Debian hosts (this Fedora-based one) cannot resolve
    // libc6 through dpkg: install with --force-depends there so
    // the journey still exercises install/verify/run/uninstall,
    // with the dependency-resolution proof staying on Debian CI.
    let force_depends = !h::run("dpkg", &["-s", "libc6"], None).status.success();
    if force_depends {
        eprintln!("note: libc6 unresolvable on this host; journey installs with --force-depends");
    }
    // Serialize with the sibling rpm journey: both drive the
    // same installed tree and cargo runs suites in parallel.
    let _lock = j::install_lock();
    let (tmp, qdirs) = j::journey_scratch("journey");
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut install = vec!["-n", "dpkg", "-i"];
        if force_depends {
            install.push("--force-depends");
        }
        install.push(deb.to_str().unwrap());
        let proc = h::run("sudo", &install, None);
        assert!(
            proc.status.success(),
            "{}",
            String::from_utf8_lossy(&proc.stderr)
        );
        let status = h::run("dpkg", &["-s", "memveil"], None);
        assert!(status.status.success());
        assert!(String::from_utf8_lossy(&status.stdout).contains("Status: install ok installed"));
        let verify = h::run("dpkg", &["--verify", "memveil"], None);
        assert!(
            verify.status.success(),
            "{}",
            String::from_utf8_lossy(&verify.stderr)
        );
        // Slim images exclude docs/man at install time (then
        // verify reports them `missing`): clear
        // /etc/dpkg/dpkg.cfg.d/excludes first, as the CI job
        // does, to prove the full payload.
        assert!(
            String::from_utf8_lossy(&verify.stdout).is_empty(),
            "dpkg --verify noisy: {}",
            String::from_utf8_lossy(&verify.stdout)
        );
        j::assert_receipts_installed(receipts);
        j::assert_loader_closure();
        j::assert_doctor_and_version(&version);
        j::record_probe(&tmp);
        j::qualify_legs(&tmp, &qdirs, receipts);
    }));
    // Teardown always runs: remove run residue, then uninstall.
    j::clear_receipts(receipts);
    j::remove_qualify_scratch(&qdirs);
    let uninst = h::run("sudo", &["-n", "dpkg", "-r", "memveil"], None);
    if failed.is_err() {
        assert!(uninst.status.success(), "teardown dpkg -r failed");
        panic!("install journey failed (teardown done)");
    }
    assert!(
        uninst.status.success(),
        "{}",
        String::from_utf8_lossy(&uninst.stderr)
    );
    assert!(!h::run("dpkg", &["-s", "memveil"], None).status.success());
    j::assert_no_residue();
}
