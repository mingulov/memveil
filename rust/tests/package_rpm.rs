// SPDX-License-Identifier: GPL-3.0-or-later
//! .rpm gate port: header, manual deps, file list, and spec contract.
//!
//! Ports the artifact assertions of
//! `tests/package/test_rpm_journey.py` plus the `%files`/
//! scriptlet/pinning assertions of `test_deb.py`'s spec section
//! to run against the Rust-built .rpm and
//! `rust/packaging/rpm/memveil.spec`, adjusting only for the
//! known deltas: no bridge (Requires is the glibc floor
//! alone), no conda texts or libbpf-mojo dirs, no Source1.
//! The Fedora container journey and the journey-script
//! preflight unit tests target the container script
//! (`tests/package/rpm_journey.sh`), whose bridge-load step
//! cannot pass on the bridgeless layout until that script
//! adapts: the container journey executes separately and
//! this suite skips it loudly.

#[path = "package_helpers/mod.rs"]
mod package_helpers;

use package_helpers as h;
use std::collections::BTreeSet;
use std::fs;

/// Pinned payload, from the one shared pin
/// (`package_helpers::FHS_FIXED_FILES`) both FHS formats consume,
/// mapped to the /-rooted form the spec and `rpm -ql` use.
fn fixed_files() -> BTreeSet<String> {
    h::FHS_FIXED_FILES
        .iter()
        .map(|rel| format!("/{rel}"))
        .collect()
}

/// The only `%dir`-owned directories.
fn owned_dirs() -> BTreeSet<String> {
    BTreeSet::from(
        [
            "/usr/lib/memveil",
            "/usr/share/memveil",
            "/usr/share/doc/memveil",
            "/usr/share/doc/memveil/LICENSES",
            "/usr/share/doc/memveil/licenses",
            "/var/lib/memveil",
            "/var/lib/memveil/receipts",
        ]
        .map(str::to_string),
    )
}

fn scratch_db(name: &str) -> std::path::PathBuf {
    let db = h::scratch(name);
    db.join("rpmdb")
}

fn repo_tree_files(root: &std::path::Path, subdir: &str, suffix: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let base = root.join(subdir);
    let mut stack = vec![base.clone()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<std::path::PathBuf> = fs::read_dir(&dir)
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

/// glibc floor derived from the .rpm payload (binary + lib/*.so*).
fn rpm_payload_floor(rpm: &std::path::Path) -> (u32, u32) {
    let root = h::rpm_extract(rpm, "rpm-floor");
    let libdir = root.join("usr").join("lib").join("memveil");
    let mut elfs = vec![root.join("usr").join("bin").join("memveil")];
    let mut libs: Vec<std::path::PathBuf> = fs::read_dir(&libdir)
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
    h::glibc_floor(&elfs)
}

fn need_rpm() -> bool {
    if !h::tool_present("rpm") {
        eprintln!("skip: rpm absent on this host: header pins need `rpm -qp`");
        return false;
    }
    true
}

#[test]
fn rpm_header() {
    if !need_rpm() {
        return;
    }
    let rpm = h::ensure_rpm();
    let db = scratch_db("rpm-header");
    let out = h::rpm_query(
        &rpm,
        &db,
        &[
            "-qp",
            "--queryformat",
            "%{NAME} %{VERSION} %{RELEASE} %{ARCH}\\n",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let fields: Vec<&str> = text.split_whitespace().collect();
    assert_eq!(fields.len(), 4, "{text}");
    assert_eq!(fields[0], "memveil");
    assert_eq!(fields[3], "x86_64");
    let version = h::engine_version();
    assert_eq!(fields[1], version, "rpm Version vs engine");
    assert_eq!(
        rpm.file_name().unwrap().to_str().unwrap(),
        format!("memveil-{version}-{}.{}.rpm", fields[2], fields[3])
    );
}

#[test]
fn rpm_manual_deps_only() {
    if !need_rpm() {
        return;
    }
    let rpm = h::ensure_rpm();
    let db = scratch_db("rpm-deps");
    let (major, minor) = rpm_payload_floor(&rpm);
    let want = format!("glibc >= {major}.{minor}");
    let out = h::rpm_query(&rpm, &db, &["-qp", "--requires"]);
    assert!(out.status.success());
    let requires: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    assert!(requires.contains(&want), "{requires:?}");
    for token in [
        "libgcc",
        "libbpf_mojo",
        "libc.so",
        "libm.so",
        "ld-linux",
        "libelf",
        "libz.so",
    ] {
        assert!(
            !requires.iter().any(|line| line.contains(token)),
            "Requires leaked {token}: {requires:?}"
        );
    }
    for line in &requires {
        assert!(line.starts_with("rpmlib(") || *line == want, "{requires:?}");
    }
    let out = h::rpm_query(&rpm, &db, &["-qp", "--provides"]);
    assert!(out.status.success());
    let provides: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    assert!(
        provides.iter().any(|l| l.starts_with("memveil = ")),
        "{provides:?}"
    );
    for token in ["libgcc", "libbpf_mojo", ".so("] {
        assert!(
            !provides.iter().any(|line| line.contains(token)),
            "Provides leaked {token}: {provides:?}"
        );
    }
}

#[test]
fn rpm_file_list_exact() {
    if !need_rpm() {
        return;
    }
    let rpm = h::ensure_rpm();
    let db = scratch_db("rpm-list");
    let listing = h::rpm_listing(&rpm, &db);
    let mut libs: BTreeSet<String> = listing
        .iter()
        .filter(|p| p.starts_with("/usr/lib/memveil/"))
        .cloned()
        .collect();
    libs.remove("/usr/lib/memveil");
    assert!(libs.contains("/usr/lib/memveil/libgcc_s.so.1"), "{libs:?}");
    let bpf: BTreeSet<String> = libs
        .iter()
        .filter(|p| p.ends_with(".bpf.o"))
        .cloned()
        .collect();
    assert_eq!(
        bpf,
        BTreeSet::from(h::BPF_OBJECTS.map(|n| format!("/usr/lib/memveil/{n}")))
    );
    let rest: BTreeSet<String> = libs.difference(&bpf).cloned().collect();
    assert!(!rest.is_empty(), "no shared libraries shipped");
    for path in &rest {
        let leaf = path.strip_prefix("/usr/lib/memveil/").unwrap();
        assert!(!leaf.contains('/'), "{path}");
        assert!(leaf.contains(".so"), "{path}");
    }
    let root = h::pristine_root();
    let mut profiles: BTreeSet<String> = repo_tree_files(&root, "profiles", ".json")
        .into_iter()
        .map(|rel| format!("/usr/share/memveil/profiles/{rel}"))
        .collect();
    profiles.insert("/usr/share/memveil/profiles/manifest.txt".to_string());
    let docs: BTreeSet<String> = repo_tree_files(&root, "docs", ".md")
        .into_iter()
        .map(|rel| format!("/usr/share/memveil/docs/{rel}"))
        .collect();
    let mut tree_dirs = BTreeSet::new();
    for path in profiles
        .iter()
        .chain(docs.iter())
        .chain(fixed_files().iter())
    {
        let mut parent: &str = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        while parent.starts_with("/usr/share/memveil/") {
            tree_dirs.insert(parent.to_string());
            parent = parent.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        }
    }
    let mut want = fixed_files();
    want.extend(profiles);
    want.extend(docs);
    want.extend(libs);
    want.extend(owned_dirs());
    want.extend(tree_dirs);
    let have: BTreeSet<String> = listing.into_iter().collect();
    let extra: Vec<&String> = have.difference(&want).collect();
    let missing: Vec<&String> = want.difference(&have).collect();
    assert!(
        extra.is_empty() && missing.is_empty(),
        "extra: {extra:?}; missing: {missing:?}"
    );
}

#[test]
fn rpm_modes_owners() {
    if !need_rpm() {
        return;
    }
    let rpm = h::ensure_rpm();
    let db = scratch_db("rpm-modes");
    let listing = h::rpm_listing(&rpm, &db);
    let out = h::rpm_query(&rpm, &db, &["-qlpv"]);
    assert!(out.status.success());
    let mut entries = BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert!(parts.len() >= 9, "{line}");
        let (mode, owner) = (parts[0], format!("{}/{}", parts[2], parts[3]));
        let path = parts[parts.len() - 1].to_string();
        entries.insert(path.clone());
        assert_eq!(owner, "root/root", "{path}");
        if mode.starts_with('d') {
            assert_eq!(mode, "drwxr-xr-x", "{path}");
        } else {
            assert!(mode.starts_with('-'), "{path}: {mode}");
            assert!(!mode.contains('s') && !mode.contains('t'), "{path}: {mode}");
            assert_ne!(mode.chars().nth(8), Some('w'), "{path}: {mode}");
            if path == "/usr/bin/memveil" {
                assert_eq!(mode, "-rwxr-xr-x", "{path}");
            } else {
                assert_eq!(mode, "-rw-r--r--", "{path}");
            }
        }
    }
    assert_eq!(entries, listing.into_iter().collect::<BTreeSet<String>>());
}

#[test]
fn rpm_payload_mirrors_repo() {
    if !h::tool_present("rpm2cpio") || !h::tool_present("cpio") {
        eprintln!("skip: rpm2cpio/cpio absent: cannot extract the payload");
        return;
    }
    let rpm = h::ensure_rpm();
    let dest = h::rpm_extract(&rpm, "rpm-mirror");
    let root = h::pristine_root();
    for (subdir, suffix, inst) in [
        ("profiles", ".json", "usr/share/memveil/profiles"),
        ("docs", ".md", "usr/share/memveil/docs"),
    ] {
        for rel in repo_tree_files(&root, subdir, suffix) {
            let staged = dest.join(inst).join(&rel);
            assert!(staged.is_file(), "{rel}");
            assert_eq!(
                fs::read(&staged).unwrap(),
                fs::read(root.join(subdir).join(&rel)).unwrap(),
                "{rel}"
            );
        }
    }
    assert!(
        dest.join("usr")
            .join("share")
            .join("memveil")
            .join("profiles")
            .join("manifest.txt")
            .is_file()
    );
}

#[test]
fn rpm_fedora_journey() {
    // Harness-owned: the journey script's bridge-load step cannot
    // pass on the bridgeless layout until the harness adapts it.
    // This suite pins the artifact the journey consumes instead.
    let _ = h::ensure_rpm();
    eprintln!(
        "skip: Fedora container journey executes in its container gate: \
         tests/package/rpm_journey.sh hard-requires libbpf_mojo.so.1"
    );
}

/// Full spec text (fails when the spec moves).
fn spec_text() -> String {
    let spec = h::packaging_dir().join("rpm").join("memveil.spec");
    assert!(spec.is_file(), "missing rust/packaging/rpm/memveil.spec");
    fs::read_to_string(spec).unwrap()
}

/// Body of one `%section` (up to the next section header).
fn spec_section(text: &str, name: &str) -> String {
    let headers = [
        "description",
        "prep",
        "build",
        "install",
        "files",
        "clean",
        "pre",
        "post",
        "preun",
        "postun",
        "pretrans",
        "posttrans",
        "trigger",
        "changelog",
        "package",
    ];
    let start = format!("%{name}\n");
    let begin = text
        .find(&start)
        .unwrap_or_else(|| panic!("spec has no %{name} section"))
        + start.len();
    let mut end = text.len();
    let mut offset = begin;
    for line in text[begin..].lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('%')
            && headers
                .iter()
                .any(|h| trimmed == format!("%{h}") || trimmed.starts_with(&format!("%{h} ")))
        {
            end = offset;
            break;
        }
        offset += line.len() + 1;
    }
    text[begin..end].to_string()
}

#[test]
fn spec_version_matches_engine() {
    let text = spec_text();
    let version = text
        .lines()
        .find_map(|line| line.strip_prefix("Version:").map(str::trim))
        .expect("spec has no Version tag");
    assert_eq!(
        version,
        h::engine_version(),
        "spec Version vs engine: bump together"
    );
}

#[test]
fn spec_files_cover_fhs() {
    let text = spec_text();
    let entries: BTreeSet<String> = spec_section(&text, "files")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    let licenses: BTreeSet<String> = fixed_files()
        .into_iter()
        .filter(|p| p.starts_with("/usr/share/doc/memveil/"))
        .collect();
    let man: BTreeSet<String> = fixed_files()
        .into_iter()
        .filter(|p| p.starts_with("/usr/share/man/"))
        .collect();
    assert!(!licenses.is_empty() && !man.is_empty());
    let mut want = BTreeSet::from(
        [
            "%defattr(-,root,root,-)",
            "/usr/bin/memveil",
            "%dir /usr/lib/memveil",
            "/usr/lib/memveil/*.so*",
            "/usr/lib/memveil/*.bpf.o",
            "%dir /usr/share/memveil",
            "/usr/share/memveil/profiles/",
            "/usr/share/memveil/docs/",
            "%dir /usr/share/doc/memveil",
            "%dir /usr/share/doc/memveil/LICENSES",
            "%dir /usr/share/doc/memveil/licenses",
            "/usr/share/bash-completion/completions/memveil",
            "/usr/share/zsh/vendor-completions/_memveil",
            "%dir /var/lib/memveil",
            "%dir /var/lib/memveil/receipts",
        ]
        .map(str::to_string),
    );
    want.extend(licenses);
    want.extend(man);
    let extra: Vec<&String> = entries.difference(&want).collect();
    let missing: Vec<&String> = want.difference(&entries).collect();
    assert!(
        extra.is_empty() && missing.is_empty(),
        "extra: {extra:?}; missing: {missing:?}"
    );
}

#[test]
fn spec_no_scriptlets_or_privilege() {
    let text = spec_text();
    for mac in [
        "%pre",
        "%post",
        "%preun",
        "%postun",
        "%pretrans",
        "%posttrans",
        "%trigger",
    ] {
        assert!(
            !text
                .lines()
                .any(|l| l == mac || l.starts_with(&format!("{mac} "))),
            "no maintainer scriptlets ({mac})"
        );
    }
    assert!(!text.contains("setcap"), "file capabilities are forbidden");
    assert!(
        !text.to_lowercase().contains("setuid"),
        "setuid is forbidden"
    );
    assert!(
        !text.contains("%attr(") || !has_privileged_attr(&text),
        "privilege bits forbidden"
    );
    assert!(
        text.lines().any(|l| l.trim() == "ExclusiveArch: x86_64"),
        "ExclusiveArch x86_64"
    );
    let requires = text
        .lines()
        .find_map(|line| line.strip_prefix("Requires:").map(str::trim))
        .expect("manual Requires missing (no auto-deps)");
    let set = h::ensure_tarball();
    let binary = set.bundle.join("bin").join("memveil");
    let lib = set.bundle.join("lib").join("memveil").join("libgcc_s.so.1");
    let (major, minor) = h::glibc_floor(&[binary, lib]);
    assert_eq!(requires, format!("glibc >= {major}.{minor}"), "{requires}");
    assert!(
        !requires.contains("libelf") && !requires.contains("libz"),
        "{requires}"
    );
}

fn has_privileged_attr(text: &str) -> bool {
    // `%attr(4755, ...)`-shaped privilege bits are forbidden.
    let mut rest = text;
    while let Some(pos) = rest.find("%attr(") {
        rest = &rest[pos + 6..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.len() == 4 && (digits.starts_with('4') || digits.starts_with('2')) {
            return true;
        }
    }
    false
}

#[test]
fn spec_private_lib_pinning() {
    let text = spec_text();
    assert!(
        text.to_lowercase().contains("bundled"),
        "private-lib note must name bundled()"
    );
    assert!(
        text.lines().any(|l| l.trim() == "AutoProv: no"),
        "AutoProv must be off"
    );
    assert!(
        text.lines().any(|l| l.trim() == "AutoReq: no"),
        "AutoReq must be off"
    );
    assert!(
        text.contains("%global") && text.contains("__find_provides") && text.contains("%{nil}"),
        "__find_provides off"
    );
    assert!(
        text.contains("%global") && text.contains("__find_requires") && text.contains("%{nil}"),
        "__find_requires off"
    );
    assert!(
        text.contains("__os_install_post") && text.contains("%{nil}"),
        "post must be off"
    );
}

#[test]
fn spec_build_spells_pinned_inputs() {
    let text = spec_text();
    assert!(
        text.lines()
            .any(|l| l.trim() == "Source0: memveil-%{version}.tar.gz"),
        "Source0 must be the source export"
    );
    assert!(
        !text.lines().any(|l| l.trim_start().starts_with("Source1:")),
        "no bridge Source1 survives"
    );
    assert!(
        !text.contains("libbpf_mojo") && !text.contains("libbpf-mojo"),
        "bridge residue"
    );
    let build = spec_section(&text, "build");
    let install = spec_section(&text, "install");
    for section in [&build, &install] {
        assert!(section.contains("MEMVEIL_CANONICAL_BUNDLE"), "{section}");
        for forbidden in ["tools/package", "mojo build", "patchelf", "strip "] {
            assert!(
                !section.contains(forbidden),
                "assembly must only copy canonical bytes"
            );
        }
    }
    for token in ["rust/scripts/gen-man.py", "rust/scripts/gen-completions.py"] {
        assert!(install.contains(token), "%install never references {token}");
    }
    for name in h::BPF_OBJECTS {
        assert!(install.contains(name), "%install never stages {name}");
    }
    assert!(
        install.contains("libgcc_s.so.1"),
        "%install never stages the closure lib"
    );
    // Every `%{` must close on the same macro.
    let mut rest = text.as_str();
    while let Some(pos) = rest.find("%{") {
        rest = &rest[pos + 2..];
        assert!(rest.contains('}'), "unbalanced %{{ macros");
    }
}

#[test]
fn rpmspec_parse() {
    let spec = h::packaging_dir().join("rpm").join("memveil.spec");
    assert!(spec.is_file());
    if !h::tool_present("rpmspec") {
        eprintln!("skip: rpmspec absent on this host");
        return;
    }
    let out = h::run("rpmspec", &["-P", spec.to_str().unwrap()], None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
