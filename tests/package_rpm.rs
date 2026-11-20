// SPDX-License-Identifier: GPL-3.0-or-later
//! .rpm gate port: header, manual deps, file list, and spec contract.
//!
//! Ports the artifact assertions of
//! `tests/package/test_rpm_journey.py` plus the `%files`/
//! scriptlet/pinning assertions of `test_deb.py`'s spec section
//! to run against the Rust-built .rpm and
//! `packaging/rpm/memveil.spec`, adjusting only for the
//! known deltas: no bridge (Requires is the glibc floor
//! alone), no conda texts or libbpf-mojo dirs, no Source1.
//! The install journeys run here: a native
//! install/verify/run/uninstall smoke through the shared
//! journey legs (serialized with the .deb journey via the
//! install lock), plus a docker-gated Fedora container
//! journey driven by the bridgeless
//! `scripts/rpm-journey.sh` against the Rust-built .rpm.
//! The Mojo container script (`tests/package/rpm_journey.sh`)
//! keeps its bridge-load step for the Mojo-built .rpm and is
//! not driven here.

#[path = "package_helpers/mod.rs"]
mod package_helpers;

use package_helpers as h;
use package_helpers::journey as j;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

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

/// Verified-manifest members under `prefix` with `suffix`.
fn manifest_members(manifest: &std::path::Path, prefix: &str, suffix: &str) -> Vec<String> {
    let expr = format!(
        "'\\n'.join(sorted(k for k in d['files'] \
         if k.startswith('{prefix}') and k.endswith('{suffix}')))"
    );
    h::json_probe(manifest, &expr)
        .lines()
        .map(str::to_string)
        .collect()
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
    match j::tool_gate(
        "rpm",
        h::tool_present("rpm"),
        h::candidate_mode(),
        "header pins need `rpm -qp`",
    ) {
        j::JourneyGate::Proceed => true,
        j::JourneyGate::Skip(reason) => {
            eprintln!("skip: {reason}");
            false
        }
        j::JourneyGate::Fail(reason) => panic!("{reason}"),
    }
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
    // Sealed artifact names come from the manifest (the loader
    // binds them); only dev builds carry the fixed pattern.
    if !h::candidate_mode() {
        assert_eq!(
            rpm.file_name().unwrap().to_str().unwrap(),
            format!("memveil-{version}-{}.{}.rpm", fields[2], fields[3])
        );
    }
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
    // Candidate mode derives the expected sets from the
    // verified manifest, never the checkout or a fresh bundle.
    let (profile_rels, doc_rels): (Vec<String>, Vec<String>) = if h::candidate_mode() {
        // Manifest rels are tree-rooted; strip to the
        // subdir-relative form the installed map expects.
        let manifest = &h::candidate_inputs().manifest;
        let strip = |rels: Vec<String>, prefix: &str| {
            rels.into_iter()
                .map(|rel| rel.strip_prefix(prefix).unwrap().to_string())
                .collect::<Vec<String>>()
        };
        (
            strip(
                manifest_members(manifest, "profiles/", ".json"),
                "profiles/",
            ),
            strip(manifest_members(manifest, "docs/", ".md"), "docs/"),
        )
    } else {
        let root = h::pristine_root();
        (
            repo_tree_files(&root, "profiles", ".json")
                .into_iter()
                .collect(),
            repo_tree_files(&root, "docs", ".md").into_iter().collect(),
        )
    };
    let mut profiles: BTreeSet<String> = profile_rels
        .into_iter()
        .map(|rel| format!("/usr/share/memveil/profiles/{rel}"))
        .collect();
    profiles.insert("/usr/share/memveil/profiles/manifest.txt".to_string());
    let docs: BTreeSet<String> = doc_rels
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
    // Per-crate notice files: candidate mode reads the
    // verified manifest, dev the bundle manifest the .rpm
    // consumed: every crates/ member plus its parent dirs.
    // Empty suffix matches every member under the prefix.
    let crate_rels: Vec<String> = if h::candidate_mode() {
        manifest_members(&h::candidate_inputs().manifest, "licenses/crates/", "")
    } else {
        let set = h::ensure_tarball();
        let bundle_manifest = set.bundle.join("MANIFEST.json");
        let probe = format!(
            "import json; d = json.load(open({bundle_manifest:?}));\n\
             [print(k) for k in sorted(d['files']) if k.startswith('licenses/crates/')]"
        );
        h::run_ok("python3", &["-c", &probe], None)
            .lines()
            .map(str::to_string)
            .collect()
    };
    let mut crates_files = BTreeSet::new();
    let mut crates_dirs = BTreeSet::from(["/usr/share/doc/memveil/licenses/crates".to_string()]);
    for rel in &crate_rels {
        crates_files.insert(format!("/usr/share/doc/memveil/{rel}"));
        let parent = format!(
            "/usr/share/doc/memveil/{}",
            rel.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
        );
        crates_dirs.insert(parent);
    }
    assert!(!crates_files.is_empty(), "bundle carries no crate texts");
    let mut want = fixed_files();
    want.extend(profiles);
    want.extend(docs);
    want.extend(libs);
    want.extend(crates_files);
    want.extend(crates_dirs);
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
    match j::tool_gate(
        "rpm2cpio/cpio",
        h::tool_present("rpm2cpio") && h::tool_present("cpio"),
        h::candidate_mode(),
        "cannot extract the payload",
    ) {
        j::JourneyGate::Proceed => {}
        j::JourneyGate::Skip(reason) => {
            eprintln!("skip: {reason}");
            return;
        }
        j::JourneyGate::Fail(reason) => panic!("{reason}"),
    }
    let rpm = h::ensure_rpm();
    let dest = h::rpm_extract(&rpm, "rpm-mirror");
    // Candidate mode mirrors the verified manifest, never the
    // checkout.
    if h::candidate_mode() {
        let manifest = &h::candidate_inputs().manifest;
        let mut rels = manifest_members(manifest, "profiles/", ".json");
        rels.extend(manifest_members(manifest, "docs/", ".md"));
        let refs: Vec<&str> = rels.iter().map(String::as_str).collect();
        let staged = h::candidate_stage(&refs);
        for rel in &rels {
            let inst = if rel.starts_with("profiles/") {
                "usr/share/memveil/profiles"
            } else {
                "usr/share/memveil/docs"
            };
            let sub = rel.split_once('/').map(|(_, rest)| rest).unwrap();
            let seen = dest.join(inst).join(sub);
            assert!(seen.is_file(), "{rel}");
            assert_eq!(
                fs::read(&seen).unwrap(),
                fs::read(staged.join(rel)).unwrap(),
                "{rel}"
            );
        }
    } else {
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
fn rpm_install_doctor_uninstall_smoke() {
    match j::journey_gate(
        "rpm",
        h::tool_present("rpm"),
        j::have_passwordless_sudo(),
        j::journey_opted_out(),
        h::candidate_mode(),
    ) {
        j::JourneyGate::Proceed => {}
        j::JourneyGate::Skip(reason) => {
            eprintln!("skip: {reason}");
            return;
        }
        j::JourneyGate::Fail(reason) => panic!("{reason}"),
    }
    let rpm = h::ensure_rpm();
    let version = h::engine_version();
    let receipts = j::RECEIPTS;
    let probe = h::run("rpm", &["-q", "memveil"], None);
    assert!(
        !probe.status.success(),
        "memveil is already installed: remove it and rerun"
    );
    let _preexisting = j::refuse_retained_receipts(receipts);
    // Non-rpm hosts (ubuntu CI) carry no `glibc` package for
    // the spec's floor requirement to resolve against:
    // install with --nodeps there so the journey still
    // exercises install/verify/run/uninstall, with the
    // dependency-resolution proof staying on the Fedora
    // container leg (which runs in this same suite).
    let nodeps = !h::run("rpm", &["-q", "glibc"], None).status.success();
    if nodeps {
        eprintln!("note: no rpm glibc provider on this host; journey installs with --nodeps");
    }
    // Serialize with the sibling deb journey: both drive the
    // same installed tree and cargo runs suites in parallel.
    let _lock = j::install_lock();
    let (tmp, qdirs) = j::journey_scratch("rpm-journey");
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut install = vec!["-n", "rpm", "-i"];
        if nodeps {
            install.push("--nodeps");
        }
        install.push(rpm.to_str().unwrap());
        let proc = h::run("sudo", &install, None);
        assert!(
            proc.status.success(),
            "{}",
            String::from_utf8_lossy(&proc.stderr)
        );
        let status = h::run("rpm", &["-q", "memveil"], None);
        assert!(status.status.success());
        // A --nodeps install leaves the floor requirement
        // unsatisfied by construction; verify files only
        // there (dependency resolution is the Fedora
        // container leg's proof, in this same suite).
        let verify = if nodeps {
            h::run("rpm", &["-V", "--nodeps", "memveil"], None)
        } else {
            h::run("rpm", &["-V", "memveil"], None)
        };
        let verify_stdout = String::from_utf8_lossy(&verify.stdout).into_owned();
        let verify_stderr = String::from_utf8_lossy(&verify.stderr).into_owned();
        assert!(
            verify.status.success(),
            "rpm -V failed:\nstdout:\n{verify_stdout}\nstderr:\n{verify_stderr}"
        );
        assert!(verify_stdout.is_empty());
        // Sealed installs prove the installed tree equals the
        // verified candidate closure before running anything.
        if h::candidate_mode() {
            j::assert_installed_closure_live(std::path::Path::new("/"));
        }
        j::assert_receipts_installed(receipts);
        j::assert_loader_closure();
        j::assert_doctor_and_version(&version);
        j::record_probe(&tmp);
        j::qualify_legs(&tmp, &qdirs, receipts);
    }));
    // Teardown always runs: remove run residue, then uninstall.
    j::clear_receipts(receipts);
    j::remove_qualify_scratch(&qdirs);
    let uninst = h::run("sudo", &["-n", "rpm", "-e", "memveil"], None);
    if failed.is_err() {
        assert!(uninst.status.success(), "teardown rpm -e failed");
        panic!("install journey failed (teardown done)");
    }
    assert!(
        uninst.status.success(),
        "{}",
        String::from_utf8_lossy(&uninst.stderr)
    );
    assert!(!h::run("rpm", &["-q", "memveil"], None).status.success());
    j::assert_no_residue();
}

const FEDORA_IMAGE: &str = "fedora:41";

const JOURNEY_STEPS: [&str; 12] = [
    "dnf-install",
    "rpm-verify",
    "version",
    "receipts-dir",
    "lib-load",
    "runpath",
    "bpf",
    "no-elf-share",
    "man-completions",
    "doctor",
    "record-probe",
    "uninstall-clean",
];

fn docker_usable() -> bool {
    h::tool_present("docker") && h::run("docker", &["info"], None).status.success()
}

fn fedora_image_ready() -> bool {
    if h::run("docker", &["image", "inspect", FEDORA_IMAGE], None)
        .status
        .success()
    {
        return true;
    }
    h::run("docker", &["pull", FEDORA_IMAGE], None)
        .status
        .success()
}

/// Decide the Fedora container journey entry (pure: test the matrix directly).
///
/// Docker/image absence skips in dev but fails in candidate
/// mode: qualification cannot claim dependency resolution
/// it never ran.
fn fedora_gate(docker_usable: bool, image_ready: bool, candidate: bool) -> j::JourneyGate {
    if !docker_usable || !image_ready {
        let reason = if !docker_usable {
            "docker unusable on this host: the Fedora journey cannot run here".to_string()
        } else {
            format!("{FEDORA_IMAGE} image unavailable (offline?): the container journey needs it")
        };
        if candidate {
            return j::JourneyGate::Fail(format!("candidate Fedora journey refused: {reason}"));
        }
        return j::JourneyGate::Skip(reason);
    }
    j::JourneyGate::Proceed
}

#[test]
fn fedora_gate_matrix() {
    // Usable docker with the image proceeds in both modes;
    // either half missing skips in dev and fails in
    // candidate mode, naming the missing half.
    assert_eq!(fedora_gate(true, true, false), j::JourneyGate::Proceed);
    assert_eq!(fedora_gate(true, true, true), j::JourneyGate::Proceed);
    for (usable, ready, missing) in [
        (false, false, "docker unusable"),
        (false, true, "docker unusable"),
        (true, false, "fedora:41 image unavailable"),
    ] {
        match fedora_gate(usable, ready, false) {
            j::JourneyGate::Skip(reason) => {
                assert!(reason.contains(missing), "{reason}");
            }
            other => panic!("dev must skip cleanly, got {other:?}"),
        }
        match fedora_gate(usable, ready, true) {
            j::JourneyGate::Fail(reason) => {
                assert!(reason.contains("candidate"), "{reason}");
                assert!(reason.contains(missing), "{reason}");
            }
            other => panic!("candidate must fail, got {other:?}"),
        }
    }
}

#[test]
fn rpm_fedora_journey() {
    if !need_rpm() {
        return;
    }
    let usable = docker_usable();
    let ready = usable && fedora_image_ready();
    match fedora_gate(usable, ready, h::candidate_mode()) {
        j::JourneyGate::Proceed => {}
        j::JourneyGate::Skip(reason) => {
            eprintln!("skip: {reason}");
            return;
        }
        j::JourneyGate::Fail(reason) => panic!("{reason}"),
    }
    let rpm = h::ensure_rpm();
    let script = h::scripts_dir().join("rpm-journey.sh");
    assert!(script.is_file(), "missing scripts/rpm-journey.sh");
    let rpm_mount = format!("{}:/mnt/m.rpm:ro", rpm.to_str().unwrap());
    let script_mount = format!("{}:/mnt/journey.sh:ro", script.to_str().unwrap());
    let out = h::run(
        "docker",
        &[
            "run",
            "--rm",
            "-v",
            &rpm_mount,
            "-v",
            &script_mount,
            FEDORA_IMAGE,
            "bash",
            "/mnt/journey.sh",
            "/mnt/m.rpm",
        ],
        None,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!("{stdout}");
    eprintln!("{stderr}");
    assert!(
        out.status.success(),
        "fedora journey failed (see log above)"
    );
    for step in JOURNEY_STEPS {
        assert!(
            stdout.contains(&format!("journey-ok: {step}")),
            "journey skipped {step}"
        );
    }
    assert!(
        stdout.contains("journey qualify receipt: ")
            || stdout.contains("journey qualify refusal: "),
        "journey never qualified"
    );
    assert!(stdout.contains("journey: all steps passed"));
}

/// Full spec text (fails when the spec moves).
fn spec_text() -> String {
    let spec = h::packaging_dir().join("rpm").join("memveil.spec");
    assert!(spec.is_file(), "missing packaging/rpm/memveil.spec");
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
    if h::candidate_mode() {
        eprintln!("skip: the committed spec pins checkout source, not sealed artifacts");
        return;
    }
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
            "/usr/share/doc/memveil/licenses/crates/",
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
    // The Requires floor sync lives in spec_requires_derived
    // (placeholder in the committed spec) plus
    // rpm_manual_deps_only (built artifact vs the oracle).
}

#[test]
fn spec_requires_derived() {
    // The committed spec carries the floor placeholder, never a
    // literal: package-rpm.py substitutes the floor it derives
    // from the consumed bundle (shared .deb parser) and then
    // re-verifies the built .rpm Requires against it, so neither
    // side can drift. rpm_manual_deps_only pins the built
    // artifact against the oracle; here the placeholder itself.
    let text = spec_text();
    let functional = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter(|l| l.contains("@MEMVEIL_GLIBC_FLOOR@"))
        .count();
    assert_eq!(
        functional, 1,
        "want exactly one functional floor placeholder"
    );
    let requires = text
        .lines()
        .find_map(|line| line.strip_prefix("Requires:").map(str::trim))
        .expect("manual Requires missing (no auto-deps)");
    assert_eq!(requires, "glibc >= @MEMVEIL_GLIBC_FLOOR@", "{requires}");
    assert!(
        !requires.contains("libelf") && !requires.contains("libz"),
        "{requires}"
    );
    for line in text.lines().filter(|l| l.starts_with("Requires:")) {
        assert!(
            !line.chars().any(|c| c.is_ascii_digit()),
            "literal version leaked into Requires: {line}"
        );
    }
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
    for token in ["scripts/gen-man.py", "scripts/gen-completions.py"] {
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
    // The committed spec carries the floor placeholder (which
    // rpmspec rightly rejects standalone), so parse the derived
    // form exactly as package-rpm.py feeds it to rpmbuild: the
    // placeholder substituted with the oracle floor from the
    // consumed bundle.
    let spec = h::packaging_dir().join("rpm").join("memveil.spec");
    assert!(spec.is_file());
    match j::tool_gate(
        "rpmspec",
        h::tool_present("rpmspec"),
        h::candidate_mode(),
        "the spec check needs `rpmspec -P`",
    ) {
        j::JourneyGate::Proceed => {}
        j::JourneyGate::Skip(reason) => {
            eprintln!("skip: {reason}");
            return;
        }
        j::JourneyGate::Fail(reason) => panic!("{reason}"),
    }
    // Candidate mode derives the floor from the sealed
    // payload, never a fresh bundle build.
    let (major, minor) = if h::candidate_mode() {
        rpm_payload_floor(&h::ensure_rpm())
    } else {
        let set = h::ensure_tarball();
        let binary = set.bundle.join("bin").join("memveil");
        let lib = set.bundle.join("lib").join("memveil").join("libgcc_s.so.1");
        h::glibc_floor(&[binary, lib])
    };
    let text = fs::read_to_string(&spec).unwrap();
    assert!(
        text.contains("@MEMVEIL_GLIBC_FLOOR@"),
        "committed spec lost its floor placeholder"
    );
    let derived = text.replace("@MEMVEIL_GLIBC_FLOOR@", &format!("{major}.{minor}"));
    let tmp = h::scratch("rpmspec-parse");
    let probe = tmp.join("memveil.spec");
    fs::write(&probe, derived).unwrap();
    let out = h::run("rpmspec", &["-P", probe.to_str().unwrap()], None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn sealed_inputs_used() {
    if !h::candidate_mode() {
        eprintln!("skip: sealed-input threading needs candidate inputs");
        return;
    }
    // The journey consumes the sealed pair from beside the
    // manifest: never a build output, even rebuild-gated.
    let inputs = h::candidate_inputs();
    let manifest = std::env::var("MV_CANDIDATE_MANIFEST").unwrap();
    let manifest_dir = std::path::Path::new(&manifest).parent().unwrap();
    assert_eq!(
        inputs.rpm.parent().unwrap(),
        manifest_dir,
        "sealed .rpm must sit beside the manifest"
    );
    assert_eq!(
        inputs.deb.parent().unwrap(),
        manifest_dir,
        "sealed .deb must sit beside the manifest"
    );
    let work = h::work_dir();
    assert!(
        !inputs.rpm.starts_with(&work),
        "resolved a build output, not the sealed input"
    );
    assert!(inputs.rpm.is_file());
    assert_eq!(inputs.rpm.extension().unwrap(), "rpm");
    assert!(inputs.deb.is_file());
    eprintln!("sealed .rpm: {}", inputs.rpm.display());
    eprintln!("sealed .deb: {}", inputs.deb.display());
}

#[test]
fn installed_closure_live_scopes_owned_paths() {
    if !h::candidate_mode() {
        eprintln!("skip: live closure scoping needs candidate inputs");
        return;
    }
    // Same live predicate as the deb suite, through the
    // sealed rpm tree: an unrelated system binary beside
    // the package accepts, while an added alias under an
    // owned path refuses naming path and target.
    fn trial_copy(tmp: &std::path::Path, extracted: &std::path::Path, name: &str) -> PathBuf {
        let trial = tmp.join(name);
        h::run_ok(
            "cp",
            &["-r", extracted.to_str().unwrap(), trial.to_str().unwrap()],
            None,
        );
        trial
    }
    fn refusal_message(f: impl FnOnce() + std::panic::UnwindSafe) -> String {
        match std::panic::catch_unwind(f) {
            Ok(()) => panic!("closure wiring passed a doctored tree"),
            Err(payload) => payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|line| line.to_string()))
                .unwrap_or_default(),
        }
    }
    let rpm = h::ensure_rpm();
    let extracted = h::rpm_extract(&rpm, "closure-live-rpm");
    let tmp = h::scratch("closure-live-neg-rpm");
    let live = trial_copy(&tmp, &extracted, "live");
    fs::write(
        live.join("usr").join("bin").join("unrelated-system-binary"),
        b"not ours",
    )
    .unwrap();
    j::assert_installed_closure_live(&live);
    let linked = trial_copy(&tmp, &extracted, "live-linked");
    std::os::unix::fs::symlink(
        "nowhere-live-target",
        linked
            .join("usr")
            .join("lib")
            .join("memveil")
            .join("alias.so"),
    )
    .unwrap();
    let message = refusal_message(std::panic::AssertUnwindSafe(|| {
        j::assert_installed_closure_live(&linked);
    }));
    assert!(message.contains("alias.so"), "{message}");
    assert!(message.contains("nowhere-live-target"), "{message}");
}
