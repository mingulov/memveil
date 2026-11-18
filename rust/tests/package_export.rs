// SPDX-License-Identifier: GPL-3.0-or-later
//! Source-export packaging port: candidate rule and git-free builds.
//!
//! Ports the packaging subset of
//! `tests/package/test_source_export.py`: a dirty tree cannot
//! produce a candidate, a clean tree records its revision, a
//! git-free export packages with revision `export` (even under
//! a dirty unrelated parent), manifest hashes bind, and every
//! referenced manual ships. The provenance-gate matrix is
//! covered by release requalification instead.

#[path = "package_helpers/mod.rs"]
mod package_helpers;

use package_helpers as h;
use std::fs;

fn package_args(root: &std::path::Path, out: &std::path::Path) -> Vec<String> {
    vec![
        h::scripts_dir()
            .join("package-tarball.py")
            .to_str()
            .unwrap()
            .to_string(),
        "--root".to_string(),
        root.to_str().unwrap().to_string(),
        "--binary".to_string(),
        h::ensure_release_binary().to_str().unwrap().to_string(),
        "--bpf-dir".to_string(),
        h::bpf_out_dir().to_str().unwrap().to_string(),
        "--out".to_string(),
        out.to_str().unwrap().to_string(),
    ]
}

fn run_packager(root: &std::path::Path, out: &std::path::Path) -> std::process::Output {
    let args = package_args(root, out);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    h::run("python3", &refs, None)
}

#[test]
fn dirty_tree_refuses_candidate() {
    let tmp = h::scratch("export-dirty");
    let clone = tmp.join("clone");
    let proc = h::run(
        "git",
        &[
            "clone",
            "--quiet",
            h::repo_root().to_str().unwrap(),
            clone.to_str().unwrap(),
        ],
        None,
    );
    assert!(proc.status.success());
    // Dirty one tracked input; the candidate rule must refuse.
    let readme = fs::read_to_string(clone.join("README.md")).unwrap();
    fs::write(clone.join("README.md"), format!("{readme}\ndirty\n")).unwrap();
    let out = tmp.join("out");
    let proc = run_packager(&clone, &out);
    assert!(!proc.status.success(), "dirty tree packaged");
    assert!(
        String::from_utf8_lossy(&proc.stderr).contains("uncommitted changes"),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
    assert!(
        !out.join(format!("memveil-{}.tar.gz", h::engine_version()))
            .exists()
    );
}

#[test]
fn clean_tree_records_revision() {
    let tmp = h::scratch("export-clean");
    let out = tmp.join("out");
    let root = h::pristine_root();
    let proc = run_packager(&root, &out);
    assert!(
        proc.status.success(),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
    let head = h::run_ok("git", &["rev-parse", "HEAD"], Some(&root));
    let manifest = out
        .join(format!("memveil-{}", h::engine_version()))
        .join("MANIFEST.json");
    assert_eq!(
        h::json_probe(&manifest, "d['memveil_revision']"),
        head.trim()
    );
}

#[test]
fn export_mode_records_export() {
    let tmp = h::scratch("export-mode");
    let export = tmp.join("export");
    fs::create_dir(&export).unwrap();
    let archive = h::run("git", &["archive", "HEAD"], Some(&h::repo_root()));
    assert!(archive.status.success());
    let file = tmp.join("head.tar");
    fs::write(&file, &archive.stdout).unwrap();
    let untar = h::run("tar", &["-xf", file.to_str().unwrap()], Some(&export));
    assert!(untar.status.success());
    let out = tmp.join("out");
    let proc = run_packager(&export, &out);
    assert!(
        proc.status.success(),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
    let bundle = out.join(format!("memveil-{}", h::engine_version()));
    let manifest = bundle.join("MANIFEST.json");
    assert_eq!(h::json_probe(&manifest, "d['memveil_revision']"), "export");
    // A dirty unrelated parent changes nothing: the export owns no repo.
    let parent = tmp.join("parent");
    fs::create_dir(&parent).unwrap();
    h::run_ok("git", &["-C", parent.to_str().unwrap(), "init", "-q"], None);
    fs::write(parent.join("unrelated-dirty.txt"), "dirty parent\n").unwrap();
    let nested = parent.join("export");
    let cp = h::run(
        "cp",
        &["-r", export.to_str().unwrap(), nested.to_str().unwrap()],
        None,
    );
    assert!(cp.status.success());
    let out2 = tmp.join("out2");
    let proc = run_packager(&nested, &out2);
    assert!(
        proc.status.success(),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
    let manifest2 = out2
        .join(format!("memveil-{}", h::engine_version()))
        .join("MANIFEST.json");
    assert_eq!(h::json_probe(&manifest2, "d['memveil_revision']"), "export");
}

#[test]
fn export_manifest_hashes_bind_and_manuals_ship() {
    let tmp = h::scratch("export-bind");
    let export = tmp.join("export");
    fs::create_dir(&export).unwrap();
    let archive = h::run("git", &["archive", "HEAD"], Some(&h::repo_root()));
    assert!(archive.status.success());
    let file = tmp.join("head.tar");
    fs::write(&file, &archive.stdout).unwrap();
    assert!(
        h::run("tar", &["-xf", file.to_str().unwrap()], Some(&export))
            .status
            .success()
    );
    let out = tmp.join("out");
    let proc = run_packager(&export, &out);
    assert!(
        proc.status.success(),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
    let bundle = out.join(format!("memveil-{}", h::engine_version()));
    let manifest = bundle.join("MANIFEST.json");
    let probe = format!(
        "import json; d = json.load(open({manifest:?})); \
         [print('%s|%s' % (k, v)) for k, v in sorted(d['files'].items())]"
    );
    let text = h::run_ok("python3", &["-c", &probe], None);
    assert_ne!(text.lines().count(), 0);
    for line in text.lines() {
        let (rel, want) = line.split_once('|').expect("rel|sha");
        assert_eq!(h::sha256_file(&bundle.join(rel)), want, "{rel}");
    }
    for name in [
        "troubleshooting.md",
        "performance.md",
        "resource-limits.md",
        "permissions.md",
        "oracles.md",
    ] {
        assert!(bundle.join("docs").join(name).is_file(), "docs lack {name}");
    }
}
