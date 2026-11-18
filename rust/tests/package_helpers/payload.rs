// SPDX-License-Identifier: GPL-3.0-or-later
//! Payload-manifest collect/check port (12 entries, no bridge).
//!
//! Mirrors `tools/payload-gate` over the Rust release packages:
//! the engine binary plus the three BPF inspection objects in
//! each of the .deb, the .rpm, and the owner bundle. The two
//! bridge entries per package are gone with the C bridge
//! (documented delta: 12 entries, not 15).

use super::BPF_OBJECTS;
use super::run_ok;
use super::scratch;
use super::sha256_file;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Logical manifest path -> (package, member path).
pub fn spec() -> Vec<(String, String, String)> {
    let mut entries = Vec::new();
    for (pkg, bin, bpf) in [
        ("deb", "usr/bin/memveil", "usr/lib/memveil"),
        ("rpm", "usr/bin/memveil", "usr/lib/memveil"),
        ("bundle", "bin/memveil", "bpf"),
    ] {
        entries.push((format!("{pkg}/{bin}"), pkg.to_string(), bin.to_string()));
        for obj in BPF_OBJECTS {
            entries.push((
                format!("{pkg}/{bpf}/{obj}"),
                pkg.to_string(),
                format!("{bpf}/{obj}"),
            ));
        }
    }
    entries.sort();
    entries
}

/// Expected logical paths (12).
pub fn expected() -> Vec<String> {
    spec().into_iter().map(|(logical, _, _)| logical).collect()
}

fn extract_deb(deb: &Path, tmp: &Path) -> PathBuf {
    let dest = tmp.join("deb");
    fs::create_dir_all(&dest).expect("deb tmp");
    run_ok(
        "dpkg-deb",
        &["-x", deb.to_str().unwrap(), dest.to_str().unwrap()],
        None,
    );
    dest
}

fn extract_rpm(rpm: &Path, tmp: &Path) -> Result<PathBuf, String> {
    use std::io::Write;
    use std::process::Command;
    use std::process::Stdio;
    let dest = tmp.join("rpm");
    fs::create_dir_all(&dest).expect("rpm tmp");
    let dump = super::run("rpm2cpio", &[rpm.to_str().unwrap()], None);
    if !dump.status.success() {
        return Err(format!(
            "payload-gate: rpm2cpio failed: {}",
            String::from_utf8_lossy(&dump.stderr)
        ));
    }
    let mut cpio = Command::new("cpio");
    cpio.args(["-idm", "--quiet"])
        .current_dir(&dest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cpio.spawn().expect("spawn cpio");
    // cpio exits at the archive trailer, possibly before
    // trailing padding bytes arrive: a late write may hit
    // EPIPE after a successful extract, so the exit status
    // (not the write result) decides success.
    let _ = child
        .stdin
        .as_mut()
        .expect("cpio stdin")
        .write_all(&dump.stdout);
    // Drop stdin before waiting so cpio sees EOF promptly.
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("cpio wait");
    if !out.status.success() {
        return Err(format!(
            "payload-gate: cpio failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(dest)
}

fn extract_bundle(tarball: &Path, tmp: &Path) -> Result<PathBuf, String> {
    let dest = tmp.join("bundle");
    fs::create_dir_all(&dest).expect("bundle tmp");
    let out = super::run("tar", &["-xzf", tarball.to_str().unwrap()], Some(&dest));
    if !out.status.success() {
        return Err(format!(
            "payload-gate: bundle extract failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let tops: Vec<PathBuf> = fs::read_dir(&dest)
        .map_err(|err| format!("payload-gate: bundle list failed: {err}"))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    if tops.len() != 1 {
        return Err("payload-gate: bundle has no single top dir".to_string());
    }
    Ok(tops.into_iter().next().unwrap())
}

/// Hash the 12 payload members of a package set.
pub fn collect(deb: &Path, rpm: &Path, bundle: &Path) -> Result<BTreeMap<String, String>, String> {
    for (path, label) in [(deb, "--deb"), (rpm, "--rpm"), (bundle, "--bundle")] {
        if !path.is_file() {
            return Err(format!(
                "payload-gate: {label} is not a file: {}",
                path.display()
            ));
        }
    }
    for tool in ["dpkg-deb", "rpm2cpio", "cpio"] {
        if !super::tool_present(tool) {
            return Err(format!("payload-gate: {tool} not found"));
        }
    }
    let tmp = scratch("payload-collect");
    let deb_root = extract_deb(deb, &tmp);
    let rpm_root = extract_rpm(rpm, &tmp)?;
    let bundle_root = extract_bundle(bundle, &tmp)?;
    let roots: BTreeMap<&str, PathBuf> = [
        ("deb", deb_root),
        ("rpm", rpm_root),
        ("bundle", bundle_root),
    ]
    .into_iter()
    .collect();
    let mut entries = BTreeMap::new();
    for (logical, pkg, member) in spec() {
        let path = roots[pkg.as_str()].join(&member);
        if !path.is_file() {
            return Err(format!("payload-gate: {pkg} lacks payload member {member}"));
        }
        entries.insert(logical, sha256_file(&path));
    }
    Ok(entries)
}

/// Parse manifest text; `Err` names malformed lines and duplicates.
pub fn parse_manifest(text: &str, label: &str) -> Result<BTreeMap<String, String>, String> {
    let mut entries = BTreeMap::new();
    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let wellformed = parts.len() == 2
            && parts[0].len() == 64
            && parts[0].chars().all(|ch| ch.is_ascii_hexdigit());
        if !wellformed {
            return Err(format!(
                "payload-gate: {label} line {} malformed",
                lineno + 1
            ));
        }
        if entries.contains_key(parts[1]) {
            return Err(format!(
                "payload-gate: {label} line {} duplicates {}",
                lineno + 1,
                parts[1]
            ));
        }
        entries.insert(parts[1].to_string(), parts[0].to_lowercase());
    }
    Ok(entries)
}

/// Render a manifest in collect order.
pub fn render_manifest(entries: &BTreeMap<String, String>) -> String {
    let mut text = String::new();
    for (logical, digest) in entries {
        text.push_str(&format!("{digest}  {logical}\n"));
    }
    text
}

/// Compare a packaged manifest against the tested one.
pub fn check(
    packaged: &BTreeMap<String, String>,
    tested: &BTreeMap<String, String>,
) -> Result<(), String> {
    let spec_paths: BTreeMap<String, ()> = expected().into_iter().map(|path| (path, ())).collect();
    let mut universe: BTreeMap<String, ()> = BTreeMap::new();
    for key in packaged
        .keys()
        .chain(tested.keys())
        .chain(spec_paths.keys())
    {
        universe.insert(key.clone(), ());
    }
    for logical in universe.keys() {
        if !spec_paths.contains_key(logical) {
            return Err(format!("payload-gate: unexpected entry {logical}"));
        }
        if !tested.contains_key(logical) {
            return Err(format!("payload-gate: tested manifest lacks {logical}"));
        }
        if !packaged.contains_key(logical) {
            return Err(format!("payload-gate: packaged manifest lacks {logical}"));
        }
        if tested[logical] == ZEROS {
            return Err(format!(
                "payload-gate: {logical} has no qualified hash (placeholder)"
            ));
        }
        if packaged[logical] != tested[logical] {
            return Err(format!(
                "payload-gate: {} mismatch: packaged {} != tested {}",
                logical, packaged[logical], tested[logical]
            ));
        }
    }
    Ok(())
}
