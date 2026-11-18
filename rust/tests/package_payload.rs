// SPDX-License-Identifier: GPL-3.0-or-later
//! Payload-gate and SBOM ports over the three Rust packages.
//!
//! Ports `tests/package/test_payload_gate.py` and
//! `tests/package/test_sbom.py` onto the helper collect/check
//! and SPDX emit ports, adjusting only for the known deltas:
//! 12 payload entries (no bridge), Cargo crate pins instead of
//! the bridge/toolchain lock pins, and no committed byte-pin
//! manifest (the collected manifest's shape stands in until
//! requalification pins release bytes).

#[path = "package_helpers/mod.rs"]
mod package_helpers;

use package_helpers as h;
use std::collections::BTreeMap;
use std::fs;

fn packages() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let set = h::ensure_tarball();
    let deb = h::ensure_deb();
    let rpm = h::ensure_rpm();
    (deb, rpm, set.tarball)
}

fn locks() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = h::pristine_root();
    (
        root.join("rust").join("Cargo.lock"),
        root.join("rust")
            .join("crates")
            .join("ebpf")
            .join("Cargo.lock"),
    )
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn flip_first(digest: &str) -> String {
    let mut out = digest.to_string();
    let first = out.chars().next().unwrap();
    out.replace_range(0..1, if first == '0' { "1" } else { "0" });
    out
}

#[test]
fn collect_covers_twelve_payload_files() {
    let (deb, rpm, bundle) = packages();
    let entries = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    let mut keys: Vec<String> = entries.keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, h::payload::expected());
    assert_eq!(keys.len(), 12);
    for (logical, digest) in &entries {
        assert!(is_hex64(digest), "{logical}");
        assert_ne!(digest, &"0".repeat(64), "{logical}");
    }
}

#[test]
fn collect_is_deterministic() {
    let (deb, rpm, bundle) = packages();
    let first = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    let second = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    assert_eq!(
        h::payload::render_manifest(&first),
        h::payload::render_manifest(&second)
    );
}

#[test]
fn check_self_passes() {
    let (deb, rpm, bundle) = packages();
    let entries = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    h::payload::check(&entries, &entries).expect("self check");
}

#[test]
fn check_flipped_hash_fails() {
    let (deb, rpm, bundle) = packages();
    let entries = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    let mut flipped = entries.clone();
    let key = "deb/usr/bin/memveil".to_string();
    flipped.insert(key.clone(), flip_first(&entries[&key]));
    let err = h::payload::check(&flipped, &entries).expect_err("flipped must fail");
    assert!(err.contains("deb/usr/bin/memveil mismatch"), "{err}");
}

#[test]
fn check_zero_hash_fails() {
    let (deb, rpm, bundle) = packages();
    let entries = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    let mut zeros = entries.clone();
    zeros.insert("rpm/usr/bin/memveil".to_string(), "0".repeat(64));
    let err = h::payload::check(&entries, &zeros).expect_err("placeholder must fail");
    assert!(err.contains("placeholder"), "{err}");
}

#[test]
fn check_missing_entry_fails() {
    let (deb, rpm, bundle) = packages();
    let entries = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    let mut short = entries.clone();
    short.remove("bundle/bin/memveil");
    let err = h::payload::check(&short, &entries).expect_err("missing must fail");
    assert!(err.contains("bundle/bin/memveil"), "{err}");
}

#[test]
fn check_extra_entry_fails() {
    let (deb, rpm, bundle) = packages();
    let entries = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    let mut extra = entries.clone();
    extra.insert("deb/usr/bin/evil".to_string(), "1".repeat(64));
    let err = h::payload::check(&extra, &entries).expect_err("extra must fail");
    assert!(err.contains("unexpected entry"), "{err}");
}

#[test]
fn check_malformed_line_fails() {
    let err =
        h::payload::parse_manifest("not-a-manifest-line\n", "packaged").expect_err("malformed");
    assert!(err.contains("malformed"), "{err}");
    let dup =
        "ab".repeat(32) + "  deb/usr/bin/memveil\n" + &"ab".repeat(32) + "  deb/usr/bin/memveil\n";
    let err = h::payload::parse_manifest(&dup, "packaged").expect_err("duplicate");
    assert!(err.contains("duplicates"), "{err}");
}

#[test]
fn check_missing_file_fails() {
    let (deb, rpm, bundle) = packages();
    let missing = h::scratch("missing-pkg").join("nope.deb");
    assert!(h::payload::collect(&missing, &rpm, &bundle).is_err());
    let _ = deb;
}

#[test]
fn collected_manifest_wellformed() {
    // Adjusted: no committed release byte-pin exists yet (the
    // cutover requalification pins release bytes), so the
    // collected manifest's own shape is the wellformedness pin.
    let (deb, rpm, bundle) = packages();
    let entries = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    let mut keys: Vec<String> = entries.keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, h::payload::expected());
    for digest in entries.values() {
        assert!(is_hex64(digest));
    }
}

#[test]
fn tampered_deb_fails_against_untampered() {
    let (deb, rpm, bundle) = packages();
    let entries = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    let tmp = h::scratch("tamper");
    let root = tmp.join("root");
    h::run_ok(
        "dpkg-deb",
        &["-R", deb.to_str().unwrap(), root.to_str().unwrap()],
        None,
    );
    let target = root.join("usr").join("bin").join("memveil");
    let mut bytes = fs::read(&target).unwrap();
    bytes[0] ^= 1;
    fs::write(&target, bytes).unwrap();
    let tampered = tmp.join("tampered.deb");
    h::run_ok(
        "dpkg-deb",
        &["-b", root.to_str().unwrap(), tampered.to_str().unwrap()],
        None,
    );
    let tainted = h::payload::collect(&tampered, &rpm, &bundle).expect("collect tampered");
    let err = h::payload::check(&tainted, &entries).expect_err("tamper must fail");
    assert!(err.contains("deb/usr/bin/memveil mismatch"), "{err}");
}

#[test]
fn bundle_missing_member_fails_collect() {
    let (deb, rpm, _) = packages();
    let tmp = h::scratch("hollow");
    let top = tmp.join("memveil-0.0.0");
    fs::create_dir(&top).unwrap();
    let hollow = tmp.join("hollow.tar.gz");
    let out = h::run(
        "tar",
        &["-czf", hollow.to_str().unwrap(), "memveil-0.0.0"],
        Some(&tmp),
    );
    assert!(out.status.success());
    let err = h::payload::collect(&deb, &rpm, &hollow).expect_err("hollow must fail");
    assert!(err.contains("lacks payload member"), "{err}");
}

#[test]
fn spdx_envelope() {
    let (deb, rpm, bundle) = packages();
    let (lock, ebpf_lock) = locks();
    let tmp = h::scratch("spdx-envelope");
    let out = tmp.join("memveil.spdx.json");
    h::sbom::emit_spdx(&bundle, &deb, &rpm, &lock, &ebpf_lock, &out).expect("emit");
    assert_eq!(h::json_probe(&out, "d['spdxVersion']"), "SPDX-2.3");
    assert_eq!(h::json_probe(&out, "d['dataLicense']"), "CC0-1.0");
    assert_eq!(h::json_probe(&out, "d['SPDXID']"), "SPDXRef-DOCUMENT");
    assert!(h::json_probe(&out, "d['name']").starts_with("memveil-"));
    assert!(h::json_probe(&out, "d['documentNamespace']").starts_with("urn:memveil:"));
    assert!(h::json_probe(&out, "d['creationInfo']['created']").ends_with('Z'));
    assert_eq!(
        h::json_probe(
            &out,
            "[r for r in d['relationships'] if r['relationshipType'] == 'DESCRIBES'].__len__()"
        ),
        "1"
    );
    let root = h::json_probe(
        &out,
        "[p['SPDXID'] for p in d['packages'] if p['name'] == 'memveil']",
    );
    let related = h::json_probe(
        &out,
        "[r['relatedSpdxElement'] for r in d['relationships'] if r['relationshipType'] == 'DESCRIBES']",
    );
    assert_eq!(root, related);
}

#[test]
fn payload_hashes_match_collect() {
    let (deb, rpm, bundle) = packages();
    let (lock, ebpf_lock) = locks();
    let tmp = h::scratch("spdx-payload");
    let out = tmp.join("memveil.spdx.json");
    h::sbom::emit_spdx(&bundle, &deb, &rpm, &lock, &ebpf_lock, &out).expect("emit");
    let entries = h::payload::collect(&deb, &rpm, &bundle).expect("collect");
    assert_eq!(entries.len(), 12);
    for (logical, digest) in &entries {
        let probe =
            format!("[f['checksums'] for f in d['files'] if f['fileName'] == 'payload/{logical}']");
        let got = h::json_probe(&out, &probe);
        assert!(got.contains(digest), "{logical}: {got}");
    }
}

#[test]
fn cargo_crates_match_locks() {
    let (deb, rpm, bundle) = packages();
    let (lock, ebpf_lock) = locks();
    let tmp = h::scratch("spdx-locks");
    let out = tmp.join("memveil.spdx.json");
    h::sbom::emit_spdx(&bundle, &deb, &rpm, &lock, &ebpf_lock, &out).expect("emit");
    // Binding direction: every manifest crate (the normal-edge
    // closure the packager recorded) must match the lock entry
    // by version and checksum, and appear in the SPDX. The lock
    // additionally holds dev-only crates (anyhow, …) that the
    // closure — and therefore the SPDX — correctly omits.
    let mut locked: BTreeMap<(String, String), String> = BTreeMap::new();
    for (name, version, _source, sum) in h::cargo_lock_packages(&lock)
        .into_iter()
        .chain(h::cargo_lock_packages(&ebpf_lock))
    {
        if !sum.is_empty() {
            locked.insert((name, version), sum);
        }
    }
    let text = h::sbom::manifest_from_bundle(&bundle).expect("manifest");
    let facts = h::sbom::manifest_facts(&text).expect("facts");
    let mut crates = facts.crates;
    crates.extend(facts.ebpf_crates);
    assert!(!crates.is_empty());
    assert!(crates.iter().any(|c| c.name == "aya"), "aya missing");
    assert!(
        crates.iter().any(|c| c.name == "aya-ebpf"),
        "aya-ebpf missing"
    );
    for krate in &crates {
        let key = (krate.name.clone(), krate.version.clone());
        let sum = locked
            .get(&key)
            .unwrap_or_else(|| panic!("{} {} not locked", krate.name, krate.version));
        let probe = format!(
            "[[p['versionInfo'], p['checksums'][0]['checksumValue']] for p in d['packages'] if p['name'] == '{}']",
            krate.name
        );
        let got = h::json_probe(&out, &probe);
        assert!(
            got.contains(&format!("[\"{}\", \"{}\"]", krate.version, sum)),
            "{}: {got}",
            krate.name
        );
    }
    assert_eq!(h::pinned_cargo_version(), "1.100.0");
    assert_eq!(
        h::json_probe(
            &out,
            "[p['versionInfo'] for p in d['packages'] if p['name'] == 'cargo']"
        ),
        "[\"1.100.0\"]"
    );
    assert_eq!(
        h::json_probe(
            &out,
            "[p['versionInfo'] for p in d['packages'] if p['name'] == 'rustc']"
        ),
        format!("[\"{}\"]", h::pinned_rustc_version())
    );
}

#[test]
fn container_hashes_match_shipped_files() {
    let (deb, rpm, bundle) = packages();
    let (lock, ebpf_lock) = locks();
    let tmp = h::scratch("spdx-containers");
    let out = tmp.join("memveil.spdx.json");
    h::sbom::emit_spdx(&bundle, &deb, &rpm, &lock, &ebpf_lock, &out).expect("emit");
    for path in [&bundle, &deb, &rpm] {
        let name = path.file_name().unwrap().to_str().unwrap();
        let probe = format!(
            "[p['checksums'][0]['checksumValue'] for p in d['packages'] if p['name'] == '{name}']"
        );
        let got = h::json_probe(&out, &probe);
        assert!(got.contains(&h::sha256_file(path)), "{name}: {got}");
    }
}

#[test]
fn deterministic_except_created() {
    let (deb, rpm, bundle) = packages();
    let (lock, ebpf_lock) = locks();
    let tmp = h::scratch("spdx-det");
    let first = tmp.join("first.spdx.json");
    let second = tmp.join("second.spdx.json");
    h::sbom::emit_spdx(&bundle, &deb, &rpm, &lock, &ebpf_lock, &first).expect("emit");
    h::sbom::emit_spdx(&bundle, &deb, &rpm, &lock, &ebpf_lock, &second).expect("emit");
    let normalize = |path: &std::path::Path| {
        h::json_probe(
            path,
            "dict(d, creationInfo=dict(d['creationInfo'], created='STAMP'))",
        )
    };
    assert_eq!(normalize(&first), normalize(&second));
}

#[test]
fn lock_disagreement_fails() {
    let (deb, rpm, bundle) = packages();
    let (lock, ebpf_lock) = locks();
    let tmp = h::scratch("spdx-disagree");
    let bad_lock = tmp.join("bad-lock.toml");
    let mut text = fs::read_to_string(&lock).unwrap();
    // Corrupt one checksum byte so the lock no longer matches the manifest pin.
    let pos = text.find("checksum = \"").expect("lock has checksums") + 12;
    let replacement = if text[pos..].starts_with('0') {
        "1"
    } else {
        "0"
    };
    text.replace_range(pos..pos + 1, replacement);
    fs::write(&bad_lock, text).unwrap();
    let out = tmp.join("disagree.spdx.json");
    let err = h::sbom::emit_spdx(&bundle, &deb, &rpm, &bad_lock, &ebpf_lock, &out)
        .expect_err("disagreement must fail");
    assert!(err.contains("disagreement"), "{err}");
    assert!(!out.exists());
}

#[test]
fn bundle_without_manifest_fails() {
    let (deb, rpm, _) = packages();
    let (lock, ebpf_lock) = locks();
    let tmp = h::scratch("spdx-hollow");
    let top = tmp.join("memveil-0.0.0");
    fs::create_dir(&top).unwrap();
    fs::write(top.join("stray.txt"), "x").unwrap();
    let hollow = tmp.join("hollow.tar.gz");
    let proc = h::run(
        "tar",
        &["-czf", hollow.to_str().unwrap(), "memveil-0.0.0"],
        Some(&tmp),
    );
    assert!(proc.status.success());
    let out = tmp.join("hollow.spdx.json");
    let err = h::sbom::emit_spdx(&hollow, &deb, &rpm, &lock, &ebpf_lock, &out)
        .expect_err("hollow must fail");
    assert!(err.contains("MANIFEST"), "{err}");
}

#[test]
fn missing_inputs_fail() {
    let (deb, rpm, bundle) = packages();
    let (lock, ebpf_lock) = locks();
    let tmp = h::scratch("spdx-missing");
    let out = tmp.join("nope.spdx.json");
    let nope = tmp.join("nope.tar.gz");
    assert!(h::sbom::emit_spdx(&nope, &deb, &rpm, &lock, &ebpf_lock, &out).is_err());
    assert!(h::sbom::emit_spdx(&bundle, &deb, &rpm, &nope, &ebpf_lock, &out).is_err());
}
