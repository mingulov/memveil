// SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX 2.3 emit port over the Rust release packages.
//!
//! SPDX emit over the Rust release packages (ported from the
//! retired `tools/sbom`): every fact comes from recorded
//! inputs (the bundle MANIFEST.json, the Cargo lockfiles, the
//! collected payload hashes). The bridge/toolchain pins become
//! Cargo crate pins plus cargo/rustc versions; the conda
//! runtime provenance becomes the single libgcc record the
//! manifest carries (documented delta). Only the creation
//! timestamp varies between runs.

use super::cargo_lock_packages;
use super::json_escape;
use super::scratch;
use super::sha256_file;
use super::utc_now;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const SPDX_VERSION: &str = "SPDX-2.3";

/// One resolved third-party crate from the manifest.
#[derive(Debug, Clone)]
pub struct CratePin {
    /// Crate name.
    pub name: String,
    /// Crate version.
    pub version: String,
    /// SPDX license expression.
    pub license: String,
    /// Registry source URL.
    pub source: String,
}

/// Manifest facts the SPDX builder consumes.
#[derive(Debug)]
pub struct ManifestFacts {
    /// Engine version (`0.1.1`).
    pub engine: String,
    /// Source revision or `export`.
    pub revision: String,
    /// Bundle directory name.
    pub bundle: String,
    /// Userspace `Cargo.lock` sha256.
    pub lock_sha: String,
    /// eBPF workspace `Cargo.lock` sha256.
    pub ebpf_lock_sha: String,
    /// Third-party userspace crates.
    pub crates: Vec<CratePin>,
    /// Third-party eBPF crates.
    pub ebpf_crates: Vec<CratePin>,
    /// cargo version that built the release.
    pub cargo_version: String,
    /// rustc version that built the release.
    pub rustc_version: String,
    /// Host system library names.
    pub system_libs: Vec<String>,
    /// Staged file hashes (`files` map).
    pub files: BTreeMap<String, String>,
}

fn spdx_id(parts: &[&str]) -> String {
    let mut out = String::from("SPDXRef-");
    let mut first = true;
    for part in parts {
        if !first {
            out.push('-');
        }
        first = false;
        for ch in part.chars() {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
                out.push(ch);
            } else {
                out.push('-');
            }
        }
    }
    out
}

/// Read MANIFEST.json text from a bundle tarball.
pub fn manifest_from_bundle(tarball: &Path) -> Result<String, String> {
    let list = super::run("tar", &["-tzf", tarball.to_str().unwrap()], None);
    if !list.status.success() {
        return Err(format!("sbom: bundle unreadable: {}", tarball.display()));
    }
    let names: Vec<String> = String::from_utf8_lossy(&list.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    let mut tops = std::collections::BTreeSet::new();
    for name in &names {
        if name.contains('/')
            && let Some(top) = name.split('/').next()
        {
            tops.insert(top.to_string());
        }
    }
    if tops.len() != 1 {
        return Err("sbom: bundle has no single top dir".to_string());
    }
    let top: String = tops.into_iter().next().unwrap();
    let member = format!("{top}/MANIFEST.json");
    if !names.contains(&member) {
        return Err("sbom: bundle lacks MANIFEST.json".to_string());
    }
    let out = super::run("tar", &["-xOzf", tarball.to_str().unwrap(), &member], None);
    if !out.status.success() {
        return Err("sbom: bundle lacks MANIFEST.json".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse manifest text into facts through one python probe.
pub fn manifest_facts(manifest_text: &str) -> Result<ManifestFacts, String> {
    let tmp = scratch("sbom-manifest");
    let path = tmp.join("MANIFEST.json");
    fs::write(&path, manifest_text).expect("write manifest probe");
    let probe = format!(
        "import json; d = json.load(open({path:?}));\n\
         print('engine=' + str(d.get('engine_version') or ''))\n\
         print('revision=' + str(d.get('memveil_revision') or ''))\n\
         print('bundle=' + str(d.get('bundle') or ''))\n\
         print('lock=' + str((d.get('cargo') or {{}}).get('lock_sha256') or ''))\n\
         print('ebpf_lock=' + str((d.get('cargo') or {{}}).get('ebpf_lock_sha256') or ''))\n\
         print('cargo_ver=' + str(((d.get('toolchain') or {{}}).get('cargo') or {{}}).get('version') or ''))\n\
         print('rustc_ver=' + str(((d.get('toolchain') or {{}}).get('rustc') or {{}}).get('version') or ''))\n\
         [print('CRATE %s|%s|%s|%s' % (c.get('name'), c.get('version'), c.get('license'), c.get('source'))) for c in (d.get('cargo') or {{}}).get('crates', [])]\n\
         [print('ECRATE %s|%s|%s|%s' % (c.get('name'), c.get('version'), c.get('license'), c.get('source'))) for c in (d.get('cargo') or {{}}).get('ebpf_crates', [])]\n\
         [print('SYS ' + s) for s in d.get('system_libraries', [])]\n\
         [print('FILE %s|%s' % (k, v)) for k, v in sorted((d.get('files') or {{}}).items())]\n"
    );
    let out = super::run("python3", &["-c", &probe], None);
    if !out.status.success() {
        return Err(format!(
            "sbom: MANIFEST.json corrupt: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let mut facts = ManifestFacts {
        engine: String::new(),
        revision: String::new(),
        bundle: String::new(),
        lock_sha: String::new(),
        ebpf_lock_sha: String::new(),
        crates: Vec::new(),
        ebpf_crates: Vec::new(),
        cargo_version: String::new(),
        rustc_version: String::new(),
        system_libs: Vec::new(),
        files: BTreeMap::new(),
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(value) = line.strip_prefix("engine=") {
            facts.engine = value.to_string();
        } else if let Some(value) = line.strip_prefix("revision=") {
            facts.revision = value.to_string();
        } else if let Some(value) = line.strip_prefix("bundle=") {
            facts.bundle = value.to_string();
        } else if let Some(value) = line.strip_prefix("ebpf_lock=") {
            facts.ebpf_lock_sha = value.to_string();
        } else if let Some(value) = line.strip_prefix("lock=") {
            facts.lock_sha = value.to_string();
        } else if let Some(value) = line.strip_prefix("cargo_ver=") {
            facts.cargo_version = value.to_string();
        } else if let Some(value) = line.strip_prefix("rustc_ver=") {
            facts.rustc_version = value.to_string();
        } else if let Some(value) = line.strip_prefix("CRATE ") {
            facts.crates.push(parse_crate(value));
        } else if let Some(value) = line.strip_prefix("ECRATE ") {
            facts.ebpf_crates.push(parse_crate(value));
        } else if let Some(value) = line.strip_prefix("SYS ") {
            facts.system_libs.push(value.to_string());
        } else if let Some(value) = line.strip_prefix("FILE ") {
            let mut parts = value.splitn(2, '|');
            if let (Some(key), Some(digest)) = (parts.next(), parts.next()) {
                facts.files.insert(key.to_string(), digest.to_string());
            }
        }
    }
    // `lock=` also prefixes `ebpf_lock=`; the strip order above
    // checks `ebpf_lock=` first so the plain arm never steals it.
    if facts.engine.is_empty() || facts.revision.is_empty() || facts.bundle.is_empty() {
        return Err("sbom: MANIFEST.json lacks identity".to_string());
    }
    Ok(facts)
}

fn parse_crate(value: &str) -> CratePin {
    let mut parts = value.split('|');
    CratePin {
        name: parts.next().unwrap_or("").to_string(),
        version: parts.next().unwrap_or("").to_string(),
        license: parts.next().unwrap_or("").to_string(),
        source: parts.next().unwrap_or("").to_string(),
    }
}

/// Emit the frozen SPDX SBOM over the full closure, exactly once.
///
/// The payload files are every copied file (not the 12-entry
/// subset), reconciled with the full-closure verifier. Delegates
/// to the release-entry harness library so the custody flow and
/// the test suite share one emitter. Refuses to overwrite.
pub fn emit_frozen(
    manifest_path: &Path,
    bundle: &Path,
    deb: &Path,
    rpm: &Path,
    lock: &Path,
    ebpf_lock: &Path,
    out: &Path,
    created: Option<&str>,
) -> Result<(), String> {
    memveil_release_entry::emit_frozen(
        manifest_path,
        bundle,
        deb,
        rpm,
        lock,
        ebpf_lock,
        out,
        created,
    )
}

/// Emit the SPDX document; `Err` carries the failure diagnostic.
pub fn emit_spdx(
    bundle: &Path,
    deb: &Path,
    rpm: &Path,
    lock: &Path,
    ebpf_lock: &Path,
    out: &Path,
) -> Result<(), String> {
    for (path, label) in [
        (bundle, "--bundle"),
        (deb, "--deb"),
        (rpm, "--rpm"),
        (lock, "--lock"),
    ] {
        if !path.is_file() {
            return Err(format!("sbom: {label} is not a file: {}", path.display()));
        }
    }
    if !ebpf_lock.is_file() {
        return Err(format!(
            "sbom: --ebpf-lock is not a file: {}",
            ebpf_lock.display()
        ));
    }
    let text = manifest_from_bundle(bundle)?;
    let facts = manifest_facts(&text)?;
    if sha256_file(lock) != facts.lock_sha {
        return Err(format!(
            "sbom: input disagreement: MANIFEST Cargo.lock {} != lock {}",
            facts.lock_sha,
            sha256_file(lock)
        ));
    }
    if sha256_file(ebpf_lock) != facts.ebpf_lock_sha {
        return Err(format!(
            "sbom: input disagreement: MANIFEST eBPF lock {} != lock {}",
            facts.ebpf_lock_sha,
            sha256_file(ebpf_lock)
        ));
    }
    let payload =
        super::payload::collect(deb, rpm, bundle).map_err(|err| format!("sbom: {err}"))?;
    let lock_entries = cargo_lock_packages(lock);
    let ebpf_entries = cargo_lock_packages(ebpf_lock);
    let mut checksums: BTreeMap<(String, String), String> = BTreeMap::new();
    for (name, version, _source, sum) in lock_entries.iter().chain(ebpf_entries.iter()) {
        if !sum.is_empty() {
            checksums.insert((name.clone(), version.clone()), sum.clone());
        }
    }
    for krate in facts.crates.iter().chain(facts.ebpf_crates.iter()) {
        if !checksums.contains_key(&(krate.name.clone(), krate.version.clone())) {
            return Err(format!(
                "sbom: input disagreement: {} {} not in the Cargo locks",
                krate.name, krate.version
            ));
        }
    }
    let created = utc_now();
    let doc = render(&facts, &payload, &checksums, &created, bundle, deb, rpm);
    fs::write(out, doc).map_err(|err| format!("sbom: cannot write {}: {err}", out.display()))?;
    Ok(())
}

fn checksum_entry(sha: &str) -> String {
    format!(
        "[{{\"algorithm\": \"SHA256\", \"checksumValue\": {}}}]",
        json_escape(sha)
    )
}

/// Payload members already covered as `payload/*` files.
fn payload_covered(name: &str) -> bool {
    name == "bin/memveil"
        || name == "bpf/swiotlb_attempt.bpf.o"
        || name == "bpf/swiotlb_copy.bpf.o"
        || name == "bpf/swiotlb_lifecycle.bpf.o"
}

#[allow(clippy::too_many_arguments)]
fn render(
    facts: &ManifestFacts,
    payload: &BTreeMap<String, String>,
    checksums: &BTreeMap<(String, String), String>,
    created: &str,
    bundle: &Path,
    deb: &Path,
    rpm: &Path,
) -> String {
    let doc_id = spdx_id(&["DOCUMENT"]);
    let root_id = spdx_id(&["Package", "memveil", &facts.engine]);
    let mut packages = String::new();
    let mut files = String::new();
    let mut rels = String::new();
    rels.push_str(&format!(
        "{{\"spdxElementId\": {}, \"relationshipType\": \"DESCRIBES\", \
         \"relatedSpdxElement\": {}}}",
        json_escape(&doc_id),
        json_escape(&root_id)
    ));
    packages.push_str(&format!(
        "{{\"SPDXID\": {}, \"name\": \"memveil\", \"versionInfo\": {}, \
         \"supplier\": \"NOASSERTION\", \"downloadLocation\": \"NOASSERTION\", \
         \"filesAnalyzed\": false, \"licenseConcluded\": \"GPL-3.0-or-later\", \
         \"licenseDeclared\": \"GPL-3.0-or-later\", \"copyrightText\": \"NOASSERTION\", \
         \"externalRefs\": [{{\"referenceCategory\": \"OTHER\", \
         \"referenceType\": \"memveil-revision\", \"referenceLocator\": {}}}]}}",
        json_escape(&root_id),
        json_escape(&facts.engine),
        json_escape(&facts.revision)
    ));
    let mut file_entries: Vec<String> = Vec::new();
    let mut rel_entries: Vec<String> = vec![rels];
    for (logical, digest) in payload {
        let id = spdx_id(&["File", "payload", logical]);
        file_entries.push(format!(
            "{{\"SPDXID\": {}, \"fileName\": {}, \"checksums\": {}, \
             \"licenseConcluded\": \"GPL-3.0-or-later\", \
             \"licenseInfoInFiles\": [\"GPL-3.0-or-later\"], \
             \"copyrightText\": \"NOASSERTION\"}}",
            json_escape(&id),
            json_escape(&format!("payload/{logical}")),
            checksum_entry(digest)
        ));
        rel_entries.push(format!(
            "{{\"spdxElementId\": {}, \"relationshipType\": \"CONTAINS\", \
             \"relatedSpdxElement\": {}}}",
            json_escape(&root_id),
            json_escape(&id)
        ));
    }
    for (name, digest) in &facts.files {
        if payload_covered(name) {
            continue;
        }
        let concluded = if name.starts_with("LICENSES/") || *name == "LICENSE" {
            "NOASSERTION"
        } else {
            "GPL-3.0-or-later"
        };
        let id = spdx_id(&["File", "bundle", name]);
        file_entries.push(format!(
            "{{\"SPDXID\": {}, \"fileName\": {}, \"checksums\": {}, \
             \"licenseConcluded\": {}, \"licenseInfoInFiles\": [{}], \
             \"copyrightText\": \"NOASSERTION\"}}",
            json_escape(&id),
            json_escape(&format!("bundle/{}/{}", facts.bundle, name)),
            checksum_entry(digest),
            json_escape(concluded),
            json_escape(concluded)
        ));
        rel_entries.push(format!(
            "{{\"spdxElementId\": {}, \"relationshipType\": \"CONTAINS\", \
             \"relatedSpdxElement\": {}}}",
            json_escape(&root_id),
            json_escape(&id)
        ));
    }
    files.push_str(&file_entries.join(", "));
    let mut package_entries: Vec<String> = vec![packages];
    let mut crates: Vec<(&CratePin, &str)> = Vec::new();
    for krate in &facts.crates {
        crates.push((krate, "crates"));
    }
    for krate in &facts.ebpf_crates {
        crates.push((krate, "ebpf"));
    }
    crates.sort_by(|left, right| {
        (&left.0.name, &left.0.version).cmp(&(&right.0.name, &right.0.version))
    });
    for (krate, scope) in crates {
        let id = spdx_id(&["Package", scope, &krate.name, &krate.version]);
        let sum = &checksums[&(krate.name.clone(), krate.version.clone())];
        package_entries.push(format!(
            "{{\"SPDXID\": {}, \"name\": {}, \"versionInfo\": {}, \
             \"supplier\": \"NOASSERTION\", \"downloadLocation\": \"NOASSERTION\", \
             \"filesAnalyzed\": false, \"licenseConcluded\": {}, \
             \"licenseDeclared\": {}, \"copyrightText\": \"NOASSERTION\", \
             \"checksums\": {}, \"externalRefs\": [{{\"referenceCategory\": \
             \"OTHER\", \"referenceType\": \"cargo-source\", \
             \"referenceLocator\": {}}}]}}",
            json_escape(&id),
            json_escape(&krate.name),
            json_escape(&krate.version),
            json_escape(&krate.license),
            json_escape(&krate.license),
            checksum_entry(sum),
            json_escape(&krate.source)
        ));
        rel_entries.push(format!(
            "{{\"spdxElementId\": {}, \"relationshipType\": \"DEPENDS_ON\", \
             \"relatedSpdxElement\": {}}}",
            json_escape(&root_id),
            json_escape(&id)
        ));
    }
    for (tool, version) in [
        ("cargo", &facts.cargo_version),
        ("rustc", &facts.rustc_version),
    ] {
        let id = spdx_id(&["Package", "toolchain", tool]);
        package_entries.push(format!(
            "{{\"SPDXID\": {}, \"name\": {}, \"versionInfo\": {}, \
             \"supplier\": \"NOASSERTION\", \"downloadLocation\": \"NOASSERTION\", \
             \"filesAnalyzed\": false, \"licenseConcluded\": \"NOASSERTION\", \
             \"licenseDeclared\": \"NOASSERTION\", \"copyrightText\": \"NOASSERTION\"}}",
            json_escape(&id),
            json_escape(tool),
            json_escape(version)
        ));
        rel_entries.push(format!(
            "{{\"spdxElementId\": {}, \"relationshipType\": \"BUILD_TOOL_OF\", \
             \"relatedSpdxElement\": {}}}",
            json_escape(&root_id),
            json_escape(&id)
        ));
    }
    if !facts.system_libs.is_empty() {
        let id = spdx_id(&["Package", "system-libraries"]);
        let mut libs: Vec<String> = facts.system_libs.clone();
        libs.sort();
        let refs: Vec<String> = libs
            .iter()
            .map(|name| {
                format!(
                    "{{\"referenceCategory\": \"OTHER\", \"referenceType\": \
                     \"soname\", \"referenceLocator\": {}}}",
                    json_escape(name)
                )
            })
            .collect();
        package_entries.push(format!(
            "{{\"SPDXID\": {}, \"name\": \"system-libraries\", \
             \"versionInfo\": \"NOASSERTION\", \"supplier\": \"NOASSERTION\", \
             \"downloadLocation\": \"NOASSERTION\", \"filesAnalyzed\": false, \
             \"licenseConcluded\": \"NOASSERTION\", \
             \"licenseDeclared\": \"NOASSERTION\", \
             \"copyrightText\": \"NOASSERTION\", \
             \"externalRefs\": [{}]}}",
            json_escape(&id),
            refs.join(", ")
        ));
        rel_entries.push(format!(
            "{{\"spdxElementId\": {}, \"relationshipType\": \"DEPENDS_ON\", \
             \"relatedSpdxElement\": {}}}",
            json_escape(&root_id),
            json_escape(&id)
        ));
    }
    for (kind, path) in [("bundle", bundle), ("deb", deb), ("rpm", rpm)] {
        let id = spdx_id(&["Package", "container", kind]);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or(kind);
        package_entries.push(format!(
            "{{\"SPDXID\": {}, \"name\": {}, \"versionInfo\": {}, \
             \"supplier\": \"NOASSERTION\", \"downloadLocation\": \"NOASSERTION\", \
             \"filesAnalyzed\": false, \"licenseConcluded\": \"NOASSERTION\", \
             \"licenseDeclared\": \"NOASSERTION\", \"copyrightText\": \"NOASSERTION\", \
             \"checksums\": {}}}",
            json_escape(&id),
            json_escape(name),
            json_escape(&facts.engine),
            checksum_entry(&sha256_file(path))
        ));
        rel_entries.push(format!(
            "{{\"spdxElementId\": {}, \"relationshipType\": \"CONTAINS\", \
             \"relatedSpdxElement\": {}}}",
            json_escape(&id),
            json_escape(&root_id)
        ));
    }
    format!(
        "{{\"spdxVersion\": {SPDX_VERSION}, \"dataLicense\": \"CC0-1.0\", \
         \"SPDXID\": {doc}, \"name\": {name}, \"documentNamespace\": {ns}, \
         \"creationInfo\": {{\"created\": {created}, \
         \"creators\": [\"Tool: memveil-package-tests/sbom\"], \
         \"licenseListVersion\": \"3.27\"}}, \
         \"packages\": [{packages}], \"files\": [{files}], \
         \"relationships\": [{rels}]}}\n",
        SPDX_VERSION = json_escape(SPDX_VERSION),
        doc = json_escape(&doc_id),
        name = json_escape(&format!("memveil-{}", facts.engine)),
        ns = json_escape(&format!("urn:memveil:{}:{}", facts.engine, facts.revision)),
        created = json_escape(created),
        packages = package_entries.join(", "),
        files = files,
        rels = rel_entries.join(", ")
    )
}
