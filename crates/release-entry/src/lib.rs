// SPDX-License-Identifier: GPL-3.0-or-later
//! Release entry point: full payload closure and frozen SPDX emit.
//!
//! Explicit-paths entry points over the three release archives
//! (owner bundle tarball, .deb, .rpm): `collect_full` hashes
//! every file the packages copy from the bundle (the full
//! copied-file closure, not the 12-entry engine/BPF subset),
//! and `emit_frozen` writes the SPDX 2.3 document over that
//! full closure exactly once. Every fact comes from recorded
//! inputs (the bundle MANIFEST.json, the Cargo lockfiles, the
//! collected payload hashes); only the creation timestamp varies
//! between runs. Archives are listed and type-checked before
//! anything is extracted, and every read refuses symlinks, so
//! untrusted bytes cannot escape the scratch directory.

/// Dependency-free SHA-256 shared with the main crate (the same
/// `#[path]` include the build script uses).
#[allow(dead_code)]
#[path = "../../../src/platform/hash.rs"]
mod hash;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

/// Shipped BPF object file names (inspection copies).
pub const BPF_OBJECTS: [&str; 3] = [
    "swiotlb_attempt.bpf.o",
    "swiotlb_lifecycle.bpf.o",
    "swiotlb_copy.bpf.o",
];

/// Installed destination of one bundle member in .deb/.rpm.
///
/// Port of the deb packager mapping (and the reverse of the rpm
/// spec check): binary, closure lib, BPF inspection copies,
/// profiles, docs plus worked examples, and every license/notice
/// text each have exactly one FHS destination. Anything else
/// fails closed.
pub fn installed_file_path(name: &str) -> Result<String, String> {
    if name.is_empty() || name.starts_with('/') {
        return Err(format!(
            "payload-closure: invalid bundle file path: {name:?}"
        ));
    }
    if name
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(format!("payload-closure: invalid bundle file path: {name}"));
    }
    if name.starts_with("docs/") || name.starts_with("profiles/") {
        return Ok(format!("usr/share/memveil/{name}"));
    }
    if name.starts_with("examples/") {
        return Ok(format!("usr/share/memveil/docs/{name}"));
    }
    if name == "LICENSE"
        || name == "THIRD-PARTY-NOTICES.md"
        || name.starts_with("LICENSES/")
        || name.starts_with("licenses/")
    {
        return Ok(format!("usr/share/doc/memveil/{name}"));
    }
    if name == "bin/memveil" || name.starts_with("lib/memveil/") {
        return Ok(format!("usr/{name}"));
    }
    if let Some(rest) = name.strip_prefix("bpf/") {
        return Ok(format!("usr/lib/memveil/{rest}"));
    }
    Err(format!("payload-closure: unknown bundle path: {name}"))
}

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

/// Manifest facts the closure and SPDX builder consume.
#[derive(Debug)]
pub struct ManifestFacts {
    /// Engine version (`0.1.0`).
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

/// Run a command, capturing both streams.
fn run(cmd: &str, args: &[&str], cwd: Option<&Path>) -> Output {
    let mut command = Command::new(cmd);
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command
        .output()
        .unwrap_or_else(|err| panic!("cannot run {cmd}: {err}"))
}

/// True when `name` resolves on PATH.
fn tool_present(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// SHA-256 of a file, streaming through the shared hasher.
fn sha256_file(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut file = fs::File::open(path)
        .map_err(|err| format!("sbom: cannot read {}: {err}", path.display()))?;
    let mut state = hash::Sha256::new();
    let mut chunk = [0u8; 65536];
    loop {
        let count = file
            .read(&mut chunk)
            .map_err(|err| format!("sbom: cannot read {}: {err}", path.display()))?;
        if count == 0 {
            break;
        }
        state.update(&chunk[..count]);
    }
    Ok(state.copy_finish())
}

/// SHA-256 of bytes already in memory.
fn sha256_bytes(data: &[u8]) -> String {
    hash::sha256_hex(data)
}

/// Scratch directory, removed on drop (best effort).
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn fresh(name: &str) -> Result<Scratch, String> {
        use std::sync::atomic::AtomicU64;
        use std::sync::atomic::Ordering;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "memveil-release-{}-{}-{}",
            name,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).map_err(|err| format!("scratch setup failed: {err}"))?;
        Ok(Scratch { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Refuse an archive member name that could escape its root.
fn check_member_name(name: &str, label: &str) -> Result<(), String> {
    if name.is_empty() || name.starts_with('/') {
        return Err(format!("{label}: absolute member {name:?}"));
    }
    if name.split('/').any(|part| part.is_empty() || part == "..") {
        return Err(format!("{label}: escaping member {name:?}"));
    }
    Ok(())
}

/// Read one regular file's bytes, refusing symlinks.
fn read_payload(root: &Path, member: &str, label: &str) -> Result<Vec<u8>, String> {
    let path = root.join(member);
    let info = fs::symlink_metadata(&path)
        .map_err(|_| format!("{label}: lacks payload member {member}"))?;
    if !info.is_file() || info.is_symlink() {
        return Err(format!("{label}: lacks payload member {member}"));
    }
    fs::read(&path).map_err(|_| format!("{label}: lacks payload member {member}"))
}

/// Typed `tar -tzvf` members: (name, is_dir); links/specials fail.
fn tar_typed_members(tarball: &Path, label: &str) -> Result<Vec<(String, bool)>, String> {
    let list = run(
        "tar",
        &[
            "--numeric-owner",
            "-tzvf",
            tarball.to_str().expect("path is UTF-8"),
        ],
        None,
    );
    if !list.status.success() {
        return Err(format!(
            "{label}: cannot list {}: {}",
            tarball.display(),
            String::from_utf8_lossy(&list.stderr)
        ));
    }
    let mut members = Vec::new();
    for line in String::from_utf8_lossy(&list.stdout).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            return Err(format!("{label}: cannot parse tar listing"));
        }
        let mode = parts[0];
        let mut name = parts[parts.len() - 1].to_string();
        let is_dir = mode.starts_with('d');
        if mode.starts_with('-') || is_dir {
            if is_dir {
                name = name.trim_end_matches('/').to_string();
            }
            check_member_name(&name, label)?;
            members.push((name, is_dir));
        } else {
            return Err(format!("{label}: links and special files are forbidden"));
        }
    }
    Ok(members)
}

/// Refuse any extracted symlink or special file under a root.
///
/// The pre-extraction listings cannot prove what the extractor
/// wrote: a member swapped between listing and extraction would
/// sail through the typed listing, so every extractor sweeps
/// its own output before any payload byte is read.
fn refuse_extracted_links(root: &Path, label: &str) -> Result<(), String> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)
            .map_err(|err| format!("{label}: extracted tree list failed: {err}"))?;
        for entry in entries.flatten() {
            let info = entry
                .file_type()
                .map_err(|err| format!("{label}: extracted tree list failed: {err}"))?;
            if info.is_symlink() || (!info.is_file() && !info.is_dir()) {
                return Err(format!("{label}: links and special files are forbidden"));
            }
            if info.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    Ok(())
}

/// Extract the bundle tarball after listing it strictly.
fn extract_bundle(tarball: &Path, tmp: &Path) -> Result<PathBuf, String> {
    let label = "payload-closure";
    let members = tar_typed_members(tarball, label)?;
    let mut tops = std::collections::BTreeSet::new();
    for (name, _) in &members {
        if let Some(top) = name.split('/').next() {
            tops.insert(top.to_string());
        }
    }
    if tops.len() != 1 {
        return Err(format!("{label}: bundle has no single top dir"));
    }
    let dest = tmp.join("bundle");
    fs::create_dir_all(&dest).expect("bundle tmp");
    let out = run(
        "tar",
        &["-xzf", tarball.to_str().expect("path is UTF-8")],
        Some(&dest),
    );
    if !out.status.success() {
        return Err(format!(
            "{label}: bundle extract failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    refuse_extracted_links(&dest, label)?;
    Ok(dest.join(tops.into_iter().next().unwrap()))
}

/// `dpkg-deb -c` payload members; links/specials fail.
fn deb_typed_members(deb: &Path, label: &str) -> Result<Vec<String>, String> {
    let list = run(
        "dpkg-deb",
        &["-c", deb.to_str().expect("path is UTF-8")],
        None,
    );
    if !list.status.success() {
        return Err(format!(
            "{label}: cannot list {}: {}",
            deb.display(),
            String::from_utf8_lossy(&list.stderr)
        ));
    }
    let mut members = Vec::new();
    for line in String::from_utf8_lossy(&list.stdout).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            return Err(format!("{label}: cannot parse deb listing"));
        }
        let path = parts[parts.len() - 1]
            .strip_prefix("./")
            .ok_or_else(|| format!("{label}: cannot parse deb listing"))?
            .trim_end_matches('/')
            .to_string();
        if path.is_empty() {
            continue;
        }
        if parts[0].starts_with('d') || parts[0].starts_with('-') {
            check_member_name(&path, label)?;
            members.push(path);
        } else {
            return Err(format!("{label}: links and special files are forbidden"));
        }
    }
    Ok(members)
}

/// Extract the .deb payload after listing it strictly.
fn extract_deb(deb: &Path, tmp: &Path) -> Result<PathBuf, String> {
    deb_typed_members(deb, "payload-closure")?;
    let dest = tmp.join("deb");
    fs::create_dir_all(&dest).expect("deb tmp");
    let out = run(
        "dpkg-deb",
        &[
            "-x",
            deb.to_str().expect("path is UTF-8"),
            dest.to_str().expect("path is UTF-8"),
        ],
        None,
    );
    if !out.status.success() {
        return Err(format!(
            "payload-closure: deb extract failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    refuse_extracted_links(&dest, "payload-closure")?;
    Ok(dest)
}

/// `rpm2cpio | cpio -t` payload member names.
fn rpm_typed_members(rpm: &Path, label: &str) -> Result<Vec<String>, String> {
    let dump = run("rpm2cpio", &[rpm.to_str().expect("path is UTF-8")], None);
    if !dump.status.success() {
        return Err(format!(
            "{label}: rpm2cpio failed: {}",
            String::from_utf8_lossy(&dump.stderr)
        ));
    }
    let mut list = Command::new("cpio");
    list.args(["-t", "--quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = list.spawn().expect("spawn cpio");
    use std::io::Write;
    let _ = child
        .stdin
        .as_mut()
        .expect("cpio stdin")
        .write_all(&dump.stdout);
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("cpio wait");
    if !out.status.success() {
        return Err(format!(
            "{label}: cpio list failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let mut members = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let name = line
            .trim()
            .trim_start_matches("./")
            .trim_end_matches('/')
            .to_string();
        if name.is_empty() || name == "." {
            continue;
        }
        check_member_name(&name, label)?;
        members.push(name);
    }
    Ok(members)
}

/// Extract the .rpm payload after listing it strictly.
fn extract_rpm(rpm: &Path, tmp: &Path) -> Result<PathBuf, String> {
    rpm_typed_members(rpm, "payload-closure")?;
    let dest = tmp.join("rpm");
    fs::create_dir_all(&dest).expect("rpm tmp");
    let dump = run("rpm2cpio", &[rpm.to_str().expect("path is UTF-8")], None);
    if !dump.status.success() {
        return Err(format!(
            "payload-closure: rpm2cpio failed: {}",
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
    use std::io::Write;
    // cpio exits at the archive trailer, possibly before
    // trailing padding bytes arrive: a late write may hit
    // EPIPE after a successful extract, so the exit status
    // (not the write result) decides success.
    let _ = child
        .stdin
        .as_mut()
        .expect("cpio stdin")
        .write_all(&dump.stdout);
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("cpio wait");
    if !out.status.success() {
        return Err(format!(
            "payload-closure: cpio failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    // The name listing cannot see member types, so refuse any
    // extracted symlink or special file before reading payload.
    refuse_extracted_links(&dest, "payload-closure")?;
    Ok(dest)
}

/// Generated installed files that are not copied bundle bytes.
///
/// Both package formats ship identical generated files from the
/// same generators: man pages under `usr/share/man/man1/`
/// (one `memveil*.1` page per CLI verb, uncompressed) plus the
/// exact completion, copyright, changelog, and lintian paths
/// below. Every other installed file must map from the bundle
/// manifest; anything else refuses.
const GENERATED_ALLOW_EXACT: &[&str] = &[
    "usr/share/bash-completion/completions/memveil",
    "usr/share/zsh/vendor-completions/_memveil",
    "usr/share/doc/memveil/copyright",
    "usr/share/doc/memveil/changelog.Debian.gz",
    "usr/share/lintian/overrides/memveil",
];

/// True when an installed path is pinned generated packaging output.
fn generated_allowed(rel: &str) -> bool {
    if GENERATED_ALLOW_EXACT.contains(&rel) {
        return true;
    }
    if let Some(rest) = rel.strip_prefix("usr/share/man/man1/") {
        return !rest.is_empty() && !rest.contains('/') && rest.ends_with(".1");
    }
    false
}

/// Actual regular files under an extraction root, as posix relpaths.
fn actual_payload_files(root: &Path, label: &str) -> Result<BTreeSet<String>, String> {
    fn walk(
        root: &Path,
        dir: &Path,
        out: &mut BTreeSet<String>,
        label: &str,
    ) -> Result<(), String> {
        let entries = fs::read_dir(dir)
            .map_err(|err| format!("{label}: extracted tree list failed: {err}"))?;
        for entry in entries {
            let entry =
                entry.map_err(|err| format!("{label}: extracted tree list failed: {err}"))?;
            let kind = entry
                .file_type()
                .map_err(|err| format!("{label}: extracted tree list failed: {err}"))?;
            if kind.is_dir() {
                walk(root, &entry.path(), out, label)?;
            } else if kind.is_file() {
                let full = entry.path();
                let rel = full
                    .strip_prefix(root)
                    .map_err(|_| format!("{label}: extracted path escapes its root"))?;
                let mut posix = String::new();
                for (idx, part) in rel.components().enumerate() {
                    let text = part
                        .as_os_str()
                        .to_str()
                        .ok_or_else(|| format!("{label}: extracted path is not UTF-8"))?;
                    if idx > 0 {
                        posix.push('/');
                    }
                    posix.push_str(text);
                }
                out.insert(posix);
            } else {
                return Err(format!("{label}: links and special files are forbidden"));
            }
        }
        Ok(())
    }
    let mut out = BTreeSet::new();
    walk(root, root, &mut out, label)?;
    Ok(out)
}

/// Hash the full copied-file closure of a package set.
///
/// Every `files{}` entry of the bundle manifest is hashed in all
/// three archives: `bundle/<rel>` plus `deb/<installed>` and
/// `rpm/<installed>` at the mapped FHS destinations. The actual
/// installed deb/rpm file sets must equal the mapped expected
/// sets modulo the pinned generated allowlist above: a smuggled
/// extra file refuses even when every mapped file matches.
pub fn collect_full(
    bundle: &Path,
    deb: &Path,
    rpm: &Path,
    manifest_text: &str,
) -> Result<BTreeMap<String, String>, String> {
    // Absolute inputs: extraction runs with changed working
    // directories, so relative paths would resolve wrongly.
    let bundle = &fs::canonicalize(bundle).map_err(|_| {
        format!(
            "payload-closure: --bundle is not a file: {}",
            bundle.display()
        )
    })?;
    let deb = &fs::canonicalize(deb)
        .map_err(|_| format!("payload-closure: --deb is not a file: {}", deb.display()))?;
    let rpm = &fs::canonicalize(rpm)
        .map_err(|_| format!("payload-closure: --rpm is not a file: {}", rpm.display()))?;
    for (path, label) in [(bundle, "--bundle"), (deb, "--deb"), (rpm, "--rpm")] {
        if !path.is_file() {
            return Err(format!(
                "payload-closure: {label} is not a file: {}",
                path.display()
            ));
        }
    }
    for tool in ["dpkg-deb", "rpm2cpio", "cpio", "tar"] {
        if !tool_present(tool) {
            return Err(format!("payload-closure: {tool} not found"));
        }
    }
    let facts = manifest_facts(manifest_text)?;
    if facts.files.is_empty() {
        return Err("payload-closure: bundle manifest has no files".to_string());
    }
    let scratch = Scratch::fresh("payload-closure")?;
    let deb_root = extract_deb(deb, &scratch.path)?;
    let rpm_root = extract_rpm(rpm, &scratch.path)?;
    let bundle_root = extract_bundle(bundle, &scratch.path)?;
    let mut entries = BTreeMap::new();
    let mut installed_expected = BTreeSet::new();
    for rel in facts.files.keys() {
        // The mapping rejects absolute and escaping names, so
        // the joins below cannot leave the extraction roots.
        let installed = installed_file_path(rel)?;
        installed_expected.insert(installed.clone());
        let data = read_payload(&bundle_root, rel, "payload-closure")?;
        entries.insert(format!("bundle/{rel}"), sha256_bytes(&data));
        let data = read_payload(&deb_root, &installed, "payload-closure")?;
        entries.insert(format!("deb/{installed}"), sha256_bytes(&data));
        let data = read_payload(&rpm_root, &installed, "payload-closure")?;
        entries.insert(format!("rpm/{installed}"), sha256_bytes(&data));
    }
    for (root, label) in [(&deb_root, "deb"), (&rpm_root, "rpm")] {
        let actual = actual_payload_files(root, "payload-closure")?;
        let extra: Vec<&str> = actual
            .iter()
            .map(String::as_str)
            .filter(|path| !installed_expected.contains(*path) && !generated_allowed(path))
            .collect();
        if let Some(first) = extra.first() {
            return Err(format!(
                "payload-closure: {label} carries unmapped payload file: {first}"
            ));
        }
    }
    Ok(entries)
}

/// Render a closure as canonical JSON: sorted keys, no spaces.
pub fn render_closure(entries: &BTreeMap<String, String>) -> String {
    let mut out = String::from("{");
    for (index, (logical, digest)) in entries.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&json_escape(logical));
        out.push(':');
        out.push_str(&json_escape(digest));
    }
    out.push_str("}\n");
    out
}

/// Read MANIFEST.json text from a bundle tarball.
pub fn manifest_from_bundle(tarball: &Path) -> Result<String, String> {
    let list = run(
        "tar",
        &["-tzf", tarball.to_str().expect("path is UTF-8")],
        None,
    );
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
    let out = run(
        "tar",
        &["-xOzf", tarball.to_str().expect("path is UTF-8"), &member],
        None,
    );
    if !out.status.success() {
        return Err("sbom: bundle lacks MANIFEST.json".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse manifest text into facts through one python probe.
pub fn manifest_facts(manifest_text: &str) -> Result<ManifestFacts, String> {
    let scratch = Scratch::fresh("release-manifest")?;
    let path = scratch.path.join("MANIFEST.json");
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
    let out = run("python3", &["-c", &probe], None);
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

const SPDX_VERSION: &str = "SPDX-2.3";

/// Emit the frozen SPDX SBOM over the full closure, exactly once.
///
/// The payload files are the FULL copied-file closure (every file
/// the packages copy from the bundle), reconciled with the
/// full-closure verifier: a 12-entry subset would fail it. Like
/// the retained port, only the creation timestamp varies between
/// runs. Refuses to overwrite an existing output.
pub fn emit_frozen(
    manifest_path: &Path,
    bundle: &Path,
    deb: &Path,
    rpm: &Path,
    lock: &Path,
    ebpf_lock: &Path,
    out: &Path,
) -> Result<(), String> {
    for (path, label) in [
        (manifest_path, "--manifest"),
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
    let text = fs::read_to_string(manifest_path)
        .map_err(|err| format!("sbom: cannot read {}: {err}", manifest_path.display()))?;
    let facts = manifest_facts(&text)?;
    if sha256_file(lock)? != facts.lock_sha {
        return Err(format!(
            "sbom: input disagreement: MANIFEST Cargo.lock {} != lock {}",
            facts.lock_sha,
            sha256_file(lock)?
        ));
    }
    if sha256_file(ebpf_lock)? != facts.ebpf_lock_sha {
        return Err(format!(
            "sbom: input disagreement: MANIFEST eBPF lock {} != lock {}",
            facts.ebpf_lock_sha,
            sha256_file(ebpf_lock)?
        ));
    }
    let payload = collect_full(bundle, deb, rpm, &text)?;
    let lock_entries = cargo_lock_packages(lock)?;
    let ebpf_entries = cargo_lock_packages(ebpf_lock)?;
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
    let created = utc_now()?;
    let doc = render(&facts, &payload, &checksums, &created, bundle, deb, rpm)?;
    write_once_bytes(out, doc.as_bytes())
}

/// Write bytes to a new file; refuse to overwrite one that exists.
fn write_once_bytes(out: &Path, data: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                format!("sbom: refusing to overwrite {}", out.display())
            } else {
                format!("sbom: cannot write {}: {err}", out.display())
            }
        })?;
    file.write_all(data)
        .map_err(|err| format!("sbom: cannot write {}: {err}", out.display()))?;
    file.sync_all()
        .map_err(|err| format!("sbom: cannot write {}: {err}", out.display()))?;
    Ok(())
}

/// Cargo.lock packages via stdlib TOML: `(name, version, source, checksum)`.
fn cargo_lock_packages(lock: &Path) -> Result<Vec<(String, String, String, String)>, String> {
    let probe = "import json, tomllib; d = tomllib.load(open(ARG, 'rb')); \
        print(json.dumps([[p.get('name'), p.get('version'), p.get('source') or '', \
        p.get('checksum') or ''] for p in d.get('package', [])]))"
        .replace("ARG", &format!("{lock:?}"));
    let out = run("python3", &["-c", &probe], None);
    if !out.status.success() {
        return Err(format!(
            "sbom: cannot parse {}: {}",
            lock.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(parse_string_table(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse a JSON `[[s, s, ...], ...]` table without dependencies.
fn parse_string_table(text: &str) -> Vec<(String, String, String, String)> {
    let mut rows = Vec::new();
    for row in text
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split("], [")
    {
        let clean = row.trim().trim_start_matches('[').trim_end_matches(']');
        let mut cells = Vec::new();
        let mut current = String::new();
        let mut in_string = false;
        let mut escaped = false;
        for ch in clean.chars() {
            if escaped {
                current.push(ch);
                escaped = false;
            } else if ch == '\\' && in_string {
                escaped = true;
            } else if ch == '"' {
                in_string = !in_string;
            } else if ch == ',' && !in_string {
                cells.push(std::mem::take(&mut current).trim().to_string());
            } else {
                current.push(ch);
            }
        }
        cells.push(current.trim().to_string());
        if cells.len() == 4 {
            rows.push((
                cells[0].clone(),
                cells[1].clone(),
                cells[2].clone(),
                cells[3].clone(),
            ));
        }
    }
    rows
}

/// JSON string literal with escaping.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ` (via `date -u`).
fn utc_now() -> Result<String, String> {
    let out = run("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"], None);
    if !out.status.success() {
        return Err("sbom: cannot stamp creation time".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
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

fn checksum_entry(sha: &str) -> String {
    format!(
        "[{{\"algorithm\": \"SHA256\", \"checksumValue\": {}}}]",
        json_escape(sha)
    )
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
) -> Result<String, String> {
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
        let sum = checksums
            .get(&(krate.name.clone(), krate.version.clone()))
            .ok_or_else(|| {
                format!(
                    "sbom: {} {} not in the Cargo locks",
                    krate.name, krate.version
                )
            })?;
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
            checksum_entry(&sha256_file(path)?)
        ));
        rel_entries.push(format!(
            "{{\"spdxElementId\": {}, \"relationshipType\": \"CONTAINS\", \
             \"relatedSpdxElement\": {}}}",
            json_escape(&id),
            json_escape(&root_id)
        ));
    }
    Ok(format!(
        "{{\"spdxVersion\": {SPDX_VERSION}, \"dataLicense\": \"CC0-1.0\", \
         \"SPDXID\": {doc}, \"name\": {name}, \"documentNamespace\": {ns}, \
         \"creationInfo\": {{\"created\": {created}, \
         \"creators\": [\"Tool: memveil-release-entry/sbom\"], \
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
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_paths_match_packagers() {
        let cases = [
            ("bin/memveil", "usr/bin/memveil"),
            ("lib/memveil/libx.so.1", "usr/lib/memveil/libx.so.1"),
            (
                "bpf/swiotlb_attempt.bpf.o",
                "usr/lib/memveil/swiotlb_attempt.bpf.o",
            ),
            ("profiles/p.json", "usr/share/memveil/profiles/p.json"),
            ("docs/quickstart.md", "usr/share/memveil/docs/quickstart.md"),
            (
                "examples/demo/f.txt",
                "usr/share/memveil/docs/examples/demo/f.txt",
            ),
            ("LICENSE", "usr/share/doc/memveil/LICENSE"),
            (
                "THIRD-PARTY-NOTICES.md",
                "usr/share/doc/memveil/THIRD-PARTY-NOTICES.md",
            ),
            (
                "LICENSES/GPL-2.0-only.txt",
                "usr/share/doc/memveil/LICENSES/GPL-2.0-only.txt",
            ),
            (
                "licenses/GPL-3.0.txt",
                "usr/share/doc/memveil/licenses/GPL-3.0.txt",
            ),
            (
                "licenses/crates/demo/LICENSE",
                "usr/share/doc/memveil/licenses/crates/demo/LICENSE",
            ),
        ];
        for (bundle, installed) in cases {
            assert_eq!(installed_file_path(bundle).expect(bundle), installed);
        }
        for bad in [
            "",
            "MANIFEST.json",
            "/abs",
            "../escape",
            "a/../b",
            "lib/other.so",
        ] {
            assert!(installed_file_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn closure_render_is_canonical() {
        let entries = BTreeMap::from([
            ("bundle/b".to_string(), "b".repeat(64)),
            ("bundle/a".to_string(), "a".repeat(64)),
        ]);
        let text = render_closure(&entries);
        assert!(text.ends_with("}\n"));
        let a_pos = text.find("\"bundle/a\"").unwrap();
        let b_pos = text.find("\"bundle/b\"").unwrap();
        assert!(a_pos < b_pos, "{text}");
        assert!(!text.contains(' '), "{text}");
    }

    #[test]
    fn manifest_facts_rejects_missing_identity() {
        let err = manifest_facts("{}").expect_err("empty must fail");
        assert!(err.contains("identity"), "{err}");
        let err = manifest_facts("not json").expect_err("garbage must fail");
        assert!(err.contains("corrupt"), "{err}");
    }

    #[test]
    fn manifest_facts_reads_files_and_crates() {
        let text = r#"{
            "engine_version": "0.1.0", "memveil_revision": "abc",
            "bundle": "memveil-0.1.0",
            "toolchain": {"cargo": {"version": "1.0.0"},
                          "rustc": {"version": "1.0.0"}},
            "cargo": {"lock_sha256": "1", "ebpf_lock_sha256": "2",
                       "crates": [{"name": "aya", "version": "0.14.0",
                                   "license": "MIT",
                                   "source": "registry+x"}],
                       "ebpf_crates": []},
            "system_libraries": ["libc.so.6"],
            "files": {"bin/memveil": "ff"}
        }"#;
        let facts = manifest_facts(text).expect("facts");
        assert_eq!(facts.engine, "0.1.0");
        assert_eq!(facts.revision, "abc");
        assert_eq!(facts.crates.len(), 1);
        assert_eq!(facts.crates[0].name, "aya");
        assert_eq!(facts.system_libs, vec!["libc.so.6".to_string()]);
        assert_eq!(
            facts.files.get("bin/memveil").map(String::as_str),
            Some("ff")
        );
    }

    #[test]
    fn collect_rejects_missing_inputs() {
        let missing = Path::new("/nonexistent-closure-input");
        let err = collect_full(missing, missing, missing, "{}").expect_err("missing must fail");
        assert!(err.contains("--bundle"), "{err}");
    }

    #[test]
    fn member_names_cannot_escape() {
        for bad in ["", "/abs", "../x", "a/../../b", "a//b"] {
            assert!(check_member_name(bad, "test").is_err(), "{bad:?}");
        }
        assert!(check_member_name("usr/bin/memveil", "test").is_ok());
    }

    #[test]
    fn write_once_refuses_overwrite() {
        let scratch = Scratch::fresh("write-once").expect("scratch");
        let out = scratch.path.join("once.bin");
        write_once_bytes(&out, b"first\n").expect("first write");
        assert_eq!(fs::read(&out).expect("read"), b"first\n");
        let err = write_once_bytes(&out, b"second\n").expect_err("overwrite");
        assert!(err.contains("refusing to overwrite"), "{err}");
        assert_eq!(fs::read(&out).expect("read"), b"first\n");
    }

    #[test]
    fn extracted_sweep_rejects_swapped_member() {
        // A member swapped between listing and extraction: the
        // typed listing saw a regular file, the tree holds a
        // link. The post-extraction sweep must refuse it.
        let scratch = Scratch::fresh("sweep").expect("scratch");
        let root = scratch.path.join("root");
        fs::create_dir_all(root.join("sub")).expect("mkdir");
        fs::write(root.join("sub/file"), b"payload").expect("write");
        std::os::unix::fs::symlink("file", root.join("sub/link")).expect("symlink");
        let err = refuse_extracted_links(&root, "payload-closure").expect_err("link must fail");
        assert!(err.contains("links and special files"), "{err}");
        fs::remove_file(root.join("sub/link")).expect("remove");
        refuse_extracted_links(&root, "payload-closure").expect("clean tree passes");
    }

    #[test]
    fn bundle_extract_rejects_link_member() {
        // End to end: a crafted bundle tarball carrying a link
        // member fails extraction (the typed listing refuses it
        // first; the sweep is the second refusal for members
        // swapped after listing).
        let scratch = Scratch::fresh("swap").expect("scratch");
        let top = scratch.path.join("top");
        fs::create_dir_all(&top).expect("mkdir");
        fs::write(top.join("payload.txt"), b"payload").expect("write");
        std::os::unix::fs::symlink("payload.txt", top.join("swapped")).expect("symlink");
        let tarball = scratch.path.join("bundle.tar.gz");
        let status = Command::new("tar")
            .args(["-czf"])
            .arg(&tarball)
            .arg("-C")
            .arg(&scratch.path)
            .arg("top")
            .status()
            .expect("run tar");
        assert!(status.success());
        let err = extract_bundle(&tarball, &scratch.path).expect_err("link member must fail");
        assert!(err.contains("links and special files"), "{err}");
    }

    #[test]
    fn shared_hasher_matches_sha256() {
        // "abc" is the FIPS 180-4 first vector.
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
