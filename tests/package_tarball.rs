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
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

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
        "licenses/crates/bytes-1.12.2/LICENSE",
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
    // its HEAD, never the live worktree's (concurrent commits
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
        h::sha256_file(&root.join("Cargo.lock"))
    );
    assert_eq!(
        h::json_probe(&manifest, "d['cargo']['ebpf_lock_sha256']"),
        h::sha256_file(&root.join("crates").join("ebpf").join("Cargo.lock"))
    );
    let crates = h::json_probe(&manifest, "[c['name'] for c in d['cargo']['crates']]");
    assert!(crates.contains("aya"), "crates: {crates}");
    assert!(
        !crates.contains("memveil"),
        "workspace member leaked: {crates}"
    );
    let ebpf = h::json_probe(&manifest, "[c['name'] for c in d['cargo']['ebpf_crates']]");
    assert!(ebpf.contains("aya-ebpf"), "ebpf crates: {ebpf}");
    // Documented gaps (see the packager's manifest comment):
    // no CPU-floor gate and no source inventory ride here.
    assert_eq!(
        h::json_probe(&manifest, "'canonical_runtime' in d"),
        "false"
    );
    assert_eq!(h::json_probe(&manifest, "'source_inventory' in d"), "false");
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
fn bpf_inspection_copies_match_embedded() {
    // The bpf/ inspection copies are the bytes the binary runs: each
    // staged copy must occur in the staged binary, and the manifest's
    // embedded_bpf entry must bind the same digest as files[].
    let set = h::ensure_tarball();
    let binary = fs::read(set.bundle.join("bin").join("memveil")).unwrap();
    let manifest = set.bundle.join("MANIFEST.json");
    for name in h::BPF_OBJECTS {
        let obj = fs::read(set.bundle.join("bpf").join(name)).unwrap();
        assert!(!obj.is_empty(), "{name} is empty");
        assert!(
            binary
                .windows(obj.len())
                .any(|window| window == obj.as_slice()),
            "{name} is not embedded in the staged binary"
        );
        let rel = format!("bpf/{name}");
        let embedded = h::json_probe(&manifest, &format!("d['embedded_bpf'][{name:?}]"));
        assert_eq!(
            embedded,
            h::json_probe(&manifest, &format!("d['files'][{rel:?}]")),
            "{name}: embedded_bpf != files[]"
        );
        assert_eq!(
            embedded,
            h::sha256_file(&set.bundle.join("bpf").join(name)),
            "{name}: embedded_bpf != staged bytes"
        );
    }
}

#[test]
fn mismatched_bpf_inputs_refuse() {
    // --binary with a stale --bpf-dir must refuse before staging: a
    // one-byte-doctored copy-channel object is a different build's bytes
    // and never occurs in the binary.
    let root = h::pristine_root();
    let binary = h::ensure_release_binary();
    let out = h::bpf_out_dir();
    let tmp = h::scratch("bpf-mismatch");
    let doctored = tmp.join("bpf");
    fs::create_dir_all(&doctored).unwrap();
    for channel in ["attempt", "lifecycle", "copy"] {
        let name = format!("memveil-ebpf-{channel}");
        let mut bytes = fs::read(out.join(&name)).unwrap();
        if channel == "copy" {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
        }
        fs::write(doctored.join(&name), &bytes).unwrap();
    }
    let script = h::scripts_dir().join("package-tarball.py");
    let dest = tmp.join("out");
    let proc = h::run(
        "python3",
        &[
            script.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--bpf-dir",
            doctored.to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
        ],
        None,
    );
    assert!(!proc.status.success(), "mixed --binary/--bpf-dir packaged");
    let stderr = String::from_utf8_lossy(&proc.stderr);
    assert!(
        stderr.contains("does not embed the swiotlb_copy.bpf.o input"),
        "{stderr}"
    );
}

#[test]
fn appended_bpf_overlay_refuses() {
    // Appended-overlay contest: a correctly marked copy object
    // that differs from the embedded bytes must refuse even
    // when its only occurrence is appended past every PT_LOAD
    // segment. The executable still runs its original bytes;
    // the manifest must never record the overlay digest.
    let root = h::pristine_root();
    let binary = h::ensure_release_binary();
    let out = h::bpf_out_dir();
    let tmp = h::scratch("bpf-overlay");
    let script = h::scripts_dir().join("package-tarball.py");

    // Doctor one byte outside the channel marker: the copy
    // input stays correctly marked yet differs from the bytes
    // the binary embeds.
    let copy = fs::read(out.join("memveil-ebpf-copy")).unwrap();
    let marker = b"memveil-channel:copy\0";
    let at = copy
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("copy marker present");
    let mut doctored = copy.clone();
    let mut flip = doctored.len() - 1;
    if (at..at + marker.len()).contains(&flip) {
        flip = 0;
        assert!(
            !(at..at + marker.len()).contains(&flip),
            "marker spans the whole object"
        );
    }
    doctored[flip] ^= 0x01;
    assert!(
        doctored.windows(marker.len()).any(|w| w == marker),
        "surgery broke the marker"
    );
    assert_ne!(doctored, copy, "surgery left the bytes identical");

    let doctored_dir = tmp.join("bpf");
    fs::create_dir_all(&doctored_dir).unwrap();
    for channel in ["attempt", "lifecycle"] {
        let name = format!("memveil-ebpf-{channel}");
        fs::copy(out.join(&name), doctored_dir.join(&name)).unwrap();
    }
    let doctored_copy = doctored_dir.join("memveil-ebpf-copy");
    fs::write(&doctored_copy, &doctored).unwrap();

    // Marker == channel still passes: only the digest binding
    // may refuse this input.
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         assert m.read_elf_section({doctored_copy:?}, 'memveil_channel') == b'memveil-channel:copy\\0'; \
         print('overlay-marker-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("overlay-marker-ok"), "{text}");

    // Overlay binary: the real bytes plus the doctored object
    // appended past the end of the file.
    let orig = fs::read(&binary).unwrap();
    let mut overlaid = orig.clone();
    overlaid.extend_from_slice(&doctored);
    let overlaid_path = tmp.join("memveil-overlay");
    fs::write(&overlaid_path, &overlaid).unwrap();
    fs::set_permissions(&overlaid_path, fs::metadata(&binary).unwrap().permissions()).unwrap();
    assert!(
        overlaid
            .windows(doctored.len())
            .any(|w| w == doctored.as_slice()),
        "overlay occurrence missing"
    );

    // Prove the geometry with readelf (independent of the
    // script under test): every PT_LOAD file range ends at or
    // before the append base.
    let layout = h::run_ok("readelf", &["-lW", overlaid_path.to_str().unwrap()], None);
    let mut loads = 0;
    for line in layout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() != Some(&"LOAD") || fields.len() < 5 {
            continue;
        }
        let hex = |field: &str| {
            u64::from_str_radix(field.trim_start_matches("0x"), 16).expect("hex field")
        };
        assert!(
            hex(fields[1]) + hex(fields[4]) <= orig.len() as u64,
            "PT_LOAD reaches the overlay: {line}"
        );
        loads += 1;
    }
    assert!(loads > 0, "no PT_LOAD segments:\n{layout}");

    let dest = tmp.join("out");
    let proc = h::run(
        "python3",
        &[
            script.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--binary",
            overlaid_path.to_str().unwrap(),
            "--bpf-dir",
            doctored_dir.to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
        ],
        None,
    );
    assert!(!proc.status.success(), "appended overlay packaged");
    let stderr = String::from_utf8_lossy(&proc.stderr);
    assert!(
        stderr.contains("does not embed the swiotlb_copy.bpf.o input"),
        "{stderr}"
    );
    assert!(
        !dest
            .join(format!("memveil-{}", h::engine_version()))
            .exists(),
        "overlay refusal left a bundle"
    );
}

/// Extend the last-ending PT_LOAD over `section`'s file range.
///
/// Minimal 64-bit little-endian ELF surgery for the
/// planted-section contest: objcopy plants the bytes but leaves
/// an allocated section outside every segment, so the covering
/// LOAD's filesz/memsz grow to the section end. The segment's
/// old zero tail ([filesz, memsz), kernel-provided BSS before
/// the extension) is re-zeroed in the file: the newly mapped
/// file bytes there would otherwise poison globals (observed:
/// a binary that prints, then parks in pause() instead of
/// exiting, because a runtime guard reads garbage).
fn extend_last_load_over_section(path: &Path, section: &str) {
    fn u64le(raw: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
    }
    fn u16le(raw: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(raw[at..at + 2].try_into().unwrap())
    }
    let mut raw = fs::read(path).unwrap();
    assert!(
        raw.len() >= 64 && raw[..4] == *b"\x7fELF" && raw[4] == 2 && raw[5] == 1,
        "not a 64-bit little-endian ELF: {}",
        path.display()
    );
    let e_phoff = u64le(&raw, 0x20) as usize;
    let e_phentsize = u16le(&raw, 0x36) as usize;
    let e_phnum = u16le(&raw, 0x38) as usize;
    let e_shoff = u64le(&raw, 0x28) as usize;
    let e_shentsize = u16le(&raw, 0x3a) as usize;
    let e_shnum = u16le(&raw, 0x3c) as usize;
    let e_shstrndx = u16le(&raw, 0x3e) as usize;
    assert!(e_phentsize >= 56 && e_phnum > 0, "no program headers");
    assert!(e_shentsize >= 64 && e_shnum > 0, "no section headers");
    assert!(e_shstrndx < e_shnum, "no section-name table");
    let str_base = e_shoff + e_shstrndx * e_shentsize;
    let str_off = u64le(&raw, str_base + 24) as usize;
    let str_size = u64le(&raw, str_base + 32) as usize;
    let mut found = None;
    for index in 0..e_shnum {
        let base = e_shoff + index * e_shentsize;
        let sh_name = u32::from_le_bytes(raw[base..base + 4].try_into().unwrap()) as usize;
        assert!(sh_name < str_size, "section name overrun");
        let end = str_off + str_size;
        let name = raw[str_off + sh_name..end]
            .split(|byte| *byte == 0)
            .next()
            .unwrap();
        if name == section.as_bytes() {
            found = Some((u64le(&raw, base + 24), u64le(&raw, base + 32)));
            break;
        }
    }
    let (sec_off, sec_size) = found.expect("planted section present");
    let mut best = None;
    let mut best_end = 0;
    for index in 0..e_phnum {
        let base = e_phoff + index * e_phentsize;
        let p_type = u32::from_le_bytes(raw[base..base + 4].try_into().unwrap());
        if p_type != 1 {
            continue;
        }
        let off = u64le(&raw, base + 8);
        let filesz = u64le(&raw, base + 32);
        let memsz = u64le(&raw, base + 40);
        if off + filesz > best_end {
            best_end = off + filesz;
            best = Some((base, off, filesz, memsz));
        }
    }
    let (base, off, old_filesz, old_memsz) = best.expect("a PT_LOAD exists");
    assert!(
        sec_off >= off + old_filesz,
        "planted section overlaps mapped bytes"
    );
    let new_filesz = sec_off + sec_size - off;
    let new_memsz = new_filesz + (old_memsz - old_filesz);
    raw[base + 32..base + 40].copy_from_slice(&new_filesz.to_le_bytes());
    raw[base + 40..base + 48].copy_from_slice(&new_memsz.to_le_bytes());
    let zero_lo = (off + old_filesz) as usize;
    let zero_hi = (off + old_memsz) as usize;
    assert!(
        zero_hi as u64 <= sec_off,
        "BSS tail zeroing would touch the planted bytes"
    );
    raw[zero_lo..zero_hi].fill(0);
    fs::write(path, &raw).unwrap();
}

#[test]
fn planted_loadable_section_refuses() {
    // Planted-section contest: a correctly marked copy object
    // that differs from the embedded bytes must refuse even
    // when it sits in its own unused loadable section, where
    // an occurrence search matches it. The executable still
    // runs its original bytes (the dumped manifest names the
    // pristine digests); only the digest binding may refuse
    // this input.
    if !h::tool_present("objcopy") {
        eprintln!("skip: objcopy absent on this host: planting needs it");
        return;
    }
    let root = h::pristine_root();
    let binary = h::ensure_release_binary();
    let out = h::bpf_out_dir();
    let tmp = h::scratch("bpf-planted");
    let script = h::scripts_dir().join("package-tarball.py");

    // Doctor one byte outside the channel marker (as in the
    // overlay test): correctly marked, differently hashed.
    let copy = fs::read(out.join("memveil-ebpf-copy")).unwrap();
    let marker = b"memveil-channel:copy\0";
    let at = copy
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("copy marker present");
    let mut doctored = copy.clone();
    let mut flip = doctored.len() - 1;
    if (at..at + marker.len()).contains(&flip) {
        flip = 0;
        assert!(
            !(at..at + marker.len()).contains(&flip),
            "marker spans the whole object"
        );
    }
    doctored[flip] ^= 0x01;
    assert!(
        doctored.windows(marker.len()).any(|w| w == marker),
        "surgery broke the marker"
    );
    assert_ne!(doctored, copy, "surgery left the bytes identical");
    let doctored_obj = tmp.join("doctored-copy.o");
    fs::write(&doctored_obj, &doctored).unwrap();

    let doctored_dir = tmp.join("bpf");
    fs::create_dir_all(&doctored_dir).unwrap();
    for channel in ["attempt", "lifecycle"] {
        let name = format!("memveil-ebpf-{channel}");
        fs::copy(out.join(&name), doctored_dir.join(&name)).unwrap();
    }
    fs::write(doctored_dir.join("memveil-ebpf-copy"), &doctored).unwrap();

    // Plant the doctored object as a new allocated section,
    // then extend PT_LOAD over its file range so the planted
    // bytes are genuinely loadable.
    let planted_path = tmp.join("memveil-planted");
    let add_section = format!(".memveil_plant={}", doctored_obj.display());
    let objcopy = h::run(
        "objcopy",
        &[
            "--add-section",
            &add_section,
            "--set-section-flags",
            ".memveil_plant=alloc,readonly",
            binary.to_str().unwrap(),
            planted_path.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        objcopy.status.success(),
        "objcopy failed: {}",
        String::from_utf8_lossy(&objcopy.stderr)
    );
    extend_last_load_over_section(&planted_path, ".memveil_plant");
    fs::set_permissions(&planted_path, fs::metadata(&binary).unwrap().permissions()).unwrap();

    // Prove the geometry with readelf (independent of the
    // script under test): the planted section exists at its
    // full size, and one PT_LOAD file range covers it wholly.
    let sections = h::run_ok("readelf", &["-SW", planted_path.to_str().unwrap()], None);
    let mut geometry = None;
    for line in sections.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 6 && fields[1] == ".memveil_plant" {
            let off = u64::from_str_radix(fields[4], 16).expect("section offset");
            let size = u64::from_str_radix(fields[5], 16).expect("section size");
            geometry = Some((off, size));
        }
    }
    let (sec_off, sec_size) = geometry.expect("planted section in readelf -SW");
    assert_eq!(sec_size as usize, doctored.len(), "planted section size");
    let layout = h::run_ok("readelf", &["-lW", planted_path.to_str().unwrap()], None);
    let mut covered = false;
    for line in layout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() != Some(&"LOAD") || fields.len() < 5 {
            continue;
        }
        let hex = |field: &str| {
            u64::from_str_radix(field.trim_start_matches("0x"), 16).expect("hex field")
        };
        if hex(fields[1]) <= sec_off && sec_off + sec_size <= hex(fields[1]) + hex(fields[4]) {
            covered = true;
        }
    }
    assert!(covered, "no PT_LOAD covers the planted section");
    // The planted bytes sit exactly there: an occurrence
    // search scoped to the mapped ranges matches them.
    let planted_bytes = fs::read(&planted_path).unwrap();
    let end = sec_off as usize + doctored.len();
    assert_eq!(&planted_bytes[sec_off as usize..end], doctored.as_slice());

    // The executable still runs its original bytes: version
    // exits 0 and the dumped manifest names the pristine
    // OUT_DIR digests, not the planted bytes.
    let version = h::run(planted_path.to_str().unwrap(), &["version"], None);
    assert!(version.status.success(), "planted binary fails version");
    let dumped = h::run(
        planted_path.to_str().unwrap(),
        &["--embedded-manifest"],
        None,
    );
    assert!(
        dumped.status.success(),
        "planted binary fails --embedded-manifest"
    );
    let dumped_text = String::from_utf8_lossy(&dumped.stdout).into_owned();
    let rows: Vec<&str> = dumped_text.lines().collect();
    assert_eq!(rows.len(), 3, "manifest rows: {rows:?}");
    for (row, channel) in rows.iter().zip(["attempt", "lifecycle", "copy"]) {
        let (name, digest) = row.split_once(' ').expect("channel digest row");
        assert_eq!(name, channel);
        assert_eq!(
            digest,
            h::sha256_file(&out.join(format!("memveil-ebpf-{channel}"))),
            "{channel} digest names the planted bytes"
        );
    }

    let dest = tmp.join("out");
    let proc = h::run(
        "python3",
        &[
            script.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--binary",
            planted_path.to_str().unwrap(),
            "--bpf-dir",
            doctored_dir.to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
        ],
        None,
    );
    assert!(!proc.status.success(), "planted section packaged");
    let stderr = String::from_utf8_lossy(&proc.stderr);
    assert!(
        stderr.contains("does not embed the swiotlb_copy.bpf.o input"),
        "{stderr}"
    );
    assert!(
        !dest
            .join(format!("memveil-{}", h::engine_version()))
            .exists(),
        "planted refusal left a bundle"
    );
}

#[test]
fn embedded_manifest_matches_bpf_dir() {
    // The dumped manifest binds the build: every row must name
    // the OUT_DIR artifact the binary embeds for that channel.
    let binary = h::ensure_release_binary();
    let out = h::bpf_out_dir();
    let proc = h::run(binary.to_str().unwrap(), &["--embedded-manifest"], None);
    assert!(
        proc.status.success(),
        "--embedded-manifest failed: {}",
        String::from_utf8_lossy(&proc.stderr)
    );
    assert!(
        proc.stderr.is_empty(),
        "manifest writes to stderr: {:?}",
        String::from_utf8_lossy(&proc.stderr)
    );
    let text = String::from_utf8(proc.stdout).expect("manifest is UTF-8");
    let rows: Vec<&str> = text.lines().collect();
    assert_eq!(rows.len(), 3, "manifest rows: {rows:?}");
    for (row, channel) in rows.iter().zip(["attempt", "lifecycle", "copy"]) {
        let (name, digest) = row.split_once(' ').expect("channel digest row");
        assert_eq!(name, channel);
        assert_eq!(
            digest,
            h::sha256_file(&out.join(format!("memveil-ebpf-{channel}"))),
            "{channel} digest differs from the build artifact"
        );
    }
}

#[test]
fn binary_without_manifest_flag_refuses() {
    // A binary too old for --embedded-manifest refuses
    // fail-closed with a rebuild pointer instead of falling
    // back to an occurrence search. The stand-in emulates a
    // pre-flag binary's unknown-verb path (usage to stderr,
    // exit 2); the gate depends only on that contract.
    use std::os::unix::fs::PermissionsExt;
    let root = h::pristine_root();
    let out = h::bpf_out_dir();
    let tmp = h::scratch("bpf-old-binary");
    let standin = tmp.join("memveil-old");
    fs::write(
        &standin,
        "#!/bin/sh\necho 'usage: memveil <verbs> [args]' >&2\nexit 2\n",
    )
    .unwrap();
    fs::set_permissions(&standin, fs::Permissions::from_mode(0o755)).unwrap();
    let script = h::scripts_dir().join("package-tarball.py");
    let dest = tmp.join("out");
    let proc = h::run(
        "python3",
        &[
            script.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--binary",
            standin.to_str().unwrap(),
            "--bpf-dir",
            out.to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
        ],
        None,
    );
    assert!(!proc.status.success(), "flag-less binary packaged");
    let stderr = String::from_utf8_lossy(&proc.stderr);
    assert!(
        stderr.contains("refuses --embedded-manifest")
            && stderr.contains("predates the embedded-digest binding"),
        "{stderr}"
    );
    assert!(
        !dest
            .join(format!("memveil-{}", h::engine_version()))
            .exists(),
        "flag-less refusal left a bundle"
    );
}

#[test]
fn embedded_manifest_parser_rejects_malformed() {
    // Pure-helper probes against the script module: a well
    // formed dump parses to its three digests, while row
    // count, order, channel, and digest deviations refuse
    // instead of binding.
    let script = h::scripts_dir().join("package-tarball.py");
    let digest = |byte: &str| byte.repeat(32);
    let good = format!(
        "attempt {}\\nlifecycle {}\\ncopy {}\\n",
        digest("aa"),
        digest("bb"),
        digest("cc")
    );
    // Dumps travel as Python `\n` escapes (Rust Debug would
    // double-escape the newlines into literal backslashes).
    let py = |dump: &str| dump.replace('\n', "\\n");
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         got = m.parse_embedded_manifest('{good}', 'fake-binary'); \
         assert got == {{'attempt': '{a}', 'lifecycle': '{b}', 'copy': '{c}'}}, got; \
         print('manifest-ok')",
        good = py(&good),
        a = digest("aa"),
        b = digest("bb"),
        c = digest("cc"),
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("manifest-ok"), "{text}");
    let cases: &[(&str, String, &str)] = &[
        (
            "truncated",
            format!("attempt {}\n", digest("aa")),
            "dumps 1 manifest rows",
        ),
        (
            "extra-row",
            format!("{good}spare {}\n", digest("dd")),
            "dumps 4 manifest rows",
        ),
        (
            "swapped-order",
            format!(
                "lifecycle {}\nattempt {}\ncopy {}\n",
                digest("bb"),
                digest("aa"),
                digest("cc")
            ),
            "bad manifest row",
        ),
        (
            "bad-channel",
            good.replace("copy ", "void "),
            "bad manifest row",
        ),
        (
            "short-digest",
            good.replace(&digest("cc"), "cc"),
            "bad copy digest",
        ),
        (
            "nonhex-digest",
            good.replace(&digest("cc"), &"zz".repeat(32)),
            "bad copy digest",
        ),
        (
            "uppercase-digest",
            good.replace(&digest("cc"), &"CC".repeat(32)),
            "bad copy digest",
        ),
    ];
    // "truncated" above drops to one row; pin the two-row
    // cut explicitly so the count message is exact, not implied.
    let two_rows = format!("attempt {}\nlifecycle {}\n", digest("aa"), digest("bb"));
    for (leaf, dump, fragment) in cases {
        let probe = format!(
            "import importlib.util; \
             l = importlib.util.spec_from_file_location('m', {script:?}); \
             m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
             m.parse_embedded_manifest('{dump}', 'fake-binary')",
            dump = py(dump),
        );
        let proc = h::run("python3", &["-B", "-c", &probe], None);
        assert!(!proc.status.success(), "{leaf} dump parsed");
        assert!(
            String::from_utf8_lossy(&proc.stderr).contains(fragment),
            "{leaf}: {}",
            String::from_utf8_lossy(&proc.stderr)
        );
    }
    // Two-row cut: the count message names the shortfall.
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         m.parse_embedded_manifest('{dump}', 'fake-binary')",
        dump = py(&two_rows),
    );
    let proc = h::run("python3", &["-B", "-c", &probe], None);
    assert!(!proc.status.success(), "two-row dump parsed");
    assert!(
        String::from_utf8_lossy(&proc.stderr).contains("dumps 2 manifest rows"),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
}

/// Open-count swap shim: serves `MV_SWAP_V1` for the first
/// `MV_SWAP_AFTER` read-opens of `MV_SWAP_TARGET`, `MV_SWAP_V2`
/// after, and records the open count in `MV_SWAP_COUNTFILE`.
///
/// Models a `--bpf-dir` input replaced between validation and
/// staging: validation (hash + marker probe) sees the original
/// bytes while the staging copy and the verify re-read see the
/// replacement. Path redirection only — the script under test
/// runs unmodified, and the open count pins its read pattern
/// (any added validation read fails the count instead of
/// silently testing the wrong state).
const SWAP_SHIM_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int (*real_open)(const char *, int, ...) = 0;
static int (*real_openat)(int, const char *, int, ...) = 0;
static int opens = 0;

static void resolve(void) {
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        real_openat = dlsym(RTLD_NEXT, "openat");
    }
}

/* Redirect path: the swap target while it is read, else NULL. */
static const char *redirect(const char *path, int flags) {
    const char *target;
    const char *after;
    int keep;
    if (!path || (flags & O_ACCMODE) != O_RDONLY)
        return 0;
    if (flags & (O_CREAT | O_TMPFILE))
        return 0;
    target = getenv("MV_SWAP_TARGET");
    if (!target || !*target || strcmp(path, target) != 0)
        return 0;
    after = getenv("MV_SWAP_AFTER");
    keep = after ? atoi(after) : 2;
    opens++;
    if (opens <= keep)
        return getenv("MV_SWAP_V1");
    return getenv("MV_SWAP_V2");
}

static int do_open(int dirfd, const char *path, int flags, mode_t mode,
                   int have_mode, int use_at) {
    const char *swap;
    resolve();
    if (!use_at || (dirfd == AT_FDCWD && path && path[0] == '/')) {
        swap = redirect(path, flags);
        if (swap && *swap)
            path = swap;
    }
    if (use_at) {
        if (have_mode)
            return real_openat(dirfd, path, flags, mode);
        return real_openat(dirfd, path, flags);
    }
    if (have_mode)
        return real_open(path, flags, mode);
    return real_open(path, flags);
}

int open(const char *path, int flags, ...) {
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return do_open(0, path, flags, mode, 1, 0);
    }
    return do_open(0, path, flags, 0, 0, 0);
}

int open64(const char *path, int flags, ...) {
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return do_open(0, path, flags, mode, 1, 0);
    }
    return do_open(0, path, flags, 0, 0, 0);
}

int openat(int dirfd, const char *path, int flags, ...) {
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return do_open(dirfd, path, flags, mode, 1, 1);
    }
    return do_open(dirfd, path, flags, 0, 0, 1);
}

int openat64(int dirfd, const char *path, int flags, ...) {
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return do_open(dirfd, path, flags, mode, 1, 1);
    }
    return do_open(dirfd, path, flags, 0, 0, 1);
}

__attribute__((destructor)) static void report(void) {
    const char *count = getenv("MV_SWAP_COUNTFILE");
    FILE *out;
    if (!count || !*count || opens == 0)
        return;
    out = fopen(count, "w");
    if (!out)
        return;
    fprintf(out, "%d\n", opens);
    fclose(out);
}
"#;

/// `SWAP_SHIM_C` plus a staged-probe marker: a constructor that
/// appends to `MV_MARK_FILE` when this process is the staged
/// binary (`/proc/self/exe == MV_MARK_STAGED`) invoked with
/// `--embedded-manifest`. The validation probe runs the
/// `--binary` path (a different exe) and `version` runs lack
/// the flag, so the marker exists iff the seal re-dumped the
/// staged copy — a deterministic execution signal, no timing
/// involved. Without `MV_MARK_STAGED`/`MV_MARK_FILE` the
/// constructor returns before any open, leaving the swap
/// behavior (and its pinned counts) unchanged.
const SWAP_MARK_SHIM_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int (*real_open)(const char *, int, ...) = 0;
static int (*real_openat)(int, const char *, int, ...) = 0;
static int opens = 0;

static void resolve(void) {
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        real_openat = dlsym(RTLD_NEXT, "openat");
    }
}

/* Redirect path: the swap target while it is read, else NULL. */
static const char *redirect(const char *path, int flags) {
    const char *target;
    const char *after;
    int keep;
    if (!path || (flags & O_ACCMODE) != O_RDONLY)
        return 0;
    if (flags & (O_CREAT | O_TMPFILE))
        return 0;
    target = getenv("MV_SWAP_TARGET");
    if (!target || !*target || strcmp(path, target) != 0)
        return 0;
    after = getenv("MV_SWAP_AFTER");
    keep = after ? atoi(after) : 2;
    opens++;
    if (opens <= keep)
        return getenv("MV_SWAP_V1");
    return getenv("MV_SWAP_V2");
}

static int do_open(int dirfd, const char *path, int flags, mode_t mode,
                   int have_mode, int use_at) {
    const char *swap;
    resolve();
    if (!use_at || (dirfd == AT_FDCWD && path && path[0] == '/')) {
        swap = redirect(path, flags);
        if (swap && *swap)
            path = swap;
    }
    if (use_at) {
        if (have_mode)
            return real_openat(dirfd, path, flags, mode);
        return real_openat(dirfd, path, flags);
    }
    if (have_mode)
        return real_open(path, flags, mode);
    return real_open(path, flags);
}

int open(const char *path, int flags, ...) {
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return do_open(0, path, flags, mode, 1, 0);
    }
    return do_open(0, path, flags, 0, 0, 0);
}

int open64(const char *path, int flags, ...) {
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return do_open(0, path, flags, mode, 1, 0);
    }
    return do_open(0, path, flags, 0, 0, 0);
}

int openat(int dirfd, const char *path, int flags, ...) {
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return do_open(dirfd, path, flags, mode, 1, 1);
    }
    return do_open(dirfd, path, flags, 0, 0, 1);
}

int openat64(int dirfd, const char *path, int flags, ...) {
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return do_open(dirfd, path, flags, mode, 1, 1);
    }
    return do_open(dirfd, path, flags, 0, 0, 1);
}

/* Staged-probe marker: when this process IS the staged binary
   invoked with --embedded-manifest, append one line to
   MV_MARK_FILE. The validation probe runs the --binary path
   (a different /proc/self/exe) and `version` runs lack the
   flag, so the marker fires only for the seal re-dump. */
__attribute__((constructor)) static void mark_staged_probe(void) {
    static const char flag[] = "--embedded-manifest";
    const char *want_exe = getenv("MV_MARK_STAGED");
    const char *mark_file = getenv("MV_MARK_FILE");
    char exe[4096];
    char cmd[4096];
    ssize_t got;
    size_t i;
    int fd;
    int seen = 0;
    if (!want_exe || !*want_exe || !mark_file || !*mark_file)
        return;
    resolve();
    if (!real_openat)
        return;
    got = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (got <= 0 || (size_t)got >= sizeof(exe) - 1)
        return;
    exe[got] = '\0';
    if (strcmp(exe, want_exe) != 0)
        return;
    fd = real_openat(AT_FDCWD, "/proc/self/cmdline", O_RDONLY);
    if (fd < 0)
        return;
    got = read(fd, cmd, sizeof(cmd));
    close(fd);
    if (got <= 0)
        return;
    for (i = 0; i + sizeof(flag) - 1 <= (size_t)got; i++) {
        if (memcmp(cmd + i, flag, sizeof(flag) - 1) == 0) {
            seen = 1;
            break;
        }
    }
    if (!seen)
        return;
    fd = real_openat(AT_FDCWD, mark_file,
                     O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return;
    if (write(fd, "probed\n", 7) != 7) {
        close(fd);
        return;
    }
    close(fd);
}

__attribute__((destructor)) static void report(void) {
    const char *count = getenv("MV_SWAP_COUNTFILE");
    FILE *out;
    if (!count || !*count || opens == 0)
        return;
    out = fopen(count, "w");
    if (!out)
        return;
    fprintf(out, "%d\n", opens);
    fclose(out);
}
"#;

#[test]
fn staged_bpf_swap_refuses() {
    // Staging TOCTOU contest: a copy input swapped between
    // validation and staging must refuse. The shim serves the
    // validated bytes for the first two opens and the
    // replacement after, so the staged-vs-source check compares
    // replacement against replacement and passes — exactly the
    // state that shipped embedded_bpf=original with
    // files=replacement. Only the staged-vs-executable binding
    // may refuse this run.
    if !h::tool_present("cc") {
        eprintln!("skip: cc absent on this host: the swap shim needs it");
        return;
    }
    let root = h::pristine_root();
    let binary = h::ensure_release_binary();
    let out = h::bpf_out_dir();
    let tmp = h::scratch("bpf-swap");
    let script = h::scripts_dir().join("package-tarball.py");

    // Replacement bytes: one flipped bit outside the channel
    // marker (correctly marked, differently hashed), same
    // length so file metadata stays consistent under the swap.
    let copy = fs::read(out.join("memveil-ebpf-copy")).unwrap();
    let marker = b"memveil-channel:copy\0";
    let at = copy
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("copy marker present");
    let mut swapped = copy.clone();
    let mut flip = swapped.len() - 1;
    if (at..at + marker.len()).contains(&flip) {
        flip = 0;
        assert!(
            !(at..at + marker.len()).contains(&flip),
            "marker spans the whole object"
        );
    }
    swapped[flip] ^= 0x01;
    assert!(
        swapped.windows(marker.len()).any(|w| w == marker),
        "surgery broke the marker"
    );
    assert_ne!(swapped, copy, "surgery left the bytes identical");

    let v1 = tmp.join("copy-v1.o");
    let v2 = tmp.join("copy-v2.o");
    fs::write(&v1, &copy).unwrap();
    fs::write(&v2, &swapped).unwrap();

    let bpf_dir = tmp.join("bpf");
    fs::create_dir_all(&bpf_dir).unwrap();
    for channel in ["attempt", "lifecycle"] {
        let name = format!("memveil-ebpf-{channel}");
        fs::copy(out.join(&name), bpf_dir.join(&name)).unwrap();
    }
    // Absolute without resolving symlinks, exactly as the
    // script's abspath spells the path it opens: the shim
    // matches that spelling byte for byte.
    let bpf_dir = if bpf_dir.is_absolute() {
        bpf_dir
    } else {
        std::env::current_dir().unwrap().join(&bpf_dir)
    };
    let target = bpf_dir.join("memveil-ebpf-copy");
    fs::copy(&v1, &target).unwrap();

    let shim_c = tmp.join("swap.c");
    let shim_so = tmp.join("swap.so");
    fs::write(&shim_c, SWAP_SHIM_C).unwrap();
    let build = h::run(
        "cc",
        &[
            "-shared",
            "-fPIC",
            "-O2",
            "-o",
            shim_so.to_str().unwrap(),
            shim_c.to_str().unwrap(),
            "-ldl",
        ],
        None,
    );
    assert!(
        build.status.success(),
        "swap shim build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let dest = tmp.join("out");
    let count = tmp.join("swap-count.txt");
    let proc = std::process::Command::new("python3")
        .arg(script.to_str().unwrap())
        .args([
            "--root",
            root.to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--bpf-dir",
            bpf_dir.to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
        ])
        .env("LD_PRELOAD", shim_so.to_str().unwrap())
        .env("MV_SWAP_TARGET", target.to_str().unwrap())
        .env("MV_SWAP_V1", v1.to_str().unwrap())
        .env("MV_SWAP_V2", v2.to_str().unwrap())
        .env("MV_SWAP_AFTER", "2")
        .env("MV_SWAP_COUNTFILE", count.to_str().unwrap())
        .output()
        .expect("cannot run package-tarball.py");
    assert!(!proc.status.success(), "swapped staging packaged");
    let stderr = String::from_utf8_lossy(&proc.stderr);
    assert!(
        stderr.contains("staged BPF copy differs from the binary's embedded manifest")
            && stderr.contains("bpf/swiotlb_copy.bpf.o"),
        "{stderr}"
    );
    // Exactly the four production reads (validation hash,
    // marker probe, staging copy, verify re-read): the old
    // staged-vs-source check saw replacement twice and passed,
    // so this refusal is the new binding firing, not an
    // unrelated failure.
    assert_eq!(
        fs::read_to_string(&count).unwrap().trim(),
        "4",
        "swap shim saw an unexpected read pattern"
    );
    assert!(
        !dest
            .join(format!("memveil-{}", h::engine_version()))
            .exists(),
        "swap refusal left a bundle"
    );
    assert!(
        !dest
            .join(format!("memveil-{}.tar.gz", h::engine_version()))
            .exists(),
        "swap refusal left a tarball"
    );
}

#[test]
fn staged_binary_exec_split_refuses() {
    // --binary exec/read-split contest: a --binary replaced
    // between the validation hash and the manifest probe (and
    // restored before staging) must refuse. The shim serves the
    // pristine bytes for every read-open while exec sees the
    // doctored on-disk file — LD_PRELOAD redirects open/openat
    // only — so validation hashes and stages V1 while the dumped
    // manifest and the --bpf-dir check see V2: exactly the state
    // that shipped embedded_bpf=V2 with files=V1. Only the
    // staged-executable re-dump binding may refuse this run.
    if !h::tool_present("cc") {
        eprintln!("skip: cc absent on this host: the swap shim needs it");
        return;
    }
    let root = h::pristine_root();
    let binary = h::ensure_release_binary();
    let out = h::bpf_out_dir();
    let tmp = h::scratch("binary-split");
    let script = h::scripts_dir().join("package-tarball.py");

    // Doctored copy object: one flipped bit outside the channel
    // marker (correctly marked, differently hashed), same length.
    let copy = fs::read(out.join("memveil-ebpf-copy")).unwrap();
    let marker = b"memveil-channel:copy\0";
    let at = copy
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("copy marker present");
    let mut doctored = copy.clone();
    let mut flip = doctored.len() - 1;
    if (at..at + marker.len()).contains(&flip) {
        flip = 0;
        assert!(
            !(at..at + marker.len()).contains(&flip),
            "marker spans the whole object"
        );
    }
    doctored[flip] ^= 0x01;
    assert!(
        doctored.windows(marker.len()).any(|w| w == marker),
        "surgery broke the marker"
    );
    assert_ne!(doctored, copy, "surgery left the bytes identical");
    let doctored_obj = tmp.join("doctored-copy.o");
    fs::write(&doctored_obj, &doctored).unwrap();
    let doctored_sha = h::sha256_file(&doctored_obj);

    // V2 binary: pristine bytes with the single baked copy-digest
    // row replaced by the doctored copy's digest. Same length,
    // still executes; dumps the doctored row for copy.
    let v1 = fs::read(&binary).unwrap();
    let pristine_sha = h::sha256_file(&out.join("memveil-ebpf-copy"));
    let hits = v1
        .windows(pristine_sha.len())
        .filter(|window| *window == pristine_sha.as_bytes())
        .count();
    assert_eq!(hits, 1, "baked copy digest is not unique");
    let at = v1
        .windows(pristine_sha.len())
        .position(|window| window == pristine_sha.as_bytes())
        .unwrap();
    let mut v2 = v1.clone();
    v2[at..at + pristine_sha.len()].copy_from_slice(doctored_sha.as_bytes());
    assert_ne!(v2, v1, "digest surgery left the bytes identical");

    let v1_path = tmp.join("binary-v1");
    let v2_path = tmp.join("binary-v2");
    fs::write(&v1_path, &v1).unwrap();
    fs::write(&v2_path, &v2).unwrap();

    // Absolute without resolving symlinks, exactly as the
    // script's abspath spells the path it opens: the shim
    // matches that spelling byte for byte.
    let mut target = tmp.join("memveil-input");
    if !target.is_absolute() {
        target = std::env::current_dir().unwrap().join(&target);
    }
    fs::copy(&v2_path, &target).unwrap();
    fs::set_permissions(&target, fs::metadata(&binary).unwrap().permissions()).unwrap();

    // The doctored input still executes and dumps the doctored
    // copy row: validation genuinely sees V2's manifest.
    let version = h::run(target.to_str().unwrap(), &["version"], None);
    assert!(version.status.success(), "V2 binary fails version");
    let dumped = h::run(target.to_str().unwrap(), &["--embedded-manifest"], None);
    assert!(
        dumped.status.success(),
        "V2 binary fails --embedded-manifest"
    );
    let dumped_text = String::from_utf8_lossy(&dumped.stdout).into_owned();
    let rows: Vec<&str> = dumped_text.lines().collect();
    assert_eq!(rows.len(), 3, "manifest rows: {rows:?}");
    for (row, channel) in rows.iter().zip(["attempt", "lifecycle", "copy"]) {
        let (name, digest) = row.split_once(' ').expect("channel digest row");
        assert_eq!(name, channel);
        let want = if channel == "copy" {
            doctored_sha.clone()
        } else {
            h::sha256_file(&out.join(format!("memveil-ebpf-{channel}")))
        };
        assert_eq!(digest, want, "{channel} row is not V2's");
    }

    // --bpf-dir inputs matching V2's dump: pristine attempt and
    // lifecycle plus the doctored copy (whose marker still
    // passes: only the exec/read split may refuse this run).
    let bpf_dir = tmp.join("bpf");
    fs::create_dir_all(&bpf_dir).unwrap();
    for channel in ["attempt", "lifecycle"] {
        let name = format!("memveil-ebpf-{channel}");
        fs::copy(out.join(&name), bpf_dir.join(&name)).unwrap();
    }
    fs::copy(&doctored_obj, bpf_dir.join("memveil-ebpf-copy")).unwrap();
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         assert m.read_elf_section({doctored_obj:?}, 'memveil_channel') == b'memveil-channel:copy\\0'; \
         print('split-marker-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("split-marker-ok"), "{text}");

    let shim_c = tmp.join("swap.c");
    let shim_so = tmp.join("swap.so");
    fs::write(&shim_c, SWAP_SHIM_C).unwrap();
    let build = h::run(
        "cc",
        &[
            "-shared",
            "-fPIC",
            "-O2",
            "-o",
            shim_so.to_str().unwrap(),
            shim_c.to_str().unwrap(),
            "-ldl",
        ],
        None,
    );
    assert!(
        build.status.success(),
        "swap shim build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    // AFTER=3 serves V1 to every read-open of --binary (the run
    // performs two: validation hash and staging copy); only the
    // manifest-probe exec sees the on-disk V2.
    let dest = tmp.join("out");
    let count = tmp.join("swap-count.txt");
    let proc = std::process::Command::new("python3")
        .arg(script.to_str().unwrap())
        .args([
            "--root",
            root.to_str().unwrap(),
            "--binary",
            target.to_str().unwrap(),
            "--bpf-dir",
            bpf_dir.to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
        ])
        .env("LD_PRELOAD", shim_so.to_str().unwrap())
        .env("MV_SWAP_TARGET", target.to_str().unwrap())
        .env("MV_SWAP_V1", v1_path.to_str().unwrap())
        .env("MV_SWAP_V2", v2_path.to_str().unwrap())
        .env("MV_SWAP_AFTER", "3")
        .env("MV_SWAP_COUNTFILE", count.to_str().unwrap())
        .output()
        .expect("cannot run package-tarball.py");
    assert!(!proc.status.success(), "split --binary packaged");
    let stderr = String::from_utf8_lossy(&proc.stderr);
    assert!(
        stderr.contains("staged executable dumps a different embedded manifest than validated")
            && stderr.contains("bin/memveil"),
        "{stderr}"
    );
    // Exactly the two production reads of --binary (validation
    // hash, staging copy): the seal binds the pinned digest and
    // the staged re-dump, never a third re-read.
    assert_eq!(
        fs::read_to_string(&count).unwrap().trim(),
        "2",
        "swap shim saw an unexpected read pattern"
    );
    assert!(
        !dest
            .join(format!("memveil-{}", h::engine_version()))
            .exists(),
        "split refusal left a bundle"
    );
    assert!(
        !dest
            .join(format!("memveil-{}.tar.gz", h::engine_version()))
            .exists(),
        "split refusal left a tarball"
    );
}

#[test]
fn staged_binary_mismatch_skips_probe() {
    // Invalid-staged-binary contest: a staged copy replaced
    // between the immediate copy check and the seal walk must
    // refuse on the digest mismatch WITHOUT executing the
    // rejected bytes. The shim serves the validated bytes for
    // the first staged read (the immediate check) and
    // same-behavior/different-digest bytes after (the seal
    // walk), while its constructor marks MV_MARK_FILE iff the
    // staged path is ever exec'd with --embedded-manifest.
    // Pre-fix the seal probed the mismatch (marker present);
    // post-fix the probe is skipped (marker absent) and the
    // refusal names the mismatch, never a probe error.
    if !h::tool_present("cc") {
        eprintln!("skip: cc absent on this host: the swap shim needs it");
        return;
    }
    let root = h::pristine_root();
    let binary = h::ensure_release_binary();
    let tmp = h::scratch("binary-mismatch");
    let script = h::scripts_dir().join("package-tarball.py");

    // V2: pristine bytes plus one trailing byte. Still a valid
    // ELF with identical behavior (proven below) but a
    // different digest, so the seal reads a mismatch while
    // every exec of the on-disk V1 succeeds.
    let v1 = fs::read(&binary).unwrap();
    let mut v2 = v1.clone();
    v2.push(0x00);
    let v1_path = tmp.join("binary-v1");
    let v2_path = tmp.join("binary-v2");
    fs::write(&v1_path, &v1).unwrap();
    fs::write(&v2_path, &v2).unwrap();
    fs::set_permissions(&v2_path, fs::metadata(&binary).unwrap().permissions()).unwrap();
    assert_ne!(
        h::sha256_file(&v1_path),
        h::sha256_file(&v2_path),
        "V2 digest surgery left the bytes identical"
    );
    let pristine_version = h::run(binary.to_str().unwrap(), &["version"], None);
    assert!(pristine_version.status.success());
    let v2_version = h::run(v2_path.to_str().unwrap(), &["version"], None);
    assert!(v2_version.status.success(), "V2 binary fails version");
    assert_eq!(
        v2_version.stdout, pristine_version.stdout,
        "V2 version differs"
    );
    let pristine_dump = h::run(binary.to_str().unwrap(), &["--embedded-manifest"], None);
    assert!(pristine_dump.status.success());
    let v2_dump = h::run(v2_path.to_str().unwrap(), &["--embedded-manifest"], None);
    assert!(
        v2_dump.status.success(),
        "V2 binary fails --embedded-manifest"
    );
    assert_eq!(v2_dump.stdout, pristine_dump.stdout, "V2 manifest differs");

    let dest = tmp.join("out");
    fs::create_dir_all(&dest).unwrap();
    // Swap spelling: absolute without resolving symlinks,
    // exactly as the script's abspath spells the staged path
    // it opens. Marker spelling: canonical, exactly as
    // /proc/self/exe spells the staged path at exec time.
    let mut target = dest.join(".stage").join("bin").join("memveil");
    if !target.is_absolute() {
        target = std::env::current_dir().unwrap().join(&target);
    }
    let staged_exe = dest
        .canonicalize()
        .unwrap()
        .join(".stage")
        .join("bin")
        .join("memveil");
    let mark = tmp.join("probe-marker.txt");
    assert!(!mark.exists(), "scratch marker already exists");

    let shim_c = tmp.join("swap.c");
    let shim_so = tmp.join("swap.so");
    fs::write(&shim_c, SWAP_MARK_SHIM_C).unwrap();
    let build = h::run(
        "cc",
        &[
            "-shared",
            "-fPIC",
            "-O2",
            "-o",
            shim_so.to_str().unwrap(),
            shim_c.to_str().unwrap(),
            "-ldl",
        ],
        None,
    );
    assert!(
        build.status.success(),
        "swap shim build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    // AFTER=1 serves V1 to the immediate copy check and V2 to
    // the seal walk: exactly the invalid-staged state. The
    // on-disk --binary and --bpf-dir stay pristine, so the
    // validation probe and the BPF binding genuinely pass and
    // only the staged-executable seal may refuse this run.
    let count = tmp.join("swap-count.txt");
    let proc = std::process::Command::new("python3")
        .arg(script.to_str().unwrap())
        .args([
            "--root",
            root.to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--bpf-dir",
            h::bpf_out_dir().to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
        ])
        .env("LD_PRELOAD", shim_so.to_str().unwrap())
        .env("MV_SWAP_TARGET", target.to_str().unwrap())
        .env("MV_SWAP_V1", v1_path.to_str().unwrap())
        .env("MV_SWAP_V2", v2_path.to_str().unwrap())
        .env("MV_SWAP_AFTER", "1")
        .env("MV_SWAP_COUNTFILE", count.to_str().unwrap())
        .env("MV_MARK_STAGED", staged_exe.to_str().unwrap())
        .env("MV_MARK_FILE", mark.to_str().unwrap())
        .output()
        .expect("cannot run package-tarball.py");
    assert!(!proc.status.success(), "mismatched staging packaged");
    let stderr = String::from_utf8_lossy(&proc.stderr);
    assert!(
        stderr.contains("staged executable differs from the validated binary")
            && stderr.contains("bin/memveil"),
        "{stderr}"
    );
    assert!(
        stderr.contains("staged tree differs from its sources"),
        "refusal is not the problems-list seal: {stderr}"
    );
    assert!(
        !stderr.contains("--embedded-manifest"),
        "probe error surfaced for an invalid staged binary: {stderr}"
    );
    assert!(!mark.exists(), "seal probed an invalid staged binary");
    // Exactly the two production reads of the staged path
    // (immediate copy check, seal walk): the refusal is the
    // staged-vs-pinned binding firing on the post-check swap,
    // not an unrelated failure.
    assert_eq!(
        fs::read_to_string(&count).unwrap().trim(),
        "2",
        "swap shim saw an unexpected read pattern"
    );
    assert!(
        !dest
            .join(format!("memveil-{}", h::engine_version()))
            .exists(),
        "mismatch refusal left a bundle"
    );
    assert!(
        !dest
            .join(format!("memveil-{}.tar.gz", h::engine_version()))
            .exists(),
        "mismatch refusal left a tarball"
    );
}

#[test]
fn swapped_bpf_inputs_refuse() {
    // Renamed same-build inputs: occurrence alone accepts them
    // (every byte is embedded), so the marker gate must refuse.
    // Both the swapped attempt/copy pair and the
    // attempt-object-supplied-twice pair refuse naming the
    // mistitled channel.
    let root = h::pristine_root();
    let binary = h::ensure_release_binary();
    let out = h::bpf_out_dir();
    let script = h::scripts_dir().join("package-tarball.py");
    for (leaf, sources) in [
        ("swap", ["copy", "lifecycle", "attempt"]),
        ("both", ["attempt", "lifecycle", "attempt"]),
    ] {
        let tmp = h::scratch(&format!("bpf-{leaf}"));
        let renamed = tmp.join("bpf");
        fs::create_dir_all(&renamed).unwrap();
        for (channel, source) in ["attempt", "lifecycle", "copy"].iter().zip(sources.iter()) {
            let bytes = fs::read(out.join(format!("memveil-ebpf-{source}"))).unwrap();
            fs::write(renamed.join(format!("memveil-ebpf-{channel}")), &bytes).unwrap();
        }
        let dest = tmp.join("out");
        let proc = h::run(
            "python3",
            &[
                script.to_str().unwrap(),
                "--root",
                root.to_str().unwrap(),
                "--binary",
                binary.to_str().unwrap(),
                "--bpf-dir",
                renamed.to_str().unwrap(),
                "--out",
                dest.to_str().unwrap(),
            ],
            None,
        );
        assert!(!proc.status.success(), "{leaf} pair packaged");
        let stderr = String::from_utf8_lossy(&proc.stderr);
        assert!(
            stderr.contains("carries channel") && stderr.contains("swapped or mixed"),
            "{leaf}: {stderr}"
        );
        assert!(
            !dest
                .join(format!("memveil-{}", h::engine_version()))
                .exists(),
            "{leaf} refusal left a bundle"
        );
    }
}

#[test]
fn bpf_marker_helpers() {
    // Pure-helper probes against the script module: the real
    // objects read back their exact markers, a name-erased input
    // reads None, and the gate refuses missing and mistitled
    // markers plus non-ELF input.
    let script = h::scripts_dir().join("package-tarball.py");
    let out = h::bpf_out_dir();
    let attempt = out.join("memveil-ebpf-attempt");
    let lifecycle = out.join("memveil-ebpf-lifecycle");
    let copy = out.join("memveil-ebpf-copy");
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         assert m.read_elf_section({attempt:?}, 'memveil_channel') == b'memveil-channel:attempt\\0'; \
         assert m.read_elf_section({lifecycle:?}, 'memveil_channel') == b'memveil-channel:lifecycle\\0'; \
         assert m.read_elf_section({copy:?}, 'memveil_channel') == b'memveil-channel:copy\\0'; \
         print('markers-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("markers-ok"), "{text}");
    let tmp = h::scratch("bpf-marker-surgery");
    let probe = format!(
        "import importlib.util, struct; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         raw = bytearray(open({copy:?}, 'rb').read()); \
         e_shoff, = struct.unpack_from('<Q', raw, 0x28); \
         e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', raw, 0x3a); \
         base = e_shoff + e_shstrndx * e_shentsize; \
         str_off, str_size = struct.unpack_from('<QQ', raw, base + 24); \
         names = bytes(raw[str_off:str_off + str_size]); \
         assert names.count(b'memveil_channel') == 1, 'shstrtab name is not unique'; \
         at = str_off + names.index(b'memveil_channel'); \
         raw[at:at + 15] = b'\\0' * 15; \
         open({tmp:?} + '/noname.o', 'wb').write(raw); \
         assert m.read_elf_section({tmp:?} + '/noname.o', 'memveil_channel') is None; \
         print('noname-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("noname-ok"), "{text}");
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         m.check_bpf_markers({{'swiotlb_copy.bpf.o': ({tmp:?} + '/noname.o', 'x')}})"
    );
    let proc = h::run("python3", &["-B", "-c", &probe], None);
    assert!(!proc.status.success(), "missing marker passed");
    assert!(
        String::from_utf8_lossy(&proc.stderr).contains("lacks the memveil_channel section"),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         raw = bytearray(open({copy:?}, 'rb').read()); \
         raw = raw.replace(b'memveil-channel:copy', b'memveil-channel:copy'.replace(b'copy', b'VOID')); \
         open({tmp:?} + '/mistitled.o', 'wb').write(raw); \
         m.check_bpf_markers({{'swiotlb_copy.bpf.o': ({tmp:?} + '/mistitled.o', 'x')}})"
    );
    let proc = h::run("python3", &["-B", "-c", &probe], None);
    assert!(!proc.status.success(), "mistitled marker passed");
    assert!(
        String::from_utf8_lossy(&proc.stderr).contains("carries channel"),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         open({tmp:?} + '/garbage.o', 'wb').write(b'not an elf'); \
         m.read_elf_section({tmp:?} + '/garbage.o', 'memveil_channel')"
    );
    let proc = h::run("python3", &["-B", "-c", &probe], None);
    assert!(!proc.status.success(), "non-ELF input parsed");
    assert!(
        String::from_utf8_lossy(&proc.stderr).contains("not an ELF file"),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
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
    for token in [
        "aya",
        "libgcc_s.so.1",
        "GCC-exception",
        "Cargo.lock",
        "libgcc-s1",
        "14.2.0-19",
        "PROVENANCE.txt",
    ] {
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

#[test]
fn runtime_provenance_pinned() {
    // Port of the release-runtime provenance binding minus the
    // pixi archive fields (no lock packages, versions, or
    // relocations survive): provenance keys equal the staged
    // lib set, staged bytes bind both the record and files[],
    // and the normalization entry bridges member to staged.
    let set = h::ensure_tarball();
    let manifest = set.bundle.join("MANIFEST.json");
    let staged: BTreeSet<String> = fs::read_dir(set.bundle.join("lib").join("memveil"))
        .expect("lib dir")
        .flatten()
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .filter(|n| n.contains(".so"))
        .map(|n| format!("lib/memveil/{n}"))
        .collect();
    assert!(!staged.is_empty(), "no staged shared libraries");
    let mut want: Vec<&String> = staged.iter().collect();
    want.sort();
    let expected = format!(
        "[{}]",
        want.iter()
            .map(|k| format!("{k:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert_eq!(
        h::json_probe(&manifest, "sorted(d['runtime_provenance'])"),
        expected
    );
    let probe = format!(
        "import json; d = json.load(open({manifest:?}));\n\
         [print('|'.join([rel, d['runtime_provenance'][rel]['staged_sha256'], \
         d['runtime_provenance'][rel]['member_sha256'], \
         d['runtime_provenance'][rel]['pre_normalization_sha256'], \
         d['normalization'][rel]['source_sha256'], \
         d['normalization'][rel]['output_sha256'], d['files'][rel]])) \
         for rel in sorted(d['runtime_provenance'])]"
    );
    let text = h::run_ok("python3", &["-c", &probe], None);
    assert!(!text.trim().is_empty(), "provenance probe is empty");
    for line in text.lines() {
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(fields.len(), 7, "{line}");
        let (rel, staged_sha, member, pre, norm_src, norm_out, files_sha) = (
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
        );
        let digest = h::sha256_file(&set.bundle.join(rel));
        assert_eq!(staged_sha, digest, "{rel}: staged != file bytes");
        assert_eq!(files_sha, digest, "{rel}: files[] != file bytes");
        assert_eq!(norm_src, member, "{rel}: normalization source != member");
        assert_eq!(norm_out, digest, "{rel}: normalization output != staged");
        assert_eq!(pre, member, "{rel}: pre-normalization != member");
    }
}

#[test]
fn vendored_libgcc_provenance() {
    // The shipped lib is the pinned Debian provider: the manifest
    // record names it, the .deb pin equals the vendored bytes in
    // the pristine tree, and the member pin equals the
    // pre-normalization bytes (the staged lib is stripped, so it
    // binds through the normalization bridge instead).
    let set = h::ensure_tarball();
    let manifest = set.bundle.join("MANIFEST.json");
    let rel = "lib/memveil/libgcc_s.so.1";
    let field = |key: &str| {
        h::json_probe(
            &manifest,
            &format!("d['runtime_provenance'][{rel:?}][{key:?}]"),
        )
    };
    assert_eq!(field("provider"), "debian-stable-libgcc-s1");
    assert_eq!(field("provider_version"), "14.2.0-19");
    assert_eq!(field("member"), "usr/lib/x86_64-linux-gnu/libgcc_s.so.1");
    assert_eq!(
        field("source_path"),
        "packaging/libgcc/libgcc-s1_14.2.0-19_amd64.deb"
    );
    let deb = h::pristine_root()
        .join("packaging")
        .join("libgcc")
        .join("libgcc-s1_14.2.0-19_amd64.deb");
    assert!(deb.is_file(), "pristine tree lacks the vendored .deb");
    assert_eq!(field("deb_sha256"), h::sha256_file(&deb));
    assert_eq!(
        field("deb_sha256"),
        "3c71917b490d1a17aed43196a2787a256ecf060526cdb20216a74bedc061b150"
    );
    assert_eq!(
        field("member_sha256"),
        "30c61ab012a4241bed033725a09b61f5fdd3bb7df95ee852d0b096520524c7af"
    );
    assert_eq!(
        field("member_sha256"),
        h::json_probe(
            &manifest,
            &format!("d['normalization'][{rel:?}]['source_sha256']")
        ),
        "member pin != normalization source"
    );
}

#[test]
fn staged_gpl3_is_vendored() {
    // The GPL-3 text pairs with the vendored Debian binary and is
    // identical on every build host: staged bytes must equal the
    // vendored bytes in the pristine tree.
    let set = h::ensure_tarball();
    let vendored = h::pristine_root()
        .join("packaging")
        .join("libgcc")
        .join("GPL-3.txt");
    assert!(vendored.is_file(), "pristine tree lacks GPL-3.txt");
    assert_eq!(
        fs::read(set.bundle.join("licenses").join("GPL-3.0.txt")).unwrap(),
        fs::read(&vendored).unwrap(),
        "staged GPL-3 != vendored GPL-3"
    );
}

#[test]
fn vendored_libgcc_helpers() {
    // Pure-helper probes against the script module (no packaging
    // run): extraction returns the pinned member bytes, a doctored
    // .deb refuses on the pin, and the unwinder gate passes the
    // real pair while refusing an unsatisfiable one.
    let script = h::scripts_dir().join("package-tarball.py");
    let deb = h::pristine_root()
        .join("packaging")
        .join("libgcc")
        .join("libgcc-s1_14.2.0-19_amd64.deb");
    let probe = format!(
        "import hashlib, importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         raw = m.extract_deb_file({deb:?}, m.LIBGCC_SO_MEMBER); \
         assert len(raw) == 182856, len(raw); \
         assert hashlib.sha256(raw).hexdigest() == m.LIBGCC_SO_SHA256; \
         assert m.sha256_file({deb:?}) == m.LIBGCC_DEB_SHA256; \
         print('extract-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("extract-ok"), "{text}");
    let tmp = h::scratch("libgcc-doctor");
    let mut bytes = fs::read(&deb).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    // A doctored .deb under a scratch root refuses on the pin
    // (vendored_libgcc resolves the .deb under the given root).
    let root = tmp.join("root");
    let staged_deb = root
        .join("packaging")
        .join("libgcc")
        .join("libgcc-s1_14.2.0-19_amd64.deb");
    fs::create_dir_all(staged_deb.parent().unwrap()).unwrap();
    fs::write(&staged_deb, &bytes).unwrap();
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         m.vendored_libgcc({root:?}, {tmp:?})"
    );
    let out = h::run("python3", &["-B", "-c", &probe], None);
    assert!(!out.status.success(), "doctored .deb verified");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("differs from its pin"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let set = h::ensure_tarball();
    let binary = set.bundle.join("bin").join("memveil");
    let lib = set.bundle.join("lib").join("memveil").join("libgcc_s.so.1");
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         m.check_libgcc_unwinder({binary:?}, {lib:?}); print('unwind-ok')"
    );
    let text = h::run_ok("python3", &["-B", "-c", &probe], None);
    assert!(text.contains("unwind-ok"), "{text}");
    let probe = format!(
        "import importlib.util; \
         l = importlib.util.spec_from_file_location('m', {script:?}); \
         m = importlib.util.module_from_spec(l); l.loader.exec_module(m); \
         m.check_libgcc_unwinder({binary:?}, {binary:?})"
    );
    let out = h::run("python3", &["-B", "-c", &probe], None);
    assert!(!out.status.success(), "unsatisfiable pair passed");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("shipped libgcc lacks 12 symbol(s)"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn runtime_licenses_match() {
    // Port of the release-runtime license binding: the two
    // staged GCC texts bind record sha256 to file bytes to
    // files[] (no compiler-vendor texts survive). The crates/
    // subtree holds the per-crate texts (bound by
    // crate_texts_match_locked_sources, not here).
    let set = h::ensure_tarball();
    let manifest = set.bundle.join("MANIFEST.json");
    let mut staged = BTreeSet::new();
    let mut dirs = BTreeSet::new();
    for entry in fs::read_dir(set.bundle.join("licenses"))
        .expect("licenses dir")
        .flatten()
    {
        let name = entry.file_name().to_str().unwrap().to_string();
        if entry.path().is_dir() {
            dirs.insert(format!("licenses/{name}"));
        } else {
            staged.insert(format!("licenses/{name}"));
        }
    }
    assert_eq!(
        dirs,
        BTreeSet::from(["licenses/crates".to_string()]),
        "{dirs:?}"
    );
    assert_eq!(staged.len(), 2, "{staged:?}");
    let mut want: Vec<&String> = staged.iter().collect();
    want.sort();
    let expected = format!(
        "[{}]",
        want.iter()
            .map(|k| format!("{k:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert_eq!(
        h::json_probe(&manifest, "sorted(d['runtime_licenses'])"),
        expected
    );
    let probe = format!(
        "import json; d = json.load(open({manifest:?}));\n\
         [print('%s|%s|%s' % (rel, d['runtime_licenses'][rel]['sha256'], \
         d['files'][rel])) for rel in sorted(d['runtime_licenses'])]"
    );
    let text = h::run_ok("python3", &["-c", &probe], None);
    assert!(!text.trim().is_empty(), "license probe is empty");
    for line in text.lines() {
        let (rel, rest) = line.split_once('|').expect("rel|sha|sha");
        let (record, files_sha) = rest.split_once('|').expect("sha|sha");
        let digest = h::sha256_file(&set.bundle.join(rel));
        assert_eq!(record, digest, "{rel}: record != file bytes");
        assert_eq!(files_sha, digest, "{rel}: files[] != file bytes");
    }
}

/// One manifest crate record: (`R`ust closure vs `E`bpf closure).
struct CrateRecord {
    side: char,
    name: String,
    version: String,
    fallback: bool,
    texts: Vec<String>,
}

/// Manifest `cargo.crates` + `cargo.ebpf_crates` records.
fn manifest_crate_records(manifest: &Path) -> Vec<CrateRecord> {
    let probe = format!(
        "import json; d = json.load(open({manifest:?}));\n\
         [print('R|%s|%s|%s|%s' % (c['name'], c['version'], c.get('fallback'), ','.join(c['texts']))) for c in d['cargo']['crates']]\n\
         [print('E|%s|%s|%s|%s' % (c['name'], c['version'], c.get('fallback'), ','.join(c['texts']))) for c in d['cargo']['ebpf_crates']]"
    );
    let mut records = Vec::new();
    for line in h::run_ok("python3", &["-c", &probe], None).lines() {
        let mut parts = line.splitn(5, '|');
        records.push(CrateRecord {
            side: parts.next().unwrap().chars().next().unwrap(),
            name: parts.next().unwrap().to_string(),
            version: parts.next().unwrap().to_string(),
            fallback: parts.next().unwrap() == "True",
            texts: parts
                .next()
                .unwrap()
                .split(',')
                .map(str::to_string)
                .collect(),
        });
    }
    records
}

/// Locked crate source dirs: (name, version) -> manifest dir, via an
/// independent offline cargo metadata query over the pristine input.
fn metadata_roots(manifest_path: &Path) -> BTreeMap<(String, String), PathBuf> {
    let out = h::run_unpinned(
        "cargo",
        &[
            "metadata",
            "--offline",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
            manifest_path.to_str().unwrap(),
        ],
        Some(&h::rust_dir()),
    );
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tmp = h::scratch("crate-roots");
    let dump = tmp.join("metadata.json");
    fs::write(&dump, &out.stdout).unwrap();
    let probe = format!(
        "import json, os; d = json.load(open({dump:?}));\n\
         [print('%s|%s|%s' % (p['name'], p['version'], os.path.dirname(p['manifest_path']))) for p in d['packages']]"
    );
    let mut roots = BTreeMap::new();
    for line in h::run_ok("python3", &["-c", &probe], None).lines() {
        let mut parts = line.splitn(3, '|');
        roots.insert(
            (
                parts.next().unwrap().to_string(),
                parts.next().unwrap().to_string(),
            ),
            PathBuf::from(parts.next().unwrap()),
        );
    }
    roots
}

#[test]
fn crate_texts_match_locked_sources() {
    // Every linked crate stages its notice files from the LOCKED
    // sources: each manifest record carries non-empty texts, each
    // text exists, is non-empty, hashes into files[], and equals
    // the locked crate source bytes; staged versions equal the
    // Cargo.lock pins, never latest.
    let set = h::ensure_tarball();
    let manifest = set.bundle.join("MANIFEST.json");
    let records = manifest_crate_records(&manifest);
    assert!(
        records.iter().any(|r| r.side == 'R'),
        "no main-closure records"
    );
    assert!(
        records.iter().any(|r| r.side == 'E'),
        "no ebpf-closure records"
    );
    let root = h::pristine_root();
    let main_lock: BTreeSet<(String, String)> = h::cargo_lock_packages(&root.join("Cargo.lock"))
        .into_iter()
        .map(|(name, version, _, _)| (name, version))
        .collect();
    let ebpf_lock: BTreeSet<(String, String)> =
        h::cargo_lock_packages(&root.join("crates").join("ebpf").join("Cargo.lock"))
            .into_iter()
            .map(|(name, version, _, _)| (name, version))
            .collect();
    let main_roots = metadata_roots(&root.join("Cargo.toml"));
    let ebpf_roots = metadata_roots(&root.join("crates").join("ebpf").join("Cargo.toml"));
    let mut leaves = BTreeSet::new();
    for record in &records {
        assert!(
            !record.texts.is_empty(),
            "{} {} stages no texts",
            record.name,
            record.version
        );
        let lock = if record.side == 'R' {
            &main_lock
        } else {
            &ebpf_lock
        };
        assert!(
            lock.contains(&(record.name.clone(), record.version.clone())),
            "{} {} is not in the {} lock",
            record.name,
            record.version,
            if record.side == 'R' { "main" } else { "ebpf" }
        );
        leaves.insert(format!("{}-{}", record.name, record.version));
        for text in &record.texts {
            assert!(text.starts_with("licenses/crates/"), "{text}");
            let staged = set.bundle.join(text);
            let bytes = fs::read(&staged).unwrap_or_else(|_| panic!("{text} missing"));
            assert!(!bytes.is_empty(), "{text} is empty");
            assert_eq!(
                h::sha256_file(&staged),
                h::json_probe(&manifest, &format!("d['files'][{text:?}]")),
                "{text}: files[] != staged bytes"
            );
            if !record.fallback {
                let roots = if record.side == 'R' {
                    &main_roots
                } else {
                    &ebpf_roots
                };
                let dir = roots
                    .get(&(record.name.clone(), record.version.clone()))
                    .unwrap_or_else(|| {
                        panic!("{} {} lacks locked sources", record.name, record.version)
                    });
                let base = text.rsplit('/').next().unwrap();
                let source = dir.join(base);
                assert_eq!(
                    fs::read(&source).unwrap_or_else(|_| panic!("{source:?} unreadable")),
                    bytes,
                    "{text} != locked source bytes"
                );
            }
        }
    }
    // No extra or missing per-crate dirs.
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(set.bundle.join("licenses").join("crates"))
        .expect("crates dir")
        .flatten()
    {
        assert!(
            entry.path().is_dir(),
            "{} is not a dir",
            entry.path().display()
        );
        actual.insert(entry.file_name().to_str().unwrap().to_string());
    }
    assert_eq!(actual, leaves);
}

/// sha256 of the shared Apache-2.0 grant staged for text-less crates.
/// Re-verify deliberately (it must stay a faithful Apache-2.0 grant)
/// before updating this pin.
const SHARED_GRANT_SHA: &str = "62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a";

#[test]
fn shared_grant_text_pinned() {
    // Exactly the three text-less aya crates take the shared-grant
    // fallback; every other record stages its own locked texts.
    let set = h::ensure_tarball();
    let manifest = set.bundle.join("MANIFEST.json");
    let records = manifest_crate_records(&manifest);
    let fallback: BTreeSet<(String, String)> = records
        .iter()
        .filter(|r| r.fallback)
        .map(|r| (r.name.clone(), r.version.clone()))
        .collect();
    assert_eq!(
        fallback,
        BTreeSet::from([
            ("aya-ebpf".to_string(), "0.2.1".to_string()),
            ("aya-ebpf-bindings".to_string(), "0.2.0".to_string()),
            ("aya-ebpf-macros".to_string(), "0.2.0".to_string()),
        ]),
        "{fallback:?}"
    );
    for (name, version) in &fallback {
        let dir = set
            .bundle
            .join("licenses")
            .join("crates")
            .join(format!("{name}-{version}"));
        let entries: Vec<_> = fs::read_dir(&dir)
            .expect("fallback dir")
            .flatten()
            .collect();
        assert_eq!(entries.len(), 1, "{dir:?} holds more than the grant");
        let file = dir.join("LICENSE-APACHE");
        assert_eq!(
            h::sha256_file(&file),
            SHARED_GRANT_SHA,
            "{name} grant drift"
        );
        let text = fs::read_to_string(&file).unwrap();
        assert!(
            text.contains("Apache License") && text.contains("Version 2.0"),
            "{name} grant is not the Apache-2.0 text"
        );
    }
}

#[test]
fn vendored_exception_matches_host() {
    // The FSF exception grant is immutable: wherever the Fedora
    // host text exists, the vendored fallback must be byte-identical
    // to it (Debian builds stage the vendored copy, Fedora builds
    // the host copy — the pin keeps them one text).
    let host = std::path::Path::new("/usr/share/licenses/libgcc/COPYING.RUNTIME");
    if !host.is_file() {
        eprintln!("skip: no Fedora host exception text here: this host stages the vendored copy");
        return;
    }
    let set = h::ensure_tarball();
    let vendored = h::packaging_dir().join("RUNTIME.LIBRARY.EXCEPTION");
    assert!(
        vendored.is_file(),
        "missing packaging/RUNTIME.LIBRARY.EXCEPTION"
    );
    let staged = fs::read(set.bundle.join("licenses/RUNTIME.LIBRARY.EXCEPTION")).unwrap();
    assert_eq!(
        staged,
        fs::read(host).unwrap(),
        "staged != Fedora host text"
    );
    assert_eq!(
        staged,
        fs::read(&vendored).unwrap(),
        "staged != vendored text"
    );
}

#[test]
fn rebuild_is_deterministic() {
    // Two builds from the pinned clone must agree on every
    // files[] hash, on the MANIFEST bytes, and on the tarball
    // bytes themselves.
    let root = h::pristine_root();
    let binary = h::ensure_release_binary();
    let bpf = h::bpf_out_dir();
    let script = h::scripts_dir().join("package-tarball.py");
    let tmp = h::scratch("rebuild-det");
    let version = h::engine_version();
    let mut listings = Vec::new();
    let mut manifests = Vec::new();
    let mut shas = Vec::new();
    for leaf in ["first", "second"] {
        let out = tmp.join(leaf);
        let args = [
            script.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--bpf-dir",
            bpf.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ];
        let proc = h::run("python3", &args, None);
        assert!(
            proc.status.success(),
            "rebuild {leaf}: {}",
            String::from_utf8_lossy(&proc.stderr)
        );
        let bundle = out.join(format!("memveil-{version}"));
        let manifest = bundle.join("MANIFEST.json");
        let tarball = out.join(format!("memveil-{version}.tar.gz"));
        assert!(manifest.is_file(), "rebuild {leaf} lacks a manifest");
        assert!(tarball.is_file(), "rebuild {leaf} lacks a tarball");
        let probe = format!(
            "import json; d = json.load(open({manifest:?})); \
             [print('%s|%s' % (k, v)) for k, v in sorted(d['files'].items())]"
        );
        listings.push(h::run_ok("python3", &["-c", &probe], None));
        manifests.push(fs::read(&manifest).expect("read manifest"));
        shas.push(h::sha256_file(&tarball));
    }
    assert!(!listings[0].is_empty(), "files[] listing is empty");
    assert_eq!(listings[0], listings[1], "files[] differ across rebuilds");
    assert_eq!(
        manifests[0], manifests[1],
        "MANIFEST differs across rebuilds"
    );
    assert_eq!(shas[0], shas[1], "tarball bytes differ across rebuilds");
}
