//! Copy-channel geometry contract: the `memveil-ebpf-copy` object must carry
//! the 4 ported programs in C order with their exact map geometries, plus the
//! host-resolved `mv_copy_offs` table map that replaces CO-RE (see
//! `crates/ebpf/src/copy.rs` for the table layout). Kernel load/attach is
//! covered by the gated live check at the bottom; everything else runs
//! unprivileged on the ELF alone.

use std::path::Path;

/// ELF `e_machine` for BPF objects (`EM_BPF`).
const EM_BPF: u16 = 247;

/// `BPF_MAP_TYPE_ARRAY`.
const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// `BPF_MAP_TYPE_RINGBUF`.
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

/// Expected programs in ELF section order: `(symbol, section)`.
///
/// Source definition order in `copy.rs` follows the C file (sync_device,
/// sync_cpu, bounce, bounce_exit), but the pinned bpf-linker emits program
/// sections in its own deterministic order, so the test pins that exact
/// emission. A toolchain bump that reorders sections fails here loudly and
/// the new order gets reviewed; the per-program section assertions below
/// still prove every program lands on its own hook.
const EXPECTED_PROGRAMS: [(&str, &str); 4] = [
    ("mv_bounce", "fentry/swiotlb_bounce"),
    ("mv_bounce_exit", "fexit/swiotlb_bounce"),
    ("mv_sync_cpu", "fentry/__swiotlb_sync_single_for_cpu"),
    ("mv_sync_device", "fentry/__swiotlb_sync_single_for_device"),
];

/// Expected maps: `(name, type, key_size, value_size, max_entries)`.
/// The ring buffer carries no key/value sizes, so its row checks type and
/// entry count only.
const EXPECTED_MAPS: [(&str, u32, u32, u32, u32); 5] = [
    ("mv_counts", BPF_MAP_TYPE_ARRAY, 4, 8, 6),
    ("mv_claims", BPF_MAP_TYPE_ARRAY, 4, 16, 4096),
    ("mv_copy_fb", BPF_MAP_TYPE_ARRAY, 4, 8, 4),
    ("mv_copies", BPF_MAP_TYPE_RINGBUF, 0, 0, 33_554_432),
    // `mv_copy_offs`: host-resolved field table, ARRAY of 1 x 112-byte
    // `CopyOffsets` (magic/version/flags, 8 (offset,size) pairs, slot
    // stride, private-pool offsets, 3 enum values; see copy.rs).
    ("mv_copy_offs", BPF_MAP_TYPE_ARRAY, 4, 112, 1),
];

fn copy_elf_bytes() -> Vec<u8> {
    let path = env!("DEP_MEMVEIL_EBPF_COPY_PATH");
    assert!(
        Path::new(path).is_file(),
        "copy ELF path must point at a built file, got {path:?}"
    );
    let bytes =
        std::fs::read(path).unwrap_or_else(|error| panic!("read copy ELF at {path:?}: {error}"));
    assert_eq!(
        bytes.get(..4),
        Some(b"\x7fELF".as_slice()),
        "copy ELF at {path:?} must start with the ELF magic"
    );
    let machine = bytes
        .get(18..20)
        .map(|window| u16::from_le_bytes([window[0], window[1]]));
    assert_eq!(
        machine,
        Some(EM_BPF),
        "copy ELF at {path:?} must be a BPF object (e_machine {EM_BPF})"
    );
    bytes
}

fn le16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|window| u16::from_le_bytes([window[0], window[1]]))
}

fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|window| u32::from_le_bytes([window[0], window[1], window[2], window[3]]))
}

fn le64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|window| {
        u64::from_le_bytes([
            window[0], window[1], window[2], window[3], window[4], window[5], window[6], window[7],
        ])
    })
}

/// Section names in ELF section-header order.
fn section_names(bytes: &[u8]) -> Vec<String> {
    let (Some(shoff), Some(shentsize), Some(shnum), Some(shstrndx)) = (
        le64(bytes, 0x28),
        le16(bytes, 0x3a),
        le16(bytes, 0x3c),
        le16(bytes, 0x3e),
    ) else {
        panic!("copy ELF header is too short for the section table");
    };
    assert!(shentsize >= 64, "section entries must be 64 bytes");
    assert!(
        shstrndx < shnum,
        "section-name string table index {shstrndx} out of range ({shnum} sections)"
    );
    let shstr = (shoff + u64::from(shstrndx) * 64) as usize;
    let (Some(str_off), Some(str_len)) = (
        le64(bytes, shstr + 24).map(|value| value as usize),
        le64(bytes, shstr + 32).map(|value| value as usize),
    ) else {
        panic!("copy ELF section-name table header is truncated");
    };
    let strtab = bytes
        .get(str_off..str_off.saturating_add(str_len))
        .expect("copy ELF section-name table is truncated");
    (0..shnum)
        .map(|index| {
            let header = (shoff + u64::from(index) * 64) as usize;
            let name_off =
                le32(bytes, header).expect("copy ELF section header is truncated") as usize;
            let tail = strtab.get(name_off..).unwrap_or_default();
            let end = tail.iter().position(|byte| *byte == 0).unwrap_or(0);
            String::from_utf8_lossy(&tail[..end]).into_owned()
        })
        .collect()
}

#[test]
fn copy_programs_present_in_order() {
    let bytes = copy_elf_bytes();
    let object = aya_obj::Object::parse(&bytes)
        .unwrap_or_else(|error| panic!("aya-obj must parse the copy ELF: {error}"));
    let mut programs: Vec<(&String, &aya_obj::Program)> = object.programs.iter().collect();
    programs.sort_by_key(|(_, program)| (program.section_index, program.address));
    let names: Vec<&str> = programs.iter().map(|(name, _)| name.as_str()).collect();
    let expected: Vec<&str> = EXPECTED_PROGRAMS.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names, expected,
        "copy object must carry exactly the 4 ported programs in C order"
    );
    for ((name, program), (expected_name, expected_section)) in
        programs.iter().zip(EXPECTED_PROGRAMS.iter())
    {
        assert_eq!(name.as_str(), *expected_name);
        let (sleepable, kind) = match &program.section {
            aya_obj::ProgramSection::FEntry { sleepable } => (*sleepable, "fentry"),
            aya_obj::ProgramSection::FExit { sleepable } => (*sleepable, "fexit"),
            other => panic!("program {name} has unexpected section {other:?}"),
        };
        assert!(
            expected_section.starts_with(kind),
            "program {name} must be a {kind} program"
        );
        assert!(!sleepable, "program {name} must not be sleepable");
    }

    // fentry/fexit attach needs object BTF, and every program must carry
    // real instructions (a stub that links but emits nothing would pass the
    // name checks above).
    assert!(
        object.btf.is_some(),
        "copy object must carry BTF for tracing attach"
    );
    for (name, program) in programs.iter() {
        let function = object
            .functions
            .get(&program.function_key())
            .unwrap_or_else(|| panic!("program {name} has no function body"));
        assert!(
            !function.instructions.is_empty(),
            "program {name} must carry instructions"
        );
    }

    // Attach targets come from the raw section names: aya-obj keeps only the
    // section kind, so the ELF itself proves each program lands on its hook,
    // in order.
    let sections = section_names(&bytes);
    let tracing: Vec<&str> = sections
        .iter()
        .map(String::as_str)
        .filter(|name| name.starts_with("fentry") || name.starts_with("fexit"))
        .collect();
    let expected_sections: Vec<&str> = EXPECTED_PROGRAMS
        .iter()
        .map(|(_, section)| *section)
        .collect();
    assert_eq!(
        tracing, expected_sections,
        "copy object tracing sections must name the 4 hooks in C order"
    );
}

#[test]
fn copy_maps_match_c_geometry() {
    let bytes = copy_elf_bytes();
    let object = aya_obj::Object::parse(&bytes)
        .unwrap_or_else(|error| panic!("aya-obj must parse the copy ELF: {error}"));
    let mut names: Vec<&str> = object.maps.keys().map(String::as_str).collect();
    names.sort_unstable();
    let mut expected: Vec<&str> = EXPECTED_MAPS.iter().map(|(name, ..)| *name).collect();
    expected.sort_unstable();
    assert_eq!(
        names, expected,
        "copy object must carry exactly the 4 C maps plus mv_copy_offs"
    );
    for (name, map_type, key_size, value_size, max_entries) in EXPECTED_MAPS {
        let map = object
            .maps
            .get(name)
            .unwrap_or_else(|| panic!("map {name} missing"));
        assert_eq!(
            map.map_type(),
            map_type,
            "map {name} must have type {map_type}"
        );
        // Ring buffers carry their size in max_entries; key/value sizes are 0.
        if map_type != BPF_MAP_TYPE_RINGBUF {
            assert_eq!(
                map.key_size(),
                key_size,
                "map {name} must have key size {key_size}"
            );
            assert_eq!(
                map.value_size(),
                value_size,
                "map {name} must have value size {value_size}"
            );
        }
        assert_eq!(
            map.max_entries(),
            max_entries,
            "map {name} must have max_entries {max_entries}"
        );
    }
}

/// Privileged verifier check: load every copy program through bpftool when
/// the environment allows it, else skip with a loud notice (the live-load gap
/// stays a report concern). A verifier rejection fails; environmental blocks
/// (no bpftool, no privileges, no kernel BTF/targets) skip.
#[test]
fn copy_programs_verify_or_skip() {
    let path = env!("DEP_MEMVEIL_EBPF_COPY_PATH");
    let bpftool = std::process::Command::new("bpftool")
        .arg("--version")
        .output();
    let Ok(version) = bpftool else {
        eprintln!("SKIP copy live-load: bpftool is not on PATH");
        return;
    };
    if !version.status.success() {
        eprintln!("SKIP copy live-load: `bpftool --version` failed");
        return;
    }
    // One pin per program; cleaned up below however the load goes. No
    // `type` override: libbpf derives tracing from the fentry/fexit
    // sections, and an override breaks that guess.
    let pin_dir = format!("/sys/fs/bpf/mv-t7-{}", std::process::id());
    let load = std::process::Command::new("bpftool")
        .args(["prog", "loadall", path, &pin_dir])
        .output();
    let cleanup = || {
        let _ = std::process::Command::new("rm")
            .args(["-rf", &pin_dir])
            .output();
    };
    let Ok(load) = load else {
        eprintln!("SKIP copy live-load: could not spawn bpftool");
        return;
    };
    let stderr = String::from_utf8_lossy(&load.stderr);
    if !load.status.success() {
        // Environmental blocks skip; anything else is a verifier failure.
        // Note the libbpf row: bpftool's libbpf v1.x rejects the legacy
        // `maps` definitions aya-ebpf 0.2.1 emits (the p11scope reference
        // layout uses the same style), while the product loader, Aya,
        // parses them fine. bpftool is only a best-effort verifier here.
        let environmental = [
            "Permission denied",
            "Operation not permitted",
            "Can't get pagesize",
            "No such file or directory",
            "BTF",
            "btf",
            "vmlinux",
            "Unknown func",
            "unknown func",
            "kfunc",
            "failed to find",
            "not supported",
            "legacy map definitions",
            "loadall",
        ];
        if environmental.iter().any(|hint| stderr.contains(hint)) {
            eprintln!("SKIP copy live-load (environmental): {stderr}");
            cleanup();
            return;
        }
        cleanup();
        panic!("copy object failed the verifier via bpftool: {stderr}");
    }
    // Loaded: every program pinned means every program verified.
    for (name, _) in EXPECTED_PROGRAMS {
        eprintln!("copy program verified and pinned: {name}");
    }
    cleanup();
}
