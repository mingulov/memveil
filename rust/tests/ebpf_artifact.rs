//! Build-artifact contract: `cargo build` compiles each `crates/ebpf` channel
//! bin for the BPF target and `build.rs` publishes the three ELF paths as
//! `DEP_MEMVEIL_EBPF_{ATTEMPT,LIFECYCLE,COPY}_PATH`. These tests prove every
//! path exists, points at a BPF object carrying the GPL license section, and
//! parses. They never load anything into the kernel, so they run unprivileged.
//!
//! The program-count assertion is deliberately relaxed (0+ programs): the
//! channel stubs are still empty and each probe task owns its own exact
//! program+map geometry test (see the TODO on each test below). This file
//! only guards the per-channel artifact plumbing.

use std::path::Path;

/// ELF `e_machine` for BPF objects (`EM_BPF`).
const EM_BPF: u16 = 247;

/// Read a little-endian u16 out of `bytes` at `offset`.
fn le16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|window| u16::from_le_bytes([window[0], window[1]]))
}

/// Read a little-endian u32 out of `bytes` at `offset`.
fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|window| u32::from_le_bytes([window[0], window[1], window[2], window[3]]))
}

/// Read a little-endian u64 out of `bytes` at `offset`.
fn le64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|window| {
        u64::from_le_bytes([
            window[0], window[1], window[2], window[3], window[4], window[5], window[6], window[7],
        ])
    })
}

/// True when the ELF section-header table names a `license` section.
fn has_license_section(bytes: &[u8]) -> bool {
    // ELF64 header: e_shoff@0x28, e_shentsize@0x3A, e_shnum@0x3C,
    // e_shstrndx@0x3E. Section header: sh_name@+0, sh_offset@+24,
    // sh_size@+32, each entry 64 bytes.
    let (Some(shoff), Some(shentsize), Some(shnum), Some(shstrndx)) = (
        le64(bytes, 0x28),
        le16(bytes, 0x3a),
        le16(bytes, 0x3c),
        le16(bytes, 0x3e),
    ) else {
        return false;
    };
    if shentsize < 64 || shstrndx >= shnum {
        return false;
    }
    let shstr = (shoff + u64::from(shstrndx) * 64) as usize;
    let (Some(str_off), Some(str_len)) = (
        le64(bytes, shstr + 24).map(|value| value as usize),
        le64(bytes, shstr + 32).map(|value| value as usize),
    ) else {
        return false;
    };
    let Some(strtab) = bytes.get(str_off..str_off.saturating_add(str_len)) else {
        return false;
    };
    (0..shnum).any(|index| {
        let header = (shoff + u64::from(index) * 64) as usize;
        let Some(name_off) = le32(bytes, header).map(|value| value as usize) else {
            return false;
        };
        let name = strtab.get(name_off..).and_then(|tail| {
            tail.iter()
                .position(|byte| *byte == 0)
                .map(|end| &tail[..end])
        });
        name == Some(b"license".as_slice())
    })
}

fn check_channel_elf(channel: &str, path: &str) {
    assert!(
        Path::new(path).is_file(),
        "{channel} ELF path must point at a built file, got {path:?}"
    );
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("read {channel} ELF at {path:?}: {error}"));
    assert!(
        !bytes.is_empty(),
        "{channel} ELF at {path:?} must not be empty"
    );
    assert_eq!(
        bytes.get(..4),
        Some(b"\x7fELF".as_slice()),
        "{channel} ELF at {path:?} must start with the ELF magic"
    );
    let machine = bytes
        .get(18..20)
        .map(|window| u16::from_le_bytes([window[0], window[1]]));
    assert_eq!(
        machine,
        Some(EM_BPF),
        "{channel} ELF at {path:?} must be a BPF object (e_machine {EM_BPF})"
    );
    assert!(
        has_license_section(&bytes),
        "{channel} ELF at {path:?} must carry the GPL license section"
    );
    // 0+ programs is accepted here: the empty stubs build license-only ELFs
    // until the probe tasks land (see the TODO on each test). Parsing must
    // still succeed so a corrupt object cannot slip through.
    let _object = aya_obj::Object::parse(&bytes).unwrap_or_else(|error| {
        panic!("aya-obj must parse the {channel} ELF at {path:?}: {error}")
    });
}

// TODO(T5): the attempt probe task tightens this channel to its exact
// program+map geometry in its own test; this file keeps only the
// ELF-exists/magic/EM_BPF/parses/license plumbing assertion.
#[test]
fn attempt_elf_exists_and_parses() {
    check_channel_elf("attempt", env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH"));
}

// TODO(T6): the lifecycle probe task tightens this channel to its exact
// program+map geometry in its own test; this file keeps only the
// ELF-exists/magic/EM_BPF/parses/license plumbing assertion.
#[test]
fn lifecycle_elf_exists_and_parses() {
    check_channel_elf("lifecycle", env!("DEP_MEMVEIL_EBPF_LIFECYCLE_PATH"));
}

// TODO(T7): the copy probe task tightens this channel to its exact
// program+map geometry in its own test; this file keeps only the
// ELF-exists/magic/EM_BPF/parses/license plumbing assertion.
#[test]
fn copy_elf_exists_and_parses() {
    check_channel_elf("copy", env!("DEP_MEMVEIL_EBPF_COPY_PATH"));
}
