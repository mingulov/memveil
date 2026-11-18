//! Build-artifact contract: `cargo build` compiles `crates/ebpf` for the BPF
//! target and `build.rs` publishes the resulting ELF path as
//! `DEP_MEMVEIL_EBPF_PATH`. This test proves the path exists, points at a
//! BPF object, and parses with at least one program. It never loads anything
//! into the kernel, so it runs unprivileged.

use std::path::Path;

/// ELF `e_machine` for BPF objects (`EM_BPF`).
const EM_BPF: u16 = 247;

#[test]
fn ebpf_elf_exists_and_parses_with_one_program() {
    let path = env!("DEP_MEMVEIL_EBPF_PATH");
    assert!(
        Path::new(path).is_file(),
        "DEP_MEMVEIL_EBPF_PATH must point at a built file, got {path:?}"
    );
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("read ELF at {path:?}: {error}"));
    assert!(!bytes.is_empty(), "ELF at {path:?} must not be empty");
    assert_eq!(
        bytes.get(..4),
        Some(b"\x7fELF".as_slice()),
        "{path:?} must start with the ELF magic"
    );
    let machine = bytes
        .get(18..20)
        .map(|window| u16::from_le_bytes([window[0], window[1]]));
    assert_eq!(
        machine,
        Some(EM_BPF),
        "{path:?} must be a BPF object (e_machine {EM_BPF})"
    );
    let object = aya_obj::Object::parse(&bytes)
        .unwrap_or_else(|error| panic!("aya-obj must parse the ELF at {path:?}: {error}"));
    assert!(
        !object.programs.is_empty(),
        "ELF at {path:?} must contain at least one BPF program"
    );
}
