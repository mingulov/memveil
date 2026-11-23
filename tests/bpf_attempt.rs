// SPDX-License-Identifier: GPL-3.0-or-later
//! Attempt-channel geometry: the embedded attempt-channel BPF object carries
//! exactly the `mv_swiotlb_attempt` program (tracepoint
//! `swiotlb:swiotlb_bounced`) plus exactly the three attempt maps with the
//! exact C geometries. Parse-only via `aya-obj`; it never loads anything
//! into the kernel.

use aya_obj::{Object, ProgramSection};

/// `BPF_MAP_TYPE_ARRAY` (`linux/bpf.h`).
const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// `BPF_MAP_TYPE_RINGBUF` (`linux/bpf.h`).
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

/// Attempt ring capacity in bytes (8 MiB, the C `MV_RING_BYTES`).
const MV_RING_BYTES: u32 = 8_388_608;

fn parse_object() -> (Vec<u8>, Object) {
    let path = env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH");
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("read ELF at {path:?}: {error}"));
    let object = Object::parse(&bytes)
        .unwrap_or_else(|error| panic!("aya-obj must parse {path:?}: {error}"));
    (bytes, object)
}

#[test]
fn attempt_program_present_with_tracepoint_section() {
    let (bytes, object) = parse_object();
    let mut programs: Vec<&str> = object.programs.keys().map(String::as_str).collect();
    programs.sort_unstable();
    assert_eq!(
        programs,
        ["mv_swiotlb_attempt"],
        "attempt object must carry exactly the ported program"
    );
    let program = object
        .programs
        .get("mv_swiotlb_attempt")
        .expect("object must contain the mv_swiotlb_attempt program");
    assert!(
        matches!(program.section, ProgramSection::TracePoint),
        "mv_swiotlb_attempt must live in a tracepoint section"
    );
    let section = b"tracepoint/swiotlb/swiotlb_bounced";
    assert!(
        bytes.windows(section.len()).any(|window| window == section),
        "ELF must contain the tracepoint/swiotlb/swiotlb_bounced section name"
    );
}

#[test]
fn attempt_map_geometries_match_c() {
    let (_, object) = parse_object();
    let mut names: Vec<&str> = object.maps.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["mv_attempts", "mv_counts", "mv_offsets"],
        "attempt object must carry exactly the 3 C maps"
    );
    let counts = object
        .maps
        .get("mv_counts")
        .expect("object must contain the mv_counts map");
    assert_eq!(counts.map_type(), BPF_MAP_TYPE_ARRAY, "mv_counts type");
    assert_eq!(counts.key_size(), 4, "mv_counts key size");
    assert_eq!(counts.value_size(), 8, "mv_counts value size");
    assert_eq!(counts.max_entries(), 6, "mv_counts entries");
    let attempts = object
        .maps
        .get("mv_attempts")
        .expect("object must contain the mv_attempts map");
    assert_eq!(
        attempts.map_type(),
        BPF_MAP_TYPE_RINGBUF,
        "mv_attempts type"
    );
    assert_eq!(
        attempts.max_entries(),
        MV_RING_BYTES,
        "mv_attempts ring bytes"
    );
    let offsets = object
        .maps
        .get("mv_offsets")
        .expect("object must contain the mv_offsets map");
    assert_eq!(offsets.map_type(), BPF_MAP_TYPE_ARRAY, "mv_offsets type");
    assert_eq!(offsets.key_size(), 4, "mv_offsets key size");
    assert_eq!(offsets.value_size(), 24, "mv_offsets value size");
    assert_eq!(offsets.max_entries(), 1, "mv_offsets entries");
}

/// Kernels before 6.7 reject `ctx + variable` when the offset
/// register's 64-bit signed min is unbounded, even when 32-bit compares
/// already bounded the value (6.0.19/6.6.160 refuse insn 219 with
/// EINVAL). Every variable context offset therefore passes a 64-bit
/// bound check (`bound_ctx_off` in `crates/ebpf-common`) before the ctx
/// arithmetic. The checks are redundant by construction (the offsets
/// table decoder and `mv_loc_ok` enforce the same caps on u32), so the
/// optimizer is tempted to fold them away — pin their presence in the
/// built object: one 64-bit `dst > imm` guard per site cap (size 120,
/// loc 124, force 127, name offset 511).
#[test]
fn attempt_ctx_offsets_have_64bit_guards() {
    let (_, object) = parse_object();
    let program = object
        .programs
        .get("mv_swiotlb_attempt")
        .expect("object must contain the mv_swiotlb_attempt program");
    let function = object
        .functions
        .get(&program.function_key())
        .expect("object must carry mv_swiotlb_attempt instructions");
    // BPF_JMP | BPF_JGT | BPF_K: 64-bit `dst > imm` comparison. The
    // 32-bit spelling (0x26) does not bound the 64-bit signed min on
    // pre-6.7 verifiers, so only the 64-bit form counts here.
    const JGT64_IMM: u8 = 0x25;
    let mut guards = std::collections::BTreeSet::new();
    let mut guard_insns = 0u32;
    for insn in &function.instructions {
        if insn.code == JGT64_IMM {
            guards.insert(insn.imm);
            guard_insns += 1;
        }
    }
    for cap in [120, 124, 127, 511] {
        assert!(
            guards.contains(&cap),
            "built attempt object must carry a 64-bit ctx-offset guard for cap {cap}, found {guards:?}"
        );
    }
    // Four site guards plus the pre-existing force-value check (also a
    // 64-bit `> 511`, on the shifted force byte): eliding any guard
    // drops this count, so pin it. If an unrelated refactor changes the
    // force check's shape, this fails loudly for human review rather
    // than silently weakening this pin.
    assert!(
        guard_insns >= 5,
        "built attempt object must carry all four 64-bit ctx-offset guards plus the force check, found {guard_insns} 64-bit guards: {guards:?}"
    );
}
