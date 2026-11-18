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
