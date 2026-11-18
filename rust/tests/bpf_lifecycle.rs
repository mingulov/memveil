//! Lifecycle-channel geometry: the embedded lifecycle-channel BPF object carries
//! the `mv_map_result` (fexit `swiotlb_tbl_map_single`) and `mv_unmap` (fentry
//! `__swiotlb_tbl_unmap_single`) programs plus the four lifecycle maps with the
//! exact C geometries. Presence-only on programs: no exact program count is
//! asserted. Parse-only via `aya-obj`; it never loads anything into the kernel.

use aya_obj::{Object, ProgramSection};

/// `BPF_MAP_TYPE_HASH` (`linux/bpf.h`).
const BPF_MAP_TYPE_HASH: u32 = 1;
/// `BPF_MAP_TYPE_ARRAY` (`linux/bpf.h`).
const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// `BPF_MAP_TYPE_RINGBUF` (`linux/bpf.h`).
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

/// Lifecycle ring capacity in bytes (32 MiB, the C `MV_RING_BYTES`).
const MV_RING_BYTES: u32 = 33_554_432;

fn parse_object() -> Object {
    let path = env!("DEP_MEMVEIL_EBPF_LIFECYCLE_PATH");
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("read ELF at {path:?}: {error}"));
    Object::parse(&bytes).unwrap_or_else(|error| panic!("aya-obj must parse {path:?}: {error}"))
}

#[test]
fn lifecycle_programs_present_with_tracing_sections() {
    let object = parse_object();
    let map_result = object
        .programs
        .get("mv_map_result")
        .expect("object must contain the mv_map_result program");
    assert!(
        matches!(
            map_result.section,
            ProgramSection::FExit { sleepable: false }
        ),
        "mv_map_result must live in an fexit section, got {:?}",
        map_result.section
    );
    let unmap = object
        .programs
        .get("mv_unmap")
        .expect("object must contain the mv_unmap program");
    assert!(
        matches!(unmap.section, ProgramSection::FEntry { sleepable: false }),
        "mv_unmap must live in an fentry section, got {:?}",
        unmap.section
    );
}

#[test]
fn lifecycle_map_geometries_match_c() {
    let object = parse_object();
    let counts = object
        .maps
        .get("mv_counts")
        .expect("object must contain the mv_counts map");
    assert_eq!(counts.map_type(), BPF_MAP_TYPE_ARRAY);
    assert_eq!((counts.key_size(), counts.value_size()), (4, 8));
    assert_eq!(counts.max_entries(), 6);
    let ring = object
        .maps
        .get("mv_lifecycle")
        .expect("object must contain the mv_lifecycle map");
    assert_eq!(ring.map_type(), BPF_MAP_TYPE_RINGBUF);
    assert_eq!(ring.max_entries(), MV_RING_BYTES);
    let table = object
        .maps
        .get("mv_gen_table")
        .expect("object must contain the mv_gen_table map");
    assert_eq!(table.map_type(), BPF_MAP_TYPE_HASH);
    assert_eq!((table.key_size(), table.value_size()), (16, 8));
    assert_eq!(table.max_entries(), 32768);
    let next = object
        .maps
        .get("mv_gen_next")
        .expect("object must contain the mv_gen_next map");
    assert_eq!(next.map_type(), BPF_MAP_TYPE_ARRAY);
    assert_eq!((next.key_size(), next.value_size()), (4, 8));
    assert_eq!(next.max_entries(), 1);
}
