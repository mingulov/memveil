// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline ELF layout probe: object family plus the exact per-family map
//! and program allowlists. Unprivileged: parses bytes with the same
//! pinned `aya-obj` the loader uses, never loads anything.
//!
//! Two families exist. The Aya family (current objects) carries a
//! `maps` section plus a `memveil_channel` marker and no CO-RE
//! relocations. The legacy family (pre-change C objects, legacy
//! `.maps` definitions) relocates against kernel BTF at load, and
//! its lifecycle object still carries the retired quarantine and
//! dark maps the shipping session gate no longer admits. The
//! compat logic lives in this harness only: each family has an
//! exact allowlist, and a layout matching neither refuses.

use std::collections::BTreeMap;

/// `BPF_MAP_TYPE_HASH` (`linux/bpf.h`).
pub const MAP_HASH: u32 = 1;
/// `BPF_MAP_TYPE_ARRAY` (`linux/bpf.h`).
pub const MAP_ARRAY: u32 = 2;
/// `BPF_MAP_TYPE_RINGBUF` (`linux/bpf.h`).
pub const MAP_RINGBUF: u32 = 27;

/// Lifecycle ring map name.
pub const RING_LIFECYCLE: &str = "mv_lifecycle";
/// Copy ring map name.
pub const RING_COPY: &str = "mv_copies";

/// Object family selected by exact map-set match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// Current objects: `maps` section, channel marker, no CO-RE.
    Aya,
    /// Pre-change C objects: legacy `.maps`, CO-RE, retired maps.
    Legacy,
}

impl Family {
    /// CLI spelling.
    pub fn name(self) -> &'static str {
        match self {
            Family::Aya => "aya",
            Family::Legacy => "c",
        }
    }

    /// Parse a CLI spelling.
    pub fn parse(text: &str) -> Option<Family> {
        match text {
            "aya" => Some(Family::Aya),
            "c" => Some(Family::Legacy),
            _ => None,
        }
    }
}

/// One declared map row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRow {
    /// Map name in the object.
    pub name: String,
    /// Map type (`BPF_MAP_TYPE_*`).
    pub map_type: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Entry count (ring capacity in bytes for ring buffers).
    pub max_entries: u32,
}

impl MapRow {
    fn named(name: &str, map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self {
            name: name.to_owned(),
            map_type,
            key_size,
            value_size,
            max_entries,
        }
    }
}

/// One declared program row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramRow {
    /// Program name in the object.
    pub name: String,
    /// Section kind: `fentry`, `fexit`, or another section label.
    pub kind: String,
    /// Sleepable sections are never admitted.
    pub sleepable: bool,
}

/// Parsed offline layout of one object.
#[derive(Clone, Debug)]
pub struct Layout {
    /// Declared maps by name.
    pub maps: BTreeMap<String, MapRow>,
    /// Declared programs by name.
    pub programs: BTreeMap<String, ProgramRow>,
    /// True when the object carries BTF CO-RE relocations.
    pub core_relocations: bool,
}

/// Parse the offline layout of one ELF with pinned `aya-obj`.
pub fn parse_layout(elf: &[u8]) -> Result<Layout, String> {
    let object =
        aya_obj::Object::parse(elf).map_err(|error| format!("ELF parse failed: {error}"))?;
    let mut maps = BTreeMap::new();
    for (name, map) in object.maps.iter() {
        maps.insert(
            name.clone(),
            MapRow {
                name: name.clone(),
                map_type: map.map_type(),
                key_size: map.key_size(),
                value_size: map.value_size(),
                max_entries: map.max_entries(),
            },
        );
    }
    let mut programs = BTreeMap::new();
    for (name, program) in object.programs.iter() {
        let (kind, sleepable) = match &program.section {
            aya_obj::ProgramSection::FEntry { sleepable } => ("fentry", *sleepable),
            aya_obj::ProgramSection::FExit { sleepable } => ("fexit", *sleepable),
            other => (section_label(other), false),
        };
        programs.insert(
            name.clone(),
            ProgramRow {
                name: name.clone(),
                kind: kind.to_owned(),
                sleepable,
            },
        );
    }
    Ok(Layout {
        maps,
        programs,
        core_relocations: object.has_btf_relocations(),
    })
}

/// Short label for a non-tracing program section (refused later).
fn section_label(section: &aya_obj::ProgramSection) -> &'static str {
    match section {
        aya_obj::ProgramSection::KProbe => "kprobe",
        aya_obj::ProgramSection::KRetProbe => "kretprobe",
        aya_obj::ProgramSection::TracePoint => "tracepoint",
        _ => "other",
    }
}

/// Exact map allowlist for one family and ring. Rings compare by
/// type and capacity only (legacy ring definitions carry no key or
/// value sizes); every other row is exact. The legacy lifecycle
/// set keeps the retired `mv_gen_quarantine` (hash 16/1 x1024) and
/// `mv_gen_dark` (array 4/1 x1) maps the shipping gate dropped:
/// admitting them here is harness compat, never product admission.
pub fn expected_maps(family: Family, ring: &str) -> Option<Vec<MapRow>> {
    let counts = || MapRow::named("mv_counts", MAP_ARRAY, 4, 8, 6);
    match (family, ring) {
        (Family::Aya, RING_LIFECYCLE) => Some(vec![
            counts(),
            MapRow::named(RING_LIFECYCLE, MAP_RINGBUF, 0, 0, 33_554_432),
            MapRow::named("mv_gen_table", MAP_HASH, 16, 8, 32768),
            MapRow::named("mv_gen_next", MAP_ARRAY, 4, 8, 1),
        ]),
        (Family::Aya, RING_COPY) => Some(vec![
            counts(),
            MapRow::named("mv_claims", MAP_ARRAY, 4, 16, 4096),
            MapRow::named("mv_copy_fb", MAP_ARRAY, 4, 8, 4),
            MapRow::named(RING_COPY, MAP_RINGBUF, 0, 0, 33_554_432),
            MapRow::named("mv_copy_offs", MAP_ARRAY, 4, 112, 1),
        ]),
        (Family::Legacy, RING_LIFECYCLE) => Some(vec![
            counts(),
            MapRow::named(RING_LIFECYCLE, MAP_RINGBUF, 0, 0, 33_554_432),
            MapRow::named("mv_gen_table", MAP_HASH, 16, 8, 32768),
            MapRow::named("mv_gen_next", MAP_ARRAY, 4, 8, 1),
            MapRow::named("mv_gen_quarantine", MAP_HASH, 16, 1, 1024),
            MapRow::named("mv_gen_dark", MAP_ARRAY, 4, 1, 1),
        ]),
        (Family::Legacy, RING_COPY) => Some(vec![
            counts(),
            MapRow::named("mv_claims", MAP_ARRAY, 4, 16, 4096),
            MapRow::named("mv_copy_fb", MAP_ARRAY, 4, 8, 4),
            MapRow::named(RING_COPY, MAP_RINGBUF, 0, 0, 33_554_432),
        ]),
        _ => None,
    }
}

/// Expected program set for one ring, in attach order: name plus
/// section kind. Both families share it.
pub fn expected_programs(ring: &str) -> Option<Vec<(&'static str, &'static str)>> {
    match ring {
        RING_LIFECYCLE => Some(vec![("mv_map_result", "fexit"), ("mv_unmap", "fentry")]),
        RING_COPY => Some(vec![
            ("mv_bounce", "fentry"),
            ("mv_bounce_exit", "fexit"),
            ("mv_sync_device", "fentry"),
            ("mv_sync_cpu", "fentry"),
        ]),
        _ => None,
    }
}

/// Match one layout against one family allowlist: every expected
/// row present with its geometry, no unexpected maps.
fn match_family(layout: &Layout, family: Family, ring: &str) -> Result<(), String> {
    let Some(expected) = expected_maps(family, ring) else {
        return Err(format!("ring `{ring}` is not a stress channel"));
    };
    for want in &expected {
        let Some(got) = layout.maps.get(&want.name) else {
            return Err(format!("missing map {}", want.name));
        };
        let ring = want.map_type == MAP_RINGBUF;
        let same = got.map_type == want.map_type
            && got.max_entries == want.max_entries
            && (ring || (got.key_size, got.value_size) == (want.key_size, want.value_size));
        if !same {
            return Err(format!(
                "map {}: want type={} key={} value={} entries={}, got type={} key={} value={} entries={}",
                want.name,
                want.map_type,
                want.key_size,
                want.value_size,
                want.max_entries,
                got.map_type,
                got.key_size,
                got.value_size,
                got.max_entries
            ));
        }
    }
    for got in layout.maps.keys() {
        if !expected.iter().any(|want| &want.name == got) {
            return Err(format!("unexpected map {got}"));
        }
    }
    Ok(())
}

/// Select the object family by exact map-set match and pin the
/// program set. Exactly one family must match; anything else
/// (including a family mix or an unknown ring) refuses naming
/// both family reasons, so a near-miss stays diagnosable.
pub fn check_layout(layout: &Layout, ring: &str) -> Result<Family, String> {
    if expected_programs(ring).is_none() {
        return Err(format!("ring `{ring}` is not a stress channel"));
    }
    let aya = match_family(layout, Family::Aya, ring);
    let legacy = match_family(layout, Family::Legacy, ring);
    let family = match (aya, legacy) {
        (Ok(()), Err(_)) => Family::Aya,
        (Err(_), Ok(())) => Family::Legacy,
        (Ok(()), Ok(())) => {
            return Err("layout matches both map families; refusing as ambiguous".to_owned());
        }
        (Err(aya_why), Err(legacy_why)) => {
            return Err(format!(
                "maps match neither family for ring `{ring}` (Aya: {aya_why}; C: {legacy_why})"
            ));
        }
    };
    check_programs(layout, ring)?;
    Ok(family)
}

/// Pin the exact program set for one ring: every expected program
/// present in its section kind and non-sleepable, no extras.
fn check_programs(layout: &Layout, ring: &str) -> Result<(), String> {
    let expected = expected_programs(ring).expect("ring checked by caller");
    for (name, kind) in &expected {
        let Some(got) = layout.programs.get(*name) else {
            return Err(format!("missing program {name}"));
        };
        if got.kind != *kind {
            return Err(format!(
                "program {name}: want section {kind}, got {}",
                got.kind
            ));
        }
        if got.sleepable {
            return Err(format!("program {name}: sleepable sections are refused"));
        }
    }
    for got in layout.programs.keys() {
        if !expected.iter().any(|(want, _)| want == got) {
            return Err(format!("unexpected program {got}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> MapRow {
        MapRow::named(name, map_type, key_size, value_size, max_entries)
    }

    fn layout(rows: Vec<MapRow>, programs: Vec<(&str, &str)>) -> Layout {
        Layout {
            maps: rows
                .into_iter()
                .map(|row| (row.name.clone(), row))
                .collect(),
            programs: programs
                .into_iter()
                .map(|(name, kind)| {
                    (
                        name.to_owned(),
                        ProgramRow {
                            name: name.to_owned(),
                            kind: kind.to_owned(),
                            sleepable: false,
                        },
                    )
                })
                .collect(),
            core_relocations: false,
        }
    }

    fn lc_programs() -> Vec<(&'static str, &'static str)> {
        vec![("mv_map_result", "fexit"), ("mv_unmap", "fentry")]
    }

    #[test]
    fn aya_lifecycle_matches() {
        let rows = expected_maps(Family::Aya, RING_LIFECYCLE).unwrap();
        let seen = check_layout(&layout(rows, lc_programs()), RING_LIFECYCLE).unwrap();
        assert_eq!(seen, Family::Aya);
    }

    #[test]
    fn legacy_lifecycle_matches_with_retired_maps() {
        let rows = expected_maps(Family::Legacy, RING_LIFECYCLE).unwrap();
        assert!(rows.iter().any(|row| row.name == "mv_gen_quarantine"));
        assert!(rows.iter().any(|row| row.name == "mv_gen_dark"));
        let seen = check_layout(&layout(rows, lc_programs()), RING_LIFECYCLE).unwrap();
        assert_eq!(seen, Family::Legacy);
    }

    #[test]
    fn quarantine_map_breaks_the_aya_set() {
        let mut rows = expected_maps(Family::Aya, RING_LIFECYCLE).unwrap();
        rows.push(row("mv_gen_quarantine", MAP_HASH, 16, 1, 1024));
        let err = check_layout(&layout(rows, lc_programs()), RING_LIFECYCLE).unwrap_err();
        assert!(err.contains("neither family"), "{err}");
    }

    #[test]
    fn missing_dark_map_breaks_the_legacy_set() {
        let rows: Vec<MapRow> = expected_maps(Family::Legacy, RING_LIFECYCLE)
            .unwrap()
            .into_iter()
            .filter(|row| row.name != "mv_gen_dark")
            .collect();
        let err = check_layout(&layout(rows, lc_programs()), RING_LIFECYCLE).unwrap_err();
        assert!(err.contains("neither family"), "{err}");
    }

    #[test]
    fn copy_table_selects_the_aya_copy_set() {
        let rows = expected_maps(Family::Aya, RING_COPY).unwrap();
        let programs = vec![
            ("mv_bounce", "fentry"),
            ("mv_bounce_exit", "fexit"),
            ("mv_sync_device", "fentry"),
            ("mv_sync_cpu", "fentry"),
        ];
        let seen = check_layout(&layout(rows, programs), RING_COPY).unwrap();
        assert_eq!(seen, Family::Aya);
    }

    #[test]
    fn copy_without_table_is_the_legacy_set() {
        let rows = expected_maps(Family::Legacy, RING_COPY).unwrap();
        assert_eq!(rows.len(), 4);
        let programs = vec![
            ("mv_bounce", "fentry"),
            ("mv_bounce_exit", "fexit"),
            ("mv_sync_device", "fentry"),
            ("mv_sync_cpu", "fentry"),
        ];
        let seen = check_layout(&layout(rows, programs), RING_COPY).unwrap();
        assert_eq!(seen, Family::Legacy);
    }

    #[test]
    fn wrong_ring_refuses() {
        let rows = expected_maps(Family::Aya, RING_COPY).unwrap();
        let programs = vec![
            ("mv_bounce", "fentry"),
            ("mv_bounce_exit", "fexit"),
            ("mv_sync_device", "fentry"),
            ("mv_sync_cpu", "fentry"),
        ];
        let err = check_layout(&layout(rows, programs), RING_LIFECYCLE).unwrap_err();
        assert!(err.contains("neither family"), "{err}");
    }

    #[test]
    fn unknown_ring_refuses() {
        let err = check_layout(&layout(vec![], vec![]), "mv_attempts").unwrap_err();
        assert!(err.contains("not a stress channel"), "{err}");
    }

    #[test]
    fn wrong_program_section_refuses() {
        let rows = expected_maps(Family::Aya, RING_LIFECYCLE).unwrap();
        let bad = vec![("mv_map_result", "fentry"), ("mv_unmap", "fentry")];
        let err = check_layout(&layout(rows, bad), RING_LIFECYCLE).unwrap_err();
        assert!(err.contains("want section fexit"), "{err}");
    }

    #[test]
    fn extra_program_refuses() {
        let rows = expected_maps(Family::Aya, RING_LIFECYCLE).unwrap();
        let mut programs = lc_programs();
        programs.push(("mv_extra", "fentry"));
        let err = check_layout(&layout(rows, programs), RING_LIFECYCLE).unwrap_err();
        assert!(err.contains("unexpected program"), "{err}");
    }

    #[test]
    fn family_spelling_round_trips() {
        assert_eq!(Family::parse("aya"), Some(Family::Aya));
        assert_eq!(Family::parse("c"), Some(Family::Legacy));
        assert_eq!(Family::parse("x"), None);
        assert_eq!(Family::Aya.name(), "aya");
        assert_eq!(Family::Legacy.name(), "c");
    }
}
