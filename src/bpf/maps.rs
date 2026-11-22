// SPDX-License-Identifier: GPL-3.0-or-later
//! Map geometry: the frozen per-channel map sets and the two map gates.
//!
//! The gates run over loader-owned [`MapSpec`] rows. The ELF-time
//! [`check_maps`] pins shipped objects exactly (tests parse with
//! `aya-obj` and convert); the load-time [`check_maps_loaded`] runs
//! over live kernel `map_info` converted by the session and leaves
//! ring capacity to record admission (upper bound) plus the
//! collector gate (live size versus the admitted size).

use super::attach::{ProgramSpec, check_programs};
use super::session::{Channel, SessionError, refusal_name};

/// `BPF_MAP_TYPE_HASH` (`linux/bpf.h`).
pub const BPF_MAP_TYPE_HASH: u32 = 1;
/// `BPF_MAP_TYPE_ARRAY` (`linux/bpf.h`).
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// `BPF_MAP_TYPE_RINGBUF` (`linux/bpf.h`).
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

/// Live geometry of one map, as the kernel reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapGeometry {
    /// Map type (`BPF_MAP_TYPE_*`).
    pub map_type: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Entry count (ring capacity in bytes for ring buffers).
    pub max_entries: u32,
}

/// One named map geometry row for the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapSpec {
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

impl MapSpec {
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

/// Frozen map set per channel. The Copy row is the Aya family (the
/// host-resolved `mv_copy_offs` table map replaces CO-RE there); the
/// C family lives in [`expected_copy_maps_c`] and the load-time gate
/// admits both.
pub fn expected_maps(channel: Channel) -> Vec<MapSpec> {
    let counts = || MapSpec::named("mv_counts", BPF_MAP_TYPE_ARRAY, 4, 8, 6);
    match channel {
        Channel::Attempt => vec![
            counts(),
            MapSpec::named("mv_attempts", BPF_MAP_TYPE_RINGBUF, 0, 0, 8_388_608),
            MapSpec::named("mv_offsets", BPF_MAP_TYPE_ARRAY, 4, 24, 1),
        ],
        Channel::Lifecycle => vec![
            counts(),
            MapSpec::named("mv_lifecycle", BPF_MAP_TYPE_RINGBUF, 0, 0, 33_554_432),
            MapSpec::named("mv_gen_table", BPF_MAP_TYPE_HASH, 16, 8, 32768),
            MapSpec::named("mv_gen_next", BPF_MAP_TYPE_ARRAY, 4, 8, 1),
        ],
        Channel::Copy => vec![
            counts(),
            MapSpec::named("mv_claims", BPF_MAP_TYPE_ARRAY, 4, 16, 4096),
            MapSpec::named("mv_copy_fb", BPF_MAP_TYPE_ARRAY, 4, 8, 4),
            MapSpec::named("mv_copies", BPF_MAP_TYPE_RINGBUF, 0, 0, 33_554_432),
            MapSpec::named("mv_copy_offs", BPF_MAP_TYPE_ARRAY, 4, 112, 1),
        ],
    }
}

/// Frozen C-family Copy map set: the clang-built object resolves field
/// offsets through loader-applied CO-RE relocations against kernel BTF
/// (the loader performs them at `Session::load`, the same derivation
/// the C objects always used), so it carries exactly the four maps the
/// C source defines and no `mv_copy_offs` table map. Geometry is pinned
/// with the same rigor as the Aya family: counts 6x8, claims 4096x16,
/// fallback 4x8, copies ring 32 MiB.
pub fn expected_copy_maps_c() -> Vec<MapSpec> {
    vec![
        MapSpec::named("mv_counts", BPF_MAP_TYPE_ARRAY, 4, 8, 6),
        MapSpec::named("mv_claims", BPF_MAP_TYPE_ARRAY, 4, 16, 4096),
        MapSpec::named("mv_copy_fb", BPF_MAP_TYPE_ARRAY, 4, 8, 4),
        MapSpec::named("mv_copies", BPF_MAP_TYPE_RINGBUF, 0, 0, 33_554_432),
    ]
}

/// Exact-set map gate: every expected map present with its exact geometry,
/// no unexpected maps. Ring rows compare type and capacity only: ring
/// buffers carry no key/value sizes. ELF-time only: [`check_maps_loaded`]
/// is the load-time gate.
pub fn check_maps(channel: Channel, actual: &[MapSpec]) -> Result<(), SessionError> {
    let expected = expected_maps(channel);
    for want in &expected {
        let Some(got) = actual.iter().find(|spec| spec.name == want.name) else {
            return Err(SessionError::Geometry(format!(
                "{channel} channel: missing map {}",
                refusal_name(&want.name)
            )));
        };
        let ring = want.map_type == BPF_MAP_TYPE_RINGBUF;
        let same = got.map_type == want.map_type
            && got.max_entries == want.max_entries
            && (ring || (got.key_size, got.value_size) == (want.key_size, want.value_size));
        if !same {
            return Err(SessionError::Geometry(format!(
                "{channel} channel: map {}: want type={} key={} value={} entries={}, got type={} key={} value={} entries={}",
                refusal_name(&want.name),
                want.map_type,
                want.key_size,
                want.value_size,
                want.max_entries,
                got.map_type,
                got.key_size,
                got.value_size,
                got.max_entries
            )));
        }
    }
    for got in actual {
        if !expected.iter().any(|want| want.name == got.name) {
            return Err(SessionError::Geometry(format!(
                "{channel} channel: unexpected map {}",
                refusal_name(&got.name)
            )));
        }
    }
    Ok(())
}

/// Single-family load-time check against one expected set: every
/// expected map present, no unexpected maps, non-ring geometry exact,
/// ring type exact, ring capacity upper-bounded by the frozen size.
/// Returns the bare reason on refusal; callers prefix the channel.
fn check_loaded_against(expected: &[MapSpec], actual: &[MapSpec]) -> Result<(), String> {
    for want in expected {
        let Some(got) = actual.iter().find(|spec| spec.name == want.name) else {
            return Err(format!("missing map {}", refusal_name(&want.name)));
        };
        let ring = want.map_type == BPF_MAP_TYPE_RINGBUF;
        let same = if ring {
            got.map_type == want.map_type && got.max_entries <= want.max_entries
        } else {
            got.map_type == want.map_type
                && got.max_entries == want.max_entries
                && (got.key_size, got.value_size) == (want.key_size, want.value_size)
        };
        if !same {
            return Err(format!(
                "map {}: want type={} key={} value={} entries={}, got type={} key={} value={} entries={}",
                refusal_name(&want.name),
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
    for got in actual {
        if !expected.iter().any(|want| want.name == got.name) {
            return Err(format!("unexpected map {}", refusal_name(&got.name)));
        }
    }
    Ok(())
}

/// Copy load-time check: the Aya family ([`expected_maps`]) or the C
/// family ([`expected_copy_maps_c`]), each exact per family. A set
/// matching neither refuses naming both family reasons, so a
/// near-miss against either family stays diagnosable.
fn check_copy_maps_loaded(actual: &[MapSpec]) -> Result<(), SessionError> {
    let channel = Channel::Copy;
    let aya = expected_maps(channel);
    let c = expected_copy_maps_c();
    let aya_err = check_loaded_against(&aya, actual).err();
    let c_err = check_loaded_against(&c, actual).err();
    match (aya_err, c_err) {
        (None, _) | (_, None) => Ok(()),
        (Some(aya_why), Some(c_why)) => Err(SessionError::Geometry(format!(
            "{channel} channel: maps match neither copy family (Aya: {aya_why}; C: {c_why})"
        ))),
    }
}

/// Load-time map gate: every expected map present, no unexpected maps,
/// non-ring geometry exact, ring type exact, ring capacity upper-bounded
/// by the frozen size. The Copy channel admits two families: the Aya
/// shape (5 maps with `mv_copy_offs`) and the C shape (4 maps, no
/// `mv_copy_offs`, offsets via loader-applied CO-RE); a set matching
/// neither refuses naming both family reasons.
///
/// Ring capacity is the one relaxation from [`check_maps`]: a smaller
/// ring is legitimate once admitted (the saturation `-test` objects
/// carry 4096-byte rings), and record admission (upper bound) plus the
/// collector gate (live size versus the admitted size) already own the
/// exact size, mirroring Mojo, which has no load-time exact gate. The
/// frozen size stays as the load-time ceiling: no admitted object
/// exceeds it, and a non-power-of-two declaration the loader rounds up
/// to pow2 (aya `adjust_to_page_size`, mirroring libbpf; the kernel
/// itself requires pow2) overshoots it and still refuses.
/// Everything else stays
/// fail-closed with the same refusal texts as [`check_maps`].
pub fn check_maps_loaded(channel: Channel, actual: &[MapSpec]) -> Result<(), SessionError> {
    if channel == Channel::Copy {
        return check_copy_maps_loaded(actual);
    }
    let expected = expected_maps(channel);
    check_loaded_against(&expected, actual)
        .map_err(|reason| SessionError::Geometry(format!("{channel} channel: {reason}")))
}

/// Whole-object geometry gate: programs then maps.
pub fn check_channel_geometry(
    channel: Channel,
    programs: &[ProgramSpec],
    maps: &[MapSpec],
) -> Result<(), SessionError> {
    check_programs(channel, programs)?;
    check_maps(channel, maps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_sets_pass() {
        for channel in [Channel::Attempt, Channel::Lifecycle, Channel::Copy] {
            let expected = expected_maps(channel);
            check_maps(channel, &expected).expect("frozen set must pass");
        }
    }

    fn tamper(channel: Channel, map: &str, f: impl FnOnce(&mut MapSpec)) -> Vec<MapSpec> {
        let mut maps = expected_maps(channel);
        let row = maps
            .iter_mut()
            .find(|row| row.name == map)
            .unwrap_or_else(|| panic!("no {map} row for {channel}"));
        f(row);
        maps
    }

    #[test]
    fn wrong_geometries_refused_naming_map() {
        let maps = tamper(Channel::Attempt, "mv_attempts", |row| row.max_entries += 1);
        let error = check_maps(Channel::Attempt, &maps).expect_err("ring size must be gated");
        assert!(error.to_string().contains("mv_attempts"));
        let maps = tamper(Channel::Attempt, "mv_offsets", |row| row.value_size = 25);
        let error = check_maps(Channel::Attempt, &maps).expect_err("table size must be gated");
        assert!(error.to_string().contains("mv_offsets"));
        let maps = tamper(Channel::Copy, "mv_copy_offs", |row| row.value_size = 113);
        let error = check_maps(Channel::Copy, &maps).expect_err("copy table must be gated");
        assert!(error.to_string().contains("mv_copy_offs"));
        let maps = tamper(Channel::Lifecycle, "mv_gen_table", |row| row.map_type = 2);
        let error = check_maps(Channel::Lifecycle, &maps).expect_err("map type must be gated");
        assert!(error.to_string().contains("mv_gen_table"));
    }

    #[test]
    fn missing_and_extra_refused() {
        let mut maps = expected_maps(Channel::Copy);
        maps.retain(|row| row.name != "mv_claims");
        let error = check_maps(Channel::Copy, &maps).expect_err("missing must be refused");
        assert!(error.to_string().contains("mv_claims"));
        let mut maps = expected_maps(Channel::Copy);
        maps.push(MapSpec::named("mv_extra", BPF_MAP_TYPE_ARRAY, 4, 8, 1));
        let error = check_maps(Channel::Copy, &maps).expect_err("extra must be refused");
        assert!(error.to_string().contains("mv_extra"));
    }

    /// Ring map name per channel.
    fn ring_name(channel: Channel) -> &'static str {
        match channel {
            Channel::Attempt => "mv_attempts",
            Channel::Lifecycle => "mv_lifecycle",
            Channel::Copy => "mv_copies",
        }
    }

    #[test]
    fn loaded_gate_admits_test_ring_size() {
        // Every saturation `-test` object carries a 4096-byte ring:
        // the load-time gate admits that shape while the ELF-time
        // gate still pins the frozen capacity.
        for channel in [Channel::Attempt, Channel::Lifecycle, Channel::Copy] {
            let ring = ring_name(channel);
            let maps = tamper(channel, ring, |row| row.max_entries = 4096);
            check_maps_loaded(channel, &maps).expect("test ring size must load");
            let error =
                check_maps(channel, &maps).expect_err("ELF-time gate must still pin capacity");
            assert!(error.to_string().contains(ring));
        }
    }

    #[test]
    fn loaded_gate_refuses_missing_map() {
        for channel in [Channel::Attempt, Channel::Lifecycle] {
            let mut maps = expected_maps(channel);
            let dropped = maps.pop().expect("frozen set is non-empty");
            let error =
                check_maps_loaded(channel, &maps).expect_err("missing map must be refused at load");
            assert!(error.to_string().contains(&dropped.name));
        }
        // Copy without `mv_claims` matches neither family: both pin it.
        let mut maps = expected_maps(Channel::Copy);
        maps.retain(|row| row.name != "mv_claims");
        let error = check_maps_loaded(Channel::Copy, &maps)
            .expect_err("copy without mv_claims must be refused at load");
        assert!(error.to_string().contains("mv_claims"));
    }

    #[test]
    fn loaded_copy_gate_admits_both_families() {
        // Aya shape: the frozen 5-map set with the offsets table.
        let aya = expected_maps(Channel::Copy);
        check_maps_loaded(Channel::Copy, &aya).expect("aya copy shape must load");
        // C shape: exactly the 4 C maps, no `mv_copy_offs` (field
        // offsets arrive via loader-applied CO-RE instead).
        let c = expected_copy_maps_c();
        assert_eq!(c.len(), 4);
        assert!(!c.iter().any(|row| row.name == "mv_copy_offs"));
        check_maps_loaded(Channel::Copy, &c).expect("C copy shape must load");
        // The shared rows pin identical geometry in both families.
        for row in &c {
            let a_row = aya
                .iter()
                .find(|a_row| a_row.name == row.name)
                .unwrap_or_else(|| panic!("aya shape lacks the C row {}", row.name));
            assert_eq!(
                (row.map_type, row.key_size, row.value_size, row.max_entries),
                (
                    a_row.map_type,
                    a_row.key_size,
                    a_row.value_size,
                    a_row.max_entries
                ),
                "shared row {} must pin the same geometry in both families",
                row.name
            );
        }
        // The admitted `-test` ring size loads in both families.
        for mut maps in [aya, c] {
            let ring = maps
                .iter_mut()
                .find(|row| row.name == "mv_copies")
                .expect("copy shape carries mv_copies");
            ring.max_entries = 4096;
            check_maps_loaded(Channel::Copy, &maps).expect("test ring size must load");
        }
    }

    fn tamper_c(map: &str, f: impl FnOnce(&mut MapSpec)) -> Vec<MapSpec> {
        let mut maps = expected_copy_maps_c();
        let row = maps
            .iter_mut()
            .find(|row| row.name == map)
            .unwrap_or_else(|| panic!("no {map} C row"));
        f(row);
        maps
    }

    #[test]
    fn loaded_copy_gate_pins_c_family_geometry() {
        // Every C row is pinned with the same rigor as the Aya family:
        // a drifted row matches neither shape and the refusal names it.
        let maps = tamper_c("mv_claims", |row| row.value_size = 8);
        let error = check_maps_loaded(Channel::Copy, &maps)
            .expect_err("drifted claims row must be refused");
        assert!(error.to_string().contains("mv_claims"));
        let maps = tamper_c("mv_copy_fb", |row| row.max_entries = 5);
        let error = check_maps_loaded(Channel::Copy, &maps)
            .expect_err("drifted fallback row must be refused");
        assert!(error.to_string().contains("mv_copy_fb"));
        let maps = tamper_c("mv_counts", |row| row.max_entries = 7);
        let error = check_maps_loaded(Channel::Copy, &maps)
            .expect_err("drifted counts row must be refused");
        assert!(error.to_string().contains("mv_counts"));
        let maps = tamper_c("mv_copies", |row| row.map_type = BPF_MAP_TYPE_ARRAY);
        let error =
            check_maps_loaded(Channel::Copy, &maps).expect_err("retyped ring must be refused");
        assert!(error.to_string().contains("mv_copies"));
        // A fifth map is neither shape, even when it is the table map
        // with drifted geometry (no sneaking a bad table in as C).
        let mut maps = expected_copy_maps_c();
        maps.push(MapSpec::named("mv_extra", BPF_MAP_TYPE_ARRAY, 4, 8, 1));
        let error = check_maps_loaded(Channel::Copy, &maps).expect_err("extra map must refuse");
        assert!(error.to_string().contains("mv_extra"));
        let mut maps = expected_copy_maps_c();
        maps.push(MapSpec::named(
            "mv_copy_offs",
            BPF_MAP_TYPE_ARRAY,
            4,
            113,
            1,
        ));
        let error =
            check_maps_loaded(Channel::Copy, &maps).expect_err("drifted table map must refuse");
        assert!(error.to_string().contains("mv_copy_offs"));
    }

    #[test]
    fn loaded_copy_gate_neither_shape_names_both_families() {
        let maps = tamper_c("mv_claims", |row| row.value_size = 8);
        let error =
            check_maps_loaded(Channel::Copy, &maps).expect_err("neither shape must be refused");
        let message = error.to_string();
        assert!(
            message.contains("neither copy family"),
            "want the neither-family diagnostic, got: {message}"
        );
        assert!(
            message.contains("Aya: ") && message.contains("C: "),
            "want both family reasons, got: {message}"
        );
        assert!(
            message.contains("mv_claims"),
            "want the drifted map named, got: {message}"
        );
    }

    #[test]
    fn loaded_gate_refuses_oversize_ring() {
        // The frozen size is the load-time ceiling: a declared
        // 8388609 reads back 16777216 live (the loader rounds a
        // non-power-of-two ringbuf size up to pow2 instead of
        // refusing), and both the declared and the rounded size refuse.
        for size in [8_388_609u32, 16_777_216u32] {
            let maps = tamper(Channel::Attempt, "mv_attempts", |row| {
                row.max_entries = size
            });
            let error = check_maps_loaded(Channel::Attempt, &maps)
                .expect_err("oversize ring must be refused at load");
            assert!(error.to_string().contains("mv_attempts"));
        }
    }

    #[test]
    fn loaded_gate_keeps_other_geometry() {
        // Ring capacity is the one relaxation: table sizes, ring
        // type, and set membership stay exact at load.
        let maps = tamper(Channel::Attempt, "mv_offsets", |row| row.value_size = 25);
        let error = check_maps_loaded(Channel::Attempt, &maps)
            .expect_err("table size must be gated at load");
        assert!(error.to_string().contains("mv_offsets"));
        let maps = tamper(Channel::Attempt, "mv_attempts", |row| row.map_type = 2);
        let error = check_maps_loaded(Channel::Attempt, &maps)
            .expect_err("ring type must be gated at load");
        assert!(error.to_string().contains("mv_attempts"));
        let mut maps = expected_maps(Channel::Copy);
        maps.push(MapSpec::named("mv_extra", BPF_MAP_TYPE_ARRAY, 4, 8, 1));
        let error =
            check_maps_loaded(Channel::Copy, &maps).expect_err("extra map must be refused at load");
        assert!(error.to_string().contains("mv_extra"));
    }
}
