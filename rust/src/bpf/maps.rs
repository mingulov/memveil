// SPDX-License-Identifier: GPL-3.0-or-later
//! Map geometry: the frozen per-channel map sets and the exact-set gate.
//!
//! The gate runs over loader-owned [`MapSpec`] rows so both the ELF-time
//! check (tests parse with `aya-obj` and convert) and the live check after
//! load (the session converts kernel `map_info`) share one comparator.

use super::attach::{ProgramSpec, check_programs};
use super::session::{Channel, SessionError};

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

/// Frozen map set per channel.
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

/// Exact-set map gate: every expected map present with its exact geometry,
/// no unexpected maps. Ring rows compare type and capacity only: ring
/// buffers carry no key/value sizes.
pub fn check_maps(channel: Channel, actual: &[MapSpec]) -> Result<(), SessionError> {
    let expected = expected_maps(channel);
    for want in &expected {
        let Some(got) = actual.iter().find(|spec| spec.name == want.name) else {
            return Err(SessionError::Geometry(format!(
                "{channel} channel: missing map {}",
                want.name
            )));
        };
        let ring = want.map_type == BPF_MAP_TYPE_RINGBUF;
        let same = got.map_type == want.map_type
            && got.max_entries == want.max_entries
            && (ring || (got.key_size, got.value_size) == (want.key_size, want.value_size));
        if !same {
            return Err(SessionError::Geometry(format!(
                "{channel} channel: map {}: want type={} key={} value={} entries={}, got type={} key={} value={} entries={}",
                want.name,
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
                got.name
            )));
        }
    }
    Ok(())
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
}
