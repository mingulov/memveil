// SPDX-License-Identifier: GPL-3.0-or-later
//! Real baseline observations, kept separate from events.
//!
//! [`read_baseline`] extracts the producer-attested initial region
//! intervals retained on the parsed session: state plus
//! provenance, never invented transitions. Late attach seeds the
//! tracker from these observations; an unmap in a shared pool
//! releases an allocation without reprivatizing the baseline.
//! [`check_observation`] validates directly built observations for
//! API users. Extracted observations are not re-validated here:
//! the session parser already enforced every bound, and a second
//! copy of those checks would drift.

use crate::model::identity::check_generation;
use crate::model::regions::{
    RegionObservation, check_region_space, check_region_span, check_region_state,
};
use crate::model::session::Session;
use crate::model::validate::{ValidationError, check_bounded_text, check_opaque_id};

/// Validate one directly built baseline observation.
pub fn check_observation(obs: &RegionObservation) -> Result<(), ValidationError> {
    check_opaque_id(&obs.region_id).map_err(|inner| ValidationError::wrap("region_id", &inner))?;
    check_region_state(&obs.state)?;
    check_region_span(obs.offset, obs.length)?;
    check_region_space(&obs.address_space)?;
    check_bounded_text(&obs.provenance, 1, 512, "region provenance")?;
    check_generation(obs.generation)
}

/// Copy the session's retained baseline observations out.
pub fn read_baseline(session: &Session) -> Vec<RegionObservation> {
    session.baseline_regions.clone()
}

#[cfg(test)]
mod tests {
    use super::{check_observation, read_baseline};
    use crate::model::regions::RegionObservation;
    use crate::model::session::parse_session;
    use crate::platform::test_support::repo_root;

    fn session_bytes(rel: &str) -> Vec<u8> {
        let path = repo_root().join(rel);
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    fn valid() -> RegionObservation {
        RegionObservation {
            region_id: "r1".to_string(),
            state: "shared".to_string(),
            offset: 0,
            length: 8192,
            address_space: "guest_physical".to_string(),
            provenance: "test-provenance".to_string(),
            generation: 1,
        }
    }

    #[test]
    fn read_baseline_extracts() {
        let s = parse_session(&session_bytes("tests/fixtures/baseline/session.json"))
            .expect("fixture parses");
        assert!(s.baseline_complete);
        let obs = read_baseline(&s);
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].region_id, "r1");
        assert_eq!(obs[0].state, "shared");
        assert_eq!(obs[0].length, 8192);
        assert_eq!(obs[0].address_space, "guest_physical");
        assert_eq!(obs[0].provenance, "test-provenance-a");
        assert_eq!(obs[1].region_id, "r2");
        assert_eq!(obs[1].state, "unknown");
        assert_eq!(obs[1].address_space, "iova");
    }

    #[test]
    fn read_baseline_empty() {
        let s = parse_session(&session_bytes("tests/fixtures/attempts/session.json"))
            .expect("fixture parses");
        assert_eq!(read_baseline(&s).len(), 0);
    }

    #[test]
    fn check_observation_valid() {
        check_observation(&valid()).expect("valid observation");
    }

    #[test]
    fn check_observation_rejects() {
        let mut bad = 0;
        let mut o = valid();
        o.state = "encrypted".to_string();
        if check_observation(&o).is_err() {
            bad += 1;
        }
        let mut o = valid();
        o.address_space = "gphys".to_string();
        if check_observation(&o).is_err() {
            bad += 1;
        }
        let mut o = valid();
        o.offset = u64::MAX;
        o.length = 1;
        if check_observation(&o).is_err() {
            bad += 1;
        }
        let mut o = valid();
        o.region_id = String::new();
        if check_observation(&o).is_err() {
            bad += 1;
        }
        let mut o = valid();
        o.provenance = String::new();
        if check_observation(&o).is_err() {
            bad += 1;
        }
        let mut o = valid();
        o.generation = 0;
        if check_observation(&o).is_err() {
            bad += 1;
        }
        assert_eq!(bad, 6);
    }

    #[test]
    fn read_baseline_returns_a_copy() {
        // Mutating the extraction must not alias the session.
        let s = parse_session(&session_bytes("tests/fixtures/baseline/session.json"))
            .expect("fixture parses");
        let mut obs = read_baseline(&s);
        obs[0].region_id = "mutated".to_string();
        assert_eq!(s.baseline_regions[0].region_id, "r1");
    }
}
