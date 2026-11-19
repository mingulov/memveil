// SPDX-License-Identifier: GPL-3.0-or-later
//! Region identity, observation, and reference types.
//!
//! A region is one opaque session-local identity plus the
//! address-space namespace its offsets are relative to. Offsets
//! are relative to the region identity, never raw kernel
//! addresses, and equality across namespaces needs a validated
//! resolver: the same token under another namespace never
//! merges. Generations separate successive lives of one token;
//! state, resolution, and provenance checks live here so every
//! consumer shares one definition.

use super::identity::check_generation;
use super::validate::{ValidationError, check_opaque_id, checked_add};

/// One producer-attested initial region interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionObservation {
    /// Opaque session-local region identity.
    pub region_id: String,
    /// Region state enum.
    pub state: String,
    /// Offset relative to the region identity.
    pub offset: u64,
    /// Interval length in bytes.
    pub length: u64,
    /// Address-space namespace of the offsets.
    pub address_space: String,
    /// Attestation provenance label.
    pub provenance: String,
    /// Mapping generation; starts at 1.
    pub generation: i64,
}

impl Default for RegionObservation {
    fn default() -> Self {
        Self {
            region_id: String::new(),
            state: String::new(),
            offset: 0,
            length: 0,
            address_space: String::new(),
            provenance: String::new(),
            generation: 1,
        }
    }
}

/// One resolved region range with its resolution proof level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionReference {
    /// Address-space namespace.
    pub namespace: String,
    /// Resolution proof level.
    pub resolution: String,
    /// Opaque session-local identity.
    pub identity: String,
    /// Offset relative to the region identity.
    pub offset: u64,
    /// Interval length in bytes.
    pub length: u64,
    /// Mapping generation; starts at 1.
    pub generation: i64,
}

impl Default for RegionReference {
    fn default() -> Self {
        Self {
            namespace: String::new(),
            resolution: String::new(),
            identity: String::new(),
            offset: 0,
            length: 0,
            generation: 1,
        }
    }
}

impl RegionReference {
    /// Render namespace, generation, and token as one key.
    ///
    /// The separator stays outside the opaque-id charset, so
    /// distinct triples never collide.
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.namespace, self.generation, self.identity)
    }

    /// Build one reference from validated fields.
    pub fn checked(
        namespace: &str,
        resolution: &str,
        identity: &str,
        offset: u64,
        length: u64,
        generation: i64,
    ) -> Result<Self, ValidationError> {
        check_region_space(namespace)?;
        check_region_resolution(resolution)?;
        check_opaque_id(identity)
            .map_err(|inner| ValidationError::wrap("region identity", &inner))?;
        check_region_span(offset, length)?;
        check_generation(generation)?;
        Ok(Self {
            namespace: namespace.to_string(),
            resolution: resolution.to_string(),
            identity: identity.to_string(),
            offset,
            length,
            generation,
        })
    }
}

/// Accept exactly shared, private, or unknown.
pub fn check_region_state(v: &str) -> Result<(), ValidationError> {
    if v == "shared" || v == "private" || v == "unknown" {
        return Ok(());
    }
    Err(ValidationError::new("region_state", "bad enum"))
}

/// Accept exactly the four schema address spaces.
pub fn check_region_space(v: &str) -> Result<(), ValidationError> {
    if v == "guest_physical" || v == "kernel_virtual" || v == "iova" || v == "identity_only" {
        return Ok(());
    }
    Err(ValidationError::new("address_space", "bad enum"))
}

/// Accept exactly the three resolution levels.
pub fn check_region_resolution(v: &str) -> Result<(), ValidationError> {
    if v == "physical_span" || v == "identity_only" || v == "unavailable" {
        return Ok(());
    }
    Err(ValidationError::new("resolution", "bad enum"))
}

/// Return the half-open end, refusing overflow.
pub fn check_region_span(offset: u64, length: u64) -> Result<u64, ValidationError> {
    checked_add(offset, length).map_err(|_| ValidationError::new("region span", "span overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_key_format() {
        let r = RegionReference {
            namespace: "guest_physical".to_string(),
            resolution: "physical_span".to_string(),
            identity: "r1".to_string(),
            offset: 0,
            length: 8192,
            generation: 1,
        };
        assert_eq!(r.key(), "guest_physical|1|r1");
        let mut gen2 = r.clone();
        gen2.generation = 2;
        assert_ne!(r.key(), gen2.key());
        let mut other_ns = r.clone();
        other_ns.namespace = "kernel_virtual".to_string();
        assert_ne!(r.key(), other_ns.key());
    }

    #[test]
    fn region_checks_accept_enums() {
        check_region_state("shared").unwrap();
        check_region_state("private").unwrap();
        check_region_state("unknown").unwrap();
        check_region_space("guest_physical").unwrap();
        check_region_space("kernel_virtual").unwrap();
        check_region_space("iova").unwrap();
        check_region_space("identity_only").unwrap();
        check_region_resolution("physical_span").unwrap();
        check_region_resolution("identity_only").unwrap();
        check_region_resolution("unavailable").unwrap();
        assert_eq!(check_region_span(4096, 4096), Ok(8192));
    }

    #[test]
    fn region_checks_reject() {
        assert!(check_region_state("encrypted").is_err());
        assert!(check_region_space("gphys").is_err());
        assert!(check_region_resolution("resolved").is_err());
        assert!(check_region_span(u64::MAX, 1).is_err());
    }

    #[test]
    fn reference_checked() {
        let got =
            RegionReference::checked("guest_physical", "physical_span", "r1", 0, 4096, 1).unwrap();
        assert_eq!(got.resolution, "physical_span");
        assert!(RegionReference::checked("gphys", "physical_span", "r1", 0, 4096, 1).is_err());
        assert!(RegionReference::checked("guest_physical", "resolved", "r1", 0, 4096, 1).is_err());
        assert!(
            RegionReference::checked("guest_physical", "physical_span", "", 0, 4096, 1).is_err()
        );
        assert!(
            RegionReference::checked("guest_physical", "physical_span", "r1", 0, 4096, 0).is_err()
        );
        assert!(
            RegionReference::checked("guest_physical", "physical_span", "r1", u64::MAX, 1, 1)
                .is_err()
        );
    }

    #[test]
    fn observation_default_generation_is_one() {
        let obs = RegionObservation::default();
        assert_eq!(obs.generation, 1);
        assert_eq!(obs.offset, 0);
        assert_eq!(obs.length, 0);
    }
}
