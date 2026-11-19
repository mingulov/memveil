// SPDX-License-Identifier: GPL-3.0-or-later
//! Validated range resolution for region observations.
//!
//! `resolve_region` maps one source observation onto a region
//! reference with an explicit resolution level. Only an
//! explicitly admitted (identity, namespace, generation) triple
//! with a proven contiguous span yields physical_span; a known
//! identity without that proof stays identity_only, and anything
//! else is unavailable. Matching is exact on all three fields:
//! a recycled identity under a new generation, or the same
//! token under another namespace, never inherits an admission.
//!
//! There is no address arithmetic path. Offsets are relative to
//! the region identity, and no virt_to_phys-style formula, page
//! table walk, or numeric coincidence across namespaces can
//! produce a physical span. Admitted mappings come from
//! validated platform evidence supplied by the caller.

use crate::model::identity::check_generation;
use crate::model::regions::{RegionReference, check_region_space, check_region_span};
use crate::model::validate::{ValidationError, check_opaque_id};

/// One source observation before resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRange {
    /// Opaque session-local identity.
    pub identity: String,
    /// Address-space namespace.
    pub namespace: String,
    /// Offset relative to the region identity.
    pub offset: u64,
    /// Interval length in bytes.
    pub length: u64,
    /// Mapping generation; starts at 1.
    pub generation: i64,
}

impl Default for RawRange {
    fn default() -> Self {
        Self {
            identity: String::new(),
            namespace: String::new(),
            offset: 0,
            length: 0,
            generation: 1,
        }
    }
}

/// One validated contiguity proof for an identity triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedMapping {
    /// Opaque session-local identity.
    pub identity: String,
    /// Address-space namespace.
    pub namespace: String,
    /// Mapping generation; starts at 1.
    pub generation: i64,
    /// True when a contiguous span was proven.
    pub proven_span: bool,
}

impl Default for AdmittedMapping {
    fn default() -> Self {
        Self {
            identity: String::new(),
            namespace: String::new(),
            generation: 1,
            proven_span: false,
        }
    }
}

/// Resolve one observation against explicit admissions.
pub fn resolve_region(
    obs: &RawRange,
    admitted: &[AdmittedMapping],
) -> Result<RegionReference, ValidationError> {
    check_opaque_id(&obs.identity)
        .map_err(|inner| ValidationError::wrap("region identity", &inner))?;
    check_region_space(&obs.namespace)?;
    check_region_span(obs.offset, obs.length)?;
    check_generation(obs.generation)?;
    let mut level = "unavailable";
    if obs.namespace == "identity_only" {
        level = "identity_only";
    } else {
        for m in admitted {
            if m.identity == obs.identity
                && m.namespace == obs.namespace
                && m.generation == obs.generation
            {
                level = if m.proven_span {
                    "physical_span"
                } else {
                    "identity_only"
                };
                break;
            }
        }
    }
    RegionReference::checked(
        &obs.namespace,
        level,
        &obs.identity,
        obs.offset,
        obs.length,
        obs.generation,
    )
}

#[cfg(test)]
mod tests {
    use super::{AdmittedMapping, RawRange, resolve_region};
    use crate::model::regions::RegionReference;

    fn raw(identity: &str, namespace: &str, generation: i64) -> RawRange {
        RawRange {
            identity: identity.to_string(),
            namespace: namespace.to_string(),
            offset: 4096,
            length: 4096,
            generation,
        }
    }

    fn admitted(identity: &str, namespace: &str, generation: i64, proven: bool) -> AdmittedMapping {
        AdmittedMapping {
            identity: identity.to_string(),
            namespace: namespace.to_string(),
            generation,
            proven_span: proven,
        }
    }

    fn admissions() -> Vec<AdmittedMapping> {
        vec![
            admitted("pool-a", "guest_physical", 1, true),
            admitted("pool-b", "guest_physical", 1, false),
        ]
    }

    #[test]
    fn proven_span_resolves() {
        let got =
            resolve_region(&raw("pool-a", "guest_physical", 1), &admissions()).expect("resolves");
        assert_eq!(got.resolution, "physical_span");
        assert_eq!(got.namespace, "guest_physical");
        assert_eq!(got.identity, "pool-a");
        assert_eq!(got.offset, 4096);
        assert_eq!(got.length, 4096);
        assert_eq!(got.generation, 1);
    }

    #[test]
    fn unproved_stays_identity_only() {
        let got =
            resolve_region(&raw("pool-b", "guest_physical", 1), &admissions()).expect("resolves");
        assert_eq!(got.resolution, "identity_only");
    }

    #[test]
    fn unknown_identity_unavailable() {
        let got =
            resolve_region(&raw("pool-z", "guest_physical", 1), &admissions()).expect("resolves");
        assert_eq!(got.resolution, "unavailable");
    }

    #[test]
    fn recycled_identity_unavailable() {
        let got =
            resolve_region(&raw("pool-a", "guest_physical", 2), &admissions()).expect("resolves");
        assert_eq!(got.resolution, "unavailable");
    }

    #[test]
    fn mismatched_namespace_unavailable() {
        let got =
            resolve_region(&raw("pool-a", "kernel_virtual", 1), &admissions()).expect("resolves");
        assert_eq!(got.resolution, "unavailable");
    }

    #[test]
    fn identity_only_never_physical() {
        let got =
            resolve_region(&raw("pool-a", "identity_only", 1), &admissions()).expect("resolves");
        assert_eq!(got.resolution, "identity_only");
    }

    #[test]
    fn namespaces_never_merge() {
        let g =
            resolve_region(&raw("pool-a", "guest_physical", 1), &admissions()).expect("resolves");
        let k =
            resolve_region(&raw("pool-a", "kernel_virtual", 1), &admissions()).expect("resolves");
        assert_ne!(g.key(), k.key());
    }

    #[test]
    fn reference_checked() {
        let got = RegionReference::checked("guest_physical", "physical_span", "r1", 0, 4096, 1)
            .expect("checked");
        assert_eq!(got.resolution, "physical_span");
        let mut bad = 0;
        if RegionReference::checked("gphys", "physical_span", "r1", 0, 4096, 1).is_err() {
            bad += 1;
        }
        if RegionReference::checked("guest_physical", "resolved", "r1", 0, 4096, 1).is_err() {
            bad += 1;
        }
        if RegionReference::checked("guest_physical", "physical_span", "", 0, 4096, 1).is_err() {
            bad += 1;
        }
        if RegionReference::checked("guest_physical", "physical_span", "r1", 0, 4096, 0).is_err() {
            bad += 1;
        }
        assert_eq!(bad, 4);
    }

    #[test]
    fn resolve_rejects_bad_input() {
        let mut bad = 0;
        let r = raw("", "guest_physical", 1);
        if resolve_region(&r, &admissions()).is_err() {
            bad += 1;
        }
        let r = raw("pool-a", "nope", 1);
        if resolve_region(&r, &admissions()).is_err() {
            bad += 1;
        }
        let mut r = raw("pool-a", "guest_physical", 1);
        r.offset = u64::MAX;
        r.length = 1;
        if resolve_region(&r, &admissions()).is_err() {
            bad += 1;
        }
        assert_eq!(bad, 3);
    }
}
