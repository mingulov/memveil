// SPDX-License-Identifier: GPL-3.0-or-later
//! Opaque correlation identities and registry budgets.
//!
//! Operation, mapping, device, and pool identities are session-local
//! opaque tokens: they name observations, never raw kernel addresses.
//! Every pairing key carries its address-space namespace, so the same
//! token under another device or namespace never merges. Generations
//! are positive per (device, namespace, token) lineages; a reused
//! address gets a new generation, never a resurrected mapping.
//!
//! Budgets below are allocation ceilings from the frozen product
//! contracts, not eager allocations.

use super::validate::{ValidationError, check_opaque_id};

/// Pending-operation registry ceiling.
pub const PENDING_MAX: usize = 65536;
/// Active-operation registry ceiling.
pub const ACTIVE_MAX: usize = 65536;
/// Operation nesting ceiling.
pub const NESTED_MAX: usize = 8;
/// Resolved-mapping registry ceiling.
pub const RESOLVED_MAX: usize = 16384;
/// Retired-mapping registry ceiling.
pub const RETIRED_MAX: usize = 16384;
/// Interned device token ceiling.
pub const DEVICE_MAX_ID: usize = 4096;
/// Pool registry ceiling.
pub const POOL_MAX: usize = 1024;
/// Region registry ceiling.
pub const REGION_MAX: usize = 4096;
/// Diagnostics registry ceiling.
pub const DIAG_MAX: usize = 2048;

/// Accept exactly kvirt, gphys, iova, or tlb-phys.
pub fn check_address_space(v: &str) -> Result<(), ValidationError> {
    if v == "kvirt" || v == "gphys" || v == "iova" || v == "tlb-phys" {
        return Ok(());
    }
    Err(ValidationError::new("address_space", "unknown namespace"))
}

/// Generations are positive.
pub fn check_generation(g: i64) -> Result<(), ValidationError> {
    if g >= 1 {
        return Ok(());
    }
    Err(ValidationError::new("generation", "must be positive"))
}

/// One session-local operation token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationId {
    /// The opaque token.
    pub value: String,
}

impl OperationId {
    /// Parse and validate one token.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        check_opaque_id(text).map_err(|inner| ValidationError::wrap("operation_id", &inner))?;
        Ok(Self {
            value: text.to_string(),
        })
    }
}

/// One session-local mapping token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MappingId {
    /// The opaque token.
    pub value: String,
}

impl MappingId {
    /// Parse and validate one token.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        check_opaque_id(text).map_err(|inner| ValidationError::wrap("mapping_id", &inner))?;
        Ok(Self {
            value: text.to_string(),
        })
    }
}

/// One interned device token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceRef {
    /// The opaque token.
    pub value: String,
}

impl DeviceRef {
    /// Parse and validate one token.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        check_opaque_id(text).map_err(|inner| ValidationError::wrap("device_id", &inner))?;
        Ok(Self {
            value: text.to_string(),
        })
    }
}

/// One pool token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolRef {
    /// The opaque token.
    pub value: String,
}

impl PoolRef {
    /// Parse and validate one token.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        check_opaque_id(text).map_err(|inner| ValidationError::wrap("pool_id", &inner))?;
        Ok(Self {
            value: text.to_string(),
        })
    }
}

/// Namespace-aware correlation key.
///
/// The rendered form joins device, namespace, and token with a
/// separator outside the opaque-id charset, so distinct triples
/// never collide. Prefer checked() for untrusted input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairingKey {
    /// Interned device token.
    pub device: String,
    /// Address-space namespace.
    pub namespace: String,
    /// Session-local token.
    pub token: String,
}

impl PairingKey {
    /// Build one key from validated fields.
    pub fn checked(device: &str, namespace: &str, token: &str) -> Result<Self, ValidationError> {
        check_opaque_id(device).map_err(|inner| ValidationError::wrap("pairing.device", &inner))?;
        check_address_space(namespace)?;
        check_opaque_id(token).map_err(|inner| ValidationError::wrap("pairing.token", &inner))?;
        Ok(Self {
            device: device.to_string(),
            namespace: namespace.to_string(),
            token: token.to_string(),
        })
    }

    /// Render device, namespace, and token as one key.
    pub fn render(&self) -> String {
        format!("{}|{}|{}", self.device, self.namespace, self.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_match_contract() {
        assert_eq!(PENDING_MAX, 65536);
        assert_eq!(ACTIVE_MAX, 65536);
        assert_eq!(NESTED_MAX, 8);
        assert_eq!(RESOLVED_MAX, 16384);
        assert_eq!(RETIRED_MAX, 16384);
        assert_eq!(DEVICE_MAX_ID, 4096);
        assert_eq!(POOL_MAX, 1024);
        assert_eq!(REGION_MAX, 4096);
        assert_eq!(DIAG_MAX, 2048);
    }

    #[test]
    fn operation_id_roundtrip() {
        let op = OperationId::parse("op12").unwrap();
        assert_eq!(op.value, "op12");
        let err = OperationId::parse("").unwrap_err();
        assert_eq!(err.what, "operation_id");
        assert_eq!(
            err.message,
            "ValidationError(what=opaque_id, message=empty value)"
        );
        assert!(OperationId::parse("has space").is_err());
    }

    #[test]
    fn mapping_and_device_tokens() {
        assert_eq!(MappingId::parse("map-1.0").unwrap().value, "map-1.0");
        assert_eq!(DeviceRef::parse("d000001").unwrap().value, "d000001");
        assert_eq!(PoolRef::parse("pool0").unwrap().value, "pool0");
        assert!(MappingId::parse(&"a".repeat(129)).is_err());
    }

    #[test]
    fn address_space_namespaces() {
        check_address_space("kvirt").unwrap();
        check_address_space("gphys").unwrap();
        check_address_space("iova").unwrap();
        check_address_space("tlb-phys").unwrap();
        let err = check_address_space("phys").unwrap_err();
        assert_eq!(err.what, "address_space");
        assert_eq!(err.message, "unknown namespace");
    }

    #[test]
    fn pairing_key_namespaces() {
        let a = PairingKey {
            device: "d000001".to_string(),
            namespace: "kvirt".to_string(),
            token: "tok9".to_string(),
        };
        let b = PairingKey {
            namespace: "gphys".to_string(),
            ..a.clone()
        };
        let d = PairingKey {
            device: "d000002".to_string(),
            ..a.clone()
        };
        assert_ne!(a.render(), b.render());
        assert_ne!(a.render(), d.render());
        assert_eq!(a.render(), "d000001|kvirt|tok9");
    }

    #[test]
    fn pairing_key_rejects_raw() {
        assert!(PairingKey::checked("d000001", "kvirt", "bad token").is_err());
        assert!(PairingKey::checked("d000001", "raw", "tok9").is_err());
    }

    #[test]
    fn generation_positive() {
        check_generation(1).unwrap();
        let err = check_generation(0).unwrap_err();
        assert_eq!(err.what, "generation");
        assert_eq!(err.message, "must be positive");
        assert!(check_generation(-1).is_err());
    }
}
