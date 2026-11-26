// SPDX-License-Identifier: GPL-3.0-or-later
//! Mapping-inventory reader checks over hand-written fixtures.
//!
//! The module compiles here through an explicit path include;
//! the crate root wires it as `analysis::exposure_mappings`
//! with no edits to the module file itself. Every expectation
//! below is hand-written from the fixture inputs, never copied
//! from reader output.

#[path = "../src/analysis/exposure_mappings.rs"]
mod exposure_mappings;

use exposure_mappings::{DaxStatus, MappingFact, read_inventory};

const MMIO: &str = include_str!("exposure/fixtures/mappings/mmio-supported.json");
const DAX: &str = include_str!("exposure/fixtures/mappings/dax-absent-unsupported.json");
const ALIAS: &str = include_str!("exposure/fixtures/mappings/alias-distinct-boundaries.json");
const DENIED: &str = include_str!("exposure/fixtures/mappings/access-denied.json");
const PARAVISOR: &str = include_str!("exposure/fixtures/mappings/paravisor-private-mmio.json");

fn fact(
    evidence: &str,
    class: &str,
    peer: &str,
    boundary: &str,
    configuration: &str,
) -> MappingFact {
    MappingFact {
        evidence_id: evidence.to_string(),
        mapping_class: class.to_string(),
        peer_class: peer.to_string(),
        trust_boundary: boundary.to_string(),
        configuration: configuration.to_string(),
    }
}

#[test]
fn supported_mmio_yields_bounded_facts() {
    let inventory = read_inventory(MMIO).expect("positive fixture reads");
    assert_eq!(inventory.capture_id, "cap-map-mmio-1");
    assert_eq!(inventory.source_id, "mapping-inventory-scan");
    assert_eq!(inventory.refused_entries, 0);
    assert_eq!(
        inventory.facts,
        vec![
            fact(
                "cap-map-mmio-1:map-mmio-1",
                "mmio",
                "device",
                "guest-device-bar0",
                "present"
            ),
            fact(
                "cap-map-mmio-1:map-mmio-2",
                "mmio",
                "device",
                "guest-device-bar1",
                "present"
            ),
        ]
    );
    assert_eq!(
        inventory.dax,
        DaxStatus {
            presence: "absent".to_string(),
            support: "unknown".to_string(),
            access_claim: None,
        }
    );
}

#[test]
fn unsupported_dax_stays_visible_without_access_claim() {
    let inventory = read_inventory(DAX).expect("dax fixture reads");
    assert_eq!(inventory.refused_entries, 0);
    assert_eq!(
        inventory.facts,
        vec![fact(
            "cap-map-dax-1:map-dax-1",
            "dax",
            "device",
            "guest-dax-window",
            "unsupported"
        )]
    );
    assert_eq!(inventory.dax.presence, "absent");
    assert_eq!(inventory.dax.support, "unsupported");
    assert_eq!(inventory.dax.access_claim, None);
}

#[test]
fn alias_keeps_equal_class_with_distinct_boundaries() {
    let inventory = read_inventory(ALIAS).expect("alias fixture reads");
    assert_eq!(inventory.refused_entries, 0);
    assert_eq!(inventory.facts.len(), 2);
    assert_eq!(inventory.facts[0].mapping_class, "mmio");
    assert_eq!(inventory.facts[1].mapping_class, "mmio");
    assert_ne!(
        inventory.facts[0].trust_boundary, inventory.facts[1].trust_boundary,
        "equal class names alone never merge trust boundaries"
    );
    assert_ne!(
        inventory.facts[0].evidence_id,
        inventory.facts[1].evidence_id
    );
}

#[test]
fn denied_stays_visible_and_unknown_peer_refuses() {
    let inventory = read_inventory(DENIED).expect("denied fixture reads");
    assert_eq!(inventory.refused_entries, 1);
    assert_eq!(inventory.facts.len(), 2);
    assert_eq!(inventory.facts[0].configuration, "present");
    assert_eq!(inventory.facts[1].configuration, "denied");
    assert_eq!(inventory.facts[1].peer_class, "device");
}

#[test]
fn paravisor_mmio_shares_class_name_only() {
    let guest = read_inventory(MMIO).expect("guest reads");
    let para = read_inventory(PARAVISOR).expect("paravisor reads");
    assert_eq!(para.refused_entries, 0);
    assert_eq!(para.facts.len(), 1);
    assert_eq!(para.facts[0].mapping_class, "mmio");
    assert_eq!(para.facts[0].peer_class, "host-or-paravisor");
    assert_eq!(para.facts[0].trust_boundary, "paravisor-private-window");
    for fact in &guest.facts {
        assert_eq!(fact.mapping_class, para.facts[0].mapping_class);
        assert_ne!(
            fact.trust_boundary, para.facts[0].trust_boundary,
            "equal class names alone must not imply equal trust boundaries"
        );
    }
}

#[test]
fn wrong_source_refuses() {
    let text = MMIO.replace("mapping-inventory-scan", "egress-controls");
    let err = read_inventory(&text).expect_err("wrong source must refuse");
    assert!(err.to_string().contains("source"), "{}", err);
}

#[test]
fn raw_memory_source_value_refuses() {
    let text = MMIO.replace("guest-device-bar0", "/dev/mem peek");
    let err = read_inventory(&text).expect_err("raw memory value must refuse");
    assert!(err.to_string().contains("forbidden"), "{}", err);
    let text = MMIO.replace("guest-device-bar1", "proc kcore view");
    let err = read_inventory(&text).expect_err("kcore value must refuse");
    assert!(err.to_string().contains("forbidden"), "{}", err);
}

#[test]
fn payload_key_refuses() {
    let text = MMIO.replace(
        "\"native_result\": 0",
        "\"native_result\": 0, \"payload\": \"aa\"",
    );
    let err = read_inventory(&text).expect_err("payload key must refuse");
    assert!(err.to_string().contains("forbidden"), "{}", err);
}

#[test]
fn address_key_refuses() {
    let text = MMIO.replace(
        "\"native_result\": 0",
        "\"native_result\": 0, \"address\": \"0x1000\"",
    );
    let err = read_inventory(&text).expect_err("address key must refuse");
    assert!(err.to_string().contains("forbidden"), "{}", err);
}

#[test]
fn unproved_dax_access_claim_refuses() {
    let text = DAX.replace("\"access_claim\": null", "\"access_claim\": \"dax-read\"");
    let err = read_inventory(&text).expect_err("unproved claim must refuse");
    assert!(err.to_string().contains("access"), "{}", err);
}

#[test]
fn duplicate_entry_refuses() {
    let text = MMIO.replace("map-mmio-2", "map-mmio-1");
    let err = read_inventory(&text).expect_err("duplicate entry must refuse");
    assert!(err.to_string().contains("duplicate"), "{}", err);
}

#[test]
fn unknown_native_result_refuses_entry_without_guessing() {
    let text = MMIO.replacen("\"native_result\": 0", "\"native_result\": -5", 1);
    let inventory = read_inventory(&text).expect("unknown result refuses entry");
    assert_eq!(inventory.refused_entries, 1);
    assert_eq!(inventory.facts.len(), 1);
}

#[test]
fn poisoned_capture_id_refuses() {
    for poison in ["/dev/mem", "/proc/kcore", "kcore-view-1"] {
        let text = MMIO.replacen(
            "\"capture_id\": \"cap-map-mmio-1\"",
            &format!("\"capture_id\": \"{poison}\""),
            1,
        );
        let err = read_inventory(&text).expect_err("poisoned capture must refuse");
        assert_eq!(err.what, "capture_id", "{poison}");
        assert!(err.to_string().contains("forbidden"), "{poison}: {err}");
    }
}
