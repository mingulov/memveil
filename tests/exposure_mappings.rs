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

#[test]
fn path_variants_refuse_in_every_carrier() {
    // None of these carries a refusal-list fragment, so the
    // token grammar (not the fragment scan) must refuse each.
    for variant in [
        "/dev//mem",
        "/dev/./mem",
        "/dev/kmem",
        "/proc",
        "proc/self/mem",
    ] {
        let capture = MMIO.replacen("cap-map-mmio-1", variant, 1);
        let err = read_inventory(&capture).expect_err("capture variant must refuse");
        assert_eq!(err.message, "value outside token grammar", "{variant}");

        // The needle names the `entry_id` field: a bare
        // `map-mmio-1` would first match inside the capture id.
        let entry = MMIO.replacen(
            "\"entry_id\": \"map-mmio-1\"",
            &format!("\"entry_id\": \"{variant}\""),
            1,
        );
        let err = read_inventory(&entry).expect_err("entry variant must refuse");
        assert_eq!(err.message, "value outside token grammar", "{variant}");

        let class = MMIO.replacen(
            "\"mapping_class\": \"mmio\"",
            &format!("\"mapping_class\": \"{variant}\""),
            1,
        );
        let err = read_inventory(&class).expect_err("class variant must refuse");
        assert_eq!(err.message, "value outside token grammar", "{variant}");

        let boundary = MMIO.replacen("guest-device-bar0", variant, 1);
        let err = read_inventory(&boundary).expect_err("boundary variant must refuse");
        assert_eq!(err.message, "value outside token grammar", "{variant}");
    }
}

#[test]
fn address_and_command_labels_refuse() {
    let address = MMIO.replacen("guest-device-bar0", "0xffff888012345000 leaked", 1);
    let err = read_inventory(&address).expect_err("address label must refuse");
    assert_eq!(err.message, "value outside token grammar");

    let command = MMIO.replacen(
        "guest-device-bar0",
        "swapon -p 5 /dev/mapper/cryptswap0 HOME=/root",
        1,
    );
    let err = read_inventory(&command).expect_err("command label must refuse");
    assert_eq!(err.message, "value outside token grammar");
}

#[test]
fn bare_address_labels_refuse_in_every_carrier() {
    // Bare addresses carry no refusal-list fragment, so the
    // leading-letter grammar must refuse each; a letter-led
    // `0x…` token pins the address-shape rule itself.
    for address in ["0xffff888012345000", "0xfe000000"] {
        let capture = MMIO.replacen("cap-map-mmio-1", address, 1);
        let err = read_inventory(&capture).expect_err("capture address must refuse");
        assert_eq!(err.message, "value outside token grammar", "{address}");

        let entry = MMIO.replacen(
            "\"entry_id\": \"map-mmio-1\"",
            &format!("\"entry_id\": \"{address}\""),
            1,
        );
        let err = read_inventory(&entry).expect_err("entry address must refuse");
        assert_eq!(err.message, "value outside token grammar", "{address}");

        let boundary = MMIO.replacen("guest-device-bar0", address, 1);
        let err = read_inventory(&boundary).expect_err("boundary address must refuse");
        assert_eq!(err.message, "value outside token grammar", "{address}");
    }

    let shaped = MMIO.replacen("guest-device-bar0", "trace-0x1f", 1);
    let err = read_inventory(&shaped).expect_err("address-shaped label must refuse");
    assert_eq!(err.message, "address-like value refused");
}

#[test]
fn unknown_dax_key_refuses() {
    let probe = MMIO.replacen(
        "\"presence\"",
        "\"device_path\": \"/dev//mem\", \"presence\"",
        1,
    );
    let err = read_inventory(&probe).expect_err("unknown dax key must refuse");
    assert_eq!(err.what, "device_path", "{err}");
    assert_eq!(err.message, "unknown field", "{err}");
}

#[test]
fn self_attested_dax_access_refuses() {
    // This slice carries no separate proof, so even a
    // `true` boolean never admits a claim.
    let proved = DAX.replacen("\"access_proved\": false", "\"access_proved\": true", 1);
    let text = proved.replacen(
        "\"access_claim\": null",
        "\"access_claim\": \"dax-read\"",
        1,
    );
    let err = read_inventory(&text).expect_err("proved claim must refuse");
    assert!(err.to_string().contains("access"), "{err}");

    let err = read_inventory(&proved).expect_err("proved flag alone must refuse");
    assert_eq!(err.what, "dax.access_proved", "{err}");
    assert!(err.to_string().contains("access"), "{err}");
}

#[test]
fn unknown_mapping_class_refuses_entry_without_guessing() {
    let text = MMIO.replacen(
        "\"mapping_class\": \"mmio\"",
        "\"mapping_class\": \"turbo\"",
        1,
    );
    let inventory = read_inventory(&text).expect("unknown class refuses entry");
    assert_eq!(inventory.refused_entries, 1);
    assert_eq!(inventory.facts.len(), 1);
    assert_eq!(inventory.facts[0].mapping_class, "mmio");
}

#[test]
fn unknown_top_level_key_refuses() {
    let probe = MMIO.replacen(
        "\"capture_id\"",
        "\"source_path\": \"/dev/mem\", \"payload\": \"aa\", \"capture_id\"",
        1,
    );
    let err = read_inventory(&probe).expect_err("forbidden top-level keys must refuse");
    assert_eq!(err.what, "source_path", "{err}");

    let benign = MMIO.replacen("\"capture_id\"", "\"zzz\": 1, \"capture_id\"", 1);
    let err = read_inventory(&benign).expect_err("unknown top-level key must refuse");
    assert_eq!(err.what, "zzz", "{err}");
    assert_eq!(err.message, "unknown field", "{err}");
}
