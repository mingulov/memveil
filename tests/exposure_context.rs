// SPDX-License-Identifier: GPL-3.0-or-later
//! Egress-context reader checks over hand-written fixtures.
//!
//! The module compiles here through an explicit path include;
//! the crate root wires it as `analysis::exposure_context`
//! with no edits to the module file itself. Every expectation
//! below is hand-written from the fixture inputs, never copied
//! from reader output.

#[path = "../src/analysis/exposure_context.rs"]
mod exposure_context;

use exposure_context::{ContextFact, Gap, read_context};

const ENCRYPTED: &str = include_str!("exposure/fixtures/context/swap-encrypted.json");
const MIXED: &str = include_str!("exposure/fixtures/context/swap-mixed-unresolved.json");
const ZRAM: &str = include_str!("exposure/fixtures/context/zram-writeback-zswap.json");
const TRANSIENT: &str = include_str!("exposure/fixtures/context/transient-changes.json");
const DENIED: &str = include_str!("exposure/fixtures/context/denied-unknown-mode.json");
const TWO_CONTROL: &str = include_str!("exposure/fixtures/context/two-control-gaps.json");

fn fact(evidence: &str, tick: u64, control: &str, status: &str) -> ContextFact {
    ContextFact {
        evidence_id: evidence.to_string(),
        tick,
        control: control.to_string(),
        status: status.to_string(),
        backing: None,
        encryption: None,
        path_state: None,
        mode: None,
        channel: None,
        name: None,
        writeback: None,
    }
}

#[test]
fn encrypted_swap_reports_explicit_state() {
    let context = read_context(ENCRYPTED).expect("encrypted fixture reads");
    assert_eq!(context.capture_id, "cap-ctx-swap-1");
    assert_eq!(context.refused_samples, 0);
    assert!(context.gaps.is_empty());
    assert_eq!(context.facts.len(), 2);
    let first = &context.facts[0];
    assert_eq!(first.evidence_id, "cap-ctx-swap-1:swap-enc-1");
    assert_eq!(first.tick, 0);
    assert_eq!(first.control, "swap");
    assert_eq!(first.status, "observed");
    assert_eq!(first.backing.as_deref(), Some("partition"));
    assert_eq!(first.encryption.as_deref(), Some("encrypted"));
    assert_eq!(first.path_state.as_deref(), Some("resolved"));
    let second = &context.facts[1];
    assert_eq!(second.evidence_id, "cap-ctx-swap-1:swap-enc-2");
    assert_eq!(second.tick, 10);
    assert_eq!(second.backing.as_deref(), Some("file"));
    assert_eq!(second.encryption.as_deref(), Some("encrypted"));
}

#[test]
fn mixed_and_unresolved_paths_stay_distinct() {
    let context = read_context(MIXED).expect("mixed fixture reads");
    assert_eq!(context.refused_samples, 0);
    assert_eq!(context.facts.len(), 3);
    assert_eq!(context.facts[0].encryption.as_deref(), Some("mixed"));
    assert_eq!(context.facts[0].path_state.as_deref(), Some("resolved"));
    assert_eq!(context.facts[1].encryption.as_deref(), Some("unresolved"));
    assert_eq!(context.facts[1].path_state.as_deref(), Some("unresolved"));
}

#[test]
fn suggestive_name_never_implies_encryption() {
    let context = read_context(MIXED).expect("mixed fixture reads");
    let named: Vec<&ContextFact> = context
        .facts
        .iter()
        .filter(|fact| fact.name.as_deref() == Some("cryptswap0"))
        .collect();
    assert_eq!(named.len(), 1);
    assert_eq!(
        named[0].encryption.as_deref(),
        Some("unknown"),
        "encryption without an explicit field stays unknown"
    );
}

#[test]
fn resample_gap_is_explicit() {
    let context = read_context(ZRAM).expect("zram fixture reads");
    assert_eq!(context.refused_samples, 0);
    assert_eq!(context.facts.len(), 3);
    assert_eq!(
        context.gaps,
        vec![Gap {
            from_tick: 5,
            to_tick: 50,
            ticks: 45,
        }]
    );
    assert_eq!(context.facts[0].backing.as_deref(), Some("zram"));
    assert_eq!(context.facts[0].writeback.as_deref(), Some("disabled"));
    assert_eq!(context.facts[2].backing.as_deref(), Some("zswap"));
}

#[test]
fn transient_changes_stay_independent() {
    let context = read_context(TRANSIENT).expect("transient fixture reads");
    assert_eq!(context.refused_samples, 0);
    assert_eq!(context.facts.len(), 3);
    let modes: Vec<Option<&str>> = context
        .facts
        .iter()
        .filter(|fact| fact.control == "module")
        .map(|fact| fact.mode.as_deref())
        .collect();
    assert_eq!(
        modes,
        vec![Some("strict"), Some("permissive"), Some("strict")]
    );
    let mut ticks: Vec<u64> = context.facts.iter().map(|fact| fact.tick).collect();
    ticks.sort();
    ticks.dedup();
    assert_eq!(ticks.len(), 3, "each fact keeps its own tick");
}

#[test]
fn denied_drops_detail_and_unknown_control_refuses() {
    let context = read_context(DENIED).expect("denied fixture reads");
    assert_eq!(context.refused_samples, 1);
    assert_eq!(context.facts.len(), 2);
    let denied: Vec<&ContextFact> = context
        .facts
        .iter()
        .filter(|fact| fact.status == "denied")
        .collect();
    assert_eq!(denied.len(), 1);
    let bare = fact("x", 0, "dump", "denied");
    assert_eq!(denied[0].backing, bare.backing);
    assert_eq!(denied[0].encryption, bare.encryption);
    assert_eq!(denied[0].path_state, bare.path_state);
    assert_eq!(denied[0].mode, bare.mode);
    assert_eq!(denied[0].channel, bare.channel);
    assert_eq!(denied[0].name, bare.name);
    assert_eq!(denied[0].writeback, bare.writeback);
    let device: Vec<&ContextFact> = context
        .facts
        .iter()
        .filter(|fact| fact.control == "device")
        .collect();
    assert_eq!(device.len(), 1);
    assert_eq!(device[0].mode.as_deref(), Some("unknown"));
    assert_eq!(device[0].status, "observed");
}

#[test]
fn wrong_source_refuses() {
    let text = ENCRYPTED.replace("egress-controls", "mapping-inventory-scan");
    let err = read_context(&text).expect_err("wrong source must refuse");
    assert!(err.to_string().contains("source"), "{}", err);
}

#[test]
fn full_command_key_refuses() {
    let text = ENCRYPTED.replace(
        "\"native_result\": 0",
        "\"native_result\": 0, \"command\": \"swapon -a\"",
    );
    let err = read_context(&text).expect_err("command key must refuse");
    assert!(err.to_string().contains("forbidden"), "{}", err);
}

#[test]
fn environment_key_refuses() {
    let text = ENCRYPTED.replace(
        "\"native_result\": 0",
        "\"native_result\": 0, \"environment\": \"PATH=/bin\"",
    );
    let err = read_context(&text).expect_err("environment key must refuse");
    assert!(err.to_string().contains("forbidden"), "{}", err);
}

#[test]
fn log_key_refuses() {
    let text = ENCRYPTED.replace(
        "\"native_result\": 0",
        "\"native_result\": 0, \"log\": \"line\"",
    );
    let err = read_context(&text).expect_err("log key must refuse");
    assert!(err.to_string().contains("forbidden"), "{}", err);
}

#[test]
fn duplicate_sample_refuses() {
    let text = ENCRYPTED.replace("swap-enc-2", "swap-enc-1");
    let err = read_context(&text).expect_err("duplicate sample must refuse");
    assert!(err.to_string().contains("duplicate"), "{}", err);
}

#[test]
fn unknown_native_result_refuses_sample_without_guessing() {
    let text = ENCRYPTED.replacen("\"native_result\": 0", "\"native_result\": -5", 1);
    let context = read_context(&text).expect("unknown result refuses sample");
    assert_eq!(context.refused_samples, 1);
    assert_eq!(context.facts.len(), 1);
}

#[test]
fn poisoned_capture_id_refuses() {
    for poison in ["/dev/mem", "/proc/kcore", "kcore-view-1"] {
        let text = ENCRYPTED.replacen(
            "\"capture_id\": \"cap-ctx-swap-1\"",
            &format!("\"capture_id\": \"{poison}\""),
            1,
        );
        let err = read_context(&text).expect_err("poisoned capture must refuse");
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
        let capture = ENCRYPTED.replacen("cap-ctx-swap-1", variant, 1);
        let err = read_context(&capture).expect_err("capture variant must refuse");
        assert_eq!(err.message, "value outside token grammar", "{variant}");

        let sample = ENCRYPTED.replacen("swap-enc-1", variant, 1);
        let err = read_context(&sample).expect_err("sample variant must refuse");
        assert_eq!(err.message, "value outside token grammar", "{variant}");

        let detail = ENCRYPTED.replacen(
            "\"encryption\": \"encrypted\"",
            &format!("\"encryption\": \"encrypted\", \"name\": \"{variant}\""),
            1,
        );
        let err = read_context(&detail).expect_err("detail variant must refuse");
        assert_eq!(err.message, "value outside token grammar", "{variant}");
    }
}

#[test]
fn command_and_movement_labels_refuse() {
    let command = ENCRYPTED.replacen(
        "\"encryption\": \"encrypted\"",
        "\"encryption\": \"encrypted\", \"name\": \"swapon -p 5 /dev/mapper/cryptswap0 HOME=/root\"",
        1,
    );
    let err = read_context(&command).expect_err("command label must refuse");
    assert_eq!(err.message, "value outside token grammar");

    let movement = ENCRYPTED.replacen(
        "\"encryption\": \"encrypted\"",
        "\"encryption\": \"encrypted\", \"mode\": \"Exfiltrated; data escaped to host\"",
        1,
    );
    let err = read_context(&movement).expect_err("movement label must refuse");
    assert_eq!(err.message, "value outside token grammar");
}

#[test]
fn refusal_list_values_still_refuse_whole_read() {
    // Bare device-name tokens without separators refuse via
    // the retained fragment scan, in samples and in details.
    let sample = ENCRYPTED.replacen("swap-enc-1", "/dev/mem", 1);
    let err = read_context(&sample).expect_err("sample value must refuse");
    assert_eq!(err.message, "forbidden value refused");

    for value in ["kcore", "/proc/kcore"] {
        let detail = ENCRYPTED.replacen(
            "\"encryption\": \"encrypted\"",
            &format!("\"encryption\": \"encrypted\", \"name\": \"{value}\""),
            1,
        );
        let err = read_context(&detail).expect_err("detail value must refuse");
        assert_eq!(err.message, "forbidden value refused", "{value}");
    }

    let movement = ENCRYPTED.replacen(
        "\"encryption\": \"encrypted\"",
        "\"encryption\": \"encrypted\", \"mode\": \"exfil-staging\"",
        1,
    );
    let err = read_context(&movement).expect_err("movement value must refuse");
    assert_eq!(err.message, "forbidden value refused");
}

#[test]
fn forbidden_detail_key_refuses_whole_read() {
    let text = ENCRYPTED.replacen(
        "\"backing\": \"partition\"",
        "\"backing\": \"partition\", \"command\": \"swapon -a\"",
        1,
    );
    let err = read_context(&text).expect_err("detail command key must refuse");
    assert!(err.to_string().contains("forbidden"), "{err}");
}

#[test]
fn unknown_detail_values_refuse_sample_without_guessing() {
    // A well-formed token outside the closed vocabulary
    // refuses its sample; the read itself still succeeds.
    let mode = ENCRYPTED.replacen(
        "\"encryption\": \"encrypted\"",
        "\"encryption\": \"encrypted\", \"mode\": \"turbo\"",
        1,
    );
    let encryption = ENCRYPTED.replacen(
        "\"encryption\": \"encrypted\"",
        "\"encryption\": \"rot13\"",
        1,
    );
    let backing = ENCRYPTED.replacen("\"backing\": \"partition\"", "\"backing\": \"nfs\"", 1);
    for (field, text) in [
        ("mode", mode),
        ("encryption", encryption),
        ("backing", backing),
    ] {
        let context = read_context(&text).expect("unknown value refuses sample");
        assert_eq!(context.refused_samples, 1, "{field}");
        assert_eq!(context.facts.len(), 1, "{field}");
    }
}

#[test]
fn unrelated_counter_never_infers_encryption() {
    let text = ENCRYPTED.replacen(
        "\"backing\": \"partition\"",
        "\"backing\": \"partition\", \"pswpin_total\": 41",
        1,
    );
    let context = read_context(&text).expect("counter sample refuses without failing read");
    assert_eq!(context.refused_samples, 1);
    assert_eq!(context.facts.len(), 1);
    assert_eq!(
        context.facts[0].encryption.as_deref(),
        Some("encrypted"),
        "surviving fact keeps its own explicit encryption state"
    );
}

#[test]
fn two_control_gap_matches_hand_written_expectation() {
    let context = read_context(TWO_CONTROL).expect("two-control fixture reads");
    assert_eq!(context.capture_id, "cap-ctx-gaps-1");
    assert_eq!(context.refused_samples, 0);
    assert_eq!(context.facts.len(), 5);
    let mut swap = fact("cap-ctx-gaps-1:swap-gap-1", 0, "swap", "observed");
    swap.backing = Some("partition".to_string());
    swap.encryption = Some("unknown".to_string());
    let mut first = fact("cap-ctx-gaps-1:mod-gap-1", 10, "module", "observed");
    first.encryption = Some("unknown".to_string());
    first.mode = Some("strict".to_string());
    let mut second = fact("cap-ctx-gaps-1:mod-gap-2", 20, "module", "observed");
    second.encryption = Some("unknown".to_string());
    second.mode = Some("strict".to_string());
    let mut third = fact("cap-ctx-gaps-1:mod-gap-3", 30, "module", "observed");
    third.encryption = Some("unknown".to_string());
    third.mode = Some("permissive".to_string());
    let mut last = fact("cap-ctx-gaps-1:swap-gap-2", 40, "swap", "observed");
    last.backing = Some("partition".to_string());
    last.encryption = Some("unknown".to_string());
    assert_eq!(context.facts, vec![swap, first, second, third, last]);
    assert_eq!(
        context.gaps,
        vec![Gap {
            from_tick: 0,
            to_tick: 40,
            ticks: 40,
        }],
        "module ticks between swap ticks never fill the swap gap"
    );
}

#[test]
fn unknown_top_level_and_resample_keys_refuse() {
    let top = ENCRYPTED.replacen("\"capture_id\"", "\"zzz\": 1, \"capture_id\"", 1);
    let err = read_context(&top).expect_err("unknown top-level key must refuse");
    assert_eq!(err.what, "zzz", "{err}");
    assert_eq!(err.message, "unknown field", "{err}");

    let resample = ENCRYPTED.replacen(
        "\"interval_ticks\"",
        "\"payload\": \"aa\", \"interval_ticks\"",
        1,
    );
    let err = read_context(&resample).expect_err("unknown resample key must refuse");
    assert_eq!(err.what, "payload", "{err}");
}
