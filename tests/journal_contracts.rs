// SPDX-License-Identifier: GPL-3.0-or-later
//! Frozen conversion journal contracts: selection, admission, wire decode,
//! budgets, and window membership.
//!
//! Port of the Mojo-era `test_journal_contracts` checks against
//! `model::journal`, plus a Rust-vs-C decoder differential: every native
//! vector from `tests/journal/test_wire.py` must decode identically under
//! the carried C oracle (`bpf/include/memveil_journal.h`, compiled with
//! sanitizers exactly as the Python suite does) and the Rust decoder.

use memveil::model::common::MaybeU64;
use memveil::model::journal::{
    CALLER_FRAME_CAPACITY, JOURNAL_CPU_MAX, JOURNAL_PAGE_SIZE, JOURNAL_RING_BYTES,
    JOURNAL_SCHEMA_VERSION, JOURNAL_WIRE_BYTES, JOURNAL_WIRE_MAGIC, JOURNAL_WIRE_VERSION,
    JournalResult, JournalWindow, NESTING_CAPACITY, OPERATION_CAPACITY, OPERATION_TOKEN_MAX,
    REPLAY_TOKEN_INTERVAL_CAPACITY, caller_label_class, classify_caller, decode_journal,
    journal_admission, next_operation_token, requested_bytes, select_journal, validate_membership,
};

#[test]
fn selection_freezes_channel_rules() {
    let ordinary = select_journal("", false, false, false).expect("empty selects ordinary");
    assert!(ordinary.attempts && !ordinary.journal);
    let journal = select_journal("conversion-journal", false, false, false).expect("journal alone");
    assert!(journal.journal && !journal.attempts && !journal.callers);
    let mixed = select_journal("conversion-journal,copy-actual", true, false, false)
        .expect("mixed with callers");
    assert!(mixed.journal && mixed.attempts && mixed.callers);
    for bad in ["unknown", "conversion-journal,conversion-journal"] {
        assert!(
            select_journal(bad, false, false, false).is_err(),
            "selector {bad:?} must refuse"
        );
    }
    assert!(select_journal("conversion-journal", false, true, false).is_err());
    assert!(select_journal("", true, false, false).is_err());
    assert!(select_journal("", false, false, true).is_err());
}

#[test]
fn admission_needs_no_attempt_source_for_journal_only() {
    let journal =
        select_journal("conversion-journal", false, false, false).expect("journal selection");
    let decision = journal_admission(journal, false, "admitted", false);
    assert_eq!(decision.exit_code, 0);
    assert_eq!(decision.reason, "ready_for_attachment");
    for status in ["provisional", "unadmitted", "unknown"] {
        let decision = journal_admission(journal, true, status, true);
        assert_eq!(decision.exit_code, 3);
        assert_eq!(decision.reason, "journal_profile_not_admitted");
    }
    let mixed =
        select_journal("copy-actual,conversion-journal", false, false, false).expect("mixed");
    for (attempts, admitted, expected) in [
        (false, false, 3),
        (true, false, 3),
        (false, true, 3),
        (true, true, 0),
    ] {
        let status = if admitted { "admitted" } else { "unadmitted" };
        let decision = journal_admission(mixed, attempts, status, true);
        assert_eq!(decision.exit_code, expected);
    }
    let callers =
        select_journal("conversion-journal", true, false, false).expect("journal callers");
    let decision = journal_admission(callers, false, "admitted", false);
    assert_eq!(decision.exit_code, 3);
    assert_eq!(decision.reason, "journal_callers_not_admitted");
    let ordinary = select_journal("", false, false, false).expect("ordinary");
    let decision = journal_admission(ordinary, true, "unknown", false);
    assert_eq!(decision.exit_code, 0);
    let decision = journal_admission(ordinary, false, "admitted", true);
    assert_eq!(decision.exit_code, 3);
    assert_eq!(decision.reason, "attempts_not_admitted");
}

#[test]
fn counts_and_classification_stay_exact() {
    assert_eq!(
        requested_bytes(2147483647, 4096).expect("max pages"),
        8796093018112
    );
    assert_eq!(classify_caller(false, false, 0, 1), 0);
    assert_eq!(classify_caller(true, true, 1, 1), 4);
    assert_eq!(classify_caller(true, false, 2, 1), 3);
    assert_eq!(classify_caller(true, false, 0, 0), 2);
    assert_eq!(classify_caller(true, false, 1, 1), 1);
    assert!(requested_bytes(-1, 4096).is_err());
    assert!(requested_bytes(1, 8192).is_err());
    assert_eq!(caller_label_class(1), 1);
    assert_eq!(caller_label_class(6), 2);
    assert_eq!(caller_label_class(10), 3);
    assert_eq!(caller_label_class(0), 0);
    assert_eq!(caller_label_class(11), 0);
}

/// The contract's canonical matched vector: magic, version/kind 1, matched
/// flag, decrypt direction, exit 30, epoch 1, token 9, entry 20, 3 pages.
fn wire() -> [u8; 72] {
    let mut data = [0u8; 72];
    data[0] = 77;
    data[1] = 86;
    data[2] = 74;
    data[3] = 82;
    data[4] = 1;
    data[6] = 1;
    data[8] = 1;
    data[10] = 1;
    data[24] = 30;
    data[32] = 1;
    data[40] = 9;
    data[48] = 20;
    data[56] = 3;
    data
}

#[test]
fn wire_decode_accepts_exactly_the_fixed_layout() {
    let data = wire();
    let result = decode_journal(&data).expect("canonical vector decodes");
    assert_eq!(result.token, 9);
    assert_eq!(result.pages, 3);
    assert_eq!(result.native_result, 0);
    assert_eq!(result.entry_ns, 20);
    assert!(result.matched);
    let mut signed = wire();
    signed[60] = 251;
    signed[61] = 255;
    signed[62] = 255;
    signed[63] = 255;
    let result = decode_journal(&signed).expect("signed result decodes");
    assert_eq!(result.native_result, -5);
    for offset in [4, 6, 8, 10, 64, 66, 68, 70] {
        let mut invalid = wire();
        invalid[offset] = 255;
        assert!(
            decode_journal(&invalid).is_err(),
            "offset {offset} must refuse"
        );
    }
    let mut large = wire();
    large[40] = 1;
    large[46] = 32;
    let result = decode_journal(&large).expect("large token decodes");
    assert_eq!(result.token, 9007199254740993);
    large[46] = 0;
    large[40] = 0;
    assert!(decode_journal(&large).is_err());
}

#[test]
fn budgets_and_window_membership_stay_exact() {
    assert_eq!(OPERATION_CAPACITY, 4096);
    assert_eq!(NESTING_CAPACITY, 8);
    assert_eq!(REPLAY_TOKEN_INTERVAL_CAPACITY, 65536);
    assert_eq!(next_operation_token(1, 4095, 7).expect("token advances"), 2);
    for (capacity, depth) in [(4096, 7), (4095, 8), (-1, 0)] {
        assert!(
            next_operation_token(1, capacity, depth).is_err(),
            "active {capacity} depth {depth} must refuse"
        );
    }
    assert!(next_operation_token(18446744073709551614, 0, 0).is_err());
    let result = decode_journal(&wire()).expect("canonical vector decodes");
    validate_membership(&result, 1, 20, 25, 31).expect("in-window result admits");
    for (epoch, start, cutoff, end) in [
        (2, 20, 25, 31),
        (1, 21, 25, 31),
        (1, 20, 20, 31),
        (1, 20, 25, 30),
    ] {
        assert!(
            validate_membership(&result, epoch, start, cutoff, end).is_err(),
            "epoch {epoch} window {start}/{cutoff}/{end} must refuse"
        );
    }
}

#[test]
fn nullable_checkpoint_window_states_stay_exact() {
    let initial = JournalWindow {
        epoch: 1,
        capture_start: 10,
        observation_end: 31,
        start: MaybeU64::absent(),
        cutoff: MaybeU64::absent(),
        start_reason: "not_opened".to_string(),
        end_reason: "not_opened".to_string(),
        finalized: false,
    };
    initial.validate().expect("initial checkpoint validates");
    let result = decode_journal(&wire()).expect("canonical vector decodes");
    assert!(initial.validate_result(&result).is_err());
    let mut opened = JournalWindow {
        epoch: 1,
        capture_start: 10,
        observation_end: 31,
        start: MaybeU64::of(20),
        cutoff: MaybeU64::absent(),
        start_reason: String::new(),
        end_reason: "admission_open".to_string(),
        finalized: false,
    };
    opened.validate_result(&result).expect("open window admits");
    opened.finalized = true;
    assert!(opened.validate().is_err());
    opened.end_reason = "close_unproved".to_string();
    opened
        .validate_result(&result)
        .expect("unproved close admits");
    opened.cutoff = MaybeU64::of(25);
    opened.end_reason = String::new();
    opened
        .validate_result(&result)
        .expect("closed window admits");
}

#[test]
fn decoder_holds_at_every_boundary() {
    // CPU ceiling decodes; one past it refuses.
    let mut cpu = wire();
    cpu[12] = 0xFF;
    cpu[13] = 0xFF;
    cpu[14] = 0x0F;
    let result = decode_journal(&cpu).expect("cpu ceiling decodes");
    assert_eq!(result.cpu, 1048575);
    cpu[14] = 0x10;
    assert!(decode_journal(&cpu).is_err());
    // Directions 1-2 decode; 0 and 3 refuse.
    for (direction, ok) in [(1, true), (2, true), (0, false), (3, false)] {
        let mut record = wire();
        record[10] = direction;
        assert_eq!(decode_journal(&record).is_ok(), ok, "direction {direction}");
    }
    // Unresolved/ambiguous/truncated callers decode with zero class/label;
    // any class or label with them refuses.
    for status in [2, 3, 4] {
        let mut record = wire();
        record[64] = status;
        decode_journal(&record).expect("non-resolved status decodes");
        record[66] = 1;
        assert!(decode_journal(&record).is_err());
        record[66] = 0;
        record[68] = 1;
        assert!(decode_journal(&record).is_err());
    }
    // Every label boundary maps to its class; only the matching class decodes.
    for (label, class) in [(1u16, 1u16), (2, 1), (3, 2), (6, 2), (7, 3), (10, 3)] {
        assert_eq!(caller_label_class(label), class);
        let mut record = wire();
        record[64] = 1;
        record[66] = class as u8;
        record[68] = label as u8;
        decode_journal(&record).expect("matching class decodes");
        record[66] = (if class == 3 { 1 } else { class + 1 }) as u8;
        assert!(decode_journal(&record).is_err());
    }
    assert_eq!(caller_label_class(0), 0);
    assert_eq!(caller_label_class(11), 0);
    // The top token decodes matched; it never advances further.
    let mut top = wire();
    top[40..48].copy_from_slice(&OPERATION_TOKEN_MAX.to_le_bytes());
    let result = decode_journal(&top).expect("top token decodes");
    assert_eq!(result.token, OPERATION_TOKEN_MAX);
    assert!(next_operation_token(OPERATION_TOKEN_MAX - 1, 0, 0).is_ok());
    // Entry equal to exit is in the closed matched bound; one past refuses.
    let mut edge = wire();
    edge[48] = 30;
    decode_journal(&edge).expect("entry equal to exit decodes");
    edge[48] = 31;
    assert!(decode_journal(&edge).is_err());
    // Signed page/result extremes decode; unsigned length extremes refuse.
    let mut extremes = wire();
    extremes[56..60].copy_from_slice(&i32::MIN.to_le_bytes());
    extremes[60..64].copy_from_slice(&i32::MAX.to_le_bytes());
    let result = decode_journal(&extremes).expect("signed extremes decode");
    assert_eq!(result.pages, i32::MIN);
    assert_eq!(result.native_result, i32::MAX);
    assert!(decode_journal(&[]).is_err());
    assert!(decode_journal(&[0u8; 71]).is_err());
    assert!(decode_journal(&[0u8; 73]).is_err());
    // Epoch ceiling decodes; zero refuses.
    let mut epoch = wire();
    epoch[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    decode_journal(&epoch).expect("epoch ceiling decodes");
    epoch[32..40].copy_from_slice(&0u64.to_le_bytes());
    assert!(decode_journal(&epoch).is_err());
}

#[test]
fn selection_covers_edge_cases() {
    // The 256-byte limit is exact: 257 bytes refuse on length, while 256
    // bytes pass the length check and refuse on the unknown id instead.
    let too_long = "a".repeat(257);
    let err = select_journal(&too_long, false, false, false).expect_err("length must refuse");
    assert_eq!(err.message, "selector too long");
    let fit = "a".repeat(256);
    let err = select_journal(&fit, false, false, false).expect_err("unknown id must refuse");
    assert_eq!(err.message, "unknown");
    // Empty segments are unknown capability ids.
    for bad in [
        "conversion-journal,",
        ",conversion-journal",
        "copy-actual,,copy-actual",
        ",",
    ] {
        assert!(
            select_journal(bad, false, false, false).is_err(),
            "{bad:?} must refuse"
        );
    }
    // Reserved observe-only name resolves as ordinary, never journal.
    let observe = select_journal("conversion-observe", false, false, false).expect("observe");
    assert!(observe.attempts && !observe.journal);
    // A device filter is fine once an ordinary channel joins the journal.
    let mixed =
        select_journal("conversion-journal,copy-actual", false, true, false).expect("mixed device");
    assert!(mixed.journal && mixed.attempts);
    // An explicit journal object still needs the journal.
    assert!(select_journal("copy-actual", false, false, true).is_err());
    select_journal("conversion-journal", false, false, true).expect("journal object");
    // Token and byte floors.
    assert_eq!(next_operation_token(0, 0, 0).expect("first token"), 1);
    assert_eq!(requested_bytes(0, 4096).expect("zero pages"), 0);
    // Unproved readiness admits no matched entry but validates as a window.
    let unproved = JournalWindow {
        epoch: 1,
        capture_start: 10,
        observation_end: 31,
        start: MaybeU64::absent(),
        cutoff: MaybeU64::absent(),
        start_reason: "readiness_unproved".to_string(),
        end_reason: "close_unproved".to_string(),
        finalized: false,
    };
    unproved.validate().expect("unproved window validates");
    let result = decode_journal(&wire()).expect("canonical vector decodes");
    assert!(unproved.validate_result(&result).is_err());
    // An unmatched exit needs no admitted entry.
    let mut unmatched = wire();
    unmatched[8] = 0;
    unmatched[40] = 0;
    unmatched[48] = 0;
    let exit = decode_journal(&unmatched).expect("unmatched exit decodes");
    assert!(!exit.matched);
    unproved
        .validate_result(&exit)
        .expect("unmatched exit needs no entry");
}

#[test]
fn frozen_numbers_stay_exact() {
    assert_eq!(JOURNAL_SCHEMA_VERSION, "0.2.0");
    assert_eq!(JOURNAL_WIRE_VERSION, 1);
    assert_eq!(JOURNAL_WIRE_BYTES, 72);
    assert_eq!(JOURNAL_WIRE_MAGIC, 0x524A_564D);
    assert_eq!(CALLER_FRAME_CAPACITY, 16);
    assert_eq!(JOURNAL_RING_BYTES, 8388608);
    assert_eq!(OPERATION_TOKEN_MAX, 18446744073709551614);
    assert_eq!(JOURNAL_CPU_MAX, 1048575);
    assert_eq!(JOURNAL_PAGE_SIZE, 4096);
}

// ---------------------------------------------------------------------------
// Rust-vs-C decoder differential over the native vectors.
// ---------------------------------------------------------------------------

/// The C oracle harness `tests/journal/test_wire.py` compiles, byte for byte.
const DECODE_C: &str = r#"#include <stdio.h>
#include "bpf/include/memveil_journal.h"
int main(void) {
    unsigned char b[73]; struct mv_journal out;
    size_t n = fread(b, 1, sizeof(b), stdin);
    int rc = mv_decode_journal(b, n, &out);
    if (rc != MV_OK) return 2;
    printf("%u %u %llu %llu %llu %llu %llu %d %d %u %u %u %u\n",
           out.direction, out.cpu, (unsigned long long)out.sequence,
           (unsigned long long)out.exit_ns, (unsigned long long)out.epoch,
           (unsigned long long)out.token, (unsigned long long)out.entry_ns,
           out.pages, out.native_result, out.caller_status, out.caller_class,
           out.caller_label, out.matched);
    return 0;
}
"#;

/// One native vector's wire fields, mirroring `test_wire.py::wire`.
#[derive(Clone)]
struct WireFields {
    magic: u32,
    version: u16,
    kind: u16,
    flags: u16,
    direction: u16,
    cpu: u32,
    seq: u64,
    exit_ns: u64,
    epoch: u64,
    token: u64,
    entry_ns: u64,
    pages: i32,
    result: i32,
    caller: u16,
    cls: u16,
    label: u16,
    reserved: u16,
}

impl WireFields {
    fn base() -> Self {
        Self {
            magic: 0x524A_564D,
            version: 1,
            kind: 1,
            flags: 1,
            direction: 1,
            cpu: 0,
            seq: 0,
            exit_ns: 30,
            epoch: 1,
            token: 9,
            entry_ns: 20,
            pages: 3,
            result: -5,
            caller: 0,
            cls: 0,
            label: 0,
            reserved: 0,
        }
    }

    /// Little-endian packing in wire order (`<IHHHHIQQQQQiiHHHH`).
    fn encode(&self) -> [u8; 72] {
        let mut out = [0u8; 72];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.kind.to_le_bytes());
        out[8..10].copy_from_slice(&self.flags.to_le_bytes());
        out[10..12].copy_from_slice(&self.direction.to_le_bytes());
        out[12..16].copy_from_slice(&self.cpu.to_le_bytes());
        out[16..24].copy_from_slice(&self.seq.to_le_bytes());
        out[24..32].copy_from_slice(&self.exit_ns.to_le_bytes());
        out[32..40].copy_from_slice(&self.epoch.to_le_bytes());
        out[40..48].copy_from_slice(&self.token.to_le_bytes());
        out[48..56].copy_from_slice(&self.entry_ns.to_le_bytes());
        out[56..60].copy_from_slice(&self.pages.to_le_bytes());
        out[60..64].copy_from_slice(&self.result.to_le_bytes());
        out[64..66].copy_from_slice(&self.caller.to_le_bytes());
        out[66..68].copy_from_slice(&self.cls.to_le_bytes());
        out[68..70].copy_from_slice(&self.label.to_le_bytes());
        out[70..72].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }
}

/// The exact 6-positive / 89-negative vector set `test_wire.py` checks.
fn native_vectors() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let base = WireFields::base();
    let mut valid = vec![base.encode().to_vec()];
    let mut extra = base.clone();
    extra.pages = i32::MIN;
    extra.result = i32::MAX;
    valid.push(extra.encode().to_vec());
    let mut extra = base.clone();
    extra.flags = 0;
    extra.token = 0;
    extra.entry_ns = 0;
    valid.push(extra.encode().to_vec());
    let mut extra = base.clone();
    extra.direction = 2;
    extra.cpu = 42;
    extra.seq = 9007199254740993;
    extra.epoch = 23;
    extra.token = 9007199254740993;
    extra.caller = 1;
    extra.cls = 1;
    extra.label = 1;
    valid.push(extra.encode().to_vec());
    let mut extra = base.clone();
    extra.caller = 1;
    extra.cls = 2;
    extra.label = 6;
    valid.push(extra.encode().to_vec());
    let mut extra = base.clone();
    extra.caller = 1;
    extra.cls = 3;
    extra.label = 10;
    valid.push(extra.encode().to_vec());

    let full = base.encode().to_vec();
    let mut invalid: Vec<Vec<u8>> = (0..72).map(|i| full[..i].to_vec()).collect();
    let mut long = full.clone();
    long.push(0);
    invalid.push(long);
    let mutations: [(&str, u64); 13] = [
        ("magic", 0),
        ("version", 2),
        ("kind", 2),
        ("flags", 2),
        ("direction", 0),
        ("cpu", 1048576),
        ("epoch", 0),
        ("token", 0),
        ("entry_ns", 31),
        ("caller", 5),
        ("cls", 1),
        ("label", 1),
        ("reserved", 1),
    ];
    for (field, value) in mutations {
        let mut mutated = base.clone();
        match field {
            "magic" => mutated.magic = value as u32,
            "version" => mutated.version = value as u16,
            "kind" => mutated.kind = value as u16,
            "flags" => mutated.flags = value as u16,
            "direction" => mutated.direction = value as u16,
            "cpu" => mutated.cpu = value as u32,
            "epoch" => mutated.epoch = value,
            "token" => mutated.token = value,
            "entry_ns" => mutated.entry_ns = value,
            "caller" => mutated.caller = value as u16,
            "cls" => mutated.cls = value as u16,
            "label" => mutated.label = value as u16,
            "reserved" => mutated.reserved = value as u16,
            _ => unreachable!("frozen mutation table"),
        }
        invalid.push(mutated.encode().to_vec());
    }
    let mut extra = base.clone();
    extra.caller = 1;
    extra.cls = 2;
    extra.label = 1;
    invalid.push(extra.encode().to_vec());
    let mut extra = base;
    extra.flags = 0;
    invalid.push(extra.encode().to_vec());
    let mut extra = WireFields::base();
    extra.token = u64::MAX;
    invalid.push(extra.encode().to_vec());
    (valid, invalid)
}

/// Render a decoded result exactly like the C oracle's `%u %u %llu ...` line.
fn render_oracle_line(result: &JournalResult) -> String {
    format!(
        "{} {} {} {} {} {} {} {} {} {} {} {} {}\n",
        result.direction,
        result.cpu,
        result.sequence,
        result.exit_ns,
        result.epoch,
        result.token,
        result.entry_ns,
        result.pages,
        result.native_result,
        result.caller_status,
        result.caller_class,
        result.caller_label,
        u8::from(result.matched),
    )
}

#[test]
fn rust_decoder_matches_c_oracle_on_every_native_vector() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let scratch = std::env::temp_dir().join(format!("journal-diff-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch dir");
    let source = scratch.join("decode.c");
    std::fs::write(&source, DECODE_C).expect("oracle source");
    let binary = scratch.join("decode");
    // Same compile as tests/journal/test_wire.py, sanitizers included.
    let compile = Command::new("clang")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-I",
        ])
        .arg(&root)
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("clang must compile the carried oracle");
    assert!(
        compile.status.success(),
        "oracle compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let version = Command::new("clang")
        .arg("--version")
        .output()
        .expect("clang version");
    println!(
        "oracle compiler: {}",
        String::from_utf8_lossy(&version.stdout)
            .lines()
            .next()
            .unwrap_or("unknown")
    );

    let run_oracle = |input: &[u8]| {
        let mut child = Command::new(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("UBSAN_OPTIONS", "halt_on_error=1")
            .spawn()
            .expect("oracle spawn");
        child
            .stdin
            .as_mut()
            .expect("oracle stdin")
            .write_all(input)
            .expect("oracle write");
        child.wait_with_output().expect("oracle wait")
    };

    // The oracle pins its own base vector first, exactly as test_wire.py does.
    let base = WireFields::base().encode().to_vec();
    let oracle = run_oracle(&base);
    assert_eq!(oracle.status.code(), Some(0));
    assert_eq!(oracle.stdout, b"1 0 0 30 1 9 20 3 -5 0 0 0 1\n");
    assert!(oracle.stderr.is_empty());

    let (valid, invalid) = native_vectors();
    assert_eq!(valid.len(), 6, "positive vector count drifted");
    assert_eq!(invalid.len(), 89, "negative vector count drifted");
    for (index, vector) in valid.iter().enumerate() {
        let oracle = run_oracle(vector);
        assert_eq!(oracle.status.code(), Some(0), "positive vector {index}");
        assert!(oracle.stderr.is_empty(), "positive vector {index}");
        let decoded = decode_journal(vector).expect("Rust must accept positive vector");
        assert_eq!(
            render_oracle_line(&decoded).as_bytes(),
            oracle.stdout.as_slice(),
            "positive vector {index} differs"
        );
    }
    for (index, vector) in invalid.iter().enumerate() {
        let oracle = run_oracle(vector);
        assert_eq!(oracle.status.code(), Some(2), "negative vector {index}");
        assert!(oracle.stdout.is_empty(), "negative vector {index}");
        assert!(oracle.stderr.is_empty(), "negative vector {index}");
        assert!(
            decode_journal(vector).is_err(),
            "Rust must refuse negative vector {index}"
        );
    }
    println!("differential: 6 positive, 89 negative vectors; zero differences");
    std::fs::remove_dir_all(&scratch).ok();
}
