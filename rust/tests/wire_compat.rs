// SPDX-License-Identifier: GPL-3.0-or-later
//! Wire-compat differential: the Rust `memveil-ebpf-common` decoders must
//! agree field-for-field with the C reference decoders on every wire record
//! of the checked-in corpora.
//!
//! Method per corpus:
//!
//! * `tests/fixtures/attempts/corpus.bin`: the test compiles
//!   `tests/native/test_attempt_decode.c` with the host C toolchain into a
//!   fresh temporary directory, runs it over the corpus, and renders the
//!   expected dump line for every `payload` record from
//!   `decode_attempt`, byte-compared against the C dump line. `tctx`
//!   records carry a 24-byte offsets table followed by a raw context: the
//!   table prefix is compared as Rust `decode_offsets_table` validity
//!   against the C `CTX_TABLE_BAD` verdict (the C harness reports table
//!   failure only through that verdict). Raw `ctx` records are not wire
//!   input and the context extractor lands in a later task, so they are
//!   counted, not compared.
//! * `tests/fixtures/lifecycle-wire/corpus.bin`: same shape with
//!   `tests/native/test_lifecycle_decode.c`; `lifecycle` and `copy`
//!   records are byte-compared from `decode_lifecycle` / `decode_copy`,
//!   while 25-byte `effective` rule inputs (not wire records) are counted,
//!   not compared.
//! * `tests/fixtures/lifecycle/`: analyzer-layer JSON events consumed only
//!   by the analyzer test suites; no wire decoder on either side reads
//!   them, so no differential applies. The test pins that directory shape
//!   fail-closed instead (any future `corpus.bin` there must gain
//!   differential coverage).
//!
//! The C oracles self-validate against `corpus.txt` and exit nonzero on
//! any mismatch, so a green run also proves the C baseline is consistent;
//! the differential itself compares live Rust output against live C output,
//! never against the checked-in expectations.

use memveil_ebpf_common::{
    DecodeError, decode_attempt, decode_copy, decode_lifecycle, decode_offsets_table,
};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Repository root: the Rust workspace lives in `rust/`, one level below it.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust/ must have a parent directory")
        .to_path_buf()
}

fn read_u32_le(blob: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(blob[off..off + 4].try_into().expect("u32 slice"))
}

/// Split a `corpus.bin` blob into `(kind, bytes)` records; any truncation or
/// trailing bytes fail the test.
fn split_corpus(blob: &[u8], corpus: &str) -> Vec<(u32, Vec<u8>)> {
    assert!(blob.len() >= 4, "{corpus}: blob shorter than count header");
    let count = read_u32_le(blob, 0) as usize;
    let mut off = 4;
    let mut out = Vec::new();
    for idx in 0..count {
        assert!(
            off + 8 <= blob.len(),
            "{corpus}: record {idx} header truncated"
        );
        let kind = read_u32_le(blob, off);
        let len = read_u32_le(blob, off + 4) as usize;
        assert!(
            off + 8 + len <= blob.len(),
            "{corpus}: record {idx} bytes truncated"
        );
        out.push((kind, blob[off + 8..off + 8 + len].to_vec()));
        off += 8 + len;
    }
    assert_eq!(off, blob.len(), "{corpus}: trailing bytes in corpus.bin");
    out
}

/// Fresh per-test scratch directory under the system temp dir.
fn workdir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("memveil-wire-compat-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create workdir");
    dir
}

/// Compile one checked-in C oracle with the host toolchain. Flags mirror the
/// repository native build minus sanitizers; the oracle self-validates, so a
/// successful exit proves the build decodes correctly. Honors `CC`, else `cc`.
fn compile_oracle(root: &Path, name: &str, work: &Path) -> PathBuf {
    let src = root.join("tests/native").join(format!("{name}.c"));
    let out = work.join(name);
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let output = Command::new(&cc)
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(root.join("bpf/include"))
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap_or_else(|error| panic!("spawning {cc}: {error}"));
    assert!(
        output.status.success(),
        "compiling {name} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    out
}

/// Run an oracle over its corpus; returns the dump lines. A nonzero exit
/// (any C-vs-expectation mismatch) fails the test with the oracle output.
fn run_oracle(bin: &Path, corpus_bin: &Path, corpus_txt: &Path, dump: &Path) -> Vec<String> {
    let output = Command::new(bin)
        .arg(corpus_bin)
        .arg(corpus_txt)
        .arg(dump)
        .output()
        .unwrap_or_else(|error| panic!("spawning {}: {error}", bin.display()));
    assert!(
        output.status.success(),
        "oracle {} failed:\nstdout:\n{}\nstderr:\n{}",
        bin.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(dump).expect("read oracle dump");
    text.lines().map(str::to_string).collect()
}

/// Rust decode failures in the shared `PAY_*` vocabulary the C dump uses.
fn verdict_name(error: DecodeError) -> &'static str {
    match error {
        DecodeError::Short => "PAY_SHORT",
        DecodeError::Long => "PAY_LONG",
        DecodeError::Magic => "PAY_MAGIC",
        DecodeError::Version => "PAY_VERSION",
        DecodeError::Flags => "PAY_FLAGS",
        DecodeError::NameLen => "PAY_NAMELEN",
        DecodeError::Nul => "PAY_NUL",
        DecodeError::Pad => "PAY_PAD",
        DecodeError::Kind => "PAY_KIND",
        DecodeError::Dir => "PAY_DIR",
        DecodeError::Reason => "PAY_REASON",
        DecodeError::Range => "PAY_RANGE",
        DecodeError::TableBad => panic!("offsets-table error from a wire record decode"),
    }
}

/// Lowercase `%02x` per byte, matching the C dump's name rendering.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Expected C dump line for one attempt payload from the Rust decode.
fn render_attempt(idx: usize, bytes: &[u8]) -> String {
    match decode_attempt(bytes) {
        Ok(got) => format!(
            "{idx} payload OK size={} force={} seq={} ktime={} namelen={} name={}",
            got.size,
            u8::from(got.force),
            got.seq,
            got.ktime,
            got.name_len,
            hex(&got.name[..usize::from(got.name_len)]),
        ),
        Err(error) => format!("{idx} payload {}", verdict_name(error)),
    }
}

/// Expected C dump line for one lifecycle record from the Rust decode.
fn render_lifecycle(idx: usize, bytes: &[u8]) -> String {
    match decode_lifecycle(bytes) {
        Ok(got) => format!(
            "{idx} lifecycle OK kind={} ok={} skip={} dir={} seq={} ktime={} size={} gen={}",
            got.kind,
            u8::from(got.ok),
            u8::from(got.skip_sync),
            got.dir,
            got.seq,
            got.ktime,
            got.size,
            got.generation,
        ),
        Err(error) => format!("{idx} lifecycle {}", verdict_name(error)),
    }
}

/// Expected C dump line for one copy record from the Rust decode.
fn render_copy(idx: usize, bytes: &[u8]) -> String {
    match decode_copy(bytes) {
        Ok(got) => format!(
            "{idx} copy OK kind={} todevice={} known={} clamped={} earlyzero={} offsetpast={} privatepool={} dir={} reason={} seq={} ktime={} requested={} effective={}",
            got.kind,
            u8::from(got.to_device),
            u8::from(got.known),
            u8::from(got.clamped),
            u8::from(got.early_zero),
            u8::from(got.offset_past),
            u8::from(got.private_pool),
            got.dir,
            got.reason,
            got.seq,
            got.ktime,
            got.requested,
            got.effective,
        ),
        Err(error) => format!("{idx} copy {}", verdict_name(error)),
    }
}

/// Check a C dump line belongs to record `idx` with tag `tag`; returns its
/// whitespace-separated words for verdict inspection.
fn split_c_line<'a>(line: &'a str, idx: usize, tag: &str) -> Vec<&'a str> {
    let words: Vec<&str> = line.split_whitespace().collect();
    assert!(words.len() >= 3, "record {idx}: short C dump line {line:?}");
    assert_eq!(
        words[0].parse::<usize>().expect("dump index"),
        idx,
        "record {idx}: C dump misaligned"
    );
    assert_eq!(words[1], tag, "record {idx}: C dump misaligned");
    words
}

#[test]
fn attempts_payload_matches_c_dump() {
    let root = repo_root();
    let work = workdir("attempts");
    let corpus = root.join("tests/fixtures/attempts");
    let bin = compile_oracle(&root, "test_attempt_decode", &work);
    let dump = run_oracle(
        &bin,
        &corpus.join("corpus.bin"),
        &corpus.join("corpus.txt"),
        &work.join("c.dump"),
    );
    let blob = std::fs::read(corpus.join("corpus.bin")).expect("read corpus.bin");
    let records = split_corpus(&blob, "tests/fixtures/attempts");
    assert_eq!(dump.len(), records.len(), "dump/record count");
    let mut compared = 0u32;
    let mut ctx_skipped = 0u32;
    let mut tctx_tables = 0u32;
    for (idx, (kind, bytes)) in records.iter().enumerate() {
        match kind {
            2 => {
                assert_eq!(render_attempt(idx, bytes), dump[idx], "record {idx}");
                compared += 1;
            }
            1 => {
                split_c_line(&dump[idx], idx, "ctx");
                ctx_skipped += 1;
            }
            3 => {
                // The leading 24 bytes are the load-time offsets table;
                // the trailing context decodes in a later task. The C
                // harness reports table failure only as CTX_TABLE_BAD, so
                // Rust table validity must match that verdict exactly.
                let words = split_c_line(&dump[idx], idx, "tctx");
                assert!(
                    bytes.len() >= 24,
                    "record {idx}: tctx shorter than offsets table"
                );
                let table = decode_offsets_table(&bytes[..24]);
                assert_eq!(
                    table.is_err(),
                    words[2] == "CTX_TABLE_BAD",
                    "record {idx}: Rust table validity must match the C verdict"
                );
                if let Ok(offsets) = table {
                    assert_eq!(offsets.loc_off, read_u32_le(bytes, 8), "record {idx}");
                    assert_eq!(offsets.size_off, read_u32_le(bytes, 12), "record {idx}");
                    assert_eq!(offsets.force_off, read_u32_le(bytes, 16), "record {idx}");
                    assert_eq!(offsets.fixed_end, read_u32_le(bytes, 20), "record {idx}");
                }
                tctx_tables += 1;
            }
            _ => panic!("record {idx}: unexpected kind {kind}"),
        }
    }
    assert!(
        compared > 0 && ctx_skipped > 0 && tctx_tables > 0,
        "compared={compared} ctx={ctx_skipped} tctx={tctx_tables}: every class must occur"
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn lifecycle_copy_matches_c_dump() {
    let root = repo_root();
    let work = workdir("lifecycle-wire");
    let corpus = root.join("tests/fixtures/lifecycle-wire");
    let bin = compile_oracle(&root, "test_lifecycle_decode", &work);
    let dump = run_oracle(
        &bin,
        &corpus.join("corpus.bin"),
        &corpus.join("corpus.txt"),
        &work.join("c.dump"),
    );
    let blob = std::fs::read(corpus.join("corpus.bin")).expect("read corpus.bin");
    let records = split_corpus(&blob, "tests/fixtures/lifecycle-wire");
    assert_eq!(dump.len(), records.len(), "dump/record count");
    let mut lifecycle_compared = 0u32;
    let mut copy_compared = 0u32;
    let mut effective_skipped = 0u32;
    for (idx, (kind, bytes)) in records.iter().enumerate() {
        match kind {
            1 => {
                assert_eq!(render_lifecycle(idx, bytes), dump[idx], "record {idx}");
                lifecycle_compared += 1;
            }
            2 => {
                assert_eq!(render_copy(idx, bytes), dump[idx], "record {idx}");
                copy_compared += 1;
            }
            3 => {
                // 25-byte effective-rule inputs, not wire records; the
                // rule helper lands in a later task.
                assert_eq!(bytes.len(), 25, "record {idx}: effective input length");
                split_c_line(&dump[idx], idx, "effective");
                effective_skipped += 1;
            }
            _ => panic!("record {idx}: unexpected kind {kind}"),
        }
    }
    assert!(
        lifecycle_compared > 0 && copy_compared > 0 && effective_skipped > 0,
        "lifecycle={lifecycle_compared} copy={copy_compared} effective={effective_skipped}: every class must occur"
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn lifecycle_json_corpus_holds_no_wire_fixtures() {
    // `tests/fixtures/lifecycle/` holds analyzer-layer JSON events (session
    // plus per-scenario event streams) consumed only by the analyzer suites;
    // no wire decoder on either side reads them, so no differential applies.
    // Pin that shape fail-closed: a future `corpus.bin` here must gain
    // differential coverage instead of silently escaping it.
    let dir = repo_root().join("tests/fixtures/lifecycle");
    let mut ndjson = 0u32;
    let mut stack = vec![dir];
    while let Some(top) = stack.pop() {
        let entries = std::fs::read_dir(&top)
            .unwrap_or_else(|error| panic!("reading {}: {error}", top.display()));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            match path.file_name().and_then(|name| name.to_str()) {
                Some("corpus.bin") | Some("corpus.txt") => panic!(
                    "wire fixture {} needs differential coverage",
                    path.display()
                ),
                _ => {}
            }
            if path.extension().and_then(|ext| ext.to_str()) == Some("ndjson") {
                ndjson += 1;
            }
        }
    }
    assert!(
        ndjson > 0,
        "expected ndjson fixtures under tests/fixtures/lifecycle"
    );
}
