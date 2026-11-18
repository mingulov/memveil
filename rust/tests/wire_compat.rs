// SPDX-License-Identifier: GPL-3.0-or-later
//! Wire-compat differential: the Rust `memveil-ebpf-common` decoders must
//! agree field-for-field with the C reference decoders on every wire record
//! of the checked-in corpora.
//!
//! Oracle setup. Each differential test compiles its checked-in C oracle
//! (`tests/native/test_attempt_decode.c` or
//! `tests/native/test_lifecycle_decode.c`, plus the shared
//! `bpf/include/memveil_events.h` they execute) with the host C toolchain
//! into a fresh temporary directory and runs it over the corpus. The exact C
//! sources are pinned by FNV-1a hash (`pin_oracle_sources`): any C drift
//! fails loudly until the pin is updated deliberately. `CC` selects the host
//! compiler (`cc` by default; must accept `-std=c11 -O2 -Wall -Wextra -Werror
//! -fsanitize=address,undefined -fno-omit-frame-pointer` and `--version`);
//! the resolved `<cc> --version` identity is logged and
//! attached to every oracle failure. The oracles self-validate against
//! `corpus.txt` and print `<tool>: <count> vectors passed` only after
//! checking every vector and fully consuming both corpus files, so the tests
//! assert that stdout line (with the exact record count) and additionally
//! require every C dump verdict word to equal the `corpus.txt` verdict word.
//!
//! Comparison boundaries. `payload`, `lifecycle`, and `copy` records are
//! byte-compared field-for-field: the Rust decode renders the expected C dump
//! line. The remaining classes have a partial or no Rust decoder in Plan 1,
//! and the tests pin exactly what each side emits:
//!
//! * `ctx` / `tctx ... OK ...` lines: the C dump carries the decoded fields
//!   of the extractor-produced payload. The test rebuilds those exact 98 wire
//!   bytes from the C-emitted values (layout pinned from the C header, not
//!   from the Rust crate) and runs the real Task 3 `decode_attempt` over
//!   them, comparing every C-emitted field against Rust output. The extractor
//!   mapping itself (raw ctx bytes to produced payload) has no Rust
//!   counterpart in Plan 1, so reject verdicts are pinned to the exact C
//!   `CTX_*` vocabulary instead; that residual is reported as a waiver
//!   request in the task report, not granted here.
//! * `tctx` offsets tables: the C dump provably carries no table field values
//!   (`dump_ok` emits only decoded-attempt fields; reject lines carry only
//!   the verdict word), so the table signal is exactly the `CTX_TABLE_BAD`
//!   verdict, raised solely by `mv_validate_offsets` failure. The test
//!   asserts Rust `decode_offsets_table` validity matches that verdict on
//!   every record, with both verdict sides present in the corpus.
//! * `effective` lines: the C oracle provably always emits `OK` plus the four
//!   rule outputs, and no Rust effective-rule helper exists in Plan 1, so the
//!   full line shape and value domains are pinned, not differentially
//!   compared (waiver requested in the task report).
//! * `tests/fixtures/lifecycle/`: analyzer-layer JSON events consumed only by
//!   the analyzer suites; no wire decoder on either side reads them, so no
//!   differential applies. The test pins that directory shape fail-closed
//!   instead (any future `corpus.bin` there must gain differential coverage).
//!
//! A deterministic oracle-free test (`renders_detect_single_byte_divergence`)
//! proves the byte-comparisons are sensitive: one flipped wire byte changes
//! the Rust render, a corrupted magic flips `OK` to `PAY_MAGIC`, and every
//! `DecodeError` maps to a distinct `PAY_*` word.

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
///
/// The name carries a nonce (process id, wall-clock nanos, and a per-process
/// counter), and any stale directory already at that path is removed before
/// use: a previous crashed run's oracle binary or dump must never be reused.
/// Clear-or-fail — a removal error fails the test loudly instead of reusing.
fn workdir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "memveil-wire-compat-{}-{nanos:x}-{nonce}-{tag}",
        std::process::id()
    ));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("clear stale workdir");
    }
    std::fs::create_dir_all(&dir).expect("create workdir");
    dir
}

/// FNV-1a 64-bit hash (std-only oracle-source pin; see `pin_oracle_sources`).
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Pinned oracle sources: `(tree-relative path, FNV-1a 64 of the file bytes)`.
///
/// The `.c` oracles plus the shared `memveil_events.h` header that carries the
/// decode/extract/rule logic they execute. Recompute after an intentional C
/// change with:
/// ```sh
/// python3 -c "
/// import sys
/// h = 14695981039346656037
/// for byte in open(sys.argv[1], 'rb').read():
///     h = ((h ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
/// print(hex(h))
/// " <file>
/// ```
/// and record the new C identity in the commit message.
const ORACLE_SOURCES: [(&str, u64); 3] = [
    ("tests/native/test_attempt_decode.c", 0x7ca361be94da8bde),
    ("tests/native/test_lifecycle_decode.c", 0x23412090e733dbc0),
    ("bpf/include/memveil_events.h", 0xfd99b99a9957d035),
];

/// Fail unless every pinned oracle source still hashes to its recorded value.
/// The differential compares against live C output, so an unpinned C change
/// (new verdict, reshaped dump, altered check order) could silently narrow or
/// skew it; this pin forces such changes through a deliberate test update.
fn pin_oracle_sources(root: &Path) {
    for (rel, want) in ORACLE_SOURCES {
        let bytes = std::fs::read(root.join(rel))
            .unwrap_or_else(|error| panic!("reading pinned oracle source {rel}: {error}"));
        let got = fnv1a64(&bytes);
        assert_eq!(
            got, want,
            "{rel}: C oracle source drift (got {got:#x}, want {want:#x}); \
             update the pin deliberately after an intentional C change and \
             record the new C identity in the commit message"
        );
    }
}

/// Compiler used for the oracle build: `$CC` when set, else `cc`.
fn cc_program() -> String {
    std::env::var("CC").unwrap_or_else(|_| "cc".to_string())
}

/// First line of `<cc> --version`, best-effort; attached to every oracle
/// failure so the exact compiler behind a green or red run is never in doubt.
fn cc_identity() -> String {
    let cc = cc_program();
    let first = Command::new(&cc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(str::to_string)
        })
        .unwrap_or_else(|| "<--version unavailable>".to_string());
    format!("`{cc}` ({first})")
}

/// Compile one checked-in C oracle with the host toolchain. Flags mirror the
/// repository native build plus AddressSanitizer/UBSan: the oracle parses
/// untrusted corpus bytes, so a sanitizer abort fails the test loudly instead
/// of letting an oracle-side over-read skew the differential. The oracle
/// self-validates, so a successful exit proves the build decodes correctly.
///
/// Allowed `CC`: any host C11 compiler (default `cc`); set `CC` to override.
/// The value must accept `-std=c11 -O2 -Wall -Wextra -Werror
/// -fsanitize=address,undefined -fno-omit-frame-pointer` and `--version`.
/// The resolved compiler identity is recorded in the test log and attached to
/// every oracle-build failure, so an exotic `CC` can break the build loudly
/// but never skew it silently.
fn compile_oracle(root: &Path, name: &str, work: &Path, cc_id: &str) -> PathBuf {
    pin_oracle_sources(root);
    let cc = cc_program();
    eprintln!("wire-compat: compiling {name} with {cc_id}");
    let src = root.join("tests/native").join(format!("{name}.c"));
    let out = work.join(name);
    let output = Command::new(&cc)
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
        ])
        .arg("-I")
        .arg(root.join("bpf/include"))
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap_or_else(|error| panic!("spawning {cc} ({cc_id}): {error}"));
    assert!(
        output.status.success(),
        "compiling {name} with {cc_id} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    out
}

/// What `run_oracle` must observe on a successful oracle run: the tool tag
/// and record count of the `<tool>: <count> vectors passed` stdout line plus
/// any extra stdout lines that must be present.
struct OracleExpect {
    tool: &'static str,
    expected_count: usize,
    extra_stdout: &'static [&'static str],
}

/// Run an oracle over its corpus; returns the dump lines. A nonzero exit
/// (any C-vs-expectation mismatch) fails the test with the oracle output.
/// The oracle prints `<tool>: <count> vectors passed` only after validating
/// every vector against `corpus.txt` and fully consuming both corpus files,
/// so asserting that line (plus any `extra_stdout` lines) ties the
/// differential to the checked-in expectations.
fn run_oracle(
    bin: &Path,
    corpus_bin: &Path,
    corpus_txt: &Path,
    dump: &Path,
    cc_id: &str,
    expect: &OracleExpect,
) -> Vec<String> {
    let output = Command::new(bin)
        .arg(corpus_bin)
        .arg(corpus_txt)
        .arg(dump)
        .output()
        .unwrap_or_else(|error| panic!("spawning {}: {error}", bin.display()));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "oracle {} (built with {cc_id}) failed:\nstdout:\n{stdout}\nstderr:\n{stderr}",
        bin.display(),
    );
    let vectors_line = format!("{}: {} vectors passed", expect.tool, expect.expected_count);
    assert!(
        stdout.lines().any(|line| line == vectors_line),
        "oracle {} (built with {cc_id}) stdout must contain {vectors_line:?}; got:\n{stdout}",
        bin.display(),
    );
    for want in expect.extra_stdout {
        assert!(
            stdout.lines().any(|line| line == *want),
            "oracle {} (built with {cc_id}) stdout must contain {want:?}; got:\n{stdout}",
            bin.display(),
        );
    }
    let text = std::fs::read_to_string(dump).expect("read oracle dump");
    text.lines().map(str::to_string).collect()
}

/// Third whitespace word (the verdict) of every non-comment `corpus.txt` line.
fn corpus_verdicts(corpus_txt: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(corpus_txt).expect("read corpus.txt");
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            line.split_whitespace()
                .nth(2)
                .unwrap_or_else(|| panic!("verdict-less corpus.txt line: {line:?}"))
                .to_string()
        })
        .collect()
}

/// Assert the C dump verdict of every record equals the checked-in
/// `corpus.txt` verdict. The oracle already enforces this internally and exits
/// nonzero otherwise, so this pins the test's dump/corpus alignment instead of
/// trusting it.
fn check_dump_matches_corpus_verdicts(dump: &[String], corpus_txt: &Path, corpus: &str) {
    let expected = corpus_verdicts(corpus_txt);
    assert_eq!(
        expected.len(),
        dump.len(),
        "{corpus}: corpus.txt/dump line count"
    );
    for (idx, (line, want)) in dump.iter().zip(expected.iter()).enumerate() {
        let got = line
            .split_whitespace()
            .nth(2)
            .unwrap_or_else(|| panic!("record {idx}: short C dump line {line:?}"));
        assert_eq!(got, want, "record {idx}: C dump verdict vs corpus.txt");
    }
}

/// Rust decode failures in the shared `PAY_*` vocabulary the C dump uses.
/// `TableBad` is unreachable from the wire-record decoders (only
/// `decode_offsets_table` raises it), but the mapping stays total: the token
/// the C dump never emits would surface as a byte mismatch in the renders,
/// never as a panic here.
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
        DecodeError::TableBad => "PAY_TABLE_BAD",
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

/// Parse one `key=<u64>` dump word; the C dump emits decimal u64s.
fn parse_kv_u64(word: &str, key: &str, idx: usize, line: &str) -> u64 {
    word.strip_prefix(key)
        .unwrap_or_else(|| panic!("record {idx}: expected `{key}..` in {line:?}"))
        .parse()
        .unwrap_or_else(|error| panic!("record {idx}: bad `{key}` value: {error}"))
}

/// Parse one `key=<0|1>` dump word.
fn parse_kv_bit(word: &str, key: &str, idx: usize, line: &str) -> bool {
    match parse_kv_u64(word, key, idx, line) {
        0 => false,
        1 => true,
        other => panic!("record {idx}: bad `{key}` bit: {other}"),
    }
}

/// Lowercase hex decode; rejects anything but `[0-9a-f]`, pinning the C `%02x`
/// rendering (an uppercase or otherwise reshaped C dump fails loudly here).
fn unhex(hex: &str, idx: usize, line: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "record {idx}: odd hex length in {line:?}");
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks(2) {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("record {idx}: non-lowercase-hex byte in {line:?}"),
        };
        out.push(digit(pair[0]) * 16 + digit(pair[1]));
    }
    out
}

/// Every non-OK verdict the C reference extractor can emit on a `ctx`/`tctx`
/// dump line: the `CTX_*` half of `reason_name` in
/// `tests/native/test_attempt_decode.c` (lines 34-81). Reject dump lines carry
/// exactly one of these words and no fields (same file, line 395).
const CTX_VERDICTS: [&str; 8] = [
    "CTX_SHORT",
    "CTX_LOC_OOB",
    "CTX_DLEN_ZERO",
    "CTX_DLEN_BIG",
    "CTX_NUL_MISSING",
    "CTX_NUL_EARLY",
    "CTX_FORCE_BAD",
    "CTX_TABLE_BAD",
];

/// `KTIME_CTX_BASE` (`tests/native/test_attempt_decode.c:29`): ctx-extracted
/// payloads use `seq = <record idx>`, `ktime = BASE + <record idx>` so dumps
/// stay deterministic (same file, lines 386-388).
const CTX_KTIME_BASE: u64 = 1_000_000_000;

/// Fields of one C `ctx`/`tctx ... OK ...` dump line.
struct CtxOkFields {
    size: u64,
    force: bool,
    seq: u64,
    ktime: u64,
    name: Vec<u8>,
}

/// Check one C `ctx`/`tctx` dump line against the exact shape the oracle emits:
/// `<idx> <tag> OK size=<u64> force=<0|1> seq=<u64> ktime=<u64> namelen=<u16>
/// name=<hex>` (`dump_ok` at `tests/native/test_attempt_decode.c:273-292`),
/// or the 3-word `<idx> <tag> <CTX_*>` reject form (same file, line 395).
/// `split_c_line` must have validated the index and tag first.
///
/// Returns the OK fields for the reconstruction differential, or `None` for a
/// vocabulary-pinned reject line.
fn check_ctx_dump_line(words: &[&str], idx: usize, line: &str) -> Option<CtxOkFields> {
    if words[2] != "OK" {
        assert_eq!(
            words.len(),
            3,
            "record {idx}: reject dump shape in {line:?}"
        );
        assert!(
            CTX_VERDICTS.contains(&words[2]),
            "record {idx}: C verdict {:?} outside the pinned CTX vocabulary",
            words[2]
        );
        return None;
    }
    assert_eq!(words.len(), 9, "record {idx}: OK dump shape in {line:?}");
    let size = parse_kv_u64(words[3], "size=", idx, line);
    let force = parse_kv_bit(words[4], "force=", idx, line);
    let seq = parse_kv_u64(words[5], "seq=", idx, line);
    let ktime = parse_kv_u64(words[6], "ktime=", idx, line);
    let namelen = parse_kv_u64(words[7], "namelen=", idx, line);
    assert!(
        namelen <= 63,
        "record {idx}: namelen {namelen} above MV_NAME_MAX in {line:?}"
    );
    let name_hex = words[8]
        .strip_prefix("name=")
        .unwrap_or_else(|| panic!("record {idx}: expected `name=..` in {line:?}"));
    let namelen_usize = usize::try_from(namelen).expect("namelen fits usize");
    assert_eq!(
        name_hex.len(),
        2 * namelen_usize,
        "record {idx}: name hex length in {line:?}"
    );
    let name = unhex(name_hex, idx, line);
    // Deterministic extractor identity: both sides compute seq/ktime from the
    // record index (C file header comment, lines 14-16); any skew fails here.
    assert_eq!(
        seq, idx as u64,
        "record {idx}: ctx seq must equal the record index"
    );
    assert_eq!(
        ktime,
        CTX_KTIME_BASE + idx as u64,
        "record {idx}: ctx ktime must equal BASE+idx"
    );
    Some(CtxOkFields {
        size,
        force,
        seq,
        ktime,
        name,
    })
}

/// Rebuild the 98-byte extractor-produced payload a C `ctx`/`tctx OK` line
/// describes, using the fixed product layout pinned from
/// `bpf/include/memveil_events.h:41-55` (`MV_PAYLOAD_LEN`, `MV_MAGIC`,
/// `MV_VERSION`, `MV_FLAG_FORCE`, `MV_OFF_*`) and the packing order in
/// `ref_extract` (`tests/native/test_attempt_decode.c:138-156`).
///
/// The field *values* come from the live C dump; only the byte layout is
/// pinned. Feeding the rebuilt wire bytes to the Rust `decode_attempt` then
/// compares every C-emitted field against real Task 3 decoder output. What
/// this cannot cover — the extractor mapping from raw ctx bytes to these
/// fields — has no Rust counterpart in Plan 1 (see the module docs) and stays
/// vocabulary-pinned pending a waiver decision.
fn rebuild_produced_payload(fields: &CtxOkFields) -> [u8; 98] {
    const MAGIC: u32 = 0x3741_564D; // MV_MAGIC "MVA7"
    const VERSION: u16 = 1; // MV_VERSION
    let mut out = [0u8; 98];
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6] = u8::from(fields.force); // MV_FLAG_FORCE = 0x1; out[7] stays 0
    out[8..16].copy_from_slice(&fields.seq.to_le_bytes());
    out[16..24].copy_from_slice(&fields.ktime.to_le_bytes());
    out[24..32].copy_from_slice(&fields.size.to_le_bytes());
    let namelen = u16::try_from(fields.name.len()).expect("namelen fits u16");
    out[32..34].copy_from_slice(&namelen.to_le_bytes());
    out[34..34 + fields.name.len()].copy_from_slice(&fields.name);
    // NUL terminator plus zero padding are already in place: `out` starts zeroed.
    out
}

/// Compare every field of one C `ctx`/`tctx OK` line against the Rust
/// `decode_attempt` output over the rebuilt produced payload.
fn check_ctx_ok_against_rust(idx: usize, fields: &CtxOkFields, line: &str) {
    let payload = rebuild_produced_payload(fields);
    let got = decode_attempt(&payload).unwrap_or_else(|error| {
        panic!("record {idx}: Rust rejects C-produced payload ({error:?}): {line:?}")
    });
    assert_eq!(got.size, fields.size, "record {idx}: size");
    assert_eq!(got.force, fields.force, "record {idx}: force");
    assert_eq!(got.seq, fields.seq, "record {idx}: seq");
    assert_eq!(got.ktime, fields.ktime, "record {idx}: ktime");
    assert_eq!(
        usize::from(got.name_len),
        fields.name.len(),
        "record {idx}: namelen"
    );
    assert_eq!(
        &got.name[..fields.name.len()],
        &fields.name[..],
        "record {idx}: name bytes"
    );
}

/// `PIN_TABLE` (`tests/native/test_attempt_decode.c:269-271`) as 24 wire
/// bytes: magic `0x35464D4D`, version 1, reserved 0, `loc_off` 8, `size_off`
/// 32, `force_off` 40, `fixed_end` 41. Kind-1 `ctx` records always run under
/// this table, so a `CTX_TABLE_BAD` verdict on one would prove the pin went
/// stale; the attempts test asserts the Rust validator accepts these exact
/// bytes and that no kind-1 line carries that verdict.
const PIN_TABLE_BYTES: [u8; 24] = [
    0x4D, 0x4D, 0x46, 0x35, // magic = MV_OFF_TABLE_MAGIC
    0x01, 0x00, // version
    0x00, 0x00, // reserved
    0x08, 0x00, 0x00, 0x00, // loc_off = 8
    0x20, 0x00, 0x00, 0x00, // size_off = 32
    0x28, 0x00, 0x00, 0x00, // force_off = 40
    0x29, 0x00, 0x00, 0x00, // fixed_end = 41
];

/// Check one C `effective` dump line against the exact shape the oracle emits.
/// `parse_eff_line` (`tests/native/test_lifecycle_decode.c:311-352`) rejects
/// any non-`OK` verdict (lines 330-333) and `check_eff_vector` unconditionally
/// dumps the `OK` line with all four rule outputs (lines 499-502), so an
/// `effective` dump line is provably always
/// `<idx> effective OK effective=<u64> clamped=<0|1> earlyzero=<0|1>
/// offsetpast=<0|1>`. No Rust `mv_effective_bytes` counterpart exists in Plan 1
/// (see the module docs), so the values are shape-pinned here, not
/// differentially compared.
fn check_effective_dump_line(words: &[&str], idx: usize, line: &str) {
    assert_eq!(
        words.len(),
        7,
        "record {idx}: effective dump shape in {line:?}"
    );
    assert_eq!(
        words[2], "OK",
        "record {idx}: effective verdict is always OK"
    );
    parse_kv_u64(words[3], "effective=", idx, line);
    parse_kv_bit(words[4], "clamped=", idx, line);
    parse_kv_bit(words[5], "earlyzero=", idx, line);
    parse_kv_bit(words[6], "offsetpast=", idx, line);
}

/// Exact per-class record counts. Regenerate after a corpus change with e.g.
/// `grep -v '^#' tests/fixtures/attempts/corpus.txt | awk '{print $2}' | sort |
/// uniq -c` and update the constants and this comment together.
const ATTEMPTS_CTX: u32 = 17;
const ATTEMPTS_PAYLOAD: u32 = 13;
const ATTEMPTS_TCTX: u32 = 15;
const LC_LIFECYCLE: u32 = 38;
const LC_COPY: u32 = 37;
const LC_EFFECTIVE: u32 = 14;

#[test]
fn attempts_payload_matches_c_dump() {
    let root = repo_root();
    let cc_id = cc_identity();
    let work = workdir("attempts");
    let corpus = root.join("tests/fixtures/attempts");
    let bin = compile_oracle(&root, "test_attempt_decode", &work, &cc_id);
    let dump = run_oracle(
        &bin,
        &corpus.join("corpus.bin"),
        &corpus.join("corpus.txt"),
        &work.join("c.dump"),
        &cc_id,
        &OracleExpect {
            tool: "decode",
            expected_count: (ATTEMPTS_CTX + ATTEMPTS_PAYLOAD + ATTEMPTS_TCTX) as usize,
            extra_stdout: &[],
        },
    );
    let blob = std::fs::read(corpus.join("corpus.bin")).expect("read corpus.bin");
    let records = split_corpus(&blob, "tests/fixtures/attempts");
    assert_eq!(dump.len(), records.len(), "dump/record count");
    check_dump_matches_corpus_verdicts(
        &dump,
        &corpus.join("corpus.txt"),
        "tests/fixtures/attempts",
    );
    // The kind-1 pinned table must validate under the Rust table decoder with
    // the exact pinned fields (see PIN_TABLE_BYTES).
    let pin = decode_offsets_table(&PIN_TABLE_BYTES).expect("pinned C table validates in Rust");
    assert_eq!(pin.loc_off, 8, "pinned loc_off");
    assert_eq!(pin.size_off, 32, "pinned size_off");
    assert_eq!(pin.force_off, 40, "pinned force_off");
    assert_eq!(pin.fixed_end, 41, "pinned fixed_end");
    let mut compared = 0u32;
    let mut ctx_seen = 0u32;
    let mut ctx_ok_diffed = 0u32;
    let mut tctx_table_bad = 0u32;
    let mut tctx_table_ok = 0u32;
    for (idx, (kind, bytes)) in records.iter().enumerate() {
        match kind {
            2 => {
                assert_eq!(render_attempt(idx, bytes), dump[idx], "record {idx}");
                compared += 1;
            }
            1 => {
                let words = split_c_line(&dump[idx], idx, "ctx");
                // Kind-1 records run under PIN_TABLE, whose validity is pinned
                // above; CTX_TABLE_BAD here would prove the pin went stale.
                assert_ne!(
                    words[2], "CTX_TABLE_BAD",
                    "record {idx}: pinned table must validate in C too"
                );
                if let Some(fields) = check_ctx_dump_line(&words, idx, &dump[idx]) {
                    check_ctx_ok_against_rust(idx, &fields, &dump[idx]);
                    ctx_ok_diffed += 1;
                }
                ctx_seen += 1;
            }
            3 => {
                // The leading 24 bytes are the load-time offsets table; the
                // trailing context extracts in a later task. The C dump
                // provably carries no table field values — `dump_ok` emits
                // only the decoded-attempt fields and reject lines carry only
                // the verdict word — so the table signal is exactly the
                // CTX_TABLE_BAD verdict, raised solely by
                // `mv_validate_offsets` failure (`ref_extract`, C lines
                // 104-105). Rust `decode_offsets_table` validity must match
                // that verdict exactly; OK lines additionally diff every
                // C-emitted field through the reconstruction check.
                assert!(
                    bytes.len() >= 24,
                    "record {idx}: tctx shorter than offsets table"
                );
                let words = split_c_line(&dump[idx], idx, "tctx");
                let ok_fields = check_ctx_dump_line(&words, idx, &dump[idx]);
                let table = decode_offsets_table(&bytes[..24]);
                if words[2] == "CTX_TABLE_BAD" {
                    assert_eq!(
                        table,
                        Err(DecodeError::TableBad),
                        "record {idx}: C reports a bad table, Rust must agree exactly"
                    );
                    tctx_table_bad += 1;
                } else {
                    assert!(
                        table.is_ok(),
                        "record {idx}: C verdict {} implies a valid table, Rust says {table:?}",
                        words[2]
                    );
                    tctx_table_ok += 1;
                }
                if let Some(fields) = ok_fields {
                    check_ctx_ok_against_rust(idx, &fields, &dump[idx]);
                }
            }
            _ => panic!("record {idx}: unexpected kind {kind}"),
        }
    }
    assert_eq!(compared, ATTEMPTS_PAYLOAD, "payload class count");
    assert_eq!(ctx_seen, ATTEMPTS_CTX, "ctx class count");
    assert_eq!(
        tctx_table_bad + tctx_table_ok,
        ATTEMPTS_TCTX,
        "tctx class count"
    );
    assert!(
        tctx_table_bad > 0 && tctx_table_ok > 0,
        "tctx correspondence must see both verdict sides \
         (bad={tctx_table_bad} ok={tctx_table_ok})"
    );
    assert!(
        ctx_ok_diffed > 0,
        "at least one ctx OK line must take the reconstruction differential"
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn lifecycle_copy_matches_c_dump() {
    let root = repo_root();
    let cc_id = cc_identity();
    let work = workdir("lifecycle-wire");
    let corpus = root.join("tests/fixtures/lifecycle-wire");
    let bin = compile_oracle(&root, "test_lifecycle_decode", &work, &cc_id);
    let dump = run_oracle(
        &bin,
        &corpus.join("corpus.bin"),
        &corpus.join("corpus.txt"),
        &work.join("c.dump"),
        &cc_id,
        &OracleExpect {
            tool: "lifecycle-decode",
            expected_count: (LC_LIFECYCLE + LC_COPY + LC_EFFECTIVE) as usize,
            extra_stdout: &[
                "lifecycle-decode: bounce sweep 3500 cases, 875 negative, 973 past",
                "lifecycle-decode: slot index checks passed",
            ],
        },
    );
    let blob = std::fs::read(corpus.join("corpus.bin")).expect("read corpus.bin");
    let records = split_corpus(&blob, "tests/fixtures/lifecycle-wire");
    assert_eq!(dump.len(), records.len(), "dump/record count");
    check_dump_matches_corpus_verdicts(
        &dump,
        &corpus.join("corpus.txt"),
        "tests/fixtures/lifecycle-wire",
    );
    let mut lifecycle_compared = 0u32;
    let mut copy_compared = 0u32;
    let mut effective_seen = 0u32;
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
                // 25-byte effective-rule inputs, not wire records: the rule
                // helper has no Rust counterpart in Plan 1, so the provably
                // fixed C line shape is pinned (see check_effective_dump_line)
                // instead of differentially compared.
                assert_eq!(bytes.len(), 25, "record {idx}: effective input length");
                let words = split_c_line(&dump[idx], idx, "effective");
                check_effective_dump_line(&words, idx, &dump[idx]);
                effective_seen += 1;
            }
            _ => panic!("record {idx}: unexpected kind {kind}"),
        }
    }
    assert_eq!(lifecycle_compared, LC_LIFECYCLE, "lifecycle class count");
    assert_eq!(copy_compared, LC_COPY, "copy class count");
    assert_eq!(effective_seen, LC_EFFECTIVE, "effective class count");
    let _ = std::fs::remove_dir_all(&work);
}

/// Deterministic oracle-free negative control: the byte-comparisons above only
/// mean something if the Rust renders are sensitive to their inputs. One
/// flipped wire byte must change the render, a corrupted magic must flip `OK`
/// to `PAY_MAGIC`, and every `DecodeError` must map to a distinct `PAY_*`
/// word (a collision would let two different failures compare equal).
#[test]
fn renders_detect_single_byte_divergence() {
    let blob = std::fs::read(repo_root().join("tests/fixtures/attempts/corpus.bin"))
        .expect("read corpus.bin");
    let records = split_corpus(&blob, "tests/fixtures/attempts");
    let bytes = records
        .iter()
        .find(|(kind, bytes)| *kind == 2 && decode_attempt(bytes).is_ok())
        .map(|(_, bytes)| bytes)
        .expect("corpus must contain an OK payload vector");
    let baseline = render_attempt(0, bytes);
    assert!(
        baseline.contains(" OK "),
        "expected an OK baseline render, got {baseline:?}"
    );
    // MV_OFF_SIZE per bpf/include/memveil_events.h: any size value still
    // decodes, so the flip must stay OK-shaped yet render differently.
    let mut flipped = bytes.clone();
    flipped[24] ^= 0x01;
    let diverged = render_attempt(0, &flipped);
    assert_ne!(
        baseline, diverged,
        "one flipped size byte must change the render"
    );
    assert!(
        diverged.contains(" OK "),
        "size flip must stay OK-shaped, got {diverged:?}"
    );
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 0xff;
    assert_eq!(render_attempt(0, &corrupt), "0 payload PAY_MAGIC");
    let vocab = [
        (DecodeError::Short, "PAY_SHORT"),
        (DecodeError::Long, "PAY_LONG"),
        (DecodeError::Magic, "PAY_MAGIC"),
        (DecodeError::Version, "PAY_VERSION"),
        (DecodeError::Flags, "PAY_FLAGS"),
        (DecodeError::NameLen, "PAY_NAMELEN"),
        (DecodeError::Nul, "PAY_NUL"),
        (DecodeError::Pad, "PAY_PAD"),
        (DecodeError::Kind, "PAY_KIND"),
        (DecodeError::Dir, "PAY_DIR"),
        (DecodeError::Reason, "PAY_REASON"),
        (DecodeError::Range, "PAY_RANGE"),
        (DecodeError::TableBad, "PAY_TABLE_BAD"),
    ];
    for (error, word) in vocab {
        assert_eq!(verdict_name(error), word);
    }
    let mut words: Vec<&str> = vocab.iter().map(|(_, word)| *word).collect();
    words.sort_unstable();
    words.dedup();
    assert_eq!(words.len(), vocab.len(), "PAY_* words must be distinct");
}

#[test]
fn lifecycle_json_corpus_holds_no_wire_fixtures() {
    // `tests/fixtures/lifecycle/` holds analyzer-layer JSON events (session
    // plus per-scenario event streams) consumed only by the analyzer suites;
    // no wire decoder on either side reads them, so no differential applies.
    // Pin that shape fail-closed: a future wire fixture here must gain
    // differential coverage instead of silently escaping it. The name match
    // is deliberately broad — any `corpus` substring (a renamed `corpus.bin`
    // still reads as a wire corpus) and any `.bin` file (wire corpora are
    // `.bin` by convention; none belongs in this analyzer-only dir).
    // Every ndjson fixture must also be non-empty: an emptied stream would
    // keep the count above zero while testing nothing.
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
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if name.to_lowercase().contains("corpus")
                || path.extension().and_then(|ext| ext.to_str()) == Some("bin")
            {
                panic!(
                    "wire fixture {} needs differential coverage",
                    path.display()
                );
            }
            if path.extension().and_then(|ext| ext.to_str()) == Some("ndjson") {
                let len = path
                    .metadata()
                    .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()))
                    .len();
                assert!(len > 0, "emptied ndjson fixture {}", path.display());
                ndjson += 1;
            }
        }
    }
    assert!(
        ndjson > 0,
        "expected ndjson fixtures under tests/fixtures/lifecycle"
    );
}
