// SPDX-License-Identifier: GPL-3.0-or-later
//! Test-only lifecycle/copy probe consumer for the VM stress gates.
//!
//! Usage: `stress-consume [--expect-sha256 HEX] [--expect-family aya|c]`
//! `<elf> <ring> <sites> <seconds> <out>`
//!
//! One pinned Aya loader drives both object families: the current
//! Aya objects and the pre-change C objects (legacy `.maps`
//! definitions, CO-RE relocations, retired quarantine/dark maps on
//! the lifecycle object). Decoding reuses the shared MemVeil wire
//! decoders plus the retired consumer's semantic relation checks,
//! so every emitted line keeps the laboratory grammar the gates
//! parse. Event lines preserve emitted generations, ordinals, and
//! receive order; the summary derives from actual ring reads,
//! delivery outcomes, and `mv_counts` snapshots.
//!
//! Offline surfaces (no privilege, no boot): `--self-check` runs
//! fixed decoder vectors; `--verify-layout <elf> <ring>` prints
//! the family plus the exact map/program verdict; `--replay <wire>`
//! `<ring> <out> --counts ...` decodes recorded wire bytes with a
//! staged counter snapshot; `--resolve-copy-table` resolves the
//! copy field table from live BTF bytes and prints it.
//!
//! Exit 0 on a decoded healthy window, 77 on privilege denial
//! (EPERM anywhere, EACCES at attach; load-time EACCES fails
//! closed), 2 on usage errors, 1 on anything else.

mod btf;
mod layout;

use std::io::Write;
use std::time::{Duration, Instant};

use aya::maps::{Array, Map, MapData, RingBuf};
use aya::programs::fentry::FEntryLinkId;
use aya::programs::fexit::FExitLinkId;
use aya::programs::{FEntry, FExit};
use aya::{Btf, Ebpf, EbpfLoader};
use layout::{Family, RING_COPY, RING_LIFECYCLE, check_layout, expected_programs, parse_layout};
use memveil_ebpf_common::{MV_COPY_OFFS_LEN, MV_CP_LEN, MV_LC_LEN, decode_copy, decode_lifecycle};

/// Healthy decoded window.
const EXIT_OK: i32 = 0;
/// Anything else, including an unhealthy retained window.
const EXIT_FAIL: i32 = 1;
/// Usage error.
const EXIT_USAGE: i32 = 2;
/// Privilege denial: retry armed, never a pass.
const EXIT_SKIP: i32 = 77;

/// `mv_copy_fb` armed slot; deferred/recovered/flags are 0/1/2.
const FB_ARMED: u32 = 3;
/// Counter words in `mv_counts`.
const COUNTS_LEN: u32 = 6;
/// Post-detach drain budget, mirroring the retired consumer.
const DRAIN_BUDGET: Duration = Duration::from_secs(2);
/// Empty-ring sleep step while polling.
const POLL_STEP: Duration = Duration::from_millis(1);
/// `EPERM`.
const EPERM: i32 = 1;
/// `EACCES`.
const EACCES: i32 = 13;

/// A fatal consumer failure carrying its exit code.
#[derive(Debug)]
struct Fail {
    code: i32,
    message: String,
}

impl Fail {
    fn refuse(message: String) -> Self {
        Self {
            code: EXIT_FAIL,
            message,
        }
    }

    fn usage(message: String) -> Self {
        Self {
            code: EXIT_USAGE,
            message,
        }
    }

    fn skip(message: String) -> Self {
        Self {
            code: EXIT_SKIP,
            message,
        }
    }
}

/// Walk an error chain to the first errno, if any wraps `io::Error`.
fn errno_of(error: &(dyn std::error::Error + 'static)) -> Option<i32> {
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(err) = next {
        if let Some(io) = err.downcast_ref::<std::io::Error>()
            && let Some(code) = io.raw_os_error()
        {
            return Some(code);
        }
        next = err.source();
    }
    None
}

mod sha256 {
    //! Compact SHA-256 (FIPS 180-4) so the digest check needs no new
    //! dependency. Covered by the `abc` known-answer test, checked
    //! against the host hashlib in the harness self-test.

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    /// Digest arbitrary bytes.
    pub fn digest(bytes: &[u8]) -> [u8; 32] {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let bit_len = (bytes.len() as u64).wrapping_mul(8);
        let mut padded = bytes.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&bit_len.to_be_bytes());
        let (blocks, _) = padded.as_chunks::<64>();
        for block in blocks {
            let mut w = [0u32; 64];
            let (words, _) = block.as_chunks::<4>();
            for (slot, word) in w.iter_mut().zip(words).take(16) {
                *slot = u32::from_be_bytes(*word);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut wv = state;
            for i in 0..64 {
                let s1 = wv[4].rotate_right(6) ^ wv[4].rotate_right(11) ^ wv[4].rotate_right(25);
                let ch = (wv[4] & wv[5]) ^ ((!wv[4]) & wv[6]);
                let t1 = wv[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = wv[0].rotate_right(2) ^ wv[0].rotate_right(13) ^ wv[0].rotate_right(22);
                let maj = (wv[0] & wv[1]) ^ (wv[0] & wv[2]) ^ (wv[1] & wv[2]);
                let t2 = s0.wrapping_add(maj);
                wv[7] = wv[6];
                wv[6] = wv[5];
                wv[5] = wv[4];
                wv[4] = wv[3].wrapping_add(t1);
                wv[3] = wv[2];
                wv[2] = wv[1];
                wv[1] = wv[0];
                wv[0] = t1.wrapping_add(t2);
            }
            for (slot, add) in state.iter_mut().zip(wv) {
                *slot = slot.wrapping_add(add);
            }
        }
        let mut out = [0u8; 32];
        let (slots, _) = out.as_chunks_mut::<4>();
        for (slot, word) in slots.iter_mut().zip(state) {
            *slot = word.to_be_bytes();
        }
        out
    }

    /// Lowercase hex of a digest.
    pub fn hex(sum: &[u8; 32]) -> String {
        const NYBBLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in sum {
            out.push(NYBBLE[(byte >> 4) as usize] as char);
            out.push(NYBBLE[(byte & 15) as usize] as char);
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn abc_known_answer() {
            let sum = digest(b"abc");
            assert_eq!(
                hex(&sum),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn empty_known_answer() {
            let sum = digest(b"");
            assert_eq!(
                hex(&sum),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
        }

        #[test]
        fn long_input_spans_blocks() {
            let sum = digest(&vec![0x61u8; 1000]);
            assert_eq!(
                hex(&sum),
                "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
            );
        }
    }
}

/// One decoded event line plus its byte size for conservation.
fn decode_lc(payload: &[u8]) -> Result<(String, u64), String> {
    let event = decode_lifecycle(payload).map_err(|error| format!("lc {error:?}"))?;
    // Semantic relation the wire decoder leaves open: unmaps are
    // always ok (a failed unmap has no identity to release).
    if event.kind == memveil_ebpf_common::MV_LC_KIND_UNMAP && !event.ok {
        return Err("lc unmap not ok".to_owned());
    }
    let ok = u8::from(event.ok);
    let skip = u8::from(event.skip_sync);
    Ok((
        format!(
            "lc kind={} ok={ok} skip={skip} dir={} seq={} ktime={} size={} gen={}",
            event.kind, event.dir, event.seq, event.ktime, event.size, event.generation
        ),
        event.size,
    ))
}

/// One decoded copy line plus its requested bytes for conservation.
fn decode_cp(payload: &[u8]) -> Result<(String, u64), String> {
    let event = decode_copy(payload).map_err(|error| format!("cp {error:?}"))?;
    // Semantic relations the wire decoder leaves open, mirroring
    // the retired consumer: syncs carry no bytes and are never
    // known, copies couple todev to direction, and known copies
    // couple effective to requested through clamp/early-zero.
    let todev = u8::from(event.to_device);
    let known = u8::from(event.known);
    let clamp = u8::from(event.clamped);
    let ezero = u8::from(event.early_zero);
    if event.kind == memveil_ebpf_common::MV_CP_KIND_SYNC {
        if event.known || event.effective != 0 || event.clamped || event.early_zero {
            return Err("cp sync carries bytes".to_owned());
        }
    } else {
        if todev != u8::from(event.dir == 1) {
            return Err("cp copy direction".to_owned());
        }
        if event.known {
            if event.effective > event.requested {
                return Err("cp effective overflow".to_owned());
            }
            if event.early_zero && event.effective != 0 {
                return Err("cp early-zero bytes".to_owned());
            }
            if event.clamped && event.effective >= event.requested {
                return Err("cp clamp bytes".to_owned());
            }
            if !event.clamped && !event.early_zero && event.effective != event.requested {
                return Err("cp effective relation".to_owned());
            }
        } else if event.effective != 0 || event.clamped || event.early_zero {
            return Err("cp unknown bytes".to_owned());
        }
    }
    Ok((
        format!(
            "cp kind={} todev={todev} known={known} clamp={clamp} ezero={ezero} dir={} reason={} seq={} ktime={} req={} eff={}",
            event.kind,
            event.dir,
            event.reason,
            event.seq,
            event.ktime,
            event.requested,
            event.effective
        ),
        event.requested,
    ))
}

/// Offline decoder check over fixed vectors (no privilege).
fn self_check() -> Result<(), Fail> {
    let mut lc = [0u8; MV_LC_LEN];
    lc[0..4].copy_from_slice(&memveil_ebpf_common::MV_LC_MAGIC.to_le_bytes());
    lc[4..6].copy_from_slice(&memveil_ebpf_common::MV_LC_VERSION.to_le_bytes());
    lc[6..8].copy_from_slice(&memveil_ebpf_common::MV_LC_KIND_MAP.to_le_bytes());
    lc[8..10].copy_from_slice(&memveil_ebpf_common::MV_LC_FLAG_OK.to_le_bytes());
    lc[10..12].copy_from_slice(&1u16.to_le_bytes());
    lc[28..36].copy_from_slice(&512u64.to_le_bytes());
    lc[36..44].copy_from_slice(&7u64.to_le_bytes());
    let (line, size) = decode_lc(&lc).map_err(Fail::refuse)?;
    if line != "lc kind=1 ok=1 skip=0 dir=1 seq=0 ktime=0 size=512 gen=7" || size != 512 {
        return Err(Fail::refuse(format!("lc vector mismatch: {line}")));
    }
    let mut bad = lc;
    bad[0] = 0;
    if decode_lc(&bad).is_ok() {
        return Err(Fail::refuse("lc bad magic accepted".to_owned()));
    }
    if decode_lc(&lc[..MV_LC_LEN - 1]).is_ok() {
        return Err(Fail::refuse("lc short accepted".to_owned()));
    }
    // Unmap without ok: the wire decoder passes it, semantics refuse.
    let mut unmap = [0u8; MV_LC_LEN];
    unmap[0..4].copy_from_slice(&memveil_ebpf_common::MV_LC_MAGIC.to_le_bytes());
    unmap[4..6].copy_from_slice(&memveil_ebpf_common::MV_LC_VERSION.to_le_bytes());
    unmap[6..8].copy_from_slice(&memveil_ebpf_common::MV_LC_KIND_UNMAP.to_le_bytes());
    unmap[8..10].copy_from_slice(&memveil_ebpf_common::MV_LC_FLAG_GEN_MISS.to_le_bytes());
    unmap[10..12].copy_from_slice(&1u16.to_le_bytes());
    unmap[28..36].copy_from_slice(&512u64.to_le_bytes());
    if decode_lc(&unmap).is_ok() {
        return Err(Fail::refuse("lc unmap without ok accepted".to_owned()));
    }
    let mut cp = [0u8; MV_CP_LEN];
    cp[0..4].copy_from_slice(&memveil_ebpf_common::MV_CP_MAGIC.to_le_bytes());
    cp[4..6].copy_from_slice(&memveil_ebpf_common::MV_CP_VERSION.to_le_bytes());
    cp[6..8].copy_from_slice(&memveil_ebpf_common::MV_CP_KIND_COPY.to_le_bytes());
    cp[8..10].copy_from_slice(
        &(memveil_ebpf_common::MV_CP_FLAG_TO_DEVICE | memveil_ebpf_common::MV_CP_FLAG_KNOWN)
            .to_le_bytes(),
    );
    cp[10..12].copy_from_slice(&1u16.to_le_bytes());
    cp[12..20].copy_from_slice(&7u64.to_le_bytes());
    cp[28..36].copy_from_slice(&1024u64.to_le_bytes());
    cp[36..44].copy_from_slice(&1024u64.to_le_bytes());
    let (line, req) = decode_cp(&cp).map_err(Fail::refuse)?;
    if line
        != "cp kind=2 todev=1 known=1 clamp=0 ezero=0 dir=1 reason=0 seq=7 ktime=0 req=1024 eff=1024"
        || req != 1024
    {
        return Err(Fail::refuse(format!("cp vector mismatch: {line}")));
    }
    let mut known_reason = cp;
    known_reason[44] = 4;
    if decode_cp(&known_reason).is_ok() {
        return Err(Fail::refuse("cp known+reason accepted".to_owned()));
    }
    // Known sync with zero bytes: invalid for a request even though
    // the wire shape alone would pass with reason NONE.
    let mut sync_known = cp;
    sync_known[6..8].copy_from_slice(&memveil_ebpf_common::MV_CP_KIND_SYNC.to_le_bytes());
    sync_known[36..44].copy_from_slice(&0u64.to_le_bytes());
    if decode_cp(&sync_known).is_ok() {
        return Err(Fail::refuse("sync semantic corruption accepted".to_owned()));
    }
    let mut overflow = cp;
    overflow[36..44].copy_from_slice(&1281u64.to_le_bytes());
    if decode_cp(&overflow).is_ok() {
        return Err(Fail::refuse("copy effective overflow accepted".to_owned()));
    }
    let sum = sha256::digest(b"abc");
    if sha256::hex(&sum) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
        return Err(Fail::refuse("sha256 known-answer mismatch".to_owned()));
    }
    println!("self-check: 2 decoders, semantic refusals, and sha256 ok");
    Ok(())
}

/// Print one object's offline layout and gate verdict (no privilege).
fn verify_layout(elf_path: &str, ring: &str) -> Result<(), Fail> {
    let elf = std::fs::read(elf_path)
        .map_err(|error| Fail::refuse(format!("cannot read object: {error}")))?;
    let sum = sha256::hex(&sha256::digest(&elf));
    let layout = parse_layout(&elf).map_err(Fail::refuse)?;
    println!("object: {elf_path}");
    println!("sha256: {sum}");
    println!(
        "core-relocations: {}",
        if layout.core_relocations { "yes" } else { "no" }
    );
    println!("maps:");
    for row in layout.maps.values() {
        println!(
            "  {} type={} key={} value={} entries={}",
            row.name, row.map_type, row.key_size, row.value_size, row.max_entries
        );
    }
    println!("programs:");
    for row in layout.programs.values() {
        println!(
            "  {} {}{}",
            row.name,
            row.kind,
            if row.sleepable { " sleepable" } else { "" }
        );
    }
    match check_layout(&layout, ring) {
        Ok(family) => {
            println!("gate: PASS family={} ring={ring}", family.name());
            Ok(())
        }
        Err(reason) => {
            println!("gate: REFUSE ring={ring} {reason}");
            Err(Fail::refuse(format!("layout refused: {reason}")))
        }
    }
}

/// Resolve the copy field table from BTF bytes and print it (no
/// privilege beyond reading the BTF path).
fn resolve_copy_table(btf_path: &str) -> Result<(), Fail> {
    let bytes = std::fs::read(btf_path)
        .map_err(|error| Fail::refuse(format!("cannot read BTF: {error}")))?;
    let btf = btf::parse_btf(&bytes).map_err(Fail::refuse)?;
    let table = btf::resolve_copy_offsets(&btf).map_err(Fail::refuse)?;
    let (bidi, to, from) = btf::lifecycle_dirs(&btf).map_err(Fail::refuse)?;
    let wire = btf::encode_table(&table);
    print!("table:");
    for byte in wire {
        print!(" {byte:02x}");
    }
    println!();
    println!(
        "fields: slot_size={} mem_off={} cc_off={} has_private={} dir_to={} dir_from={} dir_bidi={}",
        table.slot_size,
        table.mem_off,
        table.cc_off,
        u8::from(table.flags & memveil_ebpf_common::MV_COPY_OFFS_HAS_PRIVATE != 0),
        table.dir_to,
        table.dir_from,
        table.dir_bidi
    );
    println!("dirs: bidi={bidi} to={to} from={from}");
    Ok(())
}

/// Strict decimal seconds in 1..=3600.
fn parse_seconds(text: &str) -> Result<u64, Fail> {
    if text.is_empty() || text.len() > 4 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Fail::usage(format!("bad seconds: {text}")));
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(Fail::usage(format!("bad seconds: {text}")));
    }
    let seconds: u64 = text
        .parse()
        .map_err(|_| Fail::usage(format!("bad seconds: {text}")))?;
    if seconds == 0 || seconds > 3600 {
        return Err(Fail::usage(format!("bad seconds: {text}")));
    }
    Ok(seconds)
}

/// Strict lowercase hex digest.
fn parse_digest(text: &str) -> Result<String, Fail> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Fail::usage("bad --expect-sha256: want 64 hex".to_owned()));
    }
    Ok(text.to_ascii_lowercase())
}

/// Strict comma-separated u64 counters.
fn parse_counts(text: &str) -> Result<[u64; 6], Fail> {
    let parts: Vec<&str> = text.split(',').collect();
    if parts.len() != 6 {
        return Err(Fail::usage(
            "bad --counts: want 6 comma-separated u64".to_owned(),
        ));
    }
    let mut out = [0u64; 6];
    for (slot, part) in out.iter_mut().zip(parts) {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Fail::usage(
                "bad --counts: want 6 comma-separated u64".to_owned(),
            ));
        }
        *slot = part
            .parse()
            .map_err(|_| Fail::usage("bad --counts: want 6 comma-separated u64".to_owned()))?;
    }
    Ok(out)
}

/// Decode recorded wire bytes with a staged counter snapshot (no
/// privilege): fixed-size records back to back, a trailing partial
/// chunk counting one bad frame.
fn replay(wire_path: &str, ring: &str, out_path: &str, counts: [u64; 6]) -> Result<(), Fail> {
    let record_len = match ring {
        RING_LIFECYCLE => MV_LC_LEN,
        RING_COPY => MV_CP_LEN,
        _ => {
            return Err(Fail::usage(format!(
                "ring must be {RING_LIFECYCLE} or {RING_COPY}"
            )));
        }
    };
    let wire = std::fs::read(wire_path)
        .map_err(|error| Fail::refuse(format!("cannot read wire: {error}")))?;
    let mut lines = Vec::new();
    let mut badframe = 0u64;
    let mut badrec = 0u64;
    let mut rx = 0u64;
    let mut chunks = wire.chunks_exact(record_len);
    for chunk in &mut chunks {
        rx += 1;
        let decoded = match ring {
            RING_LIFECYCLE => decode_lc(chunk),
            _ => decode_cp(chunk),
        };
        match decoded {
            Ok((line, _)) => lines.push(line),
            Err(_) => badrec += 1,
        }
    }
    if !chunks.remainder().is_empty() {
        badframe += 1;
    }
    let dlv = lines.len() as u64;
    write_out(
        out_path, &lines, dlv, badframe, badrec, &counts, rx, dlv, 0, 0,
    )?;
    if badframe != 0 || badrec != 0 || counts[5] != 0 {
        return Err(Fail::refuse(
            "unhealthy decoded window; retained summary".to_owned(),
        ));
    }
    Ok(())
}

/// Write event lines plus the laboratory summary line.
#[allow(clippy::too_many_arguments)]
fn write_out(
    out_path: &str,
    lines: &[String],
    observed: u64,
    badframe: u64,
    badrec: u64,
    counts: &[u64; 6],
    rx: u64,
    dlv: u64,
    mal: u64,
    drop: u64,
) -> Result<(), Fail> {
    let mut text = String::new();
    for line in lines {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(&format!(
        "summary observed={observed} badframe={badframe} badrec={badrec} cnt_obs={} cnt_obsb={} cnt_emit={} cnt_emitb={} cnt_fail={} cnt_flags={} rx={rx} dlv={dlv} mal={mal} drop={drop}\n",
        counts[0], counts[1], counts[2], counts[3], counts[4], counts[5]
    ));
    std::fs::write(out_path, text)
        .map_err(|error| Fail::refuse(format!("cannot write out: {error}")))?;
    Ok(())
}

/// One `prog:symbol` attach site.
struct Site {
    program: String,
    symbol: String,
}

/// Parse `prog:symbol,prog:symbol` (usage errors refuse as exit 2).
fn parse_sites(text: &str) -> Result<Vec<Site>, Fail> {
    if text.is_empty() {
        return Err(Fail::usage("no attach sites".to_owned()));
    }
    let mut sites = Vec::new();
    for item in text.split(',') {
        let Some((program, symbol)) = item.split_once(':') else {
            return Err(Fail::usage("site needs prog:symbol".to_owned()));
        };
        if program.is_empty() || symbol.is_empty() {
            return Err(Fail::usage("site needs prog:symbol".to_owned()));
        }
        sites.push(Site {
            program: program.to_owned(),
            symbol: symbol.to_owned(),
        });
    }
    Ok(sites)
}

/// Require the sites to name exactly the channel program set.
fn check_sites(sites: &[Site], ring: &str) -> Result<(), Fail> {
    let expected = expected_programs(ring).expect("ring checked by caller");
    if sites.len() != expected.len() {
        return Err(Fail::refuse(format!(
            "sites must name exactly the {ring} program set ({} sites, want {})",
            sites.len(),
            expected.len()
        )));
    }
    for site in sites {
        if !expected.iter().any(|(want, _)| *want == site.program) {
            return Err(Fail::refuse(format!(
                "site program `{}` is not in the {ring} set",
                site.program
            )));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for site in sites {
        if !seen.insert(site.program.clone()) {
            return Err(Fail::refuse(format!(
                "site program `{}` twice",
                site.program
            )));
        }
    }
    Ok(())
}

/// One live link for detach.
enum Link {
    FEntry { program: String, id: FEntryLinkId },
    FExit { program: String, id: FExitLinkId },
}

/// Borrow the ring map's owned consumer without remapping per poll.
fn open_consumer(bpf: &Ebpf, ring: &str) -> Result<RingBuf<MapData>, Fail> {
    use std::os::fd::AsFd;
    let Some(map) = bpf.map(ring) else {
        return Err(Fail::refuse(format!("ring map `{ring}` missing")));
    };
    let Map::RingBuf(data) = map else {
        return Err(Fail::refuse(format!(
            "ring map `{ring}` is not a ring buffer"
        )));
    };
    let dup = data
        .fd()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| Fail::refuse(format!("ring map `{ring}` fd dup failed: {error}")))?;
    let owned = MapData::from_fd(dup)
        .map_err(|error| Fail::refuse(format!("ring map `{ring}` reopen failed: {error}")))?;
    RingBuf::try_from(Map::RingBuf(owned))
        .map_err(|error| Fail::refuse(format!("ring map `{ring}` open failed: {error}")))
}

/// Read one u64 word from an array map.
fn map_get_u64(bpf: &Ebpf, name: &str, key: u32) -> Result<u64, Fail> {
    let Some(map) = bpf.map(name) else {
        return Err(Fail::refuse(format!("map `{name}` not in object")));
    };
    let array = Array::<_, u64>::try_from(map)
        .map_err(|error| Fail::refuse(format!("map `{name}` unreadable: {error}")))?;
    array
        .get(&key, 0)
        .map_err(|error| Fail::refuse(format!("map `{name}` key {key} read failed: {error}")))
}

/// Write one u64 word to an array map.
fn map_set_u64(bpf: &mut Ebpf, name: &str, key: u32, value: u64) -> Result<(), Fail> {
    let Some(map) = bpf.map_mut(name) else {
        return Err(Fail::refuse(format!("map `{name}` not in object")));
    };
    let mut array = Array::<_, u64>::try_from(map)
        .map_err(|error| Fail::refuse(format!("map `{name}` unwritable: {error}")))?;
    array
        .set(key, value, 0)
        .map_err(|error| Fail::refuse(format!("map `{name}` key {key} write failed: {error}")))
}

/// Full live consume flow; every failure carries its exit code.
fn consume(
    elf_path: &str,
    ring: &str,
    sites_text: &str,
    seconds: u64,
    out_path: &str,
    expect_sha: Option<&str>,
    expect_family: Option<Family>,
) -> Result<(), Fail> {
    if ring != RING_LIFECYCLE && ring != RING_COPY {
        return Err(Fail::usage(format!(
            "ring must be {RING_LIFECYCLE} or {RING_COPY}"
        )));
    }
    let sites = parse_sites(sites_text)?;
    check_sites(&sites, ring)?;
    let elf = std::fs::read(elf_path)
        .map_err(|error| Fail::refuse(format!("cannot read object: {error}")))?;
    if let Some(want) = expect_sha
        && sha256::hex(&sha256::digest(&elf)) != want
    {
        return Err(Fail::refuse(
            "object digest mismatch: refusing a wrong pair".to_owned(),
        ));
    }
    let layout = parse_layout(&elf).map_err(Fail::refuse)?;
    let family = check_layout(&layout, ring).map_err(Fail::refuse)?;
    if let Some(want) = expect_family
        && family != want
    {
        return Err(Fail::refuse(format!(
            "family mismatch: want {}, object is {}",
            want.name(),
            family.name()
        )));
    }
    // One shared sysfs BTF read: the legacy family relocates
    // against it at load, fentry/fexit program loads need it, and
    // the table/dir checks below derive from these same bytes.
    let btf_bytes = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|error| Fail::refuse(format!("kernel BTF unavailable for {ring}: {error}")))?;
    if layout.core_relocations {
        // Fail-closed CO-RE guard: a relocating object without
        // parsed BTF refuses here rather than loading unrelocated.
        btf::parse_btf(&btf_bytes).map_err(Fail::refuse)?;
    }
    let parsed_btf = btf::parse_btf(&btf_bytes).map_err(Fail::refuse)?;
    if ring == RING_LIFECYCLE {
        // Both families share one lifecycle map set, so the frozen
        // direction check cannot tell them apart and runs either
        // way: a renumbered kernel refuses loudly.
        btf::lifecycle_dirs(&parsed_btf).map_err(Fail::refuse)?;
    }
    let kernel_btf = Btf::from_sys_fs()
        .map_err(|error| Fail::refuse(format!("kernel BTF unreadable: {error}")))?;
    let mut loader = EbpfLoader::new();
    loader.btf(Some(&kernel_btf));
    let mut bpf = loader.load(&elf).map_err(|error| {
        let detail = format!("load failed: {error}");
        match errno_of(&error) {
            Some(code) if code == EPERM => Fail::skip(detail),
            Some(code) if code == EACCES => {
                Fail::refuse(format!("{detail} (load-time EACCES fails closed)"))
            }
            _ => Fail::refuse(detail),
        }
    })?;
    // Live presence gate: the loader creates exactly the declared
    // maps, so names must match the admitted family set exactly.
    {
        let mut live: Vec<String> = bpf.maps().map(|(name, _)| name.to_owned()).collect();
        live.sort();
        let mut want: Vec<String> = layout.maps.keys().cloned().collect();
        want.sort();
        if live != want {
            return Err(Fail::refuse(format!(
                "live maps {live:?} differ from declared {want:?}"
            )));
        }
    }
    let mut consumer = open_consumer(&bpf, ring)?;
    if ring == RING_COPY && family == Family::Aya {
        // Install the host-resolved field table between load and
        // attach so every copy firing reads trusted offsets, then
        // read it back: the program must never run on a table the
        // read-back did not prove.
        let table = btf::resolve_copy_offsets(&parsed_btf).map_err(Fail::refuse)?;
        let wire = btf::encode_table(&table);
        {
            let Some(map) = bpf.map_mut("mv_copy_offs") else {
                return Err(Fail::refuse("map `mv_copy_offs` not in object".to_owned()));
            };
            let mut array = Array::<_, [u8; MV_COPY_OFFS_LEN]>::try_from(map)
                .map_err(|error| Fail::refuse(format!("copy table unwritable: {error}")))?;
            array
                .set(0, wire, 0)
                .map_err(|error| Fail::refuse(format!("copy table install failed: {error}")))?;
        }
        {
            let Some(map) = bpf.map("mv_copy_offs") else {
                return Err(Fail::refuse("map `mv_copy_offs` not in object".to_owned()));
            };
            let array = Array::<_, [u8; MV_COPY_OFFS_LEN]>::try_from(map)
                .map_err(|error| Fail::refuse(format!("copy table unreadable: {error}")))?;
            let back = array
                .get(&0, 0)
                .map_err(|error| Fail::refuse(format!("copy table read-back failed: {error}")))?;
            if back != wire {
                return Err(Fail::refuse("copy table read-back mismatch".to_owned()));
            }
        }
        println!(
            "copy-table ok slot_size={} has_private={}",
            table.slot_size,
            u8::from(table.flags & memveil_ebpf_common::MV_COPY_OFFS_HAS_PRIVATE != 0)
        );
    }
    // Attach every site; a failed site detaches the sites this
    // call attached, in reverse.
    let mut links: Vec<Link> = Vec::new();
    let attach_failed = |bpf: &mut Ebpf, links: &mut Vec<Link>, message: String| {
        for link in links.drain(..).rev() {
            detach_link(bpf, link);
        }
        message
    };
    for site in &sites {
        let kind = expected_programs(ring)
            .expect("ring checked")
            .into_iter()
            .find(|(name, _)| *name == site.program)
            .map(|(_, kind)| kind)
            .expect("site checked");
        // The step keeps the syscall errno beside its message so
        // privilege denial classifies from typed errors, never by
        // matching message text.
        let step: Result<Link, (String, Option<i32>)> = (|| {
            let Some(raw) = bpf.program_mut(&site.program) else {
                return Err((format!("program `{}` not in object", site.program), None));
            };
            let load_failed = |error: aya::programs::ProgramError| {
                (
                    format!("program `{}` load failed: {error}", site.program),
                    errno_of(&error),
                )
            };
            let attach_failed_step = |error: aya::programs::ProgramError| {
                (
                    format!("program `{}` attach failed: {error}", site.program),
                    errno_of(&error),
                )
            };
            if kind == "fentry" {
                let typed: &mut FEntry = raw
                    .try_into()
                    .map_err(|_| (format!("program `{}` is not an fentry", site.program), None))?;
                typed.load(&site.symbol, &kernel_btf).map_err(load_failed)?;
                let id = typed.attach().map_err(attach_failed_step)?;
                Ok(Link::FEntry {
                    program: site.program.clone(),
                    id,
                })
            } else {
                let typed: &mut FExit = raw
                    .try_into()
                    .map_err(|_| (format!("program `{}` is not an fexit", site.program), None))?;
                typed.load(&site.symbol, &kernel_btf).map_err(load_failed)?;
                let id = typed.attach().map_err(attach_failed_step)?;
                Ok(Link::FExit {
                    program: site.program.clone(),
                    id,
                })
            }
        })();
        match step {
            Ok(link) => links.push(link),
            Err((message, errno)) => {
                let message = attach_failed(&mut bpf, &mut links, message);
                // Attach-step privilege denial skips: EPERM
                // anywhere, EACCES at attach. A verifier refusal
                // or a missing symbol fails closed instead.
                match errno {
                    Some(code) if code == EPERM || code == EACCES => {
                        return Err(Fail::skip(message));
                    }
                    _ => return Err(Fail::refuse(message)),
                }
            }
        }
    }
    if ring == RING_COPY {
        // Arm only after every copy link exists, so no bare exit
        // inflates recoveries.
        if let Err(fail) = map_set_u64(&mut bpf, "mv_copy_fb", FB_ARMED, 1) {
            let message = attach_failed(&mut bpf, &mut links, fail.message);
            return Err(Fail::refuse(format!("arm copy: {message}")));
        }
    }
    println!("ready ring={ring}");
    std::io::stdout().flush().ok();
    let mut lines = Vec::new();
    let mut badrec = 0u64;
    let mut rx = 0u64;
    let start = Instant::now();
    let budget = Duration::from_secs(seconds);
    let mut detached = false;
    let mut drain_start = start;
    loop {
        let elapsed = start.elapsed();
        if !detached && elapsed >= budget {
            // Detach closes new attachments; it does not prove
            // in-flight writers quiesced.
            if ring == RING_COPY {
                // Disarm before detach, so no late exit recovers
                // after the end cut.
                if let Err(fail) = map_set_u64(&mut bpf, "mv_copy_fb", FB_ARMED, 0) {
                    let message = attach_failed(&mut bpf, &mut links, fail.message);
                    return Err(Fail::refuse(format!("disarm copy: {message}")));
                }
            }
            for link in links.drain(..).rev() {
                detach_link(&mut bpf, link);
            }
            detached = true;
            drain_start = Instant::now();
        }
        if detached && drain_start.elapsed() >= DRAIN_BUDGET {
            return Err(Fail::refuse(
                "bounded post-detach drain timed out".to_owned(),
            ));
        }
        match consumer.next().map(|item| item.to_vec()) {
            Some(bytes) => {
                rx += 1;
                let decoded = match ring {
                    RING_LIFECYCLE => decode_lc(&bytes),
                    _ => decode_cp(&bytes),
                };
                match decoded {
                    Ok((line, _)) => lines.push(line),
                    Err(_) => badrec += 1,
                }
            }
            None => {
                if detached {
                    break;
                }
                std::thread::sleep(POLL_STEP);
            }
        }
    }
    let mut counts = [0u64; 6];
    for key in 0..COUNTS_LEN {
        counts[key as usize] = map_get_u64(&bpf, "mv_counts", key)
            .map_err(|fail| Fail::refuse(format!("settle: {}", fail.message)))?;
    }
    let dlv = lines.len() as u64;
    write_out(out_path, &lines, dlv, 0, badrec, &counts, rx, dlv, 0, 0)?;
    if badrec != 0 || counts[5] != 0 {
        return Err(Fail::refuse(
            "unhealthy decoded window; retained summary".to_owned(),
        ));
    }
    Ok(())
}

/// Detach one link, best-effort at teardown.
fn detach_link(bpf: &mut Ebpf, link: Link) {
    match link {
        Link::FEntry { program, id } => {
            if let Some(raw) = bpf.program_mut(&program)
                && let Ok(typed) =
                    <&mut aya::programs::Program as TryInto<&mut FEntry>>::try_into(raw)
            {
                typed.detach(id).ok();
            }
        }
        Link::FExit { program, id } => {
            if let Some(raw) = bpf.program_mut(&program)
                && let Ok(typed) =
                    <&mut aya::programs::Program as TryInto<&mut FExit>>::try_into(raw)
            {
                typed.detach(id).ok();
            }
        }
    }
}

fn usage() -> Fail {
    Fail::usage(
        "usage: stress-consume [--expect-sha256 HEX] [--expect-family aya|c] \
         <elf> <ring> <prog:symbol,...> <seconds> <out>\n       \
         stress-consume --self-check | --verify-layout <elf> <ring> | \
         --replay <wire> <ring> <out> --counts o,ob,e,eb,f,fl | \
         --resolve-copy-table [--btf PATH]"
            .to_owned(),
    )
}

fn run(argv: &[String]) -> Result<(), Fail> {
    if argv.len() == 2 && argv[1] == "--self-check" {
        return self_check();
    }
    if argv.len() == 4 && argv[1] == "--verify-layout" {
        return verify_layout(&argv[2], &argv[3]);
    }
    if argv.len() >= 2 && argv[1] == "--resolve-copy-table" {
        let mut btf = "/sys/kernel/btf/vmlinux";
        if argv.len() == 4 && argv[2] == "--btf" {
            btf = &argv[3];
        } else if argv.len() != 2 {
            return Err(usage());
        }
        return resolve_copy_table(btf);
    }
    if argv.len() >= 2 && argv[1] == "--replay" {
        if argv.len() != 7 || argv[5] != "--counts" {
            return Err(usage());
        }
        let counts = parse_counts(&argv[6])?;
        return replay(&argv[2], &argv[3], &argv[4], counts);
    }
    let mut args: &[String] = &argv[1..];
    let mut expect_sha: Option<String> = None;
    let mut expect_family: Option<Family> = None;
    while args.len() >= 2 && args[0].starts_with("--expect-") {
        match args[0].as_str() {
            "--expect-sha256" => expect_sha = Some(parse_digest(&args[1])?),
            "--expect-family" => {
                expect_family =
                    Some(Family::parse(&args[1]).ok_or_else(|| {
                        Fail::usage("bad --expect-family: want aya or c".to_owned())
                    })?);
            }
            _ => return Err(usage()),
        }
        args = &args[2..];
    }
    if args.len() != 5 {
        return Err(usage());
    }
    let seconds = parse_seconds(&args[3])?;
    consume(
        &args[0],
        &args[1],
        &args[2],
        seconds,
        &args[4],
        expect_sha.as_deref(),
        expect_family,
    )
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let code = match run(&argv) {
        Ok(()) => EXIT_OK,
        Err(fail) => {
            println!("{}", fail.message);
            fail.code
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_shape() {
        assert_eq!(parse_seconds("1").unwrap(), 1);
        assert_eq!(parse_seconds("3600").unwrap(), 3600);
        assert!(parse_seconds("0").is_err());
        assert!(parse_seconds("3601").is_err());
        assert!(parse_seconds("01").is_err());
        assert!(parse_seconds("x").is_err());
        assert!(parse_seconds("").is_err());
    }

    #[test]
    fn digest_shape() {
        assert!(parse_digest(&"ab".repeat(32)).is_ok());
        assert!(parse_digest("ab").is_err());
        assert!(parse_digest(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn counts_shape() {
        assert_eq!(parse_counts("1,2,3,4,5,6").unwrap(), [1, 2, 3, 4, 5, 6]);
        assert!(parse_counts("1,2,3").is_err());
        assert!(parse_counts("1,2,3,4,5,x").is_err());
    }

    #[test]
    fn sites_shape() {
        let sites = parse_sites("a:b,c:d").unwrap();
        assert_eq!(sites.len(), 2);
        assert!(parse_sites("").is_err());
        assert!(parse_sites("a").is_err());
        assert!(parse_sites("a:").is_err());
        assert!(parse_sites(":b").is_err());
    }

    #[test]
    fn sites_must_name_the_channel_set() {
        let full = parse_sites("mv_map_result:x,mv_unmap:y").unwrap();
        assert!(check_sites(&full, RING_LIFECYCLE).is_ok());
        let short = parse_sites("mv_map_result:x").unwrap();
        assert!(check_sites(&short, RING_LIFECYCLE).is_err());
        let wrong = parse_sites("mv_map_result:x,mv_bounce:y").unwrap();
        assert!(check_sites(&wrong, RING_LIFECYCLE).is_err());
        let dup = parse_sites("mv_map_result:x,mv_map_result:y").unwrap();
        assert!(check_sites(&dup, RING_LIFECYCLE).is_err());
    }

    #[test]
    fn errno_walk_finds_io_errors() {
        let io = std::io::Error::from_raw_os_error(13);
        assert_eq!(errno_of(&io), Some(13));
        let plain = std::io::Error::other("x");
        assert_eq!(errno_of(&plain), None);
    }
}
