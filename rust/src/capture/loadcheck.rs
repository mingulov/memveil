// SPDX-License-Identifier: GPL-3.0-or-later
//! Load diagnostics: errno names, verifier tails, load replay.
//!
//! `errno_name`/`errno_cause` name the small errno set a BPF
//! load can return; `verifier_tail` keeps the last lines of a
//! program log; `diagnose_load` replays one object load with
//! log-on-failure to recover those lines. Nothing here attaches.
//!
//! Loads run through the statically linked Aya loader: there is
//! no bridge path to open. `load_check` judges each object the
//! way record loads it ([`Session`](crate::bpf::Session) open,
//! load, then programs through the verifier; successes held
//! open in input order so the kernel charges the same peak as
//! record), then replays failures for the verifier tail. The
//! replay also supplies the errno the session verdict
//! swallows; when the replay itself loads, the detail says so
//! and the errno stays empty.

use crate::bpf::Session;
use crate::bpf::session::{
    SessionError, channel_for_programs, check_replay_maps, core_precondition, declared_map_specs,
    diagnose_program_loads,
};
use crate::platform::reader::bytes_to_text;
use aya::{EbpfLoader, VerifierLogLevel};

/// Retired bridge ABI load op: kept for diagnostic parsing.
const OP_LOAD: u32 = 2;
/// Verifier log capture cap in bytes (kept with the tail rule).
const DIAG_LOG_CAP: usize = 65536;
/// Verifier tail line count.
const TAIL_LINES: usize = 4;
/// Verifier tail line cap in bytes.
const TAIL_LINE_CAP: usize = 256;
/// Load detail clip in bytes.
const DETAIL_CAP: usize = 512;

/// Short name for one load errno, else `errno <n>`.
pub fn errno_name(code: i32) -> String {
    match code {
        -1 => "EPERM".to_string(),
        -2 => "ENOENT".to_string(),
        -7 => "E2BIG".to_string(),
        -12 => "ENOMEM".to_string(),
        -13 => "EACCES".to_string(),
        -16 => "EBUSY".to_string(),
        -22 => "EINVAL".to_string(),
        -28 => "ENOSPC".to_string(),
        -38 => "ENOSYS".to_string(),
        -95 => "EOPNOTSUPP".to_string(),
        -524 => "ENOTSUPP".to_string(),
        _ => format!("errno {code}"),
    }
}

/// One-line cause for a load errno, else `""`.
pub fn errno_cause(code: i32) -> String {
    match code {
        -1 => "needs CAP_BPF and CAP_PERFMON".to_string(),
        -12 => "memcg or memlock limit".to_string(),
        -13 | -22 => "verifier rejected, see log".to_string(),
        -7 => "program too large".to_string(),
        _ => String::new(),
    }
}

/// One machine code for a load errno name.
pub fn load_code_for(errno: &str) -> String {
    match errno {
        "EPERM" => "load-eperm".to_string(),
        "ENOMEM" => "load-enomem".to_string(),
        "EINVAL" | "EACCES" => "verifier-rejected".to_string(),
        _ => "load-failed".to_string(),
    }
}

/// First offset of word at or after start, else none.
fn find_from(raw: &[u8], word: &[u8], start: usize) -> Option<usize> {
    if word.is_empty() {
        return None;
    }
    let mut i = start;
    while i + word.len() <= raw.len() {
        if raw[i..i + word.len()] == *word {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Machine code for a load refusal diagnostic, else `""`.
///
/// Reads the first load segment as the kernel layer writes
/// it (`op=<OP_LOAD>` then `code=-<n>` ended by a space
/// or a colon); other operations, positive codes, and
/// out-of-range magnitudes stay unclassified.
pub fn load_refusal_code(diagnostic: &str) -> String {
    let raw = diagnostic.as_bytes();
    let op_key = format!("op={OP_LOAD} ");
    let code_key = " code=-";
    let op_word = "op=";
    let key_len = code_key.len();
    let mut pos = 0;
    loop {
        let Some(hit) = find_from(raw, op_key.as_bytes(), pos) else {
            return String::new();
        };
        let seg_end = find_from(raw, op_word.as_bytes(), hit + 1).unwrap_or(raw.len());
        if let Some(mark) = find_from(raw, code_key.as_bytes(), hit)
            && mark < seg_end
        {
            let mut n = 0i64;
            let mut digits = 0;
            let mut j = mark + key_len;
            while j < raw.len() && raw[j].is_ascii_digit() {
                n = n * 10 + i64::from(raw[j] - b'0');
                digits += 1;
                j += 1;
            }
            if digits > 0
                && digits <= 6
                && (1..=4095).contains(&n)
                && j < raw.len()
                && (raw[j] == 0x20 || raw[j] == 0x3A)
            {
                return load_code_for(&errno_name(-(n as i32)));
            }
        }
        pos = hit + 1;
    }
}

/// Escape one line: backslash n/t/r, U+FFFD for C0/DEL.
fn escape_line(s: &str) -> String {
    let mut out: Vec<u8> = Vec::new();
    for b in s.as_bytes() {
        match b {
            0x0A => out.extend_from_slice(b"\\n"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0D => out.extend_from_slice(b"\\r"),
            b if *b < 0x20 || *b == 0x7F => out.extend_from_slice(&[0xEF, 0xBF, 0xBD]),
            _ => out.push(*b),
        }
    }
    String::from_utf8(out.clone()).unwrap_or_else(|_| bytes_to_text(&out))
}

/// Clip one line to cap bytes at a UTF-8 edge.
fn clip_line(s: &str, cap: usize) -> String {
    let b = s.as_bytes();
    if b.len() <= cap {
        return s.to_string();
    }
    let mut n = cap;
    while n > 0 && b[n] >= 0x80 && b[n] < 0xC0 {
        n -= 1;
    }
    let cut = b[..n].to_vec();
    String::from_utf8(cut.clone()).unwrap_or_else(|_| bytes_to_text(&cut))
}

fn is_hex_digit(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn is_f_nibble(b: u8) -> bool {
    b == 0x46 || b == 0x66
}

/// Replace kernel-address patterns with `0xADDR`.
///
/// Redacts `0x`/`0X` runs of 8-16 hex digits and bare
/// 16-hex-digit runs starting with `ffff` (bounded on both
/// sides); shorter values, longer runs, and other hex stay,
/// so offsets, counts, and hashes survive.
fn redact_pointers(s: &str) -> String {
    let raw = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let marker = b"0xADDR";
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b == 0x30 && i + 1 < raw.len() && (raw[i + 1] == 0x78 || raw[i + 1] == 0x58) {
            let mut j = i + 2;
            while j < raw.len() && is_hex_digit(raw[j]) {
                j += 1;
            }
            if (8..=16).contains(&(j - (i + 2))) {
                out.extend_from_slice(marker);
                i = j;
                continue;
            }
            out.push(b);
            i += 1;
            continue;
        }
        if is_f_nibble(b) && (i == 0 || !is_hex_digit(raw[i - 1])) {
            let mut k = i;
            while k < raw.len() && k < i + 4 && is_f_nibble(raw[k]) {
                k += 1;
            }
            if k == i + 4 {
                let mut m = k;
                while m < raw.len() && m < i + 16 && is_hex_digit(raw[m]) {
                    m += 1;
                }
                if m == i + 16 && (m == raw.len() || !is_hex_digit(raw[m])) {
                    out.extend_from_slice(marker);
                    i = m;
                    continue;
                }
            }
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out.clone()).unwrap_or_else(|_| bytes_to_text(&out))
}

/// Escape, redact addresses, then cap one line at 256 bytes.
fn clean_verifier_line(raw: &[u8]) -> String {
    clip_line(
        &redact_pointers(&escape_line(&bytes_to_text(raw))),
        TAIL_LINE_CAP,
    )
}

/// Last 4 non-empty verifier lines, redacted, capped.
///
/// A truncated log gains the fixed first line naming the
/// 64 KiB cut; each kept line holds at most 256 bytes.
pub fn verifier_tail(log: &[u8], truncated: bool) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for b in log {
        if *b == 0x0A {
            if !cur.is_empty() {
                lines.push(clean_verifier_line(&cur));
                cur.clear();
            }
        } else {
            cur.push(*b);
        }
    }
    if !cur.is_empty() {
        lines.push(clean_verifier_line(&cur));
    }
    let mut out: Vec<String> = Vec::new();
    if truncated {
        out.push(format!("verifier log truncated at {DIAG_LOG_CAP} bytes"));
    }
    let mut start = 0;
    if lines.len() > TAIL_LINES {
        start = lines.len() - TAIL_LINES;
    }
    for line in lines.iter().skip(start) {
        out.push(line.clone());
    }
    out
}

/// One load replay: errno name plus verifier tail lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadDiag {
    /// Errno name; empty when the replay loaded.
    pub errno: String,
    /// Verifier tail lines on failure.
    pub lines: Vec<String>,
}

/// One object load attempt: state, errno name, detail.
///
/// Passive runs leave `load` empty; the load-check verb
/// fills one entry per requested capability without
/// attaching. `lines` carries the verifier tail on
/// failure; it renders into capability evidence, never
/// into the load entry itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadResult {
    /// Object kind label.
    pub object: String,
    /// `loaded`, `failed`, or `skipped`.
    pub state: String,
    /// Errno name; empty unless failed.
    pub errno: String,
    /// Clipped failure detail.
    pub detail: String,
    /// Verifier tail lines on failure.
    pub lines: Vec<String>,
}

impl Default for LoadResult {
    fn default() -> Self {
        Self {
            object: String::new(),
            state: "skipped".to_string(),
            errno: String::new(),
            detail: String::new(),
            lines: Vec::new(),
        }
    }
}

/// One object to load: channel kind, ELF bytes, programs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadTarget {
    /// Channel kind: `attempt`, `lifecycle`, or `copy`.
    pub kind: String,
    /// Object bytes.
    pub elf: Vec<u8>,
    /// Program names for load diagnostics.
    pub programs: Vec<String>,
}

/// Ring name for a load kind; unknown kinds pass through and
/// fail open with an unknown-ring refusal.
fn ring_for_kind(kind: &str) -> &str {
    match kind {
        "attempt" => "mv_attempts",
        "lifecycle" => "mv_lifecycle",
        "copy" => "mv_copies",
        _ => kind,
    }
}

/// First syscall errno walking the error source chain, if any.
pub(crate) fn errno_from_chain(mut err: &(dyn std::error::Error + 'static)) -> Option<i32> {
    loop {
        if let Some(raw) = err
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
        {
            return Some(raw);
        }
        err = err.source()?;
    }
}

/// Verifier log carried in a pinned-loader Display message, if any.
///
/// The loader renders program load failures as `... syscall
/// returned {io_error}. Verifier output: {log}`; the marker is
/// stable under the pinned loader version, and OS error text
/// can never contain it.
pub(crate) fn verifier_log_from_display(message: &str) -> Option<&str> {
    message
        .split_once(". Verifier output: ")
        .map(|(_, log)| log)
}

/// Reload one object for its verifier log; never attaches.
///
/// Loads the object with verbose log capture, then loads the
/// named programs without attaching; on failure names the
/// errno and tails the failing program's log. Every path
/// releases the object; nothing attaches. Unknown program
/// names skip. The loader grows its log buffer internally, so
/// the tail never carries a truncation marker. The replay
/// shares the session's CO-RE precondition: one sysfs BTF
/// read, a fail-closed refusal for relocation-carrying
/// objects when it fails, and that same parsed BTF handed to
/// the loader. It also shares the session's declared-map gate
/// for its channel, so a renegade object the verdict sent here
/// on a BTF outage cannot allocate on replay.
pub fn diagnose_load(elf: &[u8], programs: &[String]) -> LoadDiag {
    let mut out = LoadDiag::default();
    let pre = core_precondition(elf);
    if pre.relocations && pre.btf.is_none() {
        // The BTF read's own errno names the failure; a
        // corrupt (non-errno) blob reads as invalid input.
        out.errno = pre
            .read_errno
            .map(|raw| errno_name(0 - raw))
            .unwrap_or_else(|| "EINVAL".to_string());
        return out;
    }
    // Geometry gate: the verdict's CO-RE check returns before
    // the declared gate, so a BTF outage at verdict time sends
    // renegade objects here; the replay enforces the same channel
    // rule before allocating (a channel-blind replay keeps the
    // ring abuse cap). Empty errno, like other structural replay
    // refusals (garbage input behaves the same way).
    if let Some(declared) = declared_map_specs(elf)
        && check_replay_maps(channel_for_programs(programs), &declared).is_err()
    {
        return out;
    }
    let mut loader = EbpfLoader::new();
    loader.verifier_log_level(VerifierLogLevel::VERBOSE);
    loader.btf(pre.btf.as_ref());
    let mut bpf = match loader.load(elf) {
        Ok(bpf) => bpf,
        Err(e) => {
            if let Some(raw) = errno_from_chain(&e) {
                out.errno = errno_name(0 - raw);
            }
            if let Some(log) = verifier_log_from_display(&e.to_string()) {
                let tail = verifier_tail(log.as_bytes(), false);
                if !tail.is_empty() {
                    out.lines = tail;
                }
            }
            return out;
        }
    };
    // A maps-only replay can never see a verifier rejection: load
    // the named programs too, still without attaching.
    if let Err(failure) =
        diagnose_program_loads(&mut bpf, programs, pre.btf.as_ref(), pre.read_errno)
    {
        // A corrupt (non-errno) BTF blob reads as invalid input.
        out.errno = failure
            .errno
            .map(|raw| errno_name(0 - raw))
            .unwrap_or_else(|| "EINVAL".to_string());
        if let Some(log) = failure.log.as_ref() {
            let tail = verifier_tail(log.as_bytes(), false);
            if !tail.is_empty() {
                out.lines = tail;
            }
        }
    }
    out
}

/// Load every object without attaching; report each.
///
/// Probes every verdict the way record loads it (maps, then
/// programs through the verifier), keeping earlier loads open
/// in input (record) order so the kernel charges the same peak
/// as record, then releases all. A failed verdict replays once
/// for the tail in `lines`; the replay errno substitutes for
/// the verdict errno the session swallows, and a replay that
/// loads appends the fixed suffix to the verdict detail.
/// Static geometry refusals skip the replay: no kernel failure
/// to diagnose. Map sizes are the objects' declared sizes.
/// Nothing attaches.
pub fn load_check(objects: &[LoadTarget]) -> Vec<LoadResult> {
    let mut out: Vec<LoadResult> = Vec::new();
    let mut sessions: Vec<Option<Session>> = Vec::new();
    for target in objects {
        let mut res = LoadResult {
            object: target.kind.clone(),
            ..Default::default()
        };
        match Session::open(&target.elf, ring_for_kind(&target.kind)) {
            Ok(sess) => {
                sessions.push(Some(sess));
                res.state = String::new();
            }
            Err(e) => {
                sessions.push(None);
                res.state = "failed".to_string();
                res.detail = clip_line(
                    &format!("cannot open {} object: {e}", target.kind),
                    DETAIL_CAP,
                );
            }
        }
        out.push(res);
    }
    for (i, target) in objects.iter().enumerate() {
        let Some(sess) = sessions[i].as_mut() else {
            continue;
        };
        let verdict = match sess.load() {
            Ok(()) => sess.load_programs(),
            Err(error) => Err(error),
        };
        match verdict {
            Ok(()) => {
                out[i].state = "loaded".to_string();
            }
            Err(e) => {
                out[i].state = "failed".to_string();
                out[i].detail = clip_line(&e.to_string(), DETAIL_CAP);
                if matches!(e, SessionError::Geometry(_)) {
                    // Static gate refusal: no kernel failure to
                    // diagnose, and replaying would re-attempt the
                    // refused allocation.
                    continue;
                }
                let diag = diagnose_load(&target.elf, &target.programs);
                out[i].errno = diag.errno.clone();
                out[i].lines = diag.lines.clone();
                if diag.errno.is_empty() {
                    out[i].detail = clip_line(
                        &format!("{}; diagnostic replay loaded", out[i].detail),
                        DETAIL_CAP,
                    );
                }
            }
        }
    }
    for sess in sessions.iter_mut().flatten() {
        let _ = sess.close();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        LoadTarget, diagnose_load, errno_name, load_check, load_code_for, load_refusal_code,
        verifier_tail,
    };
    use crate::platform::test_support::repo_root;

    #[test]
    fn errno_names() {
        assert_eq!(errno_name(-1), "EPERM");
        assert_eq!(errno_name(-2), "ENOENT");
        assert_eq!(errno_name(-7), "E2BIG");
        assert_eq!(errno_name(-12), "ENOMEM");
        assert_eq!(errno_name(-13), "EACCES");
        assert_eq!(errno_name(-16), "EBUSY");
        assert_eq!(errno_name(-22), "EINVAL");
        assert_eq!(errno_name(-28), "ENOSPC");
        assert_eq!(errno_name(-38), "ENOSYS");
        assert_eq!(errno_name(-95), "EOPNOTSUPP");
        assert_eq!(errno_name(-524), "ENOTSUPP");
        assert_eq!(errno_name(-99), "errno -99");
    }

    #[test]
    fn load_code_for_table() {
        assert_eq!(load_code_for("EPERM"), "load-eperm");
        assert_eq!(load_code_for("ENOMEM"), "load-enomem");
        assert_eq!(load_code_for("EINVAL"), "verifier-rejected");
        assert_eq!(load_code_for("EACCES"), "verifier-rejected");
        assert_eq!(load_code_for("EOPNOTSUPP"), "load-failed");
        assert_eq!(load_code_for(""), "load-failed");
    }

    fn load_msg(code: i32) -> String {
        format!("op=2 domain=2 code={code}: object load failed")
    }

    #[test]
    fn refusal_code_table() {
        assert_eq!(load_refusal_code(&load_msg(-1)), "load-eperm");
        assert_eq!(load_refusal_code(&load_msg(-12)), "load-enomem");
        assert_eq!(load_refusal_code(&load_msg(-22)), "verifier-rejected");
        assert_eq!(load_refusal_code(&load_msg(-13)), "verifier-rejected");
        assert_eq!(load_refusal_code(&load_msg(-95)), "load-failed");
        // Other operations stay unclassified.
        assert_eq!(load_refusal_code("op=3 domain=2 code=-1: x"), "");
        // Positive codes stay unclassified.
        assert_eq!(load_refusal_code(&load_msg(3)), "");
        // Undiagnosed text stays unclassified.
        assert_eq!(load_refusal_code("lmb_load: object load failed"), "");
        // The first load segment classifies inside a join.
        let both = format!("ch0 op=3 domain=2 code=-1: x; ch1 {}", load_msg(-1));
        assert_eq!(load_refusal_code(&both), "load-eperm");
        // A colon ends the code segment too.
        assert_eq!(
            load_refusal_code("ch0 op=2 domain=2 code=-22: object load failed"),
            "verifier-rejected"
        );
        // Out-of-range magnitudes stay unclassified.
        assert_eq!(load_refusal_code(&load_msg(-5000)), "");
        assert_eq!(load_refusal_code("op=2 domain=2 code=-0 x"), "");
    }

    fn log_bytes(lines: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in lines {
            out.extend_from_slice(line.as_bytes());
            out.push(0x0A);
        }
        out
    }

    #[test]
    fn tail_truncated() {
        let lines = vec![
            "line1", "line2", "line3", "line4", "line5", "", "line6", "line7", "line8", "line9",
            "line10",
        ];
        let tail = verifier_tail(&log_bytes(&lines), true);
        assert_eq!(tail.len(), 5);
        assert_eq!(tail[0], "verifier log truncated at 65536 bytes");
        assert_eq!(tail[1], "line7");
        assert_eq!(tail[2], "line8");
        assert_eq!(tail[3], "line9");
        assert_eq!(tail[4], "line10");
        let mut wide = vec![0x41u8; 300];
        wide.push(0x0A);
        let cut = verifier_tail(&wide, false);
        assert_eq!(cut.len(), 1);
        assert_eq!(cut[0].len(), 256);
        let dirty = b"l8\x07x\n".to_vec();
        let clean = verifier_tail(&dirty, false);
        assert_eq!(clean.len(), 1);
        assert_eq!(clean[0].as_bytes(), b"l8\xef\xbf\xbdx");
    }

    #[test]
    fn tail_redacts_pointers() {
        let lines = vec![
            "1: R2_w=0xffff888012345678",
            "2: imm=0xFFFFFFFF81234567 off=0x1234",
            "3: bare ffff888012345678 and hash deadbeef01",
            "4: short 0x1234567 kept, long 0x123456789abcdef01 kept",
        ];
        let tail = verifier_tail(&log_bytes(&lines), false);
        assert_eq!(tail.len(), 4);
        assert_eq!(tail[0], "1: R2_w=0xADDR");
        assert_eq!(tail[1], "2: imm=0xADDR off=0x1234");
        assert_eq!(tail[2], "3: bare 0xADDR and hash deadbeef01");
        assert_eq!(
            tail[3],
            "4: short 0x1234567 kept, long 0x123456789abcdef01 kept"
        );
        for line in &tail {
            assert!(!line.contains("ffff8880"));
            assert!(!line.contains("FFFFFFFF"));
        }
        let mut wide = b"x=0xffff888012345678 pad:".to_vec();
        wide.extend_from_slice(&vec![0x41u8; 300]);
        wide.push(0x0A);
        let cut = verifier_tail(&wide, false);
        assert_eq!(cut.len(), 1);
        assert_eq!(cut[0].len(), 256);
        assert!(!cut[0].contains("ffff8880"));
        assert!(cut[0].contains("0xADDR"));
    }

    fn attempt_target() -> LoadTarget {
        let path = repo_root().join("tests/fixtures/elf/ok.o");
        let elf = std::fs::read(&path).expect("read ok.o fixture");
        LoadTarget {
            kind: "attempt".to_string(),
            elf,
            programs: vec!["mv_swiotlb_attempt".to_string()],
        }
    }

    #[test]
    fn check_eperm_unprivileged() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIP check_eperm_unprivileged: running as root");
            return;
        }
        let results = load_check(&[attempt_target()]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, "failed");
        assert_eq!(results[0].errno, "EPERM");
    }

    #[test]
    fn check_garbage_elf_fails_open() {
        let target = LoadTarget {
            kind: "attempt".to_string(),
            elf: vec![0x7F, b'E', b'L', b'F', 9, 9, 9, 9],
            programs: vec!["mv_swiotlb_attempt".to_string()],
        };
        let results = load_check(&[target]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, "failed");
        assert!(results[0].detail.contains("cannot open"));
        assert!(results[0].lines.is_empty());
    }

    #[test]
    fn diagnose_garbage_elf_has_no_errno() {
        let diag = diagnose_load(&[0u8; 16], &["mv_swiotlb_attempt".to_string()]);
        assert_eq!(diag.errno, "");
    }

    /// File range of the named section, via the ELF section table.
    fn section_range(elf: &[u8], want: &str) -> (usize, usize) {
        let shoff = u64::from_le_bytes(elf[0x28..0x30].try_into().expect("shoff")) as usize;
        let shentsize = u16::from_le_bytes(elf[0x3a..0x3c].try_into().expect("shentsize")) as usize;
        let shnum = u16::from_le_bytes(elf[0x3c..0x3e].try_into().expect("shnum")) as usize;
        let shstrndx = u16::from_le_bytes(elf[0x3e..0x40].try_into().expect("shstrndx")) as usize;
        let shstr = shoff + shstrndx * shentsize;
        let str_off =
            u64::from_le_bytes(elf[shstr + 24..shstr + 32].try_into().expect("str")) as usize;
        let str_len =
            u64::from_le_bytes(elf[shstr + 32..shstr + 40].try_into().expect("len")) as usize;
        let strtab = &elf[str_off..str_off + str_len];
        for index in 0..shnum {
            let header = shoff + index * shentsize;
            let name_off =
                u32::from_le_bytes(elf[header..header + 4].try_into().expect("name")) as usize;
            let tail = &strtab[name_off..];
            let end = tail.iter().position(|byte| *byte == 0).unwrap_or(0);
            if &tail[..end] == want.as_bytes() {
                let off = u64::from_le_bytes(elf[header + 24..header + 32].try_into().expect("off"))
                    as usize;
                let len = u64::from_le_bytes(elf[header + 32..header + 40].try_into().expect("len"))
                    as usize;
                return (off, len);
            }
        }
        panic!("no {want} section");
    }

    /// Size of one BTF type record at `at`: 12 header bytes plus the
    /// kind's trailing array.
    fn btf_type_len(elf: &[u8], at: usize) -> usize {
        let info = u32::from_le_bytes(elf[at + 4..at + 8].try_into().expect("info"));
        let kind = (info >> 24) & 31;
        let vlen = (info & 0xFFFF) as usize;
        12 + match kind {
            1 | 14 | 17 => 4,
            3 => 12,
            4 | 6 | 15 | 16 => vlen * 12,
            5 => vlen * 8,
            13 => vlen * 8,
            19 => vlen * 16,
            _ => 0,
        }
    }

    /// `ok.o` with every 8 MiB BTF array length widened to 2 GiB:
    /// sections and programs untouched, the ring declaration
    /// oversized. Returns the patched bytes plus the patched count.
    fn oversize_ring_elf() -> (Vec<u8>, usize) {
        let path = repo_root().join("tests/fixtures/elf/ok.o");
        let mut elf = std::fs::read(&path).expect("read ok.o fixture");
        let (off, _) = section_range(&elf, ".BTF");
        let magic = u16::from_le_bytes(elf[off..off + 2].try_into().expect("magic"));
        assert_eq!(magic, 0xEB9F, "BTF magic");
        let hdr = u32::from_le_bytes(elf[off + 4..off + 8].try_into().expect("hdr")) as usize;
        let type_off =
            u32::from_le_bytes(elf[off + 8..off + 12].try_into().expect("toff")) as usize;
        let type_len =
            u32::from_le_bytes(elf[off + 12..off + 16].try_into().expect("tlen")) as usize;
        let mut patched = 0;
        let mut at = off + hdr + type_off;
        let end = at + type_len;
        while at + 12 <= end {
            let info = u32::from_le_bytes(elf[at + 4..at + 8].try_into().expect("info"));
            if (info >> 24) & 31 == 3 {
                let len_at = at + 20;
                let len = u32::from_le_bytes(elf[len_at..len_at + 4].try_into().expect("nelems"));
                if len == 8_388_608 {
                    elf[len_at..len_at + 4].copy_from_slice(&2_147_483_648u32.to_le_bytes());
                    patched += 1;
                }
            }
            at += btf_type_len(&elf, at);
        }
        (elf, patched)
    }

    #[test]
    fn check_oversize_ring_refused_before_load() {
        // A real object whose only sin is a 2 GiB ring declaration:
        // the verdict refuses naming the ring, with no errno and
        // no replay — the refusal is static, before any syscall
        // (unprivileged runs see Geometry, not EPERM).
        let (elf, patched) = oversize_ring_elf();
        assert!(patched >= 1, "must widen at least the ring array");
        let target = LoadTarget {
            kind: "attempt".to_string(),
            elf,
            programs: vec!["mv_swiotlb_attempt".to_string()],
        };
        let results = load_check(&[target]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, "failed");
        assert!(
            results[0].detail.contains("mv_attempts"),
            "refusal must name the ring, got: {}",
            results[0].detail
        );
        assert_eq!(results[0].errno, "");
        assert!(results[0].lines.is_empty());
        assert!(
            !results[0].detail.contains("diagnostic replay loaded"),
            "geometry refusals skip the replay, got: {}",
            results[0].detail
        );
    }

    /// `ok.o` with the 6-entry `mv_counts` BTF array length widened
    /// to 2 GiB entries: sections and programs untouched, one
    /// non-ring declaration oversized. Returns the patched bytes
    /// plus the patched count.
    fn oversize_counts_elf() -> (Vec<u8>, usize) {
        let path = repo_root().join("tests/fixtures/elf/ok.o");
        let mut elf = std::fs::read(&path).expect("read ok.o fixture");
        let (off, _) = section_range(&elf, ".BTF");
        let magic = u16::from_le_bytes(elf[off..off + 2].try_into().expect("magic"));
        assert_eq!(magic, 0xEB9F, "BTF magic");
        let hdr = u32::from_le_bytes(elf[off + 4..off + 8].try_into().expect("hdr")) as usize;
        let type_off =
            u32::from_le_bytes(elf[off + 8..off + 12].try_into().expect("toff")) as usize;
        let type_len =
            u32::from_le_bytes(elf[off + 12..off + 16].try_into().expect("tlen")) as usize;
        let mut patched = 0;
        let mut at = off + hdr + type_off;
        let end = at + type_len;
        while at + 12 <= end {
            let info = u32::from_le_bytes(elf[at + 4..at + 8].try_into().expect("info"));
            if (info >> 24) & 31 == 3 {
                let len_at = at + 20;
                let len = u32::from_le_bytes(elf[len_at..len_at + 4].try_into().expect("nelems"));
                if len == 6 {
                    elf[len_at..len_at + 4].copy_from_slice(&2_147_483_648u32.to_le_bytes());
                    patched += 1;
                }
            }
            at += btf_type_len(&elf, at);
        }
        (elf, patched)
    }

    #[test]
    fn replay_refuses_oversize_nonring_map() {
        // A real object whose only sin is a 2 GiB `mv_counts`
        // declaration: the ring-only cap admits it, but the replay
        // shares the session's channel gate and refuses before
        // allocating — empty errno, no lines. The refusal is
        // userspace, so it holds on every privilege; pre-fix the
        // replay proceeded to the loader (EPERM unprivileged).
        use crate::bpf::session::declared_map_specs;
        let (elf, patched) = oversize_counts_elf();
        assert_eq!(patched, 1, "must widen exactly the counts array");
        let declared = declared_map_specs(&elf).expect("patched object must parse");
        let counts = declared
            .iter()
            .find(|row| row.name == "mv_counts")
            .expect("patched object declares mv_counts");
        assert_eq!(counts.max_entries, 2_147_483_648);
        let diag = diagnose_load(&elf, &["mv_swiotlb_attempt".to_string()]);
        assert_eq!(diag.errno, "");
        assert!(diag.lines.is_empty());
    }

    #[test]
    fn check_drifted_table_refused_before_load() {
        // badmap.o opens (right sections) but declares mv_counts
        // with 7 entries: static refusal naming the table, no
        // replay, on every privilege.
        let path = repo_root().join("tests/fixtures/elf/badmap.o");
        let elf = std::fs::read(&path).expect("read badmap.o fixture");
        let target = LoadTarget {
            kind: "attempt".to_string(),
            elf,
            programs: vec!["mv_swiotlb_attempt".to_string()],
        };
        let results = load_check(&[target]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, "failed");
        assert!(
            results[0].detail.contains("mv_counts"),
            "refusal must name the table, got: {}",
            results[0].detail
        );
        assert_eq!(results[0].errno, "");
        assert!(results[0].lines.is_empty());
    }

    /// File range of the first section whose name starts with the
    /// prefix.
    fn section_range_prefix(elf: &[u8], prefix: &str) -> (usize, usize) {
        let shoff = u64::from_le_bytes(elf[0x28..0x30].try_into().expect("shoff")) as usize;
        let shentsize = u16::from_le_bytes(elf[0x3a..0x3c].try_into().expect("shentsize")) as usize;
        let shnum = u16::from_le_bytes(elf[0x3c..0x3e].try_into().expect("shnum")) as usize;
        let shstrndx = u16::from_le_bytes(elf[0x3e..0x40].try_into().expect("shstrndx")) as usize;
        let shstr = shoff + shstrndx * shentsize;
        let str_off =
            u64::from_le_bytes(elf[shstr + 24..shstr + 32].try_into().expect("str")) as usize;
        let str_len =
            u64::from_le_bytes(elf[shstr + 32..shstr + 40].try_into().expect("len")) as usize;
        let strtab = &elf[str_off..str_off + str_len];
        for index in 0..shnum {
            let header = shoff + index * shentsize;
            let name_off =
                u32::from_le_bytes(elf[header..header + 4].try_into().expect("name")) as usize;
            let tail = &strtab[name_off..];
            let end = tail.iter().position(|byte| *byte == 0).unwrap_or(0);
            if tail[..end].starts_with(prefix.as_bytes()) {
                let off = u64::from_le_bytes(elf[header + 24..header + 32].try_into().expect("off"))
                    as usize;
                let len = u64::from_le_bytes(elf[header + 32..header + 40].try_into().expect("len"))
                    as usize;
                return (off, len);
            }
        }
        panic!("no {prefix} section");
    }

    /// Embedded attempt object with its first instruction replaced
    /// by `ja +32767` (a jump out of range): sections, maps, and
    /// programs untouched, so every geometry gate passes and only
    /// the verifier refuses.
    fn verifier_rejected_attempt_elf() -> Vec<u8> {
        let path = env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH");
        let mut elf = std::fs::read(path).expect("read attempt ELF");
        let (off, len) = section_range_prefix(&elf, "tracepoint/");
        assert!(len >= 8, "program section must hold one instruction");
        elf[off..off + 8].copy_from_slice(&[0x05, 0x00, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00]);
        elf
    }

    #[test]
    fn check_verifier_rejected_control() {
        // The load-check runs the verifier: a geometry-clean object
        // whose program jumps out of range fails with the verifier
        // errno plus a bounded tail — never `loaded`, never a bare
        // geometry refusal. Needs root: only privilege reaches the
        // verifier.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP check_verifier_rejected_control: needs root");
            return;
        }
        let target = LoadTarget {
            kind: "attempt".to_string(),
            elf: verifier_rejected_attempt_elf(),
            programs: vec!["mv_swiotlb_attempt".to_string()],
        };
        let results = load_check(&[target]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, "failed");
        assert_eq!(results[0].errno, "EINVAL");
        assert!(
            !results[0].lines.is_empty() && results[0].lines.len() <= 4,
            "replay must tail the rejection, got: {:?}",
            results[0].lines
        );
        assert!(
            results[0].detail.contains("mv_swiotlb_attempt")
                && results[0].detail.contains("load failed")
                && results[0].detail.contains("(os error 22)"),
            "detail must name the program load failure, got: {}",
            results[0].detail
        );
        assert!(
            !results[0].detail.contains("Verifier output"),
            "detail must never carry the full log, got: {}",
            results[0].detail
        );
    }

    #[test]
    fn check_smaller_ring_reaches_past_precheck() {
        // badring.o declares a 4 MiB ring: smaller than the frozen
        // 8 MiB, so the pre-check admits it. Unprivileged runs then
        // fail at the map syscall (EPERM via the replay); root
        // loads it outright.
        let path = repo_root().join("tests/fixtures/elf/badring.o");
        let elf = std::fs::read(&path).expect("read badring.o fixture");
        let target = LoadTarget {
            kind: "attempt".to_string(),
            elf,
            programs: vec!["mv_swiotlb_attempt".to_string()],
        };
        let results = load_check(&[target]);
        assert_eq!(results.len(), 1);
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(results[0].state, "loaded");
        } else {
            assert_eq!(results[0].state, "failed");
            assert_eq!(results[0].errno, "EPERM");
        }
    }
}
