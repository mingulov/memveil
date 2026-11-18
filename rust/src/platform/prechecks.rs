// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive pre-checks: privilege, memcg headroom, BPF sysctl.
//!
//! Each check reads procfs/sysfs evidence without loading
//! anything: fail means the capability cannot run, unknown
//! leaves it load-unchecked with the check line as evidence.

use super::reader::{
    EVIDENCE_ABSENT, EVIDENCE_DENIED, EvidenceReader, bytes_to_text, file_state, read_evidence,
};
use crate::model::validate::format_u64;

/// /proc/self/status evidence path.
pub const P_STATUS: &str = "/proc/self/status";
/// /proc/self/cgroup evidence path.
pub const P_CGROUP_SELF: &str = "/proc/self/cgroup";
/// cgroup filesystem root.
pub const P_CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// /proc/self/uid_map evidence path.
pub const P_UID_MAP: &str = "/proc/self/uid_map";
/// unprivileged-BPF sysctl path.
pub const P_UNPRIV_BPF: &str = "/proc/sys/kernel/unprivileged_bpf_disabled";

const STATUS_CAP: usize = 65_536;
const CGROUP_CAP: usize = 65_536;
const MEMCG_CAP: usize = 4096;
const UIDMAP_CAP: usize = 4096;
const UNPRIV_CAP: usize = 4096;

/// One passive pre-check: id, state, reason, code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreCheck {
    /// Check id (`privilege`, `memcg`, `unprivileged-bpf`).
    pub id: String,
    /// `pass`, `fail`, or `unknown`.
    pub state: String,
    /// Human reason.
    pub reason: String,
    /// Machine code, or `""`.
    pub code: String,
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn hex_val(b: u8) -> u64 {
    match b {
        b'0'..=b'9' => u64::from(b - b'0'),
        b'a'..=b'f' => u64::from(b - b'a') + 10,
        _ => u64::from(b - b'A') + 10,
    }
}

fn is_blank(b: u8) -> bool {
    b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D
}

/// Core bytes between leading and trailing blanks.
fn strip_token(raw: &[u8]) -> Vec<u8> {
    let mut s = 0;
    while s < raw.len() && is_blank(raw[s]) {
        s += 1;
    }
    let mut e = raw.len();
    while e > s && is_blank(raw[e - 1]) {
        e -= 1;
    }
    raw[s..e].to_vec()
}

/// True when raw holds exactly 0, 0, 4294967295 as tokens.
fn is_init_uidmap(raw: &[u8]) -> bool {
    let mut toks = Vec::new();
    let mut cur = Vec::new();
    for &b in raw {
        if is_blank(b) {
            if !cur.is_empty() {
                toks.push(bytes_to_text(&cur));
                cur = Vec::new();
            }
            continue;
        }
        cur.push(b);
    }
    if !cur.is_empty() {
        toks.push(bytes_to_text(&cur));
    }
    if toks.len() != 3 {
        return false;
    }
    toks[0] == "0" && toks[1] == "0" && toks[2] == "4294967295"
}

/// Pass iff init-namespace CapEff grants BPF or sysadmin.
///
/// capable() checks the init user namespace, so a
/// namespaced CapEff cannot pass. An absent uid_map
/// means the kernel has no user namespaces at all.
pub fn check_privilege(reader: &EvidenceReader) -> PreCheck {
    let unknown = |reason: String| PreCheck {
        id: "privilege".to_string(),
        state: "unknown".to_string(),
        reason,
        code: String::new(),
    };
    let st = file_state(reader, P_STATUS);
    if st == EVIDENCE_ABSENT {
        return unknown("CapEff unreadable: absent".to_string());
    }
    if st == EVIDENCE_DENIED {
        return unknown("CapEff unreadable: denied".to_string());
    }
    let ust = file_state(reader, P_UID_MAP);
    if ust == EVIDENCE_DENIED {
        return unknown("user namespace unreadable: denied".to_string());
    }
    if ust != EVIDENCE_ABSENT {
        let umap = match read_evidence(reader, P_UID_MAP, UIDMAP_CAP) {
            Ok(umap) => umap,
            Err(e) => {
                return unknown(format!("user namespace unreadable: {}", e));
            }
        };
        if !is_init_uidmap(&umap) {
            return unknown("non-init user namespace: CapEff is namespaced".to_string());
        }
    }
    let text = match read_evidence(reader, P_STATUS, STATUS_CAP) {
        Ok(raw) => bytes_to_text(&raw),
        Err(e) => {
            return unknown(format!("CapEff unreadable: {}", e));
        }
    };
    let mut bad = true;
    let mut cap: u64 = 0;
    for line in text.split('\n') {
        if !line.starts_with("CapEff:") {
            continue;
        }
        // The first CapEff line always decides: every path below
        // breaks, so a second line is unreachable here, exactly as
        // in the source, whose second-line guard never fires.
        let lb = line.as_bytes();
        let mut vstart = 7;
        while vstart < lb.len() && is_blank(lb[vstart]) {
            vstart += 1;
        }
        let mut vend = vstart;
        while vend < lb.len() && !is_blank(lb[vend]) {
            vend += 1;
        }
        let mut rest = vend;
        while rest < lb.len() && is_blank(lb[rest]) {
            rest += 1;
        }
        if rest != lb.len() || vend - vstart != 16 {
            break;
        }
        let mut v: u64 = 0;
        let mut ok = true;
        for &b in &lb[vstart..vend] {
            if !is_hex(b) {
                ok = false;
                break;
            }
            v = v * 16 + hex_val(b);
        }
        if !ok {
            break;
        }
        cap = v;
        bad = false;
        break;
    }
    if bad {
        return unknown("CapEff unreadable: malformed".to_string());
    }
    let bpf = (cap >> 39) & 1 == 1;
    let perfmon = (cap >> 38) & 1 == 1;
    let admin = (cap >> 21) & 1 == 1;
    if (bpf && perfmon) || admin {
        let mut grant = "CAP_BPF+CAP_PERFMON".to_string();
        if !(bpf && perfmon) {
            grant = "CAP_SYS_ADMIN".to_string();
        }
        return PreCheck {
            id: "privilege".to_string(),
            state: "pass".to_string(),
            reason: format!("CapEff has {grant}"),
            code: String::new(),
        };
    }
    PreCheck {
        id: "privilege".to_string(),
        state: "fail".to_string(),
        reason: "CapEff lacks CAP_BPF+CAP_PERFMON and CAP_SYS_ADMIN".to_string(),
        code: "no-bpf-privilege".to_string(),
    }
}

/// One memcg file: unlimited, value, or unknown with why.
struct MemVal {
    unlimited: bool,
    known: bool,
    value: u64,
    why: String,
}

/// Read one memcg limit/usage file with strict digits.
fn read_mem_val(reader: &EvidenceReader, path: &str, allow_max: bool) -> MemVal {
    let mut out = MemVal {
        unlimited: false,
        known: false,
        value: 0,
        why: String::new(),
    };
    let st = file_state(reader, path);
    if st == EVIDENCE_ABSENT {
        out.unlimited = true;
        return out;
    }
    if st == EVIDENCE_DENIED {
        out.why = format!("{path} unreadable: denied");
        return out;
    }
    let raw = match read_evidence(reader, path, MEMCG_CAP) {
        Ok(raw) => raw,
        Err(e) => {
            out.why = format!("{path} unreadable: {}", e);
            return out;
        }
    };
    let tok = strip_token(&raw);
    if allow_max && tok.len() == 3 && tok == b"max" {
        out.unlimited = true;
        return out;
    }
    if tok.is_empty() || tok.len() > 20 {
        out.why = format!("{path} malformed");
        return out;
    }
    let mut v: u64 = 0;
    for &b in &tok {
        if !b.is_ascii_digit() {
            out.why = format!("{path} malformed");
            return out;
        }
        let d = u64::from(b - b'0');
        if v > (u64::MAX - d) / 10 {
            v = u64::MAX;
        } else {
            v = v * 10 + d;
        }
    }
    out.known = true;
    out.value = v;
    out
}

/// Pass iff every ancestor cgroup fits `need` bytes.
///
/// A shortfall is unknown, not fail: memory.current
/// counts reclaimable page cache and map allocation
/// reclaims. A root path is unknown too: it may be a
/// cgroup-namespace root with invisible outer limits.
pub fn check_memcg(reader: &EvidenceReader, need: i64) -> PreCheck {
    let unknown = |reason: String, code: &str| PreCheck {
        id: "memcg".to_string(),
        state: "unknown".to_string(),
        reason,
        code: code.to_string(),
    };
    let st = file_state(reader, P_CGROUP_SELF);
    if st == EVIDENCE_ABSENT {
        return unknown("cgroup unreadable: absent".to_string(), "");
    }
    if st == EVIDENCE_DENIED {
        return unknown("cgroup unreadable: denied".to_string(), "");
    }
    let text = match read_evidence(reader, P_CGROUP_SELF, CGROUP_CAP) {
        Ok(raw) => bytes_to_text(&raw),
        Err(e) => {
            return unknown(format!("cgroup unreadable: {}", e), "");
        }
    };
    let mut cgpath = String::new();
    let mut found = false;
    for line in text.split('\n') {
        if !line.starts_with("0::") {
            continue;
        }
        let lb = line.as_bytes();
        let stripped = strip_token(&lb[3..]);
        for &b in &stripped {
            if is_blank(b) {
                return unknown("malformed cgroup path".to_string(), "");
            }
        }
        cgpath = bytes_to_text(&stripped);
        found = true;
        break;
    }
    if !found {
        return unknown("no 0:: cgroup line".to_string(), "");
    }
    let mut comps = Vec::new();
    let mut cur = Vec::new();
    for &b in cgpath.as_bytes() {
        if b == 0x2F {
            if !cur.is_empty() {
                comps.push(bytes_to_text(&cur));
                cur = Vec::new();
            }
        } else {
            cur.push(b);
        }
    }
    if !cur.is_empty() {
        comps.push(bytes_to_text(&cur));
    }
    if comps.is_empty() {
        return unknown(
            "cgroup at /: possible cgroup namespace, outer limits unknown".to_string(),
            "",
        );
    }
    for c in &comps {
        if c == "." || c == ".." {
            return unknown("malformed cgroup path".to_string(), "");
        }
    }
    let mut want: u64 = 0;
    if need > 0 {
        want = need as u64;
    }
    let mut best = u64::MAX;
    let mut best_path = "/".to_string();
    let mut constrained = false;
    let mut prefix = String::new();
    for c in &comps {
        prefix += "/";
        prefix += c;
        let dir = format!("{}{}", P_CGROUP_ROOT, prefix);
        let maxv = read_mem_val(reader, &format!("{dir}/memory.max"), true);
        if !maxv.why.is_empty() {
            return unknown(maxv.why, "");
        }
        if maxv.unlimited {
            continue;
        }
        let curv = read_mem_val(reader, &format!("{dir}/memory.current"), false);
        if !curv.why.is_empty() {
            return unknown(curv.why, "");
        }
        if curv.unlimited {
            return unknown(format!("{dir}/memory.current unreadable: absent"), "");
        }
        let mut headroom: u64 = 0;
        if maxv.value >= curv.value {
            headroom = maxv.value - curv.value;
        }
        if !constrained || headroom < best {
            best = headroom;
            best_path = prefix.clone();
            constrained = true;
        }
    }
    let mut disp = cgpath.clone();
    if disp.is_empty() {
        disp = "/".to_string();
    }
    if !constrained {
        return PreCheck {
            id: "memcg".to_string(),
            state: "pass".to_string(),
            reason: format!("memcg headroom unlimited ({disp})"),
            code: String::new(),
        };
    }
    if best < want {
        return PreCheck {
            id: "memcg".to_string(),
            state: "unknown".to_string(),
            reason: format!(
                "memcg headroom {} bytes below the objects' {need} bytes (at {best_path})",
                format_u64(best)
            ),
            code: "memcg-headroom".to_string(),
        };
    }
    PreCheck {
        id: "memcg".to_string(),
        state: "pass".to_string(),
        reason: format!(
            "memcg headroom {} bytes covers the objects' {need} bytes (at {best_path})",
            format_u64(best)
        ),
        code: String::new(),
    }
}

/// Report the unprivileged-BPF sysctl; never fails.
pub fn check_unprivileged_bpf(reader: &EvidenceReader) -> PreCheck {
    let unknown = |reason: &str| PreCheck {
        id: "unprivileged-bpf".to_string(),
        state: "unknown".to_string(),
        reason: reason.to_string(),
        code: String::new(),
    };
    let st = file_state(reader, P_UNPRIV_BPF);
    if st == EVIDENCE_ABSENT {
        return unknown("unprivileged_bpf_disabled unreadable: absent");
    }
    if st == EVIDENCE_DENIED {
        return unknown("unprivileged_bpf_disabled unreadable: denied");
    }
    let raw = match read_evidence(reader, P_UNPRIV_BPF, UNPRIV_CAP) {
        Ok(raw) => raw,
        Err(e) => {
            return PreCheck {
                id: "unprivileged-bpf".to_string(),
                state: "unknown".to_string(),
                reason: format!("unprivileged_bpf_disabled unreadable: {}", e),
                code: String::new(),
            };
        }
    };
    let tok = strip_token(&raw);
    if tok.len() != 1 {
        return unknown("unprivileged_bpf_disabled malformed");
    }
    let v = tok[0];
    if v != 0x30 && v != 0x31 && v != 0x32 {
        return unknown("unprivileged_bpf_disabled malformed");
    }
    PreCheck {
        id: "unprivileged-bpf".to_string(),
        state: "pass".to_string(),
        reason: format!("unprivileged_bpf_disabled={}", bytes_to_text(&[v])),
        code: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{check_memcg, check_privilege, check_unprivileged_bpf};
    use crate::platform::reader::open_evidence_reader;
    use crate::platform::test_support::gate_fixture;

    fn gate(name: &str) -> String {
        gate_fixture(name)
    }

    fn has_hex_run(s: &str, width: usize) -> bool {
        let mut run = 0;
        for b in s.as_bytes() {
            if b.is_ascii_hexdigit() {
                run += 1;
                if run >= width {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    #[test]
    fn privilege() {
        let base = check_privilege(&open_evidence_reader(&gate("base")).expect("fixture opens"));
        assert_eq!(base.state, "pass");
        assert_eq!(base.code, "");
        assert_eq!(base.reason, "CapEff has CAP_BPF+CAP_PERFMON");
        let both = check_privilege(
            &open_evidence_reader(&gate("caps-bpf-perfmon")).expect("fixture opens"),
        );
        assert_eq!(both.state, "pass");
        assert_eq!(both.reason, "CapEff has CAP_BPF+CAP_PERFMON");
        let admin =
            check_privilege(&open_evidence_reader(&gate("caps-sysadmin")).expect("fixture opens"));
        assert_eq!(admin.state, "pass");
        assert_eq!(admin.reason, "CapEff has CAP_SYS_ADMIN");
        let none =
            check_privilege(&open_evidence_reader(&gate("caps-none")).expect("fixture opens"));
        assert_eq!(none.state, "fail");
        assert_eq!(none.code, "no-bpf-privilege");
        assert_eq!(
            none.reason,
            "CapEff lacks CAP_BPF+CAP_PERFMON and CAP_SYS_ADMIN"
        );
    }

    #[test]
    fn privilege_reason_has_no_raw_mask() {
        // Privilege reasons name the grant, never the raw mask.
        // A raw 16-hex mask is indistinguishable from a kernel
        // address to the export redaction gate.
        let base = check_privilege(&open_evidence_reader(&gate("base")).expect("fixture opens"));
        assert!(!has_hex_run(&base.reason, 16));
        assert!(base.reason.contains("CAP_BPF+CAP_PERFMON"));
        let none =
            check_privilege(&open_evidence_reader(&gate("caps-none")).expect("fixture opens"));
        assert!(!has_hex_run(&none.reason, 16));
        assert!(none.reason.contains("lacks"));
    }

    #[test]
    fn capeff_malformed() {
        let bad =
            check_privilege(&open_evidence_reader(&gate("caps-malformed")).expect("fixture opens"));
        assert_eq!(bad.state, "unknown");
        assert_eq!(bad.code, "");
        let short =
            check_privilege(&open_evidence_reader(&gate("caps-short")).expect("fixture opens"));
        assert_eq!(short.state, "unknown");
    }

    #[test]
    fn memcg_ancestor_min() {
        let small = check_memcg(
            &open_evidence_reader(&gate("memcg-ancestor")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(small.state, "pass");
        let big = check_memcg(
            &open_evidence_reader(&gate("memcg-ancestor")).expect("fixture opens"),
            76_374_232,
        );
        assert_eq!(big.state, "unknown");
        assert_eq!(big.code, "memcg-headroom");
        assert!(big.reason.contains("50000000"));
        assert!(big.reason.contains("/a"));
        let leaf = check_memcg(
            &open_evidence_reader(&gate("memcg-small")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(leaf.state, "unknown");
    }

    #[test]
    fn memcg_shortfall_unknown() {
        // memory.current counts reclaimable page cache and map
        // allocation reclaims, so a shortfall is not conclusive.
        let leaf = check_memcg(
            &open_evidence_reader(&gate("memcg-small")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(leaf.state, "unknown");
        assert_eq!(leaf.code, "memcg-headroom");
        let big = check_memcg(
            &open_evidence_reader(&gate("memcg-ancestor")).expect("fixture opens"),
            76_374_232,
        );
        assert_eq!(big.state, "unknown");
        assert_eq!(big.code, "memcg-headroom");
    }

    #[test]
    fn memcg_root_unknown() {
        // 0::/ is the namespace root or the host root; outer
        // limits may apply that this view cannot see.
        let root = check_memcg(
            &open_evidence_reader(&gate("memcg-root")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(root.state, "unknown");
        assert!(root.reason.contains("namespace"));
    }

    #[test]
    fn privilege_userns_unknown() {
        // capable() checks the init namespace, so a namespaced
        // CapEff cannot pass the privilege check.
        let ns =
            check_privilege(&open_evidence_reader(&gate("caps-userns")).expect("fixture opens"));
        assert_eq!(ns.state, "unknown");
        assert!(ns.reason.contains("user namespace"));
    }

    #[test]
    fn memcg_malformed() {
        let bad = check_memcg(
            &open_evidence_reader(&gate("memcg-malformed")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(bad.state, "unknown");
        let huge = check_memcg(
            &open_evidence_reader(&gate("memcg-huge")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(huge.state, "unknown");
        let empty = check_memcg(
            &open_evidence_reader(&gate("memcg-empty")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(empty.state, "unknown");
        let v1 = check_memcg(
            &open_evidence_reader(&gate("memcg-v1")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(v1.state, "unknown");
        let base = check_memcg(
            &open_evidence_reader(&gate("base")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(base.state, "pass");
    }

    #[test]
    fn prechecks_denied_unknown() {
        let privc =
            check_privilege(&open_evidence_reader(&gate("denied-all")).expect("fixture opens"));
        assert_eq!(privc.state, "unknown");
        let mem = check_memcg(
            &open_evidence_reader(&gate("denied-all")).expect("fixture opens"),
            8_388_680,
        );
        assert_eq!(mem.state, "unknown");
    }

    #[test]
    fn unprivileged_bpf() {
        let base =
            check_unprivileged_bpf(&open_evidence_reader(&gate("base")).expect("fixture opens"));
        assert_eq!(base.state, "unknown");
        let two = check_unprivileged_bpf(
            &open_evidence_reader(&gate("unpriv-bpf")).expect("fixture opens"),
        );
        assert_eq!(two.state, "pass");
        assert_eq!(two.reason, "unprivileged_bpf_disabled=2");
    }
}
