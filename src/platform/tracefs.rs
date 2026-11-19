// SPDX-License-Identifier: GPL-3.0-or-later
//! Tracefs root probe: locate the tree, translate paths onto it.
//!
//! The root follows libbpf's probe order (debugfs first,
//! sys second), so admission and the loader agree on which
//! tree they read. A leaf module: only the evidence reader
//! below it, so narrow and the gate can both use it without
//! a cycle.

use super::reader::{
    EVIDENCE_ABSENT, EvidenceReader, bytes_to_text, exists_f_ok, file_state, read_evidence,
};

/// debugfs tracefs root.
pub const TRACEFS_DEBUG: &str = "/sys/kernel/debug/tracing";
/// sys tracefs root.
pub const TRACEFS_SYS: &str = "/sys/kernel/tracing";

const MOUNTS_CAP: usize = 1_048_576;

/// One tracefs location probe: root, events state, mount word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracefsProbe {
    /// The located root, or `""`.
    pub root: String,
    /// True when a root was located.
    pub has_root: bool,
    /// `events` dir state under the root.
    pub events: i32,
    /// `yes`, `no`, or `unknown`.
    pub mounted: String,
}

impl TracefsProbe {
    /// An empty probe: no root, absent events, unknown mount.
    pub fn new() -> Self {
        Self {
            root: String::new(),
            has_root: false,
            events: EVIDENCE_ABSENT,
            mounted: "unknown".to_string(),
        }
    }
}

impl Default for TracefsProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Locate the tracefs root in libbpf's probe order.
///
/// The debugfs tree wins when it exists, else the sys
/// tree; the events state and the mount word (yes, no,
/// or unknown) come from the live tree and /proc/mounts.
pub fn probe_tracefs(reader: &EvidenceReader) -> TracefsProbe {
    let mut out = TracefsProbe::new();
    if exists_f_ok(reader, TRACEFS_DEBUG) {
        out.root = TRACEFS_DEBUG.to_string();
        out.has_root = true;
    } else if exists_f_ok(reader, TRACEFS_SYS) {
        out.root = TRACEFS_SYS.to_string();
        out.has_root = true;
    }
    if out.has_root {
        out.events = file_state(reader, &format!("{}/events", out.root));
    }
    let mounts = match read_evidence(reader, "/proc/mounts", MOUNTS_CAP) {
        Ok(mounts) => mounts,
        Err(_) => {
            out.mounted = "unknown".to_string();
            return out;
        }
    };
    let text = bytes_to_text(&mounts);
    let mut yes = false;
    for line in text.split('\n') {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 3 {
            continue;
        }
        let here = fields[1];
        let fstype = fields[2];
        if out.has_root && here == out.root && fstype == "tracefs" {
            yes = true;
            break;
        }
        if out.has_root
            && out.root == TRACEFS_DEBUG
            && here == "/sys/kernel/debug"
            && fstype == "debugfs"
        {
            yes = true;
            break;
        }
    }
    out.mounted = if yes {
        "yes".to_string()
    } else {
        "no".to_string()
    };
    out
}

/// Map a /sys/kernel/tracing profile path onto the live root.
///
/// Paths outside the sys tracefs prefix, and every path
/// without a probed root, pass through unchanged.
pub fn tracefs_translate(probe: &TracefsProbe, path: &str) -> String {
    if !probe.has_root {
        return path.to_string();
    }
    if path == TRACEFS_SYS {
        return probe.root.clone();
    }
    let prefix = format!("{TRACEFS_SYS}/");
    if let Some(rest) = path.strip_prefix(prefix.as_str()) {
        return format!("{}/{}", probe.root, rest);
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::{probe_tracefs, tracefs_translate};
    use crate::platform::reader::{EVIDENCE_ABSENT, EVIDENCE_OK, open_evidence_reader};
    use crate::platform::test_support::gate_fixture;

    fn probe_of(name: &str) -> super::TracefsProbe {
        let r = open_evidence_reader(&gate_fixture(name)).expect("fixture opens");
        probe_tracefs(&r)
    }

    #[test]
    fn root_order() {
        assert_eq!(probe_of("base").root, "/sys/kernel/tracing");
        assert_eq!(probe_of("debugfs-root").root, "/sys/kernel/debug/tracing");
        assert_eq!(probe_of("debug-denied").root, "/sys/kernel/tracing");
    }

    #[test]
    fn mounted_words() {
        assert_eq!(probe_of("base").mounted, "yes");
        // The debugfs tree has no debugfs mount line behind it.
        assert_eq!(probe_of("debugfs-root").mounted, "no");
        assert_eq!(probe_of("debug-denied").mounted, "yes");
        // No root, no match: a stale mounts line cannot mount it.
        assert_eq!(probe_of("tracefs-gone").mounted, "no");
        assert_eq!(probe_of("tracefs-unmounted").mounted, "no");
        // Unreadable mounts stay unknown, never no.
        assert_eq!(probe_of("tracefs-hidden").mounted, "unknown");
    }

    #[test]
    fn events_states() {
        assert!(probe_of("base").has_root);
        assert_eq!(probe_of("base").events, EVIDENCE_OK);
        assert_eq!(probe_of("debugfs-root").events, EVIDENCE_OK);
        assert_eq!(probe_of("tracefs-noevents").events, EVIDENCE_ABSENT);
        let gone = probe_of("tracefs-gone");
        assert!(!gone.has_root);
        assert_eq!(gone.root, "");
        assert_eq!(gone.events, EVIDENCE_ABSENT);
    }

    #[test]
    fn translate_sys_path_onto_debugfs() {
        let pd = probe_of("debugfs-root");
        assert_eq!(
            tracefs_translate(
                &pd,
                "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"
            ),
            "/sys/kernel/debug/tracing/events/swiotlb/swiotlb_bounced/format"
        );
    }

    #[test]
    fn translate_edges() {
        let pd = probe_of("debugfs-root");
        // The sys root itself translates.
        assert_eq!(
            tracefs_translate(&pd, "/sys/kernel/tracing"),
            "/sys/kernel/debug/tracing"
        );
        // Outside the sys prefix passes through.
        assert_eq!(
            tracefs_translate(&pd, "/sys/kernel/debug/tracing/events"),
            "/sys/kernel/debug/tracing/events"
        );
        assert_eq!(tracefs_translate(&pd, "/proc/cpuinfo"), "/proc/cpuinfo");
        // Without a probed root everything passes through.
        let gone = probe_of("tracefs-gone");
        assert_eq!(
            tracefs_translate(&gone, "/sys/kernel/tracing/events"),
            "/sys/kernel/tracing/events"
        );
    }
}
