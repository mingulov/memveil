// SPDX-License-Identifier: GPL-3.0-or-later
//! Zero-config runtime discovery for the embedded Aya artifacts.
//!
//! Collection verbs resolve per-channel BPF objects through
//! this module instead of requiring flags or environment
//! setup. Retarget note: the Rust binary embeds the three
//! channel ELFs at compile time (see
//! [`embedded_object`]); there is no bridge shared object
//! (the Aya loader links statically) and no `.bpf.o` files
//! to find on disk. Explicit paths stay authoritative
//! user overrides and are returned verbatim, never probed;
//! without an explicit path, discovery yields "" and the
//! caller uses the embedded bytes. Discovery never loads
//! anything. Callers inject the kernel-resolved executable
//! path, keeping this module free of ambient reads.

use super::reader::{geteuid_live, getuid_live};

/// Real and effective uids sampled together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UidPair {
    /// Real uid.
    pub ruid: i64,
    /// Effective uid.
    pub euid: i64,
}

/// Sample the live real and effective uids.
pub fn live_uids() -> UidPair {
    UidPair {
        ruid: getuid_live(),
        euid: geteuid_live(),
    }
}

/// True for root or shifted-identity execution.
///
/// euid 0 covers sudo and root; euid != ruid covers setuid
/// and capability-shaped identity shifts. No setuid ships
/// with MemVeil; the second arm is defense in depth.
pub fn is_privileged(ids: UidPair) -> bool {
    ids.euid == 0 || ids.euid != ids.ruid
}

/// Lexical parent: "/a/b" -> "/a", "a/b" -> "a".
///
/// Paths without "/" have no directory part (""); "/x" has
/// parent "/".
fn dirname(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return String::new();
    }
    let mut out = parts[0].to_string();
    for part in &parts[1..parts.len() - 1] {
        out += &format!("/{part}");
    }
    if out.is_empty() {
        return "/".to_string();
    }
    out
}

/// Tree root above the executable.
///
/// Packaged layout keeps the binary one directory below the
/// tree root (``<root>/bin/memveil``), so the root is the
/// parent-of-parent. "" when no parent-of-parent exists (a
/// bare name or a shallow relative path cannot name a tree);
/// callers then skip the executable-relative candidate.
pub fn exe_root(exe_path: &str) -> String {
    let parent = dirname(exe_path);
    if parent.is_empty() {
        return String::new();
    }
    dirname(&parent)
}

/// Embedded Aya ELF bytes for one channel, or None.
///
/// The three channel objects compile into the binary
/// through the `DEP_MEMVEIL_EBPF_<CH>_PATH` build contract;
/// `kind` is `attempt`, `lifecycle`, or `copy`. Anything
/// else has no artifact.
pub fn embedded_object(kind: &str) -> Option<&'static [u8]> {
    match kind {
        "attempt" => Some(include_bytes!(env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH"))),
        "lifecycle" => Some(include_bytes!(env!("DEP_MEMVEIL_EBPF_LIFECYCLE_PATH"))),
        "copy" => Some(include_bytes!(env!("DEP_MEMVEIL_EBPF_COPY_PATH"))),
        _ => None,
    }
}

/// Build-baked SHA-256 of one channel's embedded object, or None.
///
/// The build script hashes the same staged copy
/// [`embedded_object`] embeds, so this digest names exactly
/// the bytes the runtime serves — the identity the packager
/// binds inspection copies to. `kind` is `attempt`,
/// `lifecycle`, or `copy`; anything else has no artifact.
pub fn embedded_digest(kind: &str) -> Option<&'static str> {
    match kind {
        "attempt" => Some(env!("DEP_MEMVEIL_EBPF_ATTEMPT_DIGEST")),
        "lifecycle" => Some(env!("DEP_MEMVEIL_EBPF_LIFECYCLE_DIGEST")),
        "copy" => Some(env!("DEP_MEMVEIL_EBPF_COPY_DIGEST")),
        _ => None,
    }
}

/// (channel, digest) rows in channel order for `--embedded-manifest`.
pub fn embedded_manifest() -> [(&'static str, &'static str); 3] {
    [
        ("attempt", env!("DEP_MEMVEIL_EBPF_ATTEMPT_DIGEST")),
        ("lifecycle", env!("DEP_MEMVEIL_EBPF_LIFECYCLE_DIGEST")),
        ("copy", env!("DEP_MEMVEIL_EBPF_COPY_DIGEST")),
    ]
}

/// Resolve the native bridge path, or "" when none applies.
///
/// Retargeted: the Rust binary links the Aya loader
/// statically, so only an explicit path ever resolves;
/// "" otherwise names the linked loader. The retired
/// env/bundle/system lanes stay in the signature so the
/// Mojo call shape (and the privilege policy around it)
/// keeps compiling at future call sites.
pub fn discover_bridge(
    explicit: &str,
    has_explicit: bool,
    _env_value: &str,
    _ids: UidPair,
    _exe_path: &str,
) -> String {
    if has_explicit {
        return explicit.to_string();
    }
    String::new()
}

/// Resolve one channel's BPF object path, or "" when none.
///
/// Retargeted: only an explicit path (an override file)
/// ever resolves; "" otherwise names the embedded
/// artifact from [`embedded_object`], including for
/// unknown kinds, which have no artifact at all. Explicit
/// values stay authoritative user input, returned verbatim
/// and never probed; nothing is ever loaded here.
pub fn discover_object(_kind: &str, explicit: &str, has_explicit: bool, _exe_path: &str) -> String {
    if has_explicit {
        return explicit.to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::{
        UidPair, discover_bridge, discover_object, embedded_digest, embedded_manifest,
        embedded_object, exe_root, is_privileged, live_uids,
    };
    use crate::platform::hash::sha256_hex;

    const EXE: &str = "tests/fixtures/runtime/bin/memveil";
    const ENV_BRIDGE: &str = "tests/fixtures/runtime/env-bridge.so";
    const ABSENT: &str = "tests/fixtures/runtime/lib/memveil/absent.so";

    fn user() -> UidPair {
        UidPair {
            ruid: 1001,
            euid: 1001,
        }
    }

    #[test]
    fn bridge_explicit_wins_verbatim() {
        // Explicit wins even when the path does not exist: it is
        // returned verbatim, never probed.
        let got = discover_bridge(ABSENT, true, ENV_BRIDGE, user(), EXE);
        assert_eq!(got, ABSENT);
    }

    #[test]
    fn bridge_explicit_empty() {
        let got = discover_bridge("", true, ENV_BRIDGE, user(), EXE);
        assert_eq!(got, "");
    }

    #[test]
    fn bridge_without_explicit_is_linked() {
        // Retarget: the Rust binary links the Aya loader, so no
        // bridge file is ever discovered; "" names the linked
        // loader, whatever the env, privilege, or exe path.
        assert_eq!(discover_bridge("", false, ENV_BRIDGE, user(), EXE), "");
        let root = UidPair { ruid: 0, euid: 0 };
        assert_eq!(discover_bridge("", false, ENV_BRIDGE, root, EXE), "");
        let setuid = UidPair {
            ruid: 1001,
            euid: 0,
        };
        assert_eq!(discover_bridge("", false, ENV_BRIDGE, setuid, EXE), "");
        assert_eq!(discover_bridge("", false, "", user(), ""), "");
        assert_eq!(discover_bridge("", false, "", user(), "memveil"), "");
    }

    #[test]
    fn object_explicit_wins_verbatim() {
        let missing = "tests/fixtures/runtime/bpf/absent.bpf.o";
        let got = discover_object("attempt", missing, true, EXE);
        assert_eq!(got, missing);
    }

    #[test]
    fn object_unknown_kind_explicit_wins() {
        let missing = "tests/fixtures/runtime/bpf/absent.bpf.o";
        let got = discover_object("bogus", missing, true, EXE);
        assert_eq!(got, missing);
    }

    #[test]
    fn object_without_explicit_is_embedded() {
        // Retarget: without an explicit override there is no
        // file to find; "" names the embedded artifact, which
        // exists for every known channel.
        for kind in ["attempt", "lifecycle", "copy"] {
            assert_eq!(discover_object(kind, "", false, EXE), "");
            assert!(embedded_object(kind).is_some(), "kind {kind}");
        }
    }

    #[test]
    fn object_unknown_kind_has_no_artifact() {
        assert_eq!(discover_object("bogus", "", false, EXE), "");
        assert!(embedded_object("bogus").is_none());
        assert!(embedded_object("").is_none());
    }

    #[test]
    fn embedded_artifacts_are_bpf_objects() {
        // Re-verifies the build artifact contract: three
        // embedded ELFs, EM_BPF machine.
        for kind in ["attempt", "lifecycle", "copy"] {
            let bytes = embedded_object(kind).expect("channel embedded");
            assert!(!bytes.is_empty(), "kind {kind}");
            assert_eq!(&bytes[..4], b"\x7fELF", "kind {kind}");
            let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
            assert_eq!(machine, 247, "kind {kind}");
        }
    }

    #[test]
    fn embedded_digests_name_the_served_bytes() {
        // The binding is exact: each baked digest must equal
        // the SHA-256 of the bytes `embedded_object` serves
        // for that channel, and the manifest must carry the
        // same three rows in channel order.
        let manifest = embedded_manifest();
        assert_eq!(manifest.map(|row| row.0), ["attempt", "lifecycle", "copy"]);
        for (channel, digest) in manifest {
            assert_eq!(Some(digest), embedded_digest(channel));
            let bytes = embedded_object(channel).expect("channel embedded");
            assert_eq!(digest, sha256_hex(bytes), "kind {channel}");
            assert_eq!(digest.len(), 64, "kind {channel}");
        }
        assert!(embedded_digest("bogus").is_none());
        assert!(embedded_digest("").is_none());
    }

    #[test]
    fn exe_root_cases() {
        assert_eq!(exe_root(EXE), "tests/fixtures/runtime");
        assert_eq!(exe_root("/root/bin/memveil"), "/root");
        assert_eq!(exe_root("/usr/bin/memveil"), "/usr");
        assert_eq!(exe_root("/memveil"), "/");
        assert_eq!(exe_root("bin/memveil"), "");
        assert_eq!(exe_root("memveil"), "");
        assert_eq!(exe_root(""), "");
    }

    #[test]
    fn privilege_policy() {
        assert!(!is_privileged(user()));
        assert!(is_privileged(UidPair { ruid: 0, euid: 0 }));
        assert!(is_privileged(UidPair {
            ruid: 1001,
            euid: 0
        }));
        assert!(is_privileged(UidPair {
            ruid: 0,
            euid: 1001
        }));
    }

    #[test]
    fn live_uids_match_libc() {
        let ids = live_uids();
        assert!(ids.ruid >= 0);
        assert!(ids.euid >= 0);
        // SAFETY: getuid/geteuid take no arguments and always succeed.
        let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
        assert_eq!(ids.ruid, i64::from(ruid));
        assert_eq!(ids.euid, i64::from(euid));
        assert_eq!(is_privileged(ids), ids.euid == 0 || ids.euid != ids.ruid);
    }
}
