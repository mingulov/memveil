// SPDX-License-Identifier: GPL-3.0-or-later
//! Kernel-floor helpers shared by admission and reporting.
//!
//! Capability floors (6.0 for attempt-trace, 6.11 for the
//! tracing capabilities) and the 6.7 attempt-loss exactness
//! cutover live here so every verb judges them identically.

use super::evidence::{parse_kernel_triple, triple_ge};

/// Lowest `major.minor` serving one capability id.
///
/// Attempt-trace rides the tracepoint that is stable from
/// 6.0 on; lifecycle and copy need the tracing interfaces
/// verified from 6.11 on. Unknown ids need nothing because
/// no gate admits them.
pub fn cap_floor_need(cap_id: &str) -> String {
    if cap_id == "attempt-trace" {
        return "6.0".to_string();
    }
    if cap_id == "mapping-lifecycle" {
        return "6.11".to_string();
    }
    if cap_id == "copy-actual" {
        return "6.11".to_string();
    }
    String::new()
}

/// True when a release reaches one capability's floor.
pub fn cap_floor_ok(cap_id: &str, release: &str) -> bool {
    let need = cap_floor_need(cap_id);
    if need.is_empty() {
        return false;
    }
    let triple = parse_kernel_triple(release);
    if need == "6.0" {
        return triple_ge(&triple, 6, 0);
    }
    triple_ge(&triple, 6, 11)
}

/// Refusal naming the floor one capability needs.
///
/// An unparseable release cannot reach any floor, so it
/// refuses as unknown rather than naming a version it
/// might already satisfy.
pub fn cap_floor_refusal(cap_id: &str, release: &str) -> String {
    let triple = parse_kernel_triple(release);
    if !triple.ok {
        return format!("release {release} is unparseable; floor unknown");
    }
    format!(
        "capability {cap_id} needs kernel {}+ (this kernel: {release})",
        cap_floor_need(cap_id)
    )
}

/// True when attempt loss counts are exact on this release.
///
/// Kernels before 6.7 skipped programs in trace_call_bpf
/// without counting them, so loss counts there are a
/// lower bound. Unparsable releases are not exact.
pub fn attempt_loss_exact(release: &str) -> bool {
    let triple = parse_kernel_triple(release);
    if !triple.ok {
        return false;
    }
    triple_ge(&triple, 6, 7)
}

#[cfg(test)]
mod tests {
    use super::{attempt_loss_exact, cap_floor_need, cap_floor_ok, cap_floor_refusal};

    #[test]
    fn cap_floor_attempt_60() {
        assert!(cap_floor_ok("attempt-trace", "6.0.19"));
        assert!(!cap_floor_ok("attempt-trace", "5.15.0"));
        assert_eq!(cap_floor_need("attempt-trace"), "6.0");
    }

    #[test]
    fn cap_floor_lifecycle_611() {
        assert!(cap_floor_ok("mapping-lifecycle", "6.11.0"));
        assert!(!cap_floor_ok("mapping-lifecycle", "6.10.14"));
        assert_eq!(
            cap_floor_refusal("mapping-lifecycle", "6.10.14-061014-generic"),
            "capability mapping-lifecycle needs kernel 6.11+\
             \u{20}(this kernel: 6.10.14-061014-generic)"
        );
    }

    #[test]
    fn cap_floor_copy_611() {
        assert!(cap_floor_ok("copy-actual", "6.11.0"));
        assert!(!cap_floor_ok("copy-actual", "6.10.14"));
    }

    #[test]
    fn cap_floor_unknown_id() {
        assert!(!cap_floor_ok("no-such-cap", "7.3.0"));
        assert_eq!(cap_floor_need("no-such-cap"), "");
        assert_eq!(
            cap_floor_refusal("no-such-cap", "nope"),
            "release nope is unparseable; floor unknown"
        );
    }

    #[test]
    fn attempt_loss_exact_cutover() {
        assert!(!attempt_loss_exact("6.6.160"));
        assert!(attempt_loss_exact("6.7.0"));
        assert!(attempt_loss_exact("7.0.0-38-generic"));
        assert!(!attempt_loss_exact("6.0.19"));
        assert!(!attempt_loss_exact("bogus"));
    }
}
