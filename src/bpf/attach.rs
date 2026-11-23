// SPDX-License-Identifier: GPL-3.0-or-later
//! Attach sites: one spec per program plus the frozen per-channel lists.
//!
//! `AttachSpec` mirrors the previous surface (`program`, `kind`, `target_a`,
//! `target_b`); the tracing kind is subdivided into entry/exit so attach
//! never guesses which loader to use. The frozen lists pin the exact
//! programs, kinds, and targets the probes were built for.

use super::session::{Channel, SessionError, refusal_name};

/// How one program attaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachKind {
    /// Tracepoint `target_a`/`target_b` (category/event).
    Tracepoint,
    /// `fentry` on the kernel function `target_a`.
    FEntry,
    /// `fexit` on the kernel function `target_a`.
    FExit,
}

/// One requested attach site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachSpec {
    /// Program name in the object.
    pub program: String,
    /// How to attach it.
    pub kind: AttachKind,
    /// Tracepoint category or kernel function name.
    pub target_a: String,
    /// Tracepoint event name; empty for tracing attaches.
    pub target_b: String,
}

impl AttachSpec {
    /// Build one spec from string parts.
    pub fn new(program: &str, kind: AttachKind, target_a: &str, target_b: &str) -> Self {
        Self {
            program: program.to_owned(),
            kind,
            target_a: target_a.to_owned(),
            target_b: target_b.to_owned(),
        }
    }
}

/// Attempt-channel specs: the tracepoint program on its profiled site.
pub fn attempt_specs(tp_system: &str, tp_event: &str) -> Vec<AttachSpec> {
    vec![AttachSpec::new(
        "mv_swiotlb_attempt",
        AttachKind::Tracepoint,
        tp_system,
        tp_event,
    )]
}

/// Lifecycle-channel specs: map-result exit, then unmap entry.
pub fn lifecycle_specs() -> Vec<AttachSpec> {
    vec![
        AttachSpec::new(
            "mv_map_result",
            AttachKind::FExit,
            "swiotlb_tbl_map_single",
            "",
        ),
        AttachSpec::new(
            "mv_unmap",
            AttachKind::FEntry,
            "__swiotlb_tbl_unmap_single",
            "",
        ),
    ]
}

/// Copy-channel specs: bounce entry precedes exit, then the sync hooks.
/// Both sync directions run through `swiotlb_bounce`, so the bounce pair
/// attaches first and the armed slot gates recovery.
pub fn copy_specs() -> Vec<AttachSpec> {
    vec![
        AttachSpec::new("mv_bounce", AttachKind::FEntry, "swiotlb_bounce", ""),
        AttachSpec::new("mv_bounce_exit", AttachKind::FExit, "swiotlb_bounce", ""),
        AttachSpec::new(
            "mv_sync_device",
            AttachKind::FEntry,
            "__swiotlb_sync_single_for_device",
            "",
        ),
        AttachSpec::new(
            "mv_sync_cpu",
            AttachKind::FEntry,
            "__swiotlb_sync_single_for_cpu",
            "",
        ),
    ]
}

/// Multi-channel attach order, inner channels first: copies execute inside
/// map, sync, and unmap, so the copy hooks are live before any outer hook
/// can fire.
pub const ATTACH_ORDER: [Channel; 3] = [Channel::Copy, Channel::Lifecycle, Channel::Attempt];

/// Multi-channel detach order, outer channels first.
pub const DETACH_ORDER: [Channel; 3] = [Channel::Attempt, Channel::Lifecycle, Channel::Copy];

/// One expected program: name, section kind, and sleepable flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramSpec {
    /// Program name in the object.
    pub name: String,
    /// Section kind the program must live in.
    pub kind: AttachKind,
    /// Sleepable sections are never admitted.
    pub sleepable: bool,
}

/// Frozen program set per channel, in attach order.
pub fn expected_programs(channel: Channel) -> Vec<ProgramSpec> {
    let specs = match channel {
        Channel::Attempt => attempt_specs("swiotlb", "swiotlb_bounced"),
        Channel::Lifecycle => lifecycle_specs(),
        Channel::Copy => copy_specs(),
    };
    specs
        .into_iter()
        .map(|spec| ProgramSpec {
            name: spec.program,
            kind: spec.kind,
            sleepable: false,
        })
        .collect()
}

/// Exact-set program gate: every expected program present in its section
/// kind and non-sleepable, no unexpected programs.
pub fn check_programs(channel: Channel, actual: &[ProgramSpec]) -> Result<(), SessionError> {
    let expected = expected_programs(channel);
    for want in &expected {
        let Some(got) = actual.iter().find(|spec| spec.name == want.name) else {
            return Err(SessionError::Geometry(format!(
                "{channel} channel: missing program {}",
                refusal_name(&want.name)
            )));
        };
        if got.kind != want.kind {
            return Err(SessionError::Geometry(format!(
                "{channel} channel: program {}: want section {:?}, got {:?}",
                refusal_name(&want.name),
                want.kind,
                got.kind
            )));
        }
        if got.sleepable {
            return Err(SessionError::Geometry(format!(
                "{channel} channel: program {} must not be sleepable",
                refusal_name(&want.name)
            )));
        }
    }
    for got in actual {
        if !expected.iter().any(|want| want.name == got.name) {
            return Err(SessionError::Geometry(format!(
                "{channel} channel: unexpected program {}",
                refusal_name(&got.name)
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, kind: AttachKind, sleepable: bool) -> ProgramSpec {
        ProgramSpec {
            name: name.to_owned(),
            kind,
            sleepable,
        }
    }

    #[test]
    fn frozen_sets_pass() {
        for channel in [Channel::Attempt, Channel::Lifecycle, Channel::Copy] {
            let expected = expected_programs(channel);
            check_programs(channel, &expected).expect("frozen set must pass");
        }
    }

    #[test]
    fn wrong_kind_sleepable_and_extra_refused() {
        let error = check_programs(
            Channel::Attempt,
            &[spec("mv_swiotlb_attempt", AttachKind::FEntry, false)],
        )
        .expect_err("wrong section kind must be refused");
        assert!(error.to_string().contains("mv_swiotlb_attempt"));
        let error = check_programs(
            Channel::Attempt,
            &[spec("mv_swiotlb_attempt", AttachKind::Tracepoint, true)],
        )
        .expect_err("sleepable must be refused");
        assert!(error.to_string().contains("sleepable"));
        let error = check_programs(Channel::Attempt, &[]).expect_err("missing must be refused");
        assert!(error.to_string().contains("missing"));
        let error = check_programs(
            Channel::Attempt,
            &[
                spec("mv_swiotlb_attempt", AttachKind::Tracepoint, false),
                spec("mv_extra", AttachKind::Tracepoint, false),
            ],
        )
        .expect_err("extra must be refused");
        assert!(error.to_string().contains("mv_extra"));
    }
}
