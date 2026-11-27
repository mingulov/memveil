// SPDX-License-Identifier: GPL-3.0-or-later
//! Conversion-journal admission: declared bindings rebound against
//! freshly observed runtime evidence.
//!
//! [`admit_journal`] is pure: a capability selection, the ordinary
//! attempts verdict, one discovered profile binding, and one
//! rebound evidence set decide attachment readiness or a typed
//! refusal. It performs no I/O, consults no registry, and honors
//! no override: readiness needs an `admitted` status word AND an
//! exact per-leg evidence match, so a profile edit alone never
//! admits. A zero-style result means attachment readiness only,
//! never actual attachment or platform qualification.
//!
//! The refusal keeps one documented form: the bare frozen
//! `journal_profile_not_admitted` diagnostic (or the frozen
//! attempts/callers code for those gates) plus a fix line naming
//! the failed gate. No hashes, paths, or lengths leak into
//! either line.
//!
//! [`gather_journal_evidence`] rebinds the evidence half at
//! dispatch time from the live host: kernel release, machine,
//! page size, config hash, BTF hash, and the staged object
//! hash. Unobservable legs read empty and refuse; nothing
//! defaults, and source metadata alone admits nothing.

use super::collector::EXIT_REFUSAL;
use super::run::ZLIB as GUNZIP_LIB;
use crate::model::journal::JournalSelection;
use crate::platform::artifact_files::join_root;
use crate::platform::hash::sha256_hex;
use crate::platform::journal_profile::{JournalDiscoveryFailure, JournalProfileBinding};
use crate::platform::narrow::{MAX_NARROW_BTF_BYTES, read_live_bytes, read_live_config};

/// Frozen journal refusal code.
pub const JOURNAL_NOT_ADMITTED: &str = "journal_profile_not_admitted";

/// Runtime evidence rebound at dispatch time.
///
/// Every leg is observed, never declared: empty strings and a
/// zero page size mean unobservable, and any unobservable leg
/// refuses. The release is recorded for the oracle; the profile
/// binds no release string, so it never mismatches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalRuntimeEvidence {
    /// Live kernel release (recorded, never matched).
    pub release: String,
    /// Live machine architecture.
    pub architecture: String,
    /// Live page size, or 0 when the query fails.
    pub page_size: u64,
    /// Live config hash, or "" when unmeasurable.
    pub config_sha256: String,
    /// Live BTF hash, or "" when unmeasurable.
    pub btf_sha256: String,
    /// Staged object hash, or "" when no bytes staged.
    pub object_sha256: String,
}

/// Attachment readiness: which profile admitted, on what evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalReadiness {
    /// Admitted profile id.
    pub profile_id: String,
    /// The rebound evidence the decision matched.
    pub evidence: JournalRuntimeEvidence,
}

/// Typed refusal: exit code plus the documented code/fix pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRefusal {
    /// Always the exit-3 refusal code.
    pub exit_code: i64,
    /// Bare frozen reason.
    pub reason: String,
    /// Operator guidance naming the failed gate.
    pub fix: String,
}

/// Admission decision: readiness or typed refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalDispatch {
    /// Attachment may proceed behind this readiness.
    Ready(JournalReadiness),
    /// The request refuses before native/output creation.
    Refused(JournalRefusal),
}

fn refused(reason: &str, fix: &str) -> JournalDispatch {
    JournalDispatch::Refused(JournalRefusal {
        exit_code: EXIT_REFUSAL,
        reason: reason.to_string(),
        fix: fix.to_string(),
    })
}

/// Fix line for a discovery failure.
pub fn fix_for_discovery(failure: JournalDiscoveryFailure) -> String {
    match failure {
        JournalDiscoveryFailure::Unavailable => {
            "candidate profile unavailable for this host".to_string()
        }
        JournalDiscoveryFailure::Invalid => "candidate profile is invalid".to_string(),
    }
}

/// Pure admission: selection plus bindings plus rebound evidence.
///
/// Gate order is fixed: the journal channel decides fully
/// (status, then source, config, BTF, object bindings) before
/// the attempts and callers gates run, mirroring the declared
/// model order. Every binding must be present on both sides and
/// equal; null bindings and unobservable evidence refuse.
pub fn admit_journal(
    selection: JournalSelection,
    attempts_admitted: bool,
    binding: &JournalProfileBinding,
    evidence: &JournalRuntimeEvidence,
) -> JournalDispatch {
    if !selection.journal {
        return refused(
            "journal_not_requested",
            "request conversion-journal to use journal admission",
        );
    }
    if binding.status != "admitted" {
        return refused(
            JOURNAL_NOT_ADMITTED,
            "profile is not admitted for this host",
        );
    }
    if binding.architecture.is_empty()
        || evidence.architecture.is_empty()
        || binding.architecture != evidence.architecture
    {
        return refused(
            JOURNAL_NOT_ADMITTED,
            "host architecture is not bound by the profile",
        );
    }
    if binding.page_size == 0 || evidence.page_size == 0 || binding.page_size != evidence.page_size
    {
        return refused(
            JOURNAL_NOT_ADMITTED,
            "host page size is not bound by the profile",
        );
    }
    if binding.config_sha256.is_empty()
        || evidence.config_sha256.is_empty()
        || binding.config_sha256 != evidence.config_sha256
    {
        return refused(
            JOURNAL_NOT_ADMITTED,
            "config binding mismatch: the profile does not bind this host",
        );
    }
    if binding.btf_sha256.is_empty()
        || evidence.btf_sha256.is_empty()
        || binding.btf_sha256 != evidence.btf_sha256
    {
        return refused(
            JOURNAL_NOT_ADMITTED,
            "btf binding mismatch: the profile does not bind this host",
        );
    }
    if binding.object_sha256.is_empty()
        || evidence.object_sha256.is_empty()
        || binding.object_sha256 != evidence.object_sha256
    {
        return refused(
            JOURNAL_NOT_ADMITTED,
            "object binding mismatch: the profile does not bind this object",
        );
    }
    if selection.attempts && !attempts_admitted {
        return refused(
            "attempts_not_admitted",
            "attempts are not admitted for this request",
        );
    }
    if selection.callers && !binding.callers_admitted {
        return refused(
            "journal_callers_not_admitted",
            "journal caller labels are not admitted by the profile",
        );
    }
    JournalDispatch::Ready(JournalReadiness {
        profile_id: binding.profile_id.clone(),
        evidence: evidence.clone(),
    })
}

/// Rebind the evidence half at dispatch time.
///
/// Release, config, and BTF read under `root` ("" for the live
/// host); machine and page size are host properties. The staged
/// object bytes hash here; `None` leaves the object leg empty.
/// Every read failure degrades to empty, which refuses.
pub fn gather_journal_evidence(root: &str, object_bytes: Option<&[u8]>) -> JournalRuntimeEvidence {
    let release = std::fs::read_to_string(join_root(root, "/proc/sys/kernel/osrelease"))
        .map(|text| text.trim().to_string())
        .unwrap_or_default();
    let architecture = std::env::consts::ARCH.to_string();
    // SAFETY: sysconf with a valid name; -1 means unknown.
    let pages = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = if pages > 0 {
        u64::try_from(pages).unwrap_or(0)
    } else {
        0
    };
    let config = read_live_config(root, &release, GUNZIP_LIB);
    let config_sha256 = if config.src.is_empty() || config.value.state != "value" {
        String::new()
    } else {
        config.value.value.clone()
    };
    let btf = read_live_bytes(root, "/sys/kernel/btf/vmlinux", "btf", MAX_NARROW_BTF_BYTES);
    let btf_sha256 = if btf.state == "value" {
        btf.value.clone()
    } else {
        String::new()
    };
    let object_sha256 = object_bytes.map(sha256_hex).unwrap_or_default();
    JournalRuntimeEvidence {
        release,
        architecture,
        page_size,
        config_sha256,
        btf_sha256,
        object_sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::journal::journal_admission as declared_admission;

    fn bound_pair() -> (JournalProfileBinding, JournalRuntimeEvidence) {
        let binding = JournalProfileBinding {
            profile_id: "linux-7.0.14-x86-journal-provisional".to_string(),
            status: "admitted".to_string(),
            architecture: "x86_64".to_string(),
            page_size: 4096,
            callers_admitted: true,
            config_sha256: "aa".to_string(),
            btf_sha256: "bb".to_string(),
            object_sha256: "cc".to_string(),
        };
        let evidence = JournalRuntimeEvidence {
            release: "9.9.9-test".to_string(),
            architecture: "x86_64".to_string(),
            page_size: 4096,
            config_sha256: "aa".to_string(),
            btf_sha256: "bb".to_string(),
            object_sha256: "cc".to_string(),
        };
        (binding, evidence)
    }

    fn journal_only() -> JournalSelection {
        JournalSelection {
            attempts: false,
            journal: true,
            callers: false,
        }
    }

    #[test]
    fn exact_rebind_admits_with_evidence() {
        let (binding, evidence) = bound_pair();
        let dispatch = admit_journal(journal_only(), false, &binding, &evidence);
        match dispatch {
            JournalDispatch::Ready(ready) => {
                assert_eq!(ready.profile_id, binding.profile_id);
                assert_eq!(ready.evidence, evidence);
            }
            JournalDispatch::Refused(refusal) => panic!("refused: {:?}", refusal),
        }
    }

    #[test]
    fn every_binding_leg_refuses_alone() {
        let legs: Vec<(&str, &str)> = vec![
            ("architecture", "architecture"),
            ("page", "page"),
            ("config", "config"),
            ("btf", "btf"),
            ("object", "object"),
        ];
        for (leg, fix_word) in legs {
            let (mut binding, evidence) = bound_pair();
            match leg {
                "architecture" => binding.architecture = "aarch64".to_string(),
                "page" => binding.page_size = 8192,
                "config" => binding.config_sha256 = "zz".to_string(),
                "btf" => binding.btf_sha256 = "zz".to_string(),
                _ => binding.object_sha256 = "zz".to_string(),
            }
            let dispatch = admit_journal(journal_only(), false, &binding, &evidence);
            match dispatch {
                JournalDispatch::Refused(refusal) => {
                    assert_eq!(refusal.exit_code, EXIT_REFUSAL, "{leg}");
                    assert_eq!(refusal.reason, JOURNAL_NOT_ADMITTED, "{leg}");
                    assert!(refusal.fix.contains(fix_word), "{leg}: {}", refusal.fix);
                }
                JournalDispatch::Ready(_) => panic!("{leg} mismatch admitted"),
            }
        }
    }

    #[test]
    fn null_bindings_and_empty_evidence_refuse() {
        let (binding, evidence) = bound_pair();
        for leg in ["architecture", "page", "config", "btf", "object"] {
            let mut bad_binding = binding.clone();
            match leg {
                "architecture" => bad_binding.architecture.clear(),
                "page" => bad_binding.page_size = 0,
                "config" => bad_binding.config_sha256.clear(),
                "btf" => bad_binding.btf_sha256.clear(),
                _ => bad_binding.object_sha256.clear(),
            }
            assert!(
                matches!(
                    admit_journal(journal_only(), false, &bad_binding, &evidence),
                    JournalDispatch::Refused(_)
                ),
                "{leg} null binding admitted"
            );
            let mut bad_evidence = evidence.clone();
            match leg {
                "architecture" => bad_evidence.architecture.clear(),
                "page" => bad_evidence.page_size = 0,
                "config" => bad_evidence.config_sha256.clear(),
                "btf" => bad_evidence.btf_sha256.clear(),
                _ => bad_evidence.object_sha256.clear(),
            }
            assert!(
                matches!(
                    admit_journal(journal_only(), false, &binding, &bad_evidence),
                    JournalDispatch::Refused(_)
                ),
                "{leg} empty evidence admitted"
            );
        }
    }

    #[test]
    fn status_word_alone_never_admits() {
        let (mut binding, evidence) = bound_pair();
        for status in ["unadmitted", "", "ADMITTED", "admitted "] {
            binding.status = status.to_string();
            match admit_journal(journal_only(), false, &binding, &evidence) {
                JournalDispatch::Refused(refusal) => {
                    assert_eq!(refusal.reason, JOURNAL_NOT_ADMITTED);
                    assert!(refusal.fix.contains("not admitted"));
                }
                JournalDispatch::Ready(_) => panic!("status {status:?} admitted"),
            }
        }
    }

    #[test]
    fn attempts_and_callers_gates_match_model_order() {
        let (binding, evidence) = bound_pair();
        let mixed = JournalSelection {
            attempts: true,
            journal: true,
            callers: false,
        };
        assert!(matches!(
            admit_journal(mixed, false, &binding, &evidence),
            JournalDispatch::Refused(_)
        ));
        assert!(matches!(
            admit_journal(mixed, true, &binding, &evidence),
            JournalDispatch::Ready(_)
        ));
        let callers = JournalSelection {
            attempts: false,
            journal: true,
            callers: true,
        };
        assert!(matches!(
            admit_journal(callers, false, &binding, &evidence),
            JournalDispatch::Ready(_)
        ));
        let (mut no_labels, evidence) = bound_pair();
        no_labels.callers_admitted = false;
        match admit_journal(callers, false, &no_labels, &evidence) {
            JournalDispatch::Refused(refusal) => {
                assert_eq!(refusal.reason, "journal_callers_not_admitted");
            }
            JournalDispatch::Ready(_) => panic!("unlabelled callers admitted"),
        }
    }

    #[test]
    fn declared_gates_agree_with_model() {
        // The declared half (status/attempts/callers) decides
        // exactly like the frozen model check; evidence only
        // adds legs, never removes a declared refusal.
        let (binding, evidence) = bound_pair();
        for attempts in [false, true] {
            for journal in [false, true] {
                for callers in [false, true] {
                    for status in ["admitted", "unadmitted"] {
                        for attempts_ok in [false, true] {
                            let selection = JournalSelection {
                                attempts,
                                journal,
                                callers,
                            };
                            let declared = declared_admission(
                                selection,
                                attempts_ok,
                                status,
                                binding.callers_admitted,
                            );
                            let mut probe = binding.clone();
                            probe.status = status.to_string();
                            let dispatch = admit_journal(selection, attempts_ok, &probe, &evidence);
                            if !journal {
                                assert!(matches!(dispatch, JournalDispatch::Refused(_)));
                                continue;
                            }
                            match (&declared.exit_code, &dispatch) {
                                (0, JournalDispatch::Ready(_)) => {}
                                (3, JournalDispatch::Refused(refusal)) => {
                                    assert_eq!(refusal.reason, declared.reason);
                                }
                                _ => panic!("model/capture disagree: {declared:?} vs {dispatch:?}"),
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn unrequested_journal_refuses_typed() {
        let (binding, evidence) = bound_pair();
        let ordinary = JournalSelection {
            attempts: true,
            journal: false,
            callers: false,
        };
        match admit_journal(ordinary, true, &binding, &evidence) {
            JournalDispatch::Refused(refusal) => {
                assert_eq!(refusal.exit_code, EXIT_REFUSAL);
                assert_eq!(refusal.reason, "journal_not_requested");
            }
            JournalDispatch::Ready(_) => panic!("unrequested journal admitted"),
        }
    }

    #[test]
    fn discovery_fixes_name_the_gate() {
        assert!(fix_for_discovery(JournalDiscoveryFailure::Unavailable).contains("unavailable"));
        assert!(fix_for_discovery(JournalDiscoveryFailure::Invalid).contains("invalid"));
    }
}
