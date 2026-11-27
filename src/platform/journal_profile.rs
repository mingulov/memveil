// SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit discovery of source-reviewed candidates, separate from live admission.
//!
//! [`journal_profile_reason`] answers why a journal request refuses: the
//! source-provisional candidate is discovered by exact id, never admitted.
//! A profile edit alone is not admission; no admitted registry exists and
//! no public override bypasses this refusal.

use crate::model::journal_event::{fields, null_value, text};
use crate::model::scan::Scanner;
use crate::platform::reader::read_host_file;

/// The one declared journal candidate id.
pub const JOURNAL_CANDIDATE_ID: &str = "linux-7.0.14-x86-journal-provisional";

/// Closed candidate-profile shape: every name must appear exactly once.
const PROFILE_FIELDS: &[&str] = &[
    "contract",
    "profile_id",
    "status",
    "evidence_class",
    "linux_commit",
    "architecture",
    "page_size",
    "transient_key",
    "source_files",
    "config_sha256",
    "btf_sha256",
    "object_sha256",
    "required_config",
    "required_btf",
    "hooks",
    "native_result",
    "effect",
    "caller_labels",
    "admission_required",
];

/// Refusal reason for a journal request against `profiles_dir`.
///
/// An explicit non-candidate id resolves verbatim as a path; anything
/// unreadable or unparsable reads as unavailable, a wellformed
/// non-qualifying document reads as unadmitted, and the carried
/// candidate reads as unadmitted too: discovery, never admission.
pub fn journal_profile_reason(profiles_dir: &str, explicit: &str, has_explicit: bool) -> String {
    let mut path = format!("{profiles_dir}/journal-candidates/{JOURNAL_CANDIDATE_ID}.json");
    if has_explicit && explicit != JOURNAL_CANDIDATE_ID {
        path = explicit.to_string();
    }
    let data = match read_host_file(&path, "journal candidate profile", 1048576) {
        Ok(data) => data,
        Err(_) => {
            return "journal_profile_not_admitted: candidate profile unavailable".to_string();
        }
    };
    let mut scan = Scanner::new(&data);
    scan.skip_ws();
    let parsed = fields(&mut scan, PROFILE_FIELDS);
    let found = match parsed {
        Ok(found) => found,
        Err(_) => {
            return "journal_profile_not_admitted: candidate profile unavailable".to_string();
        }
    };
    scan.skip_ws();
    if !scan.at_end() {
        return "journal_profile_not_admitted: invalid profile".to_string();
    }
    let contract = text(found["contract"], false);
    let profile_id = text(found["profile_id"], false);
    let status = text(found["status"], false);
    let evidence_class = text(found["evidence_class"], false);
    let effect = text(found["effect"], false);
    let qualifying = match (contract, profile_id, status, evidence_class, effect) {
        (Ok(contract), Ok(profile_id), Ok(status), Ok(evidence_class), Ok(effect)) => {
            contract == "memveil-journal-profile/1"
                && profile_id == JOURNAL_CANDIDATE_ID
                && status == "unadmitted"
                && evidence_class == "source_reviewed_provisional"
                && effect == "request_only"
        }
        _ => {
            return "journal_profile_not_admitted: candidate profile unavailable".to_string();
        }
    };
    if !qualifying {
        return "journal_profile_not_admitted: no admitted registry entry".to_string();
    }
    if null_value(found["config_sha256"]).is_err()
        || null_value(found["btf_sha256"]).is_err()
        || null_value(found["object_sha256"]).is_err()
    {
        return "journal_profile_not_admitted: candidate profile unavailable".to_string();
    }
    "journal_profile_not_admitted".to_string()
}
