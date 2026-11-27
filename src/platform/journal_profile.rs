// SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit discovery of source-reviewed candidates, separate from live admission.
//!
//! [`discover_journal_binding`] reads one candidate document into
//! closed bindings; admission itself lives in
//! `crate::capture::journal_admission`, which binds these
//! declarations against freshly rebound runtime evidence. A
//! profile edit alone is not admission: discovery never admits.
//!
//! The user-facing refusal keeps one documented form everywhere:
//! the bare frozen `journal_profile_not_admitted` diagnostic plus
//! a fix line naming the failed gate. Discovery detail below is
//! machine-readable ([`JournalDiscoveryFailure`]); no suffixed
//! refusal string exists anymore.

use crate::model::journal_event::{fields, text, uint};
use crate::model::scan::{Scanner, object_is_empty};
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

/// Closed candidate bindings: the declared half of admission.
///
/// Empty hashes mean unbound (null in the document); admission
/// refuses unbound legs, so null is never a wildcard.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalProfileBinding {
    /// Declared candidate id (always the known id when parsed).
    pub profile_id: String,
    /// Declared status word; admission requires `admitted`.
    pub status: String,
    /// Declared host architecture the bindings cover.
    pub architecture: String,
    /// Declared host page size the bindings cover.
    pub page_size: u64,
    /// True when the document carries caller labels.
    pub callers_admitted: bool,
    /// Bound config hash, or "" when null.
    pub config_sha256: String,
    /// Bound BTF hash, or "" when null.
    pub btf_sha256: String,
    /// Bound object hash, or "" when null.
    pub object_sha256: String,
}

/// Discovery failure: unreadable vs ill-formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalDiscoveryFailure {
    /// No readable document at the resolved path.
    Unavailable,
    /// A document that fails the closed candidate contract.
    Invalid,
}

/// Discover the candidate bindings under `profiles_dir`.
///
/// An explicit non-candidate id resolves verbatim as a path;
/// anything unreadable reads as unavailable. The returned
/// bindings are declarations only, never admission.
pub fn discover_journal_binding(
    profiles_dir: &str,
    explicit: &str,
    has_explicit: bool,
) -> Result<JournalProfileBinding, JournalDiscoveryFailure> {
    let mut path = format!("{profiles_dir}/journal-candidates/{JOURNAL_CANDIDATE_ID}.json");
    if has_explicit && explicit != JOURNAL_CANDIDATE_ID {
        path = explicit.to_string();
    }
    let data = match read_host_file(&path, "journal candidate profile", 1048576) {
        Ok(data) => data,
        Err(_) => return Err(JournalDiscoveryFailure::Unavailable),
    };
    parse_journal_binding(&data)
}

/// Parse one candidate document into bindings.
///
/// The closed 19-field shape, no trailing bytes, the exact
/// contract/id/class/effect tuple, a non-empty architecture, a
/// present page size, and an object-shaped caller-labels map are
/// all required; anything else is invalid. The status word and
/// the nullable hashes pass through verbatim for admission to
/// judge against rebound evidence.
pub fn parse_journal_binding(
    data: &[u8],
) -> Result<JournalProfileBinding, JournalDiscoveryFailure> {
    let mut scan = Scanner::new(data);
    scan.skip_ws();
    let found = match fields(&mut scan, PROFILE_FIELDS) {
        Ok(found) => found,
        Err(_) => return Err(JournalDiscoveryFailure::Invalid),
    };
    scan.skip_ws();
    if !scan.at_end() {
        return Err(JournalDiscoveryFailure::Invalid);
    }
    let contract = text(found["contract"], false);
    let profile_id = text(found["profile_id"], false);
    let status = text(found["status"], false);
    let evidence_class = text(found["evidence_class"], false);
    let architecture = text(found["architecture"], false);
    let effect = text(found["effect"], false);
    let (contract, profile_id, status, evidence_class, architecture, effect) = match (
        contract,
        profile_id,
        status,
        evidence_class,
        architecture,
        effect,
    ) {
        (
            Ok(contract),
            Ok(profile_id),
            Ok(status),
            Ok(evidence_class),
            Ok(architecture),
            Ok(effect),
        ) => (
            contract,
            profile_id,
            status,
            evidence_class,
            architecture,
            effect,
        ),
        _ => return Err(JournalDiscoveryFailure::Invalid),
    };
    if contract != "memveil-journal-profile/1"
        || profile_id != JOURNAL_CANDIDATE_ID
        || evidence_class != "source_reviewed_provisional"
        || effect != "request_only"
    {
        return Err(JournalDiscoveryFailure::Invalid);
    }
    if architecture.is_empty() {
        return Err(JournalDiscoveryFailure::Invalid);
    }
    let page_size = match uint(found["page_size"]) {
        Ok(size) if size.has => size.value,
        _ => return Err(JournalDiscoveryFailure::Invalid),
    };
    let config_sha256 = match text(found["config_sha256"], true) {
        Ok(value) => value,
        Err(_) => return Err(JournalDiscoveryFailure::Invalid),
    };
    let btf_sha256 = match text(found["btf_sha256"], true) {
        Ok(value) => value,
        Err(_) => return Err(JournalDiscoveryFailure::Invalid),
    };
    let object_sha256 = match text(found["object_sha256"], true) {
        Ok(value) => value,
        Err(_) => return Err(JournalDiscoveryFailure::Invalid),
    };
    let mut labels = Scanner::new(found["caller_labels"]);
    labels.skip_ws();
    if labels.begin_object("journal").is_err() {
        return Err(JournalDiscoveryFailure::Invalid);
    }
    let callers_admitted = match object_is_empty(&mut labels, "journal") {
        Ok(empty) => !empty,
        Err(_) => return Err(JournalDiscoveryFailure::Invalid),
    };
    Ok(JournalProfileBinding {
        profile_id: profile_id.clone(),
        status,
        architecture,
        page_size,
        callers_admitted,
        config_sha256,
        btf_sha256,
        object_sha256,
    })
}
