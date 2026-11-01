# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit discovery of source-reviewed candidates, separate from live admission."""
from memveil.jsonscan import Scanner
from memveil.model.journal_json import fields, text, null_value
from memveil.platform.reader import read_host_file

comptime JOURNAL_CANDIDATE_ID = "linux-7.0.14-x86-journal-provisional"


def journal_profile_reason(profiles_dir: String, explicit: String, has_explicit: Bool) -> String:
    var path = profiles_dir + "/journal-candidates/" + String(JOURNAL_CANDIDATE_ID) + ".json"
    if has_explicit and explicit != JOURNAL_CANDIDATE_ID:
        path = explicit
    var data = List[UInt8]()
    try:
        data = read_host_file(path, String("journal candidate profile"), 1048576)
    except:
        return String("journal_profile_not_admitted: candidate profile unavailable")
    try:
        var scan = Scanner(data)
        scan.skip_ws()
        var f = fields(scan, String("contract,profile_id,status,evidence_class,linux_commit,architecture,page_size,transient_key,source_files,config_sha256,btf_sha256,object_sha256,required_config,required_btf,hooks,native_result,effect,caller_labels,admission_required"))
        scan.skip_ws()
        if not scan.at_end():
            return String("journal_profile_not_admitted: invalid profile")
        if text(f["contract"]) != "memveil-journal-profile/1" or text(f["profile_id"]) != JOURNAL_CANDIDATE_ID or text(f["status"]) != "unadmitted" or text(f["evidence_class"]) != "source_reviewed_provisional" or text(f["effect"]) != "request_only":
            return String("journal_profile_not_admitted: no admitted registry entry")
        null_value(f["config_sha256"])
        null_value(f["btf_sha256"])
        null_value(f["object_sha256"])
    except:
        return String("journal_profile_not_admitted: candidate profile unavailable")
    return String("journal_profile_not_admitted")
