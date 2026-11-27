// SPDX-License-Identifier: GPL-3.0-or-later
//! Conversion-journal integration matrix: dispatch, mixed
//! ordinary/journal runs, attach/read/control/write failure,
//! stop race/timeout, initial/open checkpoints, writer/reader
//! round-trip, and lease-gated guest legs.
//!
//! Offline legs run unconditionally on the build host through
//! typed injection plus the real admission entry point; they
//! never load, attach, or need privileges. Guest legs run ONLY
//! when `MEMVEIL_JOURNAL_LEASE` names the controller-owned
//! isolated harness as `user@host:port`; without it they
//! self-skip with a printed receipt. They never fail, hang
//! (every remote command carries timeouts), provision, or
//! touch any other machine.

use memveil::capture::collector::{
    ClockSource, Collector, CollectorConfig, EXIT_ERROR, GeomOut, KernelSource, MAP_TYPE_ARRAY,
    MAP_TYPE_RINGBUF, MissOut, PollOut, SignalSource, SnapOut, StatsOut,
};
use memveil::capture::journal_capture::{
    JOURNAL_NATIVE_COUNTERS, JournalCounters, JournalKernel, JournalPoll,
};
use memveil::capture::live::{AppendOut, CreateOut, FinalOut, GroupOut, LiveWriter, WriterSource};
use memveil::capture::run::{RecordOptions, run_collector_with};
use memveil::model::event::parse_event;
use memveil::model::session::parse_session;
use memveil::platform::hash::sha256_hex;
use memveil::platform::journal_profile::JOURNAL_CANDIDATE_ID;
use memveil::platform::narrow::{MAX_NARROW_BTF_BYTES, read_live_bytes, read_live_config};
use memveil::platform::outcome::OpOut;
use memveil::platform::signal::SignalOut;

fn ok_out() -> OpOut {
    OpOut {
        ok: true,
        message: String::new(),
    }
}

/// Scripted ordinary kernel: admitted geometry, quiet polls.
struct ScriptKernel {
    calls: Vec<String>,
}

impl ScriptKernel {
    fn new() -> Self {
        Self { calls: Vec::new() }
    }
}

impl KernelSource for ScriptKernel {
    fn open_session(&mut self) -> OpOut {
        self.calls.push("open".to_string());
        ok_out()
    }

    fn load(&mut self) -> OpOut {
        self.calls.push("load".to_string());
        ok_out()
    }

    fn map_info(&mut self, name: &str) -> GeomOut {
        self.calls.push("map_info".to_string());
        let geom = match name {
            "mv_counts" => Some((MAP_TYPE_ARRAY, 4, 8, 6)),
            "mv_attempts" => Some((MAP_TYPE_RINGBUF, 0, 0, 0)),
            "mv_offsets" => Some((
                MAP_TYPE_ARRAY,
                4,
                memveil::platform::narrow::MV_OFFSETS_TABLE_LEN as u32,
                1,
            )),
            _ => None,
        };
        match geom {
            Some((map_type, key_size, value_size, max_entries)) => GeomOut {
                ok: true,
                map_type,
                key_size,
                value_size,
                max_entries,
                message: String::new(),
            },
            None => GeomOut {
                ok: false,
                map_type: 0,
                key_size: 0,
                value_size: 0,
                max_entries: 0,
                message: "scripted".to_string(),
            },
        }
    }

    fn map_info_at(&mut self, _channel: i64, _name: &str) -> GeomOut {
        self.calls.push("map_info_at".to_string());
        GeomOut {
            ok: false,
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            message: "scripted".to_string(),
        }
    }

    fn install_offsets(&mut self, _table: &[u8]) -> OpOut {
        self.calls.push("install_offsets".to_string());
        ok_out()
    }

    fn attach(&mut self) -> OpOut {
        self.calls.push("attach".to_string());
        ok_out()
    }

    fn set_copy_armed(&mut self, _armed: bool) -> OpOut {
        self.calls.push("set_copy_armed".to_string());
        ok_out()
    }

    fn poll(&mut self, _timeout_ms: i64, _capacity: u32) -> PollOut {
        self.calls.push("poll".to_string());
        PollOut {
            kind: "timeout".to_string(),
            frame: Vec::new(),
            required: 0,
            message: String::new(),
        }
    }

    fn stats(&mut self) -> StatsOut {
        self.calls.push("stats".to_string());
        StatsOut {
            ok: true,
            received: 0,
            delivered: 0,
            staged: 0,
            malformed: 0,
            dropped: 0,
            message: String::new(),
        }
    }

    fn stats_at(&mut self, _channel: i64) -> StatsOut {
        self.calls.push("stats_at".to_string());
        self.stats()
    }

    fn read_full(&mut self) -> SnapOut {
        self.calls.push("read_full".to_string());
        SnapOut {
            ok: true,
            vals: vec![0, 0, 0, 0, 0, 0],
            message: String::new(),
        }
    }

    fn read_full_at(&mut self, _channel: i64) -> SnapOut {
        self.calls.push("read_full_at".to_string());
        self.read_full()
    }

    fn channel_count(&self) -> i64 {
        1
    }

    fn detach(&mut self) -> OpOut {
        self.calls.push("detach".to_string());
        ok_out()
    }

    fn recursion_misses(&mut self) -> MissOut {
        self.calls.push("recursion_misses".to_string());
        MissOut {
            ok: true,
            count: 0,
            message: String::new(),
            attempt: 0,
            has_copy_detail: false,
            bounce: 0,
            exit_misses: 0,
            sync_device: 0,
            sync_cpu: 0,
            lc_map: 0,
            lc_unmap: 0,
            deferred: 0,
            recovered: 0,
            detail_error: String::new(),
        }
    }

    fn close(&mut self) -> OpOut {
        self.calls.push("close".to_string());
        ok_out()
    }
}

/// Scripted monotonic clock.
struct ScriptClock {
    now_ns: u64,
    step: u64,
}

impl ScriptClock {
    fn new(start: u64, step: u64) -> Self {
        Self {
            now_ns: start,
            step,
        }
    }
}

impl ClockSource for ScriptClock {
    fn now(&mut self) -> u64 {
        let out = self.now_ns;
        self.now_ns = self.now_ns.saturating_add(self.step);
        out
    }

    fn sleep_ms(&mut self, _ms: i64) {}
}

/// Signal source that goes pending from the Nth check on.
struct StepSignal {
    checks: u64,
    fire_at: u64,
}

impl StepSignal {
    fn new(fire_at: u64) -> Self {
        Self { checks: 0, fire_at }
    }

    fn quiet() -> Self {
        Self::new(u64::MAX)
    }
}

impl SignalSource for StepSignal {
    fn setup(&mut self) -> OpOut {
        ok_out()
    }

    fn check(&mut self) -> SignalOut {
        self.checks += 1;
        SignalOut {
            state: if self.checks >= self.fire_at {
                "pending".to_string()
            } else {
                "none".to_string()
            },
            message: String::new(),
        }
    }
}

/// Recording writer with scripted residual and fatal-append fault.
struct MemWriter {
    lines: Vec<Vec<u8>>,
    checkpoints: Vec<Vec<u8>>,
    session_bytes: Vec<u8>,
    finalized: bool,
    committed: u64,
    created: bool,
    created_path: String,
    residual: String,
    /// 1-based append ordinal that fails fatal; 0 never fails.
    fail_append_at: u64,
    appends: u64,
    discards: u64,
}

impl MemWriter {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            checkpoints: Vec::new(),
            session_bytes: Vec::new(),
            finalized: false,
            committed: 0,
            created: false,
            created_path: String::new(),
            residual: String::new(),
            fail_append_at: 0,
            appends: 0,
            discards: 0,
        }
    }
}

impl WriterSource for MemWriter {
    fn create(&mut self, path: &str, _budget: u64) -> CreateOut {
        self.created = true;
        self.created_path = path.to_string();
        CreateOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }

    fn append(&mut self, line: &[u8]) -> AppendOut {
        self.appends += 1;
        if self.fail_append_at != 0 && self.appends == self.fail_append_at {
            return AppendOut {
                ok: false,
                kind: "fatal".to_string(),
                message: "scripted matrix fault".to_string(),
            };
        }
        self.lines.push(line.to_vec());
        self.committed += line.len() as u64;
        AppendOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }

    fn append_closing(&mut self, line: &[u8]) -> AppendOut {
        self.append(line)
    }

    fn group_begin(&mut self) -> GroupOut {
        GroupOut {
            ok: true,
            mark: self.committed,
            kind: String::new(),
        }
    }

    fn group_abort(&mut self, mark: u64) -> AppendOut {
        self.committed = mark;
        AppendOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }

    fn checkpoint(&mut self, session: &[u8]) -> AppendOut {
        self.checkpoints.push(session.to_vec());
        AppendOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }

    fn finalize(&mut self, session: &[u8]) -> FinalOut {
        self.session_bytes = session.to_vec();
        self.finalized = true;
        FinalOut {
            status: "finalized".to_string(),
            note: String::new(),
        }
    }

    fn abandon(&mut self) -> String {
        self.residual.clone()
    }

    fn discard(&mut self) {
        self.discards += 1;
    }

    fn committed_len(&self) -> u64 {
        self.committed
    }

    fn finalized_identity(&self) -> Vec<u64> {
        Vec::new()
    }
}

/// Scripted journal source: one matched record while open, plus
/// independent attach/control/read/counters/close fault flags.
struct MatrixJournal {
    control_bytes: Vec<u8>,
    calls: Vec<String>,
    sent: bool,
    attach_fail: bool,
    control_fail: bool,
    poll_fail: bool,
    counters_fail: bool,
    close_fail: bool,
}

impl MatrixJournal {
    fn new() -> Self {
        Self {
            control_bytes: Vec::new(),
            calls: Vec::new(),
            sent: false,
            attach_fail: false,
            control_fail: false,
            poll_fail: false,
            counters_fail: false,
            close_fail: false,
        }
    }

    fn control_u64(&self, offset: usize) -> u64 {
        let mut value: u64 = 0;
        for i in 0..8 {
            value |= u64::from(self.control_bytes[offset + i]) << (8 * i);
        }
        value
    }
}

impl JournalKernel for MatrixJournal {
    fn prepare(&mut self, control: &[u8]) -> OpOut {
        self.calls.push("prepare".to_string());
        self.control_bytes = control.to_vec();
        ok_out()
    }

    fn attach(&mut self) -> OpOut {
        self.calls.push("attach".to_string());
        OpOut {
            ok: !self.attach_fail,
            message: if self.attach_fail {
                "scripted attach".to_string()
            } else {
                String::new()
            },
        }
    }

    fn control(&mut self, value: &[u8]) -> OpOut {
        let open = value.len() == 48 && value[24] == 1;
        self.calls.push(if open {
            "open".to_string()
        } else {
            "close-admission".to_string()
        });
        self.control_bytes = value.to_vec();
        OpOut {
            ok: !self.control_fail,
            message: if self.control_fail {
                "scripted control".to_string()
            } else {
                String::new()
            },
        }
    }

    fn poll(&mut self, _timeout_ms: i64) -> JournalPoll {
        if self.poll_fail {
            return JournalPoll {
                ok: false,
                data: Vec::new(),
            };
        }
        if self.sent || self.control_bytes.len() != 48 || self.control_bytes[24] == 0 {
            return JournalPoll {
                ok: true,
                data: Vec::new(),
            };
        }
        let epoch = self.control_u64(0);
        let start = self.control_u64(8);
        let mut raw = vec![0u8; 72];
        raw[0..4].copy_from_slice(&0x524A_564Du32.to_le_bytes());
        raw[4..6].copy_from_slice(&1u16.to_le_bytes());
        raw[6..8].copy_from_slice(&1u16.to_le_bytes());
        raw[8..10].copy_from_slice(&1u16.to_le_bytes());
        raw[10..12].copy_from_slice(&1u16.to_le_bytes());
        raw[16..24].copy_from_slice(&0u64.to_le_bytes());
        raw[24..32].copy_from_slice(&(start + 1).to_le_bytes());
        raw[32..40].copy_from_slice(&epoch.to_le_bytes());
        raw[40..48].copy_from_slice(&1u64.to_le_bytes());
        raw[48..56].copy_from_slice(&start.to_le_bytes());
        raw[56..60].copy_from_slice(&3i32.to_le_bytes());
        raw[60..64].copy_from_slice(&0i32.to_le_bytes());
        self.sent = true;
        JournalPoll {
            ok: true,
            data: raw,
        }
    }

    fn counters(&mut self) -> JournalCounters {
        let mut values = vec![0u64; JOURNAL_NATIVE_COUNTERS];
        if self.sent {
            values[0] = 1;
            values[1] = 1;
            values[2] = 1;
            values[14] = 1;
        }
        JournalCounters {
            ok: !self.counters_fail,
            values,
        }
    }

    fn detach(&mut self) -> OpOut {
        self.calls.push("detach".to_string());
        ok_out()
    }

    fn close(&mut self) -> OpOut {
        self.calls.push("release".to_string());
        OpOut {
            ok: !self.close_fail,
            message: if self.close_fail {
                "scripted close".to_string()
            } else {
                String::new()
            },
        }
    }
}

fn journal_only_config() -> CollectorConfig {
    CollectorConfig {
        has_journal: true,
        journal_only: true,
        journal_callers: false,
        journal_profile: JOURNAL_CANDIDATE_ID.to_string(),
        duration_s: 1,
        ..Default::default()
    }
}

fn mixed_config() -> CollectorConfig {
    CollectorConfig {
        has_journal: true,
        journal_only: false,
        journal_callers: false,
        journal_profile: JOURNAL_CANDIDATE_ID.to_string(),
        profile_id: "matrix-mixed-profile".to_string(),
        duration_s: 1,
        ..Default::default()
    }
}

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("memveil-jm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch");
    root
}

fn write_profile(dir: &std::path::Path, name: &str, body: &str) {
    let lane = dir.join("journal-candidates");
    std::fs::create_dir_all(&lane).expect("candidates dir");
    std::fs::write(lane.join(name), body).expect("profile body");
}

fn candidate_body() -> String {
    std::fs::read_to_string("profiles/journal-candidates/linux-7.0.14-x86-journal-provisional.json")
        .expect("carried candidate reads")
}

/// Live host bindings rebound independently of the dispatch under
/// test: release, architecture, page size, config hash, BTF hash.
/// None (with a printed receipt) when the host exposes no
/// measurable config or BTF.
fn live_bindings() -> Option<(String, String, u64, String, String)> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()?
        .trim()
        .to_string();
    if release.is_empty() {
        return None;
    }
    let arch = std::env::consts::ARCH.to_string();
    // SAFETY: sysconf with a valid name; -1 means unknown.
    let pages = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages <= 0 {
        return None;
    }
    let config = read_live_config("", &release, "libz.so.1");
    if config.src.is_empty() || config.value.state != "value" {
        eprintln!("matrix mint: live config unmeasurable (src={})", config.src);
        return None;
    }
    let btf = read_live_bytes("", "/sys/kernel/btf/vmlinux", "btf", MAX_NARROW_BTF_BYTES);
    if btf.state != "value" {
        eprintln!("matrix mint: live BTF unmeasurable");
        return None;
    }
    Some((
        release,
        arch,
        pages as u64,
        config.value.value.clone(),
        btf.value.clone(),
    ))
}

/// An admitted-shaped profile binding the given live values.
/// String surgery on the carried candidate keeps the closed
/// 19-field shape byte-identical outside the rebound fields.
fn admitted_body(config: &str, btf: &str, object: &str, arch: &str, pages: u64) -> String {
    candidate_body()
        .replacen("\"status\": \"unadmitted\"", "\"status\": \"admitted\"", 1)
        .replacen(
            "\"architecture\": \"x86_64\"",
            &format!("\"architecture\": \"{arch}\""),
            1,
        )
        .replacen(
            "\"page_size\": \"4096\"",
            &format!("\"page_size\": \"{pages}\""),
            1,
        )
        .replacen(
            "\"config_sha256\": null",
            &format!("\"config_sha256\": \"{config}\""),
            1,
        )
        .replacen(
            "\"btf_sha256\": null",
            &format!("\"btf_sha256\": \"{btf}\""),
            1,
        )
        .replacen(
            "\"object_sha256\": null",
            &format!("\"object_sha256\": \"{object}\""),
            1,
        )
}

/// Non-ELF object bytes with a valid length: dispatch resolves
/// and hashes them, then the native prepare refuses on the
/// magic before any privilege use. Deterministic with or
/// without privileges.
fn garbage_object(dir: &std::path::Path) -> (std::path::PathBuf, String) {
    let path = dir.join("garbage.bpf.o");
    let bytes = vec![0xAAu8; 100];
    std::fs::write(&path, &bytes).expect("garbage object");
    (path, sha256_hex(&bytes))
}

/// Lease endpoint from the environment, or None with a receipt.
fn lease_ssh() -> Option<(String, String, String)> {
    let raw = std::env::var("MEMVEIL_JOURNAL_LEASE").unwrap_or_default();
    if raw.is_empty() {
        eprintln!("guest leg skipped: no lease (set MEMVEIL_JOURNAL_LEASE=user@host:port)");
        return None;
    }
    let (user_host, port) = raw.rsplit_once(':')?;
    let (user, host) = user_host.split_once('@')?;
    if user.is_empty() || host.is_empty() || port.is_empty() {
        eprintln!("guest leg skipped: malformed MEMVEIL_JOURNAL_LEASE");
        return None;
    }
    Some((user.to_string(), host.to_string(), port.to_string()))
}

fn ssh_args(user: &str, host: &str, port: &str) -> Vec<String> {
    vec![
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-p".to_string(),
        port.to_string(),
        format!("{user}@{host}"),
    ]
}

/// Run one remote command; every leg passes its own `timeout`.
fn ssh_run(user: &str, host: &str, port: &str, script: &str) -> std::process::Output {
    let mut args = ssh_args(user, host, port);
    args.push(script.to_string());
    std::process::Command::new("ssh")
        .args(&args)
        .output()
        .expect("ssh runs")
}

fn scp_to(user: &str, host: &str, port: &str, local: &str, remote: &str) {
    let status = std::process::Command::new("scp")
        .args([
            "-P",
            port,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=10",
            local,
            &format!("{user}@{host}:{remote}"),
        ])
        .status()
        .expect("scp runs");
    assert!(status.success(), "scp {local} -> {remote} failed");
}

/// Newest linked journal object, honoring an explicit
/// `CARGO_TARGET_DIR` like cargo itself.
fn built_journal_object() -> Option<Vec<u8>> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = match std::env::var("CARGO_TARGET_DIR") {
        Ok(dir) if !dir.is_empty() => {
            let path = std::path::PathBuf::from(&dir);
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        }
        _ => root.join("target"),
    };
    let mut cands = Vec::new();
    for profile in ["debug", "release"] {
        let base = target.join(profile).join("build").join("memveil");
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            let obj = entry
                .path()
                .join("out")
                .join("ebpf-target")
                .join("bpfel-unknown-none")
                .join("release")
                .join("memveil-ebpf-journal");
            if obj.is_file() {
                cands.push(obj);
            }
        }
    }
    cands
        .into_iter()
        .filter_map(|path| std::fs::read(&path).ok())
        .next()
}

#[test]
fn dispatch_unadmitted_profile_refuses_before_resources() {
    // The carried candidate (unadmitted, null bindings) refuses
    // with the bare frozen code before native or output
    // creation, on the unwired and the wired tree alike.
    let root = scratch("ref");
    write_profile(
        &root,
        "linux-7.0.14-x86-journal-provisional.json",
        &candidate_body(),
    );
    let out = root.join("cap");
    let opts = RecordOptions {
        output: out.to_str().expect("utf-8").to_string(),
        capabilities: "conversion-journal".to_string(),
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
    assert_eq!(result.exit_code, 3, "{}", result.diagnostic);
    assert_eq!(result.diagnostic, "journal_profile_not_admitted");
    assert!(!out.exists());
    assert!(!writer.created);
    assert!(writer.lines.is_empty());
    assert!(!writer.finalized);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dispatch_refusal_form_is_bare_code_with_fix() {
    // One documented refusal form: the diagnostic carries the
    // bare frozen code alone, and the fix line names the failed
    // discovery gate. Absent, invalid, and unadmitted profiles
    // share the code and differ only in guidance.
    let root = scratch("form");
    let out = root.join("cap");
    let run = |profiles: &str| {
        let opts = RecordOptions {
            output: out.to_str().expect("utf-8").to_string(),
            capabilities: "conversion-journal".to_string(),
            ..Default::default()
        };
        let mut writer = MemWriter::new();
        run_collector_with("", profiles, opts, &mut writer)
    };
    let absent = run(root.to_str().expect("utf-8"));
    assert_eq!(absent.exit_code, 3);
    assert_eq!(absent.diagnostic, "journal_profile_not_admitted");
    assert!(
        absent.fix.contains("unavailable"),
        "absent fix: {}",
        absent.fix
    );
    let bad = root.join("bad.json");
    std::fs::write(&bad, "{not json").expect("bad profile");
    let opts = RecordOptions {
        output: out.to_str().expect("utf-8").to_string(),
        capabilities: "conversion-journal".to_string(),
        profile: bad.to_str().expect("utf-8").to_string(),
        has_profile: true,
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let invalid = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
    assert_eq!(invalid.exit_code, 3);
    assert_eq!(invalid.diagnostic, "journal_profile_not_admitted");
    assert!(
        invalid.fix.contains("invalid") || invalid.fix.contains("unavailable"),
        "invalid fix: {}",
        invalid.fix
    );
    write_profile(
        &root,
        "linux-7.0.14-x86-journal-provisional.json",
        &candidate_body(),
    );
    let unadmitted = run(root.to_str().expect("utf-8"));
    assert_eq!(unadmitted.exit_code, 3);
    assert_eq!(unadmitted.diagnostic, "journal_profile_not_admitted");
    assert!(
        unadmitted.fix.contains("not admitted"),
        "carried fix: {}",
        unadmitted.fix
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dispatch_admitted_profile_with_rebound_evidence_reaches_native() {
    // Positive path: an admitted profile whose bindings match
    // the freshly rebound runtime evidence passes admission, so
    // the native prepare is attempted. The staged object is
    // deliberately non-ELF, so prepare refuses on the magic
    // before any privilege use; the native-attempt diagnostic
    // (instead of the frozen code) is the observable. Output
    // creation runs only after a successful prepare, so the
    // refused native attempt correctly creates no output.
    let Some((release, arch, pages, config, btf)) = live_bindings() else {
        eprintln!("skip: live config/BTF unmeasurable on this host");
        return;
    };
    let root = scratch("pos");
    let (obj_path, obj_sha) = garbage_object(&root);
    write_profile(
        &root,
        "linux-7.0.14-x86-journal-provisional.json",
        &admitted_body(&config, &btf, &obj_sha, &arch, pages),
    );
    eprintln!("matrix rebound: release={release} arch={arch} pages={pages}");
    eprintln!("matrix rebound: config={config} btf={btf} object={obj_sha}");
    let out = root.join("cap");
    let opts = RecordOptions {
        output: out.to_str().expect("utf-8").to_string(),
        capabilities: "conversion-journal".to_string(),
        journal_object: obj_path.to_str().expect("utf-8").to_string(),
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
    assert_eq!(result.exit_code, 3, "{}", result.diagnostic);
    assert_eq!(
        result.diagnostic, "journal open/load unavailable",
        "admission refused instead of reaching native"
    );
    assert!(!writer.created);
    assert!(!out.exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dispatch_mixed_admitted_journal_falls_through_to_ordinary() {
    // Mixed request, admitted journal, broken ordinary side: the
    // journal admits first and the ordinary refusal surfaces, so
    // the diagnostic names the ordinary stage, never the frozen
    // journal code.
    let Some((_release, arch, pages, config, btf)) = live_bindings() else {
        eprintln!("skip: live config/BTF unmeasurable on this host");
        return;
    };
    let root = scratch("mix");
    let (obj_path, obj_sha) = garbage_object(&root);
    write_profile(
        &root,
        "linux-7.0.14-x86-journal-provisional.json",
        &admitted_body(&config, &btf, &obj_sha, &arch, pages),
    );
    let out = root.join("cap");
    let opts = RecordOptions {
        output: out.to_str().expect("utf-8").to_string(),
        capabilities: "attempt-trace,conversion-journal".to_string(),
        journal_object: obj_path.to_str().expect("utf-8").to_string(),
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
    assert_eq!(result.exit_code, 3, "{}", result.diagnostic);
    assert!(
        !result
            .diagnostic
            .starts_with("journal_profile_not_admitted"),
        "journal refused a matching admission: {}",
        result.diagnostic
    );
    assert!(
        result.diagnostic.starts_with("cannot load profiles"),
        "ordinary stage did not surface: {}",
        result.diagnostic
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dispatch_mixed_unadmitted_journal_refuses_first() {
    // Mixed request, unadmitted journal: the journal refusal
    // wins before the ordinary stage runs.
    let root = scratch("mixref");
    let out = root.join("cap");
    let opts = RecordOptions {
        output: out.to_str().expect("utf-8").to_string(),
        capabilities: "attempt-trace,conversion-journal".to_string(),
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
    assert_eq!(result.exit_code, 3, "{}", result.diagnostic);
    assert!(
        result
            .diagnostic
            .starts_with("journal_profile_not_admitted"),
        "{}",
        result.diagnostic
    );
    assert!(!writer.created);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dispatch_profile_edit_alone_never_admits() {
    // Flipping the status word without bindings (or with forged
    // bindings that match nothing live) still refuses: a profile
    // edit alone is not admission.
    let root = scratch("edit");
    let flipped =
        candidate_body().replacen("\"status\": \"unadmitted\"", "\"status\": \"admitted\"", 1);
    write_profile(&root, "linux-7.0.14-x86-journal-provisional.json", &flipped);
    let out = root.join("cap");
    let run = || {
        let opts = RecordOptions {
            output: out.to_str().expect("utf-8").to_string(),
            capabilities: "conversion-journal".to_string(),
            ..Default::default()
        };
        let mut writer = MemWriter::new();
        let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
        assert!(!writer.created);
        result
    };
    let edited = run();
    assert_eq!(edited.exit_code, 3);
    assert_eq!(edited.diagnostic, "journal_profile_not_admitted");
    assert!(!edited.fix.is_empty());
    let forged = admitted_body(
        &"00".repeat(32),
        &"11".repeat(32),
        &"22".repeat(32),
        "forged-arch",
        1,
    );
    write_profile(&root, "linux-7.0.14-x86-journal-provisional.json", &forged);
    let forged_out = run();
    assert_eq!(forged_out.exit_code, 3);
    assert_eq!(forged_out.diagnostic, "journal_profile_not_admitted");
    assert!(!forged_out.fix.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dispatch_evidence_mismatch_matrix() {
    // Admitted status with exactly one rebound leg wrong refuses
    // on every leg: config, BTF, object, architecture, page size.
    // Each refusal names its leg in the fix line.
    let Some((_release, arch, pages, config, btf)) = live_bindings() else {
        eprintln!("skip: live config/BTF unmeasurable on this host");
        return;
    };
    let root = scratch("mm");
    let (obj_path, obj_sha) = garbage_object(&root);
    let wrong = "ff".repeat(32);
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "config",
            admitted_body(&wrong, &btf, &obj_sha, &arch, pages),
            "config",
        ),
        (
            "btf",
            admitted_body(&config, &wrong, &obj_sha, &arch, pages),
            "btf",
        ),
        (
            "object",
            admitted_body(&config, &btf, &wrong, &arch, pages),
            "object",
        ),
    ];
    for (leg, body, fix_word) in cases {
        write_profile(&root, "linux-7.0.14-x86-journal-provisional.json", &body);
        let out = root.join(format!("cap-{leg}"));
        let opts = RecordOptions {
            output: out.to_str().expect("utf-8").to_string(),
            capabilities: "conversion-journal".to_string(),
            journal_object: obj_path.to_str().expect("utf-8").to_string(),
            ..Default::default()
        };
        let mut writer = MemWriter::new();
        let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
        assert_eq!(result.exit_code, 3, "{leg}: {}", result.diagnostic);
        assert_eq!(result.diagnostic, "journal_profile_not_admitted", "{leg}");
        assert!(
            result.fix.contains(fix_word),
            "{leg} fix names no leg: {}",
            result.fix
        );
        assert!(!writer.created, "{leg} created output");
    }
    // Architecture and page size bind from the same carried
    // profile fields the live host must match.
    let wrong_arch = if arch == "aarch64" {
        "x86_64"
    } else {
        "aarch64"
    };
    let arch_body = admitted_body(&config, &btf, &obj_sha, wrong_arch, pages);
    write_profile(
        &root,
        "linux-7.0.14-x86-journal-provisional.json",
        &arch_body,
    );
    let out = root.join("cap-arch");
    let opts = RecordOptions {
        output: out.to_str().expect("utf-8").to_string(),
        capabilities: "conversion-journal".to_string(),
        journal_object: obj_path.to_str().expect("utf-8").to_string(),
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
    assert_eq!(result.exit_code, 3);
    assert_eq!(result.diagnostic, "journal_profile_not_admitted");
    assert!(result.fix.contains("architecture"), "fix: {}", result.fix);
    let wrong_pages = if pages == 8192 { 4096 } else { 8192 };
    let page_body = admitted_body(&config, &btf, &obj_sha, &arch, wrong_pages);
    write_profile(
        &root,
        "linux-7.0.14-x86-journal-provisional.json",
        &page_body,
    );
    let out = root.join("cap-page");
    let opts = RecordOptions {
        output: out.to_str().expect("utf-8").to_string(),
        capabilities: "conversion-journal".to_string(),
        journal_object: obj_path.to_str().expect("utf-8").to_string(),
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
    assert_eq!(result.exit_code, 3);
    assert_eq!(result.diagnostic, "journal_profile_not_admitted");
    assert!(result.fix.contains("page"), "fix: {}", result.fix);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn matrix_mixed_collection_uses_both_sources() {
    // Mixed ordinary/journal run: the ordinary session opens,
    // polls, detaches, and closes while the journal prepares,
    // attaches, emits one record, detaches, and releases.
    let mut collector = Collector::new(mixed_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = StepSignal::quiet();
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 0, "{}", result.diagnostic);
    assert!(writer.finalized);
    for want in ["open", "load", "detach"] {
        assert!(
            kernel.calls.iter().any(|call| call == want),
            "ordinary {want} missing: {:?}",
            kernel.calls
        );
    }
    for want in ["prepare", "attach", "detach", "release"] {
        assert!(
            journal.calls.iter().any(|call| call == want),
            "journal {want} missing: {:?}",
            journal.calls
        );
    }
    // The ordinary side adds its own closing lines; exactly one
    // persisted line carries journal data.
    let mut journal_lines = 0;
    for line in &writer.lines {
        if !line
            .windows(b"transition_result".len())
            .any(|window| window == b"transition_result")
        {
            continue;
        }
        let event = parse_event(line).expect("journal line parses");
        assert!(event.has_journal);
        journal_lines += 1;
        assert_eq!(event.journal.requested_bytes.value, 12288);
    }
    assert_eq!(journal_lines, 1);
    let session = parse_session(&writer.session_bytes).expect("session parses");
    assert!(session.has_journal);
    assert_eq!(session.journal.counters[0].value, 1);
}

#[test]
fn matrix_attach_failure_refuses_cleanly() {
    // Journal-only attach failure with a clean rollback refuses
    // with the bare reason: no residual, no close detail.
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    journal.attach_fail = true;
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = StepSignal::quiet();
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 3, "{}", result.diagnostic);
    assert_eq!(result.outcome, "refused");
    assert_eq!(result.diagnostic, "journal attach failed");
    assert!(
        journal.calls.iter().any(|call| call == "release"),
        "rollback close skipped: {:?}",
        journal.calls
    );
    assert!(!writer.finalized);
}

#[test]
fn matrix_journal_only_refusal_carries_rollback_detail() {
    // Journal-only refusal with a failed rollback reports
    // refusal-rollback-failed with the writer residual and the
    // close detail, like the ordinary refusal path.
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    journal.attach_fail = true;
    journal.close_fail = true;
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = StepSignal::quiet();
    let mut writer = MemWriter::new();
    writer.residual = "scripted residual".to_string();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, EXIT_ERROR, "{}", result.diagnostic);
    assert_eq!(result.outcome, "refusal-rollback-failed");
    assert_eq!(
        result.diagnostic,
        "journal attach failed; writer residual: scripted residual; close: scripted close"
    );
}

#[test]
fn matrix_control_write_failure_refuses() {
    // A failed readiness control write refuses before any
    // record can flow.
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    journal.control_fail = true;
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = StepSignal::quiet();
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 3, "{}", result.diagnostic);
    assert_eq!(result.outcome, "refused");
    assert_eq!(result.diagnostic, "journal readiness control failed");
    assert!(writer.lines.is_empty());
}

#[test]
fn matrix_read_failure_goes_error_path() {
    // A failed ring read takes the error path: exit 1 with the
    // error outcome after the close sequence runs.
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    journal.poll_fail = true;
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = StepSignal::quiet();
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, EXIT_ERROR, "{}", result.diagnostic);
    assert_eq!(result.outcome, "error");
    assert!(
        journal.calls.iter().any(|call| call == "detach"),
        "close sequence skipped: {:?}",
        journal.calls
    );
}

#[test]
fn matrix_write_failure_marks_unfinalizable() {
    // A fatal writer failure during the journal poll marks the
    // run unfinalizable: exit 1, events kept, no session.
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = StepSignal::quiet();
    let mut writer = MemWriter::new();
    writer.fail_append_at = 1;
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, EXIT_ERROR, "{}", result.diagnostic);
    assert_eq!(result.outcome, "unfinalizable");
    assert_eq!(writer.discards, 1);
    assert!(!writer.finalized);
}

#[test]
fn matrix_stop_signal_closes_journal_run() {
    // A stop arriving mid-run latches the signal stop and still
    // finalizes: the partial prefix is honest output.
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = StepSignal::new(3);
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 0, "{}", result.diagnostic);
    assert_eq!(result.end_reason, "signal");
    assert!(writer.finalized);
    let session = parse_session(&writer.session_bytes).expect("session parses");
    // The latch survives in end_reason; the session stop reason
    // carries the journal closure assessment instead.
    assert_eq!(
        session.stop.reason,
        "Journal closure unproved; quiet transport is not synchronization."
    );
    assert!(session.has_journal);
}

#[test]
fn matrix_duration_timeout_closes_journal_run() {
    // A zero duration budget times out before any record: the
    // empty prefix still finalizes with the duration stop.
    let mut cfg = journal_only_config();
    cfg.duration_s = 0;
    let mut collector = Collector::new(cfg);
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = StepSignal::quiet();
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 0, "{}", result.diagnostic);
    assert_eq!(result.end_reason, "duration");
    assert!(writer.lines.is_empty());
    assert!(writer.finalized);
    let session = parse_session(&writer.session_bytes).expect("session parses");
    assert_eq!(
        session.stop.reason,
        "Journal closure unproved; quiet transport is not synchronization."
    );
}

#[test]
fn matrix_initial_and_open_checkpoints() {
    // The readiness checkpoint carries the initial admission
    // state, a mid-run checkpoint the open state, and the final
    // session the closed state, all in the frozen fixture
    // vocabulary (not_opened / admission_open).
    let mut cfg = journal_only_config();
    cfg.duration_s = 30;
    let mut collector = Collector::new(cfg);
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    let mut clock = ScriptClock::new(1_000_000_000, 1_000_000_000);
    let mut signal = StepSignal::quiet();
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 0, "{}", result.diagnostic);
    assert!(
        writer.checkpoints.len() >= 2,
        "want initial + open checkpoints, got {}",
        writer.checkpoints.len()
    );
    let initial = parse_session(&writer.checkpoints[0]).expect("initial parses");
    assert_eq!(initial.stop.outcome, "partial");
    assert!(!initial.journal.admission_start_ns.has);
    assert_eq!(initial.journal.admission_start_reason, "not_opened");
    assert_eq!(initial.journal.admission_end_reason, "not_opened");
    let open = parse_session(&writer.checkpoints[1]).expect("open parses");
    assert!(open.journal.admission_start_ns.has);
    assert!(open.journal.admission_start_reason.is_empty());
    assert!(!open.journal.admission_end_ns.has);
    assert_eq!(open.journal.admission_end_reason, "admission_open");
    let session = parse_session(&writer.session_bytes).expect("session parses");
    assert!(session.journal.admission_start_ns.has);
    assert!(session.journal.admission_end_ns.has);
    assert!(session.journal.admission_end_reason.is_empty());
}

#[test]
fn matrix_writer_reader_roundtrip() {
    // A journal-only run through the real file writer produces
    // an events file and a session file that both parse: every
    // persisted line validates and the session carries the
    // journal block with the emitted counter.
    let root = scratch("rr");
    let out = root.join("cap");
    let mut cfg = journal_only_config();
    cfg.output = out.to_str().expect("utf-8").to_string();
    let mut collector = Collector::new(cfg);
    let mut kernel = ScriptKernel::new();
    let mut journal = MatrixJournal::new();
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = StepSignal::quiet();
    let mut writer = LiveWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 0, "{}", result.diagnostic);
    let events = std::fs::read(out.join("events.ndjson")).expect("events file");
    let text = String::from_utf8(events).expect("events UTF-8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let event = parse_event(lines[0].as_bytes()).expect("event parses");
    assert!(event.has_journal);
    assert_eq!(event.journal.requested_bytes.value, 12288);
    let session_bytes = std::fs::read(out.join("session.json")).expect("session file");
    let session = parse_session(&session_bytes).expect("session parses");
    assert!(session.has_journal);
    assert!(session.has_integrity);
    assert_eq!(session.journal.counters[0].value, 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn guest_verifier_accepts_journal_object() {
    // Lease-gated: the built journal object loads on the
    // isolated guest kernel, so its verifier accepts the
    // program. Without a lease this self-skips with a receipt.
    let Some((user, host, port)) = lease_ssh() else {
        return;
    };
    let Some(elf) = built_journal_object() else {
        eprintln!("guest leg skipped: no built journal object; run cargo build first");
        return;
    };
    assert!(!elf.is_empty());
    let stage = scratch("g1");
    let local = stage.join("memveil-ebpf-journal");
    std::fs::write(&local, &elf).expect("stage object");
    let remote = "/tmp/memveil-journal-matrix.o";
    scp_to(&user, &host, &port, local.to_str().expect("utf-8"), remote);
    let out = ssh_run(
        &user,
        &host,
        &port,
        "timeout 120 sudo bpftool prog load /tmp/memveil-journal-matrix.o /sys/fs/bpf/mvjr-matrix 2>&1; code=$?; sudo rm -f /sys/fs/bpf/mvjr-matrix /tmp/memveil-journal-matrix.o; echo GUEST_RC=$code",
    );
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    eprintln!("guest verifier output: {text}");
    assert!(
        text.contains("GUEST_RC=0"),
        "guest verifier rejected the journal object: {text}"
    );
    let _ = std::fs::remove_dir_all(&stage);
}

#[test]
fn guest_end_to_end_attach_oracle_detach() {
    // Lease-gated: the lane binary records a short journal-only
    // capture on the isolated guest under a test-minted admitted
    // profile (nonqualifying harness; the profile binds the
    // guest's own live config/BTF/object measurements and is
    // never shipped). The oracle verdict covers attach (four
    // tracing links observed mid-run), record validity, and
    // clean detach (no residual links). Without a lease this
    // self-skips with a receipt.
    let Some((user, host, port)) = lease_ssh() else {
        return;
    };
    let Some(elf) = built_journal_object() else {
        eprintln!("guest leg skipped: no built journal object; run cargo build first");
        return;
    };
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary = root.join("target").join("debug").join("memveil");
    assert!(binary.is_file(), "run cargo build first");
    let stage = scratch("g2");
    let obj = stage.join("memveil-ebpf-journal");
    std::fs::write(&obj, &elf).expect("stage object");
    scp_to(
        &user,
        &host,
        &port,
        binary.to_str().expect("utf-8"),
        "/tmp/mv-matrix-memveil",
    );
    scp_to(
        &user,
        &host,
        &port,
        obj.to_str().expect("utf-8"),
        "/tmp/mv-matrix-journal.o",
    );
    let mint = r#"
import gzip, hashlib, json, os
cfg_src = ""
if os.path.exists("/proc/config.gz"):
    raw = open("/proc/config.gz", "rb").read()
    cfg_src = "gz"
    cfg = hashlib.sha256(gzip.decompress(raw)).hexdigest()
else:
    rel = open("/proc/sys/kernel/osrelease").read().strip()
    raw = open("/boot/config-" + rel, "rb").read()
    cfg_src = "file"
    cfg = hashlib.sha256(raw).hexdigest()
btf = hashlib.sha256(open("/sys/kernel/btf/vmlinux", "rb").read()).hexdigest()
obj = hashlib.sha256(open("/tmp/mv-matrix-journal.o", "rb").read()).hexdigest()
arch = os.uname().machine
pages = str(os.sysconf("SC_PAGE_SIZE"))
prof = {
    "contract": "memveil-journal-profile/1",
    "profile_id": "linux-7.0.14-x86-journal-provisional",
    "status": "admitted",
    "evidence_class": "source_reviewed_provisional",
    "linux_commit": "458c6079fc1d41d564c37679c8ace02cd83ee817",
    "architecture": arch,
    "page_size": pages,
    "transient_key": {"fields": ["current_task_pointer"], "helper": "bpf_get_current_task_btf",
                      "btf_field": "task_struct.start_boottime:u64", "read": "bounded",
                      "persistence": "none", "loss_rule": "test"},
    "source_files": [],
    "config_sha256": cfg,
    "btf_sha256": btf,
    "object_sha256": obj,
    "required_config": [],
    "required_btf": "test",
    "hooks": ["fentry/set_memory_decrypted"],
    "native_result": "test",
    "effect": "request_only",
    "caller_labels": {"a": "owned"},
    "admission_required": ["exact_config_btf_object"],
}
os.makedirs("/tmp/mv-matrix-profiles/journal-candidates", exist_ok=True)
json.dump(prof, open("/tmp/mv-matrix-profiles/journal-candidates/linux-7.0.14-x86-journal-provisional.json", "w"))
print("MINTED src=" + cfg_src)
"#;
    let out = ssh_run(
        &user,
        &host,
        &port,
        &format!("timeout 60 python3 -c {mint:?}"),
    );
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "guest mint failed: {text}");
    assert!(text.contains("MINTED"), "guest mint failed: {text}");
    let run = "BASE=$(sudo bpftool link show 2>/dev/null | grep -c tracing || true); \
BASE=${BASE:-0}; \
timeout 120 sudo /tmp/mv-matrix-memveil record --output /tmp/mv-matrix-cap \
--capability conversion-journal --duration 4 \
--journal-object /tmp/mv-matrix-journal.o \
--profiles-dir /tmp/mv-matrix-profiles > /tmp/mv-matrix-run.log 2>&1 & \
CAP_PID=$!; PEAK=0; \
for i in $(seq 1 30); do \
  if ! kill -0 $CAP_PID 2>/dev/null; then break; fi; \
  N=$(sudo bpftool link show 2>/dev/null | grep -c tracing || true); \
  N=${N:-0}; \
  if [ \"$N\" -gt \"$PEAK\" ]; then PEAK=$N; fi; \
  sleep 0.2; \
done; \
wait $CAP_PID; RC=$?; echo GUEST_RC=$RC BASE_LINKS=$BASE PEAK_LINKS=$PEAK; \
sudo chmod -R a+r /tmp/mv-matrix-cap 2>/dev/null; \
cat /tmp/mv-matrix-run.log";
    let out = ssh_run(&user, &host, &port, run);
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    eprintln!("guest end-to-end output: {text}");
    assert!(text.contains("GUEST_RC=0"), "guest capture failed: {text}");
    let base = text
        .split("BASE_LINKS=")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .and_then(|raw| raw.parse::<i64>().ok())
        .expect("baseline link count");
    let peak = text
        .split("PEAK_LINKS=")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .and_then(|raw| raw.parse::<i64>().ok())
        .expect("peak link count");
    assert_eq!(
        peak,
        base + 4,
        "guest attach did not add four tracing links: {text}"
    );
    let verify = r#"
import json
sess = json.load(open("/tmp/mv-matrix-cap/session.json"))
j = sess.get("journal", {})
counters = j.get("counters", {})
print("ORACLE has_journal=%s closure=%s entries=%s drops=%s invalid=%s missed=%s" % (
    "journal" in sess, j.get("closure"), counters.get("entries"),
    counters.get("ring_drops"), counters.get("invalid_records"),
    counters.get("missed_callbacks")))
lines = [line for line in open("/tmp/mv-matrix-cap/events.ndjson").read().splitlines() if line.strip()]
print("ORACLE events=%d" % len(lines))
"#;
    let out = ssh_run(
        &user,
        &host,
        &port,
        &format!("timeout 60 python3 -c {verify:?}"),
    );
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    eprintln!("guest oracle output: {text}");
    assert!(
        text.contains("ORACLE has_journal=True"),
        "no journal block: {text}"
    );
    let out = ssh_run(
        &user,
        &host,
        &port,
        "timeout 60 sudo bpftool link show 2>/dev/null | grep -c tracing || true; rm -rf /tmp/mv-matrix-cap /tmp/mv-matrix-run.log /tmp/mv-matrix-profiles /tmp/mv-matrix-memveil /tmp/mv-matrix-journal.o",
    );
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let after = text.parse::<i64>().unwrap_or(-1);
    assert_eq!(after, base, "residual tracing links after detach: {text}");
    eprintln!("guest oracle: attach +4 links mid-run, detach clean, session verified");
    let _ = std::fs::remove_dir_all(&stage);
}
