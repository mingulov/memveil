// SPDX-License-Identifier: GPL-3.0-or-later
//! Session loader + event flow: geometry gates over the three per-channel
//! ELFs, offsets install, arm/disarm, attach order with rollback, and the
//! live smoke.
//!
//! Unprivileged tests run on every `cargo test`. Live tests need
//! `MEMVEIL_TEST_BPF_LIVE=1` plus privilege (object load and attach issue
//! privileged syscalls); without the variable they print a SKIP reason and
//! return. Run the live subset by building with
//! `cargo test --test bpf_session --no-run` (it prints the test binary's
//! `Executable` path) and then invoking that binary directly under sudo,
//! e.g. `sudo env MEMVEIL_TEST_BPF_LIVE=1 <binary> --test-threads=1`.
//!
//! The live environment cannot synthesize DMA bounce activity (no IOMMU-less
//! device, no force knob, and the oracle kernel module loads only inside the
//! disposable VM gate), so the record-receipt assertions are conditional on
//! the kernel-side `mv_counts` observed counter: zero observed means the
//! window was silent and the test SKIPs loudly; nonzero observed with no
//! decoded frame FAILS. Silence and breakage are never confused.
//!
//! Copy-table resolution needs no privilege but does need a supported host:
//! tests using it SKIP loudly when kernel BTF is unreadable or when the
//! kernel carries a half-present private-pool chain, which the loader
//! refuses instead of silently downgrading. Any other resolution failure
//! FAILS.

use memveil::bpf::{
    ATTACH_ORDER, AttachKind, AttachSpec, Channel, Channels, DETACH_ORDER, Frame, MapSpec,
    ProgramSpec, Session, attempt_specs, check_channel_geometry, copy_specs, lifecycle_specs,
    resolve_attempt_offsets, resolve_copy_offsets, sentinel_copy_offsets, validate_copy_offsets,
};
use memveil_ebpf_common::{CopyOffsets, MV_FLAG_BYTE_COVERAGE, decode_offsets_table};

/// ELF `e_machine` for BPF objects (`EM_BPF`).
const EM_BPF: u16 = 247;

/// Live-gate variable: live tests run only when it equals `"1"`.
const LIVE_VAR: &str = "MEMVEIL_TEST_BPF_LIVE";

/// True when the live subset is requested.
fn live_enabled() -> bool {
    std::env::var(LIVE_VAR).as_deref() == Ok("1")
}

/// Read one channel ELF from its `build.rs`-published path.
fn channel_bytes(channel: Channel) -> Vec<u8> {
    let path = match channel {
        Channel::Attempt => env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH"),
        Channel::Lifecycle => env!("DEP_MEMVEIL_EBPF_LIFECYCLE_PATH"),
        Channel::Copy => env!("DEP_MEMVEIL_EBPF_COPY_PATH"),
    };
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("read {channel:?} ELF at {path:?}: {error}"));
    assert_eq!(
        bytes.get(..4),
        Some(b"\x7fELF".as_slice()),
        "{channel:?} ELF at {path:?} must start with the ELF magic"
    );
    let machine = bytes
        .get(18..20)
        .map(|window| u16::from_le_bytes([window[0], window[1]]));
    assert_eq!(
        machine,
        Some(EM_BPF),
        "{channel:?} ELF at {path:?} must be a BPF object (e_machine {EM_BPF})"
    );
    bytes
}

/// Convert an `aya-obj` parse into loader-owned geometry specs.
fn lib_specs(object: &aya_obj::Object) -> (Vec<ProgramSpec>, Vec<MapSpec>) {
    let mut programs: Vec<ProgramSpec> = object
        .programs
        .iter()
        .map(|(name, program)| {
            let (kind, sleepable) = match &program.section {
                aya_obj::ProgramSection::TracePoint => (AttachKind::Tracepoint, false),
                aya_obj::ProgramSection::FEntry { sleepable } => (AttachKind::FEntry, *sleepable),
                aya_obj::ProgramSection::FExit { sleepable } => (AttachKind::FExit, *sleepable),
                other => panic!("program {name} has unexpected section {other:?}"),
            };
            ProgramSpec {
                name: name.clone(),
                kind,
                sleepable,
            }
        })
        .collect();
    programs.sort_by(|a, b| a.name.cmp(&b.name));
    let mut maps: Vec<MapSpec> = object
        .maps
        .iter()
        .map(|(name, map)| MapSpec {
            name: name.clone(),
            map_type: map.map_type(),
            key_size: map.key_size(),
            value_size: map.value_size(),
            max_entries: map.max_entries(),
        })
        .collect();
    maps.sort_by(|a, b| a.name.cmp(&b.name));
    (programs, maps)
}

/// Check one channel ELF against the frozen loader geometry.
fn check_elf(channel: Channel) {
    let bytes = channel_bytes(channel);
    let object = aya_obj::Object::parse(&bytes)
        .unwrap_or_else(|error| panic!("aya-obj must parse the {channel:?} ELF: {error}"));
    let (programs, maps) = lib_specs(&object);
    check_channel_geometry(channel, &programs, &maps)
        .unwrap_or_else(|error| panic!("{channel:?} ELF must match frozen geometry: {error}"));
}

#[test]
fn geometry_attempt_matches_frozen() {
    check_elf(Channel::Attempt);
}

#[test]
fn geometry_lifecycle_matches_frozen() {
    check_elf(Channel::Lifecycle);
}

#[test]
fn geometry_copy_matches_frozen() {
    check_elf(Channel::Copy);
}

fn le16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|window| u16::from_le_bytes([window[0], window[1]]))
}

fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|window| u32::from_le_bytes([window[0], window[1], window[2], window[3]]))
}

fn le64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|window| {
        u64::from_le_bytes([
            window[0], window[1], window[2], window[3], window[4], window[5], window[6], window[7],
        ])
    })
}

/// File range of the named ELF section.
fn section_range(bytes: &[u8], want: &str) -> (usize, usize) {
    let (Some(shoff), Some(shentsize), Some(shnum), Some(shstrndx)) = (
        le64(bytes, 0x28),
        le16(bytes, 0x3a),
        le16(bytes, 0x3c),
        le16(bytes, 0x3e),
    ) else {
        panic!("ELF header too short for the section table");
    };
    assert!(shentsize >= 64, "section entries must be 64 bytes");
    let shstr = (shoff + u64::from(shstrndx) * 64) as usize;
    let (Some(str_off), Some(str_len)) = (
        le64(bytes, shstr + 24).map(|value| value as usize),
        le64(bytes, shstr + 32).map(|value| value as usize),
    ) else {
        panic!("section-name table header is truncated");
    };
    let strtab = bytes
        .get(str_off..str_off.saturating_add(str_len))
        .expect("section-name table is truncated");
    for index in 0..shnum {
        let header = (shoff + u64::from(index) * 64) as usize;
        let name_off = le32(bytes, header).expect("section header is truncated") as usize;
        let tail = strtab.get(name_off..).unwrap_or_default();
        let end = tail.iter().position(|byte| *byte == 0).unwrap_or(0);
        if &tail[..end] == want.as_bytes() {
            let off = le64(bytes, header + 24).expect("section offset truncated") as usize;
            let len = le64(bytes, header + 32).expect("section size truncated") as usize;
            return (off, len);
        }
    }
    panic!("ELF has no {want} section");
}

/// Patch the single occurrence of one little-endian `u32` value inside the
/// `maps` section. The uniqueness assertion keeps the tamper targeted: a
/// value appearing twice would be an ambiguous patch, not a gate proof.
fn tamper_map_u32(bytes: &[u8], old: u32, new: u32) -> Vec<u8> {
    let (off, len) = section_range(bytes, "maps");
    let section = bytes.get(off..off + len).expect("maps section truncated");
    let needle = old.to_le_bytes();
    let hits: Vec<usize> = (0..section.len().saturating_sub(3))
        .filter(|at| section[*at..*at + 4] == needle)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "tamper value {old:#x} must occur exactly once in the maps section, found {}",
        hits.len()
    );
    let mut out = bytes.to_vec();
    out[off + hits[0]..off + hits[0] + 4].copy_from_slice(&new.to_le_bytes());
    out
}

/// The tampered object must still parse (else the test proves nothing about
/// the gate) and then fail the geometry check naming the tampered map.
fn assert_tamper_rejected(channel: Channel, old: u32, new: u32, map: &str) {
    let bytes = channel_bytes(channel);
    let tampered = tamper_map_u32(&bytes, old, new);
    let object = aya_obj::Object::parse(&tampered)
        .expect("tampered ELF must still parse so the gate does the refusing");
    let (programs, maps) = lib_specs(&object);
    let error = check_channel_geometry(channel, &programs, &maps)
        .expect_err("tampered geometry must be rejected");
    let message = error.to_string();
    assert!(
        message.contains(map),
        "rejection must name the tampered map {map}, got: {message}"
    );
}

#[test]
fn geometry_rejects_tampered_attempt_ring() {
    assert_tamper_rejected(Channel::Attempt, 8_388_608, 8_388_609, "mv_attempts");
}

#[test]
fn geometry_rejects_tampered_table_sizes() {
    assert_tamper_rejected(Channel::Attempt, 24, 25, "mv_offsets");
    assert_tamper_rejected(Channel::Copy, 112, 113, "mv_copy_offs");
}

#[test]
fn open_rejects_garbage() {
    assert!(Session::open(&[0u8; 64], "mv_attempts").is_err());
    assert!(Session::open(b"definitely not an ELF object", "mv_attempts").is_err());
    let bytes = channel_bytes(Channel::Attempt);
    assert!(Session::open(&bytes[..32], "mv_attempts").is_err());
    assert!(Session::open(&bytes, "mv_no_such_ring").is_err());
    // A valid ELF for the wrong channel is refused at open: the copy object
    // carries no tracepoint section.
    let copy = channel_bytes(Channel::Copy);
    let error = Session::open(&copy, "mv_attempts").expect_err("wrong-channel ELF must be refused");
    assert!(
        error.to_string().contains("tracepoint"),
        "wrong-channel refusal must name the missing section, got: {error}"
    );
}

#[test]
fn frozen_specs_pinned() {
    let attempt = attempt_specs("swiotlb", "swiotlb_bounced");
    assert_eq!(attempt.len(), 1);
    assert_eq!(attempt[0].program, "mv_swiotlb_attempt");
    assert!(matches!(
        attempt[0].kind,
        memveil::bpf::AttachKind::Tracepoint
    ));
    assert_eq!(attempt[0].target_a, "swiotlb");
    assert_eq!(attempt[0].target_b, "swiotlb_bounced");
    let lifecycle = lifecycle_specs();
    let names: Vec<&str> = lifecycle.iter().map(|spec| spec.program.as_str()).collect();
    assert_eq!(names, ["mv_map_result", "mv_unmap"]);
    assert!(matches!(lifecycle[0].kind, memveil::bpf::AttachKind::FExit));
    assert_eq!(lifecycle[0].target_a, "swiotlb_tbl_map_single");
    assert!(matches!(
        lifecycle[1].kind,
        memveil::bpf::AttachKind::FEntry
    ));
    assert_eq!(lifecycle[1].target_a, "__swiotlb_tbl_unmap_single");
    let copy = copy_specs();
    let names: Vec<&str> = copy.iter().map(|spec| spec.program.as_str()).collect();
    assert_eq!(
        names,
        [
            "mv_bounce",
            "mv_bounce_exit",
            "mv_sync_device",
            "mv_sync_cpu"
        ]
    );
    // Bounce entry precedes exit; the sync hooks follow.
    assert!(matches!(copy[0].kind, memveil::bpf::AttachKind::FEntry));
    assert_eq!(copy[0].target_a, "swiotlb_bounce");
    assert!(matches!(copy[1].kind, memveil::bpf::AttachKind::FExit));
    assert_eq!(copy[1].target_a, "swiotlb_bounce");
    assert_eq!(copy[2].target_a, "__swiotlb_sync_single_for_device");
    assert_eq!(copy[3].target_a, "__swiotlb_sync_single_for_cpu");
    for spec in lifecycle.iter().chain(copy.iter()) {
        assert!(
            spec.target_b.is_empty(),
            "tracing specs carry no second target, got {:?} for {}",
            spec.target_b,
            spec.program
        );
    }
}

#[test]
fn channel_orders_pinned() {
    assert_eq!(
        ATTACH_ORDER,
        [Channel::Copy, Channel::Lifecycle, Channel::Attempt]
    );
    assert_eq!(
        DETACH_ORDER,
        [Channel::Attempt, Channel::Lifecycle, Channel::Copy]
    );
}

#[test]
fn attempt_offsets_resolve_live() {
    // The tracefs format file needs privilege on this host; the pinned and
    // drifted layouts are covered unprivileged by the loader unit tests.
    if !live_enabled() {
        eprintln!(
            "SKIP attempt_offsets_resolve_live: set MEMVEIL_TEST_BPF_LIVE=1 and run privileged"
        );
        return;
    }
    let resolved = resolve_attempt_offsets().expect("live tracefs format must resolve");
    let table = decode_offsets_table(&resolved.table).expect("resolved table must decode");
    eprintln!(
        "attempt offsets: loc={} size={} force={} fixed_end={} moved={}",
        table.loc_off, table.size_off, table.force_off, table.fixed_end, resolved.moved
    );
    // The probe trusts magic/version only; extents were validated at resolve.
    assert_eq!(&resolved.table[..4], &0x35464D4Du32.to_le_bytes());
}

/// Resolve the live copy table for `test`, or skip it loudly when the
/// host cannot resolve by design: no readable kernel BTF, or a
/// half-present private-pool chain (exactly one of
/// `device.dma_io_tlb_mem` / `io_tlb_mem.cc_shared` exists), which the
/// loader refuses instead of silently downgrading. Any other failure is
/// a real regression and panics.
fn live_copy_table_or_skip(test: &str) -> Option<CopyOffsets> {
    match resolve_copy_offsets() {
        Ok(table) => Some(table),
        Err(error) => {
            // Path mirrors the loader's `KERNEL_BTF`.
            if std::fs::File::open("/sys/kernel/btf/vmlinux").is_err() {
                eprintln!("SKIP {test}: no readable /sys/kernel/btf/vmlinux ({error})");
                return None;
            }
            if error.to_string().contains("half-present") {
                eprintln!(
                    "SKIP {test}: host kernel has a half-present private-pool chain, which the loader refuses ({error})"
                );
                return None;
            }
            panic!("{test}: live kernel BTF must resolve: {error}");
        }
    }
}

#[test]
fn copy_offsets_resolve_live_btf() {
    let Some(table) = live_copy_table_or_skip("copy_offsets_resolve_live_btf") else {
        return;
    };
    validate_copy_offsets(&table).expect("resolved table must validate");
    eprintln!(
        "copy offsets: pool={}/{}/{} slots={} slot_size={} parms={} mask={} flags={:#x} dir={}/{}/{}",
        table.pool_start_off,
        table.pool_end_off,
        table.pool_nslabs_off,
        table.pool_slots_off,
        table.slot_size,
        table.dev_parms_off,
        table.mask_off,
        table.flags,
        table.dir_to,
        table.dir_from,
        table.dir_bidi
    );
    // Structural properties hold on every kernel: the 8 probe widths, the
    // stride fitting both slot extents, distinct enumerators, and a
    // private-pool quartet consistent with the flag.
    assert_eq!(table.pool_start_size, 8);
    assert_eq!(table.pool_end_size, 8);
    assert_eq!(table.pool_nslabs_size, 8);
    assert_eq!(table.pool_slots_size, 8);
    assert_eq!(table.slot_orig_size, 8);
    assert_eq!(table.slot_alloc_size, 8);
    assert_eq!(table.dev_parms_size, 8);
    assert_eq!(table.mask_size, 4);
    assert!(table.slot_size >= 16);
    assert_ne!(table.dir_to, table.dir_from);
    assert_ne!(table.dir_to, table.dir_bidi);
    assert_ne!(table.dir_from, table.dir_bidi);
    // Exact pins, verified against an independent BTF walk on this kernel
    // only; other kernels keep the structural checks above plus a loud note.
    let release = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_default();
    if release == "7.2.13-200.fc44.x86_64" {
        assert_eq!(table.flags, 0, "no cc_shared on this kernel");
        assert_eq!(
            (
                table.pool_start_off,
                table.pool_end_off,
                table.pool_nslabs_off,
                table.pool_slots_off
            ),
            (0, 8, 24, 56)
        );
        assert_eq!((table.slot_orig_off, table.slot_alloc_off), (0, 8));
        assert_eq!(table.slot_size, 24);
        assert_eq!(table.dev_parms_off, 640);
        assert_eq!(table.mask_off, 4);
        assert_eq!((table.dir_to, table.dir_from, table.dir_bidi), (1, 2, 0));
    } else {
        eprintln!(
            "NOTE: exact copy-offsets pins verified on 7.2.13 only; live kernel is {release}"
        );
    }
}

#[test]
fn sentinel_copy_offsets_refused() {
    let sentinel = sentinel_copy_offsets();
    assert_ne!(
        sentinel.magic,
        memveil_ebpf_common::MV_COPY_OFFS_MAGIC,
        "sentinel must fail the probe trust check"
    );
    validate_copy_offsets(&sentinel).expect_err("installer must refuse the sentinel");
}

/// Best-effort DMA stimulus for the poll window: direct-IO file traffic.
/// Returns after `rounds` of small reads/writes; never fails the test.
fn stir_io(rounds: u32) {
    for round in 0..rounds {
        let path = std::env::temp_dir().join(format!("memveil-bpf-stir-{round}"));
        let data = vec![round as u8; 1 << 20];
        if std::fs::write(&path, &data).is_ok() {
            let _ = std::fs::read(&path);
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Poll until `budget_ms` expires, stirring IO between rounds. Returns the
/// decoded frames plus the final counters.
fn poll_window(session: &mut Session, budget_ms: u32) -> (Vec<Frame>, [u64; 6]) {
    let mut frames = Vec::new();
    let start = std::time::Instant::now();
    let budget = std::time::Duration::from_millis(u64::from(budget_ms));
    while start.elapsed() < budget {
        match session.poll(500).expect("poll must not fail") {
            Some(frame) => frames.push(frame),
            None => stir_io(2),
        }
    }
    let counters = session.read_counters().expect("counters must read");
    (frames, counters)
}

#[test]
fn live_attempt_smoke() {
    if !live_enabled() {
        eprintln!("SKIP live_attempt_smoke: set MEMVEIL_TEST_BPF_LIVE=1 and run privileged");
        return;
    }
    let bytes = channel_bytes(Channel::Attempt);
    let mut session = Session::open(&bytes, "mv_attempts").expect("open");
    assert_eq!(session.channel(), Channel::Attempt);
    assert!(!session.is_loaded());
    session.load().expect("load");
    assert!(session.is_loaded());
    let info = session.map_info("mv_attempts").expect("ring map info");
    assert_eq!(info.max_entries, 8_388_608);
    let resolved = resolve_attempt_offsets().expect("resolve attempt offsets");
    session
        .install_offsets(&resolved.table)
        .expect("install offsets");
    let back = session
        .map_read("mv_offsets", 0, 24)
        .expect("read back offsets");
    assert_eq!(back.as_slice(), resolved.table.as_slice());
    session
        .attach(&attempt_specs("swiotlb", "swiotlb_bounced"))
        .expect("attach");
    assert!(session.attached());
    let (frames, counters) = poll_window(&mut session, 6_000);
    // counters: observed, observed_bytes, emitted, emitted_bytes,
    // submit_fail, flags.
    eprintln!(
        "attempt counters: observed={} emitted={} submit_fail={} flags={:#x} frames={}",
        counters[0],
        counters[2],
        counters[4],
        counters[5],
        frames.len()
    );
    assert_eq!(counters[4], 0, "valid table must never submit_fail");
    assert_eq!(counters[5], 0, "valid table must never raise flags");
    if counters[0] == 0 {
        eprintln!(
            "SKIP live_attempt_smoke records: kernel observed 0 firings in 6s; \
             this host performs no swiotlb DMA (IOMMU active, io_tlb_used=0)"
        );
    } else {
        assert_eq!(counters[2], counters[0], "every observed firing must emit");
        assert!(!frames.is_empty(), "observed firings must deliver frames");
        for frame in &frames {
            let Frame::Attempt(record) = frame else {
                panic!("attempt channel must only deliver attempt frames");
            };
            assert!(record.ktime > 0, "ktime must be sane");
        }
        let stats = session.stats();
        assert_eq!(stats.delivered as usize, frames.len());
        assert_eq!(stats.malformed, 0);
    }
    session.detach().expect("detach");
    assert!(!session.attached());
    session.close().expect("close");
    // close() is idempotent; further calls succeed.
    session.close().expect("second close");
}

#[test]
fn live_copy_install_and_armed() {
    if !live_enabled() {
        eprintln!(
            "SKIP live_copy_install_and_armed: set MEMVEIL_TEST_BPF_LIVE=1 and run privileged"
        );
        return;
    }
    let bytes = channel_bytes(Channel::Copy);
    let mut session = Session::open(&bytes, "mv_copies").expect("open");
    session.load().expect("load");
    let Some(table) = live_copy_table_or_skip("live_copy_install_and_armed") else {
        session.close().expect("close after skip");
        return;
    };
    session.install_copy_offsets(&table).expect("install");
    let back = session
        .map_read("mv_copy_offs", 0, 112)
        .expect("read back table");
    assert_eq!(back[..4], table.magic.to_le_bytes());
    assert_eq!(u16::from_le_bytes([back[4], back[5]]), table.version);
    // Armed slot roundtrip on key 3: exactly 1 arms the exit.
    let armed = |session: &mut Session| {
        session
            .map_read("mv_copy_fb", 3, 8)
            .expect("read armed slot")
    };
    assert_eq!(armed(&mut session).as_slice(), 0u64.to_le_bytes());
    session.set_copy_armed(true).expect("arm");
    assert_eq!(armed(&mut session).as_slice(), 1u64.to_le_bytes());
    let fb = session.read_copy_fb().expect("read fallback");
    assert_eq!(fb.len(), 3);
    session.set_copy_armed(false).expect("disarm");
    assert_eq!(armed(&mut session).as_slice(), 0u64.to_le_bytes());
    // The four tracing programs attach and detach cleanly; no events needed.
    session.attach(&copy_specs()).expect("attach");
    assert!(session.attached());
    session.detach().expect("detach");
    session.close().expect("close");
}

#[test]
fn live_attach_rollback_and_reattach() {
    if !live_enabled() {
        eprintln!(
            "SKIP live_attach_rollback_and_reattach: set MEMVEIL_TEST_BPF_LIVE=1 and run privileged"
        );
        return;
    }
    let mut attempt =
        Session::open(&channel_bytes(Channel::Attempt), "mv_attempts").expect("open attempt");
    let mut lifecycle =
        Session::open(&channel_bytes(Channel::Lifecycle), "mv_lifecycle").expect("open lifecycle");
    let mut copy = Session::open(&channel_bytes(Channel::Copy), "mv_copies").expect("open copy");
    attempt.load().expect("load attempt");
    lifecycle.load().expect("load lifecycle");
    copy.load().expect("load copy");
    let offsets = resolve_attempt_offsets().expect("resolve attempt offsets");
    attempt.install_offsets(&offsets.table).expect("install");
    let Some(table) = live_copy_table_or_skip("live_attach_rollback_and_reattach") else {
        attempt.close().expect("close attempt after skip");
        lifecycle.close().expect("close lifecycle after skip");
        copy.close().expect("close copy after skip");
        return;
    };
    copy.install_copy_offsets(&table).expect("install");
    let mut channels = Channels::new(attempt, Some(lifecycle), Some(copy));
    // Sabotage the last channel in attach order: the attempt attach must
    // fail and roll copy + lifecycle back to detached.
    let mut bad = attempt_specs("swiotlb", "swiotlb_bounced");
    bad[0] = AttachSpec::new(
        "mv_no_such_program",
        memveil::bpf::AttachKind::Tracepoint,
        "swiotlb",
        "swiotlb_bounced",
    );
    let error = channels
        .attach_all_with(&bad)
        .expect_err("sabotaged attach must fail");
    eprintln!("rollback refusal: {error}");
    assert!(!channels.copy_attached(), "copy must roll back");
    assert!(!channels.lifecycle_attached(), "lifecycle must roll back");
    assert!(!channels.attempt_attached(), "attempt must stay detached");
    // The good order attaches all three, detaches in reverse, and
    // re-attaches: detach leaves every session reusable.
    channels
        .attach_all("swiotlb", "swiotlb_bounced")
        .expect("attach all");
    assert!(channels.attempt_attached());
    assert!(channels.lifecycle_attached());
    assert!(channels.copy_attached());
    channels.detach_all().expect("detach all");
    assert!(!channels.attempt_attached());
    assert!(!channels.lifecycle_attached());
    assert!(!channels.copy_attached());
    channels
        .attach_all("swiotlb", "swiotlb_bounced")
        .expect("re-attach all");
    channels.detach_all().expect("final detach");
    channels.close_all().expect("close all");
}

#[test]
fn live_negative_corrupt_attempt_table() {
    if !live_enabled() {
        eprintln!(
            "SKIP live_negative_corrupt_attempt_table: set MEMVEIL_TEST_BPF_LIVE=1 and run privileged"
        );
        return;
    }
    let bytes = channel_bytes(Channel::Attempt);
    let mut session = Session::open(&bytes, "mv_attempts").expect("open");
    session.load().expect("load");
    // Pre-seed a corrupt table (bad magic) with a raw write: the installer
    // itself would refuse this, which is exactly the point.
    let mut corrupt = resolve_attempt_offsets().expect("resolve").table;
    corrupt[0] ^= 0xff;
    assert_ne!(&corrupt[..4], &0x35464D4Du32.to_le_bytes());
    session
        .map_write("mv_offsets", 0, &corrupt)
        .expect("seed corrupt table");
    session
        .attach(&attempt_specs("swiotlb", "swiotlb_bounced"))
        .expect("attach");
    let (frames, counters) = poll_window(&mut session, 6_000);
    eprintln!(
        "corrupt-table counters: observed={} emitted={} submit_fail={} flags={:#x} frames={}",
        counters[0],
        counters[2],
        counters[4],
        counters[5],
        frames.len()
    );
    if counters[0] == 0 {
        eprintln!(
            "SKIP live_negative_corrupt_attempt_table: kernel observed 0 firings in 6s; \
             BYTE_COVERAGE needs a firing this host cannot synthesize"
        );
    } else {
        assert_eq!(counters[2], 0, "corrupt table must emit nothing");
        assert!(
            counters[5] & MV_FLAG_BYTE_COVERAGE != 0,
            "corrupt table must raise BYTE_COVERAGE, flags={:#x}",
            counters[5]
        );
        assert!(
            counters[4] > 0,
            "every refused firing must submit_fail, got {}",
            counters[4]
        );
        assert!(frames.is_empty(), "no frames must arrive");
    }
    session.detach().expect("detach");
    session.close().expect("close");
}

#[test]
fn live_load_rejects_tampered_geometry() {
    if !live_enabled() {
        eprintln!(
            "SKIP live_load_rejects_tampered_geometry: set MEMVEIL_TEST_BPF_LIVE=1 and run privileged"
        );
        return;
    }
    // A table-size tamper loads (ARRAY 1x25 is valid) but the live geometry
    // gate refuses it, naming the map.
    let bytes = channel_bytes(Channel::Attempt);
    let tampered = tamper_map_u32(&bytes, 24, 25);
    let mut session = Session::open(&tampered, "mv_attempts").expect("open tampered");
    let error = session
        .load()
        .expect_err("tampered table size must be refused");
    assert!(
        error.to_string().contains("mv_offsets"),
        "refusal must name mv_offsets, got: {error}"
    );
    // A non-power-of-two ring size cannot even load; the kernel refuses it.
    let tampered = tamper_map_u32(&bytes, 8_388_608, 8_388_609);
    let mut session = Session::open(&tampered, "mv_attempts").expect("open tampered ring");
    session
        .load()
        .expect_err("non-power-of-two ring must not load");
}
