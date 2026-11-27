// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned journal tracing transport: the native [`JournalKernel`]
//! implementation behind the capture-boundary trait.
//!
//! Native diagnostics never export verifier contents: every failure
//! below reports a fixed journal message, never loader, BTF, or
//! verifier text. The session is a single Aya object with the exact
//! eight-map journal set; geometry is verified live after load and
//! any gate failure unloads again, so a refused session is never
//! left half-loaded.
//!
//! The task-birth offset (`task_struct.start_boottime`) is resolved
//! from live BTF at prepare time and installed in the `mv_jr_offs`
//! table before attach: aya emits no field relocations, so the
//! host-resolved offset replaces the retired CO-RE read, exactly
//! like the attempt/copy offset tables. Caller symbol ranges are
//! transient classifier input resolved from `/proc/kallsyms`; read
//! or resolve failures leave the classifier zeroed (unresolved),
//! while a failed map install refuses.

use super::journal_callers::{encode_caller_range, resolve_caller_ranges};
use super::journal_capture::{
    JOURNAL_NATIVE_COUNTERS, JournalCounters, JournalKernel as JournalSource, JournalPoll,
    decode_journal_counters,
};
use crate::bpf::attach::{AttachKind, AttachSpec};
use crate::bpf::maps::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_RINGBUF};
use crate::bpf::poll::open_consumer;
use crate::platform::btf::resolve_btf_member;
use crate::platform::narrow::MAX_NARROW_BTF_BYTES;
use crate::platform::outcome::OpOut;
use crate::platform::reader::read_host_file;
use aya::maps::{Array, Map, MapData, RingBuf};
use aya::programs::fentry::FEntryLinkId;
use aya::programs::fexit::FExitLinkId;
use aya::programs::{FEntry, FExit};
use aya::{Btf, Ebpf, EbpfLoader};
use std::time::{Duration, Instant};

/// `BPF_MAP_TYPE_PERCPU_ARRAY` (`linux/bpf.h`).
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;

/// Journal control block length in bytes.
const CONTROL_LEN: usize = 48;

/// Caller-requested flag byte offset in the control block.
const CONTROL_CALLERS: usize = 40;

/// Ring poll sleep step while waiting for a record.
const POLL_STEP: Duration = Duration::from_millis(2);

/// `/proc/kallsyms` read cap in bytes.
const KALLSYMS_CAP: usize = 16777216;

/// Live BTF path for the task-birth offset resolution.
const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

/// Expected live geometry: (name, type, key, value, max entries).
const EXPECTED_MAPS: [(&str, u32, u32, u32, u32); 8] = [
    ("mv_jr_control", BPF_MAP_TYPE_ARRAY, 4, 48, 1),
    ("mv_jr_counts", BPF_MAP_TYPE_ARRAY, 4, 8, 15),
    ("mv_jr_sequence", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 1),
    ("mv_jr_tasks", BPF_MAP_TYPE_HASH, 32, 16, 4096),
    ("mv_jr_ops", BPF_MAP_TYPE_HASH, 32, 24, 4096),
    ("mv_jr_symbols", BPF_MAP_TYPE_ARRAY, 4, 24, 10),
    ("mv_journal", BPF_MAP_TYPE_RINGBUF, 0, 0, 8388608),
    ("mv_jr_offs", BPF_MAP_TYPE_ARRAY, 4, 8, 1),
];

/// Attach specs in attach order: exits before entries, so no entry
/// can strand an operation its exit never sees.
pub fn journal_attach_specs() -> Vec<AttachSpec> {
    vec![
        AttachSpec::new(
            "mv_jr_dec_exit",
            AttachKind::FExit,
            "set_memory_decrypted",
            "",
        ),
        AttachSpec::new(
            "mv_jr_enc_exit",
            AttachKind::FExit,
            "set_memory_encrypted",
            "",
        ),
        AttachSpec::new(
            "mv_jr_dec_enter",
            AttachKind::FEntry,
            "set_memory_decrypted",
            "",
        ),
        AttachSpec::new(
            "mv_jr_enc_enter",
            AttachKind::FEntry,
            "set_memory_encrypted",
            "",
        ),
    ]
}

/// One live attach link.
enum JournalLink {
    /// Entry program with its link id.
    Enter { program: String, id: FEntryLinkId },
    /// Exit program with its link id.
    Exit { program: String, id: FExitLinkId },
}

/// One owned native journal session.
struct NativeSession {
    /// Loaded object; dropped on close.
    bpf: Ebpf,
    /// Pinned ring consumer for the session's life.
    consumer: RingBuf<MapData>,
    /// Live attach links in attach order.
    links: Vec<JournalLink>,
}

fn refused(message: &str) -> OpOut {
    OpOut {
        ok: false,
        message: message.to_string(),
    }
}

fn map_data(map: &Map) -> Option<&MapData> {
    match map {
        Map::Array(data) | Map::HashMap(data) | Map::PerCpuArray(data) | Map::RingBuf(data) => {
            Some(data)
        }
        _ => None,
    }
}

/// Live geometry of one loaded map.
fn live_geometry(bpf: &Ebpf, name: &str) -> Option<(u32, u32, u32, u32)> {
    let map = bpf.map(name)?;
    let data = map_data(map)?;
    let info = data.info().ok()?;
    let map_type = info.map_type().ok()? as u32;
    Some((
        map_type,
        info.key_size(),
        info.value_size(),
        info.max_entries(),
    ))
}

fn read_array_u64(bpf: &Ebpf, name: &str, key: u32) -> Option<u64> {
    let map = bpf.map(name)?;
    let array = Array::<_, u64>::try_from(map).ok()?;
    array.get(&key, 0).ok()
}

fn read_array_bytes<const N: usize>(bpf: &Ebpf, name: &str, key: u32) -> Option<[u8; N]> {
    let map = bpf.map(name)?;
    let array = Array::<_, [u8; N]>::try_from(map).ok()?;
    array.get(&key, 0).ok()
}

fn write_array_u64(bpf: &mut Ebpf, name: &str, key: u32, value: u64) -> bool {
    let Some(map) = bpf.map_mut(name) else {
        return false;
    };
    let Ok(mut array) = Array::<_, u64>::try_from(map) else {
        return false;
    };
    array.set(key, value, 0).is_ok()
}

fn write_array_bytes<const N: usize>(bpf: &mut Ebpf, name: &str, key: u32, value: [u8; N]) -> bool {
    let Some(map) = bpf.map_mut(name) else {
        return false;
    };
    let Ok(mut array) = Array::<_, [u8; N]>::try_from(map) else {
        return false;
    };
    array.set(key, value, 0).is_ok()
}

/// Native journal source: explicit ELF bytes plus one owned session.
///
/// There is no bridge path: the statically linked loader takes the
/// object bytes directly, so `setup` carries only the bytes and the
/// owned-module flag.
pub struct JournalKernel {
    /// Object bytes to load at prepare.
    elf: Vec<u8>,
    /// Owned session while open.
    session: Option<NativeSession>,
    /// True when owned-module caller labels resolve.
    stable_owned_module: bool,
}

impl JournalKernel {
    /// A closed source; call [`JournalKernel::setup`] next.
    pub fn new() -> Self {
        Self {
            elf: Vec::new(),
            session: None,
            stable_owned_module: false,
        }
    }

    /// Stage the object bytes and the owned-module flag.
    pub fn setup(&mut self, elf: Vec<u8>, stable_owned_module: bool) {
        self.elf = elf;
        self.stable_owned_module = stable_owned_module;
    }

    /// Resolve the `task_struct.start_boottime` byte offset from live
    /// BTF: an unambiguous non-bitfield 64-bit member at a byte
    /// offset, or nothing.
    fn birth_offset() -> Option<u64> {
        let data = read_host_file(VMLINUX_BTF, "btf", MAX_NARROW_BTF_BYTES).ok()?;
        let resolved = resolve_btf_member(&data, "task_struct", "start_boottime");
        if !resolved.ok || !resolved.found || resolved.ambiguous || resolved.bitfield {
            return None;
        }
        if resolved.bit_size != 64 || resolved.bit_offset < 0 || resolved.bit_offset % 8 != 0 {
            return None;
        }
        u64::try_from(resolved.bit_offset / 8).ok()
    }

    /// Install the transient caller classifier; read or resolve
    /// failures leave it zeroed, write failures refuse.
    fn install_callers(session: &mut NativeSession, stable_owned_module: bool) -> bool {
        let data = match read_host_file(VMLINUX_KALLSYMS, "caller symbol source", KALLSYMS_CAP) {
            Ok(data) => data,
            Err(_) => return true,
        };
        let text = match std::str::from_utf8(&data) {
            Ok(text) => text,
            Err(_) => return true,
        };
        let ranges = match resolve_caller_ranges(text, stable_owned_module) {
            Ok(ranges) => ranges,
            Err(_) => return true,
        };
        for (index, range) in ranges.iter().enumerate() {
            let encoded = encode_caller_range(*range);
            let mut value = [0u8; 24];
            value.copy_from_slice(&encoded);
            if !write_array_bytes(&mut session.bpf, "mv_jr_symbols", index as u32, value) {
                return false;
            }
        }
        true
    }

    /// Detach every live link in reverse order.
    fn detach_links(session: &mut NativeSession) -> bool {
        let links = std::mem::take(&mut session.links);
        let mut ok = true;
        for link in links.into_iter().rev() {
            let detached = match link {
                JournalLink::Enter { program, id } => session
                    .bpf
                    .program_mut(&program)
                    .and_then(|raw| {
                        let typed: Result<&mut FEntry, _> = raw.try_into();
                        typed.ok()
                    })
                    .is_some_and(|typed| typed.detach(id).is_ok()),
                JournalLink::Exit { program, id } => session
                    .bpf
                    .program_mut(&program)
                    .and_then(|raw| {
                        let typed: Result<&mut FExit, _> = raw.try_into();
                        typed.ok()
                    })
                    .is_some_and(|typed| typed.detach(id).is_ok()),
            };
            if !detached {
                ok = false;
            }
        }
        ok
    }
}

/// Caller symbol source path.
const VMLINUX_KALLSYMS: &str = "/proc/kallsyms";

impl Default for JournalKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl JournalSource for JournalKernel {
    fn prepare(&mut self, control: &[u8]) -> OpOut {
        if self.session.is_some() {
            return refused("journal already open");
        }
        if self.elf.len() < 64 || self.elf[0..4] != [0x7f, b'E', b'L', b'F'] {
            return refused("journal open/load unavailable");
        }
        let mut loader = EbpfLoader::new();
        let live_btf = Btf::from_sys_fs().ok();
        loader.btf(live_btf.as_ref());
        let mut bpf = match loader.load(&self.elf) {
            Ok(bpf) => bpf,
            Err(_) => return refused("journal open/load unavailable"),
        };
        for (name, want_type, want_key, want_value, want_max) in EXPECTED_MAPS {
            let geometry = live_geometry(&bpf, name);
            if geometry != Some((want_type, want_key, want_value, want_max)) {
                return refused("journal map geometry");
            }
        }
        // The birth offset installs before attach: the probe reads
        // every task birth through it, so a bad install refuses
        // here, before any firing can misread.
        let Some(offset) = Self::birth_offset() else {
            return refused("journal offsets unavailable");
        };
        if !write_array_u64(&mut bpf, "mv_jr_offs", 0, offset)
            || read_array_u64(&bpf, "mv_jr_offs", 0) != Some(offset)
        {
            return refused("journal offsets unavailable");
        }
        let consumer = match bpf.map("mv_journal") {
            Some(map) => match open_consumer(map, "mv_journal") {
                Ok(consumer) => consumer,
                Err(_) => return refused("journal open/load unavailable"),
            },
            None => return refused("journal open/load unavailable"),
        };
        let mut session = NativeSession {
            bpf,
            consumer,
            links: Vec::new(),
        };
        let mut initial = Vec::with_capacity(JOURNAL_NATIVE_COUNTERS * 8);
        for index in 0..JOURNAL_NATIVE_COUNTERS {
            match read_array_u64(&session.bpf, "mv_jr_counts", index as u32) {
                Some(value) => initial.extend_from_slice(&value.to_le_bytes()),
                None => return refused("journal initial counters unavailable"),
            }
        }
        match decode_journal_counters(&initial) {
            Ok(values) => {
                if values.iter().any(|value| *value != 0) {
                    return refused("journal initial counters nonzero");
                }
            }
            Err(_) => return refused("journal initial counters unavailable"),
        }
        if control.len() == CONTROL_LEN
            && control[CONTROL_CALLERS] != 0
            && !Self::install_callers(&mut session, self.stable_owned_module)
        {
            return refused("journal caller map unavailable");
        }
        self.session = Some(session);
        self.control(control)
    }

    fn attach(&mut self) -> OpOut {
        let Some(session) = self.session.as_mut() else {
            return refused("journal not open");
        };
        if !session.links.is_empty() {
            return refused("journal attach failed");
        }
        let live_btf = match Btf::from_sys_fs() {
            Ok(btf) => btf,
            Err(_) => return refused("journal attach failed"),
        };
        for spec in journal_attach_specs() {
            let loaded = match spec.kind {
                AttachKind::FEntry => session
                    .bpf
                    .program_mut(&spec.program)
                    .and_then(|raw| {
                        let typed: Result<&mut FEntry, _> = raw.try_into();
                        typed.ok()
                    })
                    .is_some_and(|typed| typed.load(&spec.target_a, &live_btf).is_ok()),
                AttachKind::FExit => session
                    .bpf
                    .program_mut(&spec.program)
                    .and_then(|raw| {
                        let typed: Result<&mut FExit, _> = raw.try_into();
                        typed.ok()
                    })
                    .is_some_and(|typed| typed.load(&spec.target_a, &live_btf).is_ok()),
                AttachKind::Tracepoint => false,
            };
            if !loaded {
                Self::detach_links(session);
                return refused("journal attach failed");
            }
            let link = match spec.kind {
                AttachKind::FEntry => session
                    .bpf
                    .program_mut(&spec.program)
                    .and_then(|raw| {
                        let typed: Result<&mut FEntry, _> = raw.try_into();
                        typed.ok()
                    })
                    .and_then(|typed| typed.attach().ok())
                    .map(|id| JournalLink::Enter {
                        program: spec.program.clone(),
                        id,
                    }),
                AttachKind::FExit => session
                    .bpf
                    .program_mut(&spec.program)
                    .and_then(|raw| {
                        let typed: Result<&mut FExit, _> = raw.try_into();
                        typed.ok()
                    })
                    .and_then(|typed| typed.attach().ok())
                    .map(|id| JournalLink::Exit {
                        program: spec.program.clone(),
                        id,
                    }),
                AttachKind::Tracepoint => None,
            };
            match link {
                Some(link) => session.links.push(link),
                None => {
                    Self::detach_links(session);
                    return refused("journal attach failed");
                }
            }
        }
        OpOut {
            ok: true,
            message: String::new(),
        }
    }

    fn control(&mut self, value: &[u8]) -> OpOut {
        let Some(session) = self.session.as_mut() else {
            return refused("journal control unavailable");
        };
        if value.len() != CONTROL_LEN {
            return refused("journal control unavailable");
        }
        let mut block = [0u8; CONTROL_LEN];
        block.copy_from_slice(value);
        if !write_array_bytes(&mut session.bpf, "mv_jr_control", 0, block) {
            return refused("journal control write/readback failed");
        }
        match read_array_bytes::<CONTROL_LEN>(&session.bpf, "mv_jr_control", 0) {
            Some(actual) if actual == block => OpOut {
                ok: true,
                message: String::new(),
            },
            _ => refused("journal control write/readback failed"),
        }
    }

    fn poll(&mut self, timeout_ms: i64) -> JournalPoll {
        let Some(session) = self.session.as_mut() else {
            return JournalPoll {
                ok: false,
                data: Vec::new(),
            };
        };
        let wait = u64::from(timeout_ms.clamp(0, u32::MAX as i64) as u32);
        let deadline = Instant::now() + Duration::from_millis(wait);
        loop {
            if let Some(item) = session.consumer.next() {
                return JournalPoll {
                    ok: true,
                    data: item.to_vec(),
                };
            }
            if Instant::now() >= deadline {
                return JournalPoll {
                    ok: true,
                    data: Vec::new(),
                };
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(remaining.min(POLL_STEP));
        }
    }

    fn counters(&mut self) -> JournalCounters {
        let empty = JournalCounters {
            ok: false,
            values: Vec::new(),
        };
        let Some(session) = self.session.as_ref() else {
            return empty;
        };
        let mut raw = Vec::with_capacity(JOURNAL_NATIVE_COUNTERS * 8);
        for index in 0..JOURNAL_NATIVE_COUNTERS {
            match read_array_u64(&session.bpf, "mv_jr_counts", index as u32) {
                Some(value) => raw.extend_from_slice(&value.to_le_bytes()),
                None => return empty,
            }
        }
        match decode_journal_counters(&raw) {
            Ok(values) => JournalCounters { ok: true, values },
            Err(_) => empty,
        }
    }

    fn detach(&mut self) -> OpOut {
        let Some(session) = self.session.as_mut() else {
            return OpOut {
                ok: true,
                message: String::new(),
            };
        };
        if Self::detach_links(session) {
            OpOut {
                ok: true,
                message: String::new(),
            }
        } else {
            refused("journal detach failed")
        }
    }

    fn close(&mut self) -> OpOut {
        if self.session.is_none() {
            return OpOut {
                ok: true,
                message: String::new(),
            };
        }
        let detach_ok = match self.session.as_mut() {
            Some(session) => Self::detach_links(session),
            None => true,
        };
        if !detach_ok {
            return refused("journal close failed");
        }
        self.session = None;
        OpOut {
            ok: true,
            message: String::new(),
        }
    }
}
