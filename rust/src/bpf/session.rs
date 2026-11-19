// SPDX-License-Identifier: GPL-3.0-or-later
//! One channel object under Aya: open, load, attach, poll, maps, detach,
//! close. [`Channels`] attaches every present channel inner-first with
//! rollback, mirroring the old kernel source.
//!
//! State machine per session: opened (ELF parsed and sanity-checked) then
//! loaded (kernel maps created, live geometry verified) then attached
//! (programs linked). `close` releases everything and is idempotent;
//! dropping a session releases it too.

use super::attach::{ATTACH_ORDER, AttachKind, AttachSpec, DETACH_ORDER};
use super::maps::{MapGeometry, MapSpec, check_maps_loaded};
use super::offsets::{encode_copy_offsets, validate_copy_offsets};
use super::poll::{Frame, Stats, decode_frame, open_consumer};
use crate::capture::loadcheck::errno_from_chain;
use aya::maps::{Array, Map, MapData, RingBuf};
use aya::programs::{
    Program, ProgramError,
    fentry::{FEntry, FEntryLinkId},
    fexit::{FExit, FExitLinkId},
    trace_point::{TracePoint, TracePointLinkId},
};
use aya::{Btf, Ebpf, EbpfLoader};
use memveil_ebpf_common::{CopyOffsets, MV_OFFSETS_TABLE_LEN, decode_offsets_table};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Attempt ring map name.
const RING_ATTEMPT: &str = "mv_attempts";
/// Lifecycle ring map name.
const RING_LIFECYCLE: &str = "mv_lifecycle";
/// Copy ring map name.
const RING_COPY: &str = "mv_copies";

/// Counter map name.
const MAP_COUNTS: &str = "mv_counts";
/// Attempt offsets-table map name.
const MAP_OFFSETS: &str = "mv_offsets";
/// Copy field-table map name.
const MAP_COPY_OFFS: &str = "mv_copy_offs";
/// Copy fallback map name.
const MAP_COPY_FB: &str = "mv_copy_fb";

/// Counter map keys.
const COUNT_KEYS: u32 = 6;
/// Fallback counter keys below the armed slot.
const FB_KEYS: u32 = 3;
/// Fallback armed slot: exactly 1 arms the exit.
const FB_ARMED_KEY: u32 = 3;

/// Poll sleep step while waiting for a frame.
const POLL_STEP: Duration = Duration::from_millis(2);

/// One capture channel: the ELF plus its ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Tracepoint object, channel 0.
    Attempt,
    /// Lifecycle tracing object, channel 1.
    Lifecycle,
    /// Copy tracing object, channel 2.
    Copy,
}

impl Channel {
    /// Channel index matching the old kernel source (0/1/2).
    pub fn index(self) -> u32 {
        match self {
            Channel::Attempt => 0,
            Channel::Lifecycle => 1,
            Channel::Copy => 2,
        }
    }

    /// Frozen ring map name.
    pub fn ring_name(self) -> &'static str {
        match self {
            Channel::Attempt => RING_ATTEMPT,
            Channel::Lifecycle => RING_LIFECYCLE,
            Channel::Copy => RING_COPY,
        }
    }

    /// Channel for a ring name, if frozen.
    pub fn from_ring(ring: &str) -> Option<Channel> {
        match ring {
            RING_ATTEMPT => Some(Channel::Attempt),
            RING_LIFECYCLE => Some(Channel::Lifecycle),
            RING_COPY => Some(Channel::Copy),
            _ => None,
        }
    }

    /// Expected program-section counts `(prefix, count)` for the open-time
    /// sanity check: the wrong ELF for a channel is refused unprivileged,
    /// before any syscall.
    fn expected_sections(self) -> &'static [(&'static str, usize)] {
        match self {
            Channel::Attempt => &[("tracepoint/", 1)],
            Channel::Lifecycle => &[("fentry/", 1), ("fexit/", 1)],
            Channel::Copy => &[("fentry/", 3), ("fexit/", 1)],
        }
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Channel::Attempt => f.write_str("attempt"),
            Channel::Lifecycle => f.write_str("lifecycle"),
            Channel::Copy => f.write_str("copy"),
        }
    }
}

/// Loader failure. Messages are self-describing and name the channel,
/// program, map, or hook at fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// `open` refused the ELF or ring.
    Open(String),
    /// Call on a closed session.
    NotOpen(String),
    /// Call needing `load` first.
    NotLoaded(String),
    /// Geometry gate refusal.
    Geometry(String),
    /// Kernel load failure.
    Load(String),
    /// Attach failure (names the program and target).
    Attach(String),
    /// Map info/read/write failure (names the map).
    Map(String),
    /// Poll failure.
    Poll(String),
    /// Offsets resolution/install failure.
    Offsets(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            SessionError::Open(message)
            | SessionError::NotOpen(message)
            | SessionError::NotLoaded(message)
            | SessionError::Geometry(message)
            | SessionError::Load(message)
            | SessionError::Attach(message)
            | SessionError::Map(message)
            | SessionError::Poll(message)
            | SessionError::Offsets(message) => message,
        };
        f.write_str(message)
    }
}

impl std::error::Error for SessionError {}

/// One active attach: the program plus its link id.
enum ActiveLink {
    TracePoint {
        program: String,
        id: TracePointLinkId,
    },
    FEntry {
        program: String,
        id: FEntryLinkId,
    },
    FExit {
        program: String,
        id: FExitLinkId,
    },
}

/// Programs this session loaded: program name to the (kind, target_a,
/// target_b) it was loaded for. Detach drops links but leaves programs
/// loaded, so re-attach must skip the load; the recorded target guards
/// against silently attaching a program loaded for another site.
type LoadedMap = HashMap<String, (AttachKind, String, String)>;

/// Record a fresh program load.
fn note_loaded(loaded: &mut LoadedMap, spec: &AttachSpec) {
    loaded.insert(
        spec.program.clone(),
        (spec.kind, spec.target_a.clone(), spec.target_b.clone()),
    );
}

/// Accept an already-loaded program only when this session loaded it for
/// the same site.
fn check_loaded(loaded: &LoadedMap, spec: &AttachSpec, tag: &str) -> Result<(), String> {
    match loaded.get(&spec.program) {
        Some((kind, target_a, target_b))
            if *kind == spec.kind && *target_a == spec.target_a && *target_b == spec.target_b =>
        {
            Ok(())
        }
        _ => Err(format!(
            "{tag}: program already loaded for a different target"
        )),
    }
}

/// Read a little-endian `u16` out of `bytes` at `offset`. The end is
/// checked: a file-supplied offset near `usize::MAX` yields `None`,
/// never a debug panic.
fn le16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    bytes
        .get(offset..end)
        .map(|window| u16::from_le_bytes([window[0], window[1]]))
}

/// Read a little-endian `u64` out of `bytes` at `offset`. The end is
/// checked: a file-supplied offset near `usize::MAX` yields `None`,
/// never a debug panic.
fn le64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    bytes.get(offset..end).map(|window| {
        u64::from_le_bytes([
            window[0], window[1], window[2], window[3], window[4], window[5], window[6], window[7],
        ])
    })
}

/// One shared sysfs BTF read for CO-RE loads: the parsed BTF (when
/// the read succeeded), whether the ELF carries BTF relocations, and
/// the read's errno (when the read failed with one). Normal and
/// diagnostic loads derive from the same read: relocation-carrying
/// objects refuse without it, and the loader always receives this
/// same parsed BTF — never a second silent read that could observe a
/// different sysfs.
#[derive(Debug)]
pub(crate) struct CorePrecondition {
    /// Parsed sysfs BTF; `None` when the read failed.
    pub btf: Option<Btf>,
    /// True when the ELF carries BTF relocations.
    pub relocations: bool,
    /// The sysfs read's errno; `None` on success or on a
    /// non-errno (corrupt blob) read failure.
    pub read_errno: Option<i32>,
}

/// Read the CO-RE precondition once: probe the ELF for BTF
/// relocations, then read and parse sysfs BTF a single time.
/// Unparseable objects report no relocations; the loader itself
/// judges them (open already gated structure).
pub(crate) fn core_precondition(elf: &[u8]) -> CorePrecondition {
    let relocations = aya_obj::Object::parse(elf)
        .map(|object| object.has_btf_relocations())
        .unwrap_or(false);
    match Btf::from_sys_fs() {
        Ok(btf) => CorePrecondition {
            btf: Some(btf),
            relocations,
            read_errno: None,
        },
        Err(error) => CorePrecondition {
            btf: None,
            relocations,
            read_errno: errno_from_chain(&error),
        },
    }
}

/// Fail-closed CO-RE verdict over one precondition: refuse a
/// relocation-carrying object when sysfs BTF is unreadable, naming
/// BTF. Objects without relocations pass through.
fn check_core_btf(pre: &CorePrecondition, channel: Channel) -> Result<(), SessionError> {
    if pre.relocations && pre.btf.is_none() {
        return Err(SessionError::Load(format!(
            "{channel} channel: object carries CO-RE relocations but kernel BTF is unreadable"
        )));
    }
    Ok(())
}

/// Open-time ELF sanity: 64-bit BPF object carrying the channel's program
/// sections. Manual header walk (no object parser on this side): any
/// truncation refuses.
fn check_elf(elf: &[u8], channel: Channel) -> Result<(), SessionError> {
    let open = |why: &str| SessionError::Open(format!("{channel} channel: {why}"));
    if elf.get(..4) != Some(b"\x7fELF".as_slice()) {
        return Err(open("not an ELF object"));
    }
    if elf.get(4) != Some(&2) {
        return Err(open("not a 64-bit object"));
    }
    let machine = elf
        .get(18..20)
        .map(|window| u16::from_le_bytes([window[0], window[1]]));
    if machine != Some(247) {
        return Err(open("not a BPF object"));
    }
    let (Some(shoff), Some(shentsize), Some(shnum), Some(shstrndx)) = (
        le64(elf, 0x28),
        le16(elf, 0x3a),
        le16(elf, 0x3c),
        le16(elf, 0x3e),
    ) else {
        return Err(open("ELF header truncated"));
    };
    if shentsize < 64 || shstrndx >= shnum {
        return Err(open("ELF section table invalid"));
    }
    // Every section-table multiply, add, and u64-to-usize narrowing is
    // checked: `shoff` is file-supplied, and a value near u64::MAX must
    // refuse with `Open`, never panic in debug builds or wrap in release.
    // Stride by the file's own `shentsize` (a BPF object with extended
    // section headers must still walk correctly); the 64-byte header reads
    // below stay fixed since only the first 64 bytes are interpreted.
    let stride = u64::from(shentsize);
    let Some(shstr) = u64::from(shstrndx)
        .checked_mul(stride)
        .and_then(|offset| shoff.checked_add(offset))
        .and_then(|at| usize::try_from(at).ok())
    else {
        return Err(open("section-name table offset overflows"));
    };
    let name_field = |field: usize| {
        shstr
            .checked_add(field)
            .and_then(|at| le64(elf, at))
            .and_then(|value| usize::try_from(value).ok())
    };
    let (Some(str_off), Some(str_len)) = (name_field(24), name_field(32)) else {
        return Err(open("section-name table header truncated"));
    };
    let Some(strtab) = elf.get(str_off..str_off.saturating_add(str_len)) else {
        return Err(open("section-name table truncated"));
    };
    let mut counts = vec![0usize; channel.expected_sections().len()];
    for index in 0..shnum {
        let Some(header) = u64::from(index)
            .checked_mul(stride)
            .and_then(|offset| shoff.checked_add(offset))
            .and_then(|at| usize::try_from(at).ok())
        else {
            return Err(open("section header offset overflows"));
        };
        let (Some(name_off), Some(_)) = (
            header.checked_add(4).and_then(|end| {
                elf.get(header..end)
                    .map(|window| u32::from_le_bytes([window[0], window[1], window[2], window[3]]))
            }),
            header.checked_add(64).and_then(|end| elf.get(header..end)),
        ) else {
            return Err(open("section header truncated"));
        };
        let tail = strtab.get(name_off as usize..).unwrap_or_default();
        let end = tail.iter().position(|byte| *byte == 0).unwrap_or(0);
        let name = std::str::from_utf8(&tail[..end]).map_err(|_| open("bad section name"))?;
        for (slot, (prefix, _)) in channel.expected_sections().iter().enumerate() {
            if name.starts_with(prefix) {
                counts[slot] += 1;
            }
        }
    }
    for (got, (prefix, want)) in counts.iter().zip(channel.expected_sections().iter()) {
        if got != want {
            return Err(open(&format!(
                "ELF has {got} {prefix} sections, want {want}"
            )));
        }
    }
    Ok(())
}

/// Borrow the map data for the supported info/read/write map types.
fn array_data<'a>(map: &'a Map, name: &str) -> Result<&'a MapData, SessionError> {
    match map {
        Map::Array(data) | Map::RingBuf(data) | Map::HashMap(data) => Ok(data),
        _ => Err(SessionError::Map(format!(
            "map `{name}`: unsupported map type for info"
        ))),
    }
}

/// Live geometry of one loaded map.
fn live_geometry(map: &Map, name: &str) -> Result<MapGeometry, SessionError> {
    let data = array_data(map, name)?;
    let info = data
        .info()
        .map_err(|error| SessionError::Map(format!("map `{name}` info failed: {error}")))?;
    let map_type = info
        .map_type()
        .map_err(|error| SessionError::Map(format!("map `{name}` info failed: {error}")))?;
    Ok(MapGeometry {
        map_type: map_type as u32,
        key_size: info.key_size(),
        value_size: info.value_size(),
        max_entries: info.max_entries(),
    })
}

/// Detach one link, consuming it.
fn detach_link(bpf: &mut Ebpf, link: ActiveLink) -> Result<(), String> {
    match link {
        ActiveLink::TracePoint { program, id } => {
            let Some(raw) = bpf.program_mut(&program) else {
                return Err(format!("program `{program}` missing for detach"));
            };
            let typed: &mut TracePoint = raw
                .try_into()
                .map_err(|_| format!("program `{program}` is not a tracepoint"))?;
            typed.detach(id).map_err(|error| error.to_string())
        }
        ActiveLink::FEntry { program, id } => {
            let Some(raw) = bpf.program_mut(&program) else {
                return Err(format!("program `{program}` missing for detach"));
            };
            let typed: &mut FEntry = raw
                .try_into()
                .map_err(|_| format!("program `{program}` is not an fentry"))?;
            typed.detach(id).map_err(|error| error.to_string())
        }
        ActiveLink::FExit { program, id } => {
            let Some(raw) = bpf.program_mut(&program) else {
                return Err(format!("program `{program}` missing for detach"));
            };
            let typed: &mut FExit = raw
                .try_into()
                .map_err(|_| format!("program `{program}` is not an fexit"))?;
            typed.detach(id).map_err(|error| error.to_string())
        }
    }
}

/// One channel session: the ELF bytes plus, after load, the kernel object.
pub struct Session {
    elf: Vec<u8>,
    ring: String,
    channel: Channel,
    bpf: Option<Ebpf>,
    consumer: Option<RingBuf<MapData>>,
    links: Vec<ActiveLink>,
    loaded: LoadedMap,
    received: u64,
    delivered: u64,
    malformed: u64,
    closed: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("channel", &self.channel)
            .field("ring", &self.ring)
            .field("elf_len", &self.elf.len())
            .field("loaded", &self.is_loaded())
            .field("attached", &self.attached())
            .field("closed", &self.closed)
            .finish()
    }
}

impl Session {
    /// Open the channel ELF for its ring. The ring name selects the
    /// channel; the ELF must be a 64-bit BPF object carrying that
    /// channel's program sections. Unprivileged.
    pub fn open(elf: &[u8], ring: &str) -> Result<Self, SessionError> {
        let Some(channel) = Channel::from_ring(ring) else {
            return Err(SessionError::Open(format!("unknown ring `{ring}`")));
        };
        check_elf(elf, channel)?;
        Ok(Self {
            elf: elf.to_vec(),
            ring: ring.to_owned(),
            channel,
            bpf: None,
            consumer: None,
            links: Vec::new(),
            loaded: LoadedMap::new(),
            received: 0,
            delivered: 0,
            malformed: 0,
            closed: false,
        })
    }

    /// This session's channel.
    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// This session's ring map name.
    pub fn ring(&self) -> &str {
        &self.ring
    }

    /// True once [`Session::load`] succeeded.
    pub fn is_loaded(&self) -> bool {
        self.bpf.is_some()
    }

    /// True while at least one program link is attached.
    pub fn attached(&self) -> bool {
        !self.links.is_empty()
    }

    /// Load the object: create the kernel maps, then verify live map
    /// presence and geometry (ring capacity upper-bounded by the frozen
    /// size) plus program presence against the frozen channel spec. A
    /// gate failure unloads again, so a refused session is never left
    /// half-loaded. Privileged.
    pub fn load(&mut self) -> Result<(), SessionError> {
        if self.closed {
            return Err(SessionError::NotOpen("session not open".to_owned()));
        }
        if self.bpf.is_some() {
            return Err(SessionError::Load(format!(
                "{} channel: session already loaded",
                self.channel
            )));
        }
        // Fail-closed CO-RE guard over one shared sysfs read: aya
        // skips BTF relocation silently when its own read fails, so
        // the loader receives this same parsed BTF instead of
        // reading again, and a relocation-carrying object refuses
        // here rather than loading unrelocated code.
        let pre = core_precondition(&self.elf);
        check_core_btf(&pre, self.channel)?;
        let mut loader = EbpfLoader::new();
        loader.btf(pre.btf.as_ref());
        let bpf = loader.load(&self.elf).map_err(|error| {
            SessionError::Load(format!("{} channel: load failed: {error}", self.channel))
        })?;
        let mut actual_maps = Vec::new();
        for (name, map) in bpf.maps() {
            let geometry = live_geometry(map, name)?;
            actual_maps.push(MapSpec {
                name: name.to_owned(),
                map_type: geometry.map_type,
                key_size: geometry.key_size,
                value_size: geometry.value_size,
                max_entries: geometry.max_entries,
            });
        }
        if let Err(error) = check_maps_loaded(self.channel, &actual_maps) {
            drop(bpf);
            return Err(error);
        }
        if let Err(error) = self.check_live_programs(&bpf) {
            drop(bpf);
            return Err(error);
        }
        // Pin one owned ring consumer for the session's life; a
        // consumer built per poll remaps the ring every record and
        // stalls under flood. A consumer failure unloads again, like
        // the gates above, so a refused session is never left
        // half-loaded.
        let consumer = match bpf.map(&self.ring) {
            Some(map) => match open_consumer(map, &self.ring) {
                Ok(consumer) => consumer,
                Err(error) => {
                    drop(bpf);
                    return Err(error);
                }
            },
            None => {
                drop(bpf);
                return Err(SessionError::Load(format!(
                    "{} channel: ring map `{}` missing",
                    self.channel, self.ring
                )));
            }
        };
        self.bpf = Some(bpf);
        self.consumer = Some(consumer);
        Ok(())
    }

    /// Live program gate, gate two of two: every expected program
    /// present in its section kind, no unexpected programs. Gate one
    /// is `check_elf` at open: it pins exact `tracepoint/`/`fentry/`/
    /// `fexit/` section counts, and a sleepable program lives in
    /// `fentry.s/`/`fexit.s/`, which never matches a counted prefix,
    /// so swapping one in breaks the count there. What gate one
    /// cannot see (sections beyond the counts) this gate refuses by
    /// exact program set.
    fn check_live_programs(&self, bpf: &Ebpf) -> Result<(), SessionError> {
        use super::attach::expected_programs;
        let expected = expected_programs(self.channel);
        for want in &expected {
            let Some(got) = bpf.program(&want.name) else {
                return Err(SessionError::Geometry(format!(
                    "{} channel: missing program {}",
                    self.channel, want.name
                )));
            };
            let kind = match got {
                Program::TracePoint(_) => AttachKind::Tracepoint,
                Program::FEntry(_) => AttachKind::FEntry,
                Program::FExit(_) => AttachKind::FExit,
                _ => {
                    return Err(SessionError::Geometry(format!(
                        "{} channel: program {} has an unexpected section",
                        self.channel, want.name
                    )));
                }
            };
            if kind != want.kind {
                return Err(SessionError::Geometry(format!(
                    "{} channel: program {}: want section {:?}, got {:?}",
                    self.channel, want.name, want.kind, kind
                )));
            }
        }
        for (name, _) in bpf.programs() {
            if !expected.iter().any(|want| want.name == name) {
                return Err(SessionError::Geometry(format!(
                    "{} channel: unexpected program {name}",
                    self.channel
                )));
            }
        }
        Ok(())
    }

    /// Attach every site in one all-or-none transaction: a failed site
    /// detaches the sites this call attached, in reverse. Refuses empty
    /// site lists and double attach (detach first). Privileged.
    pub fn attach(&mut self, specs: &[AttachSpec]) -> Result<(), SessionError> {
        if self.closed {
            return Err(SessionError::NotOpen("session not open".to_owned()));
        }
        if specs.is_empty() {
            return Err(SessionError::Attach("no attach sites".to_owned()));
        }
        if !self.links.is_empty() {
            return Err(SessionError::Attach(
                "already attached; detach first".to_owned(),
            ));
        }
        let Some(bpf) = self.bpf.as_mut() else {
            return Err(SessionError::NotLoaded("session not loaded".to_owned()));
        };
        let mut btf: Option<Btf> = None;
        for spec in specs {
            match attach_one(bpf, self.channel, spec, &mut btf, &mut self.loaded) {
                Ok(link) => self.links.push(link),
                Err(message) => {
                    let links = std::mem::take(&mut self.links);
                    let mut rollback = Vec::new();
                    for link in links.into_iter().rev() {
                        if let Err(error) = detach_link(bpf, link) {
                            rollback.push(error);
                        }
                    }
                    let mut full = message;
                    for error in rollback {
                        full.push_str("; rollback: ");
                        full.push_str(&error);
                    }
                    return Err(SessionError::Attach(full));
                }
            }
        }
        Ok(())
    }

    /// Poll one decoded frame, waiting up to `timeout_ms` for ring data.
    /// Returns `None` on timeout. Decode failures count as malformed and
    /// are skipped so one poisoned record never hides later ones.
    pub fn poll(&mut self, timeout_ms: u32) -> Result<Option<Frame>, SessionError> {
        if self.closed {
            return Err(SessionError::NotOpen("session not open".to_owned()));
        }
        let Some(consumer) = self.consumer.as_mut() else {
            return Err(SessionError::NotLoaded("session not loaded".to_owned()));
        };
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        loop {
            match consumer.next().map(|item| item.to_vec()) {
                Some(bytes) => {
                    self.received = self.received.wrapping_add(1);
                    match decode_frame(self.channel, &bytes) {
                        Ok(frame) => {
                            self.delivered = self.delivered.wrapping_add(1);
                            return Ok(Some(frame));
                        }
                        Err(_) => {
                            self.malformed = self.malformed.wrapping_add(1);
                        }
                    }
                }
                None => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    std::thread::sleep(remaining.min(POLL_STEP));
                }
            }
        }
    }

    /// Live geometry of one map.
    /// True when the loaded object carries the named map. Tells
    /// Aya-family copy objects (host-resolved table map) from
    /// C-family ones (CO-RE, no table map) after the load gate
    /// admitted either shape.
    pub fn has_map(&self, name: &str) -> bool {
        self.bpf.as_ref().is_some_and(|bpf| bpf.map(name).is_some())
    }

    pub fn map_info(&self, name: &str) -> Result<MapGeometry, SessionError> {
        if self.closed {
            return Err(SessionError::NotOpen("session not open".to_owned()));
        }
        let Some(bpf) = self.bpf.as_ref() else {
            return Err(SessionError::NotLoaded("session not loaded".to_owned()));
        };
        let Some(map) = bpf.map(name) else {
            return Err(SessionError::Map(format!("map `{name}` not in object")));
        };
        live_geometry(map, name)
    }

    /// Read `len` bytes from key `key` of an array map. The length must
    /// equal the live value size exactly; short reads refuse.
    pub fn map_read(&self, name: &str, key: u32, len: usize) -> Result<Vec<u8>, SessionError> {
        if self.closed {
            return Err(SessionError::NotOpen("session not open".to_owned()));
        }
        let Some(bpf) = self.bpf.as_ref() else {
            return Err(SessionError::NotLoaded("session not loaded".to_owned()));
        };
        let Some(map) = bpf.map(name) else {
            return Err(SessionError::Map(format!("map `{name}` not in object")));
        };
        if !matches!(map, Map::Array(_)) {
            return Err(SessionError::Map(format!("map `{name}` is not readable")));
        }
        let geometry = live_geometry(map, name)?;
        if geometry.key_size != 4 {
            return Err(SessionError::Map(format!(
                "map `{name}` has key size {}, want 4",
                geometry.key_size
            )));
        }
        if geometry.value_size as usize != len {
            return Err(SessionError::Map(format!(
                "map `{name}` value size is {}, asked {len}",
                geometry.value_size
            )));
        }
        if key >= geometry.max_entries {
            return Err(SessionError::Map(format!(
                "map `{name}` key {key} out of range ({})",
                geometry.max_entries
            )));
        }
        let fail =
            |error| SessionError::Map(format!("map `{name}` key {key} read failed: {error}"));
        match len {
            8 => {
                let array = Array::<_, u64>::try_from(map).map_err(fail)?;
                array
                    .get(&key, 0)
                    .map(|value| value.to_le_bytes().to_vec())
                    .map_err(fail)
            }
            16 => {
                let array = Array::<_, [u8; 16]>::try_from(map).map_err(fail)?;
                array.get(&key, 0).map(|value| value.to_vec()).map_err(fail)
            }
            24 => {
                let array = Array::<_, [u8; 24]>::try_from(map).map_err(fail)?;
                array.get(&key, 0).map(|value| value.to_vec()).map_err(fail)
            }
            112 => {
                let array = Array::<_, [u8; 112]>::try_from(map).map_err(fail)?;
                array.get(&key, 0).map(|value| value.to_vec()).map_err(fail)
            }
            _ => Err(SessionError::Map(format!(
                "map `{name}` value size {len} unsupported"
            ))),
        }
    }

    /// Write `value` to key `key` of an array map. The length must equal
    /// the live value size exactly.
    pub fn map_write(&mut self, name: &str, key: u32, value: &[u8]) -> Result<(), SessionError> {
        if self.closed {
            return Err(SessionError::NotOpen("session not open".to_owned()));
        }
        let Some(bpf) = self.bpf.as_mut() else {
            return Err(SessionError::NotLoaded("session not loaded".to_owned()));
        };
        let Some(map) = bpf.map_mut(name) else {
            return Err(SessionError::Map(format!("map `{name}` not in object")));
        };
        if !matches!(map, Map::Array(_)) {
            return Err(SessionError::Map(format!("map `{name}` is not writable")));
        }
        let geometry = live_geometry(map, name)?;
        if geometry.key_size != 4 {
            return Err(SessionError::Map(format!(
                "map `{name}` has key size {}, want 4",
                geometry.key_size
            )));
        }
        if geometry.value_size as usize != value.len() {
            return Err(SessionError::Map(format!(
                "map `{name}` value size is {}, asked {}",
                geometry.value_size,
                value.len()
            )));
        }
        if key >= geometry.max_entries {
            return Err(SessionError::Map(format!(
                "map `{name}` key {key} out of range ({})",
                geometry.max_entries
            )));
        }
        let fail =
            |error| SessionError::Map(format!("map `{name}` key {key} write failed: {error}"));
        // Lengths were checked against the live value size above, so the
        // fixed-array conversions below cannot fail; the refusal stays as
        // defense in depth.
        let bad_len = || SessionError::Map(format!("map `{name}` key {key}: bad value length"));
        match value.len() {
            8 => {
                let mut array = Array::<_, u64>::try_from(map).map_err(fail)?;
                let word = u64::from_le_bytes(value.try_into().map_err(|_| bad_len())?);
                array.set(key, word, 0).map_err(fail)
            }
            16 => {
                let mut array = Array::<_, [u8; 16]>::try_from(map).map_err(fail)?;
                let fixed: [u8; 16] = value.try_into().map_err(|_| bad_len())?;
                array.set(key, fixed, 0).map_err(fail)
            }
            24 => {
                let mut array = Array::<_, [u8; 24]>::try_from(map).map_err(fail)?;
                let fixed: [u8; 24] = value.try_into().map_err(|_| bad_len())?;
                array.set(key, fixed, 0).map_err(fail)
            }
            112 => {
                let mut array = Array::<_, [u8; 112]>::try_from(map).map_err(fail)?;
                let fixed: [u8; 112] = value.try_into().map_err(|_| bad_len())?;
                array.set(key, fixed, 0).map_err(fail)
            }
            _ => Err(SessionError::Map(format!(
                "map `{name}` value size {} unsupported",
                value.len()
            ))),
        }
    }

    /// Host-side poll accounting.
    pub fn stats(&self) -> Stats {
        Stats {
            received: self.received,
            delivered: self.delivered,
            staged: 0,
            malformed: self.malformed,
            dropped: 0,
        }
    }

    /// Install the 24-byte attempt offsets table: validate it the way the
    /// probe does, write key 0, then read it back and compare. A short or
    /// mismatched read-back refuses: the program must never run on a
    /// mis-installed table.
    pub fn install_offsets(
        &mut self,
        table: &[u8; MV_OFFSETS_TABLE_LEN],
    ) -> Result<(), SessionError> {
        decode_offsets_table(table)
            .map_err(|error| SessionError::Offsets(format!("bad offsets table: {error}")))?;
        self.map_write(MAP_OFFSETS, 0, table)?;
        let back = self.map_read(MAP_OFFSETS, 0, MV_OFFSETS_TABLE_LEN)?;
        if back.len() != MV_OFFSETS_TABLE_LEN {
            return Err(SessionError::Offsets("offsets verify short".to_owned()));
        }
        if back.as_slice() != table.as_slice() {
            return Err(SessionError::Offsets("offsets verify mismatch".to_owned()));
        }
        Ok(())
    }

    /// Install the 112-byte copy field table with the same write-plus-
    /// verify discipline as [`Session::install_offsets`].
    pub fn install_copy_offsets(&mut self, table: &CopyOffsets) -> Result<(), SessionError> {
        validate_copy_offsets(table)?;
        let bytes = encode_copy_offsets(table);
        self.map_write(MAP_COPY_OFFS, 0, &bytes)?;
        let back = self.map_read(MAP_COPY_OFFS, 0, bytes.len())?;
        if back.len() != bytes.len() {
            return Err(SessionError::Offsets(
                "copy offsets verify short".to_owned(),
            ));
        }
        if back.as_slice() != bytes.as_slice() {
            return Err(SessionError::Offsets(
                "copy offsets verify mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Write the copy fallback armed slot; exactly 1 arms the exit.
    pub fn set_copy_armed(&mut self, armed: bool) -> Result<(), SessionError> {
        let value = if armed { 1u64 } else { 0u64 };
        self.map_write(MAP_COPY_FB, FB_ARMED_KEY, &value.to_le_bytes())
    }

    /// Read the six `mv_counts` counters in key order.
    pub fn read_counters(&self) -> Result<[u64; 6], SessionError> {
        let mut out = [0u64; 6];
        for (slot, key) in (0..COUNT_KEYS).enumerate() {
            let bytes = self.map_read(MAP_COUNTS, key, 8)?;
            if bytes.len() != 8 {
                return Err(SessionError::Map("short counter read".to_owned()));
            }
            // The length check above makes this conversion infallible.
            out[slot] = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
        }
        Ok(out)
    }

    /// Read the three copy fallback slots (deferred, recovered, flags).
    pub fn read_copy_fb(&self) -> Result<[u64; 3], SessionError> {
        let mut out = [0u64; 3];
        for (slot, key) in (0..FB_KEYS).enumerate() {
            let bytes = self.map_read(MAP_COPY_FB, key, 8)?;
            if bytes.len() != 8 {
                return Err(SessionError::Map("short fallback read".to_owned()));
            }
            // The length check above makes this conversion infallible.
            out[slot] = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
        }
        Ok(out)
    }

    /// Detach every link in reverse attach order, aggregating failures.
    /// Detaching a session with no links succeeds, so unconditional
    /// teardown stays clean.
    pub fn detach(&mut self) -> Result<(), SessionError> {
        if self.closed {
            return Err(SessionError::NotOpen("session not open".to_owned()));
        }
        let Some(bpf) = self.bpf.as_mut() else {
            return Ok(());
        };
        let links = std::mem::take(&mut self.links);
        let mut errors = Vec::new();
        for link in links.into_iter().rev() {
            if let Err(error) = detach_link(bpf, link) {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SessionError::Attach(errors.join("; ")))
        }
    }

    /// Release everything. Idempotent: closing a never-loaded or already
    /// closed session succeeds.
    pub fn close(&mut self) -> Result<(), SessionError> {
        if self.closed {
            return Ok(());
        }
        let result = self.detach();
        self.bpf = None;
        self.consumer = None;
        self.closed = true;
        result
    }
}

/// Load and attach one site, returning its link. A program an earlier
/// attach in this session loaded (rollback or detach leaves loads behind)
/// skips the load when the recorded site matches.
fn attach_one(
    bpf: &mut Ebpf,
    channel: Channel,
    spec: &AttachSpec,
    btf: &mut Option<Btf>,
    loaded: &mut LoadedMap,
) -> Result<ActiveLink, String> {
    let tag = format!("{} channel program `{}`", channel, spec.program);
    let Some(raw) = bpf.program_mut(&spec.program) else {
        return Err(format!("{tag}: program not in object"));
    };
    match spec.kind {
        AttachKind::Tracepoint => {
            if spec.target_a.is_empty() || spec.target_b.is_empty() {
                return Err(format!("{tag}: tracepoint needs a category and an event"));
            }
            let typed: &mut TracePoint = raw
                .try_into()
                .map_err(|_| format!("{tag}: not a tracepoint program"))?;
            match typed.load() {
                Ok(()) => note_loaded(loaded, spec),
                Err(ProgramError::AlreadyLoaded) => check_loaded(loaded, spec, &tag)?,
                Err(error) => return Err(format!("{tag}: load failed: {error}")),
            }
            let id = typed
                .attach(&spec.target_a, &spec.target_b)
                .map_err(|error| {
                    format!(
                        "{tag}: attach to {}:{} failed: {error}",
                        spec.target_a, spec.target_b
                    )
                })?;
            Ok(ActiveLink::TracePoint {
                program: spec.program.clone(),
                id,
            })
        }
        AttachKind::FEntry | AttachKind::FExit => {
            if spec.target_a.is_empty() {
                return Err(format!("{tag}: tracing attach needs a kernel function"));
            }
            if !spec.target_b.is_empty() {
                return Err(format!("{tag}: tracing attach takes no second target"));
            }
            if btf.is_none() {
                *btf = Some(Btf::from_sys_fs().map_err(|error| {
                    format!(
                        "{tag}: kernel BTF unavailable for {}: {error}",
                        spec.target_a
                    )
                })?);
            }
            // `btf` is `Some` here: just loaded, or loaded by an earlier site.
            let kernel_btf = btf.as_ref().expect("kernel BTF loaded");
            if spec.kind == AttachKind::FEntry {
                let typed: &mut FEntry = raw
                    .try_into()
                    .map_err(|_| format!("{tag}: not an fentry program"))?;
                match typed.load(&spec.target_a, kernel_btf) {
                    Ok(()) => note_loaded(loaded, spec),
                    Err(ProgramError::AlreadyLoaded) => check_loaded(loaded, spec, &tag)?,
                    Err(error) => {
                        return Err(format!("{tag}: load for {} failed: {error}", spec.target_a));
                    }
                }
                let id = typed.attach().map_err(|error| {
                    format!("{tag}: attach to {} failed: {error}", spec.target_a)
                })?;
                Ok(ActiveLink::FEntry {
                    program: spec.program.clone(),
                    id,
                })
            } else {
                let typed: &mut FExit = raw
                    .try_into()
                    .map_err(|_| format!("{tag}: not an fexit program"))?;
                match typed.load(&spec.target_a, kernel_btf) {
                    Ok(()) => note_loaded(loaded, spec),
                    Err(ProgramError::AlreadyLoaded) => check_loaded(loaded, spec, &tag)?,
                    Err(error) => {
                        return Err(format!("{tag}: load for {} failed: {error}", spec.target_a));
                    }
                }
                let id = typed.attach().map_err(|error| {
                    format!("{tag}: attach to {} failed: {error}", spec.target_a)
                })?;
                Ok(ActiveLink::FExit {
                    program: spec.program.clone(),
                    id,
                })
            }
        }
    }
}

/// All present channel sessions: attempt plus optional lifecycle/copy.
pub struct Channels {
    attempt: Session,
    lifecycle: Option<Session>,
    copy: Option<Session>,
}

impl Channels {
    /// Bundle one attempt session with optional lifecycle/copy sessions.
    pub fn new(attempt: Session, lifecycle: Option<Session>, copy: Option<Session>) -> Self {
        Self {
            attempt,
            lifecycle,
            copy,
        }
    }

    /// True while the attempt session holds links.
    pub fn attempt_attached(&self) -> bool {
        self.attempt.attached()
    }

    /// True while the lifecycle session holds links (absent counts as no).
    pub fn lifecycle_attached(&self) -> bool {
        self.lifecycle.as_ref().is_some_and(Session::attached)
    }

    /// True while the copy session holds links (absent counts as no).
    pub fn copy_attached(&self) -> bool {
        self.copy.as_ref().is_some_and(Session::attached)
    }

    /// Attach every present channel inner-first ([`ATTACH_ORDER`]), or none:
    /// a failed channel detaches the channels this call attached, in
    /// reverse, and the error names every failure.
    pub fn attach_all(&mut self, tp_system: &str, tp_event: &str) -> Result<(), SessionError> {
        use super::attach::attempt_specs;
        self.attach_all_with(&attempt_specs(tp_system, tp_event))
    }

    /// [`Channels::attach_all`] with explicit attempt specs (the attempt
    /// site comes from the profile; lifecycle and copy stay frozen).
    pub fn attach_all_with(&mut self, attempt: &[AttachSpec]) -> Result<(), SessionError> {
        use super::attach::{copy_specs, lifecycle_specs};
        let mut done: Vec<Channel> = Vec::new();
        for channel in ATTACH_ORDER {
            let result = match channel {
                Channel::Attempt => self.attempt.attach(attempt),
                Channel::Lifecycle => match self.lifecycle.as_mut() {
                    Some(session) => session.attach(&lifecycle_specs()),
                    None => continue,
                },
                Channel::Copy => match self.copy.as_mut() {
                    Some(session) => session.attach(&copy_specs()),
                    None => continue,
                },
            };
            match result {
                Ok(()) => done.push(channel),
                Err(error) => return Err(self.rollback(done, channel, error)),
            }
        }
        Ok(())
    }

    /// Detach the channels of a failed [`Channels::attach_all`] in reverse
    /// completion order, folding rollback failures into the message.
    fn rollback(
        &mut self,
        done: Vec<Channel>,
        failed: Channel,
        error: SessionError,
    ) -> SessionError {
        let mut message = format!("ch{} {error}", failed.index());
        for channel in done.iter().rev() {
            // `done` only records channels this call attached, so a
            // missing session is unreachable; degrade to a message
            // rather than panicking out of error handling.
            let session = match channel {
                Channel::Attempt => Some(&mut self.attempt),
                Channel::Lifecycle => self.lifecycle.as_mut(),
                Channel::Copy => self.copy.as_mut(),
            };
            let Some(session) = session else {
                message.push_str(&format!("; rollback ch{}: session absent", channel.index()));
                continue;
            };
            if let Err(error) = session.detach() {
                message.push_str(&format!("; rollback ch{}: {error}", channel.index()));
            }
        }
        SessionError::Attach(message)
    }

    /// Detach every present channel outer-first ([`DETACH_ORDER`]),
    /// attempting each channel and reporting all failures.
    pub fn detach_all(&mut self) -> Result<(), SessionError> {
        let mut failed = false;
        let mut message = String::new();
        for channel in DETACH_ORDER {
            let session = match channel {
                Channel::Attempt => Some(&mut self.attempt),
                Channel::Lifecycle => self.lifecycle.as_mut(),
                Channel::Copy => self.copy.as_mut(),
            };
            let Some(session) = session else {
                continue;
            };
            if let Err(error) = session.detach() {
                failed = true;
                if !message.is_empty() {
                    message.push_str("; ");
                }
                message.push_str(&format!("ch{} {error}", channel.index()));
            }
        }
        if failed {
            Err(SessionError::Attach(message))
        } else {
            Ok(())
        }
    }

    /// Close every present channel; see [`Session::close`].
    pub fn close_all(&mut self) -> Result<(), SessionError> {
        let mut failed = false;
        let mut message = String::new();
        for channel in DETACH_ORDER {
            let session = match channel {
                Channel::Attempt => Some(&mut self.attempt),
                Channel::Lifecycle => self.lifecycle.as_mut(),
                Channel::Copy => self.copy.as_mut(),
            };
            let Some(session) = session else {
                continue;
            };
            if let Err(error) = session.close() {
                failed = true;
                if !message.is_empty() {
                    message.push_str("; ");
                }
                message.push_str(&format!("ch{} {error}", channel.index()));
            }
        }
        if failed {
            Err(SessionError::Attach(message))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal 64-bit BPF ELF header with caller-chosen section-table
    /// fields; the body is zeros.
    fn elf_header(shoff: u64, shentsize: u16, shnum: u16, shstrndx: u16) -> Vec<u8> {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // 64-bit.
        elf[18..20].copy_from_slice(&247u16.to_le_bytes()); // EM_BPF.
        elf[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        elf[0x3a..0x3c].copy_from_slice(&shentsize.to_le_bytes());
        elf[0x3c..0x3e].copy_from_slice(&shnum.to_le_bytes());
        elf[0x3e..0x40].copy_from_slice(&shstrndx.to_le_bytes());
        elf
    }

    #[test]
    fn core_precondition_probes_relocations_once() {
        // The relocation probe reads the real fixtures: the C copy
        // object carries relocations, the attempt object does not,
        // and unparseable bytes report none (the loader judges
        // those itself). The sysfs read outcome stays consistent:
        // parsed BTF and a read errno never coexist.
        let dir = crate::platform::test_support::repo_root().join("tests/fixtures/elf");
        let cp = std::fs::read(dir.join("cp-ok.o")).expect("read cp-ok.o");
        let pre = core_precondition(&cp);
        assert!(pre.relocations, "cp-ok.o must carry relocations");
        assert_eq!(pre.btf.is_some(), pre.read_errno.is_none());
        let attempt = std::fs::read(dir.join("ok.o")).expect("read ok.o");
        let pre = core_precondition(&attempt);
        assert!(!pre.relocations, "ok.o must be relocation-free");
        assert_eq!(pre.btf.is_some(), pre.read_errno.is_none());
        let pre = core_precondition(b"not an elf");
        assert!(!pre.relocations, "garbage must report no relocations");
        assert_eq!(pre.btf.is_some(), pre.read_errno.is_none());
    }

    #[test]
    fn core_guard_refuses_relocations_without_btf() {
        // A relocation-carrying object refuses when sysfs BTF is
        // unreadable, naming BTF; readable BTF passes through to
        // the loader, as do relocation-free objects. The fixture
        // parse stays real; only the sysfs outcome is staged.
        let dir = crate::platform::test_support::repo_root().join("tests/fixtures/elf");
        let cp = std::fs::read(dir.join("cp-ok.o")).expect("read cp-ok.o");
        let mut pre = core_precondition(&cp);
        pre.btf = None;
        pre.read_errno = Some(2);
        let error = check_core_btf(&pre, Channel::Copy).expect_err("must refuse without BTF");
        assert!(
            error.to_string().contains("BTF"),
            "refusal must name BTF, got: {error}"
        );
        let pre = core_precondition(&cp);
        if pre.btf.is_some() {
            assert!(check_core_btf(&pre, Channel::Copy).is_ok());
        }
        let attempt = std::fs::read(dir.join("ok.o")).expect("read ok.o");
        let mut pre = core_precondition(&attempt);
        pre.btf = None;
        pre.read_errno = Some(2);
        assert!(check_core_btf(&pre, Channel::Attempt).is_ok());
    }

    #[test]
    fn poll_refuses_before_load_and_after_close() {
        // The pinned-consumer gate: an opened session refuses poll
        // until load pins the consumer, and a closed session refuses
        // as not-open. Unprivileged: no load, no ring, no waiting.
        let path = env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH");
        let bytes = std::fs::read(path).expect("read attempt ELF");
        let mut session = Session::open(&bytes, "mv_attempts").expect("open");
        let error = session.poll(0).expect_err("unloaded poll must refuse");
        assert!(
            matches!(error, SessionError::NotLoaded(_)),
            "want NotLoaded refusal, got: {error}"
        );
        session.close().expect("close");
        let error = session.poll(0).expect_err("closed poll must refuse");
        assert!(
            matches!(error, SessionError::NotOpen(_)),
            "want NotOpen refusal, got: {error}"
        );
    }

    #[test]
    fn malicious_shoff_refuses_without_panic() {
        // shstr index arithmetic overflows: shoff near u64::MAX plus a
        // nonzero shstrndx stride. Plain `+`/`*` panics here in debug.
        let elf = elf_header(u64::MAX - 32, 64, 2, 1);
        let error = Session::open(&elf, "mv_attempts").expect_err("overflowing shstr must refuse");
        assert!(
            matches!(error, SessionError::Open(_)),
            "want Open refusal, got: {error}"
        );
        // shstr base itself at u64::MAX: the +24/+32 field reads must
        // refuse, not panic in debug builds.
        let elf = elf_header(u64::MAX, 64, 1, 0);
        let error = Session::open(&elf, "mv_attempts").expect_err("max shoff must refuse");
        assert!(
            matches!(error, SessionError::Open(_)),
            "want Open refusal, got: {error}"
        );
        // A merely out-of-range (non-overflowing) table refuses the same way.
        let elf = elf_header(0x1000, 64, 1, 0);
        let error = Session::open(&elf, "mv_attempts").expect_err("past-EOF table must refuse");
        assert!(
            matches!(error, SessionError::Open(_)),
            "want Open refusal, got: {error}"
        );
    }
}
