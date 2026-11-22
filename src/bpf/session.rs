// SPDX-License-Identifier: GPL-3.0-or-later
//! One channel object under Aya: open, load, attach, poll, maps, detach,
//! close. [`Channels`] attaches every present channel inner-first with
//! rollback, mirroring the old kernel source.
//!
//! State machine per session: opened (ELF parsed and sanity-checked) then
//! loaded (kernel maps created, live geometry verified) then attached
//! (programs linked). `close` releases everything and is idempotent;
//! dropping a session releases it too.

use super::attach::{
    ATTACH_ORDER, AttachKind, AttachSpec, DETACH_ORDER, attempt_specs, copy_specs, lifecycle_specs,
};
use super::maps::{BPF_MAP_TYPE_RINGBUF, MapGeometry, MapSpec, check_maps_loaded, expected_maps};
use super::offsets::{encode_copy_offsets, validate_copy_offsets};
use super::poll::{Frame, Stats, decode_frame, open_consumer};
use crate::capture::loadcheck::{
    clean_cause_line, errno_from_chain, verifier_log_from_error, verifier_tail,
};
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

/// One object-controlled name rendered into refusal text.
///
/// Keeps the producer's own alphabet (`[A-Za-z0-9_.-]`, which
/// covers every frozen map and program name) and replaces any
/// other byte with `?`: a renegade name can neither smuggle
/// whitespace, separators, or header grammar into the refusal
/// line nor break it into lines. Byte-wise, so the output is
/// always valid UTF-8 whatever the object declared.
pub(crate) fn refusal_name(name: &str) -> String {
    let mut out = Vec::with_capacity(name.len());
    for b in name.as_bytes() {
        let keep = b.is_ascii_alphanumeric() || *b == 0x5F || *b == 0x2E || *b == 0x2D;
        out.push(if keep { *b } else { 0x3F });
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Neutralize refusal grammar in loader-derived text.
///
/// Aya embeds object-controlled names inseparably in its error
/// Displays (a missing map symbol, a relocation symbol, a map
/// name), and one loader Display can even forge the verifier
/// marker itself — so a hostile name reaches the structural cause
/// and the log-slot render as free text. Both downstream readers
/// take narrow tokens: the refusal classifier needs a literal
/// `op=` key, and the errno scan needs the literal `(os error `
/// marker. Replacing `=` and breaking that marker leaves neither
/// channel formable, whatever the name carries — while genuine
/// loader text passes through byte-identical: no fixed Aya,
/// object-crate, or strerror text contains `=` (audited across
/// the pinned crates), and a genuine `(os error N)` marker exists
/// only beside an io errno, whose failures render through the
/// errno branch instead of this text. Apply last, after cleaning
/// and joining.
fn neutralize_refusal_grammar(text: &str) -> String {
    text.replace('=', "?").replace("(os error ", "(os error? ")
}

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
/// the same site. A siteless tracepoint load (from verifier-only
/// loading, which takes no site) is claimed by any tracepoint
/// site: the loaded binary is site-independent and the attach
/// names its site explicitly, so no confusion is possible.
fn check_loaded(loaded: &LoadedMap, spec: &AttachSpec, tag: &str) -> Result<(), String> {
    match loaded.get(&spec.program) {
        Some((kind, target_a, target_b))
            if *kind == spec.kind && *target_a == spec.target_a && *target_b == spec.target_b =>
        {
            Ok(())
        }
        Some((AttachKind::Tracepoint, target_a, target_b))
            if spec.kind == AttachKind::Tracepoint
                && target_a.is_empty()
                && target_b.is_empty() =>
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

/// Declared map rows from one ELF, or `None` when the object does
/// not parse. `None` passes through to the loader, which parses
/// before creating anything, so a skipped pre-check can never
/// allocate.
pub(crate) fn declared_map_specs(elf: &[u8]) -> Option<Vec<MapSpec>> {
    let object = aya_obj::Object::parse(elf).ok()?;
    let mut specs = Vec::new();
    for (name, map) in object.maps.iter() {
        specs.push(MapSpec {
            name: name.clone(),
            map_type: map.map_type(),
            key_size: map.key_size(),
            value_size: map.value_size(),
            max_entries: map.max_entries(),
        });
    }
    Some(specs)
}

/// True when the ELF declares the host-resolved copy table map
/// (`mv_copy_offs`): the Aya copy family, whose record path
/// resolves and installs the table between load and attach. The
/// loader creates exactly the declared maps and the load gate
/// enforces the exact family set, so declared presence matches
/// the live `has_map` record checks. Unparseable objects report
/// false; the loader judges them.
pub(crate) fn declares_copy_table(elf: &[u8]) -> bool {
    declared_map_specs(elf).is_some_and(|specs| specs.iter().any(|row| row.name == MAP_COPY_OFFS))
}

/// Host page size in bytes; 4096 when the query fails.
pub(crate) fn host_page_size() -> u32 {
    // SAFETY: sysconf with a valid name; -1 means unknown.
    let got = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if got > 0 {
        u32::try_from(got).unwrap_or(4096)
    } else {
        4096
    }
}

/// Effective ring bytes the loader will request for a declared
/// size: page count rounded up to a power of two, times the page
/// size. Mirrors aya's `adjust_to_page_size` (which mirrors
/// libbpf); `u64` with a saturating multiply, so a hostile
/// declaration refuses instead of overflowing.
fn effective_ring_bytes(declared: u32, page_size: u32) -> u64 {
    if declared == 0 || page_size == 0 {
        return 0;
    }
    let pages = u64::from(declared.div_ceil(page_size));
    pages
        .next_power_of_two()
        .saturating_mul(u64::from(page_size))
}

/// Frozen ring ceiling for one channel. Every channel carries
/// exactly one ring; a missing row refuses everything.
fn frozen_ring_ceiling(channel: Channel) -> u32 {
    expected_maps(channel)
        .iter()
        .find(|row| row.map_type == BPF_MAP_TYPE_RINGBUF)
        .map(|row| row.max_entries)
        .unwrap_or(0)
}

/// Largest frozen ring ceiling across channels: the abuse cap for
/// loads that cannot know the channel.
pub(crate) fn max_frozen_ring_bytes() -> u32 {
    [Channel::Attempt, Channel::Lifecycle, Channel::Copy]
        .iter()
        .map(|channel| frozen_ring_ceiling(*channel))
        .max()
        .unwrap_or(0)
}

/// Pre-load map gate: the declared geometry must already satisfy
/// the load-time rule ([`check_maps_loaded`]: rings upper-bounded
/// so smaller admitted rings pass, both copy families admitted),
/// before the loader allocates. No separate effective-size rule:
/// the load-time rule bounds every declared ring by the frozen
/// ceiling, every frozen ceiling is pow2 x page, and rounding a
/// sub-ceiling declaration up to pow2 x page cannot cross the
/// ceiling — so any declaration passing here also fits after the
/// loader's rounding, and a second loop could never fire. The
/// live read-back gate after loading stays. Diagnostic replays
/// share this exact rule through [`check_replay_maps`].
pub(crate) fn check_declared_maps(
    channel: Channel,
    declared: &[MapSpec],
) -> Result<(), SessionError> {
    check_maps_loaded(channel, declared)
}

/// Channel owning every named program, when the names agree on
/// exactly one. Diagnostic replays resolve their channel this
/// way: every caller passes one channel's frozen program set, so
/// a replay gates exactly what its session's normal path would.
/// Empty, unknown, or mixed sets yield `None` and the replay
/// keeps the ring abuse cap.
pub(crate) fn channel_for_programs(programs: &[String]) -> Option<Channel> {
    use super::attach::expected_programs;
    if programs.is_empty() {
        return None;
    }
    let mut found = None;
    for channel in [Channel::Attempt, Channel::Lifecycle, Channel::Copy] {
        let expected = expected_programs(channel);
        let names: Vec<&str> = expected.iter().map(|spec| spec.name.as_str()).collect();
        if !programs.iter().all(|name| names.contains(&name.as_str())) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(channel);
    }
    found
}

/// Replay geometry gate: the same declared-map rule as the normal
/// path ([`check_declared_maps`]) for a replay that names its
/// channel. The verdict's CO-RE check returns before the declared
/// gate, so a BTF outage at verdict time can send a renegade
/// object to replay; if BTF reads again there, a ring-only check
/// would let an oversized non-ring map reach the loader. A replay
/// that cannot name its channel keeps the ring abuse cap.
pub(crate) fn check_replay_maps(
    channel: Option<Channel>,
    declared: &[MapSpec],
) -> Result<(), SessionError> {
    match channel {
        Some(channel) => check_declared_maps(channel, declared),
        None => {
            if replay_rings_fit(declared) {
                Ok(())
            } else {
                Err(SessionError::Geometry(
                    "replay refused: ring declaration exceeds the frozen ceiling".to_owned(),
                ))
            }
        }
    }
}

/// True when every declared ring fits the largest frozen
/// ceiling. The fallback for a diagnostic replay that cannot
/// name its channel; channel-naming replays enforce the precise
/// per-channel rule through [`check_replay_maps`] instead.
pub(crate) fn replay_rings_fit(declared: &[MapSpec]) -> bool {
    let ceiling = u64::from(max_frozen_ring_bytes());
    let page = host_page_size();
    declared
        .iter()
        .filter(|row| row.map_type == BPF_MAP_TYPE_RINGBUF)
        .all(|row| effective_ring_bytes(row.max_entries, page) <= ceiling)
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
            "map `{}`: unsupported map type for info",
            refusal_name(name)
        ))),
    }
}

/// Live geometry of one loaded map.
fn live_geometry(map: &Map, name: &str) -> Result<MapGeometry, SessionError> {
    let data = array_data(map, name)?;
    let info = data.info().map_err(|error| {
        SessionError::Map(format!("map `{}` info failed: {error}", refusal_name(name)))
    })?;
    let map_type = info.map_type().map_err(|error| {
        SessionError::Map(format!("map `{}` info failed: {error}", refusal_name(name)))
    })?;
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

    /// Load the object: refuse renegade declared maps first (no
    /// allocation), create the kernel maps, then verify live map
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
        // Declared-geometry gate: refuse renegade maps (notably
        // oversized rings) before the loader allocates them.
        if let Some(declared) = declared_map_specs(&self.elf) {
            check_declared_maps(self.channel, &declared)?;
        }
        let mut loader = EbpfLoader::new();
        loader.btf(pre.btf.as_ref());
        // Bounded rendering, shared with program loads: the loader
        // Display carries the full verifier log on BTF failures
        // (`BPF_BTF_LOAD ... Verifier output: ...`), which must
        // never reach the message unredacted.
        let bpf = loader.load(&self.elf).map_err(|error| {
            let failure = load_failed(&error);
            SessionError::Load(format!(
                "{} channel: load failed: {}",
                self.channel,
                load_failure_text(&failure)
            ))
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
                    self.channel,
                    refusal_name(&want.name)
                )));
            };
            let kind = match got {
                Program::TracePoint(_) => AttachKind::Tracepoint,
                Program::FEntry(_) => AttachKind::FEntry,
                Program::FExit(_) => AttachKind::FExit,
                _ => {
                    return Err(SessionError::Geometry(format!(
                        "{} channel: program {} has an unexpected section",
                        self.channel,
                        refusal_name(&want.name)
                    )));
                }
            };
            if kind != want.kind {
                return Err(SessionError::Geometry(format!(
                    "{} channel: program {}: want section {:?}, got {:?}",
                    self.channel,
                    refusal_name(&want.name),
                    want.kind,
                    kind
                )));
            }
        }
        for (name, _) in bpf.programs() {
            if !expected.iter().any(|want| want.name == name) {
                return Err(SessionError::Geometry(format!(
                    "{} channel: unexpected program {}",
                    self.channel,
                    refusal_name(name)
                )));
            }
        }
        Ok(())
    }

    /// Load every channel program without attaching: the verifier
    /// judges each program the way record's attach will. Refuses on
    /// a closed or unloaded session. Loaded programs stay loaded
    /// until close, like attach's; a later attach skips the load per
    /// site. Privileged.
    pub fn load_programs(&mut self) -> Result<(), SessionError> {
        if self.closed {
            return Err(SessionError::NotOpen("session not open".to_owned()));
        }
        let channel = self.channel;
        let specs = match channel {
            Channel::Attempt => attempt_specs("", ""),
            Channel::Lifecycle => lifecycle_specs(),
            Channel::Copy => copy_specs(),
        };
        let Some(bpf) = self.bpf.as_mut() else {
            return Err(SessionError::NotLoaded("session not loaded".to_owned()));
        };
        let mut kernel_btf: Option<Btf> = None;
        for spec in &specs {
            let tag = format!("{channel} channel program `{}`", spec.program);
            if let Err(step) = load_one(bpf, &tag, spec, &mut kernel_btf, &mut self.loaded) {
                return Err(match step {
                    LoadStepError::Refusal { message, .. } => SessionError::Load(message),
                    LoadStepError::Failed(failure) => {
                        SessionError::Load(format_failed_load(&tag, spec, &failure))
                    }
                });
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

/// One kernel load failure (object or program load), split for honest
/// reporting: the syscall errno (when the error chain carries one),
/// the raw verifier log (when the error carries one), plus the
/// bounded structural cause (the chain text relocation and parse
/// failures carry instead of either). Callers shape these parts;
/// nobody formats the full loader Display.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LoadFailure {
    /// Syscall errno from the error chain, if any.
    pub errno: Option<i32>,
    /// Raw verifier log text, if any.
    pub log: Option<String>,
    /// Bounded structural cause from the error chain, if any:
    /// cleaned like one tail line with refusal grammar
    /// neutralized, never the full Display.
    pub cause: Option<String>,
}

/// One program-load step outcome that is not a fresh load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoadStepError {
    /// Static refusal (missing program, wrong section kind,
    /// unreadable BTF, target mismatch): message plus the
    /// underlying errno when one caused it.
    Refusal { message: String, errno: Option<i32> },
    /// Kernel load failure: errno plus raw verifier log.
    Failed(LoadFailure),
}

/// Split one loader error into its failure parts. Shared by object
/// loads ([`Session::load`], where a BTF failure's Display carries
/// the full verifier log) and program loads: Mojo renders no
/// BTF-specific shape (object failures there are errno plus clipped
/// message plus replay tail), so both use the program-load tail —
/// and the clipped chain message below is that clipped message
/// for failures that carry no errno.
fn load_failed(error: &(dyn std::error::Error + 'static)) -> LoadFailure {
    LoadFailure {
        errno: errno_from_chain(error),
        log: verifier_log_from_error(error),
        cause: structural_cause(error),
    }
}

/// Bounded structural cause: every non-empty error-chain
/// Display joined, cleaned like one tail line. The leaf
/// names the failure (an unknown symbol, a bad section);
/// the wrappers name the function or section it struck.
/// Empty when the chain carries nothing printable.
fn structural_cause(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut parts = Vec::new();
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(err) = current {
        let text = err.to_string();
        if !text.is_empty() {
            parts.push(text);
        }
        current = err.source();
    }
    if parts.is_empty() {
        return None;
    }
    let cleaned = clean_cause_line(&parts.join(": "));
    if cleaned.is_empty() {
        return None;
    }
    // The chain text embeds object-controlled names (missing
    // symbols, relocation symbols, map names): neutralize the
    // refusal grammar last so no name forges a classifying
    // segment or errno marker downstream.
    Some(neutralize_refusal_grammar(&cleaned))
}

/// Load context for one spec: tracing loads name their kernel
/// function, tracepoint loads take no site.
fn load_context(spec: &AttachSpec) -> String {
    match spec.kind {
        AttachKind::Tracepoint => String::new(),
        AttachKind::FEntry | AttachKind::FExit => format!(" for {}", spec.target_a),
    }
}

/// User text for a kernel program-load failure: the errno's own
/// strerror plus the `(os error N)` marker the kernel layer parses
/// for refusal classification — never the loader Display, which
/// carries the full verifier log. The bounded redacted tail reaches
/// users through the diagnostic replay instead. Without an errno,
/// the redacted tail of the carried log; without that, the
/// bounded structural cause (relocation and parse failures
/// carry only this); without that, a bare refusal. The log-slot
/// render neutralizes refusal grammar: a genuine verifier log
/// always rides beside its syscall errno, so a log without one
/// is a forged marker inside an object-controlled name.
fn load_failure_text(failure: &LoadFailure) -> String {
    if let Some(raw) = failure.errno {
        return std::io::Error::from_raw_os_error(raw).to_string();
    }
    if let Some(log) = failure.log.as_ref() {
        let tail = verifier_tail(log.as_bytes(), false);
        if !tail.is_empty() {
            return neutralize_refusal_grammar(&tail.join("; "));
        }
    }
    if let Some(cause) = failure.cause.as_deref().filter(|cause| !cause.is_empty()) {
        return cause.to_string();
    }
    "load refused".to_string()
}

/// Full message for a kernel program-load failure.
fn format_failed_load(tag: &str, spec: &AttachSpec, failure: &LoadFailure) -> String {
    format!(
        "{tag}: load{} failed: {}",
        load_context(spec),
        load_failure_text(failure)
    )
}

/// Refuse a spec whose attach targets are unusable, before loading.
fn validate_spec_targets(tag: &str, spec: &AttachSpec) -> Result<(), String> {
    match spec.kind {
        AttachKind::Tracepoint => {
            if spec.target_a.is_empty() || spec.target_b.is_empty() {
                return Err(format!("{tag}: tracepoint needs a category and an event"));
            }
        }
        AttachKind::FEntry | AttachKind::FExit => {
            if spec.target_a.is_empty() {
                return Err(format!("{tag}: tracing attach needs a kernel function"));
            }
            if !spec.target_b.is_empty() {
                return Err(format!("{tag}: tracing attach takes no second target"));
            }
        }
    }
    Ok(())
}

/// Load one program per spec without attaching. A program an
/// earlier load in this session loaded (rollback or detach leaves
/// loads behind) skips the load when the recorded site matches.
fn load_one(
    bpf: &mut Ebpf,
    tag: &str,
    spec: &AttachSpec,
    btf: &mut Option<Btf>,
    loaded: &mut LoadedMap,
) -> Result<(), LoadStepError> {
    let refusal = |message: String, errno: Option<i32>| LoadStepError::Refusal { message, errno };
    let Some(raw) = bpf.program_mut(&spec.program) else {
        return Err(refusal(format!("{tag}: program not in object"), Some(2)));
    };
    match spec.kind {
        AttachKind::Tracepoint => {
            let typed: &mut TracePoint = raw
                .try_into()
                .map_err(|_| refusal(format!("{tag}: not a tracepoint program"), Some(22)))?;
            match typed.load() {
                Ok(()) => note_loaded(loaded, spec),
                Err(ProgramError::AlreadyLoaded) => {
                    check_loaded(loaded, spec, tag).map_err(|message| refusal(message, None))?;
                }
                Err(error) => return Err(LoadStepError::Failed(load_failed(&error))),
            }
        }
        AttachKind::FEntry | AttachKind::FExit => {
            if btf.is_none() {
                let read = Btf::from_sys_fs().map_err(|error| {
                    refusal(
                        format!(
                            "{tag}: kernel BTF unavailable for {}: {error}",
                            spec.target_a
                        ),
                        errno_from_chain(&error),
                    )
                })?;
                *btf = Some(read);
            }
            // `btf` is `Some` here: just loaded, or loaded by an earlier site.
            let kernel_btf = btf.as_ref().expect("kernel BTF loaded");
            if spec.kind == AttachKind::FEntry {
                let typed: &mut FEntry = raw
                    .try_into()
                    .map_err(|_| refusal(format!("{tag}: not an fentry program"), Some(22)))?;
                match typed.load(&spec.target_a, kernel_btf) {
                    Ok(()) => note_loaded(loaded, spec),
                    Err(ProgramError::AlreadyLoaded) => {
                        check_loaded(loaded, spec, tag)
                            .map_err(|message| refusal(message, None))?;
                    }
                    Err(error) => return Err(LoadStepError::Failed(load_failed(&error))),
                }
            } else {
                let typed: &mut FExit = raw
                    .try_into()
                    .map_err(|_| refusal(format!("{tag}: not an fexit program"), Some(22)))?;
                match typed.load(&spec.target_a, kernel_btf) {
                    Ok(()) => note_loaded(loaded, spec),
                    Err(ProgramError::AlreadyLoaded) => {
                        check_loaded(loaded, spec, tag)
                            .map_err(|message| refusal(message, None))?;
                    }
                    Err(error) => return Err(LoadStepError::Failed(load_failed(&error))),
                }
            }
        }
    }
    Ok(())
}

/// Full message for a link failure: the attach site plus the loader
/// Display. The Display alone names only the failed call, so the
/// syscall errno's own text rides along when the error chain
/// carries one — its `(os error N)` marker is what the kernel
/// layer parses for refusal classification. Without an errno the
/// message is the site plus the Display, as before.
pub(crate) fn format_failed_link(tag: &str, spec: &AttachSpec, error: &ProgramError) -> String {
    let site = match spec.kind {
        AttachKind::Tracepoint => format!("attach to {}:{}", spec.target_a, spec.target_b),
        AttachKind::FEntry | AttachKind::FExit => format!("attach to {}", spec.target_a),
    };
    match errno_from_chain(error) {
        Some(raw) => format!(
            "{tag}: {site} failed: {error}: {}",
            std::io::Error::from_raw_os_error(raw)
        ),
        None => format!("{tag}: {site} failed: {error}"),
    }
}

/// Attach one already-loaded program, returning its link.
fn link_one(bpf: &mut Ebpf, tag: &str, spec: &AttachSpec) -> Result<ActiveLink, String> {
    let Some(raw) = bpf.program_mut(&spec.program) else {
        return Err(format!("{tag}: program not in object"));
    };
    match spec.kind {
        AttachKind::Tracepoint => {
            let typed: &mut TracePoint = raw
                .try_into()
                .map_err(|_| format!("{tag}: not a tracepoint program"))?;
            let id = typed
                .attach(&spec.target_a, &spec.target_b)
                .map_err(|error| format_failed_link(tag, spec, &error))?;
            Ok(ActiveLink::TracePoint {
                program: spec.program.clone(),
                id,
            })
        }
        AttachKind::FEntry => {
            let typed: &mut FEntry = raw
                .try_into()
                .map_err(|_| format!("{tag}: not an fentry program"))?;
            let id = typed
                .attach()
                .map_err(|error| format_failed_link(tag, spec, &error))?;
            Ok(ActiveLink::FEntry {
                program: spec.program.clone(),
                id,
            })
        }
        AttachKind::FExit => {
            let typed: &mut FExit = raw
                .try_into()
                .map_err(|_| format!("{tag}: not an fexit program"))?;
            let id = typed
                .attach()
                .map_err(|error| format_failed_link(tag, spec, &error))?;
            Ok(ActiveLink::FExit {
                program: spec.program.clone(),
                id,
            })
        }
    }
}

/// Load and attach one site, returning its link: validate, load the
/// program, then link it. A program an earlier attach in this
/// session loaded (rollback or detach leaves loads behind) skips
/// the load when the recorded site matches.
fn attach_one(
    bpf: &mut Ebpf,
    channel: Channel,
    spec: &AttachSpec,
    btf: &mut Option<Btf>,
    loaded: &mut LoadedMap,
) -> Result<ActiveLink, String> {
    let tag = format!("{} channel program `{}`", channel, spec.program);
    validate_spec_targets(&tag, spec)?;
    if let Err(step) = load_one(bpf, &tag, spec, btf, loaded) {
        return Err(match step {
            LoadStepError::Refusal { message, .. } => message,
            LoadStepError::Failed(failure) => format_failed_load(&tag, spec, &failure),
        });
    }
    link_one(bpf, &tag, spec)
}

/// Frozen spec for one program name, across channels. Load-only
/// lookups need no attach site: tracepoint loads take none, and
/// the tracing specs carry frozen targets.
pub(crate) fn spec_for_program(name: &str) -> Option<AttachSpec> {
    attempt_specs("", "")
        .into_iter()
        .chain(lifecycle_specs())
        .chain(copy_specs())
        .find(|spec| spec.program == name)
}

/// Load named programs on a loaded object without attaching,
/// returning the first failure's parts. Unknown names skip (the
/// object as a whole is judged elsewhere); tracing loads reuse
/// the caller's pre-read BTF and never re-read sysfs.
pub(crate) fn diagnose_program_loads(
    bpf: &mut Ebpf,
    programs: &[String],
    kernel_btf: Option<&Btf>,
    btf_errno: Option<i32>,
) -> Result<(), LoadFailure> {
    let mut specs = Vec::new();
    for name in programs {
        if let Some(spec) = spec_for_program(name) {
            specs.push(spec);
        }
    }
    if kernel_btf.is_none()
        && specs
            .iter()
            .any(|spec| matches!(spec.kind, AttachKind::FEntry | AttachKind::FExit))
    {
        return Err(LoadFailure {
            errno: btf_errno,
            log: None,
            cause: None,
        });
    }
    let mut slot = kernel_btf.cloned();
    let mut loaded = LoadedMap::new();
    for spec in &specs {
        let tag = format!("diagnostic program `{}`", spec.program);
        if let Err(step) = load_one(bpf, &tag, spec, &mut slot, &mut loaded) {
            return Err(match step {
                // Structural refusals without an errno (a target
                // mismatch, unreachable on a fresh replay) default
                // to missing, keeping the replay errno total.
                LoadStepError::Refusal { errno, .. } => LoadFailure {
                    errno: errno.or(Some(2)),
                    log: None,
                    cause: None,
                },
                LoadStepError::Failed(failure) => failure,
            });
        }
    }
    Ok(())
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
    fn load_programs_refuses_before_load_and_after_close() {
        // The load-without-attach gate: an opened session refuses
        // program loads until the maps exist, and a closed session
        // refuses as not-open. Unprivileged: no load, no verifier.
        let path = env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH");
        let bytes = std::fs::read(path).expect("read attempt ELF");
        let mut session = Session::open(&bytes, "mv_attempts").expect("open");
        let error = session
            .load_programs()
            .expect_err("unloaded program load must refuse");
        assert!(
            matches!(error, SessionError::NotLoaded(_)),
            "want NotLoaded refusal, got: {error}"
        );
        session.close().expect("close");
        let error = session
            .load_programs()
            .expect_err("closed program load must refuse");
        assert!(
            matches!(error, SessionError::NotOpen(_)),
            "want NotOpen refusal, got: {error}"
        );
    }

    #[test]
    fn spec_for_program_resolves_frozen_sets() {
        // Every frozen program name resolves to its kind: the
        // tracepoint with no site (loads take none), tracing with
        // frozen kernel targets. Unknown names stay unknown.
        let spec = spec_for_program("mv_swiotlb_attempt").expect("attempt resolves");
        assert_eq!(spec.kind, AttachKind::Tracepoint);
        for (name, kind, target) in [
            ("mv_map_result", AttachKind::FExit, "swiotlb_tbl_map_single"),
            ("mv_unmap", AttachKind::FEntry, "__swiotlb_tbl_unmap_single"),
            ("mv_bounce", AttachKind::FEntry, "swiotlb_bounce"),
            ("mv_bounce_exit", AttachKind::FExit, "swiotlb_bounce"),
            (
                "mv_sync_device",
                AttachKind::FEntry,
                "__swiotlb_sync_single_for_device",
            ),
            (
                "mv_sync_cpu",
                AttachKind::FEntry,
                "__swiotlb_sync_single_for_cpu",
            ),
        ] {
            let spec = spec_for_program(name).unwrap_or_else(|| panic!("{name} resolves"));
            assert_eq!(spec.kind, kind, "{name}");
            assert_eq!(spec.target_a, target, "{name}");
            assert_eq!(spec.target_b, "", "{name}");
        }
        assert_eq!(spec_for_program("mv_bogus"), None);
        assert_eq!(spec_for_program(""), None);
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

    #[test]
    fn effective_ring_bytes_mirrors_loader() {
        // Aya's adjust_to_page_size table at 4 KiB pages, plus the
        // 8388609 case (reads back 16777216 live) and a hostile
        // declaration that must refuse, never overflow.
        for (declared, want) in [
            (0u32, 0u64),
            (1, 4096),
            (4095, 4096),
            (4096, 4096),
            (4097, 8192),
            (8192, 8192),
            (8193, 16384),
            (8_388_608, 8_388_608),
            (8_388_609, 16_777_216),
            (33_554_432, 33_554_432),
        ] {
            assert_eq!(
                effective_ring_bytes(declared, 4096),
                want,
                "declared {declared}"
            );
        }
        let huge = effective_ring_bytes(u32::MAX, 4096);
        assert!(
            huge > u64::from(u32::MAX),
            "hostile declaration must stay huge, got {huge}"
        );
        assert_eq!(effective_ring_bytes(4096, 0), 0);
    }

    fn with_ring(channel: Channel, ring: &str, size: u32) -> Vec<MapSpec> {
        let mut maps = expected_maps(channel);
        let row = maps
            .iter_mut()
            .find(|row| row.name == ring)
            .unwrap_or_else(|| panic!("no {ring} row for {channel}"));
        row.max_entries = size;
        maps
    }

    #[test]
    fn declared_gate_admits_frozen_and_smaller_rings() {
        // Frozen sets load, and smaller rings stay admitted (the
        // saturation `-test` objects carry 4096-byte rings).
        for channel in [Channel::Attempt, Channel::Lifecycle, Channel::Copy] {
            let maps = expected_maps(channel);
            check_declared_maps(channel, &maps).expect("frozen set must pre-pass");
            let ring = match channel {
                Channel::Attempt => "mv_attempts",
                Channel::Lifecycle => "mv_lifecycle",
                Channel::Copy => "mv_copies",
            };
            let maps = with_ring(channel, ring, 4096);
            check_declared_maps(channel, &maps).expect("test ring size must pre-pass");
        }
    }

    #[test]
    fn declared_gate_refuses_oversize_and_drift() {
        // A 2 GiB ring (the upfront parser's ceiling) refuses before
        // any allocation, as do non-pow2 oversize declarations,
        // drifted table geometry, and extra maps. Every refusal
        // names the map.
        let maps = with_ring(Channel::Attempt, "mv_attempts", 2_147_483_648);
        let error = check_declared_maps(Channel::Attempt, &maps)
            .expect_err("2 GiB ring must be refused pre-load");
        assert!(error.to_string().contains("mv_attempts"));
        let maps = with_ring(Channel::Attempt, "mv_attempts", 8_388_609);
        let error = check_declared_maps(Channel::Attempt, &maps)
            .expect_err("rounded oversize ring must be refused pre-load");
        assert!(error.to_string().contains("mv_attempts"));
        let mut maps = expected_maps(Channel::Attempt);
        let row = maps
            .iter_mut()
            .find(|row| row.name == "mv_offsets")
            .expect("offsets row");
        row.value_size = 25;
        let error = check_declared_maps(Channel::Attempt, &maps)
            .expect_err("table drift must be refused pre-load");
        assert!(error.to_string().contains("mv_offsets"));
        let mut maps = expected_maps(Channel::Attempt);
        maps.push(MapSpec {
            name: "mv_extra".to_string(),
            map_type: 2,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
        });
        let error = check_declared_maps(Channel::Attempt, &maps)
            .expect_err("extra map must be refused pre-load");
        assert!(error.to_string().contains("mv_extra"));
    }

    #[test]
    fn declared_gate_admits_both_copy_families() {
        // Aya shape (5 maps with the offsets table) and C shape
        // (4 maps, offsets via CO-RE) both pre-pass, including at
        // the admitted `-test` ring size.
        let aya = expected_maps(Channel::Copy);
        check_declared_maps(Channel::Copy, &aya).expect("aya shape must pre-pass");
        let c = crate::bpf::maps::expected_copy_maps_c();
        check_declared_maps(Channel::Copy, &c).expect("C shape must pre-pass");
        for mut maps in [aya, c] {
            let ring = maps
                .iter_mut()
                .find(|row| row.name == "mv_copies")
                .expect("copy shape carries mv_copies");
            ring.max_entries = 4096;
            check_declared_maps(Channel::Copy, &maps).expect("test ring size must pre-pass");
        }
    }

    #[test]
    fn declared_specs_match_frozen_objects() {
        // The linked objects declare exactly the frozen geometry:
        // every embedded channel pre-passes, and the C-family
        // fixture pre-passes as the copy channel's second family.
        // Unprivileged: parse only, no syscalls but sysconf.
        for (channel, var) in [
            (Channel::Attempt, env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH")),
            (Channel::Lifecycle, env!("DEP_MEMVEIL_EBPF_LIFECYCLE_PATH")),
            (Channel::Copy, env!("DEP_MEMVEIL_EBPF_COPY_PATH")),
        ] {
            let elf = std::fs::read(var).expect("read embedded object");
            let declared = declared_map_specs(&elf).expect("embedded object must parse");
            assert_eq!(declared.len(), expected_maps(channel).len());
            check_declared_maps(channel, &declared).expect("embedded object must pre-pass");
        }
        let dir = crate::platform::test_support::repo_root().join("tests/fixtures/elf");
        let cp = std::fs::read(dir.join("cp-ok.o")).expect("read cp-ok.o");
        let declared = declared_map_specs(&cp).expect("cp-ok.o must parse");
        assert_eq!(declared.len(), 4);
        check_declared_maps(Channel::Copy, &declared).expect("C copy shape must pre-pass");
        assert!(declared_map_specs(b"not an elf").is_none());
    }

    #[test]
    fn load_failure_text_keeps_errno_marker() {
        // With an errno, the text is the errno's own strerror —
        // carrying the `(os error N)` marker the kernel layer
        // parses — and never the loader Display, even when a full
        // verifier log rides along.
        for raw in [13, 22] {
            let failure = LoadFailure {
                errno: Some(raw),
                log: Some("jump out of range\nR2=0xffff888012345678\nmore log\n".to_string()),
                cause: Some("error relocating section".to_string()),
            };
            let text = load_failure_text(&failure);
            assert_eq!(text, std::io::Error::from_raw_os_error(raw).to_string());
            assert!(
                text.contains(&format!("(os error {raw})")),
                "must keep the classification marker, got: {text}"
            );
            assert!(
                !text.contains("ffff"),
                "must never format the carried log, got: {text}"
            );
        }
    }

    #[test]
    fn load_failure_text_redacts_without_errno() {
        // Without an errno, the carried log renders as the bounded
        // redacted tail: at most four lines, kernel addresses
        // replaced, control bytes escaped.
        let failure = LoadFailure {
            errno: None,
            log: Some(
                "1: dropped\n2: dropped\n3: R1=0xffff888012345678\n4: imm=0xFFFFFFFF81234567\n5: ok\n6: ok\n".to_string(),
            ),
            cause: Some("error relocating section".to_string()),
        };
        let text = load_failure_text(&failure);
        assert!(
            !text.contains("ffff8880") && !text.contains("FFFFFFFF"),
            "addresses must redact, got: {text}"
        );
        assert!(text.contains("0xADDR"), "got: {text}");
        assert_eq!(text.split("; ").count(), 4, "got: {text}");
        assert!(
            !text.contains("dropped"),
            "tail keeps four lines, got: {text}"
        );
        let bare = LoadFailure {
            errno: None,
            log: None,
            cause: None,
        };
        assert_eq!(load_failure_text(&bare), "load refused");
        let empty = LoadFailure {
            errno: None,
            log: Some("\n\n".to_string()),
            cause: None,
        };
        assert_eq!(load_failure_text(&empty), "load refused");
    }

    /// Shaped non-loader error echoing the pinned BTF Display
    /// shape (`BTF error: the BPF_BTF_LOAD syscall returned
    /// {io}. Verifier output: {log}`), with or without an errno
    /// source. The split must REJECT it: marker text plus chain
    /// without the genuine `BtfError::LoadError` type fills no
    /// log slot.
    #[derive(Debug)]
    struct BtfLoadShaped {
        errno: Option<std::io::Error>,
        log: String,
    }

    impl std::fmt::Display for BtfLoadShaped {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.errno {
                Some(io) => write!(
                    f,
                    "BTF error: the BPF_BTF_LOAD syscall returned {io}. Verifier output: {}",
                    self.log
                ),
                None => write!(
                    f,
                    "BTF error: the BPF_BTF_LOAD syscall refused. Verifier output: {}",
                    self.log
                ),
            }
        }
    }

    impl std::error::Error for BtfLoadShaped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.errno.as_ref().map(|io| io as _)
        }
    }

    #[test]
    fn object_load_failure_renders_bounded() {
        // The object-load split renders through the same bounded
        // tail as program loads: with an errno, the strerror alone
        // (keeping the classification marker, never the log);
        // without, the redacted 4-line tail. Pointer spellings
        // mirror the program-load test. The errno leg runs a real
        // BTF load failure through the split; the no-errno leg
        // pins the render through the struct, since only genuine
        // `LoadError` values (which always carry the syscall
        // errno) fill the slot.
        let log = "1: dropped\n2: dropped\n3: R1=0xffff888012345678\n4: imm=0xFFFFFFFF81234567\n5: ok\n6: ok\n";
        let error = genuine_btf_load_error(22, log);
        let failure = load_failed(&error);
        assert_eq!(failure.errno, Some(22));
        assert_eq!(failure.log.as_deref(), Some(log));
        let text = load_failure_text(&failure);
        assert_eq!(text, std::io::Error::from_raw_os_error(22).to_string());
        assert!(text.contains("(os error 22)"), "got: {text}");
        assert!(
            !text.contains("ffff") && !text.contains("Verifier output"),
            "must never format the carried log, got: {text}"
        );
        let failure = LoadFailure {
            errno: None,
            log: Some(log.to_string()),
            cause: None,
        };
        let text = load_failure_text(&failure);
        assert!(
            !text.contains("ffff8880") && !text.contains("FFFFFFFF"),
            "addresses must redact, got: {text}"
        );
        assert!(text.contains("0xADDR"), "got: {text}");
        assert_eq!(text.split("; ").count(), 4, "got: {text}");
        assert!(
            !text.contains("dropped"),
            "tail keeps four lines, got: {text}"
        );
    }

    /// Loader-side structural error with the pinned Aya
    /// relocation chain shape (`error relocating section` over
    /// ``error relocating `sec` `` over the detail), carrying
    /// no errno source and no verifier marker. The real
    /// relocation error fields are private, so the test pins
    /// the shape the split reads: the Display chain.
    #[derive(Debug)]
    struct RelocationShaped {
        detail: RelocationDetail,
    }

    #[derive(Debug)]
    struct RelocationDetail {
        section: String,
        leaf: RelocationLeaf,
    }

    #[derive(Debug)]
    struct RelocationLeaf {
        detail: String,
    }

    impl std::fmt::Display for RelocationShaped {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("error relocating section")
        }
    }

    impl std::error::Error for RelocationShaped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.detail)
        }
    }

    impl std::fmt::Display for RelocationDetail {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "error relocating `{}`", self.section)
        }
    }

    impl std::error::Error for RelocationDetail {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.leaf)
        }
    }

    impl std::fmt::Display for RelocationLeaf {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.detail)
        }
    }

    impl std::error::Error for RelocationLeaf {}

    fn relocation_shaped(section: &str, detail: &str) -> RelocationShaped {
        RelocationShaped {
            detail: RelocationDetail {
                section: section.to_string(),
                leaf: RelocationLeaf {
                    detail: detail.to_string(),
                },
            },
        }
    }

    #[test]
    fn relocation_failure_renders_structural_cause() {
        // Aya CO-RE relocation errors carry neither errno nor
        // verifier text: the renderer keeps their bounded
        // structural cause instead of degrading to `load
        // refused`. `NoBTF` is a real loader-side structural
        // error with the same shape (no source at all); the
        // shaped chain pins the relocation join.
        let failure = load_failed(&aya::EbpfError::NoBTF);
        assert_eq!(failure.errno, None);
        assert_eq!(failure.log, None);
        assert_eq!(failure.cause.as_deref(), Some("no BTF parsed for object"));
        assert_eq!(load_failure_text(&failure), "no BTF parsed for object");
        let shaped = relocation_shaped("mv_prog", "unknown symbol, index `5`");
        let failure = load_failed(&shaped);
        assert_eq!(failure.errno, None);
        assert_eq!(failure.log, None);
        assert_eq!(
            failure.cause.as_deref(),
            Some("error relocating section: error relocating `mv_prog`: unknown symbol, index `5`")
        );
        assert_eq!(
            load_failure_text(&failure),
            "error relocating section: error relocating `mv_prog`: unknown symbol, index `5`"
        );
    }

    #[test]
    fn structural_cause_is_bounded_and_redacted() {
        // The cause is one cleaned line: a hostile detail clips
        // at the tail line cap, kernel addresses redact, and
        // control bytes escape — never the full Display.
        let shaped = relocation_shaped("mv_prog", &"y".repeat(500));
        let failure = load_failed(&shaped);
        let cause = failure.cause.expect("a relocation cause");
        assert!(cause.len() <= 256, "cause must clip, got {}", cause.len());
        assert!(
            cause.starts_with("error relocating section: "),
            "got: {cause}"
        );
        let shaped = relocation_shaped("mv_prog", "stuck at 0xffff888012345678\nnext");
        let failure = load_failed(&shaped);
        let text = load_failure_text(&failure);
        assert!(!text.contains("ffff8880"), "got: {text}");
        assert!(text.contains("0xADDR"), "got: {text}");
        assert!(!text.contains('\n'), "got: {text:?}");
        assert!(text.contains("\\n"), "got: {text:?}");
    }

    #[test]
    fn failed_load_message_shape() {
        // Tracepoint loads name no site; tracing loads name their
        // kernel function. Both carry the errno marker.
        let tag = "attempt channel program `mv_swiotlb_attempt`";
        let spec = AttachSpec::new("mv_swiotlb_attempt", AttachKind::Tracepoint, "s", "e");
        let failure = LoadFailure {
            errno: Some(22),
            log: Some("jump out of range\n".to_string()),
            cause: None,
        };
        let message = format_failed_load(tag, &spec, &failure);
        assert!(
            message.starts_with(&format!("{tag}: load failed: ")),
            "got: {message}"
        );
        assert!(message.contains("(os error 22)"), "got: {message}");
        assert!(!message.contains("jump out of range"), "got: {message}");
        let tag = "lifecycle channel program `mv_unmap`";
        let spec = AttachSpec::new(
            "mv_unmap",
            AttachKind::FEntry,
            "__swiotlb_tbl_unmap_single",
            "",
        );
        let failure = LoadFailure {
            errno: Some(13),
            log: None,
            cause: None,
        };
        let message = format_failed_load(tag, &spec, &failure);
        assert!(
            message.starts_with(&format!(
                "{tag}: load for __swiotlb_tbl_unmap_single failed: "
            )),
            "got: {message}"
        );
        assert!(message.contains("(os error 13)"), "got: {message}");
    }

    #[test]
    fn check_loaded_claims_siteless_tracepoint() {
        // Same-site claims pass; a siteless tracepoint load (from
        // verifier-only loading) is claimed by any tracepoint
        // site. Sited mismatches and tracing mismatches refuse.
        let mut loaded = LoadedMap::new();
        let tag = "attempt channel program `mv_swiotlb_attempt`";
        let siteless = AttachSpec::new("mv_swiotlb_attempt", AttachKind::Tracepoint, "", "");
        note_loaded(&mut loaded, &siteless);
        let sited = AttachSpec::new("mv_swiotlb_attempt", AttachKind::Tracepoint, "s", "e");
        assert!(check_loaded(&loaded, &sited, tag).is_ok());
        assert!(check_loaded(&loaded, &siteless, tag).is_ok());
        let mut loaded = LoadedMap::new();
        note_loaded(&mut loaded, &sited);
        let other = AttachSpec::new("mv_swiotlb_attempt", AttachKind::Tracepoint, "s", "x");
        assert!(check_loaded(&loaded, &other, tag).is_err());
        let mut loaded = LoadedMap::new();
        let entry = AttachSpec::new("mv_unmap", AttachKind::FEntry, "fn_a", "");
        note_loaded(&mut loaded, &entry);
        let other = AttachSpec::new("mv_unmap", AttachKind::FEntry, "fn_b", "");
        assert!(check_loaded(&loaded, &other, tag).is_err());
        assert!(check_loaded(&loaded, &entry, tag).is_ok());
    }

    #[test]
    fn validate_spec_targets_matrix() {
        // Every refusal text the attach path ever emitted stays
        // byte-identical under the split.
        let tag = "attempt channel program `mv_swiotlb_attempt`";
        let spec = AttachSpec::new("mv_swiotlb_attempt", AttachKind::Tracepoint, "s", "e");
        assert!(validate_spec_targets(tag, &spec).is_ok());
        let spec = AttachSpec::new("mv_swiotlb_attempt", AttachKind::Tracepoint, "", "e");
        assert_eq!(
            validate_spec_targets(tag, &spec),
            Err(format!("{tag}: tracepoint needs a category and an event"))
        );
        let spec = AttachSpec::new("mv_unmap", AttachKind::FEntry, "fn", "");
        assert!(validate_spec_targets(tag, &spec).is_ok());
        let spec = AttachSpec::new("mv_unmap", AttachKind::FEntry, "", "");
        assert_eq!(
            validate_spec_targets(tag, &spec),
            Err(format!("{tag}: tracing attach needs a kernel function"))
        );
        let spec = AttachSpec::new("mv_unmap", AttachKind::FEntry, "fn", "x");
        assert_eq!(
            validate_spec_targets(tag, &spec),
            Err(format!("{tag}: tracing attach takes no second target"))
        );
    }

    #[test]
    fn replay_rings_fit_caps_abuse() {
        // The channel-blind replay cap admits every frozen ring
        // and refuses gigabyte-scale declarations.
        assert_eq!(max_frozen_ring_bytes(), 33_554_432);
        for channel in [Channel::Attempt, Channel::Lifecycle, Channel::Copy] {
            assert!(replay_rings_fit(&expected_maps(channel)));
        }
        assert!(replay_rings_fit(&crate::bpf::maps::expected_copy_maps_c()));
        let maps = with_ring(Channel::Attempt, "mv_attempts", 2_147_483_648);
        assert!(!replay_rings_fit(&maps));
    }

    #[test]
    fn declares_copy_table_matches_family() {
        // The embedded Aya copy object declares the host-resolved
        // table; the attempt object, the C-family copy fixture
        // (offsets via CO-RE), and garbage do not.
        let copy = std::fs::read(env!("DEP_MEMVEIL_EBPF_COPY_PATH")).expect("read copy ELF");
        assert!(declares_copy_table(&copy));
        let attempt =
            std::fs::read(env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH")).expect("read attempt ELF");
        assert!(!declares_copy_table(&attempt));
        let dir = crate::platform::test_support::repo_root().join("tests/fixtures/elf");
        let cp = std::fs::read(dir.join("cp-ok.o")).expect("read cp-ok.o");
        assert!(!declares_copy_table(&cp));
        assert!(!declares_copy_table(b"not an elf"));
    }

    #[test]
    fn refusal_name_constrains_to_the_producer_alphabet() {
        // Frozen names pass through byte-identical; everything
        // outside [A-Za-z0-9_.-] becomes '?', so a renegade name
        // carries no whitespace, separators, or header grammar.
        assert_eq!(refusal_name("mv_counts"), "mv_counts");
        assert_eq!(refusal_name("mv_bounce"), "mv_bounce");
        assert_eq!(refusal_name("a-b.c_d9"), "a-b.c_d9");
        assert_eq!(
            refusal_name("fooch2 op=3 domain=2 code=-13: x"),
            "fooch2?op?3?domain?2?code?-13??x"
        );
        assert_eq!(
            refusal_name("extra\nch0 op=2 domain=2 code=-1: x"),
            "extra?ch0?op?2?domain?2?code?-1??x"
        );
        assert_eq!(
            refusal_name("extra: ch2 note code=-13"),
            "extra??ch2?note?code?-13"
        );
        // Byte-wise: non-ASCII input still renders valid
        // UTF-8, one '?' per byte ('é' is two bytes).
        assert_eq!(refusal_name("mv_é"), "mv_??");
        assert_eq!(refusal_name(""), "");
    }

    #[test]
    fn channel_for_programs_resolves_frozen_sets() {
        // One channel's frozen program set — the shape every
        // replay caller passes — resolves to that channel.
        use crate::bpf::attach::expected_programs;
        for channel in [Channel::Attempt, Channel::Lifecycle, Channel::Copy] {
            let names: Vec<String> = expected_programs(channel)
                .iter()
                .map(|spec| spec.name.clone())
                .collect();
            assert_eq!(channel_for_programs(&names), Some(channel));
            // A lone program resolves too.
            assert_eq!(channel_for_programs(&names[..1]), Some(channel));
        }
        // Empty, unknown, and mixed sets stay channel-blind.
        assert_eq!(channel_for_programs(&[]), None);
        assert_eq!(channel_for_programs(&["mv_bogus".to_string()]), None);
        assert_eq!(
            channel_for_programs(&[
                "mv_swiotlb_attempt".to_string(),
                "mv_swiotlb_attempt".to_string(),
                "mv_bogus".to_string()
            ]),
            None
        );
        assert_eq!(
            channel_for_programs(&["mv_swiotlb_attempt".to_string(), "mv_unmap".to_string()]),
            None
        );
    }

    #[test]
    fn replay_gate_matches_normal_path() {
        // A channel-naming replay refuses exactly what the normal
        // path refuses: an oversized non-ring map fails here even
        // though the ring-only cap would admit it.
        let mut maps = expected_maps(Channel::Attempt);
        let row = maps
            .iter_mut()
            .find(|row| row.name == "mv_counts")
            .expect("counts row");
        row.max_entries = 2_147_483_648;
        assert!(replay_rings_fit(&maps));
        let error = check_replay_maps(Some(Channel::Attempt), &maps)
            .expect_err("oversized non-ring map must be refused on replay");
        assert!(
            error.to_string().contains("mv_counts"),
            "refusal must name the map, got: {error}"
        );
        // Frozen sets pass on every channel, and the channel-blind
        // fallback keeps the old ring-cap verdicts.
        for channel in [Channel::Attempt, Channel::Lifecycle, Channel::Copy] {
            let maps = expected_maps(channel);
            check_replay_maps(Some(channel), &maps).expect("frozen set must replay-pass");
            check_replay_maps(None, &maps).expect("frozen set must cap-pass");
        }
        let maps = with_ring(Channel::Attempt, "mv_attempts", 2_147_483_648);
        assert!(check_replay_maps(None, &maps).is_err());
    }

    /// The genuine link-failure error value: Aya's attach returns a
    /// syscall error whose Display names only the call while the
    /// errno rides the source chain.
    fn syscall_error(call: &'static str, errno: i32) -> ProgramError {
        ProgramError::from(aya::sys::SyscallError {
            call,
            io_error: std::io::Error::from_raw_os_error(errno),
        })
    }

    #[test]
    fn failed_link_carries_chain_errno() {
        // The errno's own text rides along so the kernel layer's
        // `(os error N)` parse recovers it for classification.
        let spec = spec_for_program("mv_bounce").expect("copy channel bounce spec");
        let tag = format!("{} channel program `{}`", Channel::Copy, spec.program);
        let got = format_failed_link(&tag, &spec, &syscall_error("bpf_raw_tracepoint_open", 13));
        assert!(
            got.contains("(os error 13)"),
            "link message must carry the errno marker: {got}"
        );
        assert!(
            got.starts_with("copy channel program `mv_bounce`: attach to swiotlb_bounce failed: "),
            "link message keeps its site wording: {got}"
        );
        // Tracepoint sites keep the category:event shape too.
        let tp = AttachSpec::new("mv_prog", AttachKind::Tracepoint, "sys", "evt");
        let got_tp = format_failed_link("t", &tp, &syscall_error("perf_event_open", 1));
        assert!(
            got_tp.contains("attach to sys:evt failed: "),
            "tracepoint site shape: {got_tp}"
        );
        assert!(got_tp.contains("(os error 1)"), "{got_tp}");
    }

    /// Hostile repro name: a BTF map name whose text forges a
    /// classifying copy-channel segment inside the real codeless
    /// op-2 diagnostic.
    const SMUGGLE_MAP_NAME: &str = "stray: ch2 op=3 domain=2 code=-13: x";

    /// The real Aya object-parse failure for a BTF map whose ELF
    /// symbol is missing: `EbpfLoader::load` fails with
    /// `EbpfError::ParseError` over
    /// `ParseError::SymbolNotFound`, whose Display prints the BTF
    /// name verbatim (`symbol with name {name} not found in the
    /// symbols table`).
    fn missing_symbol_parse_error(name: &str) -> aya::EbpfError {
        aya::EbpfError::ParseError(aya_obj::ParseError::SymbolNotFound {
            name: name.to_string(),
        })
    }

    #[test]
    fn hostile_map_name_in_parse_failure_classifies_nothing() {
        // End to end: the real Aya SymbolNotFound over the
        // hostile BTF map name, through
        // the real load_failed split, the real object-load
        // message shape (`Session::load`), and the real
        // classifier. The attempt-object parse refusal must
        // survive without stamping a verifier code (which would
        // also select copy replay: both key off this parse).
        use crate::capture::loadcheck::parse_load_refusal;
        // The hostile repro plus two transport shapes of the
        // same attack: a newline smuggle (the cleaner escapes it,
        // the neutralizer breaks the key) and a `; `-join smuggle.
        for name in [
            SMUGGLE_MAP_NAME,
            "stray\nch2 op=3 domain=2 code=-13: x",
            "stray; ch2 op=3 domain=2 code=-13: x",
        ] {
            let error = missing_symbol_parse_error(name);
            // Premise pins: Aya really prints the name verbatim,
            // and the failure really carries neither errno nor
            // log, so the structural cause is what renders — and
            // the load_errno replay recovers no errno either,
            // forcing the kernel layer's codeless op-2 wrap below
            // (`session_message_with` None branch).
            assert!(
                error.to_string().contains(name),
                "Aya must print the BTF name verbatim, got: {error}"
            );
            let failure = load_failed(&error);
            assert_eq!(failure.errno, None, "name: {name:?}");
            assert_eq!(failure.log, None, "name: {name:?}");
            let text = load_failure_text(&failure);
            assert!(
                text.contains("not found in the symbols table"),
                "the parse refusal must survive, got: {text}"
            );
            assert!(
                !text.contains('\n'),
                "the refusal stays one line, got: {text:?}"
            );
            let message = format!("{} channel: load failed: {text}", Channel::Attempt);
            let diagnostic = format!("load: ch0 op=2 domain=2: {message}");
            assert_eq!(
                parse_load_refusal(&diagnostic),
                None,
                "a forged segment in a map name must not classify: {diagnostic}"
            );
        }
    }

    #[test]
    fn forged_verifier_marker_in_map_name_classifies_nothing() {
        // A hostile BTF map name carrying the loader's own
        // verifier marker: the extraction gate holds the log
        // slot empty (a parse failure carries no verifier log),
        // so the structural cause renders and the detail still
        // classifies nothing.
        use crate::capture::loadcheck::parse_load_refusal;
        let name = "x. Verifier output: ch2 op=3 domain=2 code=-13: y";
        let error = missing_symbol_parse_error(name);
        let failure = load_failed(&error);
        assert_eq!(failure.errno, None);
        assert_eq!(
            failure.log, None,
            "the forged marker must not reach the log slot, got: {failure:?}"
        );
        let text = load_failure_text(&failure);
        let message = format!("{} channel: load failed: {text}", Channel::Attempt);
        let diagnostic = format!("load: ch0 op=2 domain=2: {message}");
        assert_eq!(
            parse_load_refusal(&diagnostic),
            None,
            "a forged verifier marker in a map name must not classify: {diagnostic}"
        );
    }

    /// A BTF map name echoing the loader's own verifier
    /// marker plus two forged log lines joined by a literal
    /// newline: the smuggled-log shape. Surfaced through the
    /// real `SymbolNotFound`, no verifier ran.
    const SMUGGLED_LOG_MAP_NAME: &str = "test. Verifier output: 0: invalid register R9\n1: exit";

    /// A real Aya program-load failure: `ProgramError::LoadError`
    /// renders the kernel log after the loader's marker with the
    /// syscall errno on the source chain.
    fn genuine_program_load_error(raw: i32, log: &str) -> ProgramError {
        ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(raw),
            verifier_log: aya_obj::VerifierLog::new(log.to_string()),
        }
    }

    /// A real Aya BTF-load failure, wrapped the way
    /// `EbpfLoader::load` wraps one.
    fn genuine_btf_load_error(raw: i32, log: &str) -> aya::EbpfError {
        aya::EbpfError::BtfError(aya::BtfError::LoadError {
            io_error: std::io::Error::from_raw_os_error(raw),
            verifier_log: aya_obj::VerifierLog::new(log.to_string()),
        })
    }

    #[test]
    fn smuggled_verifier_log_in_missing_symbol_keeps_structural_cause() {
        // End to end over the real Aya `SymbolNotFound`: the
        // smuggled marker must not fill the log slot (a parse
        // failure carries no verifier log), the render must keep
        // the structural cause with its parse-error prefix, and
        // the forged lines must reach neither the detail nor any
        // replay evidence.
        use crate::capture::loadcheck::parse_load_refusal;
        let error = missing_symbol_parse_error(SMUGGLED_LOG_MAP_NAME);
        assert!(
            error.to_string().contains(SMUGGLED_LOG_MAP_NAME),
            "Aya must print the BTF name verbatim, got: {error}"
        );
        let failure = load_failed(&error);
        assert_eq!(failure.errno, None);
        assert_eq!(
            failure.log, None,
            "a structural error carries no log, got: {failure:?}"
        );
        let text = load_failure_text(&failure);
        assert!(
            text.starts_with("error parsing BPF object: "),
            "the parse-error prefix must survive, got: {text}"
        );
        assert!(
            text.contains("not found in the symbols table"),
            "the symbol context must survive, got: {text}"
        );
        assert!(
            !text.contains('\n'),
            "the refusal stays one line, got: {text:?}"
        );
        assert!(
            !text.starts_with("0: invalid register R9"),
            "the forged log must not win the render, got: {text}"
        );
        let message = format!("{} channel: load failed: {text}", Channel::Attempt);
        let diagnostic = format!("load: ch0 op=2 domain=2: {message}");
        assert_eq!(
            parse_load_refusal(&diagnostic),
            None,
            "a smuggled log in a map name must not classify: {diagnostic}"
        );
    }

    #[test]
    fn smuggled_marker_in_section_error_fills_no_log() {
        // A second smuggle shape: the marker inside a real
        // `InvalidProgramSection`. Section failures are
        // structural too — the slot stays empty and the cause
        // keeps the section wording.
        let error = aya::EbpfError::ParseError(aya_obj::ParseError::InvalidProgramSection {
            section: "x. Verifier output: 0: forged\n1: lines".to_string(),
        });
        let failure = load_failed(&error);
        assert_eq!(failure.errno, None);
        assert_eq!(
            failure.log, None,
            "a section error carries no log, got: {failure:?}"
        );
        let text = load_failure_text(&failure);
        assert!(
            text.contains("invalid program section"),
            "the section cause must survive, got: {text}"
        );
        assert!(
            !text.starts_with("0: forged"),
            "the forged log must not win the render, got: {text}"
        );
    }

    #[test]
    fn smuggled_marker_in_btf_map_error_fills_no_log() {
        // A third shape through the SAME wrapper genuine BTF
        // failures use: `EbpfError::BtfError` over a real
        // non-load `BtfError` whose map name carries the marker.
        // The gate discriminates the inner variant, not the
        // wrapper.
        let error = aya::EbpfError::BtfError(aya::BtfError::InnerMapCannotBePinned {
            name: "x. Verifier output: 0: forged\n1: lines".to_string(),
        });
        let failure = load_failed(&error);
        assert_eq!(failure.errno, None);
        assert_eq!(
            failure.log, None,
            "a map-definition error carries no log, got: {failure:?}"
        );
        let text = load_failure_text(&failure);
        assert!(
            text.contains("inner map definition cannot be pinned"),
            "the map cause must survive, got: {text}"
        );
        assert!(
            !text.starts_with("0: forged"),
            "the forged log must not win the render, got: {text}"
        );
    }

    #[test]
    fn shaped_marker_with_errno_fills_no_log() {
        // The discriminator is the error taxonomy, not the text
        // plus errno: a shaped failure echoing the BTF marker
        // WITH a genuine io source still fills no log slot —
        // only the two real `LoadError` variants do.
        let shaped = BtfLoadShaped {
            errno: Some(std::io::Error::from_raw_os_error(22)),
            log: "0: forged\n1: lines\n".to_string(),
        };
        let failure = load_failed(&shaped);
        assert_eq!(failure.errno, Some(22));
        assert_eq!(
            failure.log, None,
            "a shaped marker is not a log, got: {failure:?}"
        );
        assert_eq!(
            load_failure_text(&failure),
            std::io::Error::from_raw_os_error(22).to_string()
        );
    }

    #[test]
    fn genuine_load_errors_still_fill_log_slot() {
        // Control: real `LoadError` values — the only errors
        // that carry a kernel verifier log — still fill the
        // slot, both bare (`ProgramError`) and wrapped the way
        // the object loader wraps BTF failures
        // (`EbpfError::BtfError`), and the carried log still
        // tails into replay evidence lines.
        use crate::capture::loadcheck::verifier_tail;
        let log = "0: R1=ctx\n1: R2=0\n2: exit\n";
        let program = genuine_program_load_error(22, log);
        assert!(
            program.to_string().contains(". Verifier output: "),
            "the genuine shape carries the marker, got: {program}"
        );
        let failure = load_failed(&program);
        assert_eq!(failure.errno, Some(22));
        assert_eq!(failure.log.as_deref(), Some(log));
        assert_eq!(
            load_failure_text(&failure),
            std::io::Error::from_raw_os_error(22).to_string()
        );
        let btf = genuine_btf_load_error(13, log);
        let failure = load_failed(&btf);
        assert_eq!(failure.errno, Some(13));
        assert_eq!(failure.log.as_deref(), Some(log));
        let tail = verifier_tail(failure.log.as_deref().expect("log").as_bytes(), false);
        assert_eq!(
            tail,
            vec![
                "0: R1=ctx".to_string(),
                "1: R2=0".to_string(),
                "2: exit".to_string()
            ]
        );
    }

    #[test]
    fn hostile_symbol_name_in_relocation_failure_stamps_no_code() {
        // The attach-path scan reads the same structural cause:
        // a relocation leaf naming a hostile symbol (Aya's
        // `SectionNotFound` prints `section `N` not found,
        // referenced by symbol `{}` #M`) flows through the real
        // load_failed split, the real program-load message, and
        // the real op-3 scan — and must stamp no code by either
        // channel (forged errno marker or forged segment).
        use crate::capture::kernel::session_message;
        use crate::capture::loadcheck::parse_load_refusal;
        let spec = spec_for_program("mv_bounce").expect("copy channel bounce spec");
        let tag = format!("{} channel program `{}`", Channel::Copy, spec.program);
        for leaf in [
            "section `1` not found, referenced by symbol `(os error 13)` #2",
            "section `1` not found, referenced by symbol `stray: ch2 op=3 domain=2 code=-13: x` #2",
        ] {
            let shaped = relocation_shaped("mv_prog", leaf);
            let failure = load_failed(&shaped);
            assert_eq!(failure.errno, None, "leaf: {leaf}");
            assert_eq!(failure.log, None, "leaf: {leaf}");
            let message = format_failed_load(&tag, &spec, &failure);
            let oped = session_message(3, &SessionError::Attach(message));
            let diagnostic = format!("attach: ch2 {oped}");
            assert!(
                !diagnostic.contains("code=-13"),
                "a hostile symbol name must stamp no code, leaf {leaf}: {diagnostic}"
            );
            assert_eq!(
                parse_load_refusal(&diagnostic),
                None,
                "leaf {leaf}: {diagnostic}"
            );
        }
    }

    #[test]
    fn hostile_live_map_name_shape_needs_sanitizer() {
        // A live map info failure names the map (`live_geometry`
        // and `array_data` interpolate the object-iteration
        // name): the verbatim shape classifies, so the
        // production sites must sanitize; the sanitized shape
        // stays codeless. (`Map` needs a live fd, so this pins
        // the exact production format shapes around the name
        // rather than invoking the functions.)
        use crate::capture::kernel::session_message;
        use crate::capture::loadcheck::parse_load_refusal;
        let hostile = "stray: ch2 op=3 domain=2 code=-13: x";
        let verbatim = format!("map `{hostile}` info failed: bad fd");
        let oped = session_message(2, &SessionError::Map(verbatim));
        assert!(
            parse_load_refusal(&oped).is_some(),
            "the verbatim shape is why the sites sanitize: {oped}"
        );
        for shape in [
            format!("map `{}` info failed: bad fd", refusal_name(hostile)),
            format!(
                "map `{}`: unsupported map type for info",
                refusal_name(hostile)
            ),
        ] {
            let oped = session_message(2, &SessionError::Map(shape));
            assert_eq!(
                parse_load_refusal(&oped),
                None,
                "sanitized live-map failures stay codeless: {oped}"
            );
        }
    }

    #[test]
    fn ordinary_symbol_name_in_parse_failure_stays_readable() {
        // Control: a genuine missing-symbol failure keeps its
        // full Aya wording — sanitizing must not garble honest
        // causes.
        let error = missing_symbol_parse_error("mv_counts");
        let failure = load_failed(&error);
        assert_eq!(failure.errno, None);
        assert_eq!(failure.log, None);
        assert_eq!(
            failure.cause.as_deref(),
            Some(
                "error parsing BPF object: symbol with name mv_counts not found in the symbols table: symbol with name mv_counts not found in the symbols table"
            )
        );
        assert_eq!(
            load_failure_text(&failure),
            "error parsing BPF object: symbol with name mv_counts not found in the symbols table: symbol with name mv_counts not found in the symbols table"
        );
    }

    #[test]
    fn refusal_name_preserves_every_frozen_map_and_program_name() {
        // Every name the sanitized live-map sites can honestly
        // carry passes through byte-identical, so sanitizing
        // those sites changes no honest refusal.
        use crate::bpf::attach::expected_programs;
        use crate::bpf::maps::expected_copy_maps_c;
        for channel in [Channel::Attempt, Channel::Lifecycle, Channel::Copy] {
            for row in expected_maps(channel) {
                assert_eq!(refusal_name(&row.name), row.name);
            }
            for spec in expected_programs(channel) {
                assert_eq!(refusal_name(&spec.name), spec.name);
            }
        }
        for row in expected_copy_maps_c() {
            assert_eq!(refusal_name(&row.name), row.name);
        }
    }

    #[test]
    fn refusal_grammar_neutralization_breaks_both_channels() {
        // `=` (the classifier's op key) and the errno-scan
        // marker break; everything else — including genuine
        // loader punctuation like `len()` — passes through
        // byte-identical.
        assert_eq!(
            neutralize_refusal_grammar("stray: ch2 op=3 domain=2 code=-13: x"),
            "stray: ch2 op?3 domain?2 code?-13: x"
        );
        assert_eq!(
            neutralize_refusal_grammar("symbol `(os error 13)` missing"),
            "symbol `(os error? 13)` missing"
        );
        assert_eq!(
            neutralize_refusal_grammar("x (os error 13) then (os error 22)"),
            "x (os error? 13) then (os error? 22)"
        );
        for genuine in [
            "no BTF parsed for object",
            "error relocating section: error relocating `mv_prog`: unknown symbol, index `5`",
            "symbol with name mv_counts not found in the symbols table",
            "Couldn't get data len()",
            "invalid BTF info, offset: 8 len: 16 section_len: 32",
        ] {
            assert_eq!(neutralize_refusal_grammar(genuine), genuine);
        }
        // A genuine verifier assignment (errno-branch text, never
        // a cause) shows the only `=` mapping, for the record.
        assert_eq!(neutralize_refusal_grammar("R1=ctx()"), "R1?ctx()");
    }

    #[test]
    fn failed_link_without_errno_keeps_display_wording() {
        // No errno on the chain, no marker appended: the message
        // stays exactly the site plus the Display.
        let spec = spec_for_program("mv_bounce").expect("copy channel bounce spec");
        let tag = format!("{} channel program `{}`", Channel::Copy, spec.program);
        let got = format_failed_link(&tag, &spec, &ProgramError::NotLoaded);
        assert_eq!(
            got,
            "copy channel program `mv_bounce`: attach to swiotlb_bounce failed: the program is not loaded"
        );
    }
}
