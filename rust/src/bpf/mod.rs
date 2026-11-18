// SPDX-License-Identifier: GPL-3.0-or-later
//! Aya-based loader mirroring the previous `Session` surface.
//!
//! One [`Session`](session::Session) owns one channel object (attempt,
//! lifecycle, or copy): open parses and sanity-checks the ELF, load creates
//! the kernel maps and verifies their live geometry, attach loads and links
//! the frozen per-channel programs, and poll drains decoded frames from the
//! channel ring. [`Channels`](session::Channels) attaches all present
//! channels inner-first with rollback, mirroring the old kernel source.

pub mod attach;
pub mod btf;
pub mod maps;
pub mod offsets;
pub mod poll;
pub mod session;

pub use attach::{
    ATTACH_ORDER, AttachKind, AttachSpec, DETACH_ORDER, ProgramSpec, attempt_specs, copy_specs,
    lifecycle_specs,
};
pub use maps::{MapGeometry, MapSpec, check_channel_geometry};
pub use offsets::{
    AttemptOffsets, encode_copy_offsets, probe_trace_offsets, resolve_attempt_offsets,
    resolve_copy_offsets, resolve_copy_offsets_from_btf, sentinel_copy_offsets,
    validate_copy_offsets,
};
pub use poll::{Frame, Stats};
pub use session::{Channel, Channels, Session, SessionError};
