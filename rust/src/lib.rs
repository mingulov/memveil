//! MemVeil DMA-visibility observer (Rust userspace scaffold).
//!
//! Later tasks add wire types, the Aya loader, and the CLI surface on top
//! of this crate. The engine version string stays byte-identical with the
//! Mojo implementation so packaged artifacts keep matching drift guards.

/// Engine version reported by `--version` and embedded in reports.
pub const ENGINE_VERSION: &str = "memveil-0.1.0";
