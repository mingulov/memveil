//! MemVeil DMA-visibility observer (Rust userspace scaffold).
//!
//! Later tasks add wire types, the Aya loader, and the CLI surface on top
//! of this crate. The engine version string stays byte-identical with the
//! Mojo implementation so packaged artifacts keep matching drift guards.
//!
//! Panic policy: fallible production paths return errors and
//! error-handling paths never panic; `expect` appears only
//! beside its stated invariant (a just-checked length, a
//! by-construction state) or where Mojo traps on the same
//! input. Tests use `expect` freely.

pub mod analysis;
pub mod bpf;
pub mod capture;
pub mod cli;
pub mod model;
pub mod platform;
pub mod render;

/// Engine version reported by `--version` and embedded in reports.
///
/// Single-sourced from the package manifest (name plus version).
pub const ENGINE_VERSION: &str = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
