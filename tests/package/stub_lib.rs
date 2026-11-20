// SPDX-License-Identifier: GPL-3.0-or-later
//! Synthetic seal fixture closure lib: a valid ELF .so.
//!
//! Compiled directly with rustc as a cdylib by the
//! installed-mapping sealed fixture; the shaped synthetic
//! candidate stages this as lib/memveil/libgcc_s.so.1 so the
//! packagers' readelf floor derivation sees well-formed ELF.
//! The file name is fixture-required (closure lib pin); the
//! bytes are synthetic.

#[no_mangle]
pub extern "C" fn memveil_stub_probe() -> u32 {
    1
}
