// SPDX-License-Identifier: GPL-3.0-or-later
//! Data model: pure scalar types, validators, and document parsing.
//!
//! Later tasks add event/session/integrity/report/encode modules here.

pub mod common;
pub mod event;
pub mod identity;
pub mod regions;
pub(crate) mod scan;
pub mod session;
pub mod validate;
