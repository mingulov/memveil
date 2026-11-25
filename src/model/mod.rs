// SPDX-License-Identifier: GPL-3.0-or-later
//! Data model: pure scalar types, validators, document parsing,
//! and canonical encoding.

pub mod common;
pub mod encode;
pub mod event;
pub mod exposure;
pub mod identity;
pub mod integrity;
pub mod metric;
pub mod regions;
pub mod report;
pub(crate) mod scan;
pub mod session;
pub mod validate;
