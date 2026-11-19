// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared fallible-outcome shape for native-backed operations.
//!
//! `OpOut` lives here (not in the collector) so replay verbs can use
//! signal and clock helpers without importing live collection or
//! the native bridge.

/// One fallible kernel-side operation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpOut {
    /// True when the operation succeeded.
    pub ok: bool,
    /// Failure detail; empty on success.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::OpOut;

    #[test]
    fn outcome_carries_ok_and_message() {
        let ok = OpOut {
            ok: true,
            message: String::new(),
        };
        assert!(ok.ok);
        assert_eq!(ok.message, "");
        let failed = OpOut {
            ok: false,
            message: "mask install failed: errno 1".to_string(),
        };
        assert!(!failed.ok);
        assert_eq!(failed.message, "mask install failed: errno 1");
    }
}
