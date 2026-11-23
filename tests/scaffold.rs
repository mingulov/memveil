// SPDX-License-Identifier: GPL-3.0-or-later
use std::process::Command;

#[test]
fn binary_version_prints_engine_version() {
    let bin = env!("CARGO_BIN_EXE_memveil");
    for flag in ["--version", "version"] {
        let output = Command::new(bin)
            .arg(flag)
            .output()
            .expect("run memveil binary");
        assert!(
            output.status.success(),
            "flag {flag} exited with {}",
            output.status
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "memveil-0.2.0\n",
            "flag {flag} must print ENGINE_VERSION"
        );
    }
}

#[test]
fn version_ignores_trailing_args() {
    // Parity with the Mojo dispatcher: words after `version` are
    // accepted, not an invalid-usage error.
    let bin = env!("CARGO_BIN_EXE_memveil");
    for flag in ["--version", "version"] {
        let output = Command::new(bin)
            .arg(flag)
            .arg("extra")
            .arg("--bogus")
            .output()
            .expect("run memveil binary");
        assert_eq!(
            output.status.code(),
            Some(0),
            "flag {flag} with trailing args exited with {}",
            output.status
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "memveil-0.2.0\n",
            "flag {flag} with trailing args must print ENGINE_VERSION"
        );
    }
}

#[test]
fn usage_paths_exit_invalid() {
    // No verb and an unknown verb both print the usage text to
    // stderr and exit 2 (EXIT_INVALID), leaving stdout empty.
    let bin = env!("CARGO_BIN_EXE_memveil");
    let bare = Command::new(bin).output().expect("run memveil binary");
    assert_eq!(
        bare.status.code(),
        Some(2),
        "bare argv exits {}",
        bare.status
    );
    assert!(bare.stdout.is_empty(), "bare argv must leave stdout empty");
    let usage = String::from_utf8_lossy(&bare.stderr);
    assert!(
        usage.starts_with("usage: memveil <"),
        "bare argv must print usage, got {usage:?}"
    );
    let bogus = Command::new(bin)
        .arg("bogus-verb")
        .output()
        .expect("run memveil binary");
    assert_eq!(
        bogus.status.code(),
        Some(2),
        "unknown verb exits {}",
        bogus.status
    );
    assert!(
        bogus.stdout.is_empty(),
        "unknown verb must leave stdout empty"
    );
    assert_eq!(
        String::from_utf8_lossy(&bogus.stderr),
        usage,
        "unknown verb must print the same usage text"
    );
}
