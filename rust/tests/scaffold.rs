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
            "memveil-0.1.0\n",
            "flag {flag} must print ENGINE_VERSION"
        );
    }
}
