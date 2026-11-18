// SPDX-License-Identifier: GPL-3.0-or-later
//! Platform adapters: syscall and file interfaces for capture.

pub mod artifact_files;
pub mod baseline;
pub mod btf;
pub mod capabilities;
pub mod capturefiles;
pub mod clock;
pub mod evidence;
pub mod gzip;
pub mod hash;
pub mod kernelgate;
pub mod narrow;
pub mod outcome;
pub mod prechecks;
pub mod reader;
pub mod runtime;
pub mod signal;
pub mod stdout;
pub mod tracefs;

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test-only helpers for the platform adapter suites.
    //!
    //! Fixture trees live in the repository's `tests/fixtures/`
    //! directory; unit tests resolve them through [`repo_root`].
    //! Tests that need a scratch tree use [`TestDir`].

    use std::ffi::CStr;
    use std::path::PathBuf;

    /// Repository root: the Rust workspace lives in `rust/`, one level below it.
    pub(crate) fn repo_root() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("rust/ must have a parent directory")
            .to_path_buf()
    }

    /// Gate fixture directory for one gate fixture name.
    pub(crate) fn gate_fixture(name: &str) -> String {
        repo_root()
            .join("tests/fixtures/gate")
            .join(name)
            .to_str()
            .expect("fixture path must be UTF-8")
            .to_string()
    }

    /// Capability fixture directory for one capabilities fixture name.
    pub(crate) fn capabilities_fixture(name: &str) -> String {
        repo_root()
            .join("tests/fixtures/capabilities")
            .join(name)
            .to_str()
            .expect("fixture path must be UTF-8")
            .to_string()
    }

    /// Unique scratch directory under `/tmp`, removed on drop (best effort).
    pub(crate) struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        /// Create a fresh scratch directory with the given name prefix.
        pub(crate) fn create(prefix: &str) -> std::io::Result<TestDir> {
            let mut template = format!("/tmp/{prefix}-XXXXXX").into_bytes();
            template.push(0);
            // SAFETY: mkdtemp mutates the NUL-terminated template in place
            // and returns NULL on failure; the buffer outlives the call.
            let created = unsafe { libc::mkdtemp(template.as_mut_ptr().cast::<libc::c_char>()) };
            if created.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: mkdtemp replaced the XXXXXX suffix with a NUL-terminated
            // ASCII name on success.
            let path = unsafe { CStr::from_ptr(created) }
                .to_str()
                .map_err(std::io::Error::other)?
                .to_string();
            Ok(TestDir {
                path: PathBuf::from(path),
            })
        }

        /// The scratch directory path.
        pub(crate) fn path(&self) -> &std::path::Path {
            &self.path
        }

        /// The scratch directory path as a string.
        pub(crate) fn as_str(&self) -> &str {
            self.path.to_str().expect("scratch path must be UTF-8")
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
