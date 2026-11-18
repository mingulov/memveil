// SPDX-License-Identifier: GPL-3.0-or-later
//! Live writer source: WriterSource over an EventWriter.
//!
//! Thin ownership adapter, no policy: create() opens the EventWriter in its
//! slot; every later method takes the writer out, runs one call, and puts it
//! back (finalize and discard consume it: the slot empties, later calls
//! report misuse). Calls before create report misuse too.

use crate::capture::writer::{EventWriter, WriteError, residual_text};

/// One writer-create outcome (`kind` valid when not ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOut {
    /// True when the capture was created.
    pub ok: bool,
    /// Failure kind when not ok.
    pub kind: String,
    /// Human detail when not ok.
    pub message: String,
}

/// One writer-append outcome (`kind` valid when not ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOut {
    /// True when the bytes were persisted.
    pub ok: bool,
    /// Failure kind when not ok.
    pub kind: String,
    /// Human detail when not ok.
    pub message: String,
}

/// One group-begin outcome (`mark` valid when ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupOut {
    /// True when the group opened.
    pub ok: bool,
    /// Pre-group committed offset.
    pub mark: u64,
    /// Failure kind when not ok.
    pub kind: String,
}

/// One finalize outcome: status + note, or misuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalOut {
    /// Publication status (or "unfinalized" on misuse).
    pub status: String,
    /// Human detail.
    pub note: String,
}

/// Capture file surface behind scriptable outcomes.
pub trait WriterSource {
    /// Create the capture at `path` with an events budget in bytes.
    fn create(&mut self, path: &str, budget: u64) -> CreateOut;
    /// Append one attempt line.
    fn append(&mut self, line: &[u8]) -> AppendOut;
    /// Append one closing line from the reserve.
    fn append_closing(&mut self, line: &[u8]) -> AppendOut;
    /// Mark the pre-group offset for rollback.
    fn group_begin(&mut self) -> GroupOut;
    /// Roll back to a group mark.
    fn group_abort(&mut self, mark: u64) -> AppendOut;
    /// Publish a checkpoint document.
    fn checkpoint(&mut self, session: &[u8]) -> AppendOut;
    /// Publish the final session; consumes the writer.
    fn finalize(&mut self, session: &[u8]) -> FinalOut;
    /// Pre-readiness rollback; returns "" when nothing is left behind.
    fn abandon(&mut self) -> String;
    /// Close without publishing: events kept, no session.
    fn discard(&mut self);
    /// Committed event-file bytes.
    fn committed_len(&self) -> u64;
    /// Dev/inode continuity pinned at finalize, or empty.
    fn finalized_identity(&self) -> Vec<u64>;
}

fn writer_message(e: &WriteError) -> String {
    format!("{}: {}", e.kind, e.message)
}

/// Display text for stuck construction artifacts, or "" when none.
///
/// Rendered from the typed residual bits alone. The adapter boundary
/// reports them exactly once, via abandon(): the creation error keeps the
/// failure cause, never a residual suffix, so rollback cannot repeat the
/// list. Error message text is never parsed.
pub fn construction_note(residuals: u8) -> String {
    let tail = residual_text(residuals);
    if tail.is_empty() {
        return String::new();
    }
    format!("construction residuals: {tail}")
}

/// WriterSource backed by one EventWriter.
#[derive(Debug, Default)]
pub struct LiveWriter {
    writer: Option<EventWriter>,
    construction_residuals: u8,
    final_ids: Vec<u64>,
}

impl LiveWriter {
    /// An empty slot; call [`WriterSource::create`] next.
    pub fn new() -> Self {
        Self {
            writer: None,
            construction_residuals: 0,
            final_ids: Vec::new(),
        }
    }
}

impl WriterSource for LiveWriter {
    fn create(&mut self, path: &str, budget: u64) -> CreateOut {
        if self.writer.is_some() {
            return CreateOut {
                ok: false,
                kind: "misuse".to_string(),
                message: "create twice".to_string(),
            };
        }
        match EventWriter::new(path, budget) {
            Ok(mut w) => {
                if let Err(e) = w.prepare() {
                    self.writer = Some(w);
                    return CreateOut {
                        ok: false,
                        kind: e.kind,
                        message: e.message,
                    };
                }
                self.writer = Some(w);
            }
            Err(e) => {
                if e.residuals != 0 {
                    self.construction_residuals = e.residuals;
                }
                return CreateOut {
                    ok: false,
                    kind: e.kind,
                    message: e.message,
                };
            }
        }
        CreateOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }

    fn append(&mut self, line: &[u8]) -> AppendOut {
        let Some(mut w) = self.writer.take() else {
            return AppendOut {
                ok: false,
                kind: "misuse".to_string(),
                message: "append before create".to_string(),
            };
        };
        let out = match w.append(line) {
            Ok(()) => AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            },
            Err(e) => AppendOut {
                ok: false,
                kind: e.kind,
                message: e.message,
            },
        };
        self.writer = Some(w);
        out
    }

    fn append_closing(&mut self, line: &[u8]) -> AppendOut {
        let Some(mut w) = self.writer.take() else {
            return AppendOut {
                ok: false,
                kind: "misuse".to_string(),
                message: "append before create".to_string(),
            };
        };
        let out = match w.append_closing(line) {
            Ok(()) => AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            },
            Err(e) => AppendOut {
                ok: false,
                kind: e.kind,
                message: e.message,
            },
        };
        self.writer = Some(w);
        out
    }

    fn group_begin(&mut self) -> GroupOut {
        let Some(mut w) = self.writer.take() else {
            return GroupOut {
                ok: false,
                mark: 0,
                kind: "misuse".to_string(),
            };
        };
        let out = match w.group_begin() {
            Ok(mark) => GroupOut {
                ok: true,
                mark,
                kind: String::new(),
            },
            Err(e) => GroupOut {
                ok: false,
                mark: 0,
                kind: e.kind,
            },
        };
        self.writer = Some(w);
        out
    }

    fn group_abort(&mut self, mark: u64) -> AppendOut {
        let Some(mut w) = self.writer.take() else {
            return AppendOut {
                ok: false,
                kind: "misuse".to_string(),
                message: "abort before create".to_string(),
            };
        };
        let out = match w.group_abort(mark) {
            Ok(()) => AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            },
            Err(e) => AppendOut {
                ok: false,
                kind: e.kind,
                message: e.message,
            },
        };
        self.writer = Some(w);
        out
    }

    fn checkpoint(&mut self, session: &[u8]) -> AppendOut {
        let Some(mut w) = self.writer.take() else {
            return AppendOut {
                ok: false,
                kind: "misuse".to_string(),
                message: "checkpoint before create".to_string(),
            };
        };
        let out = match w.checkpoint(session) {
            Ok(()) => AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            },
            Err(e) => AppendOut {
                ok: false,
                kind: e.kind,
                message: e.message,
            },
        };
        self.writer = Some(w);
        out
    }

    fn finalize(&mut self, session: &[u8]) -> FinalOut {
        let Some(mut w) = self.writer.take() else {
            return FinalOut {
                status: "unfinalized".to_string(),
                note: "finalize before create".to_string(),
            };
        };
        match w.finalize(session) {
            Ok(outcome) => {
                if outcome.status == "finalized" {
                    self.final_ids = w.finalized_identity();
                }
                FinalOut {
                    status: outcome.status,
                    note: outcome.message,
                }
            }
            Err(e) => {
                let note = writer_message(&e);
                self.writer = Some(w);
                FinalOut {
                    status: "unfinalized".to_string(),
                    note,
                }
            }
        }
    }

    fn abandon(&mut self) -> String {
        // Idempotent cleanup: nothing created means nothing to roll back
        // (same contract as discard, and as the scripted writers). A
        // missing writer here is the normal pre-create startup-refusal
        // path, not misuse. Exception: a failed create that left
        // artifacts behind reports them once, so the refusal becomes a
        // rollback failure instead of a clean refusal.
        let Some(mut w) = self.writer.take() else {
            if self.construction_residuals != 0 {
                let bits = self.construction_residuals;
                self.construction_residuals = 0;
                return construction_note(bits);
            }
            return String::new();
        };
        w.abandon()
    }

    fn discard(&mut self) {
        if let Some(mut w) = self.writer.take() {
            w.discard();
        }
    }

    fn committed_len(&self) -> u64 {
        self.writer.as_ref().map(|w| w.committed_len()).unwrap_or(0)
    }

    fn finalized_identity(&self) -> Vec<u64> {
        self.final_ids.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{LiveWriter, WriterSource, construction_note};
    use crate::capture::writer::MIN_EVENTS_BUDGET;
    use crate::platform::test_support::TestDir;

    fn line(text: &str) -> Vec<u8> {
        [text.as_bytes(), b"\n"].concat()
    }

    fn scratch() -> TestDir {
        TestDir::create("memveil-live").expect("mkdtemp")
    }

    #[test]
    fn lifecycle() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = LiveWriter::new();
        assert_eq!(w.committed_len(), 0);
        assert!(w.create(target.to_str().unwrap(), 131072).ok);
        assert!(w.append(&line("a")).ok);
        assert_eq!(w.committed_len(), 2);
        let mark = w.group_begin();
        assert!(mark.ok);
        assert!(w.append(&line("bbb")).ok);
        assert_eq!(w.committed_len(), 6);
        assert!(w.group_abort(mark.mark).ok);
        assert_eq!(w.committed_len(), 2);
        let fin = w.finalize(&line("{}"));
        assert_eq!(fin.status, "finalized");
        let events = std::fs::read(target.join("events.ndjson")).expect("events");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], 0x61);
        let session = std::fs::read(target.join("session.json")).expect("session");
        assert_eq!(session.len(), 3);
        // Finalize consumes the slot.
        assert_eq!(w.finalize(&line("{}")).status, "unfinalized");
        assert_eq!(w.finalized_identity().len(), 6);
    }

    #[test]
    fn misuse_before_create() {
        let mut w = LiveWriter::new();
        let out = w.append(&line("x"));
        assert!(!out.ok);
        assert_eq!(out.kind, "misuse");
        assert!(!w.append_closing(&line("x")).ok);
        assert!(!w.group_begin().ok);
        assert!(!w.group_abort(0).ok);
        assert!(!w.checkpoint(&line("{}")).ok);
        assert_eq!(w.finalize(&line("{}")).status, "unfinalized");
    }

    #[test]
    fn empty_abandon_succeeds() {
        let mut w = LiveWriter::new();
        assert_eq!(w.abandon(), "");
    }

    #[test]
    fn construction_note_renders_typed_bits() {
        assert_eq!(construction_note(0), "");
        assert_eq!(construction_note(1), "construction residuals: events");
        assert_eq!(construction_note(2), "construction residuals: dir");
        assert_eq!(construction_note(3), "construction residuals: events,dir");
        assert_eq!(construction_note(255), "construction residuals: events,dir");
    }

    #[test]
    fn failed_create_reports_no_prose_account() {
        let tmp = scratch();
        let mut w = LiveWriter::new();
        let small = w.create(tmp.path().join("small").to_str().unwrap(), 1024);
        assert!(!small.ok);
        assert!(!small.message.contains("; residuals:"));
        assert_eq!(w.abandon(), "");
        assert_eq!(w.abandon(), "");
        let mut w2 = LiveWriter::new();
        let target = tmp.path().join("taken");
        assert!(w2.create(target.to_str().unwrap(), 131072).ok);
        let mut w3 = LiveWriter::new();
        let exists = w3.create(target.to_str().unwrap(), 131072);
        assert!(!exists.ok);
        assert!(!exists.message.contains("; residuals:"));
        assert_eq!(w3.abandon(), "");
        assert_eq!(w3.abandon(), "");
    }

    #[test]
    fn create_guards() {
        let tmp = scratch();
        let mut w = LiveWriter::new();
        let twice = tmp.path().join("twice");
        assert!(w.create(twice.to_str().unwrap(), 131072).ok);
        let again = w.create(tmp.path().join("other").to_str().unwrap(), 131072);
        assert!(!again.ok);
        assert_eq!(again.kind, "misuse");
        let mut w2 = LiveWriter::new();
        let small = w2.create(tmp.path().join("small").to_str().unwrap(), 1024);
        assert!(!small.ok);
        assert_eq!(small.kind, "budget");
        let mut w3 = LiveWriter::new();
        let exists = w3.create(twice.to_str().unwrap(), 131072);
        assert!(!exists.ok);
        assert_eq!(exists.kind, "exists");
    }

    #[test]
    fn abandon_and_discard() {
        let tmp = scratch();
        let mut w = LiveWriter::new();
        let gone = tmp.path().join("gone");
        assert!(w.create(gone.to_str().unwrap(), 131072).ok);
        assert!(w.append(&line("x")).ok);
        assert_eq!(w.abandon(), "");
        let mut w2 = LiveWriter::new();
        assert!(w2.create(gone.to_str().unwrap(), 131072).ok);
        let keep = tmp.path().join("keep");
        let mut w3 = LiveWriter::new();
        assert!(w3.create(keep.to_str().unwrap(), 131072).ok);
        assert!(w3.append(&line("y")).ok);
        w3.discard();
        assert_eq!(
            std::fs::read(keep.join("events.ndjson"))
                .expect("events")
                .len(),
            2
        );
        assert!(!keep.join("session.json").exists());
    }

    #[test]
    fn reserves_before_append() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = LiveWriter::new();
        assert!(w.create(target.to_str().unwrap(), MIN_EVENTS_BUDGET).ok);
        assert_eq!(
            std::fs::read(target.join(".finalization-reserve"))
                .expect("reserve")
                .len(),
            17 * 1024 * 1024
        );
        assert_eq!(
            std::fs::read(target.join("session.finalizing"))
                .expect("staging")
                .len(),
            0
        );
        assert_eq!(w.abandon(), "");
    }

    #[test]
    fn checkpoint_forwards() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = LiveWriter::new();
        assert!(w.create(target.to_str().unwrap(), 131072).ok);
        assert!(w.append(&line("x")).ok);
        assert!(w.checkpoint(b"ckpt").ok);
        assert_eq!(
            std::fs::read(target.join("checkpoint.json")).expect("ckpt"),
            b"ckpt"
        );
    }
}
