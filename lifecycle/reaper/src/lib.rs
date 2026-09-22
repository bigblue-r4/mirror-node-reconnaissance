//! `mnr-reaper` — the auditor-protection lifecycle.
//!
//! The reaper exists to protect **our own** observer node, not to act against
//! anything else. Its premise: a node left in contact with a swarm is, sooner
//! or later, noticed and influenced until it belongs to the swarm. So the node
//! runs on a short leash — a hard time-to-live plus fast trip conditions — and
//! when the leash runs out it tears itself down cleanly.
//!
//! Teardown, in order:
//! 1. **seal** the witness [`Ledger`] (write the `log-head.json` anchor) so the
//!    record of what was seen is closed and tamper-evident;
//! 2. **wipe** the node's own transient secrets and working buffers;
//! 3. return a [`TeardownReport`] describing why and what was closed.
//!
//! "Burning the bridge" here means the node severing *its own* link and erasing
//! *its own* state. Nothing in this crate touches a remote system.

use mnr_ledger::{Ledger, LedgerHead};
use serde::Serialize;
use std::time::{Duration, Instant};

/// Why the node was torn down.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum TripReason {
    /// The hard time-to-live elapsed.
    Ttl,
    /// The observer's Verifier hemisphere flagged co-option drift.
    CoOption { drift: f64 },
    /// A configured anomaly threshold tripped.
    Anomaly { detail: String },
    /// An operator pulled the node manually.
    Manual,
}

/// The short-leash timer. Cheap to poll every loop iteration.
pub struct Reaper {
    ttl: Duration,
    started: Instant,
}

impl Reaper {
    pub fn new(ttl: Duration) -> Self {
        Reaper {
            ttl,
            started: Instant::now(),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Time left before the TTL trips (saturating at zero).
    pub fn remaining(&self) -> Duration {
        self.ttl.saturating_sub(self.started.elapsed())
    }

    /// True once the TTL has elapsed.
    pub fn ttl_expired(&self) -> bool {
        self.started.elapsed() >= self.ttl
    }
}

/// A transient secret the node holds while deployed (session token, ephemeral
/// key material, connection credential). Its bytes are best-effort wiped on
/// drop and on teardown.
///
/// NOTE: for production use, back this with the `zeroize` crate, which resists
/// compiler optimizations more rigorously than the volatile writes here.
pub struct Secret {
    label: String,
    bytes: Vec<u8>,
}

impl Secret {
    pub fn new(label: impl Into<String>, bytes: Vec<u8>) -> Self {
        Secret {
            label: label.into(),
            bytes,
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Overwrite the secret's bytes with zeros using volatile writes so the
    /// store is not elided, then clear the buffer.
    fn wipe(&mut self) {
        for b in self.bytes.iter_mut() {
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        self.bytes.clear();
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// A holder for everything the node must scrub when it burns its own bridge.
#[derive(Default)]
pub struct NodeState {
    pub secrets: Vec<Secret>,
    /// In-memory working buffers (e.g. accumulated model context) to clear.
    pub buffers: Vec<Vec<u8>>,
}

impl NodeState {
    pub fn new() -> Self {
        NodeState::default()
    }

    pub fn add_secret(&mut self, secret: Secret) {
        self.secrets.push(secret);
    }

    pub fn add_buffer(&mut self, buf: Vec<u8>) {
        self.buffers.push(buf);
    }

    fn wipe(&mut self) -> usize {
        let n = self.secrets.len() + self.buffers.len();
        for s in self.secrets.iter_mut() {
            s.wipe();
        }
        self.secrets.clear();
        for b in self.buffers.iter_mut() {
            for byte in b.iter_mut() {
                unsafe {
                    std::ptr::write_volatile(byte, 0);
                }
            }
            b.clear();
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        self.buffers.clear();
        n
    }
}

/// What a teardown accomplished.
#[derive(Debug, Clone, Serialize)]
pub struct TeardownReport {
    pub reason: TripReason,
    /// The sealed head anchor of the witness log, if sealing succeeded.
    pub sealed_head: Option<LedgerHead>,
    /// Count of secrets + buffers scrubbed.
    pub wiped_items: usize,
}

/// Execute a clean teardown: seal the ledger, wipe local state, and report.
///
/// This is the only "kill-switch" in the system and it acts solely on the local
/// node: it closes the tamper-evident record and erases the node's own secrets.
pub fn execute_teardown(
    reason: TripReason,
    ledger: &Ledger,
    state: &mut NodeState,
) -> TeardownReport {
    // 1. Seal the witness log first, so the record survives the wipe.
    let sealed_head = ledger.seal().ok();
    // 2. Scrub the node's own transient state.
    let wiped_items = state.wipe();
    TeardownReport {
        reason,
        sealed_head,
        wiped_items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_ledger() -> (Ledger, std::path::PathBuf) {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("mnr-reaper-test-{n}"));
        (Ledger::open(&p).unwrap(), p)
    }

    #[test]
    fn ttl_expires() {
        let r = Reaper::new(Duration::from_millis(0));
        assert!(r.ttl_expired());
        let r = Reaper::new(Duration::from_secs(3600));
        assert!(!r.ttl_expired());
        assert!(r.remaining() > Duration::from_secs(3000));
    }

    #[test]
    fn teardown_seals_and_wipes() {
        let (mut ledger, dir) = tmp_ledger();
        ledger.append("observation", b"something seen").unwrap();

        let mut state = NodeState::new();
        state.add_secret(Secret::new("session-token", b"super-secret-token".to_vec()));
        state.add_buffer(b"model context buffer".to_vec());

        let report = execute_teardown(TripReason::CoOption { drift: 0.81 }, &ledger, &mut state);

        assert_eq!(report.reason, TripReason::CoOption { drift: 0.81 });
        assert!(report.sealed_head.is_some());
        assert_eq!(report.wiped_items, 2);
        assert!(state.secrets.is_empty());
        assert!(state.buffers.is_empty());

        // Ledger is sealed and verifies.
        assert!(Ledger::verify(&dir).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secret_wipe_clears_bytes() {
        let mut s = Secret::new("k", vec![1u8, 2, 3, 4]);
        assert_eq!(s.len(), 4);
        s.wipe();
        assert!(s.is_empty());
    }
}
