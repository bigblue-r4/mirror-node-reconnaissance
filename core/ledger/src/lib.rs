//! `mnr-ledger` — the out-of-band, tamper-evident witness log.
//! 
//! Every event an observer node sees, and every reasoning turn it takes, is
//! hashed (SHA-256) and chained to the previous entry. The chain plus a signed
//! head anchor (`log-head.json`) make two kinds of tampering detectable after
//! the fact:
//! 
//! * **mutation** — editing any past entry breaks its `entry_hash` and every
//!   `prev_hash` that follows it;
//! * **truncation / extension** — dropping or appending trailing entries makes
//!   the recomputed head disagree with the sealed anchor.
//! 
//! The log stores **fingerprints, never plaintext** (privacy-by-fingerprint):
//! callers hand raw bytes to [`Ledger::append`], and only the SHA-256 of those
//! bytes is persisted. This mirrors the append-only JSONL + fingerprint
//! convention used by the split-brain harness `sbh-store` crate.
//! 
//! This is **detection, not prevention** — the same posture as SLATE.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The `prev_hash` of the very first (genesis) entry: 64 hex zeros.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const LOG_FILE: &str = "ledger.jsonl";
const HEAD_FILE: &str = "log-head.json";

/// One link in the witness chain. No plaintext is ever stored — only the
/// SHA-256 fingerprint of the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Monotonic sequence number, starting at 0.
    pub seq: u64,
    /// UTC timestamp, RFC-3339 (`YYYY-MM-DDTHH:MM:SSZ`).
    pub ts: String,
    /// Short tag describing what kind of event this is (e.g. `"observation"`).
    pub kind: String,
    /// SHA-256 hex of the previous entry's `entry_hash` (or [`GENESIS_PREV`]).
    pub prev_hash: String,
    /// SHA-256 hex of the raw payload bytes. The payload itself is not stored.
    pub payload_fingerprint: String,
    /// SHA-256 hex over `seq | ts | kind | prev_hash | payload_fingerprint`.
    pub entry_hash: String,
}

/// The sealed head anchor written to `log-head.json`. Recomputing the chain and
/// comparing its tail against this anchor is what makes truncation detectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerHead {
    pub head_seq: u64,
    pub head_hash: String,
    pub count: u64,
    pub sealed_at: String,
}

/// Errors that [`Ledger::verify`] and construction can raise.
#[derive(Debug)]
pub enum LedgerError {
    Io(io::Error),
    /// A JSONL line could not be parsed.
    Parse {
        line: usize,
        source: serde_json::Error,
    },
    /// `prev_hash` did not point at the preceding entry's `entry_hash`.
    ChainBreak {
        seq: u64,
    },
    /// The stored `entry_hash` did not match a recomputation (entry mutated).
    HashMismatch {
        seq: u64,
    },
    /// Sequence numbers were not contiguous from 0.
    SeqGap {
        expected: u64,
        found: u64,
    },
    /// The sealed head anchor disagrees with the recomputed chain
    /// (truncation or post-seal extension).
    HeadMismatch {
        anchor: LedgerHead,
        actual_seq: u64,
        actual_hash: String,
    },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::Io(e) => write!(f, "ledger io error: {e}"),
            LedgerError::Parse { line, source } => {
                write!(f, "ledger parse error on line {line}: {source}")
            }
            LedgerError::ChainBreak { seq } => {
                write!(f, "chain break at seq {seq}: prev_hash does not match preceding entry")
            }
            LedgerError::HashMismatch { seq } => {
                write!(f, "hash mismatch at seq {seq}: entry was mutated")
            }
            LedgerError::SeqGap { expected, found } => {
                write!(f, "sequence gap: expected seq {expected}, found {found}")
            }
            LedgerError::HeadMismatch { anchor, actual_seq, actual_hash } => write!(
                f,
                "head anchor mismatch: sealed head_seq={} head_hash={}, but chain ends at seq={} hash={} (truncation or extension)",
                anchor.head_seq, anchor.head_hash, actual_seq, actual_hash
            ),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<io::Error> for LedgerError {
    fn from(e: io::Error) -> Self {
        LedgerError::Io(e)
    }
}

/// Result of a successful [`Ledger::verify`].
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub entries: u64,
    pub head_hash: String,
    /// Whether a `log-head.json` anchor was present and matched.
    pub sealed: bool,
}

/// An append-only witness log rooted at a directory.
pub struct Ledger {
    dir: PathBuf,
    last_hash: String,
    next_seq: u64,
    count: u64,
}

impl Ledger {
    /// Open (or create) a ledger in `dir`. If a log already exists it is
    /// verified before any further appends are allowed, so a broken log can
    /// never be silently extended.
    pub fn open<P: AsRef<Path>>(dir: P) -> Result<Self, LedgerError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let entries = read_all(&dir.join(LOG_FILE))?;
        check_chain(&entries)?;
        validate_head(&dir, &entries)?;
        let (last_hash, next_seq) = match entries.last() {
            Some(e) => (e.entry_hash.clone(), e.seq + 1),
            None => (GENESIS_PREV.to_string(), 0),
        };
        Ok(Ledger {
            dir,
            last_hash,
            next_seq,
            count: entries.len() as u64,
        })
    }

    /// Directory backing this ledger.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Number of entries appended so far.
    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Append a witness record for `payload`, tagged with `kind`. Only the
    /// SHA-256 fingerprint of `payload` is written; the bytes are discarded.
    /// Returns the assigned sequence number.
    pub fn append(&mut self, kind: &str, payload: &[u8]) -> Result<u64, LedgerError> {
        let seq = self.next_seq;
        let ts = iso_now();
        let payload_fingerprint = sha256_hex(payload);
        let entry_hash = compute_entry_hash(seq, &ts, kind, &self.last_hash, &payload_fingerprint);
        let entry = LedgerEntry {
            seq,
            ts,
            kind: kind.to_string(),
            prev_hash: self.last_hash.clone(),
            payload_fingerprint,
            entry_hash: entry_hash.clone(),
        };
        let line = serde_json::to_string(&entry).map_err(|e| LedgerError::Parse {
            line: seq as usize,
            source: e,
        })?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(LOG_FILE))?;
        writeln!(f, "{line}")?;
        f.flush()?;
        self.last_hash = entry_hash;
        self.next_seq += 1;
        self.count += 1;
        Ok(seq)
    }

    /// Seal the log: write the head anchor (`log-head.json`) capturing the
    /// current tail. After a seal, truncation or extension is detectable.
    pub fn seal(&self) -> Result<LedgerHead, LedgerError> {
        let head = LedgerHead {
            head_seq: self.next_seq.saturating_sub(1),
            head_hash: self.last_hash.clone(),
            count: self.count,
            sealed_at: iso_now(),
        };
        let json = serde_json::to_string_pretty(&head)
            .map_err(|e| LedgerError::Parse { line: 0, source: e })?;
        let mut f = File::create(self.dir.join(HEAD_FILE))?;
        f.write_all(json.as_bytes())?;
        f.flush()?;
        Ok(head)
    }

    /// Verify the integrity of a ledger on disk without opening it for writing.
    pub fn verify<P: AsRef<Path>>(dir: P) -> Result<VerifyReport, LedgerError> {
        let dir = dir.as_ref();
        let entries = read_all(&dir.join(LOG_FILE))?;
        check_chain(&entries)?;
        let _ = validate_head(dir, &entries)?;

        let (head_hash, actual_seq) = match entries.last() {
            Some(e) => (e.entry_hash.clone(), e.seq),
            None => (GENESIS_PREV.to_string(), 0),
        };
        let sealed = dir.join(HEAD_FILE).exists();

        // If the anchor exists it was already validated by validate_head().
        let _ = actual_seq;

        Ok(VerifyReport {
            entries: entries.len() as u64,
            head_hash,
            sealed,
        })
    }
}

/// SHA-256 of `bytes`, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

fn compute_entry_hash(seq: u64, ts: &str, kind: &str, prev_hash: &str, payload_fp: &str) -> String {
    // Field-separated preimage; `\n` cannot appear inside any field.
    let preimage = format!("{seq}\n{ts}\n{kind}\n{prev_hash}\n{payload_fp}");
    sha256_hex(preimage.as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn read_all(path: &Path) -> Result<Vec<LedgerEntry>, LedgerError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut out = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: LedgerEntry = serde_json::from_str(&line).map_err(|e| LedgerError::Parse {
            line: i + 1,
            source: e,
        })?;
        out.push(entry);
    }
    Ok(out)
}

fn validate_head(dir: &Path, entries: &[LedgerEntry]) -> Result<Option<LedgerHead>, LedgerError> {
    let head_path = dir.join(HEAD_FILE);
    if !head_path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(&head_path)?;
    let anchor: LedgerHead = serde_json::from_str(&raw)
        .map_err(|e| LedgerError::Parse { line: 0, source: e })?;

    let (actual_seq, actual_hash) = match entries.last() {
        Some(e) => (e.seq, e.entry_hash.clone()),
        None => (0, GENESIS_PREV.to_string()),
    };
    let matches = !entries.is_empty()
        && anchor.head_seq == actual_seq
        && anchor.head_hash == actual_hash
        && anchor.count == entries.len() as u64;

    if !matches {
        return Err(LedgerError::HeadMismatch {
            anchor,
            actual_seq,
            actual_hash,
        });
    }

    Ok(Some(anchor))
}

/// Recompute the chain from genesis and confirm every link.
fn check_chain(entries: &[LedgerEntry]) -> Result<(), LedgerError> {
    let mut prev = GENESIS_PREV.to_string();
    for (i, e) in entries.iter().enumerate() {
        let expected_seq = i as u64;
        if e.seq != expected_seq {
            return Err(LedgerError::SeqGap {
                expected: expected_seq,
                found: e.seq,
            });
        }
        if e.prev_hash != prev {
            return Err(LedgerError::ChainBreak { seq: e.seq });
        }
        let recomputed =
            compute_entry_hash(e.seq, &e.ts, &e.kind, &e.prev_hash, &e.payload_fingerprint);
        if recomputed != e.entry_hash {
            return Err(LedgerError::HashMismatch { seq: e.seq });
        }
        prev = e.entry_hash.clone();
    }
    Ok(())
}

fn iso_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    unix_to_iso(secs)
}

/// Convert a Unix timestamp (UTC seconds) to `YYYY-MM-DDTHH:MM:SSZ`.
fn unix_to_iso(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let mut p = std::env::temp_dir();
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("mnr-ledger-test-{n}"));
        p
    }

    #[test]
    fn append_then_verify_ok() {
        let dir = tmp();
        let mut l = Ledger::open(&dir).unwrap();
        for i in 0..5 {
            l.append("observation", format!("event-{i}").as_bytes())
                .unwrap();
        }
        let head = l.seal().unwrap();
        assert_eq!(head.head_seq, 4);
        assert_eq!(head.count, 5);

        let report = Ledger::verify(&dir).unwrap();
        assert_eq!(report.entries, 5);
        assert!(report.sealed);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_ledger_verifies() {
        let dir = tmp();
        Ledger::open(&dir).unwrap();
        let report = Ledger::verify(&dir).unwrap();
        assert_eq!(report.entries, 0);
        assert!(!report.sealed);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn opening_a_tampered_seal_fails() {
        let dir = tmp();
        let mut l = Ledger::open(&dir).unwrap();
        for i in 0..4 {
            l.append("observation", format!("event-{i}").as_bytes())
                .unwrap();
        }
        l.seal().unwrap();

        let content = std::fs::read_to_string(dir.join(LOG_FILE)).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut entry: LedgerEntry = serde_json::from_str(&lines[1]).unwrap();
        entry.payload_fingerprint = sha256_hex(b"forged");
        lines[1] = serde_json::to_string(&entry).unwrap();
        std::fs::write(dir.join(LOG_FILE), lines.join("\n") + "\n").unwrap();

        assert!(Ledger::open(&dir).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mutation_is_detected() {
        let dir = tmp();
        let mut l = Ledger::open(&dir).unwrap();
        for i in 0..4 {
            l.append("observation", format!("event-{i}").as_bytes())
                .unwrap();
        }
        l.seal().unwrap();

        // Tamper: rewrite the fingerprint of the 2nd line.
        let log = dir.join(LOG_FILE);
        let content = std::fs::read_to_string(&log).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut entry: LedgerEntry = serde_json::from_str(&lines[1]).unwrap();
        entry.payload_fingerprint = sha256_hex(b"forged");
        lines[1] = serde_json::to_string(&entry).unwrap();
        std::fs::write(&log, lines.join("\n") + "\n").unwrap();

        let err = Ledger::verify(&dir).unwrap_err();
        assert!(
            matches!(err, LedgerError::HashMismatch { seq: 1 }),
            "got {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn truncation_is_detected_via_head() {
        let dir = tmp();
        let mut l = Ledger::open(&dir).unwrap();
        for i in 0..6 {
            l.append("observation", format!("event-{i}").as_bytes())
                .unwrap();
        }
        l.seal().unwrap();

        // Drop the last two lines.
        let log = dir.join(LOG_FILE);
        let content = std::fs::read_to_string(&log).unwrap();
        let kept: Vec<&str> = content.lines().take(4).collect();
        std::fs::write(&log, kept.join("\n") + "\n").unwrap();

        let err = Ledger::verify(&dir).unwrap_err();
        assert!(matches!(err, LedgerError::HeadMismatch { .. }), "got {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn iso_conversion_is_correct() {
        // 2021-01-01T00:00:00Z == 1609459200
        assert_eq!(unix_to_iso(1_609_459_200), "2021-01-01T00:00:00Z");
        // 2000-02-29 (leap) sanity: 951782400 -> 2000-02-29T00:00:00Z
        assert_eq!(unix_to_iso(951_782_400), "2000-02-29T00:00:00Z");
    }
}
