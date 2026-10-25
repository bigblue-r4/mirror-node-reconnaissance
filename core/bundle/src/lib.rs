//! `mnr-bundle` — the producer and signer for `witness-bundle/2`.
//!
//! `witness-bundle/2` is specified in `BUNDLE_SCHEMA.md` §4: a header line whose
//! signature covers a fixed, line-oriented preimage, a copy of the node's signed
//! tree head, and one Merkle inclusion proof per entry. This crate writes that
//! file. Verification lives elsewhere on purpose — `tools/bundle-verify/` is an
//! independent implementation written from the schema — so a failure in one is
//! not masked by the other.
//!
//! # What a bundle proves
//!
//! A bundle signed here says: *the holder of this exporter key signed these
//! entry lines, and each of them is a leaf of the tree whose root the holder of
//! this node key signed.* It does not say the log was complete, that the head was
//! published at the time it claims, or that the entries describe real events.
//!
//! The producer mints the head at export time from the log it is given: it
//! computes the BLAKE3 Merkle root over the entry lines, signs `size ‖ root` with
//! the node key, and copies it into the header. A node that signs a fabricated or
//! truncated log produces a bundle that verifies, exactly as it would with any
//! signing key it controls. Retaining a head outside the node at seal time — a
//! timestamp authority, a counterparty, a ticket — is what would give the head a
//! life of its own, and this crate does not do that.
//!
//! # Input
//!
//! The log is a UTF-8 file of store entries, one JSON object per line, in
//! ascending `seq`, numbered `1..=n`. Entry fields are the store's: `seq`, `ts`,
//! `level`, `event`, `source`, `data`. Lines are carried through **byte for
//! byte**; this crate never re-serialises an entry, because the leaf is the line
//! as written (§4.4). Scope `case` selects entries whose `data.case_number`
//! equals the requested case; the proofs are still taken from the full log, so a
//! case bundle discloses the tree shape and nothing else about the other records.
//!
//! # Example
//!
//! The CLI is the intended entry point: `mnr bundle keygen` writes a seed file,
//! `mnr bundle export` writes the bundle and prints the two public keys a
//! recipient must pin.
//!
//! ```no_run
//! use mnr_bundle::{export, ExportRequest, Log, Scope};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let log_bytes = std::fs::read("entries.ndjson")?;
//! let log = Log::parse(&log_bytes)?;
//!
//! let node = mnr_bundle::from_seed_hex(&"11".repeat(32))?;
//! let exporter = mnr_bundle::from_seed_hex(&"22".repeat(32))?;
//!
//! let mut request = ExportRequest::new(Scope::Case);
//! request.bundle_id = "BUNDLE-20260512-a3b2c1d0".into();
//! request.generated_at = "2026-05-12T14:30:00Z".into();
//! request.case_number = "CASE-2026-0042".into();
//! request.department = "Honolulu PD".into();
//! request.node_id = "node-001".into();
//!
//! let bytes = export(&log, &request, &node, &exporter)?;
//! # let _ = bytes;
//! # Ok(())
//! # }
//! ```

mod export;
mod keys;
mod log;
mod merkle;

use std::fmt;

pub use ed25519_dalek::SigningKey;
pub use export::{export, ExportRequest, Scope};
pub use keys::{from_seed_hex, generate, public_hex, random_hex, seed_hex, to_hex};
pub use log::Log;

/// The value of the header's `format` field, and the first line of the signed
/// preimage.
pub const FORMAT: &str = "witness-bundle/2";

/// Everything the producer refuses to do, with the reason a caller can act on.
#[derive(Debug)]
pub enum BundleError {
    /// The log file as a whole is not the expected envelope: CRLF, no final
    /// newline, or a blank line.
    Envelope(String),
    /// A log line failed the entry rules (`BUNDLE_SCHEMA.md` §4.4). `line` is
    /// 1-based within the log file.
    Log { line: usize, detail: String },
    /// A header value is missing, empty, or could not be signed safely.
    Field { name: &'static str, detail: String },
    /// A key file, seed or hex string was not the expected shape.
    Key(String),
    /// The platform random source failed while minting a seed or an id.
    Random(String),
    /// The header could not be serialised as JSON.
    Json(serde_json::Error),
}

impl BundleError {
    pub(crate) fn envelope(detail: impl Into<String>) -> Self {
        BundleError::Envelope(detail.into())
    }

    pub(crate) fn log(line: usize, detail: impl Into<String>) -> Self {
        BundleError::Log {
            line,
            detail: detail.into(),
        }
    }

    pub(crate) fn field(name: &'static str, detail: impl Into<String>) -> Self {
        BundleError::Field {
            name,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleError::Envelope(detail) => write!(f, "log file: {detail}"),
            BundleError::Log { line, detail } => {
                write!(f, "log line {line}: {detail}")
            }
            BundleError::Field { name, detail } => write!(f, "header field {name}: {detail}"),
            BundleError::Key(detail) => write!(f, "{detail}"),
            BundleError::Random(detail) => write!(f, "random source failed: {detail}"),
            BundleError::Json(error) => write!(f, "could not encode the header: {error}"),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<serde_json::Error> for BundleError {
    fn from(error: serde_json::Error) -> Self {
        BundleError::Json(error)
    }
}
