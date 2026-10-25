//! The input side: a store log read as lines, never parsed and re-encoded.
//!
//! The bundle's leaf is the entry line's bytes (`BUNDLE_SCHEMA.md` §4.4), so this
//! type keeps every line verbatim and parses only enough of it to number the
//! entries and answer the case filter. A producer that reformatted an entry
//! would change its leaf and the proof would fail; not offering that option is
//! the point.

use crate::merkle::Tree;
use crate::{to_hex, BundleError};
use serde_json::Value;

/// A whole log, ready to export.
///
/// Built by [`Log::parse`]. Entries are numbered `1..=n` in file order; a gap,
/// a duplicate or a `seq` that disagrees with the position is refused, because
/// `proof.index == seq - 1` is part of the format and a log with holes would
/// produce proofs that cannot verify.
pub struct Log {
    pub(crate) lines: Vec<Vec<u8>>,
    pub(crate) seqs: Vec<u64>,
    pub(crate) cases: Vec<Option<String>>,
    tree: Tree,
}

impl Log {
    /// Parse a whole-log file: UTF-8, one JSON object per line, final `\n`.
    ///
    /// Empty input is an empty log. That is a real artifact — a node can export
    /// a zero-entry bundle before its first append — and it has the all-zero
    /// root and no proofs.
    pub fn parse(bytes: &[u8]) -> Result<Self, BundleError> {
        if bytes.is_empty() {
            return Ok(Self::assemble(Vec::new(), Vec::new(), Vec::new()));
        }
        if bytes.contains(&b'\r') {
            return Err(BundleError::envelope(
                "contains CR; the format is \\n terminated",
            ));
        }
        if !bytes.ends_with(b"\n") {
            return Err(BundleError::envelope("does not end with a newline"));
        }

        let mut lines = Vec::new();
        let mut seqs = Vec::new();
        let mut cases = Vec::new();
        for (offset, raw) in bytes[..bytes.len() - 1]
            .split(|byte| *byte == b'\n')
            .enumerate()
        {
            let number = offset + 1;
            if raw.is_empty() {
                return Err(BundleError::log(number, "blank line"));
            }
            let value: Value = serde_json::from_slice(raw)
                .map_err(|error| BundleError::log(number, format!("entry is not JSON: {error}")))?;
            let object = value
                .as_object()
                .ok_or_else(|| BundleError::log(number, "entry line is not a JSON object"))?;
            let seq = object
                .get("seq")
                .and_then(Value::as_u64)
                .ok_or_else(|| BundleError::log(number, "entry has no integer 'seq'"))?;
            if seq != number as u64 {
                return Err(BundleError::log(
                    number,
                    format!(
                        "entry seq is {seq}; a log is numbered 1..=n with no gaps, \
                         so line {number} must carry seq {number}"
                    ),
                ));
            }
            let case = object
                .get("data")
                .and_then(Value::as_object)
                .and_then(|data| data.get("case_number"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            lines.push(raw.to_vec());
            seqs.push(seq);
            cases.push(case);
        }
        Ok(Self::assemble(lines, seqs, cases))
    }

    fn assemble(lines: Vec<Vec<u8>>, seqs: Vec<u64>, cases: Vec<Option<String>>) -> Self {
        let tree = Tree::from_lines(&lines);
        Log {
            lines,
            seqs,
            cases,
            tree,
        }
    }

    /// Number of entries in the log.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// BLAKE3 Merkle root over the entry lines, lowercase hex.
    pub fn root_hex(&self) -> String {
        to_hex(&self.tree.root())
    }

    pub(crate) fn lines(&self) -> &[Vec<u8>] {
        &self.lines
    }

    pub(crate) fn seqs(&self) -> &[u64] {
        &self.seqs
    }

    pub(crate) fn case_of(&self, index: usize) -> Option<&str> {
        self.cases[index].as_deref()
    }

    pub(crate) fn tree(&self) -> &Tree {
        &self.tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = concat!(
        "{\"seq\":1,\"level\":\"INFO\",\"data\":{\"case_number\":\"CASE-A\"}}\n",
        "{\"seq\":2,\"level\":\"INFO\",\"data\":{\"case_number\":\"CASE-B\"}}\n",
        "{\"seq\":3,\"level\":\"INFO\",\"data\":{}}\n",
    );

    #[test]
    fn lines_are_kept_byte_for_byte() {
        let log = Log::parse(LOG.as_bytes()).unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log.lines()[0], LOG.lines().next().unwrap().as_bytes());
        assert_eq!(log.seqs(), &[1, 2, 3]);
        assert_eq!(log.case_of(0), Some("CASE-A"));
        assert_eq!(log.case_of(1), Some("CASE-B"));
        assert_eq!(log.case_of(2), None);
    }

    #[test]
    fn an_empty_file_is_an_empty_log() {
        let log = Log::parse(b"").unwrap();
        assert!(log.is_empty());
        assert_eq!(log.root_hex(), "00".repeat(32));
    }

    #[test]
    fn the_envelope_rules_are_enforced() {
        assert!(Log::parse(b"{\"seq\":1}\r\n").is_err());
        assert!(Log::parse(b"{\"seq\":1}").is_err());
        assert!(Log::parse(b"{\"seq\":1}\n\n").is_err());
        assert!(Log::parse(b"\n").is_err());
        assert!(Log::parse(b"[1,2]\n").is_err());
        assert!(Log::parse(b"{}\n").is_err());
        assert!(Log::parse(b"{\"seq\":\"1\"}\n").is_err());
    }

    #[test]
    fn gaps_duplicates_and_zero_are_refused() {
        assert!(Log::parse(b"{\"seq\":2}\n").is_err());
        assert!(Log::parse(b"{\"seq\":1}\n{\"seq\":3}\n").is_err());
        assert!(Log::parse(b"{\"seq\":1}\n{\"seq\":1}\n").is_err());
        assert!(Log::parse(b"{\"seq\":0}\n").is_err());
    }
}
