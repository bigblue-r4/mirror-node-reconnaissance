//! Key material and hex, with no key storage policy.
//!
//! The producer needs two Ed25519 signing keys: the node's, which signs the tree
//! head, and the exporter's, which signs the header. This module reads and writes
//! raw 32-byte seeds and public keys; where those bytes live is the caller's
//! problem. The CLI stores a seed as a 64-character hex file with `0600`
//! permissions and never prints a seed.

use crate::BundleError;
use ed25519_dalek::SigningKey;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex, the only form the schema names.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode exactly `len` bytes of hex, accepting either case.
pub(crate) fn decode_hex(
    text: &str,
    len: usize,
    what: &'static str,
) -> Result<Vec<u8>, BundleError> {
    if text.len() != len * 2 {
        return Err(BundleError::Key(format!(
            "{what} must be {} hex characters ({} bytes), got {}",
            len * 2,
            len,
            text.len()
        )));
    }
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        let hi = hex_digit(raw[index * 2]).ok_or_else(|| {
            BundleError::Key(format!("{what} contains a character that is not hex"))
        })?;
        let lo = hex_digit(raw[index * 2 + 1]).ok_or_else(|| {
            BundleError::Key(format!("{what} contains a character that is not hex"))
        })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Mint a fresh Ed25519 seed and its signing key.
pub fn generate() -> Result<([u8; 32], SigningKey), BundleError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| BundleError::Random(error.to_string()))?;
    Ok((seed, SigningKey::from_bytes(&seed)))
}

/// Read a signing key from a 32-byte hex seed, as written by `mnr bundle keygen`.
pub fn from_seed_hex(text: &str) -> Result<SigningKey, BundleError> {
    let bytes = decode_hex(text.trim(), 32, "seed")?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

/// Hex public key, to be pinned by the verifier.
pub fn public_hex(key: &SigningKey) -> String {
    to_hex(key.verifying_key().as_bytes())
}

/// Hex encoding of a seed, for the key file.
pub fn seed_hex(seed: &[u8; 32]) -> String {
    to_hex(seed)
}

/// `bytes` random bytes, hex encoded. Used for the per-bundle id suffix.
pub fn random_hex(bytes: usize) -> Result<String, BundleError> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).map_err(|error| BundleError::Random(error.to_string()))?;
    Ok(to_hex(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_bad_lengths() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(to_hex(&bytes), "000fa5ff");
        assert_eq!(decode_hex("000fa5ff", 4, "test").unwrap(), bytes);
        assert!(decode_hex("000fa5", 4, "test").is_err());
        assert!(decode_hex("000fa5zz", 4, "test").is_err());
    }

    #[test]
    fn a_seed_reads_back_to_the_same_public_key() {
        let (seed, key) = generate().unwrap();
        let loaded = from_seed_hex(&seed_hex(&seed)).unwrap();
        assert_eq!(public_hex(&key), public_hex(&loaded));
        assert_eq!(public_hex(&key).len(), 64);
    }

    #[test]
    fn random_ids_are_not_repeated() {
        assert_ne!(random_hex(4).unwrap(), random_hex(4).unwrap());
    }
}
