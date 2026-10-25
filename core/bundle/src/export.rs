//! Encoding and signing: `BUNDLE_SCHEMA.md` §4.2–§4.6.
//!
//! Two signatures go into a bundle, and they cover different things:
//!
//! * the **node** signs `size_be8 ‖ root` (the head), with no document around it;
//! * the **exporter** signs the line preimage of §4.3, which names both keys but
//!   excludes the proofs and the head signature.
//!
//! Neither signature covers the entry lines directly. The head signature covers
//! the root, and each proof ties one entry line to that root, which is what makes
//! the two signatures add up to "these entries were in this log" rather than two
//! independent statements.

use crate::keys::{public_hex, to_hex};
use crate::log::Log;
use crate::{BundleError, FORMAT};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Which entries a bundle discloses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Entries whose `data.case_number` equals the requested case.
    Case,
    /// Every entry in the log.
    Log,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Case => "case",
            Scope::Log => "log",
        }
    }
}

/// Everything the caller supplies for one export.
///
/// [`ExportRequest::new`] fills the optional fields with empty strings, which the
/// preimage still emits (§4.3): absence is a value, so a field cannot be added or
/// removed without changing the signature.
#[derive(Debug, Clone)]
pub struct ExportRequest {
    pub bundle_id: String,
    pub generated_at: String,
    pub scope: Scope,
    pub case_number: String,
    pub department: String,
    pub agency: String,
    pub seal: String,
    pub node_id: String,
    pub export_actor: String,
    pub export_role: String,
}

impl ExportRequest {
    pub fn new(scope: Scope) -> Self {
        ExportRequest {
            bundle_id: String::new(),
            generated_at: String::new(),
            scope,
            case_number: String::new(),
            department: String::new(),
            agency: String::new(),
            seal: String::new(),
            node_id: String::new(),
            export_actor: String::new(),
            export_role: String::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct Header {
    format: &'static str,
    bundle_id: String,
    generated_at: String,
    scope: &'static str,
    case_number: String,
    department: String,
    agency: String,
    seal: String,
    node_id: String,
    entry_count: u64,
    sha256_chain: String,
    export_actor: String,
    export_role: String,
    signed_by: String,
    log_head: LogHead,
    proofs: Vec<Proof>,
    signature: String,
}

#[derive(Debug, Serialize)]
struct LogHead {
    size: u64,
    root: String,
    ts: String,
    sig: String,
    signer_key: String,
}

#[derive(Debug, Serialize)]
struct Proof {
    seq: u64,
    index: u64,
    size: u64,
    path: Vec<String>,
}

/// Write a `witness-bundle/2` file.
///
/// `node` signs the tree head this call computes from `log`; `exporter` signs the
/// header. The head's `ts` is `request.generated_at`, because the head is minted
/// at export time — it is the node's own statement, not a timestamp authority's
/// (§4.5, §8).
pub fn export(
    log: &Log,
    request: &ExportRequest,
    node: &SigningKey,
    exporter: &SigningKey,
) -> Result<Vec<u8>, BundleError> {
    match request.scope {
        Scope::Case if request.case_number.is_empty() => {
            return Err(BundleError::field(
                "case_number",
                "scope=case requires a non-empty case number",
            ));
        }
        Scope::Log if !request.case_number.is_empty() => {
            return Err(BundleError::field(
                "case_number",
                "scope=log requires an empty case number",
            ));
        }
        _ => {}
    }

    for (name, value) in [
        ("bundle_id", request.bundle_id.as_str()),
        ("generated_at", request.generated_at.as_str()),
        ("case_number", request.case_number.as_str()),
        ("department", request.department.as_str()),
        ("agency", request.agency.as_str()),
        ("seal", request.seal.as_str()),
        ("node_id", request.node_id.as_str()),
        ("export_actor", request.export_actor.as_str()),
        ("export_role", request.export_role.as_str()),
    ] {
        no_newline(name, value)?;
    }
    for (name, value) in [
        ("bundle_id", request.bundle_id.as_str()),
        ("generated_at", request.generated_at.as_str()),
        ("department", request.department.as_str()),
        ("node_id", request.node_id.as_str()),
    ] {
        if value.is_empty() {
            return Err(BundleError::field(name, "is required and cannot be empty"));
        }
    }

    let selected: Vec<usize> = match request.scope {
        Scope::Log => (0..log.len()).collect(),
        Scope::Case => (0..log.len())
            .filter(|&index| log.case_of(index) == Some(request.case_number.as_str()))
            .collect(),
    };

    let mut digest = Sha256::new();
    for &index in &selected {
        digest.update(&log.lines()[index]);
    }
    let sha256_chain = to_hex(&digest.finalize());

    let size = log.tree().size() as u64;
    let root = log.tree().root();

    let mut head_input = [0u8; 40];
    head_input[..8].copy_from_slice(&size.to_be_bytes());
    head_input[8..].copy_from_slice(&root);
    let head_signature = node.sign(&head_input);

    let mut proofs = Vec::with_capacity(selected.len());
    for &index in &selected {
        let seq = log.seqs()[index];
        let path = log.tree().prove(index).ok_or_else(|| {
            BundleError::field("proofs", format!("no audit path for entry index {index}"))
        })?;
        proofs.push(Proof {
            seq,
            index: seq - 1,
            size,
            path: path.iter().map(|hash| to_hex(hash)).collect(),
        });
    }

    let mut header = Header {
        format: FORMAT,
        bundle_id: request.bundle_id.clone(),
        generated_at: request.generated_at.clone(),
        scope: request.scope.as_str(),
        case_number: request.case_number.clone(),
        department: request.department.clone(),
        agency: request.agency.clone(),
        seal: request.seal.clone(),
        node_id: request.node_id.clone(),
        entry_count: selected.len() as u64,
        sha256_chain,
        export_actor: request.export_actor.clone(),
        export_role: request.export_role.clone(),
        signed_by: public_hex(exporter),
        log_head: LogHead {
            size,
            root: to_hex(&root),
            ts: request.generated_at.clone(),
            sig: to_hex(&head_signature.to_bytes()),
            signer_key: public_hex(node),
        },
        proofs,
        signature: String::new(),
    };

    let signature = exporter.sign(&preimage(&header));
    header.signature = to_hex(&signature.to_bytes());

    let mut out = serde_json::to_vec(&header)?;
    out.push(b'\n');
    for &index in &selected {
        out.extend_from_slice(&log.lines()[index]);
        out.push(b'\n');
    }
    Ok(out)
}

fn no_newline(name: &'static str, value: &str) -> Result<(), BundleError> {
    if value.contains('\n') || value.contains('\r') {
        return Err(BundleError::field(
            name,
            "contains a line break; the signed preimage is line-oriented, so a \
             value with CR or LF would be read back differently",
        ));
    }
    Ok(())
}

/// The bytes the bundle signature covers: §4.3, in order, with an empty optional
/// field still emitted as `key=`.
fn preimage(header: &Header) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(FORMAT);
    out.push('\n');
    for (name, value) in [
        ("bundle_id", header.bundle_id.as_str()),
        ("generated_at", header.generated_at.as_str()),
        ("scope", header.scope),
        ("case_number", header.case_number.as_str()),
        ("department", header.department.as_str()),
        ("agency", header.agency.as_str()),
        ("seal", header.seal.as_str()),
        ("node_id", header.node_id.as_str()),
    ] {
        out.push_str(name);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out.push_str("entry_count=");
    out.push_str(&header.entry_count.to_string());
    out.push('\n');
    out.push_str("sha256_chain=");
    out.push_str(&header.sha256_chain);
    out.push('\n');
    out.push_str("export_actor=");
    out.push_str(&header.export_actor);
    out.push('\n');
    out.push_str("export_role=");
    out.push_str(&header.export_role);
    out.push('\n');
    out.push_str("signed_by=");
    out.push_str(&header.signed_by);
    out.push('\n');
    out.push_str("log_head.size=");
    out.push_str(&header.log_head.size.to_string());
    out.push('\n');
    out.push_str("log_head.root=");
    out.push_str(&header.log_head.root);
    out.push('\n');
    out.push_str("log_head.ts=");
    out.push_str(&header.log_head.ts);
    out.push('\n');
    out.push_str("log_head.signer_key=");
    out.push_str(&header.log_head.signer_key);
    out.push('\n');
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{decode_hex, from_seed_hex};
    use ed25519_dalek::{Signature, Verifier};

    const LOG: &str = concat!(
        "{\"seq\":1,\"ts\":\"2026-05-12T14:00:00Z\",\"level\":\"INFO\",",
        "\"event\":\"pd/access\",\"source\":\"pd\",",
        "\"data\":{\"case_number\":\"CASE-A\",\"item_id\":\"ITEM-1\"}}\n",
        "{\"seq\":2,\"ts\":\"2026-05-12T14:01:00Z\",\"level\":\"INFO\",",
        "\"event\":\"pd/access\",\"source\":\"pd\",",
        "\"data\":{\"case_number\":\"CASE-B\",\"item_id\":\"ITEM-2\"}}\n",
        "{\"seq\":3,\"ts\":\"2026-05-12T14:02:00Z\",\"level\":\"INFO\",",
        "\"event\":\"pd/access\",\"source\":\"pd\",",
        "\"data\":{\"case_number\":\"CASE-A\",\"item_id\":\"ITEM-3\"}}\n",
    );

    fn keys() -> (SigningKey, SigningKey) {
        let node = from_seed_hex(&"11".repeat(32)).unwrap();
        let exporter = from_seed_hex(&"22".repeat(32)).unwrap();
        (node, exporter)
    }

    fn request(scope: Scope) -> ExportRequest {
        let mut request = ExportRequest::new(scope);
        request.bundle_id = "BUNDLE-20260512-a3b2c1d0".into();
        request.generated_at = "2026-05-12T14:30:00Z".into();
        request.case_number = if scope == Scope::Case {
            "CASE-A".into()
        } else {
            String::new()
        };
        request.department = "Honolulu PD".into();
        request.agency = "Honolulu Police Department".into();
        request.seal = "HPD-2026".into();
        request.node_id = "node-001".into();
        request.export_actor = "Sgt. Example".into();
        request.export_role = "evidence_clerk".into();
        request
    }

    fn header_of(bytes: &[u8]) -> serde_json::Value {
        let line = bytes.split(|byte| *byte == b'\n').next().unwrap();
        serde_json::from_slice(line).unwrap()
    }

    /// Rebuild the preimage from the emitted header JSON, in the order §4.3 lists.
    /// Independent of `preimage()`, so the signature is checked against the
    /// document's own bytes rather than against the struct that wrote them.
    fn preimage_from_json(header: &serde_json::Value) -> Vec<u8> {
        let mut out = String::from("witness-bundle/2\n");
        for field in [
            "bundle_id",
            "generated_at",
            "scope",
            "case_number",
            "department",
            "agency",
            "seal",
            "node_id",
        ] {
            out.push_str(&format!("{field}={}\n", header[field].as_str().unwrap()));
        }
        out.push_str(&format!(
            "entry_count={}\n",
            header["entry_count"].as_u64().unwrap()
        ));
        for field in ["sha256_chain", "export_actor", "export_role", "signed_by"] {
            out.push_str(&format!("{field}={}\n", header[field].as_str().unwrap()));
        }
        out.push_str(&format!(
            "log_head.size={}\n",
            header["log_head"]["size"].as_u64().unwrap()
        ));
        for field in ["root", "ts", "signer_key"] {
            out.push_str(&format!(
                "log_head.{field}={}\n",
                header["log_head"][field].as_str().unwrap()
            ));
        }
        out.into_bytes()
    }

    #[test]
    fn the_preimage_is_the_specified_byte_string() {
        let chain = "9f1c".repeat(16);
        let signed_by = "3b1f".repeat(16);
        let root = "9d2c".repeat(16);
        let signer_key = "8a01".repeat(16);
        let header = Header {
            format: FORMAT,
            bundle_id: "BUNDLE-20260512-a3b2c1d0".into(),
            generated_at: "2026-05-12T14:30:00Z".into(),
            scope: "case",
            case_number: "CASE-2026-0042".into(),
            department: "Honolulu PD".into(),
            agency: "Honolulu Police Department".into(),
            seal: "HPD-2026".into(),
            node_id: "node-001".into(),
            entry_count: 7,
            sha256_chain: chain.clone(),
            export_actor: "Sgt. Example".into(),
            export_role: "evidence_clerk".into(),
            signed_by: signed_by.clone(),
            log_head: LogHead {
                size: 41207,
                root: root.clone(),
                ts: "2026-05-12T14:29:58Z".into(),
                sig: "ff".repeat(64),
                signer_key: signer_key.clone(),
            },
            proofs: Vec::new(),
            signature: String::new(),
        };
        let expected = format!(
            "witness-bundle/2\n\
             bundle_id=BUNDLE-20260512-a3b2c1d0\n\
             generated_at=2026-05-12T14:30:00Z\n\
             scope=case\n\
             case_number=CASE-2026-0042\n\
             department=Honolulu PD\n\
             agency=Honolulu Police Department\n\
             seal=HPD-2026\n\
             node_id=node-001\n\
             entry_count=7\n\
             sha256_chain={chain}\n\
             export_actor=Sgt. Example\n\
             export_role=evidence_clerk\n\
             signed_by={signed_by}\n\
             log_head.size=41207\n\
             log_head.root={root}\n\
             log_head.ts=2026-05-12T14:29:58Z\n\
             log_head.signer_key={signer_key}\n"
        );
        assert_eq!(String::from_utf8(preimage(&header)).unwrap(), expected);
    }

    #[test]
    fn a_case_bundle_binds_the_entries_to_the_full_log() {
        let log = Log::parse(LOG.as_bytes()).unwrap();
        let (node, exporter) = keys();
        let bytes = export(&log, &request(Scope::Case), &node, &exporter).unwrap();
        let header = header_of(&bytes);

        assert_eq!(header["format"], "witness-bundle/2");
        assert_eq!(header["scope"], "case");
        assert_eq!(header["entry_count"], 2);
        assert_eq!(header["log_head"]["size"], 3);
        assert_eq!(header["log_head"]["root"], log.root_hex().as_str());
        assert_eq!(header["signed_by"], public_hex(&exporter).as_str());
        assert_eq!(header["log_head"]["signer_key"], public_hex(&node).as_str());

        let proofs = header["proofs"].as_array().unwrap();
        assert_eq!(proofs.len(), 2);
        assert_eq!(proofs[0]["seq"], 1);
        assert_eq!(proofs[0]["index"], 0);
        assert_eq!(proofs[1]["seq"], 3);
        assert_eq!(proofs[1]["index"], 2);
        assert_eq!(proofs[0]["size"], 3);

        // The header describes the bytes that follow it.
        let body: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').skip(1).collect();
        assert_eq!(body.len(), 3, "two entries plus the empty tail");
        assert_eq!(body[2], b"");

        // Both signatures verify under the keys the header names.
        let signature = Signature::from_slice(
            &decode_hex(header["signature"].as_str().unwrap(), 64, "signature").unwrap(),
        )
        .unwrap();
        exporter
            .verifying_key()
            .verify(&preimage_from_json(&header), &signature)
            .expect("bundle signature verifies");

        let root = decode_hex(header["log_head"]["root"].as_str().unwrap(), 32, "root").unwrap();
        let mut head_input = Vec::new();
        head_input.extend_from_slice(&3u64.to_be_bytes());
        head_input.extend_from_slice(&root);
        let head_signature = Signature::from_slice(
            &decode_hex(header["log_head"]["sig"].as_str().unwrap(), 64, "sig").unwrap(),
        )
        .unwrap();
        node.verifying_key()
            .verify(&head_input, &head_signature)
            .expect("head signature verifies");
    }

    #[test]
    fn a_log_bundle_carries_every_entry() {
        let log = Log::parse(LOG.as_bytes()).unwrap();
        let (node, exporter) = keys();
        let bytes = export(&log, &request(Scope::Log), &node, &exporter).unwrap();
        let header = header_of(&bytes);
        assert_eq!(header["entry_count"], 3);
        assert_eq!(header["proofs"].as_array().unwrap().len(), 3);
        assert_eq!(header["log_head"]["size"], 3);
    }

    #[test]
    fn a_case_with_no_entries_is_an_empty_bundle() {
        let log = Log::parse(LOG.as_bytes()).unwrap();
        let (node, exporter) = keys();
        let mut request = request(Scope::Case);
        request.case_number = "CASE-MISSING".into();
        let bytes = export(&log, &request, &node, &exporter).unwrap();
        let header = header_of(&bytes);
        assert_eq!(header["entry_count"], 0);
        assert_eq!(header["proofs"].as_array().unwrap().len(), 0);
        assert_eq!(
            header["sha256_chain"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // Header line and no entry lines.
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
    }

    #[test]
    fn a_zero_entry_log_still_exports() {
        let log = Log::parse(b"").unwrap();
        let (node, exporter) = keys();
        let bytes = export(&log, &request(Scope::Log), &node, &exporter).unwrap();
        let header = header_of(&bytes);
        assert_eq!(header["log_head"]["size"], 0);
        assert_eq!(header["log_head"]["root"], "00".repeat(32));
        assert_eq!(header["entry_count"], 0);
    }

    #[test]
    fn scope_rules_are_enforced() {
        let log = Log::parse(LOG.as_bytes()).unwrap();
        let (node, exporter) = keys();

        let mut case_without_number = request(Scope::Case);
        case_without_number.case_number = String::new();
        assert!(export(&log, &case_without_number, &node, &exporter).is_err());

        let mut log_with_case = request(Scope::Log);
        log_with_case.case_number = "CASE-A".into();
        assert!(export(&log, &log_with_case, &node, &exporter).is_err());
    }

    #[test]
    fn a_line_break_in_a_header_value_is_refused() {
        let log = Log::parse(LOG.as_bytes()).unwrap();
        let (node, exporter) = keys();
        let mut injected_department = request(Scope::Case);
        injected_department.department = "Honolulu PD\nextra=field".into();
        let error = export(&log, &injected_department, &node, &exporter).unwrap_err();
        assert!(error.to_string().contains("department"), "{error}");

        let mut injected_actor = request(Scope::Case);
        injected_actor.export_actor = "Sgt.\rInjected".into();
        assert!(export(&log, &injected_actor, &node, &exporter).is_err());
    }

    #[test]
    fn required_fields_cannot_be_empty() {
        let log = Log::parse(LOG.as_bytes()).unwrap();
        let (node, exporter) = keys();
        let mut missing_id = request(Scope::Case);
        missing_id.bundle_id.clear();
        assert!(export(&log, &missing_id, &node, &exporter).is_err());

        let mut missing_time = request(Scope::Case);
        missing_time.generated_at.clear();
        assert!(export(&log, &missing_time, &node, &exporter).is_err());

        let mut missing_department = request(Scope::Case);
        missing_department.department.clear();
        assert!(export(&log, &missing_department, &node, &exporter).is_err());

        let mut missing_node = request(Scope::Case);
        missing_node.node_id.clear();
        assert!(export(&log, &missing_node, &node, &exporter).is_err());
    }

    #[test]
    fn empty_optional_fields_are_signed_as_empty() {
        let log = Log::parse(LOG.as_bytes()).unwrap();
        let (node, exporter) = keys();
        let mut request = request(Scope::Log);
        request.agency.clear();
        request.seal.clear();
        request.export_actor.clear();
        request.export_role.clear();
        let bytes = export(&log, &request, &node, &exporter).unwrap();
        let header = header_of(&bytes);
        assert_eq!(header["agency"], "");
        assert_eq!(header["seal"], "");
        assert_eq!(header["export_actor"], "");
        assert_eq!(header["export_role"], "");
        assert!(header["signature"].as_str().unwrap().len() == 128);
    }
}
