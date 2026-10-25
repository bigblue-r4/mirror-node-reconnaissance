//! `mnr bundle` end to end: keys on disk, a bundle written, and the refusals
//! that keep an issued bundle from being replaced.
//!
//! Signature and tree correctness are checked in `mnr-bundle` and by the
//! independent Python verifier on committed fixtures; this test is about the
//! command a clerk actually runs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const LOG: &str = concat!(
    "{\"seq\":1,\"level\":\"INFO\",\"data\":{\"case_number\":\"CASE-B\"}}\n",
    "{\"seq\":2,\"level\":\"INFO\",\"data\":{\"case_number\":\"CASE-A\"}}\n",
    "{\"seq\":3,\"level\":\"INFO\",\"data\":{\"case_number\":\"CASE-A\"}}\n",
);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mnr-bundle-cli-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Temp(path)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

fn mnr(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mnr"))
        .args(args)
        .output()
        .expect("mnr binary runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn export(temp: &Temp, out: &Path, department: &str, extra: &[&str]) -> Output {
    let log = temp.path("entries.ndjson");
    let node = temp.path("node.key");
    let exporter = temp.path("exporter.key");
    let out = out.display().to_string();
    let mut args = vec![
        "bundle",
        "export",
        "--log",
        &log,
        "--out",
        &out,
        "--scope",
        "case",
        "--case",
        "CASE-A",
        "--node-key",
        &node,
        "--exporter-key",
        &exporter,
        "--department",
        department,
        "--node-id",
        "node-001",
        "--generated-at",
        "2026-05-12T14:30:00Z",
        "--bundle-id",
        "BUNDLE-20260512-a3b2c1d0",
    ];
    args.extend_from_slice(extra);
    mnr(&args)
}

#[test]
fn keygen_then_export_then_refuse_to_overwrite() {
    let temp = Temp::new();
    fs::write(temp.path("entries.ndjson"), LOG).unwrap();

    for (name, expected_len) in [("node.key", 64), ("exporter.key", 64)] {
        let out = temp.path(name);
        let output = mnr(&["bundle", "keygen", "--out", &out]);
        assert!(output.status.success(), "{}", stderr(&output));
        let text = fs::read_to_string(&out).unwrap();
        assert_eq!(text.trim().len(), expected_len);
        assert!(text.trim().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(temp.path("node.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let bundle = temp.0.join("case.ndjson");
    let output = export(&temp, &bundle, "Honolulu PD", &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    let bytes = fs::read(&bundle).unwrap();
    assert!(bytes.ends_with(b"\n"));
    let header_line = bytes.split(|byte| *byte == b'\n').next().unwrap();
    let header: serde_json::Value = serde_json::from_slice(header_line).unwrap();
    assert_eq!(header["format"], "witness-bundle/2");
    assert_eq!(header["entry_count"], 2);
    assert_eq!(header["log_head"]["size"], 3);
    assert_eq!(header["proofs"].as_array().unwrap().len(), 2);
    assert_eq!(header["signature"].as_str().unwrap().len(), 128);
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 3);

    // A new bundle is a new claim; the existing file is never replaced.
    let output = export(&temp, &bundle, "Honolulu PD", &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("never overwritten"),
        "{}",
        stderr(&output)
    );

    let output = mnr(&["bundle", "keygen", "--out", &temp.path("node.key")]);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn the_command_refuses_values_it_cannot_sign_unambiguously() {
    let temp = Temp::new();
    fs::write(temp.path("entries.ndjson"), LOG).unwrap();
    for name in ["node.key", "exporter.key"] {
        let out = temp.path(name);
        let output = mnr(&["bundle", "keygen", "--out", &out]);
        assert!(output.status.success(), "{}", stderr(&output));
    }
    let bundle = temp.0.join("case.ndjson");

    let output = export(&temp, &bundle, "Honolulu PD\nextra=field", &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("line break"),
        "{}",
        stderr(&output)
    );

    // A usage error is distinct from a producer error.
    let output = mnr(&[
        "bundle",
        "export",
        "--log",
        &temp.path("entries.ndjson"),
        "--out",
        &temp.path("case.ndjson"),
        "--scope",
        "case",
        "--node-key",
        &temp.path("node.key"),
        "--exporter-key",
        &temp.path("exporter.key"),
        "--department",
        "Honolulu PD",
        "--node-id",
        "node-001",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--case"));
}
