//! A sealed head signed by the node key, checked end to end through the binary.
//!
//! `mnr-bundle` signs exports and `mnr-ledger` signs the seal; this test is about
//! the operator's path — mint a key, run the lab with it, and find out whether a
//! verifier holding that public key reaches a different conclusion from one that
//! does not.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mnr-head-sig-cli-{}-{}-{}",
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

/// Run `mnr` from the workspace root, where `configs/mnr.toml` lives.
fn mnr(args: &[&str]) -> Output {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli sits one level under the workspace root");
    Command::new(env!("CARGO_BIN_EXE_mnr"))
        .args(args)
        .current_dir(root)
        .output()
        .expect("mnr binary runs")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_run_sealed_with_a_key_verifies_only_against_that_key() {
    let temp = Temp::new();
    let key = temp.path("node.key");
    let keygen = mnr(&["bundle", "keygen", "--out", &key]);
    assert!(keygen.status.success(), "keygen failed: {}", text(&keygen));

    let dir = temp.path("run");
    let demo = mnr(&["demo", "--dir", &dir, "--head-key", &key]);
    assert!(demo.status.success(), "demo failed: {}", text(&demo));
    assert!(
        text(&demo).contains("signed=true"),
        "the seal should be signed: {}",
        text(&demo)
    );

    // The same key: an intact, attributable seal.
    let pinned = mnr(&["ledger", "verify", "--dir", &dir, "--head-key", &key]);
    assert!(
        pinned.status.success(),
        "pinned verify failed: {}",
        text(&pinned)
    );
    assert!(text(&pinned).contains("signed=true"), "{}", text(&pinned));

    // A different key: the chain still verifies, the seal is not this key's.
    let other = temp.path("other.key");
    assert!(mnr(&["bundle", "keygen", "--out", &other]).status.success());
    let wrong = mnr(&["ledger", "verify", "--dir", &dir, "--head-key", &other]);
    assert_eq!(wrong.status.code(), Some(1), "{}", text(&wrong));
    assert!(
        text(&wrong).contains("does not verify under the pinned key"),
        "{}",
        text(&wrong)
    );

    // No key at all: a valid seal, with the signature reported but not judged.
    let unprejudiced = mnr(&["ledger", "verify", "--dir", &dir]);
    assert!(unprejudiced.status.success(), "{}", text(&unprejudiced));
    assert!(
        text(&unprejudiced).contains("signed=true"),
        "{}",
        text(&unprejudiced)
    );
}

#[test]
fn an_unsigned_run_still_verifies_but_cannot_satisfy_a_pinned_key() {
    let temp = Temp::new();
    let dir = temp.path("run");
    let demo = mnr(&["demo", "--dir", &dir]);
    assert!(demo.status.success(), "demo failed: {}", text(&demo));
    assert!(text(&demo).contains("signed=false"), "{}", text(&demo));

    let key = temp.path("node.key");
    assert!(mnr(&["bundle", "keygen", "--out", &key]).status.success());
    let pinned = mnr(&["ledger", "verify", "--dir", &dir, "--head-key", &key]);
    assert_eq!(pinned.status.code(), Some(1), "{}", text(&pinned));
    assert!(
        text(&pinned).contains("carries no signature"),
        "{}",
        text(&pinned)
    );
}
