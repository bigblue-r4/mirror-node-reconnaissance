//! A second *process* must not be able to fork the witness chain.
//!
//! The unit tests cover one process opening the directory twice. This one holds
//! the lock from a genuinely separate process, because the property under test
//! is the kernel releasing the lock across process boundaries — which an
//! in-process test cannot demonstrate.
use mnr_ledger::{Ledger, LedgerError};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Set in the child process: the directory it must hold open.
const CHILD_DIR: &str = "MNR_LOCK_TEST_CHILD_DIR";

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mnr-lock-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Runs only inside the spawned child: take the lock, announce readiness, then
/// hold it until the parent closes stdin (or kills the process).
#[test]
fn child_holds_the_writer_lock() {
    let Ok(dir) = std::env::var(CHILD_DIR) else {
        // An ordinary run of the suite: this test exists for the other one.
        return;
    };
    let _ledger = Ledger::open(&dir).expect("child: open the ledger");
    // A sentinel, not stdout: waiting on a real event rather than a guessed
    // sleep, and it survives the test harness capturing output.
    std::fs::write(Path::new(&dir).join("child-ready"), b"held").unwrap();
    let mut sink = String::new();
    // Returns when stdin reaches EOF, which is how the parent releases us.
    std::io::stdin().lock().read_line(&mut sink).ok();
}

#[test]
fn a_second_process_cannot_write_while_the_first_holds_the_directory() {
    let dir = Temp::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_holds_the_writer_lock"])
        .env(CHILD_DIR, &dir.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the holder process");

    let ready = dir.0.join("child-ready");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the holder did not take the lock within 20s");
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let err = match Ledger::open(&dir.0) {
        Err(e) => e,
        Ok(_) => panic!("a second process opened a ledger that another process holds"),
    };
    assert!(matches!(err, LedgerError::Locked { .. }), "got {err}");

    // Closing stdin ends the child's read_line: it exits, dropping the handle.
    drop(child.stdin.take());
    let status = child.wait().expect("wait for the holder");
    assert!(status.success(), "the holder exited with {status}");

    let after = Ledger::open(&dir.0).expect("the lock must be released when the holder exits");
    assert_eq!(after.len(), 0, "the refused writer must not have written");
    std::fs::remove_file(&ready).ok();
}
