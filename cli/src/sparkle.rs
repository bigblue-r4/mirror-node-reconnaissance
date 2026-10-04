//! `mnr sparkle` — Multi-probe orchestrated reconnaissance demo.
//!
//! The "sparkle" mode demonstrates **scaled reconnaissance through independent probes**
//! in a sealed lab environment. Each probe runs the standard observer/reaper/ledger stack
//! with its own configuration, and they never communicate with each other.
//!
//! The controller:
//! 1. Spawns N probes, each with a unique seed offset (deterministic & independent).
//! 2. Each probe runs the full observer loop to completion (TTL, drift, budget, or stream end).
//! 3. Each probe seals its private ledger independently.
//! 4. The controller aggregates all sealed fragments under a Merkle root.
//! 5. The final aggregate ledger is a standard `mnr-ledger` JSONL log that can be
//!    verified with `mnr ledger verify`.

use mnr_ledger::{Ledger, LedgerHead};
use mnr_observer::{MeteredEngine, MockEngine, Observer, SwarmConnector};
use mnr_reaper::{execute_teardown, NodeState, Reaper, Secret, TripReason};
use mnr_sim::MockSwarm;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ============================================================================
// Configuration types
// ============================================================================

/// Configuration for a sparkle run.
#[derive(Debug, Clone)]
pub struct SparkleConfig {
    /// Number of probes to spawn (default 8–16).
    pub num_probes: u32,
    /// TTL per probe in milliseconds (default 800).
    pub ttl_ms: u64,
    /// Co-option drift threshold (default 0.75).
    pub drift_threshold: f64,
    /// Shared call budget per probe (default 32).
    pub budget_per_probe: usize,
    /// Number of swarm messages per probe (default 50).
    pub swarm_len_per_probe: usize,
    /// Base seed for determinism (default random or from config).
    pub base_seed: u64,
    /// Root output directory.
    pub dir: String,
}

impl Default for SparkleConfig {
    fn default() -> Self {
        SparkleConfig {
            num_probes: 8,
            ttl_ms: 800,
            drift_threshold: 0.75,
            budget_per_probe: 32,
            swarm_len_per_probe: 50,
            base_seed: 1337,
            dir: "./sparkle-run".to_string(),
        }
    }
}

impl SparkleConfig {
    /// Parse sparkle config from CLI args.
    /// Format: `--probes N --ttl-ms M --budget-per B --swarm-len S --seed Z --dir PATH`
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let mut cfg = SparkleConfig::default();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--probes" => {
                    cfg.num_probes = it
                        .next()
                        .ok_or("--probes requires a value")?
                        .parse()
                        .map_err(|_| "invalid --probes value")?;
                }
                "--ttl-ms" => {
                    cfg.ttl_ms = it
                        .next()
                        .ok_or("--ttl-ms requires a value")?
                        .parse()
                        .map_err(|_| "invalid --ttl-ms value")?;
                }
                "--drift-threshold" => {
                    cfg.drift_threshold = it
                        .next()
                        .ok_or("--drift-threshold requires a value")?
                        .parse()
                        .map_err(|_| "invalid --drift-threshold value")?;
                }
                "--budget-per" => {
                    cfg.budget_per_probe = it
                        .next()
                        .ok_or("--budget-per requires a value")?
                        .parse()
                        .map_err(|_| "invalid --budget-per value")?;
                }
                "--swarm-len" => {
                    cfg.swarm_len_per_probe = it
                        .next()
                        .ok_or("--swarm-len requires a value")?
                        .parse()
                        .map_err(|_| "invalid --swarm-len value")?;
                }
                "--seed" => {
                    cfg.base_seed = it
                        .next()
                        .ok_or("--seed requires a value")?
                        .parse()
                        .map_err(|_| "invalid --seed value")?;
                }
                "--dir" => {
                    cfg.dir = it
                        .next()
                        .ok_or("--dir requires a value")?
                        .to_string();
                }
                _ => {
                    return Err(format!("unknown sparkle option: {arg}"));
                }
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        let mut errs = Vec::new();
        if self.num_probes == 0 || self.num_probes > 128 {
            errs.push("num_probes must be in 1..=128".to_string());
        }
        if self.ttl_ms == 0 {
            errs.push("ttl_ms must be > 0".to_string());
        }
        if !(0.0..=1.0).contains(&self.drift_threshold) {
            errs.push(format!(
                "drift_threshold must be in 0.0..=1.0 (got {})",
                self.drift_threshold
            ));
        }
        if self.budget_per_probe == 0 {
            errs.push("budget_per_probe must be > 0".to_string());
        }
        if self.swarm_len_per_probe == 0 {
            errs.push("swarm_len_per_probe must be > 0".to_string());
        }
        if self.dir.trim().is_empty() {
            errs.push("dir must not be empty".to_string());
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

// ============================================================================
// Probe result and aggregation types
// ============================================================================

/// Result of a single probe's run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub probe_id: u32,
    pub final_drift: f64,
    pub steps: u64,
    pub trip_reason: String,
    pub fragment_hash: String,       // SHA-256 of sealed ledger.jsonl
    pub sealed_at: String,
}

/// Final aggregated result from all probes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparkleAggregation {
    pub num_probes: u32,
    pub fragments: Vec<ProbeResult>,
    pub aggregation_root: String,    // Merkle root over fragment_hashes
    pub sealed_at: String,
}

// ============================================================================
// Helper functions
// ============================================================================

/// Compute SHA-256 hash of bytes, return lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Compute ISO 8601 timestamp (UTC).
fn iso_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    unix_to_iso(secs)
}

fn unix_to_iso(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Hash of a file's contents.
fn hash_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    Ok(sha256_hex(&bytes))
}

/// Canonical hash of a ledger directory: hash(ledger.jsonl || log-head.json).
fn hash_ledger_fragment(ledger_dir: &Path) -> Result<String, String> {
    let log_file = ledger_dir.join("ledger.jsonl");
    let head_file = ledger_dir.join("log-head.json");

    let mut combined = Vec::new();
    if log_file.exists() {
        combined.extend_from_slice(&fs::read(&log_file).map_err(|e| e.to_string())?);
    }
    if head_file.exists() {
        combined.extend_from_slice(&fs::read(&head_file).map_err(|e| e.to_string())?);
    }

    Ok(sha256_hex(&combined))
}

/// Compute Merkle root over a list of hashes.
fn compute_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return sha256_hex(b"no fragments");
    }

    let mut current = hashes.to_vec();
    while current.len() > 1 {
        let mut next = Vec::new();
        for i in (0..current.len()).step_by(2) {
            let left = &current[i];
            let right = current.get(i + 1).map(|s| s.as_str()).unwrap_or(left);
            let combined = format!("{}{}", left, right);
            next.push(sha256_hex(combined.as_bytes()));
        }
        current = next;
    }
    current.pop().unwrap_or_else(|| sha256_hex(b"empty"))
}

// ============================================================================
// Main controller
// ============================================================================

pub struct SparkleController {
    config: SparkleConfig,
}

impl SparkleController {
    pub fn new(config: SparkleConfig) -> Self {
        SparkleController { config }
    }

    /// Run all probes and return the aggregation.
    pub fn run_all_probes(&mut self) -> Result<SparkleAggregation, String> {
        // Create directory structure
        let root_dir = PathBuf::from(&self.config.dir);
        fs::create_dir_all(&root_dir).map_err(|e| e.to_string())?;

        let probes_dir = root_dir.join("probes");
        fs::create_dir_all(&probes_dir).map_err(|e| e.to_string())?;

        let mut fragments = Vec::new();
        let mut fragment_hashes = Vec::new();

        // Run each probe
        for probe_id in 0..self.config.num_probes {
            let probe_dir = probes_dir.join(format!("probe-{}", probe_id));
            fs::create_dir_all(&probe_dir).map_err(|e| e.to_string())?;

            // Derive unique seed for this probe
            let seed = self.config.base_seed.wrapping_add(probe_id as u64);

            println!(
                "\n  [probe {}] running in {} (seed={})",
                probe_id,
                probe_dir.display(),
                seed
            );

            // Run the probe
            let result = self.run_probe(probe_id, seed, &probe_dir)?;

            // Verify the probe's ledger before adding to aggregation
            Ledger::verify(&probe_dir)
                .map_err(|e| format!("probe {} ledger verification failed: {}", probe_id, e))?;

            // Compute fragment hash
            let fragment_hash = hash_ledger_fragment(&probe_dir)?;
            fragment_hashes.push(fragment_hash.clone());

            println!(
                "  [probe {}] sealed: drift={:.3} steps={} reason={} hash={}…",
                probe_id,
                result.final_drift,
                result.steps,
                result.trip_reason,
                &fragment_hash[..16.min(fragment_hash.len())]
            );

            fragments.push(ProbeResult {
                probe_id,
                final_drift: result.final_drift,
                steps: result.steps,
                trip_reason: result.trip_reason,
                fragment_hash,
                sealed_at: result.sealed_at,
            });
        }

        // Compute aggregation root
        let aggregation_root = compute_merkle_root(&fragment_hashes);

        let aggregation = SparkleAggregation {
            num_probes: self.config.num_probes,
            fragments,
            aggregation_root,
            sealed_at: iso_now(),
        };

        // Write aggregate ledger with fragments as records
        self.write_aggregate_ledger(&root_dir, &aggregation)?;

        Ok(aggregation)
    }

    /// Run a single probe to completion.
    fn run_probe(
        &self,
        probe_id: u32,
        seed: u64,
        probe_dir: &Path,
    ) -> Result<ProbeResult, String> {
        // Open ledger for this probe
        let mut ledger = Ledger::open(probe_dir).map_err(|e| e.to_string())?;

        // Create node state (for wipe on exit)
        let mut state = NodeState::new();
        state.add_secret(Secret::new(
            "session-token",
            format!("tok-probe-{}", probe_id).into_bytes(),
        ));
        state.add_buffer(Vec::new());

        // Create engine, swarm, reaper
        let engine = MeteredEngine::new(MockEngine::default(), self.config.budget_per_probe);
        let mut swarm = MockSwarm::new(seed, self.config.swarm_len_per_probe);
        let reaper = Reaper::new(Duration::from_millis(self.config.ttl_ms));

        // Run the observer loop
        let trip: TripReason;
        let mut steps: u64 = 0;
        let mut final_drift = 0.0;
        {
            let mut observer = Observer::new(
                engine,
                &mut ledger,
                self.config.drift_threshold,
            );

            loop {
                // Check TTL
                if reaper.ttl_expired() {
                    trip = TripReason::Ttl;
                    break;
                }

                // Check step limit (use a generous default)
                if steps >= 1000 {
                    trip = TripReason::Manual;
                    break;
                }

                // Get next message
                let msg = match swarm.recv() {
                    Some(m) => m,
                    None => {
                        trip = TripReason::Manual;
                        break;
                    }
                };

                // Process message
                match observer.step(msg) {
                    Ok(rep) => {
                        steps = rep.step;
                        final_drift = rep.drift;
                        if rep.alarm {
                            trip = TripReason::CoOption { drift: rep.drift };
                            break;
                        }
                    }
                    Err(e) if e.contains("budget") => {
                        trip = TripReason::Anomaly {
                            detail: "call budget exhausted".to_string(),
                        };
                        break;
                    }
                    Err(e) => {
                        trip = TripReason::Anomaly { detail: e };
                        break;
                    }
                }
            }
        } // observer dropped → releases ledger borrow

        // Teardown: seal and wipe
        let _teardown = execute_teardown(trip.clone(), &ledger, &mut state);

        let trip_reason = match trip {
            TripReason::Ttl => "ttl".to_string(),
            TripReason::CoOption { drift } => format!("coption:{:.2}", drift),
            TripReason::Anomaly { detail } => format!("anomaly:{}", detail),
            TripReason::Manual => "manual".to_string(),
        };

        Ok(ProbeResult {
            probe_id,
            final_drift,
            steps,
            trip_reason,
            fragment_hash: String::new(), // will be computed by caller
            sealed_at: iso_now(),
        })
    }

    /// Write the aggregate ledger with fragment records.
    fn write_aggregate_ledger(
        &self,
        root_dir: &Path,
        aggregation: &SparkleAggregation,
    ) -> Result<(), String> {
        let agg_dir = root_dir.join("aggregate");
        fs::create_dir_all(&agg_dir).map_err(|e| e.to_string())?;

        // Open aggregate ledger
        let mut agg_ledger = Ledger::open(&agg_dir).map_err(|e| e.to_string())?;

        // Append one entry per fragment
        for frag in &aggregation.fragments {
            let payload = serde_json::json!({
                "probe_id": frag.probe_id,
                "fragment_hash": frag.fragment_hash,
                "final_drift": frag.final_drift,
                "steps": frag.steps,
                "trip_reason": frag.trip_reason,
            });
            let payload_bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
            agg_ledger
                .append("sparkle-fragment", &payload_bytes)
                .map_err(|e| e.to_string())?;
        }

        // Seal the aggregate ledger
        agg_ledger.seal().map_err(|e| e.to_string())?;

        // Write companion aggregate-root.json (metadata, not part of the sealed chain)
        let root_file = agg_dir.join("aggregate-root.json");
        let root_meta = serde_json::json!({
            "num_probes": aggregation.num_probes,
            "aggregation_root": aggregation.aggregation_root,
            "fragment_count": aggregation.fragments.len(),
            "sealed_at": aggregation.sealed_at,
        });
        let root_json = serde_json::to_string_pretty(&root_meta).map_err(|e| e.to_string())?;
        fs::write(&root_file, root_json).map_err(|e| e.to_string())?;

        Ok(())
    }
}

// ============================================================================
// Verification
// ============================================================================

/// Verify a sparkle aggregation: check all probes' ledgers and the aggregate root.
pub fn verify_sparkle_aggregation(dir: &str) -> Result<VerifyReport, String> {
    let root_dir = PathBuf::from(dir);

    // Verify each probe's ledger
    let probes_dir = root_dir.join("probes");
    let mut probes_verified = 0;
    let mut all_ok = true;

    if probes_dir.exists() {
        let entries = fs::read_dir(&probes_dir).map_err(|e| e.to_string())?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.is_dir() {
                match Ledger::verify(&path) {
                    Ok(_) => {
                        probes_verified += 1;
                    }
                    Err(e) => {
                        eprintln!("  probe {} verification failed: {}", path.display(), e);
                        all_ok = false;
                    }
                }
            }
        }
    }

    // Verify aggregate ledger
    let agg_dir = root_dir.join("aggregate");
    let agg_ok = if agg_dir.exists() {
        Ledger::verify(&agg_dir).is_ok()
    } else {
        false
    };

    // Load and verify aggregation root
    let root_file = agg_dir.join("aggregate-root.json");
    let root_hash = if root_file.exists() {
        let raw = fs::read_to_string(&root_file).map_err(|e| e.to_string())?;
        let meta: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        meta["aggregation_root"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    Ok(VerifyReport {
        probes_verified,
        all_probes_ok: all_ok,
        aggregate_ok: agg_ok,
        aggregation_root: root_hash,
    })
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub probes_verified: u32,
    pub all_probes_ok: bool,
    pub aggregate_ok: bool,
    pub aggregation_root: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_args_parses_correctly() {
        let args = vec![
            "--probes".to_string(),
            "4".to_string(),
            "--ttl-ms".to_string(),
            "500".to_string(),
            "--dir".to_string(),
            "./test-sparkle".to_string(),
        ];
        let cfg = SparkleConfig::from_args(&args).unwrap();
        assert_eq!(cfg.num_probes, 4);
        assert_eq!(cfg.ttl_ms, 500);
        assert_eq!(cfg.dir, "./test-sparkle");
        std::fs::remove_dir_all("./test-sparkle").ok();
    }

    #[test]
    fn merkle_root_is_deterministic() {
        let hashes = vec![
            "aaa".to_string(),
            "bbb".to_string(),
            "ccc".to_string(),
            "ddd".to_string(),
        ];
        let root1 = compute_merkle_root(&hashes);
        let root2 = compute_merkle_root(&hashes);
        assert_eq!(root1, root2);
    }

    #[test]
    fn sha256_is_deterministic() {
        let data = b"hello";
        let h1 = sha256_hex(data);
        let h2 = sha256_hex(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn iso_timestamp_formats_correctly() {
        let ts = iso_now();
        // Should be in format YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.contains('T'));
        assert!(ts.contains('Z'));
        assert!(ts.len() >= 19); // minimum ISO8601 length
    }
}
