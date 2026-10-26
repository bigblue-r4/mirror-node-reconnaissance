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

use mnr_ledger::{Ledger, LedgerEntry};
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
                    cfg.dir = it.next().ok_or("--dir requires a value")?.to_string();
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
    pub fragment_hash: String, // SHA-256 of sealed ledger.jsonl
    pub sealed_at: String,
}

/// Final aggregated result from all probes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparkleAggregation {
    pub num_probes: u32,
    pub fragments: Vec<ProbeResult>,
    pub aggregation_root: String, // Merkle root over fragment_hashes
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

/// Domain tags for the two committed values. Versioned so a future format change
/// cannot be confused with this one.
pub const FRAGMENT_DOMAIN: &str = "mnr/sparkle-fragment/v1";
pub const ROOT_DOMAIN: &str = "mnr/sparkle-root/v1";

/// The exact bytes committed to the sealed chain for one probe. Verification
/// rebuilds this from the probe directory alone, so nothing else may go in.
pub fn fragment_payload(probe_id: u32, fragment_hash: &str) -> Vec<u8> {
    format!("{FRAGMENT_DOMAIN}\n{probe_id}\n{fragment_hash}").into_bytes()
}

/// The exact bytes committed for the aggregation root.
pub fn root_payload(num_probes: u32, root: &str) -> Vec<u8> {
    format!("{ROOT_DOMAIN}\n{num_probes}\n{root}").into_bytes()
}

/// Canonical hash of a sealed ledger directory.
///
/// Length-prefixed and domain-separated so the boundary between the two files
/// cannot be moved (the earlier version concatenated them with no separator).
fn hash_ledger_fragment(ledger_dir: &Path) -> Result<String, String> {
    let log = fs::read(ledger_dir.join("ledger.jsonl")).map_err(|e| e.to_string())?;
    let head = fs::read(ledger_dir.join("log-head.json")).map_err(|e| e.to_string())?;

    let mut h = Sha256::new();
    h.update(b"mnr/sparkle-ledger-fragment/v1\0");
    h.update((log.len() as u64).to_le_bytes());
    h.update(&log);
    h.update((head.len() as u64).to_le_bytes());
    h.update(&head);
    Ok(hex(&h.finalize()))
}

/// The fragment hash as 0.2.0's predecessor computed it: `SHA-256(log ‖ head)`,
/// the two files concatenated with no separator and no length.
///
/// This exists only to *recognise* an aggregate written in the old layout, so a
/// reader gets one explanation instead of a mismatch per probe. Nothing is ever
/// verified with it — that both files could shift bytes into one another is why
/// the format changed.
fn legacy_fragment_hash(ledger_dir: &Path) -> Result<String, String> {
    let mut combined = fs::read(ledger_dir.join("ledger.jsonl")).map_err(|e| e.to_string())?;
    combined
        .extend_from_slice(&fs::read(ledger_dir.join("log-head.json")).map_err(|e| e.to_string())?);
    Ok(sha256_hex(&combined))
}

/// Probe directories under `<root>/probes`, ordered by numeric probe id so the
/// Merkle root does not depend on directory iteration order.
fn probe_dirs(root: &Path) -> Result<Vec<(u32, PathBuf)>, String> {
    let probes_dir = root.join("probes");
    if !probes_dir.is_dir() {
        return Err(format!("no probes directory at {}", probes_dir.display()));
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&probes_dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let id = name
            .strip_prefix("probe-")
            .and_then(|n| n.parse::<u32>().ok())
            .ok_or_else(|| format!("unexpected entry in probes/: {name}"))?;
        out.push((id, path));
    }
    out.sort_by_key(|(id, _)| *id);
    Ok(out)
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

            // Verify the probe's ledger before adding to aggregation. An unsealed
            // fragment cannot be anchored, so it cannot be aggregated.
            let checked = Ledger::verify(&probe_dir)
                .map_err(|e| format!("probe {probe_id} ledger verification failed: {e}"))?;
            if !checked.sealed {
                return Err(format!(
                    "probe {probe_id} ledger is unsealed; aggregation needs a closed fragment"
                ));
            }

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
    fn run_probe(&self, probe_id: u32, seed: u64, probe_dir: &Path) -> Result<ProbeResult, String> {
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
            let mut observer = Observer::new(engine, &mut ledger, self.config.drift_threshold);

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
        let teardown = execute_teardown(trip.clone(), &ledger, &mut state);
        if teardown.sealed_head.is_none() {
            return Err(format!("probe {probe_id}: ledger seal failed"));
        }

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

    /// Write the aggregate ledger.
    ///
    /// Each entry commits only values a verifier can rebuild from the probe
    /// directory (probe id and fragment hash), and the root is committed last so
    /// that it covers every fragment entry. Runtime statistics are not committed:
    /// they are self-reported and would make the entries unverifiable.
    fn write_aggregate_ledger(
        &self,
        root_dir: &Path,
        aggregation: &SparkleAggregation,
    ) -> Result<(), String> {
        let agg_dir = root_dir.join("aggregate");
        fs::create_dir_all(&agg_dir).map_err(|e| e.to_string())?;

        let mut agg_ledger = Ledger::open(&agg_dir).map_err(|e| e.to_string())?;

        for frag in &aggregation.fragments {
            let payload = fragment_payload(frag.probe_id, &frag.fragment_hash);
            agg_ledger
                .append("sparkle-fragment", &payload)
                .map_err(|e| e.to_string())?;
        }

        let num_probes = aggregation.fragments.len() as u32;
        agg_ledger
            .append(
                "sparkle-root",
                &root_payload(num_probes, &aggregation.aggregation_root),
            )
            .map_err(|e| e.to_string())?;

        agg_ledger.seal().map_err(|e| e.to_string())?;

        // Exported copy for publishing the root. Verification never reads it:
        // the authoritative value is the one committed in the sealed chain.
        let root_meta = serde_json::json!({
            "note": "export copy only; verification recomputes the root from the probe ledgers and checks the sealed chain",
            "num_probes": aggregation.num_probes,
            "aggregation_root": aggregation.aggregation_root,
            "fragment_count": aggregation.fragments.len(),
            "sealed_at": aggregation.sealed_at,
        });
        let root_json = serde_json::to_string_pretty(&root_meta).map_err(|e| e.to_string())?;
        fs::write(agg_dir.join("aggregate-root.json"), root_json).map_err(|e| e.to_string())?;

        Ok(())
    }
}

// ============================================================================
// Verification
// ============================================================================

/// Verify a sparkle aggregation end to end.
///
/// The root is **recomputed** from the probe ledgers and then checked against the
/// sealed aggregate chain, so verification trusts the chain rather than any file
/// in the directory. `aggregate-root.json` is an exported copy for publishing and
/// is only echoed back as [`VerifyReport::exported_root`].
pub fn verify_sparkle_aggregation(dir: &str) -> VerifyReport {
    let root_dir = PathBuf::from(dir);

    let probes = match probe_dirs(&root_dir) {
        Ok(probes) if probes.is_empty() => {
            return VerifyReport::failed(format!("no probe ledgers under {dir}"))
        }
        Ok(probes) => probes,
        Err(e) => return VerifyReport::failed(e),
    };

    // 1. Recompute each fragment hash from the probe directories.
    let mut errors = Vec::new();
    let mut probes_verified = 0u32;
    let mut all_probes_ok = true;
    let mut fragment_hashes = Vec::with_capacity(probes.len());
    for (probe_id, path) in &probes {
        match Ledger::verify(path) {
            Ok(report) if report.sealed => probes_verified += 1,
            Ok(_) => {
                all_probes_ok = false;
                errors.push(format!("probe {probe_id}: ledger is unsealed"));
            }
            Err(e) => {
                all_probes_ok = false;
                errors.push(format!("probe {probe_id}: {e}"));
            }
        }
        match hash_ledger_fragment(path) {
            Ok(hash) => fragment_hashes.push(hash),
            Err(e) => {
                all_probes_ok = false;
                errors.push(format!("probe {probe_id}: cannot hash fragment: {e}"));
                // Keep index alignment with `probes` so later checks report the
                // right probe rather than silently shifting.
                fragment_hashes.push(String::new());
            }
        }
    }
    let derived_root = compute_merkle_root(&fragment_hashes);

    // 2. Check the aggregate chain: sealed, one fragment entry per probe in probe
    //    order, then the root entry, each matching the recomputed value.
    let agg_dir = root_dir.join("aggregate");
    let mut sealed = false;
    let mut aggregate_ok = false;
    let mut legacy_layout = false;
    match Ledger::verify(&agg_dir) {
        Err(e) => errors.push(format!("aggregate ledger: {e}")),
        Ok(report) if !report.sealed => {
            errors.push("aggregate ledger is unsealed".to_string());
        }
        Ok(_) => {
            sealed = true;
            match Ledger::read_entries(&agg_dir) {
                Err(e) => errors.push(format!("aggregate ledger: {e}")),
                Ok(entries) => match legacy_layout_explanation(&entries, &probes, &agg_dir) {
                    Some(explanation) => {
                        legacy_layout = true;
                        errors.extend(explanation);
                    }
                    None => {
                        aggregate_ok = check_committed_entries(
                            &entries,
                            &probes,
                            &fragment_hashes,
                            &derived_root,
                            &mut errors,
                        );
                    }
                },
            }
        }
    }

    let exported_root = fs::read_to_string(agg_dir.join("aggregate-root.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|meta| meta["aggregation_root"].as_str().map(str::to_string));

    VerifyReport {
        probes_verified,
        all_probes_ok,
        aggregate_ok: aggregate_ok && sealed,
        aggregation_root: derived_root,
        exported_root,
        sealed,
        legacy_layout,
        errors,
    }
}

/// Explain an aggregate written before the root and the fragment payload were
/// committed to the chain, rather than reporting a mismatch per probe.
///
/// Detection is positive, not merely "there is no root entry": the chain must
/// hold exactly one fragment entry per probe, and its exported root must equal
/// the root recomputed with the *old* fragment hash. So a 0.2.0 aggregate whose
/// root entry was deleted or altered is still reported as damaged, and a
/// rewritten probe ledger is still reported as a mismatch.
fn legacy_layout_explanation(
    entries: &[LedgerEntry],
    probes: &[(u32, PathBuf)],
    agg_dir: &Path,
) -> Option<[String; 2]> {
    if entries.is_empty()
        || entries.len() != probes.len()
        || entries.iter().any(|e| e.kind != "sparkle-fragment")
    {
        return None;
    }

    let mut legacy_hashes = Vec::with_capacity(probes.len());
    for (_, path) in probes {
        legacy_hashes.push(legacy_fragment_hash(path).ok()?);
    }
    let legacy_root = compute_merkle_root(&legacy_hashes);

    let exported_root = fs::read_to_string(agg_dir.join("aggregate-root.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|meta| meta["aggregation_root"].as_str().map(str::to_string))?;
    if exported_root != legacy_root {
        return None;
    }

    Some([
        format!(
            "aggregate is in the pre-0.2.0 layout: {} fragment entries, no sparkle-root entry, \
             and an exported root {}… that matches the old fragment hash \
             (sha256(ledger.jsonl + log-head.json)) — it predates the root being committed \
             to the chain",
            entries.len(),
            &legacy_root[..16.min(legacy_root.len())]
        ),
        "its per-probe entries committed self-reported runtime statistics and a fragment hash \
         that binds neither file, so they cannot be rechecked; it is not evidence this build \
         can verify — regenerate it into a fresh directory with `mnr sparkle --dir <new dir>`"
            .to_string(),
    ])
}

/// Compare the committed aggregate entries against the values recomputed from
/// the probe directories. Returns whether the chain agrees with all of them.
fn check_committed_entries(
    entries: &[LedgerEntry],
    probes: &[(u32, PathBuf)],
    fragment_hashes: &[String],
    derived_root: &str,
    errors: &mut Vec<String>,
) -> bool {
    let mut ok = true;
    let fragments: Vec<&LedgerEntry> = entries
        .iter()
        .filter(|e| e.kind == "sparkle-fragment")
        .collect();
    let roots: Vec<&LedgerEntry> = entries
        .iter()
        .filter(|e| e.kind == "sparkle-root")
        .collect();

    if entries.len() != probes.len() + 1 {
        ok = false;
        errors.push(format!(
            "aggregate ledger holds {} entries; expected {} probes + 1 root",
            entries.len(),
            probes.len()
        ));
    }
    if roots.len() != 1 {
        ok = false;
        errors.push(format!(
            "expected exactly one sparkle-root entry, found {}",
            roots.len()
        ));
    }

    for (index, (probe_id, _)) in probes.iter().enumerate() {
        let Some(entry) = fragments.get(index) else {
            ok = false;
            errors.push(format!("no committed fragment for probe {probe_id}"));
            continue;
        };
        let expected = sha256_hex(&fragment_payload(*probe_id, &fragment_hashes[index]));
        if entry.payload_fingerprint != expected {
            ok = false;
            errors.push(format!(
                "probe {probe_id}: committed fragment does not match the probe ledger (seq {})",
                entry.seq
            ));
        }
    }

    if let Some(root_entry) = roots.first() {
        let expected = sha256_hex(&root_payload(probes.len() as u32, derived_root));
        if root_entry.payload_fingerprint != expected {
            ok = false;
            errors.push(format!(
                "committed aggregate root does not match the root recomputed from the probes (seq {})",
                root_entry.seq
            ));
        }
        if entries.last().map(|e| e.seq) != Some(root_entry.seq) {
            ok = false;
            errors.push(
                "the sparkle-root entry is not the final entry of the aggregate chain".to_string(),
            );
        }
    }

    ok
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Probe ledgers whose chain and anchor both check out.
    pub probes_verified: u32,
    pub all_probes_ok: bool,
    /// The aggregate chain agrees with the values recomputed from the probes.
    pub aggregate_ok: bool,
    /// Root recomputed from the probe ledgers.
    pub aggregation_root: String,
    /// Root echoed from the exported copy, when present. Never trusted.
    pub exported_root: Option<String>,
    /// Whether the aggregate ledger carries a head anchor.
    pub sealed: bool,
    /// The aggregate is recognisably in the pre-0.2.0 layout, so the errors
    /// explain the layout rather than listing a mismatch per probe. Never true
    /// for a chain that merely lost its root entry: see
    /// [`legacy_layout_explanation`].
    pub legacy_layout: bool,
    pub errors: Vec<String>,
}

impl VerifyReport {
    fn failed(message: String) -> Self {
        VerifyReport {
            probes_verified: 0,
            all_probes_ok: false,
            aggregate_ok: false,
            aggregation_root: String::new(),
            exported_root: None,
            sealed: false,
            legacy_layout: false,
            errors: vec![message],
        }
    }

    /// True only when every probe verified, the aggregate chain agrees with the
    /// recomputed root, the chain is sealed, and nothing failed silently.
    pub fn verified(&self) -> bool {
        self.all_probes_ok && self.aggregate_ok && self.sealed && self.errors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("mnr-sparkle-test-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn small_config(dir: &Path) -> SparkleConfig {
        SparkleConfig {
            num_probes: 2,
            ttl_ms: 5_000,
            budget_per_probe: 32,
            swarm_len_per_probe: 5,
            base_seed: 7,
            dir: dir.display().to_string(),
            ..SparkleConfig::default()
        }
    }

    fn run_aggregation(dir: &Path) -> SparkleAggregation {
        SparkleController::new(small_config(dir))
            .run_all_probes()
            .unwrap()
    }

    fn verify(dir: &Path) -> VerifyReport {
        verify_sparkle_aggregation(&dir.display().to_string())
    }

    fn probe_log(dir: &Path, id: u32) -> PathBuf {
        dir.join("probes")
            .join(format!("probe-{id}"))
            .join("ledger.jsonl")
    }

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

    #[test]
    fn aggregation_verifies_end_to_end() {
        let dir = tmp_dir();
        let aggregation = run_aggregation(&dir);
        let report = verify(&dir);
        assert!(report.verified(), "errors: {:?}", report.errors);
        assert_eq!(report.probes_verified, 2);
        assert!(report.sealed);
        assert_eq!(report.aggregation_root, aggregation.aggregation_root);
        assert_eq!(
            report.exported_root.as_deref(),
            Some(aggregation.aggregation_root.as_str())
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampered_probe_ledger_fails_verification() {
        let dir = tmp_dir();
        run_aggregation(&dir);
        let log = probe_log(&dir, 1);
        let text = std::fs::read_to_string(&log).unwrap();
        let forged = text.replacen(
            "\"payload_fingerprint\":\"",
            "\"payload_fingerprint\":\"0",
            1,
        );
        assert_ne!(forged, text, "test needs an entry to corrupt");
        std::fs::write(&log, forged).unwrap();

        let report = verify(&dir);
        assert!(!report.verified());
        assert!(!report.all_probes_ok);
        assert!(
            report.errors.iter().any(|e| e.contains("probe 1")),
            "{:?}",
            report.errors
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn truncated_probe_ledger_fails_verification() {
        let dir = tmp_dir();
        run_aggregation(&dir);
        let log = probe_log(&dir, 0);
        let text = std::fs::read_to_string(&log).unwrap();
        let kept: Vec<&str> = text.lines().take(1).collect();
        std::fs::write(&log, kept.join("\n") + "\n").unwrap();

        let report = verify(&dir);
        assert!(!report.verified());
        assert!(!report.all_probes_ok);
        assert!(
            report.errors.iter().any(|e| e.contains("anchor")),
            "{:?}",
            report.errors
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampered_aggregate_chain_fails_verification() {
        let dir = tmp_dir();
        run_aggregation(&dir);
        let agg_log = dir.join("aggregate").join("ledger.jsonl");
        let text = std::fs::read_to_string(&agg_log).unwrap();
        let forged = text.replacen(
            "\"payload_fingerprint\":\"",
            "\"payload_fingerprint\":\"f",
            1,
        );
        std::fs::write(&agg_log, forged).unwrap();

        let report = verify(&dir);
        assert!(!report.verified());
        assert!(!report.aggregate_ok);
        assert!(
            report.errors.iter().any(|e| e.contains("aggregate ledger")),
            "{:?}",
            report.errors
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_probe_directory_fails_verification() {
        let dir = tmp_dir();
        run_aggregation(&dir);
        std::fs::remove_dir_all(dir.join("probes").join("probe-1")).unwrap();

        let report = verify(&dir);
        assert!(!report.verified());
        assert!(!report.aggregate_ok);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn swapped_but_internally_valid_probe_still_fails() {
        let dir = tmp_dir();
        run_aggregation(&dir);

        // Replace one probe with a *valid, sealed* ledger from a different run.
        // The probe itself verifies; only the committed fragment hash can tell.
        let victim = dir.join("probes").join("probe-1");
        std::fs::remove_dir_all(&victim).unwrap();
        std::fs::create_dir_all(&victim).unwrap();
        let mut replacement = Ledger::open(&victim).unwrap();
        replacement
            .append("observation", b"a different run")
            .unwrap();
        replacement.seal().unwrap();

        let report = verify(&dir);
        assert!(
            report.all_probes_ok,
            "the replacement ledger is internally valid: {:?}",
            report.errors
        );
        assert!(!report.aggregate_ok);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("does not match the probe ledger")),
            "{:?}",
            report.errors
        );
        assert!(!report.verified());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn exported_root_is_never_trusted() {
        let dir = tmp_dir();
        let aggregation = run_aggregation(&dir);
        let export = dir.join("aggregate").join("aggregate-root.json");
        let zeros = "0".repeat(64);
        let mut meta: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&export).unwrap()).unwrap();
        meta["aggregation_root"] = serde_json::Value::String(zeros.clone());
        std::fs::write(&export, meta.to_string()).unwrap();

        let report = verify(&dir);
        assert!(report.verified(), "errors: {:?}", report.errors);
        assert_eq!(report.aggregation_root, aggregation.aggregation_root);
        assert_eq!(report.exported_root.as_deref(), Some(zeros.as_str()));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Rewrite the aggregate in the pre-0.2.0 layout: one JSON fragment entry per
    /// probe carrying runtime statistics, no root entry, and the root only in the
    /// side file. Returns the root an old build would have published.
    fn rewrite_as_legacy(dir: &Path) -> String {
        let agg_dir = dir.join("aggregate");
        std::fs::remove_dir_all(&agg_dir).unwrap();
        std::fs::create_dir_all(&agg_dir).unwrap();

        let probes = probe_dirs(dir).unwrap();
        let mut hashes = Vec::new();
        let mut ledger = Ledger::open(&agg_dir).unwrap();
        for (probe_id, path) in &probes {
            let fragment_hash = legacy_fragment_hash(path).unwrap();
            let payload = serde_json::json!({
                "probe_id": probe_id,
                "fragment_hash": fragment_hash,
                "final_drift": 0.42,
                "steps": 5,
                "trip_reason": "ttl",
            });
            ledger
                .append("sparkle-fragment", &serde_json::to_vec(&payload).unwrap())
                .unwrap();
            hashes.push(fragment_hash);
        }
        ledger.seal().unwrap();

        let root = compute_merkle_root(&hashes);
        let meta = serde_json::json!({
            "num_probes": probes.len(),
            "aggregation_root": root,
            "fragment_count": probes.len(),
            "sealed_at": "2026-10-23T00:00:00Z",
        });
        std::fs::write(
            agg_dir.join("aggregate-root.json"),
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();
        root
    }

    #[test]
    fn legacy_aggregate_is_explained_once_not_once_per_probe() {
        let dir = tmp_dir();
        run_aggregation(&dir);
        let legacy_root = rewrite_as_legacy(&dir);

        let report = verify(&dir);
        assert!(!report.verified(), "a legacy aggregate does not verify");
        assert!(report.legacy_layout);
        assert!(
            report.all_probes_ok,
            "the probe ledgers are untouched: {:?}",
            report.errors
        );
        assert_eq!(report.exported_root.as_deref(), Some(legacy_root.as_str()));
        assert_eq!(report.errors.len(), 2, "{:?}", report.errors);
        assert!(
            report.errors[0].contains("pre-0.2.0 layout"),
            "{:?}",
            report.errors
        );
        assert!(
            !report
                .errors
                .iter()
                .any(|e| e.contains("does not match the probe ledger")),
            "per-probe mismatches would hide the reason: {:?}",
            report.errors
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_shaped_aggregate_with_a_foreign_root_is_not_excused() {
        let dir = tmp_dir();
        run_aggregation(&dir);
        rewrite_as_legacy(&dir);
        let export = dir.join("aggregate").join("aggregate-root.json");
        let mut meta: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&export).unwrap()).unwrap();
        meta["aggregation_root"] = serde_json::Value::String("0".repeat(64));
        std::fs::write(&export, meta.to_string()).unwrap();

        let report = verify(&dir);
        assert!(
            !report.legacy_layout,
            "without a root matching the old hash, the shape alone proves nothing: {:?}",
            report.errors
        );
        assert!(!report.verified());
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("expected exactly one sparkle-root entry")),
            "{:?}",
            report.errors
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
