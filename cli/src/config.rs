//! Layered configuration: `env (MNR_*) → config file → built-in defaults`.
//!
//! This mirrors the split-brain harness `config.rs` precedence and the
//! `env().or(file).unwrap_or(default)` pattern. The config file path comes from
//! `MNR_CONFIG` and defaults to `configs/mnr.toml`.

use serde::Deserialize;
use std::path::PathBuf;

/// Fully-resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory the witness ledger is written to.
    pub ledger_dir: String,
    /// Co-option drift level (0..1) at which the node is pulled.
    pub drift_threshold: f64,
    /// Hard time-to-live for the deployment, in seconds.
    pub ttl_secs: u64,
    /// Maximum observation steps before a clean pull.
    pub max_steps: u64,
    /// Shared model-call budget across both hemispheres.
    pub budget: usize,
    /// Seed for the deterministic mock swarm.
    pub seed: u64,
    /// Number of messages the mock swarm emits.
    pub swarm_len: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ledger_dir: "./mnr-run".to_string(),
            drift_threshold: 0.75,
            ttl_secs: 300,
            max_steps: 500,
            budget: 4000,
            seed: 1337,
            swarm_len: 60,
        }
    }
}

/// All-optional mirror of [`Config`] for TOML deserialization.
#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    ledger_dir: Option<String>,
    drift_threshold: Option<f64>,
    ttl_secs: Option<u64>,
    max_steps: Option<u64>,
    budget: Option<usize>,
    seed: Option<u64>,
    swarm_len: Option<usize>,
}

fn config_path() -> PathBuf {
    std::env::var("MNR_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("configs/mnr.toml"))
}

fn load_file() -> FileConfig {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(raw) => toml::from_str(&raw).unwrap_or_else(|e| {
            eprintln!(
                "warning: could not parse {}: {e}; using defaults",
                path.display()
            );
            FileConfig::default()
        }),
        Err(_) => FileConfig::default(),
    }
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    env_str(key).and_then(|s| s.parse().ok())
}

impl Config {
    /// Resolve config from env, then file, then defaults.
    pub fn load() -> Result<Config, String> {
        let file = load_file();
        let d = Config::default();

        let cfg = Config {
            ledger_dir: env_str("MNR_LEDGER_DIR")
                .or(file.ledger_dir)
                .unwrap_or(d.ledger_dir),
            drift_threshold: env_parse("MNR_DRIFT_THRESHOLD")
                .or(file.drift_threshold)
                .unwrap_or(d.drift_threshold),
            ttl_secs: env_parse("MNR_TTL_SECONDS")
                .or(file.ttl_secs)
                .unwrap_or(d.ttl_secs),
            max_steps: env_parse("MNR_MAX_STEPS")
                .or(file.max_steps)
                .unwrap_or(d.max_steps),
            budget: env_parse("MNR_BUDGET").or(file.budget).unwrap_or(d.budget),
            seed: env_parse("MNR_SEED").or(file.seed).unwrap_or(d.seed),
            swarm_len: env_parse("MNR_SWARM_LEN")
                .or(file.swarm_len)
                .unwrap_or(d.swarm_len),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        let mut errs = Vec::new();
        if !(0.0..=1.0).contains(&self.drift_threshold) {
            errs.push(format!(
                "drift_threshold must be in 0.0..=1.0 (got {})",
                self.drift_threshold
            ));
        }
        if self.max_steps == 0 {
            errs.push("max_steps must be > 0".to_string());
        }
        if self.budget == 0 {
            errs.push("budget must be > 0".to_string());
        }
        if self.ledger_dir.trim().is_empty() {
            errs.push("ledger_dir must not be empty".to_string());
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}
