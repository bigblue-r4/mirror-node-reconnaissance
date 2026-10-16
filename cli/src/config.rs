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
    pub inject_friction: bool,
    pub friction_budget: usize,
    pub friction_threshold: f64,
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
            inject_friction: false,
            friction_budget: 16,
            friction_threshold: 0.5,
        }
    }
}

/// All-optional mirror of [`Config`] for TOML deserialization.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    ledger_dir: Option<String>,
    drift_threshold: Option<f64>,
    ttl_secs: Option<u64>,
    max_steps: Option<u64>,
    budget: Option<usize>,
    seed: Option<u64>,
    swarm_len: Option<usize>,
    inject_friction: Option<bool>,
    friction_budget: Option<usize>,
    friction_threshold: Option<f64>,
}

fn config_path() -> PathBuf {
    std::env::var("MNR_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("configs/mnr.toml"))
}

fn load_file() -> Result<FileConfig, String> {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            toml::from_str(&raw).map_err(|_| format!("invalid configuration in {}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(FileConfig::default()),
        Err(_) => Err("cannot read configuration".into()),
    }
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    env_str(key).and_then(|s| s.parse().ok())
}
fn friction_env<T: std::str::FromStr>(key: &str) -> Result<Option<T>, String> {
    env_str(key)
        .map(|value| value.parse().map_err(|_| format!("invalid {key}")))
        .transpose()
}

impl Config {
    /// Resolve config from env, then file, then defaults.
    pub fn load() -> Result<Config, String> {
        let file = load_file()?;
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
            inject_friction: friction_env("MNR_INJECT_FRICTION")?
                .or(file.inject_friction)
                .unwrap_or(d.inject_friction),
            friction_budget: friction_env("MNR_FRICTION_BUDGET")?
                .or(file.friction_budget)
                .unwrap_or(d.friction_budget),
            friction_threshold: friction_env("MNR_FRICTION_THRESHOLD")?
                .or(file.friction_threshold)
                .unwrap_or(d.friction_threshold),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
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
        if let Err(error) = (mnr_observer::FrictionConfig {
            budget: self.friction_budget,
            threshold: self.friction_threshold,
        })
        .validate(if self.inject_friction {
            self.drift_threshold
        } else {
            1.0
        }) {
            errs.push(error);
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn friction_file_fields_decode_and_bad_controls_fail() {
        let file: FileConfig =
            toml::from_str("inject_friction=true\nfriction_budget=5\nfriction_threshold=0.25")
                .unwrap();
        assert_eq!(file.inject_friction, Some(true));
        assert_eq!(file.friction_budget, Some(5));
        assert_eq!(file.friction_threshold, Some(0.25));
        assert!(toml::from_str::<FileConfig>("friction_budget=-1").is_err());
        assert!(toml::from_str::<FileConfig>("friction_buget=5").is_err());
        let cfg = Config {
            friction_budget: 0,
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
        assert!(
            Config {
                drift_threshold: 0.1,
                ..Config::default()
            }
            .validate()
            .is_ok(),
            "disabled friction must not constrain normal drift settings"
        );
    }
}
