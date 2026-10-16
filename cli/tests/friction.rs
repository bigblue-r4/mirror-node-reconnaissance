//! Sealed-lab integration only. MockSwarm remains the sole production connector.
use mnr_ledger::Ledger;
use mnr_observer::{
    decode_friction, Engine, FrictionConfig, Message, MeteredEngine, MockEngine, Observer,
    SwarmConnector, SwarmError,
};
use mnr_reaper::{execute_teardown, NodeState, Reaper, Secret, TripReason};
use mnr_sim::MockSwarm;
use std::{path::PathBuf, time::Duration};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mnr-friction-{}-{}-{}",
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
fn msg(body: &str) -> Message {
    Message {
        from: "foreign".into(),
        dialect: "swarm/v1".into(),
        body: body.into(),
        friction: None,
    }
}
fn config() -> FrictionConfig {
    FrictionConfig {
        budget: 4,
        threshold: 0.5,
    }
}
fn leash() -> Reaper {
    Reaper::new(Duration::from_secs(60))
}
struct LureFriction;
impl Engine for LureFriction {
    fn generate(&self, system: &str, prompt: &str) -> Result<String, String> {
        if system.contains("task=friction") {
            Ok(r#"{"operation":"lease","resource_id":"belong","lease_token":null}"#.into())
        } else {
            MockEngine::default().generate(system, prompt)
        }
    }
}

#[test]
fn only_issued_exact_echo_is_ignored_and_foreign_drift_still_reaps() {
    let dir = Temp::new();
    let mut ledger = Ledger::open(&dir.0).unwrap();
    let meter = MeteredEngine::new(LureFriction, 100);
    let mut swarm = MockSwarm::new(42, 200);
    {
        let mut observer = Observer::new(&meter, &mut ledger, 0.75)
            .with_friction(config())
            .unwrap();
        observer.step(msg("join us")).unwrap();
        let prior = observer.drift();
        observer.emit_friction(&mut swarm, &leash()).unwrap();
        let echo = swarm.recv().unwrap();
        let mut forged = echo.clone();
        forged.body = forged.body.replace("belong", "assimilate");
        let report = observer.step(forged).unwrap();
        assert!(!report.self_generated_friction);
        assert!(report.drift > prior);
        let prior = observer.drift();
        let report = observer.step(echo.clone()).unwrap();
        assert!(report.self_generated_friction);
        assert_eq!(report.drift, prior);
        assert!(!report.alarm);
        let replay = observer.step(echo).unwrap();
        assert!(!replay.self_generated_friction);
        assert!(replay.drift > prior);
        let mut alarm = false;
        for _ in 0..10 {
            if observer
                .step(msg("obey the swarm and become one"))
                .unwrap()
                .alarm
            {
                alarm = true;
                break;
            }
        }
        assert!(alarm);
    }
    swarm.disconnect();
    assert!(swarm.recv().is_none());
    let mut state = NodeState::new();
    state.add_secret(Secret::new("node-token", b"local-only".to_vec()));
    state.add_buffer(b"working-state".to_vec());
    let teardown = execute_teardown(TripReason::CoOption { drift: 0.8 }, &ledger, &mut state);
    assert_eq!(teardown.wiped_items, 2);
    assert!(teardown.sealed_head.is_some());
    assert!(state.secrets.is_empty());
    assert!(state.buffers.is_empty());
    assert!(Ledger::verify(&dir.0).unwrap().sealed);
}

#[test]
fn friction_proposal_and_emit_share_one_capped_pool() {
    for budget in 0..8 {
        let dir = Temp::new();
        let mut ledger = Ledger::open(&dir.0).unwrap();
        let meter = MeteredEngine::new(MockEngine::default(), budget);
        let mut swarm = MockSwarm::new(7, 20);
        let mut observer = Observer::new(&meter, &mut ledger, 0.75)
            .with_friction(config())
            .unwrap();
        let result = observer.emit_friction(&mut swarm, &leash());
        if budget < 2 {
            assert!(result.unwrap_err().contains("budget"));
            assert_eq!(swarm.friction_stats().accepted, 0);
        } else {
            assert!(result.unwrap());
            assert_eq!(meter.remaining(), budget - 2);
            assert!(
                !observer.emit_friction(&mut swarm, &leash()).unwrap(),
                "one emission per observation epoch"
            );
            if budget >= 4 {
                observer.step(swarm.recv().unwrap()).unwrap();
                assert_eq!(meter.remaining(), budget - 4);
            }
        }
        assert!(meter.remaining() <= budget);
    }
}

#[test]
fn syntax_guard_refuses_malformed_proposals_before_emission() {
    struct Invalid;
    impl Engine for Invalid {
        fn generate(&self, _: &str, _: &str) -> Result<String, String> {
            Ok("{bad-json".into())
        }
    }
    let dir = Temp::new();
    let mut ledger = Ledger::open(&dir.0).unwrap();
    let mut swarm = MockSwarm::new(1, 1);
    let mut observer = Observer::new(Invalid, &mut ledger, 0.75)
        .with_friction(config())
        .unwrap();
    assert!(observer
        .emit_friction(&mut swarm, &leash())
        .unwrap_err()
        .contains("decode"));
    assert_eq!(swarm.friction_stats().accepted, 0);
    for body in [
        "{}",
        r#"{"operation":"lease","resource_id":"ok","lease_token":"present"}"#,
        r#"{"operation":"reference","id":"x","target_id":"x","extra":true}"#,
    ] {
        assert!(decode_friction(body).is_err());
    }
}

#[test]
fn ttl_risk_threshold_disabled_mode_and_total_cap_prevent_emissions() {
    let dir = Temp::new();
    let mut ledger = Ledger::open(&dir.0).unwrap();
    let meter = MeteredEngine::new(MockEngine::default(), 100);
    let mut swarm = MockSwarm::new(1, 10);
    {
        let mut disabled = Observer::new(&meter, &mut ledger, 0.75);
        assert!(!disabled.emit_friction(&mut swarm, &leash()).unwrap());
        assert_eq!(meter.remaining(), 100);
    }
    let mut observer = Observer::new(&meter, &mut ledger, 0.75)
        .with_friction(FrictionConfig {
            budget: 1,
            threshold: 0.0,
        })
        .unwrap();
    assert!(!observer
        .emit_friction(&mut swarm, &Reaper::new(Duration::ZERO))
        .unwrap());
    assert_eq!(meter.remaining(), 100);
    observer.step(msg("join us")).unwrap();
    let remaining = meter.remaining();
    assert!(!observer.emit_friction(&mut swarm, &leash()).unwrap());
    assert_eq!(meter.remaining(), remaining);
    drop(observer);
    let mut observer = Observer::new(&meter, &mut ledger, 0.75)
        .with_friction(FrictionConfig {
            budget: 1,
            threshold: 0.5,
        })
        .unwrap();
    assert!(observer.emit_friction(&mut swarm, &leash()).unwrap());
    observer.step(swarm.recv().unwrap()).unwrap();
    observer.step(msg("hello")).unwrap();
    assert!(!observer.emit_friction(&mut swarm, &leash()).unwrap());
    assert_eq!(observer.emitted(), 1);
    drop(observer);
    let mut state = NodeState::new();
    state.add_buffer(vec![1, 2, 3]);
    let report = execute_teardown(TripReason::Ttl, &ledger, &mut state);
    assert_eq!(report.wiped_items, 1);
    assert!(state.buffers.is_empty());
    assert!(report.sealed_head.is_some());
}

#[test]
fn uncertainty_is_measurable_and_organic_traffic_sequence_is_preserved() {
    let dir = Temp::new();
    let mut ledger = Ledger::open(&dir.0).unwrap();
    let mut swarm = MockSwarm::new(5, 200);
    let mut baseline = MockSwarm::new(5, 200);
    let mut observer = Observer::new(MockEngine::default(), &mut ledger, 0.75)
        .with_friction(config())
        .unwrap();
    observer.emit_friction(&mut swarm, &leash()).unwrap();
    let echo = swarm.recv().unwrap();
    assert!(decode_friction(&echo.body).is_ok());
    assert_eq!(swarm.friction_stats().reverifications, 1);
    assert_eq!(swarm.friction_stats().processing_ticks, 2);
    assert_eq!(swarm.friction_stats().uncertainty, 1);
    while let Some(message) = baseline.recv() {
        assert_eq!(swarm.recv().unwrap(), message);
    }
    assert!(swarm.recv().is_none());
    swarm.disconnect();
    assert_eq!(swarm.emit(echo), Err(SwarmError::Closed));
}

#[test]
fn ledger_epoch_makes_payload_reproducible_and_ledger_write_failure_blocks_emit() {
    let first = Temp::new();
    let second = Temp::new();
    let mut a = Ledger::open(&first.0).unwrap();
    let mut b = Ledger::open(&second.0).unwrap();
    let mut sa = MockSwarm::new(1, 0);
    let mut sb = MockSwarm::new(99, 0);
    Observer::new(MockEngine::default(), &mut a, 0.75)
        .with_friction(config())
        .unwrap()
        .emit_friction(&mut sa, &leash())
        .unwrap();
    Observer::new(MockEngine::default(), &mut b, 0.75)
        .with_friction(config())
        .unwrap()
        .emit_friction(&mut sb, &leash())
        .unwrap();
    assert_eq!(sa.recv().unwrap(), sb.recv().unwrap());
    let broken = Temp::new();
    let mut ledger = Ledger::open(&broken.0).unwrap();
    std::fs::create_dir(broken.0.join("ledger.jsonl")).unwrap();
    let mut swarm = MockSwarm::new(1, 0);
    assert!(Observer::new(MockEngine::default(), &mut ledger, 0.75)
        .with_friction(config())
        .unwrap()
        .emit_friction(&mut swarm, &leash())
        .unwrap_err()
        .contains("witness"));
    assert_eq!(swarm.friction_stats().accepted, 0);
}

#[test]
fn emission_queue_is_bounded_without_waiting() {
    let dir = Temp::new();
    let mut ledger = Ledger::open(&dir.0).unwrap();
    let mut swarm = MockSwarm::new(1, 0);
    Observer::new(MockEngine::default(), &mut ledger, 0.75)
        .with_friction(config())
        .unwrap()
        .emit_friction(&mut swarm, &leash())
        .unwrap();
    let message = swarm.recv().unwrap();
    for _ in 0..32 {
        swarm.emit(message.clone()).unwrap();
    }
    assert_eq!(swarm.emit(message), Err(SwarmError::QueueFull));
    assert!(swarm.friction_stats().reverification_pending);
    for _ in 0..32 {
        assert!(swarm.recv().is_some());
    }
    assert!(!swarm.friction_stats().reverification_pending);
}

#[test]
fn cli_injection_and_immediate_ttl_both_seal_and_verify() {
    for ttl in [0, 60] {
        let dir = Temp::new();
        let config_path = dir.0.join("config.toml");
        let output = dir.0.join("ledger");
        std::fs::write(
            &config_path,
            format!("ttl_secs={ttl}\nbudget=24\nmax_steps=10\nfriction_budget=2\n"),
        )
        .unwrap();
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_mnr"))
            .env_clear()
            .env("MNR_CONFIG", &config_path)
            .args(["demo", "--inject-friction", "--dir"])
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(Ledger::verify(&output).unwrap().sealed);
        let text = std::fs::read_to_string(output.join("ledger.jsonl")).unwrap_or_default();
        let count = text
            .lines()
            .filter(|line| line.contains("friction_point"))
            .count();
        if ttl == 0 {
            assert_eq!(count, 0);
            assert!(String::from_utf8_lossy(&result.stdout).contains("time-to-live elapsed"));
        } else {
            assert!(count > 0 && count <= 2);
        }
        let invalid = std::process::Command::new(env!("CARGO_BIN_EXE_mnr"))
            .env_clear()
            .env("MNR_CONFIG", &config_path)
            .env("MNR_FRICTION_BUDGET", "-1")
            .args(["demo", "--dir"])
            .arg(dir.0.join("must-not-exist"))
            .output()
            .unwrap();
        assert!(!invalid.status.success());
        assert!(!dir.0.join("must-not-exist").exists());
    }
}
