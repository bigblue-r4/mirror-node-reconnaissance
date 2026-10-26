//! `mnr` — Mirror Node Reconnaissance command line.
//!
//! Subcommands:
//!   demo            Run the observer against the bundled mock swarm, then seal
//!                   and verify the witness log.
//!   sparkle         Run the sealed-lab multi-probe sparkle demo.
//!   sparkle verify  Recompute the aggregation and check it against the sealed chain.
//!   ledger verify   Verify the integrity of a witness log on disk.
//!   ledger show     Print a short summary of a witness log.
//!   bundle keygen   Mint an Ed25519 seed file for the node or the exporter.
//!   bundle export   Write a witness-bundle/2 for a whole-log file.
//!
//! The demo is fully lab-contained: the only swarm it can talk to is the
//! in-process `mnr-sim` mock. See AUTHORIZATION.md.

mod bundle;
mod config;
mod sparkle;

use config::Config;
use mnr_ledger::Ledger;
use mnr_observer::{FrictionConfig, MeteredEngine, MockEngine, Observer, SwarmConnector};
use mnr_reaper::{execute_teardown, NodeState, Reaper, Secret, TripReason};
use mnr_sim::MockSwarm;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("demo") => cmd_demo(&args[1..]),
        Some("sparkle") => cmd_sparkle(&args[1..]),
        Some("ledger") => cmd_ledger(&args[1..]),
        Some("bundle") => bundle::cmd_bundle(&args[1..]),
        Some("help") | Some("-h") | Some("--help") | None => {
            print_help();
            0
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n");
            print_help();
            2
        }
    };
    std::process::exit(code);
}

fn print_help() {
    println!(
        "mnr — Mirror Node Reconnaissance (lab demo)\n\n\
         USAGE:\n  \
         mnr demo [--dir <path>]          Run the observer vs. the bundled mock swarm\n  \
         Friction options: --inject-friction --friction-budget <1..1024> --friction-threshold <0..drift_threshold>\n  \
         mnr sparkle [--probes N] [--ttl-ms MS] [--dir <path>]   Run the multi-probe sparkle demo\n  \
         mnr sparkle verify [--dir <path>]   Recompute the aggregation from the probe ledgers and check the sealed chain\n  \
         mnr ledger verify [--dir <path>] Verify a witness log's integrity\n  \
         mnr ledger show   [--dir <path>] Summarize a witness log\n  \
         mnr bundle keygen --out <file>  Mint an Ed25519 seed for the node or the exporter\n  \
         mnr bundle export --log <entries.ndjson> --out <bundle.ndjson>\n    \
             --scope <case|log> --node-key <file> --exporter-key <file>\n    \
             --department <name> --node-id <id> [--case <number>]\n    \
             [--agency <name>] [--seal <id>] [--actor <who>] [--role <role>]\n\n\
         Config: env MNR_* > configs/mnr.toml > defaults (see configs/mnr.toml.example)."
    );
}

/// Pull `--dir <path>` out of args, if present.
fn arg_dir(args: &[String]) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--dir" {
            return it.next().cloned();
        }
    }
    None
}

fn cmd_demo(args: &[String]) -> i32 {
    let mut cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return 1;
        }
    };
    if let Some(dir) = arg_dir(args) {
        cfg.ledger_dir = dir;
    }
    if let Err(error) = apply_friction_args(&mut cfg, args).and_then(|_| cfg.validate()) {
        eprintln!("config error: {error}");
        return 2;
    }

    println!("== Mirror Node Reconnaissance — lab demo ==");
    println!(
        "ledger_dir={} drift_threshold={:.2} ttl={}s max_steps={} budget={} seed={} swarm_len={}\n",
        cfg.ledger_dir,
        cfg.drift_threshold,
        cfg.ttl_secs,
        cfg.max_steps,
        cfg.budget,
        cfg.seed,
        cfg.swarm_len
    );

    let mut ledger = match Ledger::open(&cfg.ledger_dir) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ledger error: {e}");
            return 1;
        }
    };

    // The node's own transient state — this is what the reaper burns on exit.
    let mut state = NodeState::new();
    state.add_secret(Secret::new(
        "session-token",
        format!("tok-{}", cfg.seed).into_bytes(),
    ));
    state.add_buffer(Vec::new());

    let engine = MeteredEngine::new(MockEngine::default(), cfg.budget);
    let mut swarm = MockSwarm::new(cfg.seed, cfg.swarm_len);
    let reaper = Reaper::new(Duration::from_secs(cfg.ttl_secs));

    // Drive the loop manually so we can interleave the TTL check with steps.
    let trip: TripReason;
    let mut steps: u64 = 0;
    {
        let mut observer = Observer::new(engine, &mut ledger, cfg.drift_threshold);
        if cfg.inject_friction {
            observer = match observer.with_friction(FrictionConfig {
                budget: cfg.friction_budget,
                threshold: cfg.friction_threshold,
            }) {
                Ok(observer) => observer,
                Err(error) => {
                    eprintln!("config error: {error}");
                    return 2;
                }
            };
        }
        loop {
            if reaper.ttl_expired() {
                trip = TripReason::Ttl;
                break;
            }
            if steps >= cfg.max_steps {
                trip = TripReason::Manual;
                break;
            }
            let msg = match swarm.recv() {
                Some(m) => m,
                None => {
                    trip = TripReason::Manual; // stream ended; pull the node
                    break;
                }
            };
            match observer.step(msg) {
                Ok(rep) => {
                    steps = rep.step;
                    println!(
                        "step {:>3} | stance={:<9} | drift={:.3} | audit={:<8} | {}",
                        rep.step,
                        rep.proposer.stance,
                        rep.drift,
                        if rep.verifier.agree {
                            "agree"
                        } else {
                            "DISAGREE"
                        },
                        rep.verifier.note
                    );
                    if rep.alarm {
                        trip = TripReason::CoOption { drift: rep.drift };
                        break;
                    }
                    if reaper.ttl_expired() {
                        trip = TripReason::Ttl;
                        break;
                    }
                    if let Err(error) = observer.emit_friction(&mut swarm, &reaper) {
                        trip = TripReason::Anomaly { detail: error };
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
    } // observer dropped here → releases the &mut Ledger borrow
    swarm.disconnect();
    println!(
        "friction accepted={} reverifications={} virtual_ticks={}",
        swarm.friction_stats().accepted,
        swarm.friction_stats().reverifications,
        swarm.friction_stats().processing_ticks
    );

    println!("\n-- teardown --");
    match &trip {
        TripReason::CoOption { drift } => {
            println!("TRIP: co-option drift {drift:.3} >= threshold {:.2} — pulling the node before it belongs to the swarm.", cfg.drift_threshold)
        }
        TripReason::Ttl => {
            println!("TRIP: time-to-live elapsed — short leash spent, pulling the node.")
        }
        TripReason::Anomaly { detail } => println!("TRIP: anomaly — {detail}."),
        TripReason::Manual => println!("TRIP: stream ended / manual pull."),
    }

    let report = execute_teardown(trip, &ledger, &mut state);
    if let Some(head) = &report.sealed_head {
        println!(
            "ledger sealed: head_seq={} count={} head_hash={}…",
            head.head_seq,
            head.count,
            &head.head_hash[..16.min(head.head_hash.len())]
        );
    } else {
        println!("warning: ledger seal failed");
    }
    println!(
        "wiped {} local secret/buffer item(s) — bridge burned.\n",
        report.wiped_items
    );

    // Prove the witness log is intact and tamper-evident.
    println!("-- witness log verification --");
    match Ledger::verify(&cfg.ledger_dir) {
        Ok(r) => {
            println!(
                "OK: {} entries, sealed={}, head={}…",
                r.entries,
                r.sealed,
                &r.head_hash[..16.min(r.head_hash.len())]
            );
            println!(
                "\nTry it: edit any line in {}/ledger.jsonl, then run `mnr ledger verify --dir {}` — verification will fail.",
                cfg.ledger_dir, cfg.ledger_dir
            );
            println!(
                "Also try truncating that file and re-running the demo in the same directory: it refuses, because the sealed anchor is never rewritten. Use a fresh --dir for each run."
            );
            0
        }
        Err(e) => {
            eprintln!("VERIFY FAILED: {e}");
            1
        }
    }
}

fn apply_friction_args(cfg: &mut Config, args: &[String]) -> Result<(), String> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--inject-friction" => cfg.inject_friction = true,
            "--friction-budget" => {
                cfg.friction_budget = args
                    .next()
                    .ok_or("missing --friction-budget value")?
                    .parse()
                    .map_err(|_| "invalid --friction-budget")?
            }
            "--friction-threshold" => {
                cfg.friction_threshold = args
                    .next()
                    .ok_or("missing --friction-threshold value")?
                    .parse()
                    .map_err(|_| "invalid --friction-threshold")?
            }
            "--dir" => {
                args.next().ok_or("missing --dir value")?;
            }
            _ => return Err(format!("unknown demo argument: {arg}")),
        }
    }
    Ok(())
}

fn cmd_sparkle(args: &[String]) -> i32 {
    if let Some("verify") = args.first().map(String::as_str) {
        return cmd_sparkle_verify(&args[1..]);
    }
    let cfg = match sparkle::SparkleConfig::from_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sparkle config error: {e}");
            return 1;
        }
    };

    println!("== Mirror Node Reconnaissance — sparkle demo ==");
    println!(
        "probes={} ttl_ms={} drift_threshold={:.2} budget_per_probe={} swarm_len={} base_seed={} dir={}\n",
        cfg.num_probes,
        cfg.ttl_ms,
        cfg.drift_threshold,
        cfg.budget_per_probe,
        cfg.swarm_len_per_probe,
        cfg.base_seed,
        cfg.dir
    );

    let mut controller = sparkle::SparkleController::new(cfg.clone());
    match controller.run_all_probes() {
        Ok(agg) => {
            println!(
                "\n-- sparkle aggregation --\n{} probes sealed, root={}…",
                agg.num_probes,
                &agg.aggregation_root[..16.min(agg.aggregation_root.len())]
            );

            let report = sparkle::verify_sparkle_aggregation(&cfg.dir);
            print_sparkle_report(&report);
            if report.verified() {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("sparkle run failed: {e}");
            1
        }
    }
}

fn cmd_sparkle_verify(args: &[String]) -> i32 {
    let mut dir = sparkle::SparkleConfig::default().dir;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--dir" => match it.next() {
                Some(value) => dir = value.clone(),
                None => {
                    eprintln!("usage: mnr sparkle verify [--dir <path>]");
                    return 2;
                }
            },
            other => {
                eprintln!("unknown sparkle verify argument: {other}\n\nusage: mnr sparkle verify [--dir <path>]");
                return 2;
            }
        }
    }
    let report = sparkle::verify_sparkle_aggregation(&dir);
    print_sparkle_report(&report);
    if report.verified() {
        0
    } else {
        1
    }
}

fn print_sparkle_report(report: &sparkle::VerifyReport) {
    let root = &report.aggregation_root;
    let short = &root[..16.min(root.len())];
    if report.verified() {
        println!(
            "OK: probes_verified={} all_probes_ok={} aggregate_ok={} sealed={} root={short}…",
            report.probes_verified, report.all_probes_ok, report.aggregate_ok, report.sealed
        );
    } else {
        eprintln!(
            "SPARKLE VERIFY FAILED: probes_verified={} all_probes_ok={} aggregate_ok={} sealed={} recomputed_root={short}…",
            report.probes_verified, report.all_probes_ok, report.aggregate_ok, report.sealed
        );
        for error in &report.errors {
            eprintln!("  - {error}");
        }
    }
    // For a pre-0.2.0 aggregate the exported root legitimately differs from the
    // recomputed one, and the explanation above already says so. Repeating it as
    // a warning reads like a second, unrelated finding.
    if let Some(exported) = &report.exported_root {
        if !report.legacy_layout && exported != root {
            eprintln!(
                "  warning: aggregate-root.json claims {exported}…, which is not the root recomputed from the chain"
            );
        }
    }
}

fn cmd_ledger(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("verify") => {
            let dir = arg_dir(&args[1..]).unwrap_or_else(|| {
                Config::load()
                    .map(|c| c.ledger_dir)
                    .unwrap_or_else(|_| "./mnr-run".into())
            });
            match Ledger::verify(&dir) {
                Ok(r) if r.sealed => {
                    println!(
                        "OK: {} entries in {dir}, sealed=true, head={}…",
                        r.entries,
                        &r.head_hash[..16.min(r.head_hash.len())]
                    );
                    0
                }
                Ok(r) => {
                    eprintln!(
                        "UNSEALED: {} entries in {dir} form an intact chain (head={}…), but there is no head anchor, so truncation cannot be ruled out. A deleted anchor and a never-sealed log look the same.",
                        r.entries,
                        &r.head_hash[..16.min(r.head_hash.len())]
                    );
                    1
                }
                Err(e) => {
                    eprintln!("VERIFY FAILED for {dir}: {e}");
                    1
                }
            }
        }
        Some("show") => {
            let dir = arg_dir(&args[1..]).unwrap_or_else(|| "./mnr-run".into());
            match Ledger::verify(&dir) {
                Ok(r) => {
                    println!("ledger {dir}: {} entries, sealed={}", r.entries, r.sealed);
                    0
                }
                Err(e) => {
                    eprintln!("cannot read ledger {dir}: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("usage: mnr ledger <verify|show> [--dir <path>]");
            2
        }
    }
}

#[cfg(test)]
mod friction_config_tests {
    use super::*;
    #[test]
    fn cli_friction_switches_are_validated() {
        let mut cfg = Config::default();
        assert!(!cfg.inject_friction);
        let args = [
            "--inject-friction",
            "--friction-budget",
            "3",
            "--friction-threshold",
            "0.4",
        ]
        .map(String::from);
        apply_friction_args(&mut cfg, &args).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.inject_friction);
        assert_eq!(cfg.friction_budget, 3);
        cfg.friction_threshold = f64::NAN;
        assert!(cfg.validate().is_err());
        cfg.friction_threshold = 0.9;
        assert!(cfg.validate().is_err());
        assert!(apply_friction_args(&mut cfg, &["--friction-budget".into()]).is_err());
    }
}
