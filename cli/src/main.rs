//! `mnr` — Mirror Node Reconnaissance command line.
//!
//! Subcommands:
//!   demo            Run the observer against the bundled mock swarm, then seal
//!                   and verify the witness log.
//!   ledger verify   Verify the integrity of a witness log on disk.
//!   ledger show     Print a short summary of a witness log.
//!
//! The demo is fully lab-contained: the only swarm it can talk to is the
//! in-process `mnr-sim` mock. See AUTHORIZATION.md.

mod config;

use config::Config;
use mnr_ledger::Ledger;
use mnr_observer::{MeteredEngine, MockEngine, Observer, SwarmConnector};
use mnr_reaper::{execute_teardown, NodeState, Reaper, Secret, TripReason};
use mnr_sim::MockSwarm;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("demo") => cmd_demo(&args[1..]),
        Some("ledger") => cmd_ledger(&args[1..]),
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
         mnr ledger verify [--dir <path>] Verify a witness log's integrity\n  \
         mnr ledger show   [--dir <path>] Summarize a witness log\n\n\
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
                        "step {:>3} | stance={:<9} | drift={:.3} | {}",
                        rep.step, rep.proposer.stance, rep.drift, rep.verifier.note
                    );
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
    } // observer dropped here → releases the &mut Ledger borrow

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
            0
        }
        Err(e) => {
            eprintln!("VERIFY FAILED: {e}");
            1
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
                Ok(r) => {
                    println!(
                        "OK: {} entries in {dir}, sealed={}, head={}…",
                        r.entries,
                        r.sealed,
                        &r.head_hash[..16.min(r.head_hash.len())]
                    );
                    0
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
