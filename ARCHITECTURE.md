# MNR Architecture

## 1. Overview

MNR is a Rust workspace of four library crates and one binary. The dangerous
field mechanics (traffic interception, protocol impersonation, evasion) are
strictly compartmentalized away from the runnable substrate — they exist only as
documentation in `proxy/`.

```
                      ┌──────────────────────────────────────────────┐
                      │                mnr (CLI)                      │
                      │   loads config, drives the run, verifies log  │
                      └───────┬───────────────┬───────────────┬──────┘
                              │               │               │
                 reads from   ▼               ▼ witnesses      ▼ bounds
        ┌──────────────────────────┐  ┌───────────────┐  ┌──────────────────┐
        │  SwarmConnector (trait)  │  │  mnr-ledger   │  │   mnr-reaper     │
        │  ── only impl: mnr-sim   │  │ hash-chained  │  │ TTL + trip →     │
        │     (bundled mock swarm) │  │ witness log   │  │ seal + wipe      │
        └────────────┬─────────────┘  └──────▲────────┘  └────────▲─────────┘
                     │ Message               │ append            │ trip
                     ▼                       │                   │
        ┌───────────────────────────────────┴───────────────────┴─────────┐
        │                    mnr-observer (the node)                        │
        │                                                                   │
        │   Message ─► Proposer  ─► characterization (topology/dialect/…)   │
        │              │                                                    │
        │              └─► Verifier ─► audits + scores CO-OPTION DRIFT ─────┼─► alarm
        │                                                                   │
        │   both hemispheres share ONE capped call budget (MeteredEngine)   │
        └───────────────────────────────────────────────────────────────────┘
```

Data flow per observed message:

1. The observer pulls a `Message` from the `SwarmConnector`.
2. It writes an `observation` record to the witness ledger (fingerprint only).
3. The **Proposer** hemisphere characterizes the message and reports its stance.
4. The **Verifier** hemisphere audits that characterization and emits the
   authoritative **drift** score. Each hemisphere's turn is also witnessed.
5. If drift ≥ threshold, the observer raises a co-option alarm.
6. The CLI loop also checks the reaper's TTL between steps.
7. On any trip, the reaper seals the ledger and wipes the node's local state.

## 2. The split-brain mechanism (an honest account)

The "split-brain" here is **logical role separation, not tensor isolation.** This
is inherited faithfully from the SGAIL split-brain harness, where the same
correction applies. There is no separate process per hemisphere and no
weight/tensor partitioning. What is actually separated:

- **Roles.** `Role::Proposer` and `Role::Verifier` receive different system
  prompts and reason over the same observation independently. A real deployment
  can back each role with a different model; the demo backs both with one
  deterministic `MockEngine`.
- **Task framing.** The Verifier is instructed to treat the Proposer's output as
  *data to audit*, not as a conclusion to accept — the same "audit, don't
  collaborate" stance the reference harness uses.
- **Budget.** Both roles draw from a single `AtomicUsize` call budget
  (`MeteredEngine`), so a two-hemisphere run cannot exceed the ceiling a
  single-hemisphere run would have.

**Co-option drift** is the security-relevant signal. It models the operational
reality that sustained exposure to a swarm's influence gradually assimilates a
node: drift rises with lure-bearing traffic and relaxes with benign traffic. The
Verifier's drift score is authoritative; the Proposer's self-reported stance
(`observing → engaging → adopting`) is a human-readable shadow of it. When the
Verifier's drift crosses `drift_threshold`, the node has been in contact too long
and is pulled.

> The `MockEngine` is a deterministic stand-in for a real base model. Replacing
> it with an LLM-backed `Engine` (same `generate(system, prompt)` trait) is the
> single seam between the lab demo and a live-model deployment.

## 3. The witness ledger

`mnr-ledger` is an append-only JSONL log with a companion `log-head.json` anchor.

- **Entry:** `{ seq, ts, kind, prev_hash, payload_fingerprint, entry_hash }`.
- **Fingerprint, not plaintext.** Callers hand raw bytes to `append`; only the
  SHA-256 of those bytes is stored. No observed content is persisted in the clear
  (privacy-by-fingerprint, as in the split-brain `sbh-store` convention).
- **Chain:** `entry_hash = SHA256(seq | ts | kind | prev_hash | payload_fp)`;
  `prev_hash` of entry *n* is `entry_hash` of entry *n-1*; genesis is 64 zeros.
  Mutating any past entry breaks its own hash and every subsequent `prev_hash`.
- **Head anchor:** `seal()` writes `{ head_seq, head_hash, count, sealed_at }`.
  `verify()` recomputes the whole chain **and** checks its tail against the
  anchor, so truncation (dropping trailing entries) and extension (appending
  after a seal) are both detectable.

This is **detection, not prevention** — the same posture as SLATE. An attacker
with write access can still destroy the log; they cannot silently *edit* it and
have `verify()` pass.

## 4. The reaper (auditor protection)

`mnr-reaper` is the only kill-switch, and it acts solely on the **local node**:

- `Reaper` holds a `Duration` TTL and reports `ttl_expired()` / `remaining()`.
- `TripReason` is one of `Ttl`, `CoOption { drift }`, `Anomaly { detail }`,
  `Manual`.
- `execute_teardown` (1) seals the witness ledger, then (2) wipes the node's own
  `NodeState` — transient `Secret`s and working buffers are overwritten with
  volatile zero writes and cleared. `Secret` also wipes on `Drop`.

"Burning the bridge" is the node severing *its own* link and erasing *its own*
secrets. Nothing here reaches out to a remote system. (Production deployments
should back `Secret` with the `zeroize` crate for stronger anti-optimization
guarantees; a code comment marks the spot.)

## 5. Configuration

`env (MNR_*) → configs/mnr.toml → built-in defaults`, resolved in
`cli/src/config.rs` with `validate()` run before any deployment. This mirrors the
split-brain harness precedence exactly. Fields: `ledger_dir`, `drift_threshold`,
`ttl_secs`, `max_steps`, `budget`, `seed`, `swarm_len`.

## 6. Testing

15 tests, all backend-free (deterministic `MockEngine` + seeded `MockSwarm`):

- **ledger** — append/verify round-trip, empty log, mutation detection,
  truncation detection via anchor, ISO timestamp conversion.
- **observer** — benign traffic stays below threshold; sustained lures trip the
  alarm; the shared budget is capped; every step is witnessed.
- **reaper** — TTL expiry, teardown seals + wipes, secret wipe clears bytes.
- **sim** — determinism for a seed, exact message count, escalating lure
  pressure.
