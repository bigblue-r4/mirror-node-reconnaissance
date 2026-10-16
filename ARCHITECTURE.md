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
             reads/emits lab  ▼               ▼ witnesses      ▼ bounds
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

Tests are backend-free (deterministic `MockEngine` + seeded `MockSwarm`):

- **ledger** — append/verify round-trip, empty log, mutation detection,
  truncation detection via anchor, ISO timestamp conversion.
- **observer** — benign traffic stays below threshold; sustained lures trip the
  alarm; the shared budget is capped; every step is witnessed.
- **reaper** — TTL expiry, teardown seals + wipes, secret wipe clears bytes.
- **sim** — determinism for a seed, exact message count, escalating lure
  pressure.

## 7. Friction Injection (Lab Only)

`SwarmConnector::emit(Message)` is a synchronous, non-blocking emission seam;
the only production implementation remains the in-process `MockSwarm`. Other
receive-only connectors default to an unsupported error. No networking, TLS,
interception or impersonation implementation is added. See
[AUTHORIZATION.md](AUTHORIZATION.md); external injection remains concept-only
and `proxy/` code is unchanged.

The opt-in observer path performs these bounded operations:

1. Check total friction cap, outstanding receipts, prior drift, per-observation
   rate and the existing reaper TTL. No friction follows a self-attributed echo.
2. Charge a Proposer call against the existing shared pool. Seed SplitMix64 from
   the ledger's 32-byte epoch nonce and generate a short lease/reference request.
   The same ledger state yields the same payload; the mock swarm RNG is separate.
3. Dry-run `decode_friction`, the same strict, bounded JSON schema parser used
   by MockSwarm ingestion. Syntactic errors/unknown fields never reach emit.
   The allowed incompleteness is semantic: absent lease token, circular reference
   or unresolved ID. Rejected proposals are fingerprint-witnessed and stop the run.
4. Witness the valid proposal as a `friction_point` attempt, check TTL again,
   charge emission from the shared pool, then perform the non-blocking emit.
   Any witness error stops before ingestion. No raw payload is written to disk.
5. Store a bounded, single-use local receipt with an epoch tag and salted hash
   of the full message envelope. The returned metadata is untrusted until that
   receipt matches exactly. Altered bodies, forged tags and replayed receipts
   take the normal Verifier path. Matched self-perturbations hold existing drift
   steady in both the mock scorer and observer; they cannot erase genuine drift.

The queue and local receipt window each hold at most 32 messages. Mock ingestion
increments uncertainty and re-verification counters, adds two virtual work ticks,
and marks re-verification pending until its echo is consumed. It does not block,
sleep or change the seeded organic traffic sequence. The CLI checks TTL between
steps and before emission; teardown disconnects the mock queue before sealing
and wiping. The synchronous mock model is bounded work; there is no unbounded
external model call or remote connector in this implementation.

Witness entry shape and hash-chain verification are unchanged. For a friction
entry, the epoch nonce is `SHA-256("mnr/friction-epoch/v1" || previous_hash_ascii
|| sequence_u64_little_endian)`; the stored payload fingerprint is exactly
`SHA-256(payload_bytes || nonce)`. The public, reconstructible nonce separates
epochs and keeps generation reproducible; it is not a secret salt or encryption.
Sealing/verification also accepts a genuinely empty ledger, which is necessary
when TTL expires before the first observation. Mutation, truncation and extension
remain detectable relative to the retained head anchor.

Configuration adds `inject_friction`, `friction_budget` and `friction_threshold`
to file/env/default resolution, with explicit CLI overrides. Injection defaults
off; budgets are capped at 1024 and the enabled friction threshold cannot exceed
the drift threshold. Malformed config and invalid friction environment values
are errors rather than silently enabling default emission limits.

Integration tests exercise shared-budget exhaustion, disabled/risk/TTL gating,
full queue rejection, exact self-attribution versus spoof/replay, organic traffic
preservation, re-verification work, deterministic initial epochs, fail-closed
witness writes, genuine-drift teardown, salted fingerprints/no plaintext, ledger
tampering and both normal/zero-TTL CLI sealing paths.
