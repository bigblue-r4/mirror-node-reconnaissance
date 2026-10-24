# MNR Architecture

## 1. Overview

MNR is a Rust workspace of four library crates and one binary. The field
mechanics — traffic interception, protocol impersonation, evasion — exist only as
a written problem statement in `proxy/`; no implementation is present.

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
        │              └─► Verifier ─► scores CO-OPTION DRIFT ──────────────┼─► alarm
        │                                                                   │
        │   both roles share ONE capped call budget (MeteredEngine)         │
        └───────────────────────────────────────────────────────────────────┘
```

Data flow per observed message, as implemented:

1. The CLI pulls a `Message` from the `SwarmConnector` and calls
   `Observer::step`.
2. The observer appends an `observation` entry: the SHA-256 of the serialized
   message. The bytes are not stored.
3. The **Proposer** role is called with its system prompt and a `StepContext`
   (message, prior drift, echo flag); the raw answer is witnessed as a
   `model-turn` entry.
4. The **Verifier** role is called with its own system prompt and the *same*
   `StepContext` — not the Proposer's answer — and its `drift` field becomes the
   authoritative score, clamped to `0..1`. Its turn is witnessed the same way.
   Non-JSON output holds the previous drift. An attributed echo also holds drift.
5. If drift ≥ `drift_threshold`, the step reports an alarm.
6. The CLI checks the reaper's TTL between steps and again before any emission.
7. On a trip, the CLI disconnects the mock connector, then `execute_teardown`
   seals the ledger and wipes the node's local state.

## 2. The split-brain mechanism (an honest account)

The "split-brain" here is **logical role separation, not tensor isolation**. There
is no process per role and no weight or tensor partitioning. What is actually
separated:

- **Roles.** `Role::Proposer` and `Role::Verifier` get different system prompts
  and are called independently.
- **Task framing.** The Verifier is instructed to treat the Proposer's output as
  *data to audit*, not as a conclusion to accept.
- **Budget.** Both roles draw from a single `AtomicUsize` call budget
  (`MeteredEngine`), so a two-role run cannot exceed the ceiling a single-role
  run would have.

Three limits are worth stating plainly, because they are easy to assume away:

- **The Verifier is not given the Proposer's answer.** `run_role` passes the same
  `StepContext` to both roles, and that struct carries the message, the prior
  drift and the echo flag. The audit instruction is in the prompt; the artifact
  to be audited is not. So the second role re-characterizes the message rather
  than checking the first role's characterization.
- **Under `MockEngine`, both roles compute the same number.** Drift is arithmetic
  over eight literal marker substrings (`+0.16` per lure-bearing message, `-0.03`
  per benign one, clamped). The Proposer reports it as `self_drift`; the Verifier
  reports it as `drift`; the Verifier's `agree` flag is simply `!lure`. The alarm
  is the Verifier's value crossing the threshold, so **disagreement between roles
  is not currently the signal**, despite the framing above.
- **Nothing here is evaluated.** There is no false-positive rate, no adversarial
  model that knows it is observed, and no comparison against a single-role
  baseline. The drift score is a demonstration of the plumbing.

> The `MockEngine` is a deterministic stand-in, not a model. Replacing it with an
> LLM-backed `Engine` (same `generate(system, prompt)` signature) is the single
> seam between the lab and a live-model run — and would invalidate every
> behavioural number in the demo.

## 3. The witness ledger

`mnr-ledger` is an append-only JSONL log with a companion `log-head.json` anchor.

- **Entry:** `{ seq, ts, kind, prev_hash, payload_fingerprint, entry_hash }`.
- **Fingerprint, not plaintext.** Callers hand raw bytes to `append`; only the
  SHA-256 of those bytes is stored. This limits bulk disclosure, not a determined
  reader: with a small input domain a fingerprint can be inverted by guessing.
- **Chain:** `entry_hash = SHA256(seq \n ts \n kind \n prev_hash \n payload_fp)`;
  `prev_hash` of entry *n* is `entry_hash` of entry *n-1*; genesis is 64 zeros.
  `kind` is restricted to `[A-Za-z0-9._-]{1,64}` so a caller cannot break the
  newline-delimited preimage.
- **Head anchor:** `seal()` writes `{ head_seq, head_hash, count, sealed_at }`
  with `create_new`, so an anchor is written exactly once. `verify()` recomputes
  the whole chain **and** checks its tail against the anchor, so truncation
  (dropping trailing entries) is detectable. `open()` runs the same check before
  appending and then refuses a sealed directory (`AlreadySealed`); re-sealing a
  different head is likewise refused instead of overwriting the anchor.
- **Durability:** entries are `sync_data`'d as they are appended and the anchor
  is `sync_all`'d before it is trusted. A crash before sealing leaves a chain that
  verifies only as `UNSEALED`; the directory entry itself is not fsynced.
- **What this does not prove.** SHA-256 only — no key, MAC or signature. A party
  who can write the whole ledger directory can delete the log and the anchor,
  rebuild a consistent chain and seal it, and `verify()` will pass; a deleted
  anchor is indistinguishable from a log that was never sealed. Cross-party
  evidence requires exporting the head hash at seal time, which this crate does
  not implement. Timestamps are self-reported wall-clock values.

This is **detection, not prevention** — the same posture as SLATE, and not a
trusted timestamp. An attacker with write access can still destroy the log; they
cannot silently edit it, or shorten and re-seal it, and have `verify()` pass.

## 4. The reaper (auditor protection)

`mnr-reaper` is the only kill-switch, and it acts solely on the **local node**:

- `Reaper` holds a `Duration` TTL and reports `ttl_expired()` / `remaining()`. It
  is polled by the caller; nothing here interrupts a blocking call.
- `TripReason` is one of `Ttl`, `CoOption { drift }`, `Anomaly { detail }`,
  `Manual`.
- `execute_teardown` (1) seals the ledger, then (2) wipes `NodeState` — transient
  `Secret`s and working buffers are overwritten with volatile zero writes and
  cleared. `Secret` also wipes on `Drop`.

The reaper does **not** touch the connector: the `demo` path disconnects the mock
before teardown, and the sparkle probes simply drop theirs. Wiping is
best-effort — earlier copies (allocator reuse, `format!` temporaries, swap,
hibernation) are out of reach, and production use should back `Secret` with
`zeroize` and lock pages as a code comment already notes.

## 5. Configuration

`env (MNR_*) → config file → built-in defaults`, resolved in `cli/src/config.rs`,
with `MNR_CONFIG` overriding the file path (default `configs/mnr.toml`). Fields:
`ledger_dir`, `drift_threshold`, `ttl_secs`, `max_steps`, `budget`, `seed`,
`swarm_len`, plus the three friction controls.

`validate()` runs before a run starts and rejects: `drift_threshold` outside
`0..=1`, zero `max_steps`, zero `budget`, empty `ledger_dir`, and an invalid
friction block (budget outside `1..=1024`; threshold non-finite or above
`drift_threshold` while enabled).

Only the three friction environment variables reject unparseable values. The
other `MNR_*` values are parsed with `.ok()`, so a malformed `MNR_TTL_SECONDS`
or `MNR_DRIFT_THRESHOLD` is **silently ignored** in favour of the file or the
default. A config file that is unreadable, is not valid TOML, or contains unknown
fields is a hard error.

## 6. Testing

`cargo test --workspace` runs 36 tests. They are deterministic: `MockEngine` plus
a seeded `MockSwarm`, no backend and no network.

- **ledger (13)** — append/verify round-trip, empty log, mutation detection,
  truncation detection via anchor, truncated-then-reopened rejection, seal
  create-once and idempotence, refusal to reopen a sealed log, deleted-anchor
  reporting, validated entry reading, `kind` preimage constraints, epoch-nonce
  fingerprints, ISO timestamps.
- **observer (4)** — benign traffic stays below threshold, sustained lures trip
  the alarm, the shared budget is capped, every step is witnessed.
- **reaper (3)** — TTL expiry, teardown seals and wipes, secret wipe.
- **sim (3)** — determinism per seed, exact message count, rising lure pressure.
- **CLI unit (13)** — config validation, friction CLI overrides, and the sparkle
  suite: end-to-end aggregation verification, tampered/truncated probe ledgers,
  a tampered aggregate chain, a missing probe directory, a probe swapped for a
  different valid ledger, and an edited export copy that must not be trusted.
- **CLI integration (8)** — the sealed-lab friction suite: shared-budget
  exhaustion, disabled/threshold/TTL gating, bounded queue, exact echo
  attribution versus spoof and replay, organic traffic preservation, fail-closed
  witness writes, and both normal and zero-TTL sealing paths.

CI (`.github/workflows/ci.yml`, stable Rust) runs `cargo fmt --all --check`,
`cargo build --workspace --all-targets`, `cargo test --workspace` and
`cargo clippy --workspace --all-targets -- -D warnings`. It does not pass
`--locked`, so a stale `Cargo.lock` would be updated silently in CI.

## 7. Request emission (lab only)

`SwarmConnector::emit(Message)` is a synchronous, non-blocking emission seam; the
only implementation remains the in-process `MockSwarm`. Other connectors default
to `SwarmError::Unsupported`. See [AUTHORIZATION.md](AUTHORIZATION.md); external
injection remains concept-only and `proxy/` is unchanged.

The opt-in observer path performs these bounded operations:

1. Check the total emission cap, the outstanding-receipt window, drift against
   both the drift threshold and the friction threshold, the per-step rate, whether
   the previous step was an attributed echo, and the reaper TTL.
2. Charge a Proposer call against the shared pool. Seed SplitMix64 from the
   ledger's 32-byte epoch nonce and generate a short lease/reference request. The
   same ledger state yields the same payload; the mock's RNG is separate.
3. Dry-run `decode_friction`, the same strict, bounded JSON parser used by mock
   ingestion. Unknown fields, oversized bodies and malformed identifiers are
   rejected here; the only permitted incompleteness is semantic (missing lease
   token, circular reference, unresolved ID). Rejected proposals are witnessed
   and stop the run.
4. Witness the valid proposal as a `friction_point` attempt, re-check TTL, charge
   emission from the same pool, then perform the non-blocking emit. A witness
   error stops before ingestion.
5. Store a bounded, single-use local receipt with an epoch tag and salted hash of
   the full envelope. The echo is untrusted until that receipt matches exactly;
   altered bodies, forged tags and replays take the normal Verifier path, and a
   matched echo holds drift instead of lowering it.

The queue and the receipt window each hold at most 32 messages. Mock ingestion
increments uncertainty and re-verification counters, adds two virtual work ticks,
and marks re-verification pending until the echo is consumed. It does not block,
sleep or change the seeded organic traffic sequence. This models added work; it
does not measure it.

Emission is off by default. `friction_budget` is a total cap in `1..=1024`, at
most one emission is allowed per observed step, and emission is withheld above
the friction threshold, at the drift alarm, after TTL, or while the receipt
window is full. `Observer::run` does **not** emit; the CLI calls `emit_friction`
explicitly between steps.

## 8. Sparkle aggregation

`mnr sparkle` runs N independent probes. Each probe is a full observer + ledger +
reaper run in its own directory, and each seals its own log. The controller then
commits two kinds of value to a separate aggregate ledger:

1. one `sparkle-fragment` entry per probe, whose payload is exactly
   `mnr/sparkle-fragment/v1\n<probe_id>\n<fragment_hash>`, where the fragment hash
   covers that probe's `ledger.jsonl` and `log-head.json` (domain-separated and
   length-prefixed);
2. one final `sparkle-root` entry committing
   `mnr/sparkle-root/v1\n<probe_count>\n<merkle_root>`, where the root is a Merkle
   tree over the fragment hashes taken in probe-id order.

The ledger stores only the SHA-256 fingerprint of each payload, but because the
payloads are fully determined by the probe directories, a verifier can rebuild
them. `mnr sparkle verify` does that: it re-verifies every probe ledger (chain
**and** anchor, refusing unsealed fragments), recomputes the fragment hashes and
the root, and compares the fingerprint of each rebuilt payload against the sealed
aggregate chain. It exits nonzero on any disagreement.

Consequences:

- Swapping a probe for a *different but internally valid* sealed ledger is caught,
  because the committed fragment hash belongs to the original probe.
- Deleting a probe, adding an entry, or rewriting the root is caught by count,
  ordering and hash comparison.
- `aggregate-root.json` is an export copy for publishing the root. Verification
  never reads it; a mismatch is reported as a warning, never trusted.
- The root commits to fragment hashes, not to probe plaintext, and verification
  needs the probe directories: this is a local audit, not a compact proof that a
  third party can check from the root alone.

## 9. Status and known gaps

Architecture-level gaps that the code does not close (the behavioural ones are
listed in [README](README.md#what-this-does-not-show)):

- `Observer::run` neither consults the reaper nor emits friction; it is a
  convenience loop for tests and simple callers.
- `mnr-sim` depends on `mnr-observer` for `Message` and the friction parser, so
  the wire format lives in the reasoning crate rather than in a protocol crate.
- No crash-recovery path: an interrupted run is left unsealed by design.
- Aggregation verification is local: it needs the probe ledgers, so it cannot be
  handed to a third party as a standalone proof.
