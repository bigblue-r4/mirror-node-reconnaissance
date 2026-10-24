# Mirror Node Reconnaissance (MNR)

> A short-lived instrument for observing an adversarial agent collective from the
> inside — with a tamper-evident record of what it saw, and a lifecycle that
> pulls it out before it can be co-opted.

MNR is a Rust workspace exploring one question: **can you instrument an untrusted
multi-agent collective from the inside and still trust what you learned?** The
shipped code is a sealed lab in which a simulated observer reads synthetic swarm
traffic, scores its own exposure, writes a hash-chained witness log, and tears
itself down when its lease expires.

It is deliberately small: four library crates and one CLI, no network code, no
model backend. Everything runs in-process against a bundled mock.

> **Status: early-stage research prototype (roughly TRL 3–4).** Lab-validated
> components, not an integrated capability. Nothing here connects to an external
> system, and the central control — co-option detection — is demonstrated only
> against the bundle's own deterministic stand-in for a model. Read
> [What this does not show](#what-this-does-not-show) before citing any result,
> and [Dual use and misuse risk](#dual-use-and-misuse-risk) before shipping it
> anywhere.

---

## What the code does

Three mechanisms, each bounded and testable in isolation:

1. **A witness log.** Every observed message and every model turn is reduced to a
   SHA-256 fingerprint and hash-chained into an append-only JSONL file, then
   closed by a create-once head anchor. Edits and truncation are detectable by
   anyone who cannot write the ledger directory; a sealed log cannot be reopened,
   extended or re-anchored. The guarantee is conditional and narrow — see
   [Trust boundary of the witness log](#trust-boundary-of-the-witness-log).
2. **An observer with two reasoning roles.** Each message is characterized by a
   *Proposer* role and independently scored by a *Verifier* role, which produces
   the authoritative **co-option drift** value. Both roles draw on one shared,
   capped call budget, so a two-role run cannot buy itself extra calls. In the
   demo both roles are backed by the same deterministic `MockEngine`: separate
   prompts, same model call function, and drift computed from a fixed marker
   list. That is a mechanism demonstration, not evidence of detection.
3. **A lifecycle controller.** A time-to-live plus trip conditions (drift,
   anomaly, manual pull) bound a run. On a trip, the ledger is sealed and the
   node's own transient secrets and buffers are overwritten. The reaper acts on
   the local node only; it has no code path that touches anything else.

## What is code vs. concept

| Component | Path | Status |
|---|---|---|
| Witness ledger | `core/ledger/` | **Code** — SHA-256 chain, create-once `log-head.json` anchor, CLI verification |
| Observer (Proposer/Verifier roles) | `harness/agent/` | **Code** — shared budget metering, drift scoring, per-step witnessing |
| Lifecycle controller (reaper) | `lifecycle/reaper/` | **Code** — TTL/trip checks, seal-then-wipe, best-effort volatile zeroing |
| Bundled synthetic swarm | `sim/mock-swarm/` | **Code** — the only connector; a lab fixture with simulated counters |
| CLI and configuration | `cli/`, `configs/` | **Code** — `demo`, `sparkle`, `ledger verify`, `ledger show` |
| Lab-only request emission ("friction") | `harness/agent/` | **Code, off by default** — mock connector only; dual-use, see below |
| A model backend | — | **Not included** — the `Engine` trait is the seam; `MockEngine` ships |
| A real swarm connector | — | **Not included** — `SwarmConnector` has exactly one implementation |
| Interception / dialect shaping | `proxy/` | **Concept only** — [`proxy/README.md`](proxy/README.md), no working code |

## Dual use and misuse risk

Most of this repository is defensive substrate: an audit log, a role-separated
observer, a kill switch. One component is not, and it deserves to be named
plainly rather than buried.

**The dual-use part is request emission** (`Observer::emit_friction` with
`SwarmConnector::emit`). It generates schema-valid but semantically incomplete
requests — a lease with no token, a self-reference, a dangling identifier — and
sends them to whatever connector is attached. The intent in the lab is to
measure how a collective reacts to ambiguity. Pointed at a real collective, the
same code would consume peers' verification work: an **availability-degradation
effect, i.e. DoS-like, not reconnaissance**. It does not observe more; it makes
the target do more work.

What the shipped code actually contains:

- The only connector is the in-process mock (`sim/mock-swarm/`), so the emission
  path terminates in a queue and a counter. There is no transport.
- Volume is bounded: total emissions capped at 1–1024, at most one per observed
  step, suspended above a configured drift threshold, and suspended after TTL.
- Each attempt is witnessed before emission, dry-run through the parser the mock
  would use, and charged against the same call budget as reasoning.

What those controls do **not** provide: any measurement of impact on a real
target, any rate limit expressed against a real system, any consent or
authorization mechanism, and any remote kill switch. They bound the lab fixture,
not a deployment.

If a real connector were written, this repository would be a weak
denial-of-service tool, and its use would require a specific authorized,
consented engagement with an explicit availability-impact cap — not merely
"the target is hostile". That is also why `proxy/` is a written problem statement
with no implementation. Report misuse as described in
[Reporting](#reporting).

## Quickstart (sealed lab)

```bash
cargo build
cargo test --workspace     # 36 tests: ledger, observer, reaper, sim, CLI

# Run the observer against the bundled synthetic swarm:
cargo run -p mnr-cli --bin mnr -- demo --dir ./mnr-run

# Verify the resulting witness log:
cargo run -p mnr-cli --bin mnr -- ledger verify --dir ./mnr-run
```

The demo streams synthetic traffic whose lure pressure escalates with dwell time.
Drift rises through `observing → engaging → adopting`, the threshold trips, the
node is pulled, and the log is sealed and verified. Two tampering experiments,
each from a fresh run:

```bash
# Mutation is detected (perl -pi is portable across GNU and BSD userlands).
cargo run -p mnr-cli --bin mnr -- demo --dir ./mnr-mutate
perl -pi -e 's/"kind":"observation"/"kind":"modelled"/ if $. == 1' ./mnr-mutate/ledger.jsonl
cargo run -p mnr-cli --bin mnr -- ledger verify --dir ./mnr-mutate   # exits 1

# Truncation is detected, and cannot be re-anchored.
cargo run -p mnr-cli --bin mnr -- demo --dir ./mnr-truncate
head -n 3 ./mnr-truncate/ledger.jsonl > /tmp/short \
  && mv /tmp/short ./mnr-truncate/ledger.jsonl
cargo run -p mnr-cli --bin mnr -- demo --dir ./mnr-truncate          # exits 1
```

**A sealed log is final**, so use a fresh `--dir` for each run; re-running the
demo against a sealed directory exits 1 by design. Deleting the anchor is
reported as `UNSEALED` rather than `OK`, because a missing anchor is
indistinguishable from a log that was never sealed.

Multi-probe runs seal one ledger per probe and commit their aggregation to a
second ledger. Verification recomputes that aggregation from the probe ledgers:

```bash
cargo run -p mnr-cli --bin mnr -- sparkle --probes 4 --dir ./sparkle-run
cargo run -p mnr-cli --bin mnr -- sparkle verify --dir ./sparkle-run   # exits 0
```

`sparkle verify` exits nonzero if a probe ledger fails or is unsealed, a probe was
swapped for a different (even internally valid) ledger, the aggregate chain was
edited, or the committed root disagrees with the recomputed one.

## Trust boundary of the witness log

The ledger detects tampering; it does not prevent it, and its guarantee is
narrower than "tamper-proof".

- **What is detected.** Any edit to a past entry (the hash chain breaks), any
  truncation of trailing entries (the recomputed tail disagrees with the anchor),
  and any attempt to extend and re-anchor a sealed log (`open()` refuses a sealed
  directory; `seal()` never rewrites an existing anchor).
- **Who it holds against.** A party who can read the ledger but cannot write the
  ledger directory — including the observer node once it has been pulled, since a
  sealed log is closed to it.
- **What it cannot do.** There is no key, MAC or signature: only SHA-256. Anyone
  who can write the whole directory can delete `ledger.jsonl` and
  `log-head.json`, rebuild a consistent chain, seal it, and pass verification.
- **What evidentiary use would need.** The head hash has to leave the node: copy
  it into separate custody at seal time (a timestamp authority, a co-signing
  party, or a ticket). The repository does not implement that step, and the
  timestamps inside the log are self-reported wall-clock values, so nothing here
  is a trusted timestamp or a legal artifact.
- **What is not secret.** Payloads are stored as SHA-256 fingerprints. With a
  small input domain — the mock's six- and five-entry word tables, for instance —
  a fingerprint can be inverted by guessing.

## What this does not show

These are the claims the code cannot support yet, listed so nobody has to
discover them the hard way.

- **Drift scoring is not validated detection.** Under `MockEngine`, drift is
  arithmetic over eight literal marker substrings: `+0.16` when a message
  contains one, `-0.03` otherwise, clamped to `0..1`. There is no evaluation, no
  baseline, no false-positive measurement, and no adversary that knows it is
  being observed. A real model would produce a different — and unmeasured —
  score.
- **The Verifier does not see the Proposer's output.** Both roles receive the
  message and the prior drift; the Verifier scores the message independently.
  The "audit the proposer's characterization" instruction exists in the system
  prompt, but the Proposer's answer is not passed in. The roles are separated;
  the audit chain is not yet closed. Under the mock, both roles also land on the
  same number, so "their disagreement is the alarm" is not implemented — the
  alarm is drift crossing the threshold.
- **The friction effect is simulated.** Uncertainty, re-verification and
  "virtual processing ticks" are counters incremented by the mock. Nothing
  measures wall-clock, economic or availability cost on a real system.
- **Aggregation verification is local, not a portable proof.**
  `mnr sparkle verify` recomputes every fragment hash and the Merkle root from the
  probe ledgers and checks them against the sealed aggregate chain, so a swapped
  probe, a deleted probe, an edited chain or a rewritten root is caught. But a
  third party still needs the whole probe directory tree, and the root commits to
  fragment hashes rather than to the probes' plaintext.
- **Only the friction variables fail closed.** A malformed
  `MNR_FRICTION_BUDGET`, `MNR_FRICTION_THRESHOLD` or `MNR_INJECT_FRICTION` is an
  error, but a malformed `MNR_TTL_SECONDS` (or any other non-friction `MNR_*`
  value) is silently ignored in favour of the file or the default. A typo in the
  TTL therefore shortens containment without warning.
- **`Observer::run` ignores the leash.** The convenience loop does not consult
  the reaper and does not emit friction; TTL enforcement and emission live in the
  CLI's own loop. Use `step()` plus your own loop if you need both.
- **Wiping is best-effort.** `Secret` and `NodeState` overwrite their buffers
  with volatile writes and clear them. Copies made earlier — reallocation during
  construction, `format!` temporaries, the allocator itself, swap or hibernation
  — are outside their reach. The crate comment already notes that `zeroize` would
  be the stronger choice.
- **An interrupted run is unsealed.** Entries and the anchor are fsynced, but a
  crash before sealing leaves a chain that verifies only as `UNSEALED`, and the
  directory entry itself is not fsynced.
- **It is a single-process demo.** No multi-node coordination, no scheduling, no
  evidence export, no model backend, no connector.

What would move these from "demonstrated mechanism" to "measured capability":
several model backends behind the same `Engine` trait, a scoring function
evaluated against an adversary that knows it is observed, false-positive cost
measured at fixed TTL, and a single-role baseline to show the second role earns
its budget.

## Friction injection (lab only)

Off by default; the default `configs/mnr.toml` has `inject_friction = false`.

```bash
cargo run -p mnr-cli --bin mnr -- demo --inject-friction \
  --friction-budget 8 --friction-threshold 0.40 --dir ./mnr-friction-run
```

Each attempt charges one Proposer call, is dry-run through the mock's strict
decoder, is witnessed as a `friction_point` before emission, then charges one
emission from the same shared pool. The mock queues it, bumps its uncertainty and
re-verification counters, and echoes it back; the observer recognises its own echo
only through an outstanding local receipt matching the entire envelope and epoch,
once. Replays and altered bodies take the normal scoring path. The queue and
receipt window each hold at most 32 messages, and a full queue returns
immediately instead of blocking.

The witness stores only `SHA-256(payload || epoch_nonce)`, where the nonce is
derived from the ledger tip and counter. That is audit separation, not secrecy:
it is public and reconstructible, so it does not protect payloads from guessing.

Volume and gating: total emissions capped at 1–1024, at most one per observed
step, suspended above the friction threshold, at the drift alarm, after TTL, or
when the receipt window is full. Budget exhaustion leaves a witnessed attempt
un-emitted. None of this bounds impact on a real target — see
[Dual use and misuse risk](#dual-use-and-misuse-risk).

## Architecture

[ARCHITECTURE.md](ARCHITECTURE.md) has the component diagram, the honest account
of the split-brain mechanism (logical role separation, not tensor isolation), the
ledger's exact preimage and seal rules, and the reaper's teardown order.
[THREAT_MODEL.md](THREAT_MODEL.md) states the adversary and what each mitigation
does and does not cover. [AUTHORIZATION.md](AUTHORIZATION.md) sets the lab-only
posture and the rules of engagement any real deployment would require.

## Design lineage

MNR draws on two patterns from SGAIL's other work: split-brain role separation
and witness-layer audit logging. This repository is a standalone prototype of
those patterns applied to reconnaissance. It does not claim that either component
is in production use, and no result here should be read as evidence about a
deployed system.

## Reporting

Report vulnerabilities or misuse through the repository's private reporting
(GitHub → **Security** → *Report a vulnerability*); there is no published email
address for this project. Do not open a public issue containing exploit detail.

---

© 2026 SGAIL LLC. See [LICENSE](LICENSE) and [AUTHORIZATION.md](AUTHORIZATION.md).
