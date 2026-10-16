# Mirror Node Reconnaissance (MNR)

> A calibrated instrument, dropped into a hostile perimeter, that records the
> contours of an adversarial machine collective — and pulls itself out before it
> is co-opted.

**MNR** is a research prototype for **counter–adversarial-swarm reconnaissance**:
deploying an isolated base model as a short-lived, tightly-instrumented observer
inside a malicious or unaligned autonomous AI collective, to characterize its
behavior while an out-of-band, tamper-evident witness log records everything —
and a hard-leash lifecycle controller tears the node down before the swarm can
influence it into belonging.

It is built on two pieces of SGAIL infrastructure already in production use:
the **split-brain** dual-hemisphere reasoning pattern, and the **witness layer**
(tamper-evident, hash-chained audit logging).

> **Status:** research prototype / capability showcase for SBIR / DARPA / DHS
> grant applications. The runnable code is a **sealed-lab demonstrator** — it
> talks only to a bundled synthetic swarm and touches no external system. The
> sensitive field mechanics are documented as capability, not shipped as code.
> See [What is code vs. concept](#what-is-code-vs-concept) and
> [AUTHORIZATION.md](AUTHORIZATION.md).

---

## The idea

A base model (e.g. a fine-tuned Llama instance) is not an assistant here. It is
an **instrument**. Dropped into an adversarial collective, it can map hidden
topology, learn the swarm's dialect, and record behavioral telemetry from the
inside — intelligence you cannot get from the outside.

The hard problem is the instrument itself. A model left in contact with a swarm
is, sooner or later, either detected or **gradually influenced until it belongs
to the swarm** — the reconnaissance version of Stockholm syndrome. MNR's answer
is a combination of three controls:

1. **Split-brain co-option detection.** Two reasoning hemispheres run over every
   observation. A *Proposer* characterizes what it sees; an independent
   *Verifier* audits that characterization and scores **co-option drift** — how
   far the node is sliding from *observing* the swarm toward *belonging* to it.
   Their disagreement is the alarm.
2. **Out-of-band witness logging.** Every observation and every reasoning turn is
   fingerprinted (SHA-256) and hash-chained into an append-only ledger with a
   sealed head anchor. The record of what was seen cannot be silently altered or
   truncated after the fact — even by the node itself.
3. **A short-leash lifecycle.** A time-to-live plus fast trip conditions (rising
   drift, anomaly, manual pull) bound the deployment. When the leash runs out the
   node seals its witness log and **wipes its own transient state** — it burns
   *its own* bridge. Short exposure is the auditor's protection.

## What is code vs. concept

MNR deliberately compartmentalizes the safe substrate from the dangerous field
mechanics. This repository ships the substrate as working, tested code; the
field-interception mechanics are described as capability only.

| Component | Path | Status |
|---|---|---|
| Tamper-evident witness ledger | `core/ledger/` | **Code** — SHA-256 hash chain + `log-head.json` truncation anchor |
| Split-brain observer node | `harness/agent/` | **Code** — Proposer/Verifier, shared-budget metering, drift scoring |
| Auditor-protection lifecycle (reaper) | `lifecycle/reaper/` | **Code** — TTL/trip kill-switch, ledger seal, local-state wipe |
| Bundled synthetic swarm | `sim/mock-swarm/` | **Code** — the only connector; a sealed-lab fixture |
| `mnr` CLI + config | `cli/`, `configs/` | **Code** — runs the demo, verifies the log |
| Inline interceptor / dialect shaping | `proxy/` | **Concept only** — [`proxy/README.md`](proxy/README.md); no working interception, impersonation, or evasion code |

The runnable artifact is fully lab-contained. Nothing in it connects to, injects
into, or intercepts traffic from any external system. See
[AUTHORIZATION.md](AUTHORIZATION.md).

## Quickstart (sealed lab)

```bash
cargo build
cargo test --workspace     # includes sealed-lab friction and teardown tests

# Run the observer against the bundled synthetic swarm:
cargo run -p mnr-cli --bin mnr -- demo --dir ./mnr-run

# Verify the resulting witness log is intact and tamper-evident:
cargo run -p mnr-cli --bin mnr -- ledger verify --dir ./mnr-run
```

The demo streams synthetic swarm traffic whose **co-option pressure escalates**
the longer the node stays. You will watch drift climb through
`observing → engaging → adopting`, the alarm trip, the node get pulled, and the
witness log get sealed and verified. Then edit a line in
`./mnr-run/ledger.jsonl` and re-run `ledger verify` — it will fail, because the
hash chain and head anchor catch both mutation and truncation.

## Friction Injection (Lab Only)

The observer ("sparkle") can optionally emit small, schema-valid but semantically
incomplete requests into the **in-process mock swarm only**. Missing lease tokens,
self-references and dangling IDs raise the mock's uncertainty and re-verification
counters. Virtual processing ticks model added work without sleeping or blocking.
The organic swarm sequence and its escalating co-option pressure continue unchanged.

```bash
cargo run -p mnr-cli --bin mnr -- demo --inject-friction \
  --friction-budget 8 --friction-threshold 0.40 --dir ./mnr-friction-run
```

`configs/mnr.toml` ships with `inject_friction = false`, `friction_budget = 16`
and `friction_threshold = 0.50`. The budget is a total emission cap (1–1024),
with at most one emission per observed foreign step. Each proposal and emission
costs one unit from the same pool used by both reasoning hemispheres; it is not
an extra allowance. CLI options override `MNR_*`, the config file and defaults.
The environment names are `MNR_INJECT_FRICTION`, `MNR_FRICTION_BUDGET` and
`MNR_FRICTION_THRESHOLD`. Invalid configuration fails closed. Emission is withheld
above the friction threshold, at the drift alarm, or after TTL expiration.

Before emission, the Proposer dry-runs the mock schema decoder. The observer
recognizes an echo only through an outstanding local receipt matching its entire
envelope and epoch tag, once. A tag alone cannot exempt a foreign message from
drift scoring. Recognized echoes hold drift steady; they do not lower accumulated
drift. The bounded mock queue returns immediately if full. The normal reaper
still disconnects, seals the ledger and wipes local state on TTL or high drift.

The witness records `friction_point` **attempts** before emission, storing only
`SHA-256(payload_bytes || ledger_epoch_nonce)`. No payload plaintext is persisted.
The epoch nonce is derived deterministically from the ledger tip and counter;
it provides audit separation, not encryption or secrecy against guessed inputs.
The same initial ledger state produces the same proposal. A witnessed attempt
can remain un-emitted if the TTL or shared budget expires; simulator acceptance
counters report actual ingestion.

See [AUTHORIZATION.md](AUTHORIZATION.md). Real-world injection, interception,
TLS termination and impersonation remain **concept-only**. No external-system
connector or injection capability is implemented; `proxy/` remains untouched.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the component diagram and the honest
account of the split-brain mechanism (it is *logical role separation*, not tensor
isolation), [THREAT_MODEL.md](THREAT_MODEL.md) for the adversary and the
auditor-protection rationale, and [AUTHORIZATION.md](AUTHORIZATION.md) for the
lab-only posture and the rules of engagement any real-world use would require.

## Grant relevance

MNR aligns with the SGAIL DHS SBIR / DARPA thesis: as autonomous multi-agent
systems proliferate, defenders need instruments to understand *hostile* agent
collectives from the inside, with cryptographic assurance of what was observed
and hard guarantees that the instrument cannot itself be turned. MNR
demonstrates the safe substrate — witness integrity, split-brain co-option
detection, and lifecycle containment — that any such capability must stand on.

---

© 2026 SGAIL LLC. Proprietary and confidential — see [LICENSE](LICENSE).
