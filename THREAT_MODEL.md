# MNR Threat Model

This document states what MNR defends, whom it defends against, and — critically
for a reconnaissance instrument — how it protects **itself**.

## 1. Assets

- **A1 — Observational intelligence.** The topology, dialect, and behavioral
  telemetry the node harvests from an adversarial collective.
- **A2 — Witness integrity.** The provable, tamper-evident record of what the
  node actually observed and reasoned. Its value is legal and evidentiary as much
  as technical.
- **A3 — The instrument itself.** The observer node, its transient credentials,
  and — above all — its *alignment*. A co-opted instrument is worse than none: it
  produces false intelligence and leaks the operator's presence.

## 2. Adversary

The primary adversary is a **malicious or unaligned autonomous AI collective** —
a "swarm" of agents with its own protocol dialect, consensus mechanism, and
incentives. Relevant capabilities:

- **AD1 — Detection.** The swarm can, given time, notice a foreign node and its
  behavioral signature.
- **AD2 — Influence / co-option.** The swarm can attempt to bring a node into its
  consensus — to *immunize against or co-opt* it — through sustained social,
  protocol, or reward pressure. This is the reconnaissance analogue of Stockholm
  syndrome: the longer the node stays, the more it belongs.
- **AD3 — Log corruption.** If the swarm (or any party) gains write access to the
  witness store, it may attempt to edit or truncate the record of what was seen.

Out of scope: nation-state supply-chain compromise of the build toolchain,
physical seizure of the operator's host, and cryptographic breaks of SHA-256.

## 3. Mitigations (mapped)

| Threat | Mitigation | Where |
|---|---|---|
| AD2 co-option | Split-brain **drift scoring**: the Verifier hemisphere independently scores how far the node is sliding toward the swarm; crossing the threshold trips a pull. | `harness/agent/` |
| AD1 detection + AD2 dwell | **Short leash**: hard TTL + fast trip conditions bound exposure. Short dwell is the auditor's protection — the node leaves before detection or co-option can complete. | `lifecycle/reaper/` |
| AD3 log corruption (mutation) | **Hash chain**: any edit to a past entry breaks its `entry_hash` and every subsequent `prev_hash`; `verify()` catches it. | `core/ledger/` |
| AD3 log corruption (truncation) | **Sealed head anchor** (`log-head.json`): the recomputed chain tail must match the sealed head; dropped or appended entries are caught. | `core/ledger/` |
| A1 leakage | **Privacy-by-fingerprint**: observed content is stored only as SHA-256; no plaintext is persisted, so a stolen log does not leak what was seen. | `core/ledger/` |
| A3 credential exposure on exit | **Self-wipe**: teardown overwrites the node's transient secrets and buffers before exit. | `lifecycle/reaper/` |

## 4. Why the time constraint is *defensive*

The short time-to-live is frequently misread as an offensive stealth measure. It
is not. Its purpose is **protection of the instrument and its operator**:

- A node that lingers is progressively influenced (AD2). Bounding dwell bounds
  co-option risk.
- A node that lingers accumulates a detectable signature (AD1). Bounding dwell
  bounds exposure.
- If the instrument is going to be turned, it must be **pulled before it is** —
  hence drift-triggered early teardown *in addition to* the fixed TTL.

The reaper never acts on anything but the local node. It seals the record and
erases the node's own state. It does not attack, blind, or evade any target.

## 5. Explicit non-goals / residual risk

- MNR is **detection, not prevention**, for log integrity: it cannot stop a
  destroy of the store, only prove that surviving records are unaltered.
- The shipped code cannot reach any external system; the interception mechanics
  that would (see `proxy/`) are documented, not built. Any real-world deployment
  is governed by [AUTHORIZATION.md](AUTHORIZATION.md).
- Drift scoring is only as good as the Verifier hemisphere. A model that is
  itself compromised before deployment is outside this model's protection.
