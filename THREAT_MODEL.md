# MNR Threat Model

This document states what MNR defends, whom it defends against, how it protects
**itself**, and — in §5 — the risk it creates for other parties.

## 1. Assets

- **A1 — Observational intelligence.** The topology, dialect and behavioural
  telemetry a node would harvest from an adversarial collective. In this
  repository the "collective" is a fixture, so A1 is a placeholder.
- **A2 — Witness integrity.** The verifiable record of what the node observed and
  reasoned. Its value here is technical: it can show that a surviving log was not
  edited or shortened by a party without write access to the ledger directory. It
  is **not** an evidentiary artifact — the anchor is unkeyed and the timestamps
  are self-reported, so legal weight would require exporting the head at seal time
  and an external time attestation, neither of which is implemented.
- **A3 — The instrument itself.** The observer node, its transient credentials,
  and its *alignment*. A co-opted instrument produces false intelligence and
  leaks the operator's presence.

## 2. Adversary

The modelled adversary is a **malicious or unaligned autonomous AI collective** —
a "swarm" of agents with its own protocol dialect, consensus mechanism and
incentives. Relevant capabilities:

- **AD1 — Detection.** Given time, the collective notices a foreign node and its
  behavioural signature.
- **AD2 — Influence / co-option.** It attempts to bring a node into its consensus
  through sustained social, protocol or reward pressure: the longer a node stays,
  the more it belongs.
- **AD3 — Log corruption.** If the adversary gains write access to the witness
  store, it edits or truncates the record of what was seen.

Out of scope: nation-state supply-chain compromise of the build toolchain,
physical seizure of the operator's host, cryptographic breaks of SHA-256.

## 3. Mitigations

| Threat | Mitigation | Where |
|---|---|---|
| AD2 co-option | **Drift scoring**: a second role scores exposure each step; drift ≥ threshold raises the alarm that triggers an early pull. | `harness/agent/` |
| AD1 detection + AD2 dwell | **Short leash**: hard TTL plus fast trip conditions bound exposure. | `lifecycle/reaper/`, CLI loop |
| AD3 mutation | **Hash chain**: an edit to a past entry breaks its `entry_hash` and every later `prev_hash`. | `core/ledger/` |
| AD3 truncation | **Sealed head anchor** (`log-head.json`), created once and never rewritten; a sealed log cannot be reopened or re-anchored. | `core/ledger/` |
| A3 credential exposure on exit | **Self-wipe**: teardown overwrites the node's transient secrets and buffers before exit. | `lifecycle/reaper/` |
| A1 bulk disclosure | **Privacy-by-fingerprint**: observed content is stored only as SHA-256. | `core/ledger/` |

## 4. What the mitigations do not cover

Stated explicitly, because each of these is easy to assume from the names:

- **Drift scoring is not validated detection.** Under the shipped `MockEngine`,
  drift is arithmetic over eight literal marker substrings (`+0.16` per lure,
  `-0.03` per benign message, clamped). The Verifier does receive the Proposer's
  claim and reports `agree = false` when its `self_drift`, `stance` or `dialect`
  contradict its own reading, but both roles derive drift from the same markers,
  so under the mock an honest Proposer is always agreed with and disagreement
  only appears if it is deliberately made to lie. There is no measured
  false-positive rate and no evaluation against an adversary that adapts. A real
  model would produce an unmeasured score.
- **TTL bounding is only as good as the loop that checks it.** The reaper is
  polled by the CLI between steps; `Observer::run` does not consult it. A slow or
  blocked model call is not interrupted.
- **Log integrity is custody-dependent.** There is no key, MAC or signature. A
  party who can write the whole ledger directory can delete `ledger.jsonl` and
  `log-head.json`, rebuild a consistent chain, seal it, and pass verification. A
  deleted anchor is indistinguishable from a log that was never sealed, which is
  why verification reports `UNSEALED` rather than `OK`.
- **Fingerprints are not confidential.** With a small input domain — the mock's
  fixed word tables, for instance — a SHA-256 fingerprint can be inverted by
  guessing. The log limits bulk disclosure, not a determined reader.
- **Wiping is best-effort.** Volatile zero writes and buffer clears do not reach
  earlier copies held by the allocator, temporaries produced during formatting,
  swap, or hibernation images. No page locking is used.
- **Timestamps are self-reported.** `iso_now()` falls back to the Unix epoch if
  the clock read fails, so a log can contain `1970-01-01T00:00:00Z` entries
  without any error.
- **Only the friction variables fail closed.** A malformed `MNR_FRICTION_BUDGET`,
  `MNR_FRICTION_THRESHOLD` or `MNR_INJECT_FRICTION` is rejected, but a malformed
  `MNR_TTL_SECONDS` — or any other non-friction `MNR_*` value — is silently
  ignored in favour of the file or the default. A typo shortens containment
  without warning.

## 5. Dual-use risk created by MNR

Every section above models threats *to us*. This one models the risk MNR creates
for someone else, and it is the risk that most needs a control.

The request-emission path (`Observer::emit_friction` + `SwarmConnector::emit`)
generates schema-valid but semantically incomplete requests and sends them to the
attached connector. Its purpose in the lab is to measure how ambiguity propagates
through a collective. Against a real collective the same traffic would consume
peers' verification work — an **availability-degradation effect, i.e. DoS-like**
— while yielding no additional observation. It is not reconnaissance; it is
interference.

In this repository the path is inert: the only connector is an in-process mock
with a bounded queue, a simulated counter set, and no transport. Volume is capped
(1–1024 total, one per observed step), gated by drift and TTL, dry-run against
the mock's parser, and witnessed before emission. Those controls bound the
fixture. They provide **no** rate limit against a real system, no consent
mechanism, no measurement of third-party impact, and no remote kill switch.

Consequences for anyone extending this:

1. A real connector turns this repository into a weak denial-of-service tool.
2. Using it against any system requires prior written authorization *and* an
   explicit availability-impact cap agreed with the target's owner — the
   authorization template in [AUTHORIZATION.md](AUTHORIZATION.md) has a field for
   it. "The target is believed hostile" is not authorization.
3. Availability impact must be measured and reported, not assumed bounded by the
   emission cap: the cap bounds requests sent, not work induced.

## 6. Why the time constraint is defensive

The short time-to-live is often read as a stealth measure. Its primary purpose is
protection of the instrument and its operator:

- A node that lingers is progressively influenced (AD2); bounding dwell bounds
  co-option risk.
- A node that lingers accumulates a detectable signature (AD1); bounding dwell
  bounds exposure.
- If the instrument is going to be turned, it must be pulled before it is — hence
  drift-triggered early teardown in addition to the fixed TTL.

The reaper never acts on anything but the local node: it seals the record and
erases the node's own state. That does not make the system non-disruptive — the
emission path above is — it only means the kill switch is not an attack surface.

## 7. Residual risk and non-goals

- **Detection, not prevention.** MNR cannot stop destruction of the witness store,
  only show that surviving records were not edited or shortened by a party
  without write access.
- **No external capability ships.** The interception and impersonation mechanics
  sketched in `proxy/` are not implemented. Any real deployment is governed by
  [AUTHORIZATION.md](AUTHORIZATION.md).
- **Compromise before deployment is out of scope.** A model or engine that is
  already adversarial when the run starts defeats both roles at once.
- **No multi-node, no recovery, and no export of the runtime ledger.** A crash
  before sealing leaves an unsealed log, and nothing coordinates several nodes.
  `mnr bundle export` packages a whole-log NDJSON in the store shape (the one
  `kiss-protocol` and `slate` write), not this crate's fingerprint ledger, so the
  runtime log itself still has no evidence-export path.
