# Witness logging — MNR

> An append-only record of what a system saw and did, chained and sealed so that
> editing it afterwards is detectable — and exportable as a bundle a third party
> can check on their own machine, without trusting the one that wrote it.

Mirror Node Reconnaissance is a Rust workspace built around one component: **a
witness log that survives a dispute.** The log answers three questions:

| Question | Answer |
|---|---|
| Was this record edited after it was written? | A SHA-256 chain: an edit breaks its own `entry_hash` and every `prev_hash` after it |
| Was anything dropped off the end? | A create-once `log-head.json` anchor. A sealed log cannot be reopened, extended or re-anchored |
| Can a stranger check it? | `witness-bundle/2` — Ed25519 over a specified byte string, the node's signed head, one Merkle inclusion proof per entry — and a verifier that shares no code with the producers |

Payloads are never stored, only their SHA-256 fingerprints. What the log
therefore cannot do is in [Limits](#limits), at the same level of detail.

> **Status: early-stage (roughly TRL 3–4), and the product is the log, not the
> swarm.** This repository ships the log, the seal, the bundle format, an
> independent verifier, and a sealed lab that exercises all three under load.
> It does not sign entries in the runtime ledger — only the exported v2 bundle is
> signed — and it does not ship a producer for that bundle, a timestamp
> authority, or a network connector. Read [Limits](#limits) before quoting a
> result.

---

## Two deployments it was built for

The log is not a demo looking for a use. Two applications in this portfolio run
on it, and they pull in opposite directions: one is a building full of animals,
the other is a property room with a chain of custody.

### The farm — a poultry house that restarts, and the alarm at 03:00

A controller watches temperature, feed and water across a house of twenty
thousand birds. Two things go wrong that a witness log fixes:

- **The controller restarts.** When it comes back, the question is not "what does
  the dashboard say" but "what was recorded while it was down, and is the gap in
  the feed or in the record?" A chain sealed before the restart makes those two
  distinguishable, and a log that is already sealed cannot be quietly extended
  forward to hide the hole.
- **The house goes silent.** Ventilation fails, the birds stop moving, the
  alarm trips. Six weeks later, in a claim with an insurer or a buyer, the
  question is whether the alarm was raised then — or written into the record
  afterwards. A sealed head that left the building at the time is the difference
  between a story and a record.

What the deployment supplies: the sensor gateway that writes entries, the alarm
rule, and a custodian for the retained head. What the log supplies: the part of
the account nobody can renegotiate later. The poultry application itself lives
in `harborlight-poultry-demo` (its `internal/farm` package), not in this
repository.

### The evidence room — intake a clerk can defend

An item is booked, moved, released, re-sealed. Each event is a line in the log.
Three questions come up, and a hash chain plus a signed bundle answers all three:

- **Was this item in the log?** A v2 bundle carries the node's signed head and a
  proof per entry, so a bundle can no longer be assembled from an unlogged draft
  slice and pass — which the current v1 format permits, because nothing in it
  ties the entries to the log.
- **Has anything changed since intake?** Any edit to a booked entry breaks the
  chain from that point on; removing trailing entries disagrees with the seal.
- **Can the other side check it themselves?** Yes: an offline verifier and two
  pinned public keys — the node that kept the log and the exporter that produced
  the bundle. No access to our systems, no trust in our dashboard.

Two police implementations already exist (`kiss-protocol`'s `cmd/witness-pd` and
`slate`) and they forked the same export file into two formats with different
signed fields. [BUNDLE_SCHEMA.md](BUNDLE_SCHEMA.md) is the one format that
replaces both; the verifier in [tools/bundle-verify/](tools/bundle-verify/README.md)
already checks bundles from each, so migrating records already issued does not
mean re-signing them.

Legal weight also needs a head retained outside the node at seal time (a
timestamp authority, a co-signing party, a ticket) and timestamps that are not
self-reported. Neither is implemented here; see [Limits](#limits).

## Try it now (sealed lab)

The lab is the load: a simulated observer reads synthetic swarm traffic, writes
every step to the log, and tears itself down when its lease expires.

```bash
cargo build
cargo test --workspace     # 47 tests: ledger, observer, reaper, sim, CLI

cargo run -p mnr-cli --bin mnr -- demo --dir ./mnr-run
cargo run -p mnr-cli --bin mnr -- ledger verify --dir ./mnr-run
```

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

**A sealed log is final**, so use a fresh `--dir` for each run; re-running against
a sealed directory exits 1 by design. Deleting the anchor is reported as
`UNSEALED` rather than `OK`, because a missing anchor is indistinguishable from a
log that was never sealed.

Multi-probe runs seal one ledger per probe and commit their aggregation to a
second ledger, which verification recomputes:

```bash
cargo run -p mnr-cli --bin mnr -- sparkle --probes 4 --dir ./sparkle-run
cargo run -p mnr-cli --bin mnr -- sparkle verify --dir ./sparkle-run   # exits 0
```

`sparkle verify` exits nonzero if a probe ledger fails or is unsealed, if a probe
was swapped for a different (internally valid) ledger, if the aggregate chain was
edited, or if the committed root disagrees with the recomputed one.

## Verification, measured

Third-party checking is the product, so it is stated as results rather than as
intent. The verifier is Python with no dependencies, written from the schema —
BLAKE3 and Ed25519 included — so it shares nothing with the Go encoders.

| Input | Result |
|---|---|
| Bundle issued by `kiss-protocol/internal/pd/export` (v1) | `VERIFIED` — 904 B, HTML-escaped payload bytes intact |
| Bundle issued by `slate/internal/export` (v1) | `VERIFIED` — 889 B, `prev_hash` + `agency`/`seal` |
| Zero-entry v1 bundle | `VERIFIED` — 419 B, the `"entries":null` rule reproduced from the spec |
| Unsigned v1 bundle | `UNAUTHENTICATED`, exit 3 — never `VERIFIED` |
| `witness-bundle/2`, `scope=case` / `scope=log` / 7-leaf | `VERIFIED` — 4,301 / 5,895 / 3,560 B |
| One bundle per log size 1…8 | All `VERIFIED`, with audit paths of 0–3 hashes |
| Forged-but-signed bundles, 10 controls | Each rejected at the step that should catch it — `inclusion`, `proofs`, `scope`, `head`, `preimage` — and two honest signed controls that must verify |

```bash
python3 -m unittest discover -s tools/bundle-verify     # 47 tests
python3 tools/bundle-verify/verify_bundle.py BUNDLE.ndjson --pin HEX [--pin HEX ...]
```

Building it changed the spec: `scope=log` originally said only "`case_number`
empty", which lets a bundle claim to be the whole log and ship a subset, because
every shipped entry's proof is genuine. Step 7 now also requires
`entry_count == log_head.size`. See [BUNDLE_SCHEMA.md](BUNDLE_SCHEMA.md) §4.7.
[`tools/bundle-verify/README.md`](tools/bundle-verify/README.md) has usage, exit
codes and the limits of what it can judge.

## Limits

The log detects tampering; it does not prevent it, and its guarantee is narrower
than "tamper-proof". This section is the short version of
[THREAT_MODEL.md](THREAT_MODEL.md) §4.

- **Custody-dependent.** There is no key, MAC or signature in the runtime ledger —
  only SHA-256. A party who can write the whole directory can delete
  `ledger.jsonl` and `log-head.json`, rebuild a consistent chain, seal it and pass
  verification. Exporting the head to separate custody at seal time is what would
  bind it; the repository does not do that step.
- **No trusted time.** Timestamps are self-reported wall-clock values, and
  `iso_now()` falls back to the Unix epoch if the clock read fails. Nothing here
  is a trusted timestamp or by itself a legal artifact.
- **Fingerprints are not confidential.** With a small input domain a SHA-256
  fingerprint can be inverted by guessing. The log limits bulk disclosure, not a
  determined reader.
- **A crash before sealing leaves `UNSEALED`.** Entries and the anchor are
  fsynced; the directory entry is not.
- **Wiping is best-effort.** Volatile zero writes miss allocator copies,
  `format!` temporaries, swap and hibernation images.
- **The new bundle format has no producer yet.** `witness-bundle/2` is a
  specification plus a verifier; the Go producers still write v1 and are being
  reconciled per [CONSOLIDATION.md](CONSOLIDATION.md).
- **Aggregation is local, not a portable proof.** `mnr sparkle verify` needs the
  whole probe directory tree, and the root commits to fragment hashes rather
  than to plaintext.
- **The lab's detection is not validated.** Under `MockEngine`, drift is
  arithmetic over eight literal marker substrings (`+0.16` per lure, `-0.03`
  otherwise, clamped). The Verifier does audit the Proposer's claim — a test
  feeds it a downplaying Proposer and it rejects the claim — but both roles
  derive drift from the same markers, so an honest mock Proposer always agrees,
  and there is no measured false-positive rate and no adversary that adapts. A
  real model would produce an unmeasured score.
- **`Observer::run` ignores the leash.** TTL enforcement and emission live in the
  CLI's loop; `run()` does not consult the reaper and does not emit friction.
- **Only the friction variables fail closed.** A malformed `MNR_FRICTION_BUDGET`,
  `MNR_FRICTION_THRESHOLD` or `MNR_INJECT_FRICTION` is an error, but a malformed
  `MNR_TTL_SECONDS` is silently ignored in favour of the file or the default — a
  typo shortens containment without warning.
- **Single process.** No multi-node coordination, no scheduling, no evidence
  export command, no model backend, no connector.

## Friction injection (lab only, off by default)

One component is not defensive substrate: request emission
(`Observer::emit_friction` + `SwarmConnector::emit`) generates schema-valid but
semantically incomplete requests and sends them to the attached connector. It is
not reconnaissance — against a real collective it consumes peers' verification
work, an **availability-degradation effect, i.e. DoS-like.** It ships inert: the
only connector is the in-process mock, volume is capped at 1–1024 and one per
observed step, gated by drift and TTL, dry-run against the mock's parser, and
witnessed before emission.

```bash
cargo run -p mnr-cli --bin mnr -- demo --inject-friction \
  --friction-budget 8 --friction-threshold 0.40 --dir ./mnr-friction-run
```

[THREAT_MODEL.md](THREAT_MODEL.md) §5 is the full account: what those bounds do
and do not cover, and why a real connector would require written authorization
with an agreed availability-impact cap. `proxy/` is a written problem statement
with no implementation for the same reason.

## Where the pieces live

| Component | Path | Status |
|---|---|---|
| Witness ledger | `core/ledger/` | **Code** — SHA-256 chain, create-once anchor, verification |
| Observer (Proposer/Verifier roles) | `harness/agent/` | **Code** — shared call budget, audited drift, per-step witnessing |
| Lifecycle controller (reaper) | `lifecycle/reaper/` | **Code** — TTL/trip checks, seal-then-wipe |
| Bundled synthetic swarm | `sim/mock-swarm/` | **Code** — the only connector; a lab fixture |
| CLI and configuration | `cli/`, `configs/` | **Code** — `demo`, `sparkle`, `ledger verify`, `ledger show` |
| Court-export format | `BUNDLE_SCHEMA.md` | **Specification** — proposed; v1 bundles still verify |
| Independent bundle verifier | `tools/bundle-verify/` | **Code** — Python, no dependencies, 47 tests |
| A model backend | — | **Not included** — the `Engine` trait is the seam |
| A real swarm connector | — | **Not included** — one implementation exists |
| Interception / dialect shaping | `proxy/` | **Concept only** — [`proxy/README.md`](proxy/README.md) |

[ARCHITECTURE.md](ARCHITECTURE.md) has the component diagram, the honest account
of the split-brain mechanism (logical role separation, not tensor isolation), the
ledger's exact preimage and seal rules, and the reaper's teardown order.

## Design lineage

MNR draws on two patterns from SGAIL's other work: split-brain role separation and
witness-layer audit logging. This repository is the Rust member of a family of
five implementations of the witness log — two of them vendored copies — and the
same pattern backs the farm and evidence-room applications. [CONSOLIDATION.md](CONSOLIDATION.md) maps them, argues for
one importable core, and records the unresolved licensing question that blocks
it. [EXTRACTION_PLAN.md](EXTRACTION_PLAN.md) is that proposal's first step worked
out to the command level, rehearsed but not applied.

Nothing in those documents has been executed, and no result here should be read
as evidence about a deployed system.

## Reporting

Report vulnerabilities or misuse through the repository's private reporting
(GitHub → **Security** → *Report a vulnerability*); there is no published email
address for this project. Do not open a public issue containing exploit detail.

---

© 2026 SGAIL LLC. See [LICENSE](LICENSE) and [AUTHORIZATION.md](AUTHORIZATION.md).
