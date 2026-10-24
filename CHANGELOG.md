# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `mnr sparkle verify [--dir <path>]` — recomputes the aggregation from the probe
  ledgers and checks it against the sealed aggregate chain, exiting nonzero on
  any disagreement. `mnr sparkle` now runs the same verification and inherits its
  exit code.
- `Ledger::read_entries` — reads an on-disk ledger's entries after verifying the
  chain, so an offline verifier can re-derive committed values.
- Aggregate entries now commit the fragment hash and the Merkle root as
  domain-separated, versioned payloads (`sparkle-fragment`, `sparkle-root`), so a
  verifier can rebuild them from the probe directories.

### Fixed
- Sparkle verification previously trusted `aggregate-root.json`, which was not
  part of any sealed chain, and never recomputed the root. It now recomputes the
  fragment hashes and root from the probe ledgers and compares them against the
  sealed chain; the export copy is reported but never trusted.
- An unsealed probe ledger is refused during aggregation instead of being included
  as a fragment, and a failed seal now aborts the probe.
- Probe ordering for the Merkle root is by numeric probe id, not directory
  iteration order, so the root is reproducible.
- `hash_ledger_fragment` no longer concatenates the log and anchor without a
  separator (domain-separated and length-prefixed).
- Aggregate entries no longer carry self-reported run statistics (drift, steps,
  trip reason), which made them impossible to verify.
- **Witness-log integrity.** `Ledger::seal()` now creates `log-head.json` with
  `create_new` and never rewrites it, and `Ledger::open()` checks an existing
  anchor against the chain before appending, then refuses a sealed directory.
  Truncating a log and re-running the node no longer re-anchors the shortened
  chain. Entries are `sync_data`'d and the anchor is `sync_all`'d, so a durable
  anchor cannot outrun the log it describes.
- `mnr ledger verify` reports an unsealed log as `UNSEALED` and exits nonzero
  instead of printing `OK`; truncation is only detectable against an anchor.
- `kind` tags are restricted to `[A-Za-z0-9._-]{1,64}`, so a caller-supplied tag
  cannot break the newline-delimited hash preimage.

### Changed
- `sparkle::verify_sparkle_aggregation` returns a `VerifyReport` with an explicit
  `verified()` predicate and collected errors, instead of a `Result` whose caller
  ignored the flags.
- Aggregations produced before this change do not verify under it: the fragment
  hash layout and the committed payloads both changed.
- README, ARCHITECTURE and THREAT_MODEL now state the trust boundary of the
  witness log: detection rather than prevention, unkeyed anchor, dependent on
  custody of the ledger directory, and not a trusted timestamp. "Out-of-band"
  and "signed head anchor" are corrected to "separate from the reasoning path"
  and "sealed".
- **Documentation rewritten against the implementation.** README is restructured
  around what the code does, with a dual-use/misuse section and a "what this does
  not show" section, and drops the grant-showcase framing and the
  production-use claim. ARCHITECTURE now records that the Verifier role is not
  given the Proposer's output, that `MockEngine` drift is marker arithmetic, that
  only the friction variables fail closed, and that the reaper does not touch the
  connector. THREAT_MODEL withdraws the evidentiary claim, scopes the drift
  mitigation, and adds a dual-use risk section. AUTHORIZATION adds an
  availability-impact cap and the private reporting channel; `proxy/README.md`
  drops proposal framing and shows the current `SwarmConnector` signature.

## [0.1.0] — 2026-09-21

Initial build — a lab-contained showcase of counter–adversarial-swarm
reconnaissance built on SGAIL's split-brain and witness-layer tech.

### Added
- **`mnr-ledger`** (`core/ledger`) — tamper-evident witness log: SHA-256 hash
  chain plus a `log-head.json` anchor. Stores fingerprints, never plaintext.
  `verify()` detects mutation and truncation against the anchor.
- **`mnr-observer`** (`harness/agent`) — split-brain observer node: a Proposer
  characterizes swarm traffic while a Verifier independently scores co-option
  drift. Both roles share one capped call budget (`MeteredEngine`). Ships a
  deterministic `MockEngine` so runs need no live backend.
- **`mnr-reaper`** (`lifecycle/reaper`) — short-leash lifecycle: a TTL/trip
  kill-switch that seals the witness log and wipes the node's own secrets and
  buffers. Acts only on the local node.
- **`mnr-sim`** (`sim/mock-swarm`) — seeded synthetic swarm with escalating
  co-option lures; the only `SwarmConnector` shipped, keeping the system
  sealed-lab only.
- **`mnr` CLI** (`cli`) — `demo` and `ledger verify` subcommands, with layered
  `MNR_* → configs/mnr.toml → defaults` configuration.
- Documentation: `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`,
  `AUTHORIZATION.md`, and `proxy/README.md` (interception / dialect-shaping /
  evasion described as capability only — no working code).
- CI (`cargo fmt`, `build`, `test`, `clippy -D warnings`). The count in the
  original notes was stale; the workspace now runs 36 tests.

### Security
- The runnable artifact touches no external system; the sensitive field
  mechanics are documented, not implemented. Any real-world use is gated by
  `AUTHORIZATION.md`.

[Unreleased]: https://github.com/bigblue-r4/mirror-node-reconnaissance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bigblue-r4/mirror-node-reconnaissance/releases/tag/v0.1.0
