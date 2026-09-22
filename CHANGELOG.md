# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-09-21

Initial build — a lab-contained showcase of counter–adversarial-swarm
reconnaissance built on SGAIL's split-brain and witness-layer tech.

### Added
- **`mnr-ledger`** (`core/ledger`) — out-of-band, tamper-evident witness log:
  SHA-256 hash chain plus a `log-head.json` truncation anchor. Stores
  fingerprints, never plaintext. `verify()` detects both mutation and
  truncation/extension.
- **`mnr-observer`** (`harness/agent`) — split-brain observer node: a Proposer
  characterizes swarm traffic while a Verifier independently scores co-option
  drift. Both hemispheres share one capped call budget (`MeteredEngine`). Ships
  a deterministic `MockEngine` so runs need no live backend.
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
- CI (`cargo fmt`, `build`, `test`, `clippy -D warnings`); 15 tests.

### Security
- The runnable artifact touches no external system; the sensitive field
  mechanics are documented, not implemented. Any real-world use is gated by
  `AUTHORIZATION.md`.

[Unreleased]: https://github.com/bigblue-r4/mirror-node-reconnaissance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bigblue-r4/mirror-node-reconnaissance/releases/tag/v0.1.0
