# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `core/bundle/` and `mnr bundle keygen` / `mnr bundle export` — the producer and
  signer for `witness-bundle/2`, which until now existed as a schema and a
  verifier only. A BLAKE3 Merkle tree with leaf-first audit paths, the §4.3
  preimage built field by field rather than by serialising a struct, Ed25519 over
  the header and over `size ‖ root` for the node's head. Entry lines are carried
  byte for byte; a log with a sequence gap, a CRLF, or a header value containing
  a line break is refused instead of re-encoded, because a reformatted entry is
  a different leaf. Keys are 32-byte seeds in `0600` files, and an existing key
  or bundle is never overwritten. The first Rust-produced bundles are committed
  as verifier fixtures: over the same 12 entry lines a Go emitter used, the root,
  `sha256_chain` and all 12 proof paths are identical, and the independent
  Python verifier reports `VERIFIED` for that bundle and for a filtered
  case-scoped one. 20 crate tests and 2 CLI integration tests; the Python suite
  is now 49.
- `CONSOLIDATION.md` — a cross-repository decision document: the map of the
  witness-log implementations (including two vendored copies) and the
  applications built on them, an ordered proposal to extract one importable core
  and retire the duplicates, and the unresolved licensing question that blocks
  it. It records two findings outside this repository that motivate the
  proposal: the head field set that neither the MAC nor the signature covers, and
  a court-export implementation that exists twice in two repositories with
  different signed fields. Documentation only; no code change, and nothing in it
  has been executed.
- `EXTRACTION_PLAN.md` — the rehearsed P0-2 plan from `CONSOLIDATION.md`: the
  `witness` module layout, the pinned `go.mod`, the import rewrite and `go.mod`
  change for each of the three consumers, CI gates, rollback, and a rehearsal log.
  Documentation only; rehearsed in a scratch copy, not applied to any repository.
- `BUNDLE_SCHEMA.md` — the P0-3 schema decision: `witness-bundle/2`, one
  court-export format for the two forked implementations. States the exact signed
  preimage, the entry-as-line-bytes leaf rule, the log head plus per-entry
  inclusion proofs, an eight-step offline verification procedure, and the
  byte-level rule that verifies bundles already issued under the old format
  without re-signing them. Records six defects in the current format, each with
  the code that shows it, and the rehearsed evidence: bundles from both
  repositories verified by one verifier, and ten forged-but-signed controls each
  failing at the step that catches it. Documentation only; the format is proposed, not implemented.
- `tools/bundle-verify/` — an independent verifier for `witness-bundle/2` and
  for legacy v1 bundles, in Python with the standard library only, written from
  the schema rather than from the Go producers. BLAKE3 and Ed25519 are
  implemented locally so there is no dependency to share with the encoder. It
  verifies bundles written and signed by both current implementations, the v2
  shapes, and — in rehearsal — one bundle per log size from 1 to 8 records; it
  reports an unsigned v1 bundle as `UNAUTHENTICATED` (exit 3) rather than
  verified, and rejects forged-but-signed bundles at the step that catches each.
  49 tests, with the bundles kept as frozen vectors. It is a cross-check of an
  external format, not a component of this system, and it now checks two bundles
  written by the producer below.
- `mnr sparkle verify [--dir <path>]` — recomputes the aggregation from the probe
  ledgers and checks it against the sealed aggregate chain, exiting nonzero on
  any disagreement. `mnr sparkle` now runs the same verification and inherits its
  exit code.
- `VerifierContext` (observer) — the Verifier's prompt now carries the step
  state *and* the Proposer's characterization, with three tests: the claim
  reaches the Verifier, a downplaying Proposer is rejected while its `self_drift`
  is discarded, and benign traffic is audited as consistent.
- `Ledger::read_entries` — reads an on-disk ledger's entries after verifying the
  chain, so an offline verifier can re-derive committed values.
- Aggregate entries now commit the fragment hash and the Merkle root as
  domain-separated, versioned payloads (`sparkle-fragment`, `sparkle-root`), so a
  verifier can rebuild them from the probe directories.
- `scripts/ci/sparkle-tamper.sh`, run by a new `aggregation` CI job: it runs a
  sparkle aggregation, asserts the untouched run verifies, alters one byte of a
  probe ledger, and asserts verification then exits 1 and names that probe.

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
- **README repositioned around the witness log — the product — instead of the
  swarm lab.** It leads with what the log answers, then with the two deployments
  it was built for: a poultry house (restart catch-up, a silent-house alarm, a
  record that survives a claim) and a police evidence room (intake you can prove
  was not edited, and a bundle the other side can check offline). The lab is
  presented as the load on the log and the appendix, per P2-7 in
  `CONSOLIDATION.md`. Duplicated caveat prose is consolidated into one `Limits`
  section; nothing was dropped except repetition — the one item that had no home
  in `THREAT_MODEL.md` (only the friction variables fail closed) is stated there
  too. Measured verifier results and the `scope=log` rule found by building the
  verifier are now on the front page rather than buried in the appendix.
- **The Verifier now audits the Proposer instead of re-scoring the message.**
  `Observer::step` hands the Verifier a `VerifierContext` — the step state plus
  the Proposer's parsed view — and the mock Verifier's `agree` flag becomes a
  consistency check on `self_drift`, `stance` and `dialect` against its own
  reading, naming every field that failed in its note. The Verifier's `drift`
  remains the only authoritative score: the Proposer's `self_drift` never feeds
  the alarm. `mnr demo` prints the per-step audit verdict.
- `MockEngine` accepts either context shape, preferring `VerifierContext`, and
  reports a Proposer-less prompt as "no characterization supplied" rather than
  silently skipping the audit.
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
  production-use claim. ARCHITECTURE recorded that the Verifier role was not
  given the Proposer's output (since closed — see the first entry in this
  section), that `MockEngine` drift is marker arithmetic, that only the friction
  variables fail closed, and that the reaper does not touch the connector. THREAT_MODEL withdraws the evidentiary claim, scopes the drift
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
