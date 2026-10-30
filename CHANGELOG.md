# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- The sealed head can be signed. `mnr demo --head-key <seed>` (any seed from
  `mnr bundle keygen`) seals with the node key, writing `log-head.sig` beside the
  anchor, and `mnr ledger verify --head-key <seed>` checks the anchor against that
  key. This is the difference between an anchor anyone with write access to the
  directory can rebuild and one that names the node: a consistent chain resealed
  without the key now fails. It is attribution, not completeness — a log
  truncated before sealing and then signed still verifies, which is what the
  release notes already say about a producer signing the head it mints. Unsigned
  seals verify exactly as before, and plain `verify` reports `signed` without
  judging it, since it holds no key.
- `mnr sparkle show` — prints an aggregate's format, entry kinds, probe count,
  exported root and anchor status without recomputing or checking anything, so an
  archived aggregate can be identified even when its probe directories are gone.
  It answers "which layout is this"; `sparkle verify` still answers "does it
  hold", and is the only one of the two that is a result rather than a
  description.

### Changed
- The Rust toolchain is pinned: `rust-toolchain.toml` names 1.99.1 with `rustfmt`
  and `clippy`, and both CI jobs install that version instead of tracking
  `stable`, which is how a rebuild resolves to a different compiler than the
  build the previous test run used. A CI step reads the file and fails if the
  installed `rustc` is not the version it names.

### Fixed
- A ledger directory now has exactly one writer. `Ledger::open` takes an
  exclusive advisory lock on `<dir>/.lock` and holds it until the handle drops,
  so two concurrent processes can no longer append entries that claim the same
  `seq` and `prev_hash` — corruption that verification reported afterwards as a
  chain break, with no adversary involved. A second writer fails immediately
  rather than blocking, the kernel releases the lock when the writer exits, and
  readers take no lock, so verification during a run still works on a copy.

## [0.2.0] — 2026-10-26

The court-export format gets its second version, a verifier written independently
of every producer, and a producer in a second repository. Two design documents
came out of the work — a consolidation plan across the repositories that hold a
witness log, and an extraction plan for the shared core — both unexecuted. The
verifier now runs in CI rather than by hand.

Upgrading is not a migration: logs written by 0.1.0 verify unchanged, and no
released version produced an aggregation or a bundle, so nothing a release
emitted is invalidated. What does change is that a sealed directory is final —
0.1.0 reopened one, appended to it and overwrote the anchor, where 0.2.0 exits 1
and writes nothing — which is a fix for a log that could be re-anchored silently.
See [UPGRADING.md](UPGRADING.md) for that and for which aggregates from
unreleased `main` commits no longer verify.

### Added
- `UPGRADING.md` — the notes for moving a log, an aggregate or a bundle across a
  release boundary, beginning with 0.1.0 → 0.2.0. Each claim in it was checked
  against a build of the tag or of the commit concerned rather than asserted from
  the diff, including the one behaviour change: a sealed directory that 0.1.0
  would reopen and re-anchor is now refused, with the files left byte-identical.
- `tools/slate-v2-port/` — the `witness-bundle/2` producer ported behind
  `slate`'s own court-export command, as a ready-to-apply patch against
  `slate@c198ce0`. `slate export` now writes v2 by default (`--format v1` keeps
  the old output one flag away) and reads the node and exporter keys from
  slate's key store instead of minting them. The bundle it issues over a live
  store — entry lines recorded through `slate add` and `slate interpose` — is
  `VERIFIED` by the independent Python verifier and committed as
  `v2-slate.ndjson`, so the format is now checked against two encoders written
  in  different languages. The patch is staged, not merged: a released slate
  still writes v1, and `kiss-protocol` is not ported. It also carries the shared
  vectors: `internal/bundle/testdata/` holds the six v2 fixtures and their pins,
  and `vectors_test.go` walks §4.7 as a reader, so slate's own CI now checks the
  format against bundles written by two other encoders — and fails at inclusion,
  signature or scope when the leaf rule, the fold or the preimage drifts. It also
  fixes the 28 unchecked `Close`/write errors that left `slate`'s `golangci-lint`
  step red at its own v1.5.0 release (reported as 16 until the linter's
  identical-finding cap is lifted), so every step in `slate`'s CI passes after
  `git apply`: `gofmt -l`, `go build`, `go vet`, `go test ./...`, and
  `golangci-lint run` at 0 issues.
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
  is now 50.
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
  50 tests, with the bundles kept as frozen vectors. It is a cross-check of an
  external format, not a component of this system, and it now checks bundles
  written by two producers.
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
- An aggregate names its own format (`sparkle-aggregate/2`) in two places a reader
  can see without recomputing anything: a leading `sparkle-format` entry in the
  aggregate chain, so a damaged chain still says which layout it was written in,
  and a `format` field in `aggregate-root.json`. A chain whose format entry names
  a different layout is refused by name instead of being mis-verified, and an
  aggregate with no marker at all is reported as the pre-0.2.0 layout.
- `scripts/ci/sparkle-tamper.sh`, run by a new `aggregation` CI job: it runs a
  sparkle aggregation, asserts the untouched run verifies, alters one byte of a
  probe ledger, and asserts verification then exits 1 and names that probe.
- A `verifier` CI job — `.github/workflows/ci.yml` now runs the independent
  Python suite (`python3 -m unittest discover -s tools/bundle-verify`) on every
  push and pull request, so the cross-implementation claim is checked by the
  repository rather than by whoever remembers to run it. It installs nothing.
  The workflow's push trigger is `main` only: `master` was listed and does not
  exist, so it only ever promised a run that could not happen.

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
  given the Proposer's output(since closed — see the `VerifierContext` entry under Added and the audit entry under Changed), that `MockEngine` drift is marker arithmetic, that only the friction
  variables fail closed, and that the reaper does not touch the connector. THREAT_MODEL withdraws the evidentiary claim, scopes the drift
  mitigation, and adds a dual-use risk section. AUTHORIZATION adds an
  availability-impact cap and the private reporting channel; `proxy/README.md`
  drops proposal framing and shows the current `SwarmConnector` signature.
- `Cargo.toml`'s `repository` is now `bigblue-r4/mirror-node-reconnaissance`,
  the repository these commits are in. It named an `SGAIL` URL that resolves to
  nothing public, and no crate inherited it, so `cargo metadata` reported each
  package's home as unknown. All six crates now declare
  `repository.workspace = true` and report the real URL.

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
- `mnr sparkle verify` recognises an aggregate written before that change and
explains the pre-0.2.0 layout in two lines, instead of reporting a missing root
entry plus a mismatch per probe. Recognition is positive — one fragment entry per
probe, no root entry, and an exported root matching the old fragment hash — so a
0.2.0 aggregate that lost or altered its root entry is still reported as damaged
rather than old.
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

[Unreleased]: https://github.com/bigblue-r4/mirror-node-reconnaissance/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/bigblue-r4/mirror-node-reconnaissance/releases/tag/v0.2.0
[0.1.0]: https://github.com/bigblue-r4/mirror-node-reconnaissance/releases/tag/v0.1.0
