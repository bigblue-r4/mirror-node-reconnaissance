# v0.2.0 — a log a stranger can check

Released 2026-10-26.

The witness log's on-disk format is unchanged. What this release adds is a way
for someone who does not trust us to check the record on their own machine, and a
hard stop on extending a log after it has been sealed.

`witness-bundle/2` is now **produced**, not just specified: a Rust crate and a
`slate` command write it, a Python verifier that shares no code with either one
checks it, and that verifier runs in CI rather than when someone remembers. The
log, the seal and the export are exercised by the same sealed lab as before.

## If you are upgrading

Three cases, in the order most people hit them. [UPGRADING.md](UPGRADING.md) has
the full detail and the transcripts behind every claim below.

### Your logs: nothing to do

The on-disk log is the same file, with the same entry fields and the same hash
preimage, and a log written by 0.1.0 verifies under 0.2.0 with the head hash it
was sealed at. There is no migration step, and a 0.1.0 `configs/mnr.toml` still
loads.

### A sealed log is now final — this is the one behaviour change

0.1.0 could be talked into reopening a sealed directory: it appended to the log
and overwrote `log-head.json`, so a second run re-anchored over the first and the
head hash from the first run stopped describing anything. 0.2.0 refuses instead,
and writes nothing:

```
ledger error: ledger is already sealed at 81 entries (head_seq=80, head_hash=54c2…); a sealed witness log is final — use a fresh directory
```

Reading is unaffected — `mnr ledger verify` and `mnr ledger show` still work on a
sealed directory. To keep recording, leave the sealed run as it is and point
`--dir` at a new one.

One thing this cannot retrofit: if a 0.1.0 directory of yours holds more entries
than its anchor counts, the anchor is the *most recent* write and nothing on disk
records what it replaced. Only a copy of the head taken out of the directory at
seal time can settle that.

### Aggregations: regenerate rather than re-verify

No released version produced an aggregation — 0.1.0's whole surface was `demo`,
`ledger verify` and `ledger show` — so nothing a release emitted is invalidated.

Aggregates from unreleased `main` commits of this development cycle do fail: the
fragment hash became length-prefixed and domain-separated, the committed
per-probe payload dropped self-reported run statistics, and the root moved from a
side file into the sealed chain. `mnr sparkle verify` names the situation instead
of printing a mismatch per probe:

```
  - aggregate is in the pre-0.2.0 layout: 2 fragment entries, no sparkle-root entry, and an exported root 6314d7bddf327f55… that matches the old fragment hash (sha256(ledger.jsonl + log-head.json)) — it predates the root being committed to the chain
```

Regenerate into a fresh `--dir`. A new aggregate also states which layout it is
in — a leading `sparkle-format` entry and `"format": "sparkle-aggregate/2"` in the
export copy — so the next change of this kind is identifiable by inspection
rather than by a failed verification.

### Bundles: nothing to re-sign

`core/bundle`, `witness-bundle/2` and the v1 exporters are all new here. Bundles
already issued by `slate` and `kiss-protocol` are v1 files in their own
repositories; the verifier still reads them, and `slate export --format 1` still
writes them.

## What is in it

- **A producer for the export format.** `mnr bundle keygen` and `mnr bundle
  export` write and sign `witness-bundle/2`: a BLAKE3 Merkle tree with leaf-first
  audit paths, the signed preimage built field by field, Ed25519 over the header
  and over `size ‖ root`. Entry lines are carried byte for byte — a sequence gap,
  a CRLF or a header value containing a line break is refused rather than
  re-encoded, because a reformatted entry is a different leaf. Keys are 32-byte
  seeds in `0600` files, and an existing key or bundle is never overwritten.
- **A verifier written from the schema, not from the code.** `tools/bundle-verify/`
  is Python with the standard library only — BLAKE3 and Ed25519 implemented
  locally — so there is no dependency to share with the encoder it checks. 50
  tests, with the bundles kept as frozen vectors. It runs in CI on every push.
- **A second producer, in a second language.** `tools/slate-v2-port/` ports the
  format behind `slate`'s own export command as a ready-to-apply patch: v2 by
  default, keys read from slate's store instead of minted, the shared fixtures in
  slate's test suite, and the 28 unchecked errors fixed so its lint gate passes.
  The patch is staged, not merged — a released `slate` still writes v1.
- **An aggregation that proves itself.** Sparkle verification recomputes the
  fragment hashes and the Merkle root from the probe ledgers and checks them
  against the sealed chain, instead of trusting the side file that carried the
  root. Aggregate entries commit only values a verifier can rebuild.
- **The witness-log integrity work.** `log-head.json` is created once and never
  rewritten, opening a sealed directory fails, entries are `sync_data`'d and the
  anchor `sync_all`'d so a durable anchor cannot outrun the log it describes, and
  `mnr ledger verify` reports a missing anchor as `UNSEALED` rather than `OK`.
- **Documentation you can act on.** [BUNDLE_SCHEMA.md](BUNDLE_SCHEMA.md) is the
  format, [UPGRADING.md](UPGRADING.md) is what changes for files you already have,
  and [CONSOLIDATION.md](CONSOLIDATION.md) / [EXTRACTION_PLAN.md](EXTRACTION_PLAN.md)
  record a cross-repository plan that is proposed and rehearsed, not executed.

## What this release does not claim

- **Detection, not prevention.** Anyone who can write to the ledger directory can
  still rewrite the whole log and re-seal it. The chain makes edits visible; it
  does not make them impossible.
- **No trusted timestamp.** A head is sealed, not timestamped. Anchoring it
  outside the node — an authority, a co-signing party, a ticket — is deployment
  work this release does not do, and without it, times in the log are
  self-reported.
- **Provenance needs the probes.** `mnr sparkle verify` is a local audit: it needs
  the probe directories, not just the aggregate, so it is not a compact proof a
  third party can check from a root alone.
- **Nothing is signed except exported bundles.** Entries in the runtime ledger are
  not signed; the signature belongs to the v2 bundle.
- **The lab is a lab.** The swarm is an in-process mock. Drift is marker
  arithmetic over synthetic traffic; nothing here measures real behaviour.

## Checking this release

```
cargo test --workspace                                    # 77 tests
python3 -m unittest discover -s tools/bundle-verify -t tools/bundle-verify
scripts/ci/sparkle-tamper.sh                              # aggregation, then a tampered probe
```

CI runs those same three checks. No GitHub Actions result is quoted above: the
numbers are from a local run, and a workflow run of this exact tag should be read
on its own.

Full list: [CHANGELOG.md](CHANGELOG.md). Trust boundary and limits:
[THREAT_MODEL.md](THREAT_MODEL.md), and the `Limits` section of the
[README](README.md).

---

Two commits landed on `main` after this tag — `mnr sparkle show`, and pinning the
Rust toolchain — and are recorded under `Unreleased` rather than folded into this
release.
