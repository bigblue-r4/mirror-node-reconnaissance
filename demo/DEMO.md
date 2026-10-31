# Real-world demo — an evidence room, and the edge of what it proves

`demo/run.sh` walks a custody log through the whole product the way a property
room would: record, export, hand over, and then every way someone tries to
change the story afterwards. Six acts, each ending in an exit-code assertion, so
the run proves its points instead of narrating them.

The records are fictional. The log format, the keys, the signatures, the
independent verifier and every failure below are the real binaries in this
repository — no mock verifier and no captured output.

```bash
cargo build -p mnr-cli
./demo/run.sh          # ~30 s, exit 0, artifacts kept in demo/out/
```

```bash
DEMO_SKIP_SPARKLE=1 ./demo/run.sh   # skip the aggregation act
DEMO_DIR=/tmp/mnr-demo ./demo/run.sh
```

`DEMO_DIR` is wiped and recreated. `demo/out/` is gitignored; its keys are
throwaway and must never be committed.

## What is real, what is not

| Part | Status |
|---|---|
| `witness-bundle/2` export, Ed25519 signing, Merkle proofs | Real — `mnr bundle export`, `core/bundle` |
| Independent verifier and its exit codes | Real — `tools/bundle-verify/`, Python, no dependencies |
| Ledger chain, seal, anchor, signed seal | Real — `mnr demo`, `mnr ledger verify` |
| Aggregation over probes | Real — `mnr sparkle`, then a one-byte probe tamper |
| Custody records, case numbers, item IDs, people | **Fictional** — `demo/scenario/evidence-room.ndjson` |
| Drift score, mock swarm | Lab fixture — marker arithmetic, not a model |
| A deployed evidence room, network, timestamp authority | **Not present** |

## The talk track

### 1. "Can the other side check it themselves?"

Twelve custody events, two cases. Export `--scope case`: nine entries disclosed,
each with an inclusion proof taken from the full twelve-leaf tree, plus the
node's signed head and the exporter's signature. The recipient gets the bundle
and two public keys — no access to our systems, no trust in our dashboard.

> *Verification is Python written from the schema, sharing no code with the Rust
> producer. That is what makes it a check rather than a second opinion.*

What is on screen: `RESULT VERIFIED`, `entries 9`, `head: 12 leaves`, both pins.
Keep the printed root: it is what acts 3 and 4 depend on.

### 2. "What if someone edits the file?"

The item was re-sealed on 2026-10-18 under `SEAL-77188`. Change that one string
in the issued bundle to `SEAL-77120` and the item looks like it was never
re-sealed. The verifier exits 1 and names the step that failed.

> *This is the easy attack, and it is the one a hash chain plus a signature is
> designed to catch.*

### 3. "What if the person who edits it also holds the keys?"

This is the act worth the demo. Edit the **source log**, then export again with
the same node and exporter keys. The bundle is re-signed honestly over the new
tree, and the verifier says `VERIFIED` — because everything in it is internally
consistent and correctly signed.

> *Nothing is broken here. The producer signs the head it mints, so it can only
> prove the node signed that tree, not that the tree was the node's whole log.
> A verifier holding one bundle cannot tell a current head from an old one.*

The check that works is the one a court already performs: compare the head the
recipient retained at issue time with the head in the bundle handed over now.
The demo prints both roots — same twelve leaves, different root. It asserts they
differ, so the point is not a coincidence.

What would close this gap is not a code change in the verifier: it is the head
leaving the node at seal time — a timestamp authority, a co-signing party, a
ticket. That is deployment work this repository does not do, and the demo says
so on screen rather than in a footnote.

### 4. "Someone deleted the whole directory and rebuilt it."

Run the lab sealed with the node key, verify pinned: `signed=true`. Then delete
the directory, rebuild a self-consistent log without the key, and verify twice:

- plain `mnr ledger verify` → exit 0, `signed=false` — it holds no key and cannot judge;
- `mnr ledger verify --head-key node.key` → exit 1, "the seal carries no signature".

> *Attribution, not completeness. A log truncated before sealing and then signed
> still verifies. Signing narrows the custody gap; it does not close it.*

### 5. "What about the log the node wrote while it ran?"

Three fresh runs, three failures that never read `OK`:

| Change | Result |
|---|---|
| one entry's `kind` edited | exit 1, `hash mismatch at seq 0: entry was mutated` |
| log cut to its first three entries | exit 1, anchor describes 81 entries, chain ends at seq 2 |
| the same truncated directory reopened | exit 1, the writer refuses rather than re-anchoring |
| `log-head.json` deleted | exit 1, `UNSEALED` — not `OK`, because a deleted anchor and a never-sealed log look the same |

### 6. "How does that work across many probes?"

Eight probes, each with its own sealed ledger; the controller commits a fragment
hash per probe and a Merkle root over them to a second, sealed chain. A script
edits one byte of probe 0's first entry, and verification exits 1 naming probe 0
— the committed fragment hash no longer matches what is on disk.

> *The root commits to fragment hashes, so this is a local audit: it needs the
> probe directories, not just the root.*

## Questions to expect

**"So it's tamper-proof?"** No — tamper-evident. Anyone with write access can
destroy the log; they cannot edit or shorten it and still have verification pass.
Custody is the guarantee's weak point, and `THREAT_MODEL.md` §4 and §7 say so.

**"Why two signatures?"** Two roles. The node signs the tree head; the exporter
signs the header and the claim about which entries are disclosed. A recipient
pins both, and a bundle that names its own key proves nothing.

**"Why a Python verifier?"** Because a verifier sharing code with the producer
cannot test the format, only its own encoder. Standard library only, 50 tests,
BLAKE3 and Ed25519 implemented locally.

**"Why SHA-256 in the log and BLAKE3 in the bundle?"** Different layers with
different histories: the on-disk chain is the pre-existing ledger format, the
export format is specified separately and chose BLAKE3 for its tree.

**"What about timestamps?"** Self-reported wall-clock values, and `iso_now()`
falls back to the Unix epoch if the clock read fails. Nothing here is a trusted
timestamp or, by itself, a legal artifact.

**"Is the drift alarm real?"** No. Under `MockEngine` drift is arithmetic over
eight marker substrings. Replacing the engine with a model is the one seam, and
it would invalidate every behavioural number in the lab demo.

**"Could we run this in production?"** Not as shipped: one writer per directory,
no crash recovery, no external head custody, and the `slate` port is staged
rather than merged. The demo's value is showing exactly which of those are
missing.

**"What must the auditor keep?"** The bundle, the two pinned public keys, and the
head root/size recorded at issue time. Everything else in the demo is
reconstructible; that retained head is not.

## The other deployment, if asked

The farm case is the same log with a different writer: a sensor gateway records
temperature, feed and water, and the two questions are "what was recorded while
the controller was down" and "was the 03:00 alarm raised then or written in
later". The mechanics are identical — seal before the restart, retain the head
outside the building. Only the evidence-room version ships here, because it
exercises the export path as well as the log.

## Files

| Path | Purpose |
|---|---|
| `demo/run.sh` | the six acts, with assertions and a proved/not-proved summary |
| `demo/scenario/evidence-room.ndjson` | 12 fictional custody events across two cases, in the store shape `mnr bundle export` reads |
| `demo/out/` | everything the run produced, for inspection after the demo (gitignored) |

The scenario is deliberately ordinary — booking, sealing, transfer, examination,
release, return, re-seal, audit — because the point is that the log is used the
way a property room already works, not that the data is exotic.
