# Consolidation Decision: one witness core, several applications

**Status:** proposal for decision — nothing in this document has been executed.
**Snapshot:** public `github.com/bigblue-r4`, default branches, 2026-10-25.
**Scope:** the public repositories only. Anything private or local was not visible.

## 1. The finding

Witness logging is the reusable asset in this portfolio. It is also the component
that has been built repeatedly: two real logs with cryptography, two vendored
copies of one of them, a plain append-only feed that calls itself a witness layer,
the unsigned Rust chain in this repository, and a second, unrelated idea also
named "witness" (a constrained output schema). The police and poultry artifacts
are applications of the log, not separate products — and the police application
has already been forked into two implementations whose court-export bundles are
no longer the same format.

The proposal: one importable core, three consumers, one lab. Keep the
applications, delete the copies, and give the core the capabilities no copy has.

## 2. Method and evidence base

Thirteen public repositories exist. Six contain witness code or its
documentation; they were cloned and read. The other seven were not reviewed for
this document.

| Repository | Language | Files | Depth |
|---|---|---|---|
| `kiss-protocol` (Harborlight) | Go | 151 | Log store, Merkle, signer, encryption, enforcer, gossip, PD packages, farm package, `cmd/witness`, `cmd/witness-pd`, docs, tests |
| `slate` | Go | 43 | Store, head, evidence, export, custody/peer, roles, docs, installer |
| `harborlight-poultry-demo` | Go | 39 | Tree, `SOURCE.md`, sync script, copied packages |
| `sgail-playground` (`witness/`) | Go | 38 | Tree, `SOURCE.md`, sync script, copied packages |
| `split-brain-harness` | Rust | 150 | `crates/sbh-store` (session log, audit), `crates/sbh-core/witness_schema.rs` |
| `mirror-node-reconnaissance` | Rust | — | Read in full: ledger, observer, reaper, sim, CLI, all docs |

Not reviewed: `deobfuscate-rs`, `deobfuscate-vision`, `unicode-interference`,
`glyph-validator`, `dreaming`, `thumb-server`, the profile repository. None is
described as a log; none was opened for this document.

**No line numbers are cited.** Paths, type names and function names are given
instead, because those survive refactors and let anyone check a claim with one
`grep`. Statements are marked **read** (I opened the code) or **not measured**
(the conclusion is arithmetic or inference, not a benchmark).

## 3. The map

```
                    the witness *log* (append-only, tamper-evident)
                                      │
        ┌─────────────────┬───────────┴───────────┬──────────────────┐
        │                 │                        │                  │
  kiss-protocol      slate                   2 vendored copies    mirror-node
  Merkle + signed    chained signed          @ v3.3.3            (Rust)
  head + proofs      head + custody          (poultry, playground) unsigned chain
  + encryption       + court export
        │                 │
        ├─ cmd/witness         (872-line generic log CLI)
        ├─ cmd/witness-pd      (514-line police product)   ──┐
        ├─ internal/farm       (poultry package)            │  same product,
        └─ examples/poultry    (poultry binary)             │  same bundle format,
                                                            ─┘  independently diverged
                    the other "witness" (not a log)
                             │
                  sbh-core/witness_schema.rs
                  closed-vocabulary output schema
```

### 3.1 `kiss-protocol` — the strongest log

- **Read.** An RFC-6962-style Merkle log: append-only store, inclusion proofs
  (`internal/merkle/proof.go`), signed tree heads, a trusted/pinned key set, a
  PIV/hardware signer, an additional BLAKE3 MAC over the head, AES-GCM encrypted
  records with a length-prefixed frame per record, and a crash-tail quarantine
  with a recovery report. `cmd/witness` exposes twelve subcommands, among them
  `init`, `start`, `status`, `audit`, `prove`, `export`, `verify-export`,
  `migrate` and `watchdog`. Fuzz tests exist for the tree, the store, the gossip
  layer and the mirror.
- **Read.** Key handling is the right shape: `SignerKey` is treated as
  attacker-writable unless pinned to a trusted key, with `OpenPinned` and
  `OpenTrusting` variants instead of one ambiguous default.
- **Read — defect 1, head cost.** `Store.Append` ends with a call to
  `writeTreeHead`, and `writeTreeHead` recomputes `merkle.Root` over every leaf
  before signing and rewriting the head file. Cost per append is therefore O(n):
  O(n²) over a run, plus one signature per event — a *hardware* signature per
  event with the PIV signer. **Not measured**; the claim is arithmetic from the
  call path.
- **Read — defect 2, durability.** `Append` writes the record frame and then
  writes the head without fsyncing either; `writeTreeHead` uses `os.WriteFile`
  followed by `os.Rename` with no `Sync` on the temporary file. The head can
  outrun the records it commits to. The codebase repairs this afterwards
  (quarantine, recovery report) rather than preventing it.
- **Read — defect 3, unauthenticated linkage.** `TreeHead` carries `Size`, `Root`,
  `PrevRoot`, `Timestamp`, `MAC`, `Signature`, `SignerKey`; but both the MAC and
  the signature are computed over `size_be8 || root` only. `prev_root` and `ts`
  are therefore outside the authenticated preimage, and an attacker with write
  access can set them freely without invalidating either. The mirror check in
  `cmd/witness/audit.go` compares a remote head's `PrevRoot` against the local
  one, so that comparison is over an attacker-writable value; the authenticated
  parts remain `size` and `root`.

### 3.2 `slate` — the best product, weaker log

- **Read.** Hash-chained log with encrypted frames, a signed head per append,
  X25519-sealed multi-node custody, roles, tokens, peer discovery, an evidence
  package, court export, a dashboard, an offline installer and a release pipeline.
- **Read — the head discipline the core should adopt.** Slate does three things
  kiss does not:
  1. **Record first, then head.** The store writes the record before re-anchoring,
     and the comment states the reason: a crash between the two leaves a head that
     is *behind* the log ("stale"), never one that claims records the log does not
     contain. Stale is recoverable and honest; over-claiming is indistinguishable
     from truncation.
     **Read — and the code does not yet earn the comment.** There is no `Sync()`
     on the log between the record write and `writeHead`; the head's temp file *is*
     `Sync`ed before the rename. On power loss the anchor can therefore be durable
     while the records it commits to are still in the page cache — the exact window
     the comment says is impossible. The ordering intent is right; one missing
     `Sync()` is what would make it true.
  2. **The signature covers the whole head.** `Head.Sign` signs a payload of all
     fields, not a subset, so `prev_head` and `timestamp` are authenticated. Its
     `Verify` is also honest about scope: it checks the self-signature against the
     advertised `SignerKey` and says plainly that this does not establish that the
     key is one you should trust.
  3. **The chain commits to the previous head's bytes.** `PrevHead` is
     `SHA-256` of the previous head *file as it sits on disk*, not of a
     re-marshalled struct, so editing any byte of it — including in ways that
     round-trip through the struct — breaks the link.
- **Read — where slate regressed against kiss.** It writes each record as two
  calls (`[uint32 length]` then the sealed bytes). Kiss deliberately builds one
  buffer and issues a single write so an interrupted append leaves at most one
  partial frame, never a length with no record. Slate's reader has to cope with
  the case kiss designed out.
- **Read — the symmetry worth stating.** Kiss has the better record framing and
  the weaker head; slate has the better head and the weaker record framing, plus
  the missing fsync. Neither is the core. Their union is, which is the whole
  argument of this document in one sentence.
- **Read — the gap.** No Merkle tree (`internal/` has no `merkle` package), no
  inclusion proofs. The head chain gives continuity; it cannot prove that one
  specific record is in the log.

### 3.3 The copies

- **Read.** `harborlight-poultry-demo/internal/` holds `SOURCE.md` plus copies of
  `encrypt`, `farm`, `merkle`, `pipelock`, `signer` and `store`, produced by
  `scripts/sync-from-kiss.sh`. `sgail-playground/witness/internal/` holds
  `SOURCE.md` plus copies of `encrypt`, `merkle`, `signer` and `store`, with the
  same script.
- **Read.** The copies exist for one reason: Go forbids importing `internal/`
  packages across modules. The sync script, the provenance file and the import
  rewriting are all workarounds for that packaging choice.
- Both are documented and pinned, which is the honest way to fork. They are also
  already behind: kiss has moved past the version they pin, and the defects in
  §3.1 now exist in three places.

### 3.4 The two police artifacts have already forked

This is the most consequential finding in the review.

- **Read.** `kiss-protocol/internal/pd/{evidence,export,roles}` and
  `kiss-protocol/cmd/witness-pd` implement a police product. `slate` implements
  the same product with its own `internal/{evidence,export,roles}` and a
  2,709-line `cmd/slate`. Both carry seven documents on the same skeleton —
  overview, architecture, node model, roles, chain of custody, court export —
  with kiss adding `dashboard.md` and slate adding `deployment.md`.
- **Read — the code.** `internal/pd/export/export.go` and
  `slate/internal/export/export.go` are both 178 lines and differ by 38: the
  import path, and slate's added `Agency` and `Seal` fields (branding, but
  covered by the signature), plus comment rewording. They are one file that has
  been forked, not two implementations.
- **Read — the docs.** After normalising the product name, the document pairs
  differ by 46–167 changed lines each. Same skeleton, diverged content.
- **Consequence.** Two bundles that are both called "court export", signed over
  different field sets. A verifier written against one either rejects the other
  outright or silently ignores the branding fields it does not know. In an
  evidence room that is not a duplication nuisance; it is the one place where a
  format fork has a legal consequence.

### 3.5 The other "witness" — `split-brain-harness`

- **Read.** `crates/sbh-store/src/session_log.rs` and `audit.rs` are plain
  append-only JSONL with FNV-1a fingerprints and masked client addresses. One
  doc comment says the log is "suitable as a witness-layer feed". There is no
  hash chain, no Merkle tree and no anchor in either file.
- **Read.** `crates/sbh-core/src/witness_schema.rs` is a different idea with the
  same word: a *fair witness* output schema. A watcher returns a closed verdict
  enum and closed anomaly codes, there are hard caps on findings and quote
  length, and unknown keys fail the parse. A finding cites a verbatim quote, which
  is checked as an exact substring and then stored as a byte span, so nothing the
  model *wrote* survives into the record — only positions in what it was shown. It
  exists to close the channel by which content a watcher read comes back out as
  the watcher's own judgement.

This matters twice. First, the map should not call the feed a log — it is a feed,
and the Rust log is the one in this repository. Second, the fair-witness schema
solves a problem this repository still has (§6, P2-6).

### 3.6 This repository

- **Read.** `core/ledger`: SHA-256 chain, fingerprints only, create-once
  `log-head.json`, `sync_data` per entry and `sync_all` on the anchor, mutation
  and truncation detection, sealed-directory refusal. No key, no MAC, no
  signature, no proofs, no recovery.
- **Read.** Gaps that bear on a consolidation decision: the log never records the
  node's own conclusion (no drift/`agree`/alarm entry, and no trip-reason entry
  before sealing); `execute_teardown` discards the seal error; the anchor is
  unsigned and never exported; `iso_now()` writes the Unix epoch on clock failure
  and verification checks neither timestamp format nor monotonicity; there is no
  writer lock; `mnr ledger show` prints a count and little else.
- **Read.** The Proposer and Verifier both return free text (`topology_hint`,
  `telemetry`, `note`), and the docs already admit two of those fields are passed
  to the Verifier but never checked. That is exactly the smuggling channel
  `witness_schema.rs` was written to close.

**The uncomfortable conclusion.** Of the five log implementations in the
portfolio, this one is a strict subset of the strongest: it cannot prove inclusion, sign a
head, encrypt a payload, or export a head for custody. It is a good *laboratory
demonstrator* of instrumenting an adversarial environment — which is what its
documentation says it is — and it is the wrong home for the primitive's future.

## 4. Why it happened

Three structural causes, none of them carelessness:

1. **Go's `internal/` rule.** The most reusable code was placed where no other
   module can import it, so reuse required copying. Every copy traces to this.
2. **Applications living inside the core repository.** `cmd/witness-pd`,
   `internal/farm` and `examples/poultry-demo` are portfolio applications, not log
   features. Because they live in the log's repository, "depend on the log" was
   never the obvious move and "copy the log" was.
3. **No named owner for the primitive.** Each codebase satisfies its local need,
   so no single artifact is the one that gets fixed, and a fix applied in one copy
   has to be remembered in three others.

## 5. The decision being proposed

**One core, three consumers, one lab.**

- **Core.** A small public module — working name `witness` — holding exactly four
  packages taken from `kiss-protocol`: `store`, `merkle`, `signer`, `encrypt`.
  Nothing else from that repository's 23 internal packages; the verticals,
  gossip, enforcer, mirror and farm logic stay where they are. No CLI beyond a
  verifier.
- **Consumers.** The poultry application (one repo, one binary, the demo becomes
  a mode) and `kiss-protocol` itself at P0-2; `slate` (the evidence-room product)
  after P1-2, because its current head is stronger than the one being extracted;
  and — after P2-5 — this repository's lab.
- **Lab.** `mirror-node-reconnaissance` keeps the recon demonstrator, the
  role-separated observer and the dual-use analysis, and stops being the home of
  the witness log.

### 5.1 Disposition

| Artifact | Disposition | Why |
|---|---|---|
| `kiss-protocol/internal/{store,merkle,signer,encrypt}` | **Extract** into `witness` v1.0.0, public packages | The only complete implementation; currently unimportable by design |
| `kiss-protocol/cmd/witness` | Keep, rebuilt on the module | Generic log CLI belongs with the log |
| `kiss-protocol/cmd/witness-pd`, `internal/pd/*`, `docs/pd/*` | **Retire** into `slate` | Same product as slate, already forked, different bundle format (§3.4) |
| `slate` | Keep as the product; swap its private store for the module **after P1-2**; add proofs | Best operational story: installer, releases, custody, roles, legal holds, offline — but its head is stronger than the core's until P1-2 lands |
| `harborlight-poultry-demo` | Keep as the poultry application; delete copied internals | Right example, wrong fork |
| `sgail-playground` witness demo | Keep as a WASM showcase; depend on the module | Same |
| `kiss-protocol/internal/farm`, `examples/poultry-demo` | Retire into the poultry repo | Third copy of one vertical |
| `split-brain-harness/crates/sbh-store` | Keep, relabel as a feed; do not grow it into a log | It is honest about being append-only and unhashed; saying so is the fix |
| This repo's `core/ledger` | Keep for the lab, or consume the module — decide explicitly (P2-5) | It is the weakest log carrying the flagship docs |
| `scripts/sync-*`, both `internal/SOURCE.md` | Delete after extraction | The reason for them disappears |
| `proxy/` | Keep as concept only | Correctly unimplemented |

### 5.2 The flagship recommendation

Keep **`slate`**, retire **`cmd/witness-pd`**. Slate has what a records clerk needs
and a demo never does: a machine-bound key with a recovery sheet, legal holds that
block destruction, roles, an offline installer, a release pipeline, and a court
export with branding fields. Port into it the two things kiss does better — Merkle
inclusion proofs and pinned-key verification — through the shared core.

The cost is lower than it first looks, and the reason is §3.4: this is not porting
features between complementary products, it is reconciling one product that has
been forked. The bundle schema is the only part that needs care, and it needs care
because existing bundles may already be in the wild.

**Do not delete the retired binary before the schema question is settled.** Publish
a single bundle version that accepts the union of both field sets, state which
fields are covered by the signature, and keep the old verifier path working for
bundles already issued.

## 6. Priority order

Each step is worth doing even if the next never happens.

### P0 — decisions and de-duplication

**P0-1. Settle the core's licence (§7).** Blocks every file move.
*Done when:* `LICENSE`/`NOTICE` names the core's licence and the reason, in one
paragraph.

**P0-2. Extract the core and delete the copies.** Move the four packages out of
`internal/`, tag `v1.0.0`, make kiss, the poultry repo and the playground depend
on it, delete both `sync-from-kiss.sh`, both `SOURCE.md` and every vendored file.
*Done when:* `grep -r sync-from-kiss` returns nothing across all four repos and
they build against one tagged version. Roughly a day of mechanical work; converts
four maintenance surfaces into one. **This is a pure move:** no behaviour change
while extracting. The defects in §3.1 get fixed afterwards, once, in the core —
which is the entire reason to move first. Rehearsed end to end in
[EXTRACTION_PLAN.md](EXTRACTION_PLAN.md): module layout, exact `go.mod` pins,
per-consumer edits, gates, and the one thing the move fixes on the way
(the PIV build, which cannot compile today).

**P0-3. Reconcile the two police artifacts into `slate`.** Bundle schema first,
then documentation, then the retired binary.
*Done when:* one repository owns the evidence-room product, one signed bundle
format exists with a stated field set, and the old verifier still accepts bundles
already issued. The schema half is worked out in
[BUNDLE_SCHEMA.md](BUNDLE_SCHEMA.md): `witness-bundle/2`, the exact bytes it signs,
an eight-step verification procedure, and the byte-level rule that lets one
verifier read bundles already issued by either implementation — rehearsed against
real bundles from both, with every tamper control failing closed.

**P0-4. Freeze feature work in the copies.** From now until P0-2, a fix goes into
the canonical core first. Otherwise the extraction becomes a merge.

### P1 — make the core worth depending on

**P1-1. Stop signing a head on every append.** Adopt a checkpoint policy
(maximum merge delay: every *N* events or *T* seconds, plus an explicit
"checkpoint now") with an incremental Merkle frontier so appends stay O(log n).
`RootAt(size)` already anticipates the read side; the write path is what changes.
*Done when:* a 10⁵-event run has per-append cost that does not grow with *n*, and
inclusion proofs still verify across a checkpoint boundary.

**P1-2. Combine both head designs, including the line neither has.** Take slate's
whole-head signature, its chain over previous head bytes, and its record-then-head
ordering; add the `Sync()` on the log that slate documents but does not perform;
take kiss's single-write length-prefixed frame. Together with P1-1 that leaves the
head authenticated field by field, appends O(log n), and no window in which the
anchor can claim a record the log does not hold.
*Done when:* a crash injected between the log write and the head write leaves the
log verifying as stale, never as over-claiming; editing `prev_root` or `ts`
invalidates the signature; and a torn append at any offset is recovered rather
than read as a length without a record. **Compatibility cost:** changing the
signed preimage invalidates existing heads, so the new head carries a format
version and the verifier accepts both. **Sequence:** land this before `slate`
migrates its store to the module, or it trades a better head for a worse one.

**P1-3. Give the verifier its own head chain.** Every repository carries the same
caveat: whoever can write the directory can rebuild log and head and pass
verification, and deletion is indistinguishable from never having sealed. Both
stores already *chain* heads (kiss via `prev_root`, slate via `prev_head`), and
kiss even has a gossip mesh that detects a silent peer — but in every case the
chain lives with the operator, so it proves continuity to someone who already
trusts the operator. A verifier that retains a ~100-byte head chain *outside* the
operator's control — an auditor's machine, county IT, a nightly email, an RFC-3161
timestamp, a ticket — changes the claim from "tamper-evident if you trust the
audited party" to "tamper-evident against a head I have held since yesterday".
*Done when:* an operator who rebuilds a perfectly self-consistent log and head
still fails verification against a head the verifier obtained earlier.

### P2 — product surface, then the lab

**P2-4. One verifier that answers five questions, offline.** Integrity (recompute
to the signed head), provenance (signed by a pinned key), freshness (contiguous
from a head the verifier held), inclusion (this record is in the log), and a
human-readable bundle for a non-engineer. Kiss has proofs; slate has the bundle;
freshness exists nowhere. One binary, no network, runnable by the other party
without your source.
*Done when:* someone who has never seen the codebase verifies a bundle and an
inclusion proof from a clean machine.

**P2-5. Decide what this repository's ledger is.** Two honest options: (a) keep
`mnr-ledger` as the lab's own chain and say so in one line, or (b) delete it and
consume the core. What must not continue is a third artifact that looks
production-shaped. If (a), close the specific gaps: witness the verdict and the
trip reason before sealing, stop discarding the seal error, check timestamp format
and monotonicity, and take a writer lock.
*Done when:* the README states which of the two it is, and "trust what we learned"
is answerable from the log itself.

**P2-6. Adopt the fair-witness output shape for the roles.** The Proposer and
Verifier return free text, and `topology_hint`/`telemetry` are already
passed-and-ignored. A closed vocabulary with no free-text field — the shape
`sbh-core/src/witness_schema.rs` already implements — removes the channel, makes
`agree` checkable field by field, and stops the Verifier's `note` from being a
place a compromised role can editorialise.
*Done when:* a response with an unknown key or a free-text field fails the parse.

**P2-7. One story per audience.** Farm: restart catch-up and a silent-house alarm
with a record that survives a dispute. Evidence room: intake records you can prove
were not edited after the fact. Neither requires the recon lab to make sense; lead
with both and keep the swarm work as the lab appendix it already is.

### Explicitly not proposed

- **Rewriting kiss in Rust** so this repository can own the core.
- **A sixth witness implementation**, or promoting `sbh-store` into one.
- **Implementing `proxy/`.** Concept-only is the correct state.
- **Keeping `witness-pd` and `slate` "for now".** That is how a portfolio ends up
  with two court-export formats — and per §3.4, it already has.

## 7. The open licensing question

Answer this before any file moves. In practice it is a one-way door.

**As it stands.** `kiss-protocol`, `slate`, `harborlight-poultry-demo`,
`sgail-playground` and `split-brain-harness` are MIT. This repository is
proprietary SGAIL LLC, all rights reserved. Extracting the core from an MIT
codebase and relicensing it as proprietary is legally awkward; extracting it and
keeping it MIT means this repository's future improvements to the core cannot flow
back without a licence grant. Either is defensible. Drifting into it is not.

Also worth settling, because it may already be live: this repository is
proprietary while the Rust witness work it draws on (`split-brain-harness`) is
MIT. The README describes that relationship as shared *patterns*, not copied code,
which would not trigger MIT's notice requirement — but nobody has checked that
line by line, and it becomes harder to check as the codebases converge (P2-5 would
make them converge).

**The question that answers it:** where does the trust anchor sit? The claim is
"you can verify our records without trusting us." That claim fails if the
verifying party cannot inspect the verifier. So decide on adoption, not on
protection:

| Option | Effect on the claim | Effect on the business | Verdict |
|---|---|---|---|
| **A. Core MIT, applications proprietary** | The county's own IT can inspect and run the verifier | Core becomes a public good that pulls the paid verticals; needs discipline about what belongs where | **Recommended** — the core's value is being trusted by strangers, which is what a proprietary licence prevents |
| B. Core proprietary, licensed per engagement | The trust anchor becomes a contract; every auditor is a negotiation | Maximum control, minimum adoption | Viable for one large engagement, poor as a default |
| C. A, plus a source-published verification CLI | Strongest "inspect the verifier" story | Slight extra work to ship two distribution forms | Good second step after A |

Three things to settle in the same paragraph as the licence:

1. **Copyright holder and contributor grant.** Files are moving between
   repositories owned by the same entity — easy now, impossible to reconstruct
   later. A short grant keeps the relicensing option open.
2. **Trademark.** Keep the names (`Harborlight`, `kiss`, `SLATE`) separable from
   the code so a fork cannot present itself as your product.
3. **Do not let the licence imply more than the crypto proves.** No licence text
   turns an unexported head into a legal artifact. P1-3 is what earns the
   evidentiary claim; a "court-ready" tier without it is a claim the code does not
   support.

**If the decision is A, this is the paragraph:**

> The witness core — log, Merkle tree, signer and record framing — is MIT, so any
> party asked to trust a record can inspect and run the code that verifies it. The
> applications built on it, the poultry deployment and the evidence-room product,
> are proprietary and licensed per engagement. The verifier is distributed free of
> charge and its source is published.

## 8. What must survive consolidation

- **Kiss's key instincts.** A signer key treated as attacker-writable unless
  pinned, a MAC *and* a signature, no ambiguous constructor. Port the reasoning,
  not just the code.
- **Slate's head discipline, and the honesty of its doc comment.** Sign the whole
  head; chain to previous head bytes; record before head. It is the best-engineered
  small file in the portfolio. Its comment about stale versus over-claiming is also
  the clearest statement of intent anywhere in the code — and the missing `Sync()`
  under it is the best illustration of why intent without a test drifts.
- **This repository's honesty.** "What this does not show", the threat-model
  section that lists what a mitigation does *not* cover, the split-brain section
  that refuses to call logical role separation tensor isolation. In a field full
  of "tamper-proof" claims that voice is a differentiator — move it to the
  flagship rather than archiving it with the repo it currently lives in.
- **Slate's operational realism.** Recovery sheet, legal holds, offline install,
  roles. That is the difference between a demo and something a clerk will use.
- **The farm framing.** Restart catch-up and a silent-house alarm are concrete,
  understandable, and carry no dual-use baggage — a better front door than
  reconnaissance will ever be.

## 9. What this document does not decide

- The commercial model (per site, per seat, support contract).
- Whether the poultry application is a product, a reference implementation, or
  both.
- How a retained head is delivered (email, RFC-3161, a ticket, a co-signing
  partner) — P1-3 fixes the requirement, not the transport.
- Anything about the recon lab's research direction, which is a separate question
  from its packaging.

## 10. Open items

- **Unverified:** the provenance check in §7 — whether any line of this
  repository's ledger derives from the MIT `split-brain-harness`, as opposed to
  the shared pattern the README describes.
- **Unverified:** whether anything outside these repositories pins an import path
  or a bundle schema, which would change the migration plan for P0-2/P0-3.
- **Not measured:** the O(n²) claim in §3.1 and the cost of the P1-1 change. Run a
  benchmark before quoting a number to anyone.
- **Not reviewed:** the seven unrelated repositories, and `split-brain-harness`
  beyond `sbh-store` and `witness_schema.rs`.
- **Decision needed from you:** P0-1 (licence), P0-3 (which police artifact
  survives), and P2-5 (whether this repository keeps a ledger at all).

## Appendix A — claims and where to check them

| Claim | Where | Look for |
|---|---|---|
| Head rewritten on every append | `kiss-protocol/internal/store/store.go` | `Append` ends with `writeTreeHead`; `writeTreeHead` calls `merkle.Root(leaves)` |
| Head not fsynced before rename | same | `os.WriteFile` then `os.Rename`, no `Sync` |
| Only `size` and `root` are authenticated | same | `TreeHead` struct vs `treeHeadSigInput` and `computeMAC` |
| Mirror continuity compares an unsigned field | `kiss-protocol/cmd/witness/audit.go` | `remote.PrevRoot != local.PrevRoot` |
| Record-then-head ordering, with rationale | `slate/internal/store/store.go` | `writeHead` call after the record write; comment about "stale" |
| No fsync of the log before the head | same | no `Sync()` between the record write and `writeHead`; `head.go` fsyncs only its own temp file |
| Two writes per record | same | `PutUint32` written separately from the sealed bytes |
| Single frame per record | `kiss-protocol/internal/store/store.go` | length prefix and sealed record appended into one buffer, one `Write` |
| Whole-head signature | `slate/internal/store/head.go` | `Head.Sign` over `h.payload()`; `Verify` note about key trust |
| Chain commits to head file bytes | same | `hashHeadFile` hashes the file, not a re-marshalled struct |
| Two court-export implementations forked from one file | `kiss-protocol/internal/pd/export/export.go`, `slate/internal/export/export.go` | 178 lines each; diff is the import path plus `Agency`/`Seal` |
| Copies and their provenance | `harborlight-poultry-demo/internal/SOURCE.md`, `sgail-playground/witness/internal/SOURCE.md` | `scripts/sync-from-kiss.sh` |
| Feed is not a log | `split-brain-harness/crates/sbh-store/src/session_log.rs` | append-only JSONL, FNV-1a fingerprint, no chain |
| Closed output schema | `split-brain-harness/crates/sbh-core/src/witness_schema.rs` | `WatchVerdict`, `AnomalyCode`, byte spans, caps |
| This repository's ledger gaps | `core/ledger/`, `lifecycle/reaper/src/lib.rs` | no verdict/trip entry; `execute_teardown` seal error discarded |
