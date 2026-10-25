# One Court-Export Bundle Format — `witness-bundle/2`

**Status:** proposal for decision. Schema agreed here; a reference producer and
signer ship in [core/bundle/](core/bundle/) behind `mnr bundle export`, and
[tools/bundle-verify/](tools/bundle-verify/README.md) is an independent verifier
for the format and the legacy path.
**Snapshot:** `kiss-protocol` at `4aa41c0`, `slate` at `c198ce0`, 2026-10-25.
**Implements:** P0-3 in [CONSOLIDATION.md](CONSOLIDATION.md) — the schema half,
before documentation is merged and before `cmd/witness-pd` is retired.
**Depends on:** P0-2 ([EXTRACTION_PLAN.md](EXTRACTION_PLAN.md)). The bundle code
lands in the extracted `witness` module, which is why this schema is written for
a package that does not exist yet.

## 1. What this document decides

Today there are two court-export implementations, 178 lines each, forked from one
file, with **different signed fields and different entry bytes for the same
case**. This document specifies the one format that replaces both, states the
exact bytes it signs, and gives a verification procedure for bundles that have
already been issued under the old format — proven by rehearsal, not asserted.

Out of scope, and named here so nobody assumes otherwise: timestamp attestation,
per-entry confidentiality, retention, multi-node case assembly, and the P0-1
licence question.

## 2. What exists today

Four artifacts in this portfolio are called a bundle. Only two of them are court
exports, and they are not the same format.

| Artifact | Producer | What it binds | Signed over |
|---|---|---|---|
| Court export (kiss) | `kiss-protocol/internal/pd/export`, driven by `cmd/witness-pd` | case-filtered `store.Entry` list, re-hashed with SHA-256 | `json.Marshal(bundle)` minus `signature` |
| Court export (slate) | `slate/internal/export`, driven by `cmd/slate` (CLI, dashboard, API) | same, plus `agency`/`seal`; entries carry `prev_hash` | same |
| Transfer bundle | `slate/internal/peer` (`TransferBundle`) | one item snapshot + its custody events + `events_hash`; verified against an **enrolled** key, not the key it names | `json.Marshal` minus `signature` |
| Log export | `kiss-protocol/internal/store` (`Export`, `VerifyExport`) | the whole log: signed head, **every** leaf hash, filtered entries, pinned signer, prior-head append-only check | the head, not the document |

Two measurements from the rehearsal, both worth stating plainly:

- **Neither court-export package has a single test.** `internal/pd/export/` and
  `internal/export/` each contain one file, `export.go`. The signature path, the
  case filter and the file writer are uncovered in both repositories.
- **Neither repository can verify a bundle file.** `cmd/witness-pd` has no
  `verify` subcommand. `slate verify` verifies the *local* store (chain plus head
  anchor), not a bundle. A clerk who receives a `.ndjson` today has nothing to
  run.

The fourth row is the one to learn from: `witness-export/1` already has an
export type, a verifier, pinned signer keys and an append-only check. It is the
only bundle-shaped thing in the portfolio that a third party can actually check.

## 3. Six defects that stop v1 being the survivor

Each is stated with the evidence that shows it.

1. **Nothing ties the entries to the log.** `Bundle` carries no head, no root and
   no proof. `Verify` checks one signature over the document. The bundle asserts
   "these entries existed"; the log says nothing about it. A bundle can be
   generated from an unlogged draft slice and it verifies.
2. **The documented check does not exist.** Both `docs/*/court-export.md` tell the
   reader that `sha256_chain` proves the bundle "was not altered after
   generation". `Verify` never recomputes it, and neither implementation checks
   `entry_count` against the number of lines. The field is carried, signed and
   unused.
3. **The signed bytes are one encoder's output, not a specification.** v1 signs
   `json.Marshal` of a Go struct. What that means in practice, all confirmed in
   the rehearsal:
   - `bundlePayload` zeroes `signature`, and `omitempty` then *removes the key*,
     so the signed bytes contain no `signature` field at all while the file does;
   - a zero-entry bundle signs `"entries":null`, not `"entries":[]`;
   - `generated_at` and `ts` are RFC3339Nano with Go's trailing-zero trimming, so
     the digit count varies per record;
   - `json.RawMessage` payloads are re-compacted with HTML escaping, so `&`, `<`
     and `>` inside `data` appear as `\u0026`, `\u003c`, `\u003e`.

   A verifier written in any other language that re-serialises the parsed JSON
   produces different bytes and rejects a good bundle. §6 shows the one way out;
   it is a rescue of v1, not a property of it.
4. **Identical case content hashes differently in the two implementations.**
   `slate`'s entry type carries `prev_hash` (no `omitempty`) inside the hash
   preimage; kiss's does not. Rehearsal, same four custody events, two chain
   values: kiss `31ec34bc68dc0e9b…`, slate `5de17268b2ea5110…`. Documentation that
   quotes a `sha256_chain` from one product cannot be checked against the other.
5. **No format marker.** A v1 bundle is recognised by the absence of a field.
   Neither implementation records a format name or version, so a reader cannot
   tell which product wrote the file, or that a future format is not this one.
6. **Neither format names its signer.** `Bundle` has no key field. Compare
   `TransferBundle.SenderPubKey`, whose comment already states the right rule
   (verify against the enrolled key, not the one named), and `TreeHead.SignerKey`.
   For a court bundle there are *two* signers — the node that kept the log and the
   officer who exported — and v1 conflates them into one out-of-band key.

## 4. The format

Name: `witness-bundle/2`. The string appears in the header's `format` field and as
the first line of the signed preimage. `witness-export/1` in the core keeps its
own name; the two are different artifacts and must not be confused.

### 4.1 Envelope

Unchanged from v1, deliberately: a reader that can split lines can read this.

- UTF-8, one JSON object per line, `\n` terminated, no CR, no trailing blank line.
- Line 1 is the header.
- Lines 2…N+1 are entries, **byte-identical** to the bytes that were hashed into
  the log, in ascending `seq` order.
- The header carries no `entries` key, and a verifier ignores unknown keys. (v1
  wrote `"entries":null`; the new format does not need the placeholder because the
  signature never covers a re-serialised document. The rehearsal prototype still
  emitted the placeholder — it reused v1's struct — and the verifier ignores it;
  the real encoder drops the field.)

### 4.2 Header fields

| Field | Type | Presence | Provenance |
|---|---|---|---|
| `format` | string | required | new — the value is `witness-bundle/2` |
| `bundle_id` | string | required | v1 (both): `BUNDLE-YYYYMMDD-8hex` |
| `generated_at` | string | required | v1 (both) |
| `scope` | string | required | new — `case` or `log` |
| `case_number` | string | required when `scope=case`, else `""` | v1 (both) |
| `department` | string | required | v1 (both) |
| `agency` | string | optional | v1 (slate only) |
| `seal` | string | optional | v1 (slate only) |
| `node_id` | string | required | v1 (both) |
| `entry_count` | int | required | v1 (both) |
| `sha256_chain` | string | required | v1 (both), same algorithm (§4.4) |
| `export_actor` | string | optional | new — slate records it in the audit log, never in the bundle |
| `export_role` | string | optional | new — same |
| `signed_by` | string | required | new — hex Ed25519 public key of the exporter |
| `log_head` | object | required | new — `{size, root, ts, sig, signer_key}` |
| `proofs` | array | required when `entry_count>0` | new — one `{seq, index, size, path[]}` per entry |
| `signature` | string | required | v1 (both), new preimage (§4.3) |

`scope` exists so the case claim is checkable: under `scope=case` every entry's
`data.case_number` must equal the header's `case_number`, and `case_number` must
be non-empty. v1 filtered by case at generation time and then never checked it.

`log_head` is the signed tree head at export time. `mac` is deliberately **not**
carried: it is BLAKE3-keyed by the node's machine key, which a court verifier does
not hold, and shipping an unverifiable field invites a check nobody can perform.

### 4.3 The signed preimage

The bytes the bundle signature covers, in this order, `\n` after every line:

```
witness-bundle/2
bundle_id=BUNDLE-20260512-a3b2c1d0
generated_at=2026-05-12T14:30:00Z
scope=case
case_number=CASE-2026-0042
department=Honolulu PD
agency=Honolulu Police Department
seal=HPD-2026
node_id=node-001
entry_count=7
sha256_chain=9f1c…(64 hex)
export_actor=Sgt. Example
export_role=evidence_clerk
signed_by=3b1f…(64 hex)
log_head.size=41207
log_head.root=9d2c…(64 hex)
log_head.ts=2026-05-12T14:29:58Z
log_head.signer_key=8a01…(64 hex)
```

Rules, all of which a verifier must enforce:

- **Order is fixed** as above. The first line is the format name, which separates
  this preimage from any other signature in the system.
- **`key=value`, split on the first `=`.** Values may contain `=`; they are raw
  UTF-8.
- **No value may contain `\n` or `\r`.** The generator must reject such a value;
  the verifier must reject a preimage it cannot rebuild unambiguously. This is the
  whole injection surface of a line-oriented preimage and it is one check.
- **Empty optional fields are still emitted** as `key=` — absence is never
  implied, so a field cannot be added or removed without changing the signature.
- **Time strings are copied verbatim** from the header into the preimage. The
  verifier parses them to sanity-check them but never reformats: this is what
  removes the encoder dependency that broke v1.
- **`log_head.sig` and `proofs` are not in the preimage.** The head signature is
  verified against its own preimage (§4.5), and `proofs` are checked against the
  signed root, so tampering with them can only cause failure. The head's MAC is
  not carried at all (§4.2).
- `sha256_chain` is the same field name and the same algorithm as v1 (§4.4). It is
  redundant once proofs are verified; it stays because it is the one check an
  existing v1 tool can already perform, and because it makes entry-set tampering
  visible without parsing a tree.

Consequence, arithmetic not benchmarked: signing costs O(1) in the number of
entries instead of v1's O(n), because the preimage is one line per header field
plus one 64-hex digest.

### 4.4 Entry lines and the leaf rule

The entry JSON is the store's entry as written to the log: `seq`, `ts`, `level`,
`event`, `source`, `data`, and `prev_hash` where the producing store uses it.

**The leaf preimage is the entry line's bytes as they appear in the file.** No
re-serialisation, no normalisation, no re-escaping:

```
leaf  = BLAKE3-leaf-hash(line bytes)      // merkle.HashLeaf in the core
chain = SHA-256(concat(entry line bytes)) // = v1 sha256_chain, same value
```

This is what makes the format implementable outside Go: a verifier hashes what it
read. It also means the producer **must not** reformat entries — an entry read
from a log, re-marshalled by a different library, is a different leaf and the
proof will not verify. Sorting and ordering are part of the format: entries are in
ascending `seq`, `seq` is 1-based and unique, and `proof.index == entry.seq - 1`.

### 4.5 The log head

`log_head` is a copy of the signed head at export time:

| Field | Meaning |
|---|---|
| `size` | number of records the head covers |
| `root` | hex BLAKE3 Merkle root over the first `size` leaves |
| `ts` | head timestamp, self-reported by the node |
| `sig` | hex Ed25519 signature over `size_be8 ‖ root` |
| `signer_key` | hex public key that produced `sig` |

Two things a reader must not assume, both already documented as defects of the
core ([CONSOLIDATION §3.1](CONSOLIDATION.md)):

- the head signature covers `size` and `root` **only** — `ts` and
  `prev_root` are outside the preimage, so a bundle must never claim that the
  head's timestamp is authenticated;
- the head names a key; naming is not trust. The verifier's pinned set is what
  makes `signer_key` meaningful, exactly as `verifyHeadSignature` already
  requires for `verify-export`.

### 4.6 Proofs

One entry per proof: `{seq, index, size, path[]}`, where `path` is the audit path
from leaf to root as hex, leaf-first (`merkle.Prove` produces it, `merkle.Verify`
consumes it). Cost is O(log n) per entry, and — the reason it is per-entry rather
than a full leaf list — a case bundle then discloses nothing about the rest of the
log beyond the tree shape. Rehearsal, same 500-record log, 4 records in the case:

| Document | Entries shipped | Leaf material | Head | Total |
|---|---|---|---|---|
| `witness-bundle/2`, `scope=case` | 4 (729 B) | 4 audit paths, 9 hashes each, 2,585 B | 331 B | 4,301 B |
| `witness-export/1`, whole log | 500 (91,833 B) | 500 leaf hashes, 33,501 B | 483 B | 125,953 B |

The two head figures are not the same encoding: a bundle carries only `size`,
`root`, `ts`, `sig` and `signer_key` (331 B), while `witness-export/1` marshals
the store's `TreeHead` struct and its extra fields (483 B). The v2 row is
measured on `tools/bundle-verify/testdata/v2-case.ndjson`.

Total size is not the honest comparison — the whole-log export is not case-scoped,
so most of it is 496 records nobody asked for. The comparable number is the leaf
material: 2,585 bytes against 33,501 for the same log, 13× less, and the recipient
of a case bundle learns nothing about the other records beyond the tree shape.
Per-entry proofs are also the only option that works when the export is filtered
at all: a full leaf list says "this is the whole log" and then a filter
contradicts it.

### 4.7 Verification

Implementable from the file plus pinned public keys, and nothing else:

1. **Split** lines; reject CRLF and a missing final `\n`. Parse line 1.
2. **Dispatch on `format`.** Not `witness-bundle/2` → refuse, do not guess. Absent
   → this is a v1 bundle; use §6.
3. **Pin.** `signed_by` and `log_head.signer_key` must both be in the caller's
   pinned set. A bundle that names its own key proves nothing; a pinned set that
   contains only one of the two keys fails here (measured, §6.2).
4. **Bundle signature.** Rebuild the preimage from the header, verify
   `signature` against `signed_by`.
5. **Count and digest.** `len(lines)-1 == entry_count`;
   `SHA-256(concat(lines[1:])) == sha256_chain`.
6. **Head signature.** Decode `root`, verify `log_head.sig` over
   `size_be8 ‖ root` against `log_head.signer_key`.
7. **Scope.** If `scope=case`: `case_number` non-empty and every entry's
   `data.case_number` equals it. If `scope=log`: `case_number` empty **and
   `entry_count == log_head.size`**, so a bundle cannot claim to be the whole log
   and ship a subset of it. Unknown scope → refuse.
8. **Inclusion.** For each entry line: find its proof, require
   `proof.size == log_head.size` and `proof.index == seq-1`, decode the path, and
   `merkle.Verify(root, HashLeaf(line), proof)`. A missing proof is a failure, not
   a warning.

Any failure exits nonzero with the failing step named. Verification never needs
the log directory, the AES key, the machine key, or network access.

### 4.8 What changed for each v1 field

| v1 | v2 | Change |
|---|---|---|
| `bundle_id`, `generated_at`, `department`, `node_id`, `entry_count` | kept | same meaning, now covered by a specified preimage |
| `case_number` | kept + `scope` | the case claim becomes checkable |
| `agency`, `seal` (slate only) | kept | parity: kiss-issued bundles carry them empty |
| `sha256_chain` | kept | same algorithm; no longer the only integrity claim |
| `entries` inline in the signed payload | entry lines outside the preimage | signature no longer grows with the bundle |
| `signature` over encoder output | over §4.3 | reproducible in any language |
| — | `signed_by` | the exporter is named, and must be pinned |
| — | `log_head`, `proofs` | entries are bound to a log the node signed |
| — (audit log only) | `export_actor`, `export_role` | who exported becomes part of the artifact |

## 5. Two keys, not one

A court bundle makes two claims: *this record was in the log the node signed*, and
*this agency exported it*. v1 signs once, with one key, and never says whose key.
`witness-bundle/2` names both and requires both to be pinned.

This was found by breaking it: the first prototype verified the head against the
bundle's key, and its head check failed, because the log belonged to a node signer
and the bundle to an agency key. That failure is the argument for two fields.

Operationally: the node's key is the one already in `signing_key_pub` and
published to counterparties; the agency export key is a separate pair, and its
public half is what a court or opposing expert is given. Nothing in the format
requires them to differ — an operator may use one key for both — but the format
never lets a verifier *assume* they are the same.

## 6. Migration: bundles already issued

P0-3's done-when includes "the old verifier still accepts bundles already issued".
Read literally that is vacuous — a v1 verifier verifies v1 bundles, and always
will. What the clause has to mean is that the **surviving** verifier accepts them,
without shipping a second binary and without re-signing anything. That is a
property of the verifier rather than of the format, and it is what §6.1
specifies.

### 6.1 The v1 verification rule

A v1 bundle can be verified from its own bytes without re-marshalling a struct.
The signed payload is the header line with the signature field removed and the
entries spliced in where `"entries":null` sits:

1. Split the file into `header` (line 1) and `entries` (lines 2…N).
2. `payload = header` **with the trailing `,"signature":"<hex>"` element cut**
   (keep the preceding comma).
3. If `entries` is empty, `payload` stays as-is — the signature covers
   `"entries":null` and **must not** be normalised to `[]`. Otherwise replace
   `"entries":null` in `payload` with
   `"entries":[` + lines joined by `,` + `]`.
4. `SHA-256(concat(entries))` must equal `sha256_chain`;
   `entry_count` must equal the number of entry lines.
5. `ed25519.Verify(pub, payload, signature)`.

An unsigned v1 bundle is a real case — `--sign` was optional in both products. It
has no signature element, so step 2 removes nothing and step 5 has nothing to
check; steps 1, 3 and 4 still run. Report that file as **unauthenticated**, never
as verified: `sha256_chain` is a digest carried inside the document it describes,
so it catches corruption and does not catch editing.

Steps 2 and 3 are exactly the two places a naive implementation gets it wrong;
both were wrong in the first rehearsal attempt and both are covered by the tests
described below. In any language with a JSON parser, an Ed25519 library and a
SHA-256, this is forty lines. It never formats a timestamp and never re-serialises
an entry, which is why it works outside Go.

### 6.2 It is proven, not argued

Rehearsal on the two repositories at the snapshot above:

- A bundle generated, signed and written by `kiss-protocol/internal/pd/export`,
  verified against a bundle verifier compiled **inside the slate module**:
  passes. 2 entries, 904 bytes.
- A bundle generated, signed and written by `slate/internal/export`, verified by
  the same recipe: passes. 2 entries, 888 bytes. The package's own `Verify` and
  the byte-level recipe accept the same file.
- A slate-shaped bundle (with `agency`, `seal` and `prev_hash` present) verified
  by the recipe: passes. 2 entries, 1,118 bytes.
- A zero-entry bundle: 429 bytes, `sha256_chain`
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` — the
  SHA-256 of nothing. That is also the value printed in **both** repositories'
  `court-export.md` example headers next to `"entry_count": 7`, which means the
  documented example was never a real 7-entry bundle. Fix the example when the
  docs merge.

Tampering, all rejected: edit one byte of an entry line; drop the last entry; edit
`case_number` in the header; verify against an unrelated key. Same four controls
against the slate-issued bundle, plus an edited `notes` field.

The v2 prototype, for the same reason — a schema that has only been reasoned
about is not a schema:

- 4 case entries from a 500-record log, built from a real `store` with a software
  signer, `log_head` and four proofs: verifies. 4,308 bytes.
- Rejected: an edited entry (`ITEM-000` → `ITEM-999`), proofs stripped, an entry
  from another case substituted, the head root rewritten, an unrelated pin, a pin
  set holding only the export key.
- A v1 `Verify` handed the v2 bundle: `signature verification failed`, i.e. the
  old verifier **fails closed** on the new format.

Then the same claims from outside Go. `tools/bundle-verify/` is a Python
verifier written from §4.3 and §6.1 — standard library only, no shared code with
the producers — with the bundles kept as frozen vectors and 49 tests. Sizes are
the committed fixtures; they differ from the runs above by a byte or two because
`generated_at` and the bundle id are per-run.

| Bundle | Producer | Result |
|---|---|---|
| `v1-kiss.ndjson`, 904 B | `kiss-protocol/internal/pd/export` | `VERIFIED` |
| `v1-slate.ndjson`, 889 B | `slate/internal/export` | `VERIFIED` — the §10 item |
| `v1-kiss-empty.ndjson`, 419 B | kiss, zero entries | `VERIFIED` |
| `v1-unsigned.ndjson`, 761 B | kiss, never signed | `UNAUTHENTICATED`, exit 3 |
| `v2-case.ndjson`, 4,301 B | scratch emitter, §4 | `VERIFIED`, 4 entries, head 500 |
| `v2-log.ndjson`, 5,895 B | scratch emitter, §4 | `VERIFIED`, 12 entries, head 12 |
| `v2-seven.ndjson`, 3,560 B | scratch emitter, §4 | `VERIFIED`, 7 entries, 3-hash paths |
| `v2-rust-log.ndjson`, 5,895 B | `mnr bundle export`, §4 in Rust | `VERIFIED`, 12 entries; root, `sha256_chain` and every proof path identical to `v2-log.ndjson` |
| `v2-rust-case.ndjson`, 2,052 B | `mnr bundle export`, §4 in Rust | `VERIFIED`, 3 of 7 entries at seqs 2, 5, 7 |

One bundle per log size from 1 to 8 records also verified — audit paths of 0, 1,
2, 2, 3, 3, 3 and 3 hashes — so the tree walk agrees with `merkle.Prove` on
every shape up to eight leaves, including the one-leaf tree whose audit path is
empty and the 4+3 split whose right subtree splits again, not just on the sizes
that happen to be checked in.

And forged bundles, correctly signed with a pinned key the tests mint themselves,
rejected at the step that catches them: an entry substituted out of the tree
(`inclusion` — the only check a valid export key cannot satisfy), a reversed
path, a wrong proof size, a wrong index, a duplicate `seq` (`proofs`), a
relabelled case and `scope=log` asserted over a subset (`scope`), a restated head
root (`head`), one of the two keys missing from the pin set (`pin`), and a
newline smuggled into a header value (`preimage`). A control case signs a
consistent bundle the same way and verifies, so each failure is the check under
test rather than the harness.

What this still does not prove: no **product** has written a v2 bundle. The v2
vectors come from a scratch Go emitter and, since the producer landed, from
`mnr bundle export`, which reproduces the Go emitter's root, `sha256_chain` and
all twelve proof paths over the same entry lines (Appendix B). Two encoders
written from this document and agreeing byte for byte is stronger evidence than
one, but neither is `slate`. When it first issues v2, its bundle should join
these fixtures rather than replace the evidence that the format is portable.

### 6.3 Policy

1. **Never re-issue.** A v1 bundle stays v1. Re-signing it under v2 would produce
   a new `generated_at` and `bundle_id` and a new claim about an old export; if new
   evidence is needed, generate a new bundle and keep the old file.
2. **The v2 verifier carries the v1 path permanently.** `bundle/legacy_v1.go`
   plus committed fixtures: the two `.ndjson` files and the public key from the
   rehearsal, checked in as test vectors so the recipe cannot rot.
3. **Do not make old verifiers accept v2.** No tolerance shim, no fallback parse.
   Failure is the correct outcome (measured above); a compatibility layer would
   mean the old verifier "accepting" a document whose bytes it never checked.
4. **Default to v2, keep an escape hatch for one release.** `slate export
   --format=1` for agencies whose counterpart cannot verify v2 yet. The flag is
   removed at the next minor version, not deprecated silently.

### 6.4 Before an agency's first v2 bundle

- generate the agency export key pair; publish the public half to counterparties;
- pin the node's `signer_key` alongside it (two pins, §4.7 step 3);
- keep the last v1 verifier binary on hand until every counterpart has moved;
- replace the example header in the product documentation with a real bundle's
  header — including a real `sha256_chain`.

## 7. Where the code goes

In the extracted core (P0-2), as a new package:

| Path | Contents |
|---|---|
| `bundle/bundle.go` | header and proof types, `Encode`, `Decode` (streaming, line-oriented) |
| `bundle/canonical.go` | the §4.3 preimage, one function, no encoder dependency |
| `bundle/sign.go` | `Sign(*Bundle, ed25519.PrivateKey)`; refuses values containing CR/LF |
| `bundle/verify.go` | §4.7 as one function: `Verify(file []byte, pins []ed25519.PublicKey) error` |
| `bundle/legacy_v1.go` | §6.1, separate entry point, called only when `format` is absent |
| `bundle/testdata/` | the rehearsal vectors: v1 kiss, v1 slate, v2, plus their pinned keys |

`Verify` takes bytes and public keys. It must not open a store, a key file or a
directory: the whole point is that a recipient with no access to the node can run
it. That constrains the package: entries are carried as raw JSON lines
(`json.RawMessage`), never as `store.Entry`, so `bundle` imports `merkle` and
nothing else from the module and cannot accidentally require the log or the AES
key. Steps that need entry fields (§4.7 step 7, `seq`, `data.case_number`) decode a
local two-field struct from the line they already have.

Consumers:

- **`slate`** stops owning `internal/export`. Its `export`, dashboard and API paths
  call `bundle.Sign`/`Encode`; `slate verify-bundle` and the dashboard gain a
  verify view that calls `bundle.Verify`. The local `verify` subcommand keeps
  checking the store, which is a different question.
- **`kiss-protocol`** keeps `cmd/witness` and `store.Export`/`VerifyExport`;
  `internal/pd/export` is deleted with the `witness-pd` retirement (P0-3's second
  half).
- **`mirror-node-reconnaissance`** now carries a reference producer. Its ledger
  is a different primitive — SHA-256 fingerprints, no Merkle tree and no signed
  head — so the producer reads a whole-log NDJSON in the store shape rather than
  that ledger, and this crate is a second implementation of §4, not the product
  path. The Go `bundle` package above is still where `slate` and `kiss` land;
  P2-5 still asks whether the ledger should exist at all.

Outside that package, and deliberately not shipped with it:
`tools/bundle-verify/` in this repository holds the Python verifier and its
vectors (§6.2). It is a cross-check, not a distribution path — products call
`bundle.Verify` — but it is the only artifact that can notice §4.3 drifting back
into an encoder detail, so it stays and is re-run whenever the format changes.

Version: a new package on a tagged module is a minor bump — `witness v1.1.0`,
after `v1.0.0` from P0-2. Nothing in `store`, `merkle`, `signer` or `encrypt`
changes.

One CLI decision belongs to P0-3's second half and is not made here: whether the
canonical verifier ships as `witness bundle verify <file> --pin <hex>` in the
core, as `slate verify-bundle`, or both as thin wrappers. The format is
indifferent; the recommendation is the core binary as the canonical artifact,
because a verifier should not require installing the product whose records it is
checking.

## 8. What this schema does not do

- **One bundle is one log head.** A case whose items moved between two nodes is
  two bundles and a manifest. `slate`'s transfer bundle (`SealedBundle` over
  X25519 plus AEAD) is the transport artifact for the hand-off, not the court
  artifact; it should not be mistaken for this format, and its
  verify-against-enrolled-key discipline should be copied into the manifest when
  that gets designed (P1).
- **Timestamps stay self-reported.** `log_head.ts` and `generated_at` are the
  node's and the exporter's own statements. A court-facing claim of "this existed
  by date X" needs an external attestation (RFC 3161 over the head root, stored
  beside the bundle). Not designed here.
- **Entries are plaintext** once filtered out of the log — which is intended for a
  disclosure, but means the bundle is not a secure container. Transport and
  storage are the agency's problem.
- **Deleting the log does not invalidate issued bundles**, and is not detectable
  from the bundle alone. That is a retention question, not a format one.
- **No licence position.** §7 of [CONSOLIDATION.md](CONSOLIDATION.md) still gates
  the code move.

## 9. Decisions needed from you

1. **v2 as the survivor**, rather than "v1 plus proofs bolted on". The
   recommendation is v2: v1's preimage is the defect, and patching proofs into it
   leaves the encoder dependency and the missing format marker in place.
2. **`scope`**: is a whole-log bundle (`scope=log`) wanted in the police product,
   or is every bundle case-scoped? Keeping `scope` costs one field and lets the
   farm and playground use the same format honestly.
3. **Two key roles, two pins.** Proposed: head signed by the node, bundle by the
   exporter, both required in the pinned set. If an agency insists on a single
   key, the format still works — the verifier just pins one key twice — but the
   field stays, so a verifier never has to assume the roles are the same.
4. **`export_actor`/`export_role` inside the signature.** Proposed: yes. `slate`
   already records them in the audit log, but the audit log stays with the agency,
   so today the artifact does not say who exported it.
5. **Where the verifier binary lives** (§7, last paragraph).

## 10. Definition of done

- `bundle/` in the `witness` module at `v1.1.0`, with the §4.7 verifier and the
  §6.1 legacy verifier, both covered by the rehearsal vectors.
- `slate` issues v2 by default; `--format=1` exists for one minor version.
- `internal/pd/export` and `cmd/witness-pd` deleted; `kiss-protocol` no longer
  contains a second court-export implementation.
- One merged `docs/court-export.md` describing `witness-bundle/2` and the v1
  verification rule, with the empty-hash example replaced.
- **An independent implementation verifies a `slate`-issued bundle.** Done:
  `tools/bundle-verify/` verifies the `slate`- and `kiss`-issued v1 fixtures and
  the v2 vectors, and rejects forged bundles (§6.2). Keep it — it is the only
  thing that can tell a deliberate change to §4.3 from an accident of one
  encoder. Its remaining gap is stated there: no v2 fixture has been written by
  a product yet.
- **A reference producer exists.** `core/bundle/` encodes and signs §4, and
  `mnr bundle export` writes a bundle whose output the independent verifier
  accepts (§6.2, Appendix B). This shows the format is implementable outside Go;
  it does not satisfy the `witness` module item above, and products still write
  v1 until that lands.

## Appendix A — claims and where to check them

| Claim | Where | Look for |
|---|---|---|
| Neither export package has tests | `kiss-protocol/internal/pd/export/`, `slate/internal/export/` | one `export.go` each, no `_test.go` |
| Signature excludes the signature key | both `export.go` | `bundlePayload` zeroing `Signature`; `omitempty` on the field |
| `sha256_chain` is never checked | both `export.go` | `Verify` verifies the signature only |
| Zero-entry bundles sign `"entries":null` | both `export.go` | `Entries` has no `omitempty`; `Generate` leaves the slice nil |
| Entry bytes differ across products | `kiss-protocol/internal/store/store.go`, `slate/internal/store/store.go` | kiss `Entry` has no `PrevHash`; slate's does, with no `omitempty` |
| Bundles carry no head or proof | both `export.go` | `Bundle` fields |
| No bundle verifier in either CLI | `kiss-protocol/cmd/witness-pd/main.go`, `slate/cmd/slate/main.go` | no `verify` case reaches a bundle; `runVerify` calls `VerifyChain`/`VerifyHead` |
| A verifiable bundle already exists | `kiss-protocol/internal/store/export.go` | `Export`, `VerifyExport`, `ExportFormat`, `verifyHeadSignature` |
| Pin rule to copy | `slate/internal/peer/peer.go` | `TransferBundle.SenderPubKey` comment |
| Head signature covers two fields | `kiss-protocol/internal/store/store.go` | `TreeHead` vs `treeHeadSigInput` |
| Proof primitives | `kiss-protocol/internal/merkle/proof.go` | `Prove`, `Verify`, `Proof{Index,Size,Path}` |

## Appendix B — rehearsal log

Scratch clones of both repositories, plus Go 1.25.3 in `/tmp/goroot`. Nothing was
committed to either repository; the scratch tests are throwaway and named `p03_*`.

```
# emit and verify v1 bundles, both shapes, with tamper controls
P03_DIR=/tmp/p03/out go test ./internal/pd/export/ -run TestP03LegacyBundle -v
  kiss bundle: 2 entries, 904 bytes, recipe verifies
  same case, two chain values: kiss=31ec34bc… slate=5de17268…
  slate-shaped bundle: 2 entries, 1118 bytes, recipe verifies
  tamper_entry PASS  drop_entry PASS  relabel_case PASS  wrong_key PASS

# same recipe, compiled inside the slate module
P03_DIR=/tmp/p03/out go test ./internal/export/ -run TestP03SlateIssuedBundle -v
  slate-issued bundle: 2 entries, 888 bytes, recipe verifies
  package Verify and byte recipe agree on the same file
  kiss-issued bundle verified inside the slate module: 2 entries, 904 bytes

# empty bundle
  empty bundle: 429 bytes, entries=0, sha256_chain=e3b0c44298fc1c149afbf4c8996f…

# v2 prototype against a real store with a software signer
go test ./internal/pd/export/ -run TestP03V2Prototype -v
  v2 bundle: 4 case entries from a 500-entry log, 4308 bytes, verifies
  witness-export/1 for the same log: 500 leaf hashes, 125953 bytes
  head alone: 483 bytes; proofs array: 2585 bytes for 4 proofs (9 hashes each)

# size breakdown of that log, witness-export/1 as it stands
  full export=125953 bytes: head=483 leaf_hashes=33501 (500) entries=91833 (500)
  case entries: 4, entry lines=734 bytes
  edit an entry PASS  strip proofs PASS  swap an entry PASS
  rewrite the head root PASS  unpinned key PASS  pin one key PASS
  v1 verifier rejects a v2 bundle PASS — signature verification failed

# independent verifier: Python 3.12, standard library only, from the spec
python3 -m unittest discover -s tools/bundle-verify
  Ran 49 tests  OK

python3 tools/bundle-verify/verify_bundle.py testdata/v1-kiss.ndjson --pin …
  VERIFIED               904 B, kiss-issued
python3 … testdata/v1-slate.ndjson --pin …
  VERIFIED               889 B, slate-issued
python3 … testdata/v1-kiss-empty.ndjson --pin …
  VERIFIED               419 B, entries=0
python3 … testdata/v1-unsigned.ndjson
  UNAUTHENTICATED        761 B, exit 3
python3 … testdata/v2-case.ndjson --pin … --pin …
  VERIFIED               4301 B, 4 entries, head 500 leaves
python3 … testdata/v2-log.ndjson --pin … --pin …
  VERIFIED               5895 B, 12 entries, head 12 leaves
python3 … testdata/v2-seven.ndjson --pin … --pin …
  VERIFIED               3560 B, 7 entries, 3-hash audit paths

# reference producer written from §4 in Rust: core/bundle, mnr bundle export
cargo run -p mnr-cli --bin mnr -- bundle keygen --out /tmp/node.key
cargo run -p mnr-cli --bin mnr -- bundle keygen --out /tmp/exporter.key
  seed files created 0600; public keys printed for pinning
cargo run -p mnr-cli --bin mnr -- bundle export \
  --log /tmp/farm-entries.ndjson --out /tmp/rust-log.ndjson --scope log …
  head root 0b0250f7…, 12 entries
python3 … /tmp/rust-log.ndjson --pin … --pin …
  VERIFIED               5895 B; root, sha256_chain and all 12 proof paths
                         identical to v2-log.ndjson, written by the Go emitter
python3 … /tmp/rust-case.ndjson --pin … --pin …
  VERIFIED               2052 B, 3 of 7 entries, indices 1/4/6 at seqs 2/5/7
refused: newline in --department (exit 1), --scope case without --case (exit 2),
         overwrite of an existing bundle (exit 1), a log with a seq gap (exit 1)

# tree shapes: one scope=log bundle per log size, from real stores
n=1 path_len=0  n=2 path_len=1  n=3 path_len=2  n=4 path_len=2
n=5 path_len=3  n=6 path_len=3  n=7 path_len=3  n=8 path_len=3
  all eight VERIFIED by the independent verifier

# forged but correctly signed with a freshly minted, pinned key
  entry substituted out of the tree   FAILED at inclusion
  proof path reversed                 FAILED at inclusion
  proof size 4 over a 500-leaf head   FAILED at proofs
  proof index 1 for seq 1             FAILED at proofs
  duplicate proof seq                 FAILED at proofs
  case relabelled CASE-A → CASE-B     FAILED at scope
  scope=log asserted over a subset    FAILED at scope
  head root restated                  FAILED at head
  pin set holding one of two keys     FAILED at pin
  newline in a header value           FAILED at preimage
  control, signed and consistent      VERIFIED
```

The fixtures are checked in at `tools/bundle-verify/testdata/`. The Go emitters
were scratch programs (one per repository, plus one written from §4 for the v2
shapes) and are not kept, because a fixture is only useful if it is what a
producer expected to write at that snapshot. The two `v2-rust-*` files were
written by the committed producer instead: the seeds for that run were generated
in `/tmp` and discarded, and only the two public keys are kept beside them.

Tests: 11 Go subtests across the three scratch files, 20 `mnr-bundle` tests, 2
CLI integration tests and 49 Python tests across the verifier suite, all green at
the snapshot above. Every number quoted in this document comes from one of those
runs.
