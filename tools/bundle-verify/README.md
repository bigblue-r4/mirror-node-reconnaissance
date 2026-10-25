# `bundle-verify` — an independent court-bundle verifier

A verifier for the two court-export bundle formats, written from
[BUNDLE_SCHEMA.md](../../BUNDLE_SCHEMA.md) and sharing no code, no dependency
and no build system with the Go producers. That independence is the point: the
claim under test is that `witness-bundle/2` is a specification rather than one
repository's encoder, and a verifier in the same language as the encoder cannot
show that. It closes the last item of §10 of the schema document. Since the Rust
producer landed (`core/bundle`, `mnr bundle export`), the v2 half is also checked
across two implementations: fixtures written by that producer are verified here
and compared field by field against the Go emitter's fixtures.

It handles two things:

- **`witness-bundle/2`** — the proposed format: a signed line preimage, a copy
  of the node's signed tree head, and one Merkle inclusion proof per entry.
- **legacy v1** — bundles already issued by `kiss-protocol/internal/pd/export`
  and `slate/internal/export`, verified from their own bytes by the rule in
  §6.1. Nothing is re-signed and no second binary is needed.

Python 3, standard library only — no packages, no `requirements.txt`, tested on
CPython 3.12. BLAKE3 and Ed25519 are implemented here, so there is nothing to
install and nothing to trust but `hashlib`.

## Usage

```console
$ python3 verify_bundle.py BUNDLE.ndjson --pin HEX [--pin HEX ...]

$ python3 verify_bundle.py tools/bundle-verify/testdata/v1-slate.ndjson \
      --pin cbd37e856ba7e4cc41d6f0a8e3cbc44d…
  format            witness-bundle/1 (legacy)
  bundle_id         BUNDLE-20261025-bd37e9ec
  generated_at      2026-10-25T17:01:39.009336314Z
  case_number       CASE-2026-0042
  agency            Honolulu Police Department
  node_id           node-001
  entries           2
                    legacy v1: no format marker, no log head, no inclusion proof
                    signature: OK with pinned key cbd37e856ba7e4cc…
  RESULT            VERIFIED
```

A v2 bundle needs two pins — the exporter's key and the node's — because it
carries two signatures:

```console
$ python3 verify_bundle.py testdata/v2-case.ndjson \
      --pin "$(cat testdata/v2-case.export.pub)" \
      --pin "$(cat testdata/v2-case.node.pub)"
  format            witness-bundle/2
  bundle_id         BUNDLE-20260512-4e1a7c02
  case_number       CASE-A
  entries           4
                    head: 500 leaves, root 3b7aad9e7f71e3f6…
                    pins: bundle 78e37a81fa6d3898…, head c225f89837ee6c70…
  RESULT            VERIFIED
```

Success is only ever reported with both pins present and both signatures
checked. A bundle that names its own key proves nothing.

## Exit status

| Code | Meaning |
|---|---|
| `0` | `VERIFIED` — every check passed, including a pinned signature |
| `1` | `FAILED` — the file does not support the claim it makes; the step that failed is printed |
| `2` | `ERROR` — unreadable file or bad arguments |
| `3` | `UNAUTHENTICATED` — a legacy bundle with no signature |

`--quiet` prints only the status word, for use in a script.

`UNAUTHENTICATED` is deliberately not `0`. A v1 bundle whose signature was
optional (`--sign` never passed) still carries a `sha256_chain`, but that digest
travels inside the document it describes: it catches corruption and not editing.
Reporting it as verified would be a lie a court could repeat.

## What it checks

**`witness-bundle/2`** — §4.7 of the schema, in that order, each step named in
its output so a failure maps to a paragraph:

1. split lines; reject CRLF, a blank line, or a missing final newline
2. dispatch on `format`; an unknown value is refused, never guessed at
3. both `signed_by` and `log_head.signer_key` are in the pinned set
4. the bundle signature verifies over the §4.3 preimage rebuilt from the header
5. `entry_count` equals the number of entry lines, and `sha256_chain` equals
   SHA-256 over those lines as written
6. `log_head.sig` verifies over `size_be8 ‖ root` with the head's own key
7. `scope` is `case` or `log`; under `case`, every entry's
   `data.case_number` equals the header's, and under `log`, `entry_count`
   equals `log_head.size`
8. every entry line has exactly one proof, `proof.size` matches the head,
   `proof.index == seq - 1`, and the audit path recomputes the signed root from
   `BLAKE3(0x00 ‖ line bytes)`

**legacy v1** — §6.1, five steps:

1. split lines, header and entries
2. cut the `,"signature":"…"` element from the header, keeping the preceding
   comma
3. splice the entry lines into the `"entries":null` placeholder — and leave
   `null` alone when there are no entries, because that is what a zero-entry
   bundle signed
4. `entry_count` equals the line count; `sha256_chain` equals SHA-256 over the
   entry bytes
5. a pinned key verifies the signature over that rebuilt payload

## Test vectors

`testdata/` holds bundles emitted by the producers themselves. The keys are
throwaway and the records are fictional.

| File | Producer | Size | Exercises |
|---|---|---|---|
| `v1-kiss.ndjson` | `kiss-protocol/internal/pd/export` | 904 B | 2 entries, HTML-escaped `&`/`<`/`>` inside `data`, non-ASCII |
| `v1-slate.ndjson` | `slate/internal/export` | 889 B | 2 entries with `prev_hash`, plus `agency` and `seal` |
| `v1-kiss-empty.ndjson` | kiss | 419 B | zero entries: the signed payload keeps `"entries":null` |
| `v1-unsigned.ndjson` | kiss | 761 B | never signed; must report `UNAUTHENTICATED` |
| `v2-case.ndjson` | scratch emitter, §4 | 4,301 B | `scope=case`, 4 entries out of a real 500-record log, 9-hash audit paths |
| `v2-log.ndjson` | scratch emitter, §4 | 5,895 B | `scope=log`, all 12 entries, `entry_count == log_head.size` |
| `v2-seven.ndjson` | scratch emitter, §4 | 3,560 B | a 4+3 split whose right subtree splits again; 3-hash paths |
| `v2-rust-log.ndjson` | `mnr bundle export` (Rust) | 5,895 B | the same 12 entry lines as `v2-log.ndjson`; root, chain and proofs must match it |
| `v2-rust-case.ndjson` | `mnr bundle export` (Rust) | 2,052 B | 3 entries out of 7 at seqs 2, 5, 7; indices 1, 4, 6 |
| `v2-slate.ndjson` | `slate export` (Go, `tools/slate-v2-port`; v2 is the default there) | 2,087 B | 2 entries out of 4 from the product's own store; distinct node and exporter keys, both pinned |

The three scratch-emitter files were written by a Go program built from §4
alone, then deleted; the bundles and their public keys are kept as frozen
vectors. The two `v2-rust-*` files were written by the committed Rust producer;
the keys for that run were generated in `/tmp` and discarded, so only the public
halves are kept. `v2-slate.ndjson` comes from slate's real export path with the
default format flipped to v2, driven through `slate add` and `slate interpose`
rather than a fixture reader. Regenerate a fixture when the format changes — do
not hand-edit one, because a fixture that no longer matches what a producer
writes is a test that proves nothing.

These files are also committed into the `slate` patch in `tools/slate-v2-port/`
as `internal/bundle/testdata/`, where `internal/bundle/vectors_test.go` walks
§4.7 as a reader and checks them in Go on every `slate` CI run. This suite stays
authoritative — it is the one written in a different language from every producer
— so a format change has to regenerate both copies.

## Tests

```console
$ python3 -m unittest discover -s tools/bundle-verify -v
...
Ran 50 tests in 0.9s
OK
```

The suite covers:

- **BLAKE3** against the published empty and `abc` vectors and against 16
  lengths produced by `lukechampine.com/blake3`, the library both producers use
  — including 102,400 bytes, which spans 100 chunks and so exercises the tree
  and the root flag rather than a single compression.
- **Ed25519** against signatures made by Go's `crypto/ed25519`, cross-checked
  against the `cryptography` package when it is installed (skipped otherwise),
  plus rejection of a non-canonical scalar.
- Every fixture, and the four v1 failure modes that matter: an edited entry, a
  dropped entry, a relabelled `case_number`, an unrelated key.
- Malformed containers: CRLF, no trailing newline, a missing `entries`
  placeholder, an unknown `format` value, and a v2 bundle with its `format`
  stripped — which must be refused rather than quietly re-read as legacy.
- **Forged but properly signed bundles.** Editing a fixture's bytes is not
  enough to reach the inclusion check, because `sha256_chain` covers the entry
  lines and is itself signed. So the tests mint a key, sign their own headers
  and ask what a *dishonest exporter* can do: substitute an entry that is not a
  leaf of the node's tree, reverse a proof path, claim the wrong proof size or
  index, relabel the case, claim `scope=log` over a subset, or restate the head.
  A control case signs a consistent bundle first, so each failure is the check
  under test and not the harness. An empty case bundle signed the same way
  verifies too — no entries, no proofs, the head still checked.

## Cost

Measured on this machine, CPython 3.12:

| Operation | Time |
|---|---|
| verify `v2-case.ndjson` (4 proofs, 2 signatures), end to end | ~60 ms |
| one Ed25519 verification | ~4 ms |
| BLAKE3, 1 KiB | ~1.3 ms |
| BLAKE3, 100 KiB | ~155 ms |

Pure-Python BLAKE3 is roughly three orders of magnitude slower than the
compiled library, which is irrelevant for a bundle of a few hundred KB and
matters if someone points this at a whole-log export of a million records. The
Go `bundle` package is the fast path; this is the cross-check.

## Limits

- **Verification only.** Nothing here signs, and the pure-Python Ed25519 is not
  constant-time. It handles public data only: no private key, no secret, no
  memory-wiping concern. Do not lift it into a signing path.
- **It does not check that the head is the log's latest head.** The head's MAC
  is BLAKE3-keyed by the node's machine key and is deliberately not carried
  (§4.2), so a verifier without that key cannot tell a current head from an old
  one — only that the node signed it. Freshness needs the node or an external
  attestation.
- **Timestamps are unauthenticated.** `log_head.ts` sits outside the head
  signature and `generated_at` is the exporter's own statement. The verifier
  parses nothing about time and claims nothing about it.
- **Deleting the log does not invalidate an issued bundle**, and this verifier
  cannot detect it. Retention is not a format property.
- **One bundle is one log head.** A case spanning two nodes is two bundles.
- `scope=case` assumes `data.case_number` is a JSON string; a bundle whose
  entries carry a number there fails the scope check rather than being coerced.
