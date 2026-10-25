# `slate-v2-port` — a `witness-bundle/2` producer for slate

`slate` v1.5.0 (`c198ce0`) writes court exports as v1: one Ed25519 signature over
the JSON encoding of the whole document, no head, no proofs. This is the port that
makes it write [`witness-bundle/2`](../../BUNDLE_SCHEMA.md) instead, by default, in
both the CLI and the HTTP API.

It is a patch rather than a commit because `slate` is a separate repository and is
not connected to the session that produced this: the only repository this
workspace can push to is `mirror-node-reconnaissance`. The patch applies cleanly
to a fresh clone at the stated base and its tests pass there.

```
git clone https://github.com/bigblue-r4/slate
cd slate && git checkout c198ce0
git apply slate-v2-producer.patch
go test ./...
go build -o slate ./cmd/slate
```

Base: `c198ce0` — *release: v1.5.0 — signed truncation anchor*.
Patch: `slate-v2-producer.patch` — 2,396 lines added, 78 removed, across 34 files.
Toolchain used: Go 1.25.3 (the module declares `go 1.22`).

## What it changes

| Path | Change |
|---|---|
| `internal/bundle/merkle.go` | new — BLAKE3 Merkle tree, RFC 6962 split, leaf-first audit paths |
| `internal/bundle/bundle.go` | new — header, §4.3 preimage, signed head, per-entry proofs, encoding, `O_EXCL` write |
| `internal/bundle/bundle_test.go` | new — 9 tests: preimage bytes, tree paths 1–9 leaves, case filtering, both signatures, refusals |
| `internal/bundle/vectors_test.go` | new — 9 tests: the shared vectors read back, the §4.7 steps as a reader, every refusal |
| `internal/bundle/testdata/` | new — the six v2 vectors and their public keys, copied from `tools/bundle-verify/testdata/` |
| `cmd/slate/main.go` | `export` defaults to v2, `--format=1` escape hatch; `/api/export` defaults to v2 with `"format": 1`; `exportSigningKeys` |
| `cmd/slate/export_integration_test.go` | new — 4 tests: API default, legacy path, unknown format, output location |
| `internal/export/export.go` | `DecodePrivateKey` extracted from `Sign`; `WriteNDJSON` now reports a failed close |
| `cmd/slate/main.go`, `internal/{discovery,store}/…` | the 28 unchecked errors that kept `slate`'s lint step red — see [below](#the-lint-gate) |
| `README.md`, `docs/*` | export usage, the format, how to verify, the legacy flag |

Behaviour:

- **Two keys, two roles.** The node identity key (`SLATE_NODE_KEY`, or the sealed
  `nodekey.enc` created by `slate init`, via `resolveNodeKey`) signs the tree head
  over `size_be8 ‖ root`. `SLATE_SIGN_KEY` signs the header; when it is unset the
  node key signs both, which §5 permits and the format never lets a verifier
  assume otherwise.
- **v2 is always signed.** `--sign` now only affects the legacy path; it is kept
  so existing scripts do not break.
- **Entries are the store's bytes.** Lines are `json.Marshal` of the store entry,
  the same bytes the store chained at append time, and are never reformatted.
- **A new bundle is never overwritten.** Writes use `O_CREATE|O_EXCL`; v1 used
  `os.Create` and would replace a file at the same path.
- **Refusals.** A header value containing CR/LF, a sequence gap, a case scope with
  no case number, or a log scope with one is an error, not a coercion.
- **Case scope only, for now.** The package supports `scope=log`, but slate's CLI
  and API remain case exports; no new flag exposes whole-log disclosure.

## Evidence

Run in the scratch clone, and again in a fresh clone after `git apply`:

```
$ go vet ./...
(no output)
$ gofmt -l cmd internal
(no output)
$ go test ./...
ok  github.com/bigblue-r4/slate/cmd/slate
ok  github.com/bigblue-r4/slate/internal/apiwire
ok  github.com/bigblue-r4/slate/internal/bundle
ok  github.com/bigblue-r4/slate/internal/discovery
ok  github.com/bigblue-r4/slate/internal/evidence
ok  github.com/bigblue-r4/slate/internal/peer
ok  github.com/bigblue-r4/slate/internal/query
ok  github.com/bigblue-r4/slate/internal/store
$ golangci-lint run ./...
0 issues.
```

18 tests and 35 subtests in `internal/bundle`, 4 more in `cmd/slate`. No new
dependency: the package still imports only `internal/store`, the standard library
and BLAKE3.

End to end, against a real store built with `slate init` and three intakes:

```
$ SLATE_DIR=/tmp/e2e slate export --case CASE-2026-0042
Export bundle: BUNDLE-20261025-0a24c202
  Format      : witness-bundle/2 (scope=case, 2 of 4 entries)
  Head root   : 3b626afaf51461307c52efe5920369ff19d8939ef9b76226ae0c2db1af133d5c
  Pin         : --pin a1cf842dfdf9471d…

$ python3 tools/bundle-verify/verify_bundle.py <bundle> --pin <node key>
format            witness-bundle/2
entries           2
                  head: 4 leaves, root 3b626afaf5146130…
                  pins: bundle a1cf842dfdf9471d…, head a1cf842dfdf9471d…
RESULT            VERIFIED
```

With a separate export key (`SLATE_SIGN_KEY` set), the two pins differ and both
are checked:

```
                  pins: bundle ffb0897094f5c0fb…, head a1cf842dfdf9471d…
RESULT            VERIFIED
```

The escape hatch still produces a verifiable legacy bundle, reported honestly:

```
$ slate export --case CASE-2026-0042 --format 1
$ python3 tools/bundle-verify/verify_bundle.py <bundle>
format            witness-bundle/1 (legacy)
                  no signature: sha256_chain is carried inside the document …
RESULT            UNAUTHENTICATED
exit 3
```

The two-key, four-record export is committed as
[`tools/bundle-verify/testdata/v2-slate.ndjson`](../bundle-verify/testdata/v2-slate.ndjson)
with its public keys, and the Python suite verifies it on every run. That closes
the schema's stated gap — until now no product had written a v2 bundle — with the
caveat that the product is `slate` **with this patch applied**, not upstream.

## The lint gate

`slate`'s CI runs `golangci-lint` as its last step, and at `c198ce0` that step
**fails**: 28 unchecked-error findings in `cmd/slate`, `internal/discovery`,
`internal/store` and `internal/export`. (It reports 16, because golangci-lint
caps identical findings at three by default; `--max-same-issues=0` shows all 28.
Which is why a patch that fixed only the reported 16 would leave the gate red
and looking correct.)

None of them is v2 work. They are folded in because a patch whose CI is red
cannot show that its own tests ran under CI, and because the reader of a
"verified" table deserves to know which steps actually pass. `golangci-lint`
v2.15.0 with default linters, after the patch: **0 issues**.

| Finding | Sites | Fix |
|---|---|---|
| `defer f.Close()` on a file only read | 2 in `store.go` | discarded in a closure — a read-only close error tells the caller nothing |
| `defer conn.Close()` on a UDP socket | 2 in `discovery.go` | discarded; the socket dies with the process |
| `defer ev.Close()` in a CLI command | 14 in `main.go` | discarded; `Store.Close` already discards its own `Sync` error, so there is nothing to propagate |
| `defer resp.Body.Close()` | 1 in `main.go` | discarded; the body is read to completion before the defer runs |
| SSE `fmt.Fprint` / `Fprintf` | 3 in `main.go` | **checked**, and the handler returns — a failed write means the client is gone, so the loop should stop rather than tick on |
| `fmt.Fprintf` into a `sha256.Hash` | 1 in `main.go` | discarded as `_, _ =`; `hash.Hash.Write` documents a nil error |
| `os.Remove` of the temp head | 1 in `head.go` | discarded; whether the rename succeeded is the result that matters |
| `tmp.Close()` after a failed write or sync | 2 in `head.go` | discarded; the write error is the one being returned |
| `f.Close()` in a test helper | 1 in `head_test.go` | `t.Fatalf` |
| `defer f.Close()` in `WriteNDJSON` | 1 in `export.go` | promoted to the return value through a named result — a close failure can mean the last record never landed, and that file is the evidence |

The one finding the patch itself introduced — `QF1012` on a
`WriteString(fmt.Sprintf(...))` in `Preimage` — is fixed with
`strconv.FormatUint`.

## Tests that run in slate's CI

The six v2 vectors and their public keys are copied into
`internal/bundle/testdata/`, and `vectors_test.go` carries the verifier's half of
§4.7 — a reader, not a second producer — so the format is checked on every change
to `slate`, in `slate`'s own CI, with no other repository in the loop. The
listing in `slate`'s `ci.yml` runs `gofmt -l`, `go test ./...`, `go build`, `go
vet` and `golangci-lint`; these tests are inside that.

| Test | What it holds |
|---|---|
| `TestSharedVectorsVerify` | all six vectors verify against their pins: entry counts, head sizes, `seq`s, audit-path lengths |
| `TestProducersAgreeOnTheSameEntryLines` | the Rust and scratch-Go log bundles over the same twelve lines have equal roots and equal `sha256_chain` |
| `TestTheTreeAgreesWithFullLogVectors` | slate's own tree, rebuilt over those entry lines, reaches the same root and the same paths hash for hash (12 and 7 leaves) |
| `TestTheSlateVectorUsesTwoKeys` | the one product-written vector has distinct node and exporter keys, so the two-pin rule is exercised rather than assumed |
| `TestContainerAndDigestFailures` | CRLF, a missing final newline, a blank line, a stripped or unknown `format`, an edited entry (digest), a dropped entry (count) |
| `TestProofFailures` | stripped proofs, a duplicate `seq`, a proof naming another tree size, a wrong index, a reversed path (inclusion) |
| `TestBothPinsAreRequired` | no pins, either pin alone, an unrelated pin |
| `TestScopeFailures` | an unknown scope, `scope=log` over a subset, `scope=case` without a case number, a relabelled case, a line break smuggled into a header value — each re-signed first, so the refusal is the check under test and not the signature |
| `TestADishonestExporterWithAPinnedKey` | a pinned but dishonest exporter: a substituted entry fails at inclusion, a restated head fails at the head signature, and an empty case bundle still verifies |

The control case in `TestScopeFailures` signs an unmodified bundle and expects
`VERIFIED`, so the failures below it cannot be the harness refusing everything.
Three sabotages confirm the vectors bite rather than merely pass: leaf prefix
`0x00` → `0x02` fails at inclusion, swapping `hashNode(sibling, running)` for
`hashNode(running, sibling)` fails at inclusion, and exchanging two fields in
`preimageOf` fails at signature.

## What this does not do

- **It is not merged.** The fixture's provenance is this patch. When it lands in
  `slate`, regenerate the fixture from the released binary so the vector is what a
  product writes, not what a patched clone wrote.
- **It is not the extraction.** `BUNDLE_SCHEMA.md` §7 puts the bundle code in the
  extracted `witness` module, and `slate` is supposed to stop owning export. This
  puts a self-contained package in `slate` because that module does not exist yet;
  `internal/bundle` imports only `internal/store` and the standard library plus
  BLAKE3, so it can move out without changing its API.
- **The head is minted at export time** from the log on the node. A truncated log
  yields a smaller, valid bundle. Retaining a head outside the node at seal time
  is still missing.
- **No live-server test.** The API path is covered with `httptest` against the
  real handler, not by running `slate serve` and posting to it.
- **No dashboard work.** The dashboard's export button still calls `/api/export`
  and therefore gets v2 by default; no format is displayed.
- **The vectors now exist twice.** `tools/bundle-verify/testdata/` stays
  authoritative for the Python cross-check and the copies in `slate` are what its
  CI reads; a format change has to regenerate both, and the Go copy is only as
  good as the last time someone did.
