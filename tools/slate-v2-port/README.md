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
Patch: `slate-v2-producer.patch` — 1,242 lines added, 49 removed, across 12 files.
Toolchain used: Go 1.25.3 (the module declares `go 1.22`).

## What it changes

| Path | Change |
|---|---|
| `internal/bundle/merkle.go` | new — BLAKE3 Merkle tree, RFC 6962 split, leaf-first audit paths |
| `internal/bundle/bundle.go` | new — header, §4.3 preimage, signed head, per-entry proofs, encoding, `O_EXCL` write |
| `internal/bundle/bundle_test.go` | new — 9 tests: preimage bytes, tree paths 1–9 leaves, case filtering, both signatures, refusals |
| `cmd/slate/main.go` | `export` defaults to v2, `--format=1` escape hatch; `/api/export` defaults to v2 with `"format": 1`; `exportSigningKeys` |
| `cmd/slate/export_integration_test.go` | new — 4 tests: API default, legacy path, unknown format, output location |
| `internal/export/export.go` | `DecodePrivateKey` extracted from `Sign` |
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
```

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
