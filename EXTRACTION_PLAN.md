# P0-2 Extraction Plan: the `witness` module

**Implements:** [CONSOLIDATION.md](CONSOLIDATION.md) P0-2.
**Status:** rehearsed end to end in a scratch copy; not applied to any real repository.
**Rehearsal:** Go 1.25.3, linux/amd64, 2026-10-25. Every build, vet and test
command below was run and its result is in §10. Publishing, tagging and CI
changes were not executed.

## 1. What this plan moves, and what it does not

Move four packages out of `kiss-protocol/internal/`, publish them as one module,
and make three repositories depend on it:

| Consumer | Change | Status |
|---|---|---|
| `kiss-protocol` | 38 import lines in 27 files; delete four directories | **P0-2** |
| `harborlight-poultry-demo` | 3 import lines in 3 files; delete four directories + `SOURCE.md` + `scripts/` | **P0-2** |
| `sgail-playground/witness` | 10 import lines in 4 files; delete four directories + `SOURCE.md` + `scripts/` | **P0-2** |
| `slate` | none yet | **After P1-2**, not now — see §8 |

This is a **pure move**: package names, type names and signatures do not change,
so every consumer edit is an import string. Nothing in this plan fixes a bug,
improves a design, or changes behaviour. The defects in
[CONSOLIDATION §3.1](CONSOLIDATION.md) are fixed once, afterwards, in one place —
which is the reason to do the move first.

## 2. Target module

```
github.com/bigblue-r4/witness
├── go.mod
├── store/        package store      (8 files, 2,061 lines, 6 test files)
│   └── testdata/fuzz/FuzzAppend/68c721c847bc26f2
├── merkle/       package merkle     (5 files, 481 lines, 3 test files)
├── signer/       package signer     (5 files, 309 lines, 1 test file)
└── encrypt/      package encrypt    (2 files, 148 lines, 1 test file)
```

20 Go files, ~3,000 lines, 74 tests, one fuzz corpus entry. The module root holds
no Go files.

**Package names stay `store`, `merkle`, `signer`, `encrypt`.** Renaming them to
`log`/`tree`/`keys`/`frame` would read better and would also make every consumer
edit a code change instead of an import change. Do the rename, if at all, in a
later release; it is not part of P0-2.

### 2.1 `go.mod` — use exactly this

```
module github.com/bigblue-r4/witness

go 1.22

require (
	github.com/go-piv/piv-go v1.11.0
	golang.org/x/crypto v0.19.0
	lukechampine.com/blake3 v1.4.1
)

require github.com/klauspost/cpuid/v2 v2.0.9 // indirect
```

Three constraints are baked into that file, and each was verified:

- **`go 1.22`, not whatever `tidy` writes.** Started from an empty module,
  `go mod tidy` resolved `golang.org/x/crypto v0.58.0`, which forced
  `go 1.26.0` and downloaded a newer toolchain. Every consumer declares `go 1.22`;
  a core that demanded 1.26 would force an upgrade everywhere. Pinned as above,
  `go mod tidy` leaves the file unchanged.
- **`x/crypto v0.19.0` and `blake3 v1.4.1`** are what the consumers already use,
  so minimum-version selection changes nothing in their build lists.
- **`piv-go v1.11.0` must be declared, or `-tags piv` cannot build.** See §6.1.

No `toolchain` line: it forces a download on every consumer that lacks that exact
version, and the module has no need for one.

### 2.2 Tag plan

- Tag `v1.0.0` at the import of the four packages (single commit is fine).
- `v1.x` is additive only. The head-format work (P1-1, P1-2) ships as **v1.1.0**:
  the API does not break, the *data format* gains a version field, and the
  verifier reads both. That is a conscious trade — it keeps four consumers on one
  major version instead of splitting the fleet across `v1` and `v2` during a
  migration.
- If the API ever breaks, the module path becomes `github.com/bigblue-r4/witness/v2`;
  Go requires the suffix.
- The repository must be public for consumers and their CI to fetch it. If it is
  private, every consumer needs `GOPRIVATE=github.com/bigblue-r4/*` (and CI
  credentials). That is the one place P0-1 (licence) has a mechanical consequence.

## 3. Why the four packages can leave cleanly

Their dependency set is closed and small — verified by building the module alone:

| Package | Third-party | Internal |
|---|---|---|
| `merkle` | none (stdlib) | none |
| `signer` | `go-piv/piv-go` (behind `-tags piv` only) | none |
| `encrypt` | `golang.org/x/crypto/hkdf` | none |
| `store` | `lukechampine.com/blake3` | `merkle`, `signer`, `encrypt` |

No `config`, no `machid`, no `soul`, no `toml`. The extraction needs no interface
surgery, no dependency injection, no new seam.

Two consequences worth knowing:

- The four packages' own tests move with them (11 test files). Their import lines
  are rewritten inside the module, which is why the consumer footprint (38 lines
  in kiss) is smaller than the total number of occurrences (46): the difference is
  the tests that left.
- `store/testdata/fuzz/FuzzAppend/...` is the only non-Go artifact. Copy it with
  the directory or the fuzz target loses its seed corpus.

## 4. Step-by-step

Run from a scratch clone of each repository. Steps 1–2 create the module; steps
3–5 convert consumers; step 6 records it. Each consumer is one commit, and
nothing is pushed until every step's gate passes.

### Step 1 — create the module

```bash
git init witness && cd witness
go mod init github.com/bigblue-r4/witness

for p in store merkle signer encrypt; do
  mkdir -p $p
  cp -r ../kiss-protocol/internal/$p/. $p/
done

# Rewrite the intra-module imports.
find . -name '*.go' -exec sed -i -E \
  's#github.com/bigblue-r4/kiss-protocol/internal/#github.com/bigblue-r4/witness/#g' {} +
```

Then write §2.1's `go.mod` by hand, `rm go.sum`, and run `go mod tidy`. Tidy
should leave `go.mod` byte-identical; if it does not, stop and compare.

Package doc comments in the moved files still say things like "the
`kiss-protocol` store". Grep for `kiss-protocol` and `internal/` in the four
directories and fix the prose — this is the only non-mechanical edit in the whole
plan, and it is small.

### Step 2 — verify and tag

```bash
go build ./... && go vet ./... && go test ./...
go build -tags piv ./signer      # needs libpcsclite-dev; see §6.1
git add -A && git commit -m "witness: initial import from kiss-protocol v3.x"
git tag v1.0.0 && git push origin main --tags
```

Before tagging, confirm test parity: 74 top-level tests pass here and 74 pass in
`kiss-protocol` for the same four packages. That number is the acceptance test
for "nothing was left behind".

### Step 3 — convert `kiss-protocol`

```bash
git checkout -b extract-witness

rm -rf internal/store internal/merkle internal/signer internal/encrypt

find . -name '*.go' -exec sed -i -E \
  's#github.com/bigblue-r4/kiss-protocol/internal/(store|merkle|signer|encrypt)"#github.com/bigblue-r4/witness/\1"#g' {} +

go mod edit -require=github.com/bigblue-r4/witness@v1.0.0
go mod tidy
```

Use `#` as the `sed` delimiter and `-E`. With `s|…|…|` the alternation escapes
(`\|`) collide with the delimiter and the substitution silently matches nothing —
the plan's first rehearsal failed exactly this way and produced 27 files still
importing the deleted packages.

`go mod tidy` reshapes `go.mod`: `blake3` and `piv-go` become indirect (nothing in
kiss imports blake3 directly any more), and `x/crypto` stays direct only because
`cmd/witness-pd/main.go` still uses it — it may drop to indirect once P0-3 retires
that binary. Commit tidy's output rather than hand-editing the block ordering.

Gate:

```bash
go build ./... && go vet ./... && go test ./...
git grep -nE 'kiss-protocol/internal/(store|merkle|signer|encrypt)"' -- '*.go'   # must print nothing
```

### Step 4 — convert `harborlight-poultry-demo`

```bash
rm -rf internal/store internal/merkle internal/signer internal/encrypt \
       internal/SOURCE.md scripts

find . -name '*.go' -exec sed -i -E \
  's#github.com/bigblue-r4/harborlight-poultry-demo/internal/(store|merkle|signer|encrypt)"#github.com/bigblue-r4/witness/\1"#g' {} +

go mod edit -require=github.com/bigblue-r4/witness@v1.0.0
go mod tidy
```

After tidy, `x/crypto` and `blake3` are declared only as indirect, and `witness`
is the module's only direct requirement besides the standard library. That
collapse is the visible payoff of the extraction.

Keep `internal/farm` and `internal/pipelock`: they are the application. Only the
copied core goes — and per §6.6 the copied core is strictly older than what the
module replaces, so no fix is lost.

### Step 5 — convert `sgail-playground/witness`

Same shape; this one is a **nested module** (`sgail-playground/witness/go.mod` at
a subdirectory), so run everything inside `witness/` and remember its replacement
path is two levels up, not one:

```bash
cd witness
rm -rf internal/store internal/merkle internal/signer internal/encrypt internal/SOURCE.md scripts

find . -name '*.go' -exec sed -i -E \
  's#github.com/bigblue-r4/sgail-playground/witness/internal/(store|merkle|signer|encrypt)"#github.com/bigblue-r4/witness/\1"#g' {} +

go mod edit -require=github.com/bigblue-r4/witness@v1.0.0
go mod tidy
```

### Step 6 — record it

- `kiss-protocol`: note in `CHANGELOG`/`docs` that the log core now lives in
  `witness`, and delete any `docs/` text that describes `internal/store` as the
  home of the log.
- Both copies: delete `internal/SOURCE.md` **last**, after the dependency works —
  while the migration is in flight it is the only provenance record.
- `CONSOLIDATION.md` P0-2: mark done, record the tag.

## 5. CI gates to add (one per consumer, plus one in the core)

1. **No re-vendoring.** A step that fails the build if a copied core reappears:
   `! git grep -qE 'internal/(store|merkle|signer|encrypt)"' -- '*.go'`.
   Without this, the next person under deadline does exactly what the last one
   did.
2. **Version skew.** In the core repo, a scheduled job that shallow-clones each
   consumer, runs `go list -m github.com/bigblue-r4/witness`, and fails if two
   consumers pin different versions. This is P0-4 ("freeze the copies") made
   mechanical instead of a promise.
3. **`-tags piv` build**, with `libpcsclite-dev` installed, so the hardware path
   cannot rot again (§6.1).

## 6. Risks, and what was measured about each

### 6.1 The PIV path is already broken, and the move is what fixes it

`kiss-protocol/internal/signer/piv.go` (`//go:build piv`) imports
`github.com/go-piv/piv-go/piv`, but **neither `kiss-protocol/go.mod` nor `go.sum`
mentions `piv-go`**. Building with the tag today fails before it reaches any
hardware:

```
internal/signer/piv.go:18:2: no required module provides package
  github.com/go-piv/piv-go/piv; to add it: go get github.com/go-piv/piv-go/piv
```

The file's own comment says to run `go get` — so this is a documented manual step
that nobody has taken, which means the advertised hardware path has not been
compiled from a clean checkout in a while. **Declaring `piv-go` in the core's
`go.mod` (§2.1) fixes it for every consumer at once.** After the move, kiss with
`-tags piv` resolves the module and stops only at the system library:

```
# [pkg-config --cflags -- libpcsclite]
Package libpcsclite was not found
```

That is a build-environment requirement, not a module one: `-tags piv` needs
`libpcsclite-dev` (cgo). Default builds need neither. **Unverified:** this VM has
no `sudo`, so the PIV tag was never compiled to completion — install the dev
package and run step 2's `-tags piv` line before tagging.

### 6.2 `tidy` will try to modernise the module

Covered by pinning (§2.1). Expect a one-time diff if anyone runs `go get -u`.

### 6.3 Supply chain grows by one module per consumer

Declaring `piv-go` in the core means every consumer's `go.sum` gains its entries
even though nothing cgo is compiled without the tag. Reviewers will ask. The
alternative — leaving `piv-go` to the consumer — keeps the default graph smaller
but leaves the hardware path broken by default, which is the state being fixed.
Take the entries.

### 6.4 History

The moved files' history stays in `kiss-protocol`. `git log --follow` does not
cross repositories. If line-level provenance matters, seed the new repo with

```bash
git filter-repo --path internal/store --path internal/merkle \
                 --path internal/signer --path internal/encrypt
```

and rewrite the paths, rather than copying. Optional; the copy is clearer and the
history remains one `git log` away in the old repo. Either way, record the source
commit in the new repo's first commit message.

### 6.5 Consumers behind a private module

Only if the repository is private: `GOPRIVATE=github.com/bigblue-r4/*` and CI
credentials. Decide with P0-1.

### 6.6 Deleting the copies loses no local fixes — measured

Both copies were diffed against `kiss-protocol` HEAD with the import paths
normalised. Each differs in exactly four files, and both differ in the *same*
four: `store/store.go`, `store/crash_tail_test.go`, `store/treehead_signer_test.go`
and `signer/dev.go`. Every difference is an addition on the kiss side —
`OpenPinned`, `Last()`, `NewSoftware`, `ErrHeadNotSigned` and the pinned-key
verification path. Nothing exists in a copy that kiss lacks.

So the copies are strictly older, not locally patched, and deleting them is safe.
The same check should be re-run immediately before the deletion commit, since the
canonical core will keep moving in the meantime.

## 7. Rollback

Per consumer, the change is one commit: `git revert` restores the vendored
directories exactly, because they are deleted, not edited. Converting in the
order core → kiss → poultry → playground means a failure is contained to the repo
being converted; the module and the already-converted repos keep working.

## 8. Why `slate` is not in this plan

[CONSOLIDATION §5.2](CONSOLIDATION.md) keeps `slate` as the evidence-room product
and `cmd/witness-pd` retires into it. That makes `slate` a consumer eventually —
but its head implementation is *stronger* than the one being extracted: it signs
the whole head, chains to the previous head's bytes, and orders record-before-head.
Pointing `slate` at a core whose head authenticates only `size || root` would be a
downgrade in the exact component the evidence room depends on.

So: extract first (P0-2), fix the head once in the core (P1-2), *then* migrate
`slate`. This also keeps P0-2 genuinely mechanical: three consumers, import
strings only, no design decisions in the diff.

## 9. Definition of done

- [ ] `github.com/bigblue-r4/witness@v1.0.0` exists, public or `GOPRIVATE`-scoped, tagged.
- [ ] Core: `go build`, `go vet`, `go test` green; 74 tests, matching the 74 that left kiss.
- [ ] Core: `go.mod` matches §2.1 exactly, `go 1.22`, no `toolchain` line.
- [ ] `kiss-protocol`: builds, vets, tests green; zero `internal/(store|merkle|signer|encrypt)` imports.
- [ ] `harborlight-poultry-demo`: green; copies, `SOURCE.md` and `scripts/` deleted.
- [ ] `sgail-playground/witness`: green; copies, `SOURCE.md` and `scripts/` deleted.
- [ ] No consumer pins a different version (skew job green).
- [ ] `git grep sync-from-kiss` returns nothing, anywhere.
- [ ] The `-tags piv` build compiles on a machine with `libpcsclite-dev`.
- [ ] `CONSOLIDATION.md` P0-2 marked done with the tag it shipped as.

## 10. Rehearsal log

Every consumer was rebuilt from a fresh clone in a scratch directory, with the
module wired in via `replace` instead of a tag (no publishing in a rehearsal).

| Step | Result |
|---|---|
| Baseline `kiss-protocol` (`go build ./...`, `go test ./...`) | green, 22s build, all packages ok |
| Module from the four packages, `tidy` with no pins | compiled, but `go 1.26.0` + `x/crypto v0.58.0` — rejected, see §2.1 |
| Module with §2.1's `go.mod`, `tidy` | `go.mod` unchanged; build, vet, tests green |
| Module, `-tags piv` | fails at `libpcsclite` only; module resolution solved |
| `kiss-protocol` after 38 import edits + 4 deletions | build, vet, all tests green; 0 old imports |
| `harborlight-poultry-demo` after 3 edits | build, vet, tests green (`farm`, `pipelock`) |
| `sgail-playground/witness` after 10 edits | build, vet, tests green (`demo`) |
| Test parity | 74 passing in the module, 74 in kiss's four packages |
| `-tags piv` in converted kiss | module resolves; stops at `libpcsclite` (no `sudo` here) |

Not rehearsed: publishing, tagging, CI changes, and the `libpcsclite-dev` build.
