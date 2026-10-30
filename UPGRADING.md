# Upgrading

What changes for someone who already has files on disk, one section per release.
Anything not listed here did not change.

## 0.1.0 → 0.2.0

### Logs keep verifying

The on-disk log is unchanged: `ledger.jsonl` plus `log-head.json`, the same entry
fields, the same `seq\nts\nkind\nprev_hash\nfingerprint` preimage. A 0.1.0 log
verifies under 0.2.0 with the head hash it was sealed at, because no migration
step exists or is needed:

```
$ mnr ledger verify --dir ./mnr-run      # written by 0.1.0, checked by 0.2.0
OK: 81 entries in ./mnr-run, sealed=true, head=54c29766a7cdc8b1…
```

A 0.1.0 `configs/mnr.toml` loads unchanged too — the friction keys 0.2.0 adds are
optional.

### A sealed log is final

This is the one change that reaches files a 0.1.0 run left behind. Seal was
create-once in intent only: 0.1.0 opened a sealed directory, appended to the log
and overwrote the anchor with `File::create`. Two `mnr demo` runs against one
directory therefore end with 162 entries and an anchor counting 162, so the
second run silently re-anchored over the first, and the head hash from the first
run no longer describes anything. 0.2.0 refuses instead, and writes nothing:

```
$ mnr demo --dir ./mnr-run
ledger error: ledger is already sealed at 81 entries (head_seq=80, head_hash=54c2…); a sealed witness log is final — use a fresh directory
```

`mnr ledger verify` and `mnr ledger show` still read a sealed directory — only
appending is closed. To keep recording, leave the sealed directory as the closed
run and point `--dir` at a new one.

If a 0.1.0 directory of yours holds more entries than its anchor counts, the
anchor is the most recent write, not the original one, and nothing on disk can
tell you what it was: only a copy of the head taken out of the directory at seal
time can. That custody step is the one thing this change cannot retrofit.

### Aggregations: nothing released to migrate

0.1.0 had no multi-probe command — its whole surface was `demo`,
`ledger verify` and `ledger show` — so no aggregation produced by a release
exists to re-verify. Nothing here invalidates a released artifact.

Aggregates produced from unreleased `main` commits do fail, because both the
fragment hash and the aggregate ledger changed during 0.2.0's development:

- A fragment is no longer `SHA-256(ledger.jsonl ‖ log-head.json)`. It is a
  length-prefixed, domain-separated preimage: `mnr/sparkle-ledger-fragment/v1\0`,
  then each file's little-endian length and bytes. Same inputs, different hash —
  and the two files can no longer shift bytes into one another.
- The aggregate ledger's per-fragment entry was a JSON object carrying runtime
  statistics (`final_drift`, `steps`, `trip_reason`) as well as the fragment
  hash. It is now a `mnr/sparkle-fragment/v1` payload of probe id and fragment
  hash only, so the statistics no longer affect what is committed, and each
  probe's id is bound to its hash.
- The aggregation root used to sit in a side file, `aggregate-root.json`,
  outside the chain. It is committed now, as the aggregate ledger's last entry,
  so verification trusts the chain and treats that file as an exported copy.
- The chain is marked with its layout: a leading `sparkle-format` entry commits
  `mnr/sparkle-format/v1\nsparkle-aggregate/2`, and the exported copy repeats
  `sparkle-aggregate/2` in a `format` field. Neither existed before, so an
  aggregate carrying neither is the old layout.

An aggregate archived from one of those commits fails `mnr sparkle verify`, and
the failure says which layout it is in rather than listing a mismatch per probe
— four findings that all have one cause read like four problems:

```
$ mnr sparkle verify --dir ./sparkle-old
SPARKLE VERIFY FAILED: probes_verified=2 all_probes_ok=true aggregate_ok=false sealed=true recomputed_root=b28916f8cdeff5eb…
  - aggregate is in the pre-0.2.0 layout: 2 fragment entries, no sparkle-root entry, and an exported root 6314d7bddf327f55… that matches the old fragment hash (sha256(ledger.jsonl + log-head.json)) — it predates the root being committed to the chain
  - its per-probe entries committed self-reported runtime statistics and a fragment hash that binds neither file, so they cannot be rechecked; it is not evidence this build can verify — regenerate it into a fresh directory with `mnr sparkle --dir <new dir>`
```

The aggregate still fails: recognising the layout does not make it verify. The
recognition is positive rather than by elimination — one fragment entry per
probe, no root entry, *and* an exported root that matches the root recomputed
with the old fragment hash. An aggregate whose root entry was deleted or
altered, or whose probe ledger was swapped, therefore still reports the mismatch
or the missing root, and is not excused as old. A probe ledger also still has to
verify on its own before any of this is said.

Regenerate a legacy aggregate rather than keep it: `mnr sparkle` into a fresh
`--dir`, then `mnr sparkle verify`.

A 0.2.0 aggregate also says which layout it is in, so telling the two apart no
longer needs a verification:

- the aggregate chain's first entry has `"kind":"sparkle-format"`, visible in
  `aggregate/ledger.jsonl`. Payloads are stored only as fingerprints, so the kind
  says the chain is versioned and the export copy below says which version;
  `mnr sparkle show --dir <path>` prints this without verifying anything;
- `aggregate-root.json` carries `"format": "sparkle-aggregate/2"`.

An aggregate written before the marker has neither, and that absence is the
format-1 marker. A chain whose format entry names something this build does not
verify is refused by name rather than half-checked:

```
  - aggregate names a format this build cannot verify (expected sparkle-aggregate/2): written by a different version of this tool? (seq 0)
```

The `format` field in the export copy is descriptive only, the same rule as its
root: editing it does not change what is verified, and a value this build does
not recognise is reported as a warning.

### Bundles: nothing to re-sign

`core/bundle`, `witness-bundle/2` and the v1 exporters are all new in 0.2.0; no
released version produced a bundle. Bundles already issued by `slate` and
`kiss-protocol` live in their own repositories, are v1 files, and are still read
by `tools/bundle-verify/`; `slate export --format 1` still writes them.

### What the claims above rest on

| Claim | Check |
|---|---|
| A 0.1.0 log verifies under 0.2.0 | Built `v0.1.0` from its tag, ran `mnr demo`, verified the result with the 0.2.0 binary: `OK: 81 entries`, same head hash |
| 0.1.0 re-anchored a sealed directory | Ran 0.1.0's `mnr demo` against its own sealed `--dir`: 81 → 162 entries, `log-head.json` rewritten, exit 0 |
| 0.2.0 refuses and writes nothing | Ran the 0.2.0 `mnr demo` against a copy of that sealed directory: exit 1, `ledger.jsonl` and `log-head.json` byte-identical afterwards |
| 0.1.0 had no aggregation or bundle | Built `v0.1.0` prints its own usage: `demo`, `ledger verify`, `ledger show` only |
| Old aggregates fail, and how | Built `92cb930` (sparkle, before the chain and preimage change), produced an aggregate with it, verified it with the 0.2.0 binary: exit 1, two lines naming the pre-0.2.0 layout and pointing at a fresh run |
| The layout is identifiable by inspection | Ran `mnr sparkle` for 2 probes: `aggregate/ledger.jsonl` starts with `kind: sparkle-format` and `aggregate-root.json` has `"format": "sparkle-aggregate/2"`; verification reports `format=sparkle-aggregate/2` |
| The layout is recognised, not guessed | Two CLI tests: a rewritten pre-0.2.0 aggregate is explained once with no per-probe mismatch lines; the same shape with a foreign exported root is not explained, and still reports the missing root |
| The aggregate changes are as described | Compared `cli/src/sparkle.rs` at `92cb930` with the current file: fragment hash and committed payload, as listed above |
