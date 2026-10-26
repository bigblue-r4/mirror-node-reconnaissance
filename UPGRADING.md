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

An aggregate archived from one of those commits fails `mnr sparkle verify` at
the fragment hashes. Regenerate it rather than keep it — `mnr sparkle` into a
fresh `--dir`, then `mnr sparkle verify`.

One caveat worth knowing when you compare old and new artifacts: the domain
strings above both say `/v1`, and the aggregate ledger's `kind` tag stayed
`sparkle-fragment` across the change. The two layouts are therefore not
distinguishable by inspection, only by failing.

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
| The aggregate changes are as described | Read the diffs of `cli/src/sparkle.rs` at `256d647` (first sparkle) and `9c61a46` (chain and preimage) |
