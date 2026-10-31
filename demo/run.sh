#!/usr/bin/env bash
#
# A real-world demo of the witness log: an evidence room's chain of custody.
#
# Six acts. Each one ends in an assertion, so a run either makes its point or
# fails; nothing below is a screenshot of a previous run.
#
#   1. export a case bundle from a custody log and have a stranger check it
#      with the independent verifier and two pinned keys;
#   2. edit one disclosed entry inside the issued bundle — the verifier refuses;
#   3. re-export the whole bundle from an edited log with the same keys — the
#      verifier accepts it, and only the head retained in act 1 catches it;
#   4. sign the seal, then rebuild the log wholesale — the pinned key refuses;
#   5. mutate, truncate and un-anchor the runtime ledger — each is detected;
#   6. tamper with one probe of an aggregation — verification names the probe.
#
# The records in demo/scenario/evidence-room.ndjson are fictional. The log
# format, the keys, the signatures, the verifier and the failures are real.
# See demo/DEMO.md for the talk track and for what this does not prove.
#
# Usage:
#     ./demo/run.sh                       # artifacts in demo/out/
#     DEMO_DIR=/tmp/mnr-demo ./demo/run.sh
#     DEMO_SKIP_SPARKLE=1 ./demo/run.sh   # skip act 6
#
# DEMO_DIR is wiped and recreated. Exit codes: 0 every assertion held,
# 1 an assertion failed, 2 setup problem.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bin="${MNR_BIN:-$repo_root/target/debug/mnr}"
verifier="$repo_root/tools/bundle-verify/verify_bundle.py"
scenario="$repo_root/demo/scenario/evidence-room.ndjson"
work="${DEMO_DIR:-$repo_root/demo/out}"
case_number=CASE-2026-0042

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# One act header, and the sentence a presenter reads aloud.
act() { printf '\n== %s ==\n' "$*"; }
say() { printf '   %s\n' "$*"; }
show() { sed 's/^/  | /' "$1"; }

# expect_exit <want> <label> <log> <command...>
expect_exit() {
    local want=$1 label=$2 log=$3
    shift 3
    local got=0
    "$@" >"$log" 2>&1 || got=$?
    if [ "$got" -ne "$want" ]; then
        printf 'FAIL: %s — expected exit %s, got %s\n' "$label" "$want" "$got" >&2
        show "$log" >&2
        return 1
    fi
    printf 'ok: %s (exit %s)\n' "$label" "$got"
}

# expect_contains <file> <pattern> <label>
expect_contains() {
    local file=$1 pattern=$2 label=$3
    if ! grep -q -- "$pattern" "$file"; then
        printf 'FAIL: %s — %s not found\n' "$label" "$pattern" >&2
        show "$file" >&2
        return 1
    fi
    printf 'ok: %s\n' "$label"
}

# head_field <bundle> <size|root> — read one field of the signed tree head.
head_field() {
    python3 - "$1" "$2" <<'PY'
import json, sys
print(json.loads(open(sys.argv[1], encoding="utf-8").readline())["log_head"][sys.argv[2]])
PY
}

[ -x "$bin" ] || {
    printf 'FAIL: no executable at %s\nrun: cargo build -p mnr-cli\n' "$bin" >&2
    exit 2
}
[ -f "$verifier" ] || fail "missing $verifier"
[ -f "$scenario" ] || fail "missing $scenario"
command -v python3 >/dev/null || fail 'python3 is required for the verifier'

case "$work" in
    / | "$repo_root" | "$HOME") fail "refusing to wipe $work — point DEMO_DIR at a scratch directory" ;;
esac
rm -rf "${work:?}"
mkdir -p "$work"

printf 'mnr witness-log demo — evidence room, case %s\n' "$case_number"
printf 'binary %s\n' "$bin"
printf 'artifacts %s\n' "$work"

# ---------------------------------------------------------------------------
act "1. Export a case bundle; a stranger checks it"
say "Twelve custody events, two cases. We disclose only the nine for $case_number."
cp "$scenario" "$work/custody-log.ndjson"

"$bin" bundle keygen --out "$work/node.key" | tee "$work/act1-key-node.log"
"$bin" bundle keygen --out "$work/exporter.key" | tee "$work/act1-key-exporter.log"
node_pub=$(awk '/^public key/{print $3}' "$work/act1-key-node.log")
exporter_pub=$(awk '/^public key/{print $3}' "$work/act1-key-exporter.log")

"$bin" bundle export \
    --log "$work/custody-log.ndjson" \
    --out "$work/case-0042.bundle.ndjson" \
    --scope case --case "$case_number" \
    --node-key "$work/node.key" --exporter-key "$work/exporter.key" \
    --department "Honolulu PD" --agency "Honolulu Police Department" \
    --seal HPD-2026 --node-id node-0042 \
    --actor "Sgt. M. Kealoha" --role evidence_clerk \
    --generated-at 2026-10-20T09:00:00Z --bundle-id BUNDLE-20261020-0042a \
    | tee "$work/act1-export.log"
say "Two public keys are printed above. The recipient pins both; a bundle that"
say "names its own key proves nothing."

expect_exit 0 "the bundle verifies with both keys pinned" "$work/act1-verify.log" \
    python3 "$verifier" "$work/case-0042.bundle.ndjson" --pin "$exporter_pub" --pin "$node_pub"
show "$work/act1-verify.log"
expect_contains "$work/act1-verify.log" 'VERIFIED' 'the independent verifier reports VERIFIED'
say "That verifier is Python with no dependencies and shares no code with the"
say "Rust producer, so this is a second implementation agreeing, not the same one."

head_size=$(head_field "$work/case-0042.bundle.ndjson" size)
head_root=$(head_field "$work/case-0042.bundle.ndjson" root)
printf '%s\n' "$head_root" >"$work/head-retained-at-export.root"
say "The bundle ships 9 entries but the head covers $head_size leaves, and the"
say "root is $head_root…"
say "That root, kept outside this machine, is the anchor for acts 3 and 4."

# ---------------------------------------------------------------------------
act "2. Someone edits a disclosed entry inside the issued bundle"
say "The item was re-sealed on 2026-10-18 under SEAL-77188. Change the disclosed"
say "copy to SEAL-77120 and the item looks like it was never re-sealed at all."
cp "$work/case-0042.bundle.ndjson" "$work/case-0042.edited.ndjson"
perl -pi -e 's/SEAL-77188/SEAL-77120/' "$work/case-0042.edited.ndjson"

expect_exit 1 "an edited entry is rejected" "$work/act2-verify.log" \
    python3 "$verifier" "$work/case-0042.edited.ndjson" --pin "$exporter_pub" --pin "$node_pub"
show "$work/act2-verify.log"
expect_contains "$work/act2-verify.log" 'FAILED' 'the failure names its step'
say "Exit 1, not 0 and not 3: the file no longer supports the claim it makes."

# ---------------------------------------------------------------------------
act "3. Re-export from an edited log, with the same keys"
say "Act 2 is the easy case. Here the same clerk edits the source log and exports"
say "again with the node and exporter keys they legitimately hold."
mkdir -p "$work/forged"
cp "$scenario" "$work/forged/custody-log.ndjson"
perl -pi -e 's/SEAL-77188/SEAL-77120/' "$work/forged/custody-log.ndjson"

"$bin" bundle export \
    --log "$work/forged/custody-log.ndjson" \
    --out "$work/forged/case-0042.bundle.ndjson" \
    --scope case --case "$case_number" \
    --node-key "$work/node.key" --exporter-key "$work/exporter.key" \
    --department "Honolulu PD" --agency "Honolulu Police Department" \
    --seal HPD-2026 --node-id node-0042 \
    --actor "Sgt. M. Kealoha" --role evidence_clerk \
    --generated-at 2026-10-20T09:00:00Z --bundle-id BUNDLE-20261020-0042b \
    | tee "$work/act3-export.log"

expect_exit 0 "the verifier ACCEPTS the re-export (this is the documented limit)" \
    "$work/act3-verify.log" \
    python3 "$verifier" "$work/forged/case-0042.bundle.ndjson" --pin "$exporter_pub" --pin "$node_pub"
show "$work/act3-verify.log"
say "Nothing here is broken: the producer signs the head it mints, so an edited"
say "log produces a smaller, internally consistent, honestly signed bundle."

forged_size=$(head_field "$work/forged/case-0042.bundle.ndjson" size)
forged_root=$(head_field "$work/forged/case-0042.bundle.ndjson" root)
say "Same size ($forged_size leaves), different root:"
say "  retained at export  $head_root"
say "  re-export           $forged_root"
[ "$head_root" != "$forged_root" ] \
    || fail 'the re-exported head root matched the retained one — the scenario proves nothing'
printf 'ok: the retained head no longer matches the re-export\n'
say "A verifier holding one bundle cannot tell a current head from an old one."
say "The check that works is the one a court already does: compare the head the"
say "recipient kept at issue time against the head in the bundle handed over now."

# ---------------------------------------------------------------------------
act "4. Sign the seal, then rebuild the log without the key"
"$bin" demo --dir "$work/ledger-signed" --head-key "$work/node.key" \
    >"$work/act4-run.log" 2>&1 || { show "$work/act4-run.log"; fail 'the signed demo run failed'; }
expect_exit 0 "the signed seal verifies against the pinned node key" "$work/act4-pinned.log" \
    "$bin" ledger verify --dir "$work/ledger-signed" --head-key "$work/node.key"
show "$work/act4-pinned.log"

say "Now someone with write access deletes the directory and rebuilds a tidy,"
say "self-consistent log — the exact attack the chain alone cannot stop. They do"
say "not have the node key."
rm -rf "$work/ledger-signed"
"$bin" demo --dir "$work/ledger-signed" >"$work/act4-rebuild.log" 2>&1 \
    || { show "$work/act4-rebuild.log"; fail 'the rebuild run failed'; }

expect_exit 0 "plain verify accepts the rebuilt log — it holds no key" "$work/act4-plain.log" \
    "$bin" ledger verify --dir "$work/ledger-signed"
show "$work/act4-plain.log"
expect_contains "$work/act4-plain.log" 'signed=false' 'the rebuilt seal is unsigned'
expect_exit 1 "pinned verify refuses it" "$work/act4-reject.log" \
    "$bin" ledger verify --dir "$work/ledger-signed" --head-key "$work/node.key"
show "$work/act4-reject.log"
expect_contains "$work/act4-reject.log" 'carries no signature' 'the reason is named'
say "Attribution, not completeness: a log truncated before sealing and then signed"
say "still verifies. Signing narrows the custody gap; it does not close it."

# ---------------------------------------------------------------------------
act "5. The runtime ledger: edit, truncate, strip the anchor"
"$bin" demo --dir "$work/ledger-lab" >"$work/act5-run.log" 2>&1 \
    || { show "$work/act5-run.log"; fail 'the lab run failed'; }
expect_exit 0 "an intact run verifies" "$work/act5-ok.log" \
    "$bin" ledger verify --dir "$work/ledger-lab"
show "$work/act5-ok.log"

say "One entry changed: observation becomes modelled at seq 0."
perl -pi -e 's/"kind":"observation"/"kind":"modelled"/ if $. == 1' "$work/ledger-lab/ledger.jsonl"
expect_exit 1 "one edited entry fails verification" "$work/act5-mutated.log" \
    "$bin" ledger verify --dir "$work/ledger-lab"
show "$work/act5-mutated.log"

say "A different fresh run, then cut it to its first three entries."
"$bin" demo --dir "$work/ledger-trunc" >"$work/act5-trunc-run.log" 2>&1 \
    || { show "$work/act5-trunc-run.log"; fail 'the truncation run failed'; }
head -n 3 "$work/ledger-trunc/ledger.jsonl" >"$work/ledger-trunc/short"
mv "$work/ledger-trunc/short" "$work/ledger-trunc/ledger.jsonl"
expect_exit 1 "truncation disagrees with the anchor" "$work/act5-truncated.log" \
    "$bin" ledger verify --dir "$work/ledger-trunc"
show "$work/act5-truncated.log"
expect_exit 1 "the truncated directory cannot be reopened either" "$work/act5-reopen.log" \
    "$bin" demo --dir "$work/ledger-trunc"
expect_contains "$work/act5-reopen.log" 'ledger error' 'the reopen failure says why'

say "And a run whose anchor was deleted outright."
"$bin" demo --dir "$work/ledger-unanchored" >"$work/act5-unanchored-run.log" 2>&1 \
    || { show "$work/act5-unanchored-run.log"; fail 'the unanchored run failed'; }
rm "$work/ledger-unanchored/log-head.json"
expect_exit 1 "a missing anchor is UNSEALED, never OK" "$work/act5-unsealed.log" \
    "$bin" ledger verify --dir "$work/ledger-unanchored"
show "$work/act5-unsealed.log"
expect_contains "$work/act5-unsealed.log" 'UNSEALED' 'it reports UNSEALED rather than OK'

# ---------------------------------------------------------------------------
if [ "${DEMO_SKIP_SPARKLE:-0}" = "1" ]; then
    act "6. Aggregation — skipped (DEMO_SKIP_SPARKLE=1)"
else
    act "6. Aggregation: one tampered probe out of eight"
    say "Eight probes, each with its own sealed ledger; the controller commits one"
    say "fragment hash per probe and a Merkle root over them. Then edit one byte."
    expect_exit 0 "the aggregation verifies intact, then fails tampered" "$work/act6.log" \
        env MNR_BIN="$bin" "$repo_root/scripts/ci/sparkle-tamper.sh"
    tail -n 8 "$work/act6.log" | sed 's/^/  | /'
    expect_contains "$work/act6.log" 'PASS: aggregation verifiable when intact' 'the probe is named'
fi

# ---------------------------------------------------------------------------
act "What this run proved, and what it did not"
cat <<'TEXT'
   Proved, with exit codes:
     - an issued bundle verifies under two pinned keys and an independent verifier;
     - an edit inside an issued bundle is rejected, and the step is named;
     - an edit before export is NOT rejected by the verifier — the retained head
       is what catches it;
     - a rebuilt log passes plain verification, and fails a pinned one;
     - a mutated, truncated or un-anchored ledger is never reported OK;
     - a tampered probe inside an aggregation is detected and named.

   Not proved, by design (README "Limits", THREAT_MODEL.md §4):
     - that the disclosed entries are the whole log: the producer signs the head
       it mints, so a truncated source log yields a smaller, valid bundle;
     - who held the write access that produced a rebuild;
     - that timestamps are true: there is no trusted time, and a failed clock
       read falls back to the Unix epoch;
     - that fingerprints are confidential: a SHA-256 of a small input can be
       guessed;
     - anything about the mock swarm's drift score; it is marker arithmetic,
       not a measured model.
TEXT

printf '\nartifacts kept in %s\n' "$work"
printf 'presenter notes: demo/DEMO.md\n'
printf 'PASS: every act above reached the result it asserts\n'
