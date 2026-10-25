#!/usr/bin/env bash
#
# Tamper check for the sealed sparkle aggregation.
#
# Run by CI, and runnable locally against an existing debug build:
#
#     cargo build -p mnr-cli && scripts/ci/sparkle-tamper.sh
#
# The check proves three things, in order:
#   1. an untouched aggregation verifies (exit 0) — the baseline, without which a
#      later failure would prove nothing;
#   2. the tamper actually altered the probe ledger on disk;
#   3. the same aggregation then fails verification with exit 1 and names the
#      probe whose committed fragment no longer matches.
#
# Exit codes: 0 every assertion held, 1 an assertion failed, 2 setup problem.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
bin="${MNR_BIN:-$repo_root/target/debug/mnr}"
probes="${PROBES:-8}"
ttl_ms="${TTL_MS:-800}"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# sha256sum is on every Linux CI runner; shasum covers a developer on macOS.
digest() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

if [ ! -x "$bin" ]; then
    printf 'FAIL: no executable at %s (run: cargo build -p mnr-cli)\n' "$bin" >&2
    exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
run_dir="$work/run"

# expect_exit <expected> <label> <log> <command...>
expect_exit() {
    local want=$1 label=$2 log=$3
    shift 3
    local got=0
    "$@" >"$log" 2>&1 || got=$?
    if [ "$got" -ne "$want" ]; then
        printf 'FAIL: %s — expected exit %s, got %s\n' "$label" "$want" "$got" >&2
        sed 's/^/  | /' "$log" >&2
        exit 1
    fi
    printf 'ok: %s (exit %s)\n' "$label" "$got"
}

# 1. A clean aggregation must verify. `mnr sparkle` seals the aggregate chain and
#    then runs the same verification `mnr sparkle verify` runs, so exit 0 here
#    covers both the run and the check.
expect_exit 0 'aggregation runs and self-verifies' "$work/run.log" \
    "$bin" sparkle --probes "$probes" --ttl-ms "$ttl_ms" --dir "$run_dir"

expect_exit 0 'intact aggregation verifies' "$work/verify-clean.log" \
    "$bin" sparkle verify --dir "$run_dir"
grep -q 'aggregate_ok=true' "$work/verify-clean.log" \
    || fail 'clean verification did not report aggregate_ok=true'
grep -q 'sealed=true' "$work/verify-clean.log" \
    || fail 'clean verification did not report sealed=true'

# 2. Alter exactly one byte of probe 0's chain: the first hex digit of the first
#    entry's payload fingerprint. The line stays valid JSON, so verification must
#    reject it on the chain, not on parse errors.
ledger="$run_dir/probes/probe-0/ledger.jsonl"
[ -f "$ledger" ] || fail "expected a probe ledger at $ledger"

before=$(digest "$ledger")
current=$(sed -n '1s/.*"payload_fingerprint":"\([0-9a-f]\)[0-9a-f]*".*/\1/p' "$ledger")
if [ "${#current}" -ne 1 ]; then
    fail "could not locate payload_fingerprint on line 1 of $ledger"
fi
if [ "$current" = 0 ]; then replacement=1; else replacement=0; fi
sed "1s/\"payload_fingerprint\":\"$current/\"payload_fingerprint\":\"$replacement/" \
    "$ledger" >"$ledger.tmp"
mv "$ledger.tmp" "$ledger"

after=$(digest "$ledger")
[ "$before" != "$after" ] || fail 'tamper did not change the probe ledger'
printf 'ok: tampered with %s (sha256 %s… -> %s…)\n' \
    "probes/probe-0/ledger.jsonl" "${before:0:12}" "${after:0:12}"

# 3. The same directory must now fail verification, with exit 1 — not 2, which
#    would mean the CLI rejected the arguments instead of the data.
expect_exit 1 'tampered aggregation fails verification' "$work/verify-tampered.log" \
    "$bin" sparkle verify --dir "$run_dir"
grep -q 'SPARKLE VERIFY FAILED' "$work/verify-tampered.log" \
    || fail 'tampered verification did not report SPARKLE VERIFY FAILED'
grep -q 'probe 0' "$work/verify-tampered.log" \
    || fail 'tampered verification did not name probe 0'

printf 'PASS: aggregation verifiable when intact, rejected when tampered\n'
