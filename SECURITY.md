# Security Policy

This repository is a sealed-lab research instrument, not a service. Its security
surface is small but unusual: the valuable property is that a surviving witness
log, aggregation or bundle **cannot be made to verify when it should not** — and
that the tool does not damage the machine or the third parties it is pointed at.

## Supported versions

| Version | Supported |
|---|---|
| `main` (0.2.x) | Yes — fixes land here |
| 0.1.x | No — superseded by 0.2.0; see [UPGRADING.md](UPGRADING.md) |

There is no long-term support branch. If you are running a commit that is not on
`main`, reproduce against `main` before reporting, and say which commit you saw
the problem on (`git rev-parse HEAD`).

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private advisory flow: the repository's **Security** tab →
**Report a vulnerability**. That creates a draft advisory only you and the
maintainers can see, and it is the channel this policy is written for.

If that button is not available to you, open a public issue that says only that
you have a security report and asks for a private channel — no details, no
reproducer, no affected version. Sending the substance over a public thread
discloses it, and this project would rather wait a day for a private channel than
have you do that.

A useful report contains:

- the commit or version, and the command you ran;
- what you expected to happen, and what happened instead;
- a reproducer — a directory layout, a mutated file, or a script;
- the impact as you understand it, especially whether a verifier can be made to
  print `OK` for evidence that should fail;
- whether the affected directory, aggregate or bundle still exists, so a fix can
  be checked against it.

## What counts as a vulnerability

In scope:

- **False acceptance.** Any input that makes `mnr ledger verify`,
  `mnr sparkle verify`, a bundle from `mnr bundle export`, or the independent
  verifier in [`tools/bundle-verify/`](tools/bundle-verify/) report success for
  evidence that was edited, truncated, swapped or forged. Hash framing mistakes,
  signature bypass, and a pinned key that is not actually checked all belong
  here.
- **Silent corruption without an adversary.** Cases where an ordinary sequence of
  commands — concurrent runs, an interrupted seal, a crash — leaves a log that no
  longer verifies, or that verifies while describing something other than what
  happened.
- **Hostile-input handling.** Panics, unbounded allocation, path traversal or
  writes outside the target directory when reading a ledger, an aggregate or a
  bundle that someone else produced.
- **Key material exposure.** A seed written where another user can read it, echoed
  into output or logs, or a signature that can be replayed against a different
  payload.

Out of scope — these are documented limits, not defects. Reporting them is still
welcome, but the reply will be a pointer rather than a fix:

- **Loss without detection.** A party with write access to the ledger directory
  deleting `ledger.jsonl`, `log-head.json` and `log-head.sig` can always destroy
  the evidence; that is [THREAT_MODEL.md](THREAT_MODEL.md) §7. A *deleted* anchor
  is reported as `UNSEALED`, never as `OK` — if you find a case where deletion or
  a rebuild prints `OK`, that is in scope.
- **Completeness.** A head covers the entries that were sealed. A log truncated
  *before* sealing and then signed verifies, and `mnr bundle export` signs the
  tree it was handed. This is the custody gap the README's *Limits* section names.
- **Timestamps and fingerprints.** Self-reported clocks, the Unix-epoch fallback
  in `iso_now()`, and fingerprint inversion over a small input domain are
  properties of the design, described in THREAT_MODEL.md §4.
- **Best-effort wiping.** Volatile zero writes do not reach allocator copies,
  `format!` temporaries, swap or hibernation images.

## Not a target for testing

Do not test any of this against systems you do not own or have written
authorization to touch. The friction-injection path is inert here — the only
connector is an in-process mock with a bounded queue — but the same code pointed
at a real collective would consume peers' verification work, and that use is
governed by [AUTHORIZATION.md](AUTHORIZATION.md), not by this policy. A report
about traffic sent to a third party is a misuse report, not a vulnerability.

## What to expect

- An acknowledgement, with an assessment of whether the report is in scope.
- A reproducer run against `main` before any claim about a fix.
- Coordination with you on disclosure timing if the issue is real, and credit in
  the advisory unless you ask otherwise.
- No monetary reward: this is an unfunded, proprietary-labelled project, and
  offering a bounty that will not be paid would be worse than not offering one.

If a report is out of scope, the reply will say which document covers the
behaviour, so the same ground does not have to be covered twice.
