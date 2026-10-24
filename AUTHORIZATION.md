# Authorization & Rules of Engagement

MNR is a **dual-use security research artifact**. The configuration shipped in
this repository is lab-only, but the component set includes a request-emission
path that would degrade a real target's availability if someone attached a real
connector to it. This document sets out the conditions under which that is
acceptable. The binding legal instrument is [LICENSE](LICENSE); this file is the
operating policy.

## 1. Shipped configuration: LAB-ONLY

As shipped, the code communicates only with the bundled synthetic swarm
(`sim/mock-swarm/`) and touches no external system. It **cannot** connect to,
join, intercept, inject into, or exfiltrate from any real network or third-party
system:

- The only `SwarmConnector` implementation is the in-process mock.
- There is **no** traffic-interception, TLS-termination, protocol-impersonation
  or defense-evasion code. Those field mechanics are described as a problem
  statement in [`proxy/README.md`](proxy/README.md) and deliberately not
  implemented.
- There is no model backend; `MockEngine` is a deterministic stand-in.

Writing a connector is therefore the step that changes what this code *is*, and
it puts the emission path — a bounded, DoS-like capability — in reach. Anyone
doing it takes on the obligations below.

## 2. Real-world use requires prior written authorization

Any deployment of MNR — or of any capability it describes — against a system or
network is permitted **only** when **all** of the following hold:

1. **Ownership or written authorization.** The operator owns the target, or holds
   explicit, current, written authorization from its owner to assess it (a signed
   engagement contract, or a government tasking with the requisite legal
   authority).
2. **Defined scope.** The authorization names the in-scope systems, permitted
   techniques, the time window, and data-handling requirements.
3. **Legal review.** Applicable law — including, in the U.S., the Computer Fraud
   and Abuse Act and wiretap/interception statutes — has been reviewed by counsel
   for this specific engagement, and the activity is lawful under it.
4. **Data governance.** A plan exists for the intelligence collected and the
   witness log produced: retention, access control, disposal, and who may read
   the head hash.
5. **Availability cap.** If the emission path is enabled at all, the target's
   owner has agreed a measurable cap on induced work (requests per interval,
   abort threshold, and a monitoring method), and someone is watching it.

Absent any one of these, deployment against a non-lab target is **prohibited**,
regardless of whether the target is believed to be "malicious". Belief that a
target is hostile does not create authorization to access it, and an emission cap
that bounds requests does not bound the work those requests induce.

## 3. Rules of Engagement — template

An engagement should record, at minimum:

- **Authorizing party & authority:** _______________________________________
- **In-scope targets (identifiers):** ______________________________________
- **Out-of-scope (explicitly excluded):** __________________________________
- **Permitted techniques:** ________________________________________________
- **Time window (start / hard stop):** _____________________________________
- **Max node dwell (TTL) & drift threshold:** ______________________________
- **Emission authorized? (yes/no) — total cap, rate cap, abort threshold:** __
- **Impact monitoring method & who watches it:** ___________________________
- **Witness-log custody, head-hash escrow & retention:** ____________________
- **Emergency contact / abort procedure:** _________________________________
- **Legal sign-off (name, date):** _________________________________________

## 4. Reporting

Report suspected misuse or a vulnerability through the repository's private
reporting (GitHub → **Security** → *Report a vulnerability*). There is no
published email address for this project; do not open a public issue containing
operational detail.

The [LICENSE](LICENSE) prohibits unauthorized use, redistribution and deployment,
and the [THREAT_MODEL](THREAT_MODEL.md#5-dual-use-risk-created-by-mnr) explains
why the emission path is the part that needs the most care.
