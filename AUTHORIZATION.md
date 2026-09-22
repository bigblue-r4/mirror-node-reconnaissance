# Authorization & Rules of Engagement

MNR is a **defensive security research** artifact. This document governs what may
and may not be done with it. It is binding on anyone who uses this repository.

## 1. Default posture: LAB-ONLY

The code in this repository is a **sealed-lab demonstrator**. It communicates
only with the bundled synthetic swarm (`sim/mock-swarm/`) and touches no external
system. In its shipped form it **cannot** connect to, join, intercept, inject
into, or exfiltrate from any real network or third-party system:

- The only `SwarmConnector` implementation is the in-process mock.
- There is **no** traffic-interception, TLS-termination, protocol-impersonation,
  or defense-evasion code in this repository. Those field mechanics are described
  as capability in [`proxy/README.md`](proxy/README.md) and are deliberately not
  implemented here.

## 2. Real-world use requires prior written authorization

Any deployment of MNR — or of any capability it describes — against a system or
network is permitted **only** when **all** of the following are true:

1. **Ownership or written authorization.** The operator owns the target, or holds
   explicit, current, written authorization from the target's owner to assess it
   (e.g. a signed engagement contract, or a government tasking with the requisite
   legal authority).
2. **Defined scope.** The authorization names the in-scope systems, the permitted
   techniques, the time window, and the data-handling requirements.
3. **Legal review.** Applicable law (including, in the U.S., the Computer Fraud
   and Abuse Act and any wiretap/interception statutes) has been reviewed by
   counsel for the specific engagement, and the activity is lawful under it.
4. **Data governance.** A plan exists for the intelligence collected and the
   witness log produced — retention, access control, and disposal.

Absent any one of these, deployment against a non-lab target is **prohibited**,
regardless of whether the target is believed to be "malicious." Belief that a
target is hostile does not create authorization to access it.

## 3. Rules of Engagement — template

An engagement using MNR against an authorized target should record, at minimum:

- **Authorizing party & authority:** _______________________________________
- **In-scope targets (identifiers):** ______________________________________
- **Out-of-scope (explicitly excluded):** __________________________________
- **Permitted techniques:** ________________________________________________
- **Time window (start / hard stop):** _____________________________________
- **Max node dwell (TTL) & drift threshold:** ______________________________
- **Witness-log custody & retention:** _____________________________________
- **Emergency contact / abort procedure:** _________________________________
- **Legal sign-off (name, date):** _________________________________________

## 4. Reporting

Suspected misuse of this repository should be reported to SGAIL LLC. The
proprietary license (see [LICENSE](LICENSE)) prohibits unauthorized use,
redistribution, and deployment.
