# `proxy/` — Interception Layer (CONCEPT ONLY — NOT IMPLEMENTED)

> **There is no code in this directory.** This is a written problem statement. No
> interception, TLS termination, protocol impersonation or defense-evasion
> functionality exists anywhere in this repository. Any real-world use is
> governed by [`../AUTHORIZATION.md`](../AUTHORIZATION.md) and requires prior
> written authorization plus legal review.

## Purpose in the MNR architecture

In the full concept, an **interception / adaptation layer** would sit between the
observer node ([`../harness/agent/`](../harness/agent/)) and a target collective,
so the node can speak the target's wire protocol well enough to be admitted and
to observe from the inside. In this repository that layer is replaced entirely by
the bundled synthetic swarm ([`../sim/mock-swarm/`](../sim/mock-swarm/)), which
the observer talks to through the same `SwarmConnector` seam — so the substrate
can be demonstrated without any interception capability existing.

## What such a layer would have to solve

Described as problem statements and interface boundaries, not as an
implementation:

- **Protocol translation** — presenting the observer's structured `Message`
  stream to and from a target's transport, so the reasoning core stays
  transport-agnostic.
- **Dialect conformance** — shaping the node's emissions to match a target
  collective's expected schema closely enough to participate as a peer.
- **Boundary enforcement** — isolating the interception surface from the command
  architecture, so a compromise at the perimeter cannot reach the operator's core.
- **Egress accounting** — a rate and volume budget enforced at the boundary itself
  rather than in the reasoner, so a bug in the observer cannot exceed the agreed
  impact cap. Nothing in the current code does this.

## The seam

Everything above meets the rest of MNR at exactly one interface
(`harness/agent/src/lib.rs`):

```rust
pub trait SwarmConnector {
    fn recv(&mut self) -> Option<Message>;
    fn emit(&mut self, _message: Message) -> Result<(), SwarmError> {
        Err(SwarmError::Unsupported)   // default: receive-only connectors
    }
    fn disconnect(&mut self) {}
}
```

The runnable system provides exactly one implementation — the mock swarm. A
production layer would be *another* implementation of the same trait, and writing
it is out of scope for this repository. The observer, ledger and reaper neither
know nor care which side of the seam they are on, which is what lets the
defensive substrate be demonstrated and tested in a sealed lab.

## Why it is not implemented here

1. **Scope.** MNR's contribution is the defensive substrate: witness integrity,
   role-separated observation, lifecycle containment. That is what the code
   demonstrates.
2. **Safety.** A working interception and impersonation layer is general-purpose
   intrusion tooling. Combined with the emission path it is also a bounded
   denial-of-service capability. Shipping it — even privately — creates risk out
   of proportion to a research prototype.
3. **Authorization.** Such a layer is lawful only inside a specific authorized
   engagement ([`../AUTHORIZATION.md`](../AUTHORIZATION.md)), so it belongs to an
   engagement, not to a general-purpose repository.

For the same reason, the one authored component with a plausible offensive use —
request emission — ships only against the mock, is off by default, and is
described in [THREAT_MODEL §5](../THREAT_MODEL.md#5-dual-use-risk-created-by-mnr).
