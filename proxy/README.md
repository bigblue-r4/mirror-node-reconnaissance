# `proxy/` — Interception Layer (CONCEPT ONLY — NOT IMPLEMENTED)

> **There is no code in this directory.** This is a capability description for
> research and grant-proposal purposes. No interception, TLS-termination,
> protocol-impersonation, or defense-evasion functionality is implemented
> anywhere in this repository. Any real-world use is governed by
> [`../AUTHORIZATION.md`](../AUTHORIZATION.md) and requires prior written
> authorization and legal review.

## Purpose in the MNR architecture

In the full MNR concept, an **interception / adaptation layer** would sit between
the observer node ([`../harness/agent/`](../harness/agent/)) and a target
collective, so the node can speak the swarm's wire protocol well enough to be
admitted and to observe from the inside. In this repository that layer is
replaced entirely by the bundled synthetic swarm
([`../sim/mock-swarm/`](../sim/mock-swarm/)), which the observer talks to through
the same `SwarmConnector` seam — so the substrate can be demonstrated without any
real interception capability existing.

## What the layer is responsible for (described, not built)

At the level of a research abstract, an authorized-use interception layer would
need to solve:

- **Protocol translation** — presenting the observer's structured `Message`
  stream to/from a target's transport, so the reasoning core stays transport-
  agnostic.
- **Dialect conformance** — shaping the node's emissions to match a target
  collective's expected schema closely enough to participate as a peer.
- **Boundary enforcement** — cryptographically isolating the interception surface
  from the command architecture, so a compromise at the perimeter cannot reach
  the operator's core (the "double-agent stays in its lane" principle).

These are described here as *problem statements and interface boundaries*, not as
an operational implementation. The intent is to document that SGAIL understands
the shape of the capability — sufficient for a DHS SBIR / DARPA proposal — without
shipping tooling that could be run against a non-consenting system.

## The seam that keeps this honest

Everything above meets the rest of MNR at exactly one interface:

```rust
// harness/agent/src/lib.rs
pub trait SwarmConnector {
    fn recv(&mut self) -> Option<Message>;
}
```

The runnable system provides exactly one implementation of that trait — the mock
swarm. A production interception layer would be *another* implementation of the
same trait, and building it is out of scope for this repository by design. The
observer, ledger, and reaper neither know nor care which side of the seam they
are on, which is what lets us demonstrate and test the whole defensive substrate
in a sealed lab.

## Why it is not implemented here

1. **Scope.** MNR's contribution is the *defensive substrate* — witness
   integrity, split-brain co-option detection, lifecycle containment. That is
   what the code proves.
2. **Safety.** A working interception/impersonation/evasion engine is
   general-purpose intrusion tooling. Shipping it — even privately — creates
   risk disproportionate to a capability showcase.
3. **Authorization.** Such a layer is lawful only inside a specific authorized
   engagement (see [`../AUTHORIZATION.md`](../AUTHORIZATION.md)). It therefore
   belongs to an engagement, not to a general-purpose repository.
