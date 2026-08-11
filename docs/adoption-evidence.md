# Adoption evidence

AgentFence should broaden its product surface only when there is evidence that unrelated users put it on a real tool boundary and **keep it enabled after evaluation**.

This document defines a lightweight, privacy-preserving evidence protocol for [#225](https://github.com/dgenio/agentfence/issues/225). It is deliberately not an analytics system.

## No built-in telemetry

AgentFence does not need hidden/default telemetry to prove adoption.

Do not add automatic usage reporting, installation beacons, policy uploads, audit-log collection, or other phone-home behavior for growth measurement.

Use only information that is already public or that an adopter voluntarily chooses to share.

## What counts as meaningful evidence

Evidence is stronger when it appears farther down the actual-use funnel.

### Weak discovery signals

Useful for context, but **not evidence of retained adoption**:

- GitHub stars;
- page views;
- one-time repository clones;
- social reactions;
- one-time demo runs;
- a user saying the idea looks interesting.

### Evaluation signals

Evidence that someone investigated the product:

- a question based on running the maintained demo;
- an installation/package issue;
- a real client/server configuration question;
- a policy customization question;
- a bug report from an actual mediated call path.

These matter, but still do not prove retention.

### Adoption signals

Higher-confidence evidence includes:

- a public repository that commits an AgentFence policy/configuration used by a real workflow;
- external documentation that tells users to put AgentFence on a real MCP/tool boundary;
- an adopter voluntarily stating that AgentFence remains enabled after repeated use;
- a bug/feature contribution motivated by the contributor's own ongoing AgentFence deployment;
- a public integration or case study with the actual client/server boundary described;
- a downstream project pinning a released AgentFence version or container image in a maintained workflow.

### Retention/removal evidence

The most useful signal is not praise. It is knowing whether the boundary remained useful.

When an adopter volunteers context, try to capture:

- client / orchestrator;
- MCP server or mediated tool boundary;
- why native client/server authorization was insufficient;
- policy changes needed for the environment;
- what AgentFence controlled that mattered;
- meaningful friction, false positives, or bypass concerns;
- whether AgentFence remained enabled after repeated work;
- if removed, the concrete reason it was removed and what replaced it.

A removal is valuable product evidence. Do not classify it as a failed community interaction.

## Evidence log

Only record public evidence or evidence the person explicitly agreed can be published.

| Date | Evidence | Boundary/use case | Retained? | Public source / consent | Product implication |
|---|---|---|---|---|---|
| _none yet_ | | | | | |

Do not populate this table from private conversations, private repositories, customer/company details, or inferred usage without permission.

If public evidence grows enough that this table becomes noisy, move individual cases to issue/discussion links and keep only a compact summary here.

## Maintainer validation questions

For a voluntary adopter report, the maintainer should prefer a few concrete questions over a generic request for a testimonial:

1. What real client -> AgentFence -> server/tool path did you use?
2. Which native permissions/auth controls did you already have, and what gap remained?
3. What did you have to change in the example policy to make it correct for your environment?
4. Did you keep AgentFence enabled after the initial test? Why or why not?
5. What was the largest source of friction or uncertainty?
6. Was there a path the client could take that bypassed AgentFence?
7. What change would most increase the chance you keep using it?

Never ask an adopter to publish secrets, internal hostnames, policies, audit logs, or employer details merely to count as adoption evidence.

## Decision rule before broad scope expansion

The directional validation target in #225 is:

- roughly **10 unrelated retained workflows/users**, and
- at least **2 concrete public usage stories** when adopters consent.

The number is not a KPI to game. The decision-relevant questions are:

- Are unrelated users reaching a real mediated boundary rather than only the demo?
- Do they customize policy successfully without maintainer hand-holding?
- Does AgentFence remain enabled after repeated use?
- Is the separate authorization layer solving a gap that native MCP/client controls do not already solve?

If evidence repeatedly looks like:

```text
interesting demo
  -> star / clone
  -> no real boundary
  -> no retained use
```

then revisit the product thesis before building adjacent DLP, sandbox, response-scanning, dashboard, or hosted-platform features.

Likewise, if adopters consistently remove AgentFence because native authorization is sufficient or because a broader gateway/sandbox covers the same need with less operational cost, treat that as evidence for a narrower niche or pivot.

## Relationship to other gates

Retained-adoption evidence becomes much more meaningful after the project can prove the boundary clearly:

- [#89](https://github.com/dgenio/agentfence/issues/89) — deployment/preflight truth;
- [#221](https://github.com/dgenio/agentfence/issues/221) — server/tool identity binding;
- [#222](https://github.com/dgenio/agentfence/issues/222) — policy/action/approval binding;
- [#214](https://github.com/dgenio/agentfence/issues/214) — real client + real server proof;
- [#223](https://github.com/dgenio/agentfence/issues/223) — independent security evidence.

Do not wait for perfection before listening to users, but do not interpret adoption of a weaker current boundary as proof that the future security claims are already satisfied.
