# AgentFence roadmap

_Last updated: 2026-08-11._

This is a **directional** roadmap, not a commitment or a dated release plan. The authoritative source of truth is the issue tracker, especially the [`roadmap`](https://github.com/dgenio/agentfence/labels/roadmap) label. When this document and the tracker disagree, the tracker wins.

## Product thesis

AgentFence should stay narrow:

> **A small, deterministic authorization enforcement point for MCP/tool-call paths that are actually routed through it.**

The project should not try to win by accumulating every adjacent AI-security feature. Identity/IAM, prompt/DLP detection, sandboxing/OS containment, and arbitrary shell interpretation are separate layers that should compose with AgentFence where useful.

See [`docs/positioning.md`](docs/positioning.md) for the trust-boundary model.

## Completed foundations

The original phased roadmap is substantially complete:

- **Phase 0 — Harden the MVP** ([#2](https://github.com/dgenio/agentfence/issues/2)): contributor guidance, CI, validation, structured output, strict YAML handling, safer path behavior, and release tooling.
- **Phase 1 — Expand the policy language** ([#3](https://github.com/dgenio/agentfence/issues/3)): groups/wildcards, argument/URL/command constraints, `policy test`, `explain`, and imports/packs.
- **Phase 2 — MCP proxy support** ([#4](https://github.com/dgenio/agentfence/issues/4)): stdio interception, interactive approval, timeout, and integration guidance.
- **Phase 3 — Trustworthy audit logs** ([#5](https://github.com/dgenio/agentfence/issues/5)): versioned events, sequencing/session IDs, hash chaining, verification, threat-model expansion, and fuzzing.

Additional shipped foundations include streamable-HTTP proxying, Ed25519 audit signing, audit anchors/rotation/sinks, SBOM/signed release artifacts, typed decision reason codes, metrics/logging, taint/confused-deputy defense-in-depth, and the maintained blocked-call proof. See [CHANGELOG.md](CHANGELOG.md) for release-level specifics.

## Current gates

The next phase is **not primarily more features**. It is proving that the authorization boundary is truthful, deployable, independently reviewable, and useful enough that unrelated users keep it enabled.

### G0 — Boundary truth and launch proof

- [#74](https://github.com/dgenio/agentfence/issues/74): finish the result-centered launch around the maintained blocked-call proof.
- [#115](https://github.com/dgenio/agentfence/issues/115): make the narrow MCP authorization category and bypass/non-goals explicit.

Success means a stranger understands what is mediated and what is not without reading the implementation.

### G1 — Deployment preflight

- [#89](https://github.com/dgenio/agentfence/issues/89): `agentfence doctor` must verify policy/proxy/upstream/audit/approval setup and make the actual mediation boundary visible.

A correct engine is not sufficient if the operator accidentally configured a bypass path, writable policy, untrusted approval channel, or wrong upstream.

### G2 — Server/tool identity binding

- [#221](https://github.com/dgenio/agentfence/issues/221): define and implement how authorization binds to the configured/resolved MCP server/tool and descriptor/schema drift.

A matching tool-name string must not silently inherit authority when the capability underneath it changes.

### G3 — Policy and approval integrity

- [#222](https://github.com/dgenio/agentfence/issues/222): bind decisions to the effective policy and bind approvals to the exact action they authorize.

The policy/configuration itself must be outside the authority of the agent it constrains, or protected by deployment controls. Approval replay/substitution must fail closed.

### G4 — Real integration proof

- [#214](https://github.com/dgenio/agentfence/issues/214): prove one real MCP client -> AgentFence -> real MCP server path, with a useful ALLOW and a blocked high-risk call, while explicitly showing any unmediated client path.

The hermetic stub remains the CI regression proof; this gate establishes practical integration evidence.

### G5 — Independent security evidence

- [#223](https://github.com/dgenio/agentfence/issues/223): obtain an independent review of the policy/parser/proxy/approval/audit boundary and publish scoped findings/disposition.

Strong tests and maintainer-run coding-agent reviews are valuable, but they are not independent security review.

### G6 — Retained adoption

- [#225](https://github.com/dgenio/agentfence/issues/225): validate that unrelated users connect real workflows, customize policy, and keep AgentFence enabled after evaluation.

No built-in telemetry should be added for this. Use public/voluntary signals and treat weak retention as product evidence, not automatically as a distribution problem.

### G7 — Human contributor viability

- [#224](https://github.com/dgenio/agentfence/issues/224): protect claimed `help wanted` / `good first issue` work from maintainer-agent races and curate a smaller, current contribution surface.

The optimization target is useful outside contributions landing successfully, not maximum issue-closing throughput.

## Deliberately lower priority until the gates above have evidence

### Policy examples, not universal `safe` packs

- [#208](https://github.com/dgenio/agentfence/issues/208): assumption-explicit coding-workflow examples.
- [#211](https://github.com/dgenio/agentfence/issues/211): small tested high-risk capability examples.

These are onboarding material. A community policy marketplace/auto-update ecosystem should wait until retained adoption exists and there is a deliberate provenance/version-pinning trust model.

### Conservative shell handling

- [#203](https://github.com/dgenio/agentfence/issues/203): prefer structured argv/tool fields and gate ambiguous shell/interpreter strings conservatively.

AgentFence should not become an incomplete Bash/PowerShell/cmd interpreter or claim to infer every side effect of arbitrary shell programs. Sandboxing/OS controls remain the containment layer after forwarding.

### Broader detection/enforcement surfaces

Features such as response-side policy, deeper DLP-like inspection, more heuristic taint analysis, dashboards, hosted control planes, and broad security scanning should not outrank the gates above merely because they expand the feature matrix.

## Product kill/pivot discipline

The roadmap should change if evidence says the standalone authorization boundary is not sufficiently useful.

A healthy adoption funnel is roughly:

```text
discover
  -> reproduce ALLOW/DENY proof
  -> connect real client/server
  -> customize policy
  -> keep AgentFence enabled
  -> contribute/share because the boundary remains useful
```

If real evaluation repeatedly becomes `cool demo -> star -> never used`, or if native MCP/client authorization and broader gateway/sandbox products consistently remove the need for a separate policy boundary, revisit the thesis rather than expanding into adjacent categories by default.

## Smaller work

CLI ergonomics, performance, tests, benchmarks, and documentation improvements continue to live in the tracker without necessarily carrying the `roadmap` label. Browse [open issues](https://github.com/dgenio/agentfence/issues), [`help wanted`](https://github.com/dgenio/agentfence/labels/help%20wanted), and [`good first issue`](https://github.com/dgenio/agentfence/labels/good%20first%20issue) for entry points.
