# Where AgentFence fits

AgentFence is a **small, deterministic authorization enforcement point for MCP and tool-call paths that are actually routed through it**.

It answers a narrow question before a mediated action executes:

> Given this tool call, its arguments, the configured upstream context, and the active policy, should this action be allowed, denied, or sent for approval?

That narrow boundary is intentional. AgentFence is not a general AI-security platform and should not be evaluated as one.

## The boundary

```text
                       mediated MCP/tool path
AI client  ----------------------------------------------+
   |                                                     |
   |                                                     v
   |                                              +-------------+
   |                                              | AgentFence  |
   |                                              | policy gate |
   |                                              +------+------+ 
   |                                                     |
   |                                             ALLOW   |   DENY / ASK
   |                                                     v
   |                                                MCP server
   |
   +---- native shell / native filesystem / direct MCP -------> outside AgentFence
```

AgentFence only governs calls that cross its configured CLI/proxy boundary. If a client can reach the same capability through another path, that path needs its own controls.

This means examples such as Claude Code, Cursor, VS Code, or another coding client should be read as:

> Put AgentFence in front of the MCP tools this client uses.

They must **not** be read as:

> AgentFence secures every action the client can take.

## What AgentFence owns

AgentFence is designed to own a small set of responsibilities:

- deterministic policy evaluation over mediated tool calls;
- constraints over the request fields the upstream tool contract actually exposes;
- `allow`, `deny`, and `ask` decisions;
- fail-closed behavior where the configured boundary cannot make a trustworthy decision;
- local, inspectable decision receipts and audit evidence;
- stdio, streamable-HTTP, and CLI/CI mediation surfaces implemented by the project.

The project should prefer boring, inspectable authorization semantics over broad detection heuristics.

## What AgentFence does not own

### Identity and enterprise access

AgentFence is not an identity provider. MCP authentication, OAuth, enterprise-managed authorization, group membership, and account provisioning belong to the surrounding identity/access layer.

Where authenticated principal or server context is available, AgentFence can consume it as policy input. It should not invent a parallel identity protocol.

### Prompt-injection detection

AgentFence does not make a model trustworthy and does not promise to detect every prompt injection. Its useful security property is narrower: if a successful injection causes a mediated tool request that policy forbids, AgentFence can stop that request before it reaches the upstream server.

Response-side heuristics or taint tracking are defense-in-depth, not the definition of the product.

### Sandboxing and containment

After an allowed call is forwarded, the server/process still needs appropriate OS, container, network, credential, and application controls. AgentFence does not replace those layers.

For opaque shell programs in particular, AgentFence should prefer structured request fields where available and conservatively gate ambiguous interpreter/string execution. It should not claim to predict every side effect of arbitrary shell semantics.

### Proving that a policy is sufficient

AgentFence can evaluate the policy it is given. It cannot prove that an operator authored the right policy for an environment.

Deployment guidance and `agentfence doctor` should help surface risky configuration, but the policy/configuration itself must be protected from the agent it is intended to constrain.

## How adjacent controls compose

| Layer | Primary question | AgentFence relationship |
|---|---|---|
| MCP authentication / enterprise-managed authorization | Who may connect or access this MCP service? | Complementary. AgentFence should consume trustworthy identity context rather than replace it. |
| AgentFence | May this mediated action execute under local policy? | Core responsibility. |
| Prompt/DLP/gateway controls | Does content or traffic contain suspicious, sensitive, or policy-relevant signals? | Complementary defense-in-depth. |
| Sandbox / OS / container / network controls | What can forwarded code or processes actually touch? | Required for containment beyond the mediated decision. |
| Embedded application authorization | What may an agent do inside a runtime the application controls? | Complementary; an embedded runtime can enforce closer to the application than an external proxy. |

The practical goal is composition, not feature-count competition.

## Why a separate authorization boundary can still be useful

Native client permissions and MCP authentication may answer different questions from fine-grained tool-call authorization.

A deployment may legitimately want to say:

```text
this principal may connect to the GitHub MCP server

but

repository read        -> ALLOW
open pull request       -> ASK
merge pull request      -> DENY
publish release         -> DENY
```

AgentFence is useful when an operator wants that decision to be deterministic, local to the protected boundary, portable across clients, and independently auditable.

## Identity, policy, and approval hardening

The long-term authorization claim depends on more than a tool-name string. The roadmap tracks three important hardening areas:

- [#221](https://github.com/dgenio/agentfence/issues/221): bind authorization to MCP server/tool identity and descriptor drift;
- [#222](https://github.com/dgenio/agentfence/issues/222): bind effective policy and approvals to the exact authorized action;
- [#89](https://github.com/dgenio/agentfence/issues/89): add a preflight/doctor command so operators can verify that the boundary they think is active is actually configured.

Until those contracts ship, documentation and launch material should not imply stronger guarantees than the current implementation provides.

## When to choose something else

AgentFence is probably the wrong primary tool if your main requirement is:

- isolating arbitrary code after it executes;
- scanning all network traffic or content for DLP/injection patterns;
- managing enterprise identities and OAuth grants;
- controlling client-native capabilities that cannot be routed through AgentFence;
- interpreting the full semantics of arbitrary shell programs;
- obtaining a hosted centralized security platform rather than a local policy boundary.

In those cases, use the appropriate adjacent control. AgentFence can still compose with it when a separate deterministic authorization decision is useful.

## Product test

The project should earn broader scope through retained use, not through feature accumulation. [#225](https://github.com/dgenio/agentfence/issues/225) tracks whether unrelated users actually keep AgentFence enabled in real workflows after the initial demo.

If users consistently find native authorization sufficient, or prefer a broader gateway/sandbox that makes a separate policy boundary unnecessary, the project should treat that as product evidence rather than automatically expanding into adjacent categories.
