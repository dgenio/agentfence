# Edge proxy vs. in-process kernel: choosing an integration point

AgentFence and `agent-kernel` enforce policy on agent tool use at **two
different integration points**. They are complementary layers, not competitors —
many deployments use both. This page maps the same intent onto each so you can
decide where a given control belongs.

The AgentFence side is concrete and runnable here. The `agent-kernel` side is
described at the level the [README](../README.md#relationship-to-agent-kernel)
establishes — an embeddable in-process runtime configured by the application
author — without reproducing its API, which lives in its own project.

## The two integration points

```
                 ┌──────────────────────── your process ────────────────────────┐
   operator      │   application author                                          │
   configures    │   configures                                                  │
      │          │       │                                                        │
      ▼          │       ▼                                                        │
┌───────────┐    │  ┌───────────┐        ┌──────────────┐        ┌────────────┐  │
│ AgentFence│◄───┼──│  agent    │──▶ tool │  agent-kernel │──▶ run │   tool     │  │
│   proxy   │    │  │  (host)   │  calls  │ (in-process)  │        │  handler   │  │
└───────────┘    │  └───────────┘        └──────────────┘        └────────────┘  │
      │          └───────────────────────────────────────────────────────────────┘
      ▼
  audit log (JSONL, tamper-evident)
```

- **AgentFence** sits **outside** the agent process, on the wire between an MCP
  client and a tool server. It is configured by an *operator* and needs no
  changes to the agent or the app.
- **agent-kernel** sits **inside** the agent process as a library. It is
  configured by the *application author* and can see in-process context an
  external gate cannot.

## Same intent, two places

Take one intent: *allow filesystem reads, deny writes to `.env`.*

**At the edge (AgentFence).** Author a policy and gate the tool server. This is
fully runnable — it is the [Quickstart](quickstart.md):

```yaml
# agentfence.yaml
version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
    constraints:
      paths:
        deny: [".env", "**/secrets/**"]
  filesystem.write:
    decision: deny
```

```console
$ agentfence check --policy agentfence.yaml --call calls.jsonl --output text --no-interactive
c1 filesystem.read -> allow (tool filesystem.read matched explicit policy rule)
c2 filesystem.read -> deny (path ".env" denied by pattern ".env")
```

Enforced live by wrapping the server: `agentfence proxy --policy agentfence.yaml
-- <server>` (see the [integration guide](integration-guide.md)).

**In-process (agent-kernel).** The application author expresses the equivalent
allow/deny intent through the kernel's in-process configuration, so the check
runs before the app's own tool handler executes — compiled into the application
rather than enforced on the wire. (See the `agent-kernel` project for its
configuration surface.)

## Where semantics intentionally differ

| Aspect | AgentFence (edge proxy) | agent-kernel (in-process) |
|---|---|---|
| Configured by | Operator | Application author |
| Requires app changes | No | Yes (it is a library) |
| Sees in-process context | No — only the tool-call on the wire | Yes — app state, call site |
| Enforces on | Any MCP server, any language | The app's own tool execution |
| Audit trail | Standalone JSONL, tamper-evident, signed | The app's responsibility |
| Trust boundary | Outside the agent process | Inside it |

The edge gate deliberately sees *less* — only the tool call crossing the
boundary — which is exactly why it can wrap a server it did not write. The
in-process layer sees *more* and can act earlier, at the cost of being wired
into the application.

## When to choose which

- **Edge proxy (AgentFence)** — the policy author is not the app author; you
  need to constrain an MCP server or agent you did not build; you want an
  operator-owned audit trail independent of the app.
- **In-process (agent-kernel)** — you are building the agent application and want
  safety compiled in, with access to in-process context.
- **Both** — defence in depth: compile in-process guarantees with `agent-kernel`
  *and* enforce an operator-controlled boundary with AgentFence. The two policies
  can express the same intent at different layers.

If you only adopt one to start, pick the layer whose *configurator* matches who
will own the policy: operator → AgentFence, application author → agent-kernel.
