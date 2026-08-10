# Confused-deputy (taint) scenario

A hermetic, runnable demonstration of AgentFence's taint guard catching the
**confused-deputy** pattern: an agent is tricked, by instructions hidden in
untrusted tool output, into making a *later* tool call whose arguments the
static policy would allow on their own. The fixture uses the stateless MCP
`2026-07-28` request shape; client metadata travels in each request.

- [`policy.yaml`](policy.yaml) — allows `filesystem.read` and `filesystem.write`
  statically, but enables taint tracking in `escalate` mode.
- [`run.sh`](run.sh) — drives the scenario through `agentfence proxy` in front of
  the bundled [`../stub-mcp-server`](../stub-mcp-server) (no network, no npm).

## What it shows

1. An allowed `filesystem.read` returns untrusted text that embeds an injected
   path (`deploy/prod-secrets.env`) — standing in for a prompt injection planted
   in a file.
2. A later `filesystem.write` targets **exactly that path**. The static policy
   allows the write, but AgentFence sees the `path` argument was lifted verbatim
   from untrusted output, escalates `allow → ask`, and (non-interactively) denies
   it with a `BlockedByPolicy` error the tool server never sees.

## Run it

```bash
./examples/taint-scenario/run.sh
```

The script asserts the read is allowed and the tainted write is blocked
(`-32001`), so it doubles as a smoke test. It is defensive by design: the
"injection" is a benign path string, never a real attack payload.
