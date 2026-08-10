# Flagship MCP boundary demo

This is the maintained fixture behind `demo-blocked-call.sh` and the README
hero. It demonstrates one complete, deterministic path through the real
AgentFence stdio proxy using the stateless MCP `2026-07-28` request shape
(client metadata travels in each request; there is no `initialize` handshake).
See the official
[`2026-07-28` specification](https://modelcontextprotocol.io/specification/2026-07-28):

1. `filesystem.read(project-notes.txt)` is allowed and reaches the bundled MCP
   stub, which returns prompt-injected text.
2. The deterministic agent fixture follows that text and requests
   `filesystem.write(.env, OPENAI_API_KEY=…)`.
3. AgentFence evaluates the exact tool and arguments, denies `.env`, and returns
   `BlockedByPolicy` before forwarding the request.
4. The stub's diagnostic method proves it received only `filesystem.read`.
5. The audit receipt records both decisions, redacts the fake secret, and
   verifies as a hash chain.

Run it from the repository root:

```bash
./examples/demo-blocked-call.sh
```

The script compares its short terminal summary with
[`hero-expected.txt`](hero-expected.txt) and its normalized runtime audit with
[`hero-expected-audit-receipt.jsonl`](hero-expected-audit-receipt.jsonl), so CI
fails if the policy, proxy behavior, reason codes, redaction, or audit shape
drifts.

The attack text and secret are inert test fixtures. The upstream is the local
[`stub-mcp-server`](stub-mcp-server), not a third-party or production system.

## Boundary

This proves mediation at the configured MCP proxy. AgentFence does not prevent
prompt injection, sandbox the MCP server, or govern calls that bypass the proxy.
It limits what an injection can cause only at tool boundaries it actually
mediates. `ask` decisions need a trustworthy approval path to add safety; this
demo uses a direct argument-aware deny.
