# JSON-RPC batch handling across transports

This note records how AgentFence treats JSON-RPC *batch* (array) request bodies
on each transport, why the default is reject-by-default, and the migration
implications. It grounds the gating behavior shipped in the HTTP proxy
(`--on-batch`, `--on-unparsed`).

## What a batch is

JSON-RPC 2.0 §6 allows a client to send an **array** of request objects in a
single payload; the server replies with an array of responses. MCP layers on
top of JSON-RPC, so a batch can in principle carry several `tools/call`
requests at once.

## Observed behavior of the two proxies (before this change)

Both proxies modeled only a single request envelope (`internal/mcp/model.go`),
so a batch slipped past the gate:

- **HTTP proxy** (`internal/httpproxy`): `ServeHTTP` parsed one
  `mcp.ParseRequest(body)`. An array failed that parse and fell through to a
  transparent `forward(...)` — **ungated**.
- **stdio proxy** (`internal/proxy`): `processAgentLine` parses one JSON-RPC
  request per line. A single line holding an array also fails `ParseRequest`
  and is forwarded untouched — **ungated**.

For a security gate, "a documented hole is still a hole": an agent (or an
injected instruction) could wrap a denied `tools/call` in a one-element array
to bypass policy.

## Do MCP clients actually send batches?

Batch support across MCP clients is inconsistent, and the dominant pattern is
one request per message. The 2025 MCP specification revision moved to **remove
JSON-RPC batching** from the protocol, so batches are at best a legacy edge and
at worst an attack vector — not a path worth optimizing for. This evidence
points to *reject-by-default* as the safe, low-regret choice rather than
building full batch fan-out.

## Decision

- **HTTP proxy:** reject batches by default (`--on-batch reject`), returning a
  JSON-RPC error (`ErrorCodeBatchNotGated`). An operator who genuinely needs
  batching can opt into `--on-batch evaluate`, which evaluates every
  `tools/call` member and forwards the **whole** batch only if all members are
  allowed (all-or-nothing). A single non-allow member rejects the entire batch,
  so a denied call can never ride along with allowed ones. Each member's
  decision is still audited.
- **stdio proxy:** the line-framed relay already forwards a batch line
  untouched. Because the per-line model never evaluates it, the safe posture is
  the same reject-by-default intent; a batch line that fails single-request
  parsing is non-`tools/call` traffic. Bringing an equivalent `--on-batch`
  switch to the stdio relay is tracked as follow-up — the HTTP path is where
  batches arrive as a single inspectable body today.

Related, the HTTP proxy now also fails closed on **oversize** bodies (refused
rather than forwarded uninspected) and offers `--on-unparsed reject` for bodies
that are not valid JSON-RPC at all. Valid JSON-RPC methods other than
`tools/call` (initialize, ping, notifications) are always forwarded so the MCP
session keeps working.

## Migration implications

Rejecting batches by default is a behavior change for any client that sent
batches and relied on transparent forwarding. Such clients will receive a
JSON-RPC error instructing them to send one request per body or to run the
proxy with `--on-batch evaluate`. Given that batching is being removed from MCP
and was previously ungated (and therefore unsafe to rely on), this is the
correct fail-closed default.
