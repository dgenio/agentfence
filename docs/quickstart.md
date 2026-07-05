# Quickstart: your first 10 minutes with AgentFence

This is the shortest linear path from install to a working, policy-gated setup.
By the end you will have scaffolded a policy, seen an **allowed** call and a
**denied** call, and read the decisions back out of the audit log. (For a
_tamper-evident_ audit log and how to verify it, see [CLAIMS](claims.md).)

Every command below is copy-pasteable. The evaluation steps (2–6, with the
bundled stub) run entirely offline against files you create here or files
bundled in this repo; only installing the binary (step 1) and the optional
real MCP server (step 6, via `npx`) reach the network.

For the conceptual tour (why AgentFence exists, the four enforcement modes, the
threat model), start at the [README](../README.md). For day-to-day operation
after this, see the [Daily Driver guide](daily-driver.md).

## 1. Install

Pick one (full options in the [README](../README.md#install)):

```bash
# Install script (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/dgenio/agentfence/main/scripts/install.sh | sh

# …or build from source (Go 1.22+)
go build -o agentfence ./cmd/agentfence
```

Confirm it runs:

```bash
agentfence version
```

## 2. Scaffold a policy from a pack

Instead of writing YAML from scratch, start from a curated pack. The
`filesystem` pack allows reads, gates writes behind an `ask`, denies deletes,
and blocks secret-bearing paths like `.env`:

```bash
agentfence init --pack filesystem
```

```
Created agentfence.filesystem.yaml
Created agentfence.yaml
```

`agentfence.yaml` is your policy; it imports the pack and is where you add your
own rules. (Run `agentfence init --pack '?'` to list every available pack.)

## 3. Validate it

```bash
agentfence validate --policy agentfence.yaml
```

```
agentfence.yaml: OK
```

## 4. See what the policy decides

Create a small tool-call trace (one JSON object per line — the same shape a
proxy would evaluate live):

```bash
cat > calls.jsonl <<'JSONL'
{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}
{"id":"c2","tool":"filesystem.read","arguments":{"path":".env"}}
{"id":"c3","tool":"filesystem.delete","arguments":{"path":"build/out"}}
JSONL
```

Evaluate it, writing decisions to an audit log:

```bash
agentfence check \
  --policy agentfence.yaml \
  --call calls.jsonl \
  --output text \
  --no-interactive \
  --audit-log audit.jsonl
```

```
c1 filesystem.read -> allow (tool filesystem.read matched explicit policy rule)
c2 filesystem.read -> deny (path ".env" denied by pattern ".env")
c3 filesystem.delete -> deny (tool filesystem.delete matched explicit policy rule)

3 call(s) processed, 0 parse error(s): allow=1 deny=2 ask=0
```

There it is: a normal read is **allowed**, a read of `.env` is **denied**, and
the delete is **denied**.

## 5. Read the audit log

Every decision was recorded as one JSON line:

```bash
cat audit.jsonl
```

```jsonl
{"schema_version":"4","session_id":"…","seq":1,"timestamp":"…","call_id":"c1","tool":"filesystem.read","decision":"allow","reason":"tool filesystem.read matched explicit policy rule","reason_code":"rule_match"}
{"schema_version":"4","session_id":"…","seq":2,"timestamp":"…","call_id":"c2","tool":"filesystem.read","decision":"deny","reason":"path \".env\" denied by pattern \".env\"","reason_code":"path_denied"}
{"schema_version":"4","session_id":"…","seq":3,"timestamp":"…","call_id":"c3","tool":"filesystem.delete","decision":"deny","reason":"tool filesystem.delete matched explicit policy rule","reason_code":"rule_match"}
```

## 6. Gate a live MCP server

`check` evaluates a recorded trace; the **proxy** does the same thing in real
time, sitting between an MCP client and a tool server. The bundled smoke example
runs the proxy in front of a tiny stub server (no network, no npm) and shows an
allowed read plus a denied write:

```bash
./examples/proxy-smoke.sh
```

```
+ agentfence proxy (prevention mode) wrapping the stub MCP server
…
{"jsonrpc":"2.0","id":2,"result":{…}}                 # read forwarded
{"jsonrpc":"2.0","id":3,"error":{"code":-32001,…}}    # write blocked by policy
…
PASS: read forwarded, write blocked by policy (BlockedByPolicy -32001).
```

To gate a **real** server, point the proxy at any MCP server command after `--`.
For example, the official filesystem server:

```bash
agentfence proxy \
  --policy agentfence.yaml \
  --audit-log audit.jsonl \
  -- \
  npx -y @modelcontextprotocol/server-filesystem "$PWD"
```

Then point your MCP client at that `agentfence proxy …` command instead of the
server directly — see the [integration guide](integration-guide.md) for
per-client config (Claude Code, Cursor, VS Code, Claude Desktop).

## Where to go next

- [Daily Driver guide](daily-driver.md) — operating AgentFence day to day.
- [Enforcement modes](modes.md) — detection, prevention, audit-only, dry-run.
- [Policy language](policy-language.md) — the full policy schema.
- [Integration guide](integration-guide.md) — wiring it into MCP clients.
- [Threat model](threat-model.md) — what AgentFence does and does not defend.
