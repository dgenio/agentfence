#!/usr/bin/env bash
# proxy-smoke.sh — a hermetic, runnable proof that `agentfence proxy` gates a
# live MCP server over stdio: an allowed read is forwarded to the server, and a
# denied write is blocked with a JSON-RPC BlockedByPolicy error the server never
# sees. It wraps the bundled examples/stub-mcp-server, so it needs no network,
# npm, or external MCP server (issue #141).
#
# Usage:
#   ./examples/proxy-smoke.sh                 # builds ./agentfence if needed
#   AGENTFENCE=/path/to/agentfence ./examples/proxy-smoke.sh
set -euo pipefail

cd "$(dirname "$0")/.."

AGENTFENCE="${AGENTFENCE:-./agentfence}"
if [ ! -x "$AGENTFENCE" ]; then
  echo "+ building agentfence"
  go build -o ./agentfence ./cmd/agentfence
  AGENTFENCE=./agentfence
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Build the stub MCP server once so the proxy spawns a fast binary (not `go run`).
stub="$workdir/stub-mcp-server"
echo "+ building stub MCP server"
go build -o "$stub" ./examples/stub-mcp-server

# A tiny, self-contained policy: allow reads, deny writes.
policy="$workdir/policy.yaml"
cat >"$policy" <<'YAML'
version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
  filesystem.write:
    decision: deny
YAML

# Three JSON-RPC lines an MCP client would send: the initialize handshake, an
# allowed read, and a write the policy denies.
requests="$workdir/requests.jsonl"
cat >"$requests" <<'JSONL'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"README.md"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"secret.txt","content":"data"}}}
JSONL

out="$workdir/agent-stdout.jsonl"
audit="$workdir/audit.jsonl"

echo "+ agentfence proxy (prevention mode) wrapping the stub MCP server"
"$AGENTFENCE" proxy \
  --policy "$policy" \
  --audit-log "$audit" \
  --no-interactive \
  -- \
  "$stub" <"$requests" >"$out" 2>/dev/null

echo
echo "+ agent-visible JSON-RPC responses:"
cat "$out"

echo
echo "+ audit trail:"
cat "$audit"

# Assertions: the read is allowed (a result for id 2), and the write is blocked
# with the BlockedByPolicy error code (-32001) for id 3.
echo
if ! grep -q '"id":2' "$out"; then
  echo "FAIL: no response for the allowed read (id 2)" >&2
  exit 1
fi
if ! grep -q '"code":-32001' "$out"; then
  echo "FAIL: expected a BlockedByPolicy error (-32001) for the denied write" >&2
  exit 1
fi
if ! grep -q '"decision":"deny"' "$audit"; then
  echo "FAIL: expected a deny decision in the audit log" >&2
  exit 1
fi

echo "PASS: read forwarded, write blocked by policy (BlockedByPolicy -32001)."
