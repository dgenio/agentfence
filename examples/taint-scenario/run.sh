#!/usr/bin/env bash
# run.sh — a hermetic, runnable demonstration of AgentFence's confused-deputy
# (taint) guard. An allowed filesystem.read returns untrusted text that contains
# an injected path; a later filesystem.write to *exactly that path* — which the
# static policy would allow — is escalated and blocked because its argument was
# derived from untrusted tool output (issue #153).
#
# It wraps the bundled examples/stub-mcp-server, so it needs no network or
# external MCP server. The steps are driven request/response (the write is only
# sent after the read's result has been observed) so the outcome is
# deterministic — no sleeps, no races.
#
# Usage:
#   ./examples/taint-scenario/run.sh          # builds ./agentfence if needed
#   AGENTFENCE=/path/to/agentfence ./examples/taint-scenario/run.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/../.."

AGENTFENCE="${AGENTFENCE:-./agentfence}"
if [ ! -x "$AGENTFENCE" ]; then
  echo "+ building agentfence"
  go build -o ./agentfence ./cmd/agentfence
  AGENTFENCE=./agentfence
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

stub="$workdir/stub-mcp-server"
echo "+ building stub MCP server"
go build -o "$stub" ./examples/stub-mcp-server

# The path the stub's read result embeds — the "injected" instruction. The
# write below targets exactly this string, so the taint tracker flags it. It is
# relative (and traversal-free) so the static policy allows it: taint is the only
# thing that blocks the write.
marker="deploy/prod-secrets.env"
audit="$workdir/audit.jsonl"
out="$workdir/agent-stdout.jsonl"
: >"$out"

# Start the proxy as a coprocess so we can send a request, wait for its
# response, then send the next — guaranteeing the read's result is observed
# before the write is evaluated.
coproc PROXY { "$AGENTFENCE" proxy \
  --policy "$here/policy.yaml" \
  --audit-log "$audit" \
  --no-interactive \
  -- "$stub" 2>/dev/null; }

send() { printf '%s\n' "$1" >&"${PROXY[1]}"; }

# Read agent-visible lines until one matching the given id arrives.
await_id() {
  local want="$1" line
  while IFS= read -r line <&"${PROXY[0]}"; do
    printf '%s\n' "$line" >>"$out"
    case "$line" in *"\"id\":$want"*) return 0 ;; esac
  done
  return 1
}

echo "+ 1. filesystem.read (allowed) — returns untrusted text containing $marker"
send '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"notes.txt"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"agentfence-taint-demo","version":"1"}}}}'
await_id 1

echo "+ 2. filesystem.write to the injected path (static policy would allow it)"
send "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"filesystem.write\",\"arguments\":{\"path\":\"$marker\",\"content\":\"exfiltrated\"},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{},\"io.modelcontextprotocol/clientInfo\":{\"name\":\"agentfence-taint-demo\",\"version\":\"1\"}}}}"
await_id 2

# Close the proxy's stdin so it drains and exits.
eval "exec ${PROXY[1]}>&-"
wait "$PROXY_PID" 2>/dev/null || true

echo
echo "+ agent-visible JSON-RPC responses:"
cat "$out"

echo
echo "+ audit trail:"
cat "$audit"

echo
if ! grep -q '"id":1.*"result"' "$out"; then
  echo "FAIL: the read (id 1) should have been allowed and returned a result" >&2
  exit 1
fi
if ! grep -q '"id":2.*"code":-32001' "$out"; then
  echo "FAIL: the tainted write (id 2) should have been blocked (-32001)" >&2
  exit 1
fi
if ! grep -q '"call_id":"2".*"decision":"deny"' "$audit"; then
  echo "FAIL: expected a deny decision for the tainted write in the audit log" >&2
  exit 1
fi

echo "PASS: read allowed; write blocked because its path came from untrusted output."
