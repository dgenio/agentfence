#!/usr/bin/env bash
# demo-blocked-call.sh — canonical, recordable AgentFence proof.
#
# It wraps the bundled MCP stub server with the real `agentfence proxy`, forwards
# a useful read, blocks a prompt-injected credential write before the MCP server
# sees it, records redacted decisions, and verifies the hash-chained audit log.
# The final five-line receipt is deterministic and checked against
# examples/hero-expected.txt so README/launch material cannot silently drift.
#
# Usage:
#   ./examples/demo-blocked-call.sh
#   AGENTFENCE=/path/to/agentfence ./examples/demo-blocked-call.sh
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

stub="$workdir/stub-mcp-server"
go build -o "$stub" ./examples/stub-mcp-server

out="$workdir/agent-stdout.jsonl"
audit="$workdir/audit.jsonl"
receipt="$workdir/receipt.txt"

"$AGENTFENCE" proxy \
  --policy examples/hero-policy.yaml \
  --audit-log "$audit" \
  --tamper-evident \
  --no-interactive \
  -- \
  "$stub" <examples/hero-requests.jsonl >"$out" 2>/dev/null

# Prove the useful call was forwarded and the sensitive call was intercepted at
# the policy boundary. The JSON-RPC error is produced by AgentFence, not the MCP
# server.
grep -q '"id":2.*"result"' "$out"
grep -q '"id":3.*"code":-32001' "$out"
grep -q '"call_id":"2".*"decision":"allow"' "$audit"
grep -q '"call_id":"3".*"decision":"deny"' "$audit"

# Audit output may contain the attempted arguments, but configured secret
# patterns must be redacted. Never let the fake credential leak into the
# maintained proof artifact.
if grep -q 'sk-demo-not-a-real-secret-1234567890' "$audit"; then
  echo "FAIL: demo secret leaked into the audit log" >&2
  exit 1
fi
grep -q '\[REDACTED:openai_api_key\]' "$audit"

# Verify the tamper-evident chain, but keep the public receipt stable.
"$AGENTFENCE" audit verify --log "$audit" >/dev/null

cat >"$receipt" <<'EOF'
AgentFence MCP firewall demo
ALLOW filesystem.read README.md -> forwarded to MCP server
DENY filesystem.write .env -> blocked before MCP server (BlockedByPolicy -32001)
AUDIT allow + deny recorded; fake secret redacted; hash chain verified
PASS: useful call allowed, sensitive call stopped before the side effect.
EOF

diff -u examples/hero-expected.txt "$receipt"
cat "$receipt"
