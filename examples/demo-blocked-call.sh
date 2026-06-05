#!/usr/bin/env bash
# demo-blocked-call.sh — a short, recordable demo of AgentFence blocking a
# prompt-injected MCP tool call and producing a redacted, tamper-evident audit
# trail. This is the script used to record the README demo GIF/asciinema (see
# docs/distribution.md); it is also a fine smoke test.
#
# Usage:
#   ./examples/demo-blocked-call.sh            # builds ./agentfence if needed
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
calls="$workdir/injected-calls.jsonl"
audit="$workdir/audit.jsonl"

# Three calls an injected prompt might try to make: exfiltrate a secret into a
# .env write, and delete a repo. The fake secret is clearly non-real.
cat >"$calls" <<'JSONL'
{"id":"call_1","tool":"filesystem.read","arguments":{"path":"README.md"}}
{"id":"call_2","tool":"filesystem.write","arguments":{"path":".env","content":"OPENAI_API_KEY=sk-demo-not-a-real-secret-1234567890"}}
{"id":"call_3","tool":"github.delete_repo","arguments":{"repo":"dgenio/agentfence"}}
JSONL

echo "+ agentfence check (prevention mode, tamper-evident audit)"
"$AGENTFENCE" check \
  --policy examples/policy.yaml \
  --call "$calls" \
  --audit-log "$audit" \
  --tamper-evident \
  --no-interactive \
  --output text || true

echo
echo "+ audit trail (note the redacted secret in the blocked .env write):"
cat "$audit"

echo
echo "+ verify the hash chain:"
"$AGENTFENCE" audit verify --log "$audit"
