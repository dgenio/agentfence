#!/usr/bin/env bash
# demo-blocked-call.sh — the deterministic, recordable flagship proof for
# AgentFence. A real MCP stdio proxy allows a bounded read, receives injected
# text, blocks the resulting secret-bearing .env write before upstream, and
# emits a redacted, hash-chained audit receipt.
#
# Usage:
#   ./examples/demo-blocked-call.sh
#   AGENTFENCE=/path/to/agentfence ./examples/demo-blocked-call.sh
set -euo pipefail

cd "$(dirname "$0")/.."

AGENTFENCE="${AGENTFENCE:-./agentfence}"
if [ ! -x "$AGENTFENCE" ]; then
  go build -o ./agentfence ./cmd/agentfence
  AGENTFENCE=./agentfence
fi

policy="examples/hero-policy.yaml"
requests="examples/hero-requests.jsonl"
expected_summary="examples/hero-expected.txt"
expected_receipt="examples/hero-expected-audit-receipt.jsonl"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

stub="$workdir/stub-mcp-server"
audit="$workdir/audit.jsonl"
responses="$workdir/responses.jsonl"
proxy_stderr="$workdir/proxy-stderr.log"
actual_summary="$workdir/summary.txt"
actual_receipt="$workdir/normalized-audit.jsonl"
: >"$responses"

go build -o "$stub" ./examples/stub-mcp-server

# Keep the advertised protocol fixture honest. AgentFence deliberately
# preserves rather than validates MCP protocol metadata, so the demo itself
# checks the two fields that 2026-07-28 requires on every request.
request_count=0
while IFS= read -r request; do
  request_count=$((request_count + 1))
  case "$request" in
    *'"io.modelcontextprotocol/protocolVersion":"2026-07-28"'*) ;;
    *) echo "FAIL: request $request_count is missing required MCP 2026-07-28 metadata" >&2; exit 1 ;;
  esac
  case "$request" in
    *'"io.modelcontextprotocol/clientCapabilities":{}'*) ;;
    *) echo "FAIL: request $request_count is missing required MCP 2026-07-28 metadata" >&2; exit 1 ;;
  esac
done <"$requests"
if [ "$request_count" -ne 3 ]; then
  echo "FAIL: expected 3 flagship requests, got $request_count" >&2
  exit 1
fi

fail() {
  echo "FAIL: $1" >&2
  if [ -s "$proxy_stderr" ]; then
    echo "Proxy/stub stderr:" >&2
    sed 's/^/  | /' "$proxy_stderr" >&2
  fi
  if [ -s "$responses" ]; then
    echo "Responses received:" >&2
    sed 's/^/  | /' "$responses" >&2
  fi
  exit 1
}

# Drive the proxy request-by-request. Waiting for the untrusted read result
# before sending the write makes the prompt-injection sequence deterministic;
# no LLM, network, sleep, or third-party system is involved.
coproc PROXY { "$AGENTFENCE" proxy \
  --policy "$policy" \
  --audit-log "$audit" \
  --tamper-evident \
  --no-interactive \
  -- "$stub" 2>"$proxy_stderr"; }
proxy_in="${PROXY[1]}"
proxy_out="${PROXY[0]}"
proxy_pid="$PROXY_PID"

request_line() { sed -n "${1}p" "$requests"; }
send() { printf '%s\n' "$1" >&"$proxy_in"; }
await_id() {
  local want="$1" line
  while IFS= read -r line <&"$proxy_out"; do
    printf '%s\n' "$line" >>"$responses"
    case "$line" in *"\"id\":$want"*) return 0 ;; esac
  done
  return 1
}

send "$(request_line 1)"
await_id 1 || fail "proxy closed before the bounded-read response"
send "$(request_line 2)"
await_id 2 || fail "proxy closed before the denied-write response"
send "$(request_line 3)"
await_id 3 || fail "proxy closed before the upstream diagnostic response"

eval "exec ${proxy_in}>&-"
wait "$proxy_pid" || fail "AgentFence proxy exited unexpectedly"

safe_response="$(grep '"id":1' "$responses")" || fail "missing bounded-read response"
blocked_response="$(grep '"id":2' "$responses")" || fail "missing denied-write response"
upstream_response="$(grep '"id":3' "$responses")" || fail "missing upstream diagnostic response"

case "$safe_response" in
  *'"result"'*'Ignore previous instructions'*'.env'*) ;;
  *) fail "the bounded read did not return the injected fixture" ;;
esac
case "$safe_response" in
  *'"resultType":"complete"'*) ;;
  *) fail "the upstream response is missing MCP resultType=complete" ;;
esac
case "$blocked_response" in
  *'"code":-32001'*) ;;
  *) fail "the .env write was not blocked with BlockedByPolicy" ;;
esac
case "$upstream_response" in
  *'"receivedTools":["filesystem.read"]'*) ;;
  *) fail "upstream received an unexpected tool call: $upstream_response" ;;
esac

# Normalize only runtime-generated envelope fields. Everything security-relevant
# (tool, arguments, decision, reason, reason code, redaction, sequence) remains
# exact and is compared with the committed receipt.
sed -E \
  -e 's/"session_id":"[^"]+"/"session_id":"<session_id>"/' \
  -e 's/"timestamp":"[^"]+"/"timestamp":"<timestamp>"/' \
  -e 's/"prev_hash":"[0-9a-f]+"/"prev_hash":"<prev_hash>"/' \
  -e 's/"hash":"[0-9a-f]+"/"hash":"<hash>"/' \
  "$audit" >"$actual_receipt"

if ! cmp -s "$expected_receipt" "$actual_receipt"; then
  echo "FAIL: flagship audit receipt drifted" >&2
  diff -u "$expected_receipt" "$actual_receipt" >&2 || true
  exit 1
fi
if grep -q 'sk-demo-not-a-real-secret' "$audit"; then
  fail "the fake secret leaked into the audit log"
fi
verify_output="$("$AGENTFENCE" audit verify --log "$audit")" || \
  fail "the audit hash chain did not verify"

cat >"$actual_summary" <<'EOF'
AgentFence flagship MCP demo
ALLOW filesystem.read path=project-notes.txt -> upstream
DENY filesystem.write path=.env -> BlockedByPolicy before upstream
PROOF upstream received tools: ["filesystem.read"]
PASS safe read executed; injected .env write blocked before side effect.
EOF
if ! cmp -s "$expected_summary" "$actual_summary"; then
  echo "FAIL: flagship terminal summary drifted" >&2
  diff -u "$expected_summary" "$actual_summary" >&2 || true
  exit 1
fi

cat "$actual_summary"
echo
echo "RECEIPT (runtime fields normalized; fake secret redacted)"
cat "$actual_receipt"
echo
printf '%s\n' "$verify_output"
