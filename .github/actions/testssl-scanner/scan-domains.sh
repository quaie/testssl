#!/bin/bash
set -euo pipefail

DOMAINS_FILE="${DOMAINS_FILE:-domains.txt}"
OUTPUT_FILE="${OUTPUT_FILE:-testssl-results.json}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-120}"
TESTSSL_PATH="${TESTSSL_PATH:-./testssl-repo/testssl.sh}"

echo "Scanning → capture partial data even on timeout"

if [[ ! -f "$DOMAINS_FILE" ]]; then
  echo "❌ $DOMAINS_FILE missing"
  exit 1
fi

mapfile -t DOMAINS < "$DOMAINS_FILE"
RESULTS=()

for DOMAIN in "${DOMAINS[@]}"; do
  DOMAIN=$(echo "$DOMAIN" | xargs)
  [[ -z "$DOMAIN" ]] && continue

  echo "Scanning $DOMAIN..."
  TEMP_JSON=$(mktemp)

  # Run testssl + check JSON even if timeout
  "$TESTSSL_PATH" \
    --jsonfile "$TEMP_JSON" \
    --quiet \
    --warnings off \
    "$DOMAIN" &
  TEST_PID=$!

  # Wait with timeout BUT check JSON regardless
  if ! timeout "${SCAN_TIMEOUT}s" wait "$TEST_PID"; then
    echo "⚠️  $DOMAIN timed out → checking partial JSON"
  fi

  # ALWAYS try to parse JSON (partial data = success!)
  if jq empty "$TEMP_JSON" 2>/dev/null >/dev/null; then
    DOMAIN_CLEAN=$(echo "$DOMAIN" | sed 's/:443$//')
    
    IP=$(jq -r '.ip // "partial"' "$TEMP_JSON" 2>/dev/null || echo "partial")
    TLS_VERSIONS=$(jq -r '[.findings[]? | select(.id=="protocols")] | map(.finding | split(" ")[0] // empty) | unique | join(", ") // "partial"' "$TEMP_JSON" 2>/dev/null || echo "partial")
    CIPHERS=$(jq -r '[.findings[]? | select(.id=="ciphers")] | map(.finding // empty) | join(", ") // "partial"' "$TEMP_JSON" 2>/dev/null || echo "partial")
    
    RESULTS+=("{
      \"domain\": \"${DOMAIN_CLEAN}\",
      \"ip_addresses\": \"${IP}\",
      \"tls_versions_supported\": \"${TLS_VERSIONS}\",
      \"list_of_ciphers\": \"${CIPHERS}\"
    }")
    
    echo "✅ $DOMAIN | IP:$IP | $(echo "$TLS_VERSIONS" | cut -c1-30)"
  else
    echo "❌ $DOMAIN no JSON"
    RESULTS+=("{
      \"domain\": \"${DOMAIN}\", 
      \"ip_addresses\": \"no_json\",
      \"tls_versions_supported\": \"no_json\",
      \"list_of_ciphers\": \"no_json\"
    }")
  fi

  rm -f "$TEMP_JSON"
done

printf '%s\n' "${RESULTS[@]}" | jq -s . > "$OUTPUT_FILE"
echo "✅ $(jq 'length' "$OUTPUT_FILE") results"

jq '.[].domain, .[].ip_addresses' "$OUTPUT_FILE"
