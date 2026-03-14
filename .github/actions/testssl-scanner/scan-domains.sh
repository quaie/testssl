#!/bin/bash
set -euo pipefail

DOMAINS_FILE="${1:-domains.txt}"
OUTPUT_FILE="${2:-testssl-results.json}"
TIMEOUT="${3:-60}"

# Read domains from file (one per line, trim whitespace)
mapfile -t DOMAINS < "$DOMAINS_FILE"

RESULTS=()

for DOMAIN in "${DOMAINS[@]}"; do
  DOMAIN=$(echo "$DOMAIN" | xargs)  # trim
  if [[ -z "$DOMAIN" ]]; then continue; fi

  echo "Scanning $DOMAIN..."
  TEMP_JSON=$(mktemp)
  TEMP_LOG=$(mktemp)

  timeout "$TIMEOUT" ./testssl.sh \
    --jsonfile "$TEMP_JSON" \
    --quiet \
    --warnings off \
    "$DOMAIN" > "$TEMP_LOG" 2>&1 || true

  # Extract required fields from JSON (testssl.sh flat JSON structure)
  DOMAIN_CLEAN=$(echo "$DOMAIN" | sed 's/:443$//')  # clean port if present
  IP=$(jq -r '.ip // "unknown"' "$TEMP_JSON" 2>/dev/null || echo "scan_failed")
  GRADE=$(jq -r '.grade.overall // "unknown"' "$TEMP_JSON" 2>/dev/null || echo "scan_failed")
  CIPHERS=$(jq -r '.findings[]? | select(.id?=="ciphers") | .finding // empty' "$TEMP_JSON" | tr '\n' ',' | sed 's/,$//')

  RESULTS+=("{
    \"domain\": \"$DOMAIN_CLEAN\",
    \"ip_addresses\": \"$IP\",
    \"grade\": \"$GRADE\",
    \"cipher_types\": \"$CIPHERS\"
  }")

  rm -f "$TEMP_JSON" "$TEMP_LOG"
done

# Write JSON array
printf '%s\n' "${RESULTS[@]}" | jq -s . > "$OUTPUT_FILE"
echo "Results saved to $OUTPUT_FILE"
