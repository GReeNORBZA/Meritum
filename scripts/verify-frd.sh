#!/usr/bin/env bash
# verify-frd.sh — Verify an updated FRD file meets quality checks
# Usage: ./scripts/verify-frd.sh <frd-file-path> [min-words]

set -euo pipefail

FILE="${1:?Usage: verify-frd.sh <file-path> [min-words]}"
MIN_WORDS="${2:-500}"

# Check file exists
if [[ ! -f "$FILE" ]]; then
  echo "FAIL: File does not exist: $FILE"
  exit 1
fi

# Check file is not empty
if [[ ! -s "$FILE" ]]; then
  echo "FAIL: File is empty: $FILE"
  exit 1
fi

# Check minimum word count
WORD_COUNT=$(wc -w < "$FILE" | tr -d ' ')
if [[ $WORD_COUNT -lt $MIN_WORDS ]]; then
  echo "FAIL: File too short ($WORD_COUNT words, minimum $MIN_WORDS)"
  exit 1
fi

# Check for FRD header pattern
if ! head -10 "$FILE" | grep -qiE "meritum|domain|functional requirements"; then
  echo "FAIL: Missing FRD header (expected 'Meritum', 'Domain', or 'Functional Requirements' in first 10 lines)"
  exit 1
fi

# Check for markdown heading structure
HEADING_COUNT=$(grep -c '^#' "$FILE" || true)
if [[ $HEADING_COUNT -lt 3 ]]; then
  echo "FAIL: Insufficient document structure ($HEADING_COUNT headings, expected >= 3)"
  exit 1
fi

# Warn (but don't fail) on placeholder text
PLACEHOLDERS=$(grep -ciE '\bTODO\b|\bPLACEHOLDER\b|\bTBD\b|\bFIXME\b' "$FILE" || true)
if [[ $PLACEHOLDERS -gt 0 ]]; then
  echo "WARN: File contains $PLACEHOLDERS lines with placeholder text (TODO/TBD/FIXME)"
fi

echo "PASS: $FILE ($WORD_COUNT words, $HEADING_COUNT headings)"
exit 0
