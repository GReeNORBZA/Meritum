#!/usr/bin/env bash
# ============================================================================
# check-prompt-staleness.sh
# Scans prompt .md files for backtick-quoted file/directory paths and checks
# whether those paths actually exist in the codebase.
#
# Usage:
#   ./scripts/check-prompt-staleness.sh <prompts-dir>
#   ./scripts/check-prompt-staleness.sh scripts/tasks/prompts/d05/
#
# Exit codes:
#   0 — All referenced paths exist
#   1 — One or more referenced paths are missing (stale)
# ============================================================================

set -euo pipefail

PROMPTS_DIR="${1:-}"

if [[ -z "$PROMPTS_DIR" ]]; then
  echo "Usage: $0 <prompts-dir>"
  echo "Example: $0 scripts/tasks/prompts/d05/"
  exit 1
fi

if [[ ! -d "$PROMPTS_DIR" ]]; then
  echo "Error: Directory not found: $PROMPTS_DIR"
  exit 1
fi

# Counters
TOTAL_STALE=0
STALE_FILES=0
TOTAL_PROMPT_FILES=0

# Collect all .md files
shopt -s nullglob
MD_FILES=("$PROMPTS_DIR"/*.md)
shopt -u nullglob

if [[ ${#MD_FILES[@]} -eq 0 ]]; then
  echo "No .md files found in $PROMPTS_DIR"
  exit 0
fi

for md_file in "${MD_FILES[@]}"; do
  TOTAL_PROMPT_FILES=$((TOTAL_PROMPT_FILES + 1))
  FILE_HAS_STALE=false

  # Extract backtick-quoted paths:
  #   - Must contain at least one /
  #   - Must either end with a file extension (.ts, .js, .json, .yaml, .yml, .md, .sh, .sql, .env, etc.)
  #     OR end with / (directory path)
  # Use grep -oP to extract content inside backticks matching the pattern
  PATHS=$(grep -oP '`([^`]*?/[^`]*?\.(?:ts|js|tsx|jsx|json|yaml|yml|md|sh|sql|env|css|scss|html|xml|toml|cfg|conf|ini|txt|csv|mjs|cjs|mts|cts|d\.ts)|[^`]*?/[^`]*?/)`' "$md_file" 2>/dev/null | sed 's/^`//;s/`$//' || true)

  if [[ -z "$PATHS" ]]; then
    continue
  fi

  while IFS= read -r ref_path; do
    # Skip empty lines
    [[ -z "$ref_path" ]] && continue

    # Skip URLs (http://, https://)
    [[ "$ref_path" =~ ^https?:// ]] && continue

    # Skip paths that are clearly not filesystem references (e.g., npm package names)
    # A valid path should start with a letter, dot, or slash
    [[ ! "$ref_path" =~ ^[a-zA-Z./] ]] && continue

    # Check if the path exists (file or directory)
    if [[ ! -e "$ref_path" ]]; then
      echo "STALE: $md_file references $ref_path (not found)"
      TOTAL_STALE=$((TOTAL_STALE + 1))
      FILE_HAS_STALE=true
    fi
  done <<< "$PATHS"

  if [[ "$FILE_HAS_STALE" == true ]]; then
    STALE_FILES=$((STALE_FILES + 1))
  fi
done

# Output result
if [[ $TOTAL_STALE -eq 0 ]]; then
  echo "OK: All referenced paths exist in $TOTAL_PROMPT_FILES prompt files"
  exit 0
else
  echo ""
  echo "$TOTAL_STALE stale references across $STALE_FILES prompt files"
  exit 1
fi
