#!/usr/bin/env bash
# ============================================================================
# build-status.sh — Cross-domain build status dashboard
#
# Reads .build-state/ completion markers and latest log summaries to show
# a quick at-a-glance view of all domains' build status.
#
# Usage:
#   ./scripts/build-status.sh              # Show all domains
#   ./scripts/build-status.sh --verbose    # Include latest log details
#
# Output:
#   Summary table with: domain, status, tasks, timestamp
# ============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

VERBOSE=false
for arg in "$@"; do
  [[ "$arg" == "--verbose" ]] && VERBOSE=true
done

BUILD_STATE_DIR=".build-state"
LOG_DIR="logs/build"
CONFIGS_DIR="configs"

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Build Status Dashboard${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# --- Discover all domains ---
# Sources: config files, completion markers, and log directories
declare -A DOMAINS

# From configs
if [[ -d "$CONFIGS_DIR" ]]; then
  for cfg in "$CONFIGS_DIR"/*.json; do
    [[ -f "$cfg" ]] || continue
    BASENAME=$(basename "$cfg" .json)
    DOMAINS["$BASENAME"]=1
  done
fi

# From completion markers
if [[ -d "$BUILD_STATE_DIR" ]]; then
  for marker in "$BUILD_STATE_DIR"/*.completed; do
    [[ -f "$marker" ]] || continue
    BASENAME=$(basename "$marker" .completed)
    DOMAINS["$BASENAME"]=1
  done
fi

# From log directories (extract manifest name from dir name pattern: name-YYYYMMDD-HHMMSS)
if [[ -d "$LOG_DIR" ]]; then
  for logdir in "$LOG_DIR"/*/; do
    [[ -d "$logdir" ]] || continue
    DIRNAME=$(basename "$logdir")
    # Strip the timestamp suffix: domain-name-20250101-120000 → domain-name
    BASENAME=$(echo "$DIRNAME" | sed -E 's/-[0-9]{8}-[0-9]{6}$//')
    [[ -n "$BASENAME" ]] && DOMAINS["$BASENAME"]=1
  done
fi

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
  echo -e "${YELLOW}  No domains found. Run init-project.sh to set up your first domain.${NC}"
  echo ""
  exit 0
fi

# --- Collect status for each domain ---
TOTAL_DOMAINS=0
COMPLETED_DOMAINS=0
INCOMPLETE_DOMAINS=0
NOT_STARTED_DOMAINS=0

# Sort domain names
SORTED_DOMAINS=($(echo "${!DOMAINS[@]}" | tr ' ' '\n' | sort))

# Print header
printf "  ${BOLD}%-40s %-12s %-14s %-20s${NC}\n" "DOMAIN" "STATUS" "TASKS" "COMPLETED AT"
echo -e "  ${DIM}$(printf '─%.0s' {1..86})${NC}"

for domain in "${SORTED_DOMAINS[@]}"; do
  TOTAL_DOMAINS=$((TOTAL_DOMAINS + 1))

  MARKER_FILE="${BUILD_STATE_DIR}/${domain}.completed"
  STATUS=""
  TASKS_INFO=""
  COMPLETED_AT=""

  if [[ -f "$MARKER_FILE" ]]; then
    # --- Completed ---
    STATUS="${GREEN}COMPLETED${NC}"
    COMPLETED_DOMAINS=$((COMPLETED_DOMAINS + 1))

    # Parse marker file
    TASKS_PASSED=$(grep "^tasks_passed=" "$MARKER_FILE" 2>/dev/null | cut -d= -f2)
    TASKS_TOTAL=$(grep "^tasks_total=" "$MARKER_FILE" 2>/dev/null | cut -d= -f2)
    MARKER_TIME=$(grep "^completed_at=" "$MARKER_FILE" 2>/dev/null | cut -d= -f2)

    TASKS_INFO="${TASKS_PASSED:-?}/${TASKS_TOTAL:-?} passed"
    # Format timestamp: strip timezone info for display
    if [[ -n "$MARKER_TIME" ]]; then
      COMPLETED_AT=$(echo "$MARKER_TIME" | sed -E 's/\+.*//' | sed 's/T/ /')
    fi
  else
    # Check if there are any logs (started but not completed)
    LATEST_LOG=""
    if [[ -d "$LOG_DIR" ]]; then
      LATEST_LOG=$(ls -dt "$LOG_DIR/${domain}"-*/ 2>/dev/null | head -1)
    fi

    if [[ -n "$LATEST_LOG" && -d "$LATEST_LOG" ]]; then
      # --- Incomplete (has logs but no completion marker) ---
      INCOMPLETE_DOMAINS=$((INCOMPLETE_DOMAINS + 1))

      # Read summary.log if available
      SUMMARY_FILE="${LATEST_LOG}/summary.log"
      if [[ -f "$SUMMARY_FILE" ]]; then
        RESULT_LINE=$(grep -E '^Passed:|^Failed:|^Blocked:' "$SUMMARY_FILE" 2>/dev/null | tail -1)
        if [[ -n "$RESULT_LINE" ]]; then
          STATUS="${YELLOW}INCOMPLETE${NC}"
          TASKS_INFO="$RESULT_LINE"
        else
          STATUS="${YELLOW}INCOMPLETE${NC}"
          # Count pass/fail from progress file
          PROGRESS_FILE="${LATEST_LOG}/.progress"
          if [[ -f "$PROGRESS_FILE" ]]; then
            P_COUNT=$(grep -c "PASSED" "$PROGRESS_FILE" 2>/dev/null || true)
            F_COUNT=$(grep -c "FAILED" "$PROGRESS_FILE" 2>/dev/null || true)
            TASKS_INFO="${P_COUNT} passed, ${F_COUNT} failed"
          else
            TASKS_INFO="(in progress?)"
          fi
        fi
      else
        STATUS="${YELLOW}IN PROGRESS${NC}"
        TASKS_INFO="(logs exist)"
      fi

      # Extract timestamp from log dir name
      LOG_DIRNAME=$(basename "$LATEST_LOG")
      COMPLETED_AT=$(echo "$LOG_DIRNAME" | grep -oE '[0-9]{8}-[0-9]{6}' | sed -E 's/([0-9]{4})([0-9]{2})([0-9]{2})-([0-9]{2})([0-9]{2})([0-9]{2})/\1-\2-\3 \4:\5:\6/')
    else
      # --- Not started ---
      NOT_STARTED_DOMAINS=$((NOT_STARTED_DOMAINS + 1))
      STATUS="${DIM}NOT STARTED${NC}"
      TASKS_INFO=""
      COMPLETED_AT=""

      # Try to count tasks from config
      CONFIG_FILE="${CONFIGS_DIR}/${domain}.json"
      if [[ -f "$CONFIG_FILE" ]]; then
        TASK_COUNT=$(node -e "
          const cfg = JSON.parse(require('fs').readFileSync(process.argv[1], 'utf-8'));
          let count = 0;
          for (const s of (cfg.sections || [])) count += (s.tasks || []).length;
          console.log(count);
        " "$CONFIG_FILE" 2>/dev/null || echo "?")
        TASKS_INFO="${TASK_COUNT} tasks defined"
      fi
    fi
  fi

  printf "  %-40s %-24s %-14s %-20s\n" "$domain" "$(echo -e "$STATUS")" "$TASKS_INFO" "$COMPLETED_AT"

  # Verbose: show latest failure details
  if [[ "$VERBOSE" == true ]]; then
    LATEST_LOG=$(ls -dt "$LOG_DIR/${domain}"-*/ 2>/dev/null | head -1)
    if [[ -n "$LATEST_LOG" && -d "$LATEST_LOG" ]]; then
      SUMMARY_FILE="${LATEST_LOG}/summary.log"
      if [[ -f "$SUMMARY_FILE" ]]; then
        # Show failed/blocked tasks
        FAILURES=$(grep -E '^(FAILED|BLOCKED)' "$SUMMARY_FILE" 2>/dev/null || true)
        if [[ -n "$FAILURES" ]]; then
          echo -e "  ${DIM}  Latest failures:${NC}"
          while IFS= read -r line; do
            echo -e "  ${RED}    ${line}${NC}"
          done <<< "$FAILURES"
        fi
      fi
    fi
  fi
done

# --- Summary ---
echo ""
echo -e "  ${DIM}$(printf '─%.0s' {1..86})${NC}"
printf "  ${BOLD}%-40s${NC}" "TOTAL: ${TOTAL_DOMAINS} domain(s)"
echo ""
echo -e "  ${GREEN}Completed:   ${COMPLETED_DOMAINS}${NC}"
if [[ $INCOMPLETE_DOMAINS -gt 0 ]]; then
  echo -e "  ${YELLOW}Incomplete:  ${INCOMPLETE_DOMAINS}${NC}"
fi
if [[ $NOT_STARTED_DOMAINS -gt 0 ]]; then
  echo -e "  ${DIM}Not started: ${NOT_STARTED_DOMAINS}${NC}"
fi

# --- Lock status ---
if [[ -d "$BUILD_STATE_DIR" ]]; then
  ACTIVE_LOCKS=()
  for lockfile in "$BUILD_STATE_DIR"/*.lock; do
    [[ -f "$lockfile" ]] || continue
    LOCK_PID=$(cat "$lockfile" 2>/dev/null || true)
    if [[ -n "$LOCK_PID" ]] && kill -0 "$LOCK_PID" 2>/dev/null; then
      LOCK_NAME=$(basename "$lockfile" .lock)
      ACTIVE_LOCKS+=("${LOCK_NAME} (PID ${LOCK_PID})")
    fi
  done

  if [[ ${#ACTIVE_LOCKS[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${CYAN}Active builds:${NC}"
    for lock in "${ACTIVE_LOCKS[@]}"; do
      echo -e "  ${CYAN}  ▸ ${lock}${NC}"
    done
  fi
fi

echo ""
