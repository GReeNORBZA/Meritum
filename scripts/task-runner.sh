#!/usr/bin/env bash
# ============================================================================
# Meritum Build Task Runner
# Orchestrates Claude Code invocations for automated build-test-fix workflow.
#
# Each task gets a fresh Claude Code context window with only:
#   - CLAUDE.md (always loaded by Claude Code automatically)
#   - The task prompt (scoped to one work unit)
#   - Referenced FRD sections (included in the prompt)
#
# Usage:
#   ./scripts/task-runner.sh <manifest-file>
#   ./scripts/task-runner.sh tasks/domain-01-iam.tasks
#   ./scripts/task-runner.sh tasks/domain-05-providers.tasks --resume
#   ./scripts/task-runner.sh tasks/domain-05-providers.tasks --dry-run
#
# Manifest format: see tasks/*.tasks files
# ============================================================================

set -euo pipefail

# --- Configuration ---
MAX_RETRIES=2                    # Retry a failed task this many times
RETRY_DELAY=5                    # Seconds between retries
LOG_DIR="logs/build"
TASK_TIMEOUT=600                 # 10 minutes per task invocation
CLAUDE_CMD="claude"              # Claude Code CLI command

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Parse Arguments ---
MANIFEST=""
RESUME=false
DRY_RUN=false

for arg in "$@"; do
  case $arg in
    --resume)  RESUME=true ;;
    --dry-run) DRY_RUN=true ;;
    *)         MANIFEST="$arg" ;;
  esac
done

if [[ -z "$MANIFEST" ]]; then
  echo -e "${RED}Usage: $0 <manifest-file> [--resume] [--dry-run]${NC}"
  exit 1
fi

if [[ ! -f "$MANIFEST" ]]; then
  echo -e "${RED}Manifest not found: $MANIFEST${NC}"
  exit 1
fi

# --- Setup Logging ---
PROJECT_ROOT="$(pwd)"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
MANIFEST_NAME=$(basename "$MANIFEST" .tasks)
RUN_LOG_DIR="${PROJECT_ROOT}/${LOG_DIR}/${MANIFEST_NAME}-${TIMESTAMP}"
mkdir -p "$RUN_LOG_DIR"

SUMMARY_FILE="${RUN_LOG_DIR}/summary.log"
PROGRESS_FILE="${PROJECT_ROOT}/${LOG_DIR}/${MANIFEST_NAME}.progress"

echo "Build run: ${MANIFEST_NAME}" > "$SUMMARY_FILE"
echo "Started:   $(date -Iseconds)" >> "$SUMMARY_FILE"
echo "Manifest:  ${MANIFEST}" >> "$SUMMARY_FILE"
echo "---" >> "$SUMMARY_FILE"

# --- Parse Manifest ---
# Manifest format:
#   Lines starting with # are comments
#   Lines starting with ## are section headers (logged but not executed)
#   Task lines:  TASK_ID | DESCRIPTION | PROMPT_FILE | VERIFY_COMMAND
#
# Example:
#   ## Domain 5: Provider Management - Schema Layer
#   D05-001 | Drizzle schema for providers table | tasks/prompts/d05-001.md | pnpm --filter shared build
#   D05-002 | Drizzle schema for business_arrangements | tasks/prompts/d05-002.md | pnpm --filter shared build

declare -a TASK_IDS
declare -a TASK_DESCS
declare -a TASK_PROMPTS
declare -a TASK_VERIFY
TASK_COUNT=0

while IFS= read -r line; do
  # Skip empty lines and comments
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^#$ ]] && continue
  [[ "$line" =~ ^#[^#] ]] && continue

  # Section headers
  if [[ "$line" =~ ^## ]]; then
    echo -e "${BLUE}${line}${NC}"
    echo "$line" >> "$SUMMARY_FILE"
    continue
  fi

  # Parse task line
  IFS='|' read -r id desc prompt verify <<< "$line"
  TASK_IDS+=("$(echo "$id" | xargs)")
  TASK_DESCS+=("$(echo "$desc" | xargs)")
  TASK_PROMPTS+=("$(echo "$prompt" | xargs)")
  TASK_VERIFY+=("$(echo "$verify" | xargs)")
  TASK_COUNT=$((TASK_COUNT + 1))
done < "$MANIFEST"

echo -e "${BLUE}Loaded ${TASK_COUNT} tasks from ${MANIFEST}${NC}"

# --- Resume Support ---
SKIP_UNTIL=""
if [[ "$RESUME" == true && -f "$PROGRESS_FILE" ]]; then
  SKIP_UNTIL=$(tail -1 "$PROGRESS_FILE" | cut -d' ' -f1)
  echo -e "${YELLOW}Resuming after task: ${SKIP_UNTIL}${NC}"
fi

# --- Execute Tasks ---
PASSED=0
FAILED=0
BLOCKED=0
SKIPPED=0
SKIP_MODE=false

if [[ -n "$SKIP_UNTIL" ]]; then
  SKIP_MODE=true
fi

for i in $(seq 0 $((TASK_COUNT - 1))); do
  TASK_ID="${TASK_IDS[$i]}"
  TASK_DESC="${TASK_DESCS[$i]}"
  PROMPT_FILE="${TASK_PROMPTS[$i]}"
  VERIFY_CMD="${TASK_VERIFY[$i]}"

  # Resume: skip until we find the last completed task
  if [[ "$SKIP_MODE" == true ]]; then
    if [[ "$TASK_ID" == "$SKIP_UNTIL" ]]; then
      SKIP_MODE=false
    fi
    echo -e "${YELLOW}  SKIP ${TASK_ID}: ${TASK_DESC}${NC}"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  echo ""
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}  Task ${TASK_ID}: ${TASK_DESC}${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

  # Dry run: just print what would happen
  if [[ "$DRY_RUN" == true ]]; then
    echo -e "  Prompt: ${PROMPT_FILE}"
    echo -e "  Verify: ${VERIFY_CMD}"
    continue
  fi

  # Check prompt file exists
  if [[ ! -f "$PROMPT_FILE" ]]; then
    echo -e "${RED}  MISSING PROMPT: ${PROMPT_FILE}${NC}"
    echo "MISSING ${TASK_ID} ${TASK_DESC} — prompt file not found: ${PROMPT_FILE}" >> "$SUMMARY_FILE"
    FAILED=$((FAILED + 1))
    continue
  fi

  TASK_LOG="${RUN_LOG_DIR}/${TASK_ID}.log"
  TASK_PASSED=false

  # --- Attempt Loop (initial + retries) ---
  for attempt in $(seq 0 "$MAX_RETRIES"); do
    if [[ $attempt -gt 0 ]]; then
      echo -e "${YELLOW}  Retry ${attempt}/${MAX_RETRIES} after ${RETRY_DELAY}s...${NC}"
      sleep "$RETRY_DELAY"
    fi

    ATTEMPT_LOG="${RUN_LOG_DIR}/${TASK_ID}-attempt${attempt}.log"

    # Build the prompt
    PROMPT=$(cat "$PROMPT_FILE")

    # Prepend minimal project identity (always included, ~10 lines)
    PREAMBLE="Project: Meritum Health Technologies — Alberta physician billing platform (AHCIP + WCB).
Regulatory: Health Information Act (Alberta). All PHI must stay in Canada. IMA required per physician.
Security: Physician tenant isolation on every PHI query. No PHI in emails, errors, or logs. PHN masked as 123******.
Stack: Fastify 5 + Drizzle + PostgreSQL 16 (DO Toronto) | Next.js 15 (App Router) | Vitest + Supertest
Auth: Lucia sessions + custom IAM. Argon2id passwords. Mandatory TOTP MFA. 24h absolute / 60min idle session expiry.
Refer to CLAUDE.md for all coding conventions, module structure, and security testing requirements."

    # If this is a retry, prepend failure context from previous attempt
    if [[ $attempt -gt 0 && -f "${RUN_LOG_DIR}/${TASK_ID}-verify-attempt$((attempt-1)).log" ]]; then
      FAILURE_OUTPUT=$(tail -50 "${RUN_LOG_DIR}/${TASK_ID}-verify-attempt$((attempt-1)).log")
      PROMPT="[TASK] [RETRY ${attempt}/${MAX_RETRIES}]

${PREAMBLE}

The previous attempt failed verification. Here is the test output from the last run:

\`\`\`
${FAILURE_OUTPUT}
\`\`\`

Fix the failures and ensure all tests pass. Original task:

${PROMPT}"
    else
      PROMPT="[TASK]

${PREAMBLE}

${PROMPT}"
    fi

    # --- Invoke Claude Code ---
    echo -e "  Invoking Claude Code (attempt $((attempt+1)))..."
    set +e
    timeout "$TASK_TIMEOUT" $CLAUDE_CMD -p "$PROMPT" --output-format text > "$ATTEMPT_LOG" 2>&1
    CLAUDE_EXIT=$?
    set -e

    if [[ $CLAUDE_EXIT -ne 0 ]]; then
      echo -e "${RED}  Claude Code exited with code ${CLAUDE_EXIT}${NC}"
      echo "  See: ${ATTEMPT_LOG}"

      # Check for timeout
      if [[ $CLAUDE_EXIT -eq 124 ]]; then
        echo -e "${RED}  TIMEOUT after ${TASK_TIMEOUT}s${NC}"
      fi
      continue
    fi

    # Check for TASK_BLOCKED signal
    if grep -q '\[TASK_BLOCKED\]' "$ATTEMPT_LOG"; then
      BLOCK_REASON=$(grep '\[TASK_BLOCKED\]' "$ATTEMPT_LOG" | head -1 | sed 's/.*\[TASK_BLOCKED\] reason: //')
      echo -e "${RED}  BLOCKED: ${BLOCK_REASON}${NC}"
      echo "BLOCKED ${TASK_ID} ${TASK_DESC} — ${BLOCK_REASON}" >> "$SUMMARY_FILE"
      BLOCKED=$((BLOCKED + 1))
      TASK_PASSED=false
      break
    fi

    # --- Run Verification Command ---
    echo -e "  Running verification: ${VERIFY_CMD}"
    VERIFY_LOG="${RUN_LOG_DIR}/${TASK_ID}-verify-attempt${attempt}.log"
    set +e
    ( eval "$VERIFY_CMD" ) > "$VERIFY_LOG" 2>&1
    VERIFY_EXIT=$?
    set -e

    if [[ $VERIFY_EXIT -eq 0 ]]; then
      echo -e "${GREEN}  ✓ PASSED${NC}"
      TASK_PASSED=true
      break
    else
      echo -e "${RED}  ✗ Verification failed (exit code ${VERIFY_EXIT})${NC}"
      echo -e "  Failure output (last 10 lines):"
      tail -10 "$VERIFY_LOG" | sed 's/^/    /'
    fi
  done

  # --- Record Result ---
  if [[ "$TASK_PASSED" == true ]]; then
    echo "PASSED ${TASK_ID} ${TASK_DESC}" >> "$SUMMARY_FILE"
    echo "${TASK_ID} PASSED" >> "$PROGRESS_FILE"
    PASSED=$((PASSED + 1))
  elif [[ $BLOCKED -eq 0 || $(tail -1 "$SUMMARY_FILE" | grep -c "BLOCKED ${TASK_ID}") -eq 0 ]]; then
    echo "FAILED ${TASK_ID} ${TASK_DESC} — failed after $((MAX_RETRIES+1)) attempts" >> "$SUMMARY_FILE"
    echo "${TASK_ID} FAILED" >> "$PROGRESS_FILE"
    FAILED=$((FAILED + 1))

    # Ask whether to continue or abort
    echo ""
    echo -e "${RED}Task ${TASK_ID} failed after all retries.${NC}"
    echo -e "  Logs: ${RUN_LOG_DIR}/${TASK_ID}-*"
    read -rp "  Continue to next task? [Y/n] " CONTINUE
    if [[ "$CONTINUE" =~ ^[Nn] ]]; then
      echo -e "${YELLOW}Aborting. Resume later with: $0 $MANIFEST --resume${NC}"
      break
    fi
  fi
done

# --- Summary ---
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Build Summary${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}Passed:  ${PASSED}${NC}"
echo -e "  ${RED}Failed:  ${FAILED}${NC}"
echo -e "  ${RED}Blocked: ${BLOCKED}${NC}"
echo -e "  ${YELLOW}Skipped: ${SKIPPED}${NC}"
echo -e "  Total:   ${TASK_COUNT}"
echo ""
echo -e "  Full log: ${RUN_LOG_DIR}/"
echo -e "  Summary:  ${SUMMARY_FILE}"

echo "---" >> "$SUMMARY_FILE"
echo "Finished:  $(date -Iseconds)" >> "$SUMMARY_FILE"
echo "Passed: ${PASSED}, Failed: ${FAILED}, Blocked: ${BLOCKED}, Skipped: ${SKIPPED}" >> "$SUMMARY_FILE"

# Exit with failure if any tasks failed
if [[ $FAILED -gt 0 || $BLOCKED -gt 0 ]]; then
  exit 1
fi
