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
VERIFY_TIMEOUT=120               # 2 minutes per verify command
CLAUDE_CMD="claude"              # Claude Code CLI command
LOG_RETENTION="${LOG_RETENTION:-10}"   # Keep this many recent log dirs per manifest
GIT_CHECKPOINT=true              # Commit after each passed task, rollback on failure
PREFLIGHT_CHECK=true             # Verify environment before starting

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Notification Function ---
# Sends desktop notification and optional webhook POST on build completion.
send_notification() {
  local status="$1"
  local summary="$2"

  # --- Desktop Notification ---
  if [[ "$(uname -s)" == "Linux" ]]; then
    if command -v notify-send &>/dev/null; then
      local urgency="normal"
      if [[ "$status" == "FAILED" ]]; then
        urgency="critical"
      fi
      notify-send --urgency="$urgency" "Task Runner: $status" "$summary" 2>/dev/null || true
    fi
  elif [[ "$(uname -s)" == "Darwin" ]]; then
    if command -v osascript &>/dev/null; then
      osascript -e "display notification \"$summary\" with title \"Task Runner: $status\"" 2>/dev/null || true
    fi
  fi

  # --- Webhook POST ---
  if [[ -n "${NOTIFY_WEBHOOK:-}" ]]; then
    local end_time
    end_time=$(date +%s)
    local duration_secs=$(( end_time - START_TIME ))
    local iso_timestamp
    iso_timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    local json_payload
    json_payload=$(cat <<EOJSON
{
  "status": "${status}",
  "manifest": "${MANIFEST_NAME}",
  "passed": ${PASSED},
  "failed": ${FAILED},
  "blocked": ${BLOCKED},
  "skipped": ${SKIPPED},
  "total": ${TASK_COUNT},
  "duration_seconds": ${duration_secs},
  "timestamp": "${iso_timestamp}",
  "summary": "${summary}",
  "log_dir": "${RUN_LOG_DIR}/"
}
EOJSON
)

    if ! curl -s -o /dev/null -w '' --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        "$NOTIFY_WEBHOOK" 2>/dev/null; then
      echo -e "${YELLOW}  Warning: Failed to POST notification to webhook: ${NOTIFY_WEBHOOK}${NC}"
    fi
  fi
}

# --- Parse Arguments ---
MANIFEST=""
CONFIG_FILE=""
RESUME=false
DRY_RUN=false
CLEAN_LOGS=false
ONLY_TASK=""
NON_INTERACTIVE=false
PARALLEL=1
NOTIFY_WEBHOOK="${TASK_RUNNER_WEBHOOK:-}"

for arg in "$@"; do
  case $arg in
    --resume)          RESUME=true ;;
    --dry-run)         DRY_RUN=true ;;
    --config=*)        CONFIG_FILE="${arg#--config=}" ;;
    --webhook=*)       NOTIFY_WEBHOOK="${arg#--webhook=}" ;;
    --no-checkpoint)   GIT_CHECKPOINT=false ;;
    --no-preflight)    PREFLIGHT_CHECK=false ;;
    --clean-logs)      CLEAN_LOGS=true ;;
    --only=*)          ONLY_TASK="${arg#--only=}" ;;
    --non-interactive) NON_INTERACTIVE=true ;;
    --parallel)        PARALLEL=2 ;;
    --parallel=*)      PARALLEL="${arg#--parallel=}" ;;
    *)                 MANIFEST="$arg" ;;
  esac
done

# Auto-detect non-interactive mode when stdin is not a terminal (e.g., CI pipelines)
if [[ ! -t 0 ]]; then
  NON_INTERACTIVE=true
fi

if [[ -z "$MANIFEST" && "$CLEAN_LOGS" != true ]]; then
  echo -e "${RED}Usage: $0 <manifest-file> [--config=<config.json>] [--resume] [--dry-run] [--only=<task-id>] [--parallel[=N]] [--no-checkpoint] [--no-preflight] [--non-interactive] [--clean-logs]${NC}"
  exit 1
fi

# --- Log Cleanup Mode ---
if [[ "$CLEAN_LOGS" == true ]]; then
  if [[ -z "$MANIFEST" ]]; then
    # No manifest: clean ALL log dirs under logs/build/, keep newest LOG_RETENTION total
    echo -e "${BLUE}Cleaning all log dirs under ${LOG_DIR}/ (keeping newest ${LOG_RETENTION})...${NC}"
    if [[ -d "$LOG_DIR" ]]; then
      OLD_DIRS=$(ls -dt "${LOG_DIR}"/*/ 2>/dev/null | tail -n +$((LOG_RETENTION + 1)))
      if [[ -n "$OLD_DIRS" ]]; then
        REMOVED_COUNT=0
        while IFS= read -r dir; do
          echo -e "${YELLOW}  Removing: ${dir}${NC}"
          rm -rf "$dir"
          REMOVED_COUNT=$((REMOVED_COUNT + 1))
        done <<< "$OLD_DIRS"
        echo -e "${GREEN}Removed ${REMOVED_COUNT} old log dir(s).${NC}"
      else
        echo -e "${GREEN}Nothing to clean — ${LOG_RETENTION} or fewer log dirs exist.${NC}"
      fi
    else
      echo -e "${YELLOW}Log directory ${LOG_DIR}/ does not exist.${NC}"
    fi
  else
    # Manifest provided: clean only dirs matching that manifest's basename pattern
    CLEAN_BASENAME=$(basename "$MANIFEST" .tasks)
    echo -e "${BLUE}Cleaning log dirs matching '${CLEAN_BASENAME}-*' under ${LOG_DIR}/ (keeping newest ${LOG_RETENTION})...${NC}"
    if [[ -d "$LOG_DIR" ]]; then
      OLD_DIRS=$(ls -dt "${LOG_DIR}/${CLEAN_BASENAME}"-*/ 2>/dev/null | tail -n +$((LOG_RETENTION + 1)))
      if [[ -n "$OLD_DIRS" ]]; then
        REMOVED_COUNT=0
        while IFS= read -r dir; do
          echo -e "${YELLOW}  Removing: ${dir}${NC}"
          rm -rf "$dir"
          REMOVED_COUNT=$((REMOVED_COUNT + 1))
        done <<< "$OLD_DIRS"
        echo -e "${GREEN}Removed ${REMOVED_COUNT} old log dir(s) for ${CLEAN_BASENAME}.${NC}"
      else
        echo -e "${GREEN}Nothing to clean — ${LOG_RETENTION} or fewer log dirs exist for ${CLEAN_BASENAME}.${NC}"
      fi
    else
      echo -e "${YELLOW}Log directory ${LOG_DIR}/ does not exist.${NC}"
    fi
  fi
  exit 0
fi

# --- Auto-detect config file if not specified ---
# Convention: manifest "domain-05-provider.tasks" → config "configs/domain-05-provider*.json"
if [[ -z "$CONFIG_FILE" ]]; then
  MANIFEST_BASENAME=$(basename "$MANIFEST" .tasks)
  # Try exact match first, then glob for suffix variations (e.g., -manifests.json)
  if [[ -f "configs/${MANIFEST_BASENAME}.json" ]]; then
    CONFIG_FILE="configs/${MANIFEST_BASENAME}.json"
  else
    CANDIDATES=(configs/${MANIFEST_BASENAME}*.json)
    if [[ -f "${CANDIDATES[0]:-}" ]]; then
      CONFIG_FILE="${CANDIDATES[0]}"
    fi
  fi
fi

if [[ ! -f "$MANIFEST" ]]; then
  echo -e "${RED}Manifest not found: $MANIFEST${NC}"
  exit 1
fi

# --- Config Validation ---
# If a config file is available, validate its schema before proceeding.
VALIDATE_SCRIPT="./scripts/validate-config.sh"
if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" && -f "$VALIDATE_SCRIPT" && "$DRY_RUN" != true ]]; then
  echo -e "${BLUE}Validating config: ${CONFIG_FILE}...${NC}"
  set +e
  "$VALIDATE_SCRIPT" "$CONFIG_FILE" 2>&1
  VALIDATE_EXIT=$?
  set -e
  if [[ $VALIDATE_EXIT -ne 0 ]]; then
    echo -e "${RED}Config validation failed. Fix the errors above before running.${NC}"
    exit 1
  fi
  echo ""
fi

# --- Concurrent Build Lock ---
# Prevent two task-runner instances from operating on the same manifest simultaneously.
MANIFEST_NAME_FOR_LOCK=$(basename "$MANIFEST" .tasks)
LOCK_FILE=".build-state/${MANIFEST_NAME_FOR_LOCK}.lock"
mkdir -p ".build-state"

if [[ -f "$LOCK_FILE" ]]; then
  LOCK_PID=$(cat "$LOCK_FILE" 2>/dev/null || true)
  if [[ -n "$LOCK_PID" ]] && kill -0 "$LOCK_PID" 2>/dev/null; then
    echo -e "${RED}Another task-runner instance (PID ${LOCK_PID}) is already running manifest: ${MANIFEST_NAME_FOR_LOCK}${NC}"
    echo -e "${RED}Lock file: ${LOCK_FILE}${NC}"
    echo -e "${YELLOW}If this is stale, remove the lock file and retry: rm ${LOCK_FILE}${NC}"
    exit 1
  else
    echo -e "${YELLOW}Removing stale lock file (PID ${LOCK_PID} is not running)${NC}"
    rm -f "$LOCK_FILE"
  fi
fi

echo $$ > "$LOCK_FILE"

# Release lock on exit (normal, error, or signal)
# Note: the RESULT_DIR trap (added later) chains to this via combined trap
cleanup_lock() {
  rm -f "$LOCK_FILE"
}
trap cleanup_lock EXIT

# --- Resolve Preamble ---
# The preamble is prepended to every task prompt. Resolution order:
#   1. Config JSON "preamble" field (string or array of strings)
#   2. preamble.txt file in project root
#   3. Generic fallback
PREAMBLE=""

if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
  PREAMBLE=$(node -e "
    const cfg = require('./${CONFIG_FILE}');
    if (typeof cfg.preamble === 'string' && cfg.preamble.trim()) {
      console.log(cfg.preamble.trim());
    } else if (Array.isArray(cfg.preamble) && cfg.preamble.length > 0) {
      console.log(cfg.preamble.join('\n'));
    }
  " 2>/dev/null || true)
fi

if [[ -z "$PREAMBLE" && -f "preamble.txt" ]]; then
  PREAMBLE=$(cat "preamble.txt")
fi

if [[ -z "$PREAMBLE" ]]; then
  PREAMBLE="Refer to CLAUDE.md for all coding conventions, module structure, and testing requirements."
fi

# --- Resolve Language ---
# Read the config's "language" field to drive language-aware preflight checks.
# Defaults to "typescript" for backward compatibility.
CONFIG_LANGUAGE="typescript"
if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
  RESOLVED_LANG=$(node -e "
    const cfg = require('./${CONFIG_FILE}');
    if (typeof cfg.language === 'string' && cfg.language.trim()) {
      console.log(cfg.language.trim());
    }
  " 2>/dev/null || true)
  if [[ -n "$RESOLVED_LANG" ]]; then
    CONFIG_LANGUAGE="$RESOLVED_LANG"
  fi
fi

# --- Start Timer ---
START_TIME=$(date +%s)

# --- Preflight Checks ---
# Catch environmental issues (missing tools, DB down, dirty git state) before
# burning 30 minutes of Claude API calls only to fail on task 1.
if [[ "$PREFLIGHT_CHECK" == true && "$DRY_RUN" != true ]]; then
  echo -e "${BLUE}Running preflight checks...${NC}"
  PREFLIGHT_FAIL=false

  echo -e "  Language: ${CONFIG_LANGUAGE}"

  # 1. Claude CLI available
  if ! command -v "$CLAUDE_CMD" &>/dev/null; then
    echo -e "${RED}  ✗ Claude CLI not found: ${CLAUDE_CMD}${NC}"
    PREFLIGHT_FAIL=true
  else
    echo -e "${GREEN}  ✓ Claude CLI available${NC}"
  fi

  # 2. Node available (needed for orchestration scripts: generate-tasks.js, audit, validate-config)
  if ! command -v node &>/dev/null; then
    echo -e "${RED}  ✗ Node.js not found (required by orchestration scripts)${NC}"
    PREFLIGHT_FAIL=true
  else
    echo -e "${GREEN}  ✓ Node.js $(node -v)${NC}"
  fi

  # 3. Language toolchain — check for the project's primary language tools
  case "$CONFIG_LANGUAGE" in
    typescript|javascript|ts|js)
      # Check for a JS package manager (pnpm > yarn > npm)
      if command -v pnpm &>/dev/null; then
        echo -e "${GREEN}  ✓ pnpm $(pnpm -v)${NC}"
      elif command -v yarn &>/dev/null; then
        echo -e "${GREEN}  ✓ yarn $(yarn -v)${NC}"
      elif command -v npm &>/dev/null; then
        echo -e "${GREEN}  ✓ npm $(npm -v)${NC}"
      else
        echo -e "${RED}  ✗ No JS package manager found (pnpm, yarn, or npm)${NC}"
        PREFLIGHT_FAIL=true
      fi
      ;;
    python|py)
      if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
        echo -e "${RED}  ✗ Python not found${NC}"
        PREFLIGHT_FAIL=true
      else
        PYTHON_CMD=$(command -v python3 || command -v python)
        echo -e "${GREEN}  ✓ Python $($PYTHON_CMD --version 2>&1 | awk '{print $2}')${NC}"
      fi
      # Check for pip/poetry/pipenv
      if command -v poetry &>/dev/null; then
        echo -e "${GREEN}  ✓ poetry $(poetry --version 2>&1 | awk '{print $NF}')${NC}"
      elif command -v pipenv &>/dev/null; then
        echo -e "${GREEN}  ✓ pipenv $(pipenv --version 2>&1 | awk '{print $NF}')${NC}"
      elif command -v pip &>/dev/null || command -v pip3 &>/dev/null; then
        PIP_CMD=$(command -v pip3 || command -v pip)
        echo -e "${GREEN}  ✓ pip $($PIP_CMD --version 2>&1 | awk '{print $2}')${NC}"
      else
        echo -e "${YELLOW}  ! No Python package manager found (poetry, pipenv, or pip)${NC}"
      fi
      ;;
    go|golang)
      if ! command -v go &>/dev/null; then
        echo -e "${RED}  ✗ Go not found${NC}"
        PREFLIGHT_FAIL=true
      else
        echo -e "${GREEN}  ✓ Go $(go version | awk '{print $3}')${NC}"
      fi
      ;;
    rust|rs)
      if ! command -v cargo &>/dev/null; then
        echo -e "${RED}  ✗ Cargo not found${NC}"
        PREFLIGHT_FAIL=true
      else
        echo -e "${GREEN}  ✓ Cargo $(cargo --version | awk '{print $2}')${NC}"
      fi
      if ! command -v rustc &>/dev/null; then
        echo -e "${RED}  ✗ rustc not found${NC}"
        PREFLIGHT_FAIL=true
      else
        echo -e "${GREEN}  ✓ rustc $(rustc --version | awk '{print $2}')${NC}"
      fi
      ;;
    java|kotlin|jvm)
      if ! command -v java &>/dev/null; then
        echo -e "${RED}  ✗ Java not found${NC}"
        PREFLIGHT_FAIL=true
      else
        echo -e "${GREEN}  ✓ Java $(java -version 2>&1 | head -1)${NC}"
      fi
      if command -v mvn &>/dev/null; then
        echo -e "${GREEN}  ✓ Maven $(mvn --version 2>&1 | head -1 | awk '{print $3}')${NC}"
      elif command -v gradle &>/dev/null; then
        echo -e "${GREEN}  ✓ Gradle $(gradle --version 2>&1 | grep Gradle | awk '{print $2}')${NC}"
      else
        echo -e "${YELLOW}  ! No Java build tool found (maven or gradle)${NC}"
      fi
      ;;
    *)
      echo -e "${YELLOW}  ! Unknown language '${CONFIG_LANGUAGE}' — skipping toolchain check${NC}"
      ;;
  esac

  # 4. Git repo and clean working tree (required for checkpointing)
  if [[ "$GIT_CHECKPOINT" == true ]]; then
    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
      echo -e "${YELLOW}  ! Not a git repo — disabling checkpointing${NC}"
      GIT_CHECKPOINT=false
    elif [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
      echo -e "${YELLOW}  ! Uncommitted changes detected. Stashing before build...${NC}"
      git stash push -m "task-runner-preflight-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
      echo -e "${GREEN}  ✓ Changes stashed${NC}"
    else
      echo -e "${GREEN}  ✓ Git working tree clean${NC}"
    fi
  fi

  # 5. Database connectivity (if DATABASE_URL is set)
  if [[ -n "${DATABASE_URL:-}" ]]; then
    if command -v pg_isready &>/dev/null; then
      if pg_isready -d "$DATABASE_URL" -t 3 &>/dev/null; then
        echo -e "${GREEN}  ✓ Database reachable${NC}"
      else
        echo -e "${RED}  ✗ Database unreachable (DATABASE_URL is set but pg_isready failed)${NC}"
        PREFLIGHT_FAIL=true
      fi
    else
      echo -e "${YELLOW}  ! pg_isready not available — skipping DB check${NC}"
    fi
  else
    echo -e "${YELLOW}  ! DATABASE_URL not set — skipping DB check${NC}"
  fi

  # 6. Dependencies installed (language-aware)
  case "$CONFIG_LANGUAGE" in
    typescript|javascript|ts|js)
      if [[ -f "pnpm-lock.yaml" && ! -d "node_modules" ]]; then
        echo -e "${YELLOW}  ! node_modules missing — running pnpm install...${NC}"
        if pnpm install --frozen-lockfile &>/dev/null; then
          echo -e "${GREEN}  ✓ Dependencies installed${NC}"
        else
          echo -e "${RED}  ✗ pnpm install failed${NC}"
          PREFLIGHT_FAIL=true
        fi
      elif [[ -f "yarn.lock" && ! -d "node_modules" ]]; then
        echo -e "${YELLOW}  ! node_modules missing — running yarn install...${NC}"
        if yarn install --frozen-lockfile &>/dev/null; then
          echo -e "${GREEN}  ✓ Dependencies installed${NC}"
        else
          echo -e "${RED}  ✗ yarn install failed${NC}"
          PREFLIGHT_FAIL=true
        fi
      elif [[ -f "package-lock.json" && ! -d "node_modules" ]]; then
        echo -e "${YELLOW}  ! node_modules missing — running npm ci...${NC}"
        if npm ci &>/dev/null; then
          echo -e "${GREEN}  ✓ Dependencies installed${NC}"
        else
          echo -e "${RED}  ✗ npm ci failed${NC}"
          PREFLIGHT_FAIL=true
        fi
      else
        echo -e "${GREEN}  ✓ Dependencies present${NC}"
      fi
      ;;
    python|py)
      if [[ -f "poetry.lock" ]]; then
        if command -v poetry &>/dev/null; then
          echo -e "${GREEN}  ✓ poetry.lock present${NC}"
        fi
      elif [[ -f "Pipfile.lock" ]]; then
        echo -e "${GREEN}  ✓ Pipfile.lock present${NC}"
      elif [[ -f "requirements.txt" ]]; then
        echo -e "${GREEN}  ✓ requirements.txt present${NC}"
      else
        echo -e "${YELLOW}  ! No Python dependency file found (poetry.lock, Pipfile.lock, requirements.txt)${NC}"
      fi
      ;;
    go|golang)
      if [[ -f "go.mod" ]]; then
        echo -e "${GREEN}  ✓ go.mod present${NC}"
      else
        echo -e "${YELLOW}  ! go.mod not found${NC}"
      fi
      ;;
    rust|rs)
      if [[ -f "Cargo.toml" ]]; then
        echo -e "${GREEN}  ✓ Cargo.toml present${NC}"
      else
        echo -e "${YELLOW}  ! Cargo.toml not found${NC}"
      fi
      ;;
    java|kotlin|jvm)
      if [[ -f "pom.xml" ]]; then
        echo -e "${GREEN}  ✓ pom.xml present (Maven)${NC}"
      elif [[ -f "build.gradle" || -f "build.gradle.kts" ]]; then
        echo -e "${GREEN}  ✓ build.gradle present (Gradle)${NC}"
      else
        echo -e "${YELLOW}  ! No Java build file found (pom.xml, build.gradle)${NC}"
      fi
      ;;
    *)
      echo -e "${GREEN}  ✓ Dependencies check skipped (unknown language)${NC}"
      ;;
  esac

  if [[ "$PREFLIGHT_FAIL" == true ]]; then
    echo ""
    echo -e "${RED}Preflight checks failed. Fix the above issues and re-run.${NC}"
    echo -e "${YELLOW}To skip preflight: $0 $MANIFEST --no-preflight${NC}"
    exit 1
  fi

  echo -e "${GREEN}Preflight OK.${NC}"
  echo ""
fi

# --- Cross-Domain Prerequisite Check ---
# If a config file is available and has a "prerequisites" array, verify that each
# listed domain has a completion marker in .build-state/ before proceeding.
if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
  # Extract prerequisites array from config JSON using node (jq may not be available)
  PREREQS=$(node -e "
    const cfg = require('./${CONFIG_FILE}');
    if (Array.isArray(cfg.prerequisites) && cfg.prerequisites.length > 0) {
      console.log(cfg.prerequisites.join('\n'));
    }
  " 2>/dev/null || true)

  if [[ -n "$PREREQS" ]]; then
    echo -e "${BLUE}Checking cross-domain prerequisites...${NC}"
    PREREQ_MISSING=()

    while IFS= read -r prereq; do
      MARKER_FILE=".build-state/${prereq}.completed"
      if [[ -f "$MARKER_FILE" ]]; then
        echo -e "${GREEN}  ✓ ${prereq} — completed${NC}"
      else
        echo -e "${RED}  ✗ ${prereq} — not completed (missing ${MARKER_FILE})${NC}"
        PREREQ_MISSING+=("$prereq")
      fi
    done <<< "$PREREQS"

    if [[ ${#PREREQ_MISSING[@]} -gt 0 ]]; then
      echo ""
      echo -e "${RED}Cross-domain prerequisite check failed.${NC}"
      echo -e "${RED}The following prerequisite domains must be built successfully first:${NC}"
      for missing in "${PREREQ_MISSING[@]}"; do
        echo -e "${RED}  - ${missing}${NC}"
      done
      echo ""
      echo -e "${YELLOW}Run the prerequisite domain manifests first, then re-run this manifest.${NC}"
      exit 1
    fi

    echo -e "${GREEN}All prerequisites satisfied.${NC}"
    echo ""
  fi
elif [[ -z "$CONFIG_FILE" ]]; then
  echo -e "${YELLOW}  ! No config file found — skipping prerequisite check.${NC}"
  echo ""
fi

# --- Prompt Staleness Check ---
if [[ "$DRY_RUN" != true ]]; then
  STALENESS_SCRIPT="./scripts/check-prompt-staleness.sh"

  if [[ ! -f "$STALENESS_SCRIPT" ]]; then
    echo -e "${YELLOW}  Warning: ${STALENESS_SCRIPT} not found — skipping staleness check${NC}"
  else
    # Extract the prompts directory from the manifest.
    # Manifest lines look like: D05-010 | ... | tasks/prompts/d05/D05-010.md | ...
    # We grab the first prompt path and derive its directory.
    FIRST_PROMPT_PATH=$(grep -v '^\s*#' "$MANIFEST" | grep -v '^\s*$' | head -1 | awk -F'|' '{print $3}' | xargs)
    if [[ -n "$FIRST_PROMPT_PATH" ]]; then
      PROMPTS_DIRECTORY=$(dirname "$FIRST_PROMPT_PATH")

      echo -e "${BLUE}Checking prompt staleness in ${PROMPTS_DIRECTORY}/...${NC}"
      set +e
      STALENESS_OUTPUT=$("$STALENESS_SCRIPT" "$PROMPTS_DIRECTORY" 2>&1)
      STALENESS_EXIT=$?
      set -e

      if [[ $STALENESS_EXIT -ne 0 ]]; then
        # Stale references found
        echo "$STALENESS_OUTPUT"

        if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
          echo -e "${YELLOW}Stale prompts detected. Auto-regenerating from config...${NC}"
          set +e
          node scripts/generate-tasks.js "$CONFIG_FILE" 2>&1
          set -e

          # Re-run staleness check after regeneration
          set +e
          STALENESS_OUTPUT=$("$STALENESS_SCRIPT" "$PROMPTS_DIRECTORY" 2>&1)
          STALENESS_EXIT=$?
          set -e

          if [[ $STALENESS_EXIT -ne 0 ]]; then
            echo "$STALENESS_OUTPUT"
            echo -e "${YELLOW}  Warning: Some references remain stale after regeneration — proceeding anyway (Claude usually adapts)${NC}"
          else
            echo -e "${GREEN}  Prompts up to date${NC}"
          fi
        else
          echo -e "${YELLOW}  Warning: Stale prompt references detected but no config file available for regeneration — proceeding anyway (Claude usually adapts)${NC}"
        fi
      else
        echo -e "${GREEN}  Prompts up to date${NC}"
      fi
    fi
  fi
fi

# --- Setup Logging ---
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
MANIFEST_NAME=$(basename "$MANIFEST" .tasks)
RUN_LOG_DIR="${LOG_DIR}/${MANIFEST_NAME}-${TIMESTAMP}"
mkdir -p "$RUN_LOG_DIR"

SUMMARY_FILE="${RUN_LOG_DIR}/summary.log"
PROGRESS_FILE="${RUN_LOG_DIR}/.progress"

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
declare -a TASK_SECTION    # Section index for each task (for parallel grouping)
TASK_COUNT=0
CURRENT_SECTION=-1
declare -a SECTION_NAMES   # Human-readable section titles

while IFS= read -r line; do
  # Skip empty lines and comments
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^#$ ]] && continue
  [[ "$line" =~ ^#[^#] ]] && continue

  # Section headers — track boundaries for parallel execution
  if [[ "$line" =~ ^## ]]; then
    CURRENT_SECTION=$((CURRENT_SECTION + 1))
    SECTION_NAMES+=("$line")
    echo -e "${BLUE}${line}${NC}"
    echo "$line" >> "$SUMMARY_FILE"
    continue
  fi

  # Assign tasks before any section header to section 0
  if [[ $CURRENT_SECTION -lt 0 ]]; then
    CURRENT_SECTION=0
    SECTION_NAMES+=("## (Default Section)")
  fi

  # Parse task line
  IFS='|' read -r id desc prompt verify <<< "$line"
  TASK_IDS+=("$(echo "$id" | xargs)")
  TASK_DESCS+=("$(echo "$desc" | xargs)")
  TASK_PROMPTS+=("$(echo "$prompt" | xargs)")
  TASK_VERIFY+=("$(echo "$verify" | xargs)")
  TASK_SECTION+=("$CURRENT_SECTION")
  TASK_COUNT=$((TASK_COUNT + 1))
done < "$MANIFEST"

SECTION_COUNT=$((CURRENT_SECTION + 1))
echo -e "${BLUE}Loaded ${TASK_COUNT} tasks in ${SECTION_COUNT} section(s) from ${MANIFEST}${NC}"
if [[ "$PARALLEL" -gt 1 ]]; then
  echo -e "${BLUE}Parallel mode: up to ${PARALLEL} concurrent tasks per section${NC}"
fi

# --- Validate --only task ID ---
if [[ -n "$ONLY_TASK" ]]; then
  ONLY_FOUND=false
  for id in "${TASK_IDS[@]}"; do
    if [[ "$id" == "$ONLY_TASK" ]]; then
      ONLY_FOUND=true
      break
    fi
  done
  if [[ "$ONLY_FOUND" != true ]]; then
    echo -e "${RED}Error: --only task '${ONLY_TASK}' not found in manifest.${NC}"
    echo -e "${RED}Valid task IDs:${NC}"
    for id in "${TASK_IDS[@]}"; do
      echo -e "${RED}  - ${id}${NC}"
    done
    exit 1
  fi
  echo -e "${BLUE}Running only task: ${ONLY_TASK}${NC}"
fi

# --- Resume Support ---
SKIP_UNTIL=""
if [[ "$RESUME" == true && -f "$PROGRESS_FILE" ]]; then
  SKIP_UNTIL=$(tail -1 "$PROGRESS_FILE" | cut -d' ' -f1)
  echo -e "${YELLOW}Resuming after task: ${SKIP_UNTIL}${NC}"
fi

# --- Single Task Execution Function ---
# Runs one task through the full attempt loop (invoke Claude, verify, retry).
# In parallel mode, this runs as a background job writing results to a file.
#
# Arguments: task_index
# Output: writes "PASSED", "FAILED", or "BLOCKED" to $RESULT_DIR/$TASK_ID
# Logs: writes to $RUN_LOG_DIR/$TASK_ID-*
#
run_task() {
  local idx="$1"
  local t_id="${TASK_IDS[$idx]}"
  local t_desc="${TASK_DESCS[$idx]}"
  local t_prompt="${TASK_PROMPTS[$idx]}"
  local t_verify="${TASK_VERIFY[$idx]}"

  local result_file="${RESULT_DIR}/${t_id}"
  local task_log="${RUN_LOG_DIR}/${t_id}.log"
  local task_passed=false

  echo -e "${BLUE}  ▸ ${t_id}: ${t_desc}${NC}"

  # Check prompt file exists
  if [[ ! -f "$t_prompt" ]]; then
    echo -e "${RED}  MISSING PROMPT: ${t_prompt}${NC}"
    echo "MISSING" > "$result_file"
    return
  fi

  # --- Attempt Loop (initial + retries) ---
  for attempt in $(seq 0 "$MAX_RETRIES"); do
    if [[ $attempt -gt 0 ]]; then
      echo -e "${YELLOW}  ${t_id}: Retry ${attempt}/${MAX_RETRIES} after ${RETRY_DELAY}s...${NC}"
      sleep "$RETRY_DELAY"
    fi

    local attempt_log="${RUN_LOG_DIR}/${t_id}-attempt${attempt}.log"

    # Build the prompt
    local prompt
    prompt=$(cat "$t_prompt")

    # If this is a retry, prepend failure context from previous attempt
    if [[ $attempt -gt 0 && -f "${RUN_LOG_DIR}/${t_id}-verify-attempt$((attempt-1)).log" ]]; then
      local failure_output
      failure_output=$(tail -50 "${RUN_LOG_DIR}/${t_id}-verify-attempt$((attempt-1)).log")
      prompt="[TASK] [RETRY ${attempt}/${MAX_RETRIES}]

${PREAMBLE}

The previous attempt failed verification. Here is the test output from the last run:

\`\`\`
${failure_output}
\`\`\`

Fix the failures and ensure all tests pass. Original task:

${prompt}"
    else
      prompt="[TASK]

${PREAMBLE}

${prompt}"
    fi

    # --- Invoke Claude Code ---
    echo -e "  ${t_id}: Invoking Claude Code (attempt $((attempt+1)))..."
    set +e
    timeout "$TASK_TIMEOUT" $CLAUDE_CMD -p "$prompt" --output-format text > "$attempt_log" 2>&1
    local claude_exit=$?
    set -e

    if [[ $claude_exit -ne 0 ]]; then
      echo -e "${RED}  ${t_id}: Claude Code exited with code ${claude_exit}${NC}"
      if [[ $claude_exit -eq 124 ]]; then
        echo -e "${RED}  ${t_id}: TIMEOUT after ${TASK_TIMEOUT}s${NC}"
      fi
      continue
    fi

    # Check for TASK_BLOCKED signal
    if grep -q '\[TASK_BLOCKED\]' "$attempt_log"; then
      local block_reason
      block_reason=$(grep '\[TASK_BLOCKED\]' "$attempt_log" | head -1 | sed 's/.*\[TASK_BLOCKED\] reason: //')
      echo -e "${RED}  ${t_id}: BLOCKED: ${block_reason}${NC}"
      echo "BLOCKED ${block_reason}" > "$result_file"
      return
    fi

    # --- Run Verification Command ---
    echo -e "  ${t_id}: Running verification..."
    local verify_log="${RUN_LOG_DIR}/${t_id}-verify-attempt${attempt}.log"
    set +e
    timeout "$VERIFY_TIMEOUT" bash -c "$t_verify" > "$verify_log" 2>&1
    local verify_exit=$?
    set -e

    if [[ $verify_exit -eq 124 ]]; then
      echo -e "${RED}  ${t_id}: ✗ Verification TIMED OUT after ${VERIFY_TIMEOUT}s${NC}"
    elif [[ $verify_exit -eq 0 ]]; then
      echo -e "${GREEN}  ${t_id}: ✓ PASSED${NC}"
      task_passed=true
      break
    else
      echo -e "${RED}  ${t_id}: ✗ Verification failed (exit ${verify_exit})${NC}"
    fi
  done

  if [[ "$task_passed" == true ]]; then
    echo "PASSED" > "$result_file"
  else
    echo "FAILED" > "$result_file"
  fi
}

# --- Execute Tasks ---
PASSED=0
FAILED=0
BLOCKED=0
SKIPPED=0
SKIP_MODE=false
ABORT_BUILD=false

if [[ -n "$SKIP_UNTIL" ]]; then
  SKIP_MODE=true
fi

# Create temp dir for task results (used by both sequential and parallel modes)
RESULT_DIR=$(mktemp -d)
trap "rm -rf '$RESULT_DIR'; cleanup_lock" EXIT

# --- Sequential Execution (default, --parallel=1) ---
if [[ "$PARALLEL" -le 1 ]]; then

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

    # --only mode: skip tasks that don't match the requested ID
    if [[ -n "$ONLY_TASK" && "$TASK_ID" != "$ONLY_TASK" ]]; then
      echo -e "${YELLOW}  SKIP ${TASK_ID}: not selected by --only${NC}"
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

    run_task "$i"

    # --- Collect Result ---
    RESULT_FILE="${RESULT_DIR}/${TASK_ID}"
    TASK_RESULT=$(cat "$RESULT_FILE" 2>/dev/null || echo "FAILED")

    if [[ "$TASK_RESULT" == "PASSED" ]]; then
      echo "PASSED ${TASK_ID} ${TASK_DESC}" >> "$SUMMARY_FILE"
      echo "${TASK_ID} PASSED" >> "$PROGRESS_FILE"
      PASSED=$((PASSED + 1))

      # Git checkpoint
      if [[ "$GIT_CHECKPOINT" == true ]]; then
        git add -A &>/dev/null && \
        git commit -m "checkpoint: ${TASK_ID} — ${TASK_DESC}" --no-verify -q &>/dev/null || true
      fi

    elif [[ "$TASK_RESULT" == BLOCKED* ]]; then
      BLOCK_REASON="${TASK_RESULT#BLOCKED }"
      echo "BLOCKED ${TASK_ID} ${TASK_DESC} — ${BLOCK_REASON}" >> "$SUMMARY_FILE"
      echo "${TASK_ID} BLOCKED" >> "$PROGRESS_FILE"
      BLOCKED=$((BLOCKED + 1))

    elif [[ "$TASK_RESULT" == "MISSING" ]]; then
      echo "MISSING ${TASK_ID} ${TASK_DESC} — prompt file not found" >> "$SUMMARY_FILE"
      FAILED=$((FAILED + 1))

    else
      echo "FAILED ${TASK_ID} ${TASK_DESC} — failed after $((MAX_RETRIES+1)) attempts" >> "$SUMMARY_FILE"
      echo "${TASK_ID} FAILED" >> "$PROGRESS_FILE"
      FAILED=$((FAILED + 1))

      # Git rollback
      if [[ "$GIT_CHECKPOINT" == true ]]; then
        echo -e "${YELLOW}  Rolling back to last checkpoint...${NC}"
        git checkout -- . &>/dev/null 2>&1 || true
        git clean -fd &>/dev/null 2>&1 || true
        echo -e "${YELLOW}  Rolled back. Next task starts from last passing state.${NC}"
      fi

      # Ask whether to continue or abort
      echo ""
      echo -e "${RED}Task ${TASK_ID} failed after all retries.${NC}"
      echo -e "  Logs: ${RUN_LOG_DIR}/${TASK_ID}-*"
      if [[ "$NON_INTERACTIVE" == true ]]; then
        echo -e "${YELLOW}  Non-interactive mode: auto-continuing to next task.${NC}"
      else
        read -rp "  Continue to next task? [Y/n] " CONTINUE
        if [[ "$CONTINUE" =~ ^[Nn] ]]; then
          echo -e "${YELLOW}Aborting. Resume later with: $0 $MANIFEST --resume${NC}"
          ABORT_BUILD=true
          break
        fi
      fi
    fi
  done

# --- Parallel Execution (--parallel=N where N > 1) ---
else

  # In parallel mode, tasks within each section run concurrently (up to N).
  # Sections still run sequentially — a section doesn't start until the
  # previous one completes. Git checkpoints happen per section, not per task.
  #
  # This provides safe parallelism: tasks grouped in the same section are
  # expected to be independent (no file conflicts), while section boundaries
  # mark dependency barriers.

  if [[ "$GIT_CHECKPOINT" == true ]]; then
    echo -e "${YELLOW}  Parallel mode: git checkpoints are per-section (not per-task).${NC}"
  fi

  for section_idx in $(seq 0 $((SECTION_COUNT - 1))); do
    # Collect task indices for this section
    SECTION_TASK_INDICES=()
    for i in $(seq 0 $((TASK_COUNT - 1))); do
      if [[ "${TASK_SECTION[$i]}" -eq "$section_idx" ]]; then
        SECTION_TASK_INDICES+=("$i")
      fi
    done

    [[ ${#SECTION_TASK_INDICES[@]} -eq 0 ]] && continue

    SECTION_LABEL="${SECTION_NAMES[$section_idx]:-## Section $section_idx}"
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  ${SECTION_LABEL} (${#SECTION_TASK_INDICES[@]} task(s), parallel=${PARALLEL})${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Filter: apply resume and --only logic
    RUNNABLE_INDICES=()
    for i in "${SECTION_TASK_INDICES[@]}"; do
      TASK_ID="${TASK_IDS[$i]}"
      TASK_DESC="${TASK_DESCS[$i]}"

      if [[ "$SKIP_MODE" == true ]]; then
        if [[ "$TASK_ID" == "$SKIP_UNTIL" ]]; then
          SKIP_MODE=false
        fi
        echo -e "${YELLOW}  SKIP ${TASK_ID}: ${TASK_DESC}${NC}"
        SKIPPED=$((SKIPPED + 1))
        continue
      fi

      if [[ -n "$ONLY_TASK" && "$TASK_ID" != "$ONLY_TASK" ]]; then
        echo -e "${YELLOW}  SKIP ${TASK_ID}: not selected by --only${NC}"
        SKIPPED=$((SKIPPED + 1))
        continue
      fi

      if [[ "$DRY_RUN" == true ]]; then
        echo -e "  ${TASK_ID}: ${TASK_DESC}"
        echo -e "    Prompt: ${TASK_PROMPTS[$i]}"
        echo -e "    Verify: ${TASK_VERIFY[$i]}"
        continue
      fi

      RUNNABLE_INDICES+=("$i")
    done

    [[ "$DRY_RUN" == true ]] && continue
    [[ ${#RUNNABLE_INDICES[@]} -eq 0 ]] && continue

    # Launch tasks in parallel batches of $PARALLEL
    BATCH_START=0
    SECTION_HAD_FAILURE=false

    while [[ $BATCH_START -lt ${#RUNNABLE_INDICES[@]} ]]; do
      PIDS=()
      BATCH_IDS=()

      for offset in $(seq 0 $((PARALLEL - 1))); do
        local_idx=$((BATCH_START + offset))
        [[ $local_idx -ge ${#RUNNABLE_INDICES[@]} ]] && break

        task_i="${RUNNABLE_INDICES[$local_idx]}"
        BATCH_IDS+=("${TASK_IDS[$task_i]}")

        run_task "$task_i" &
        PIDS+=($!)
      done

      # Wait for all tasks in this batch
      for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
      done

      BATCH_START=$((BATCH_START + PARALLEL))
    done

    # Collect results for all tasks in this section
    SECTION_PASSED=0
    SECTION_FAILED=0

    for i in "${RUNNABLE_INDICES[@]}"; do
      TASK_ID="${TASK_IDS[$i]}"
      TASK_DESC="${TASK_DESCS[$i]}"
      RESULT_FILE="${RESULT_DIR}/${TASK_ID}"
      TASK_RESULT=$(cat "$RESULT_FILE" 2>/dev/null || echo "FAILED")

      if [[ "$TASK_RESULT" == "PASSED" ]]; then
        echo "PASSED ${TASK_ID} ${TASK_DESC}" >> "$SUMMARY_FILE"
        echo "${TASK_ID} PASSED" >> "$PROGRESS_FILE"
        PASSED=$((PASSED + 1))
        SECTION_PASSED=$((SECTION_PASSED + 1))

      elif [[ "$TASK_RESULT" == BLOCKED* ]]; then
        BLOCK_REASON="${TASK_RESULT#BLOCKED }"
        echo "BLOCKED ${TASK_ID} ${TASK_DESC} — ${BLOCK_REASON}" >> "$SUMMARY_FILE"
        echo "${TASK_ID} BLOCKED" >> "$PROGRESS_FILE"
        BLOCKED=$((BLOCKED + 1))
        SECTION_HAD_FAILURE=true

      elif [[ "$TASK_RESULT" == "MISSING" ]]; then
        echo "MISSING ${TASK_ID} ${TASK_DESC} — prompt file not found" >> "$SUMMARY_FILE"
        FAILED=$((FAILED + 1))
        SECTION_HAD_FAILURE=true

      else
        echo "FAILED ${TASK_ID} ${TASK_DESC} — failed after $((MAX_RETRIES+1)) attempts" >> "$SUMMARY_FILE"
        echo "${TASK_ID} FAILED" >> "$PROGRESS_FILE"
        FAILED=$((FAILED + 1))
        SECTION_HAD_FAILURE=true
      fi
    done

    echo ""
    echo -e "  Section result: ${GREEN}${SECTION_PASSED} passed${NC}, ${RED}$((${#RUNNABLE_INDICES[@]} - SECTION_PASSED)) failed/blocked${NC}"

    # Git checkpoint per section
    if [[ "$GIT_CHECKPOINT" == true ]]; then
      if [[ "$SECTION_HAD_FAILURE" == true ]]; then
        echo -e "${YELLOW}  Rolling back section to last checkpoint...${NC}"
        git checkout -- . &>/dev/null 2>&1 || true
        git clean -fd &>/dev/null 2>&1 || true
        echo -e "${YELLOW}  Section rolled back. Next section starts from last passing state.${NC}"
      elif [[ $SECTION_PASSED -gt 0 ]]; then
        git add -A &>/dev/null && \
        git commit -m "checkpoint: ${SECTION_LABEL} (${SECTION_PASSED} tasks)" --no-verify -q &>/dev/null || true
        echo -e "${GREEN}  Section checkpoint committed.${NC}"
      fi
    fi

    # If section had failures, ask whether to continue
    if [[ "$SECTION_HAD_FAILURE" == true ]]; then
      if [[ "$NON_INTERACTIVE" == true ]]; then
        echo -e "${YELLOW}  Non-interactive mode: auto-continuing to next section.${NC}"
      else
        echo ""
        read -rp "  Section had failures. Continue to next section? [Y/n] " CONTINUE
        if [[ "$CONTINUE" =~ ^[Nn] ]]; then
          echo -e "${YELLOW}Aborting. Resume later with: $0 $MANIFEST --resume${NC}"
          ABORT_BUILD=true
          break
        fi
      fi
    fi
  done
fi

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

# --- Automatic Log Rotation ---
if [[ "$DRY_RUN" != true ]]; then
  OLD_LOG_DIRS=$(ls -dt "${LOG_DIR}/${MANIFEST_NAME}"-*/ 2>/dev/null | tail -n +$((LOG_RETENTION + 1)))
  if [[ -n "$OLD_LOG_DIRS" ]]; then
    PRUNED_COUNT=0
    while IFS= read -r old_dir; do
      rm -rf "$old_dir"
      PRUNED_COUNT=$((PRUNED_COUNT + 1))
    done <<< "$OLD_LOG_DIRS"
    echo -e "${YELLOW}  Pruned ${PRUNED_COUNT} old log dir(s) for ${MANIFEST_NAME} (keeping newest ${LOG_RETENTION}).${NC}"
  fi
fi

# --- Write Completion Marker ---
# If ALL tasks passed (0 failures, 0 blocked), write a marker file so that
# downstream domains can verify this domain completed successfully.
if [[ $FAILED -eq 0 && $BLOCKED -eq 0 && "$DRY_RUN" != true && -z "$ONLY_TASK" ]]; then
  mkdir -p ".build-state"
  MARKER_FILE=".build-state/${MANIFEST_NAME}.completed"
  cat > "$MARKER_FILE" <<EOF
manifest=${MANIFEST_NAME}
completed_at=$(date -Iseconds)
tasks_passed=${PASSED}
tasks_total=${TASK_COUNT}
tasks_skipped=${SKIPPED}
EOF
  echo ""
  echo -e "${GREEN}  Completion marker written: ${MARKER_FILE}${NC}"
elif [[ "$DRY_RUN" != true ]]; then
  echo ""
  echo -e "${YELLOW}  Completion marker NOT written (${FAILED} failed, ${BLOCKED} blocked).${NC}"
fi

# --- Test Coverage Audit (automatic) ---
AUDIT_SCRIPT="./scripts/audit-test-coverage.sh"
AUDIT_EXIT=0

if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" && -f "$AUDIT_SCRIPT" && "$DRY_RUN" != true && -z "$ONLY_TASK" ]]; then
  echo ""
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}  Test Coverage Audit${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "  Config: ${CONFIG_FILE}"

  AUDIT_LOG="${RUN_LOG_DIR}/test-audit.log"
  set +e
  "$AUDIT_SCRIPT" "$CONFIG_FILE" --verbose > "$AUDIT_LOG" 2>&1
  AUDIT_EXIT=$?
  set -e

  # Display audit output
  cat "$AUDIT_LOG"

  # Append to summary
  echo "" >> "$SUMMARY_FILE"
  echo "--- Test Coverage Audit ---" >> "$SUMMARY_FILE"
  cat "$AUDIT_LOG" >> "$SUMMARY_FILE"

  if [[ $AUDIT_EXIT -ne 0 ]]; then
    echo -e "${RED}  Test coverage gaps detected. See: ${AUDIT_LOG}${NC}"
    echo "TEST_AUDIT: GAPS_FOUND" >> "$SUMMARY_FILE"
  else
    echo "TEST_AUDIT: PASS" >> "$SUMMARY_FILE"
  fi
elif [[ -z "$CONFIG_FILE" ]]; then
  echo ""
  echo -e "${YELLOW}  Skipping test audit: no config file found.${NC}"
  echo -e "${YELLOW}  To enable, pass --config=configs/your-domain.json or name your config to match the manifest.${NC}"
elif [[ ! -f "$AUDIT_SCRIPT" ]]; then
  echo ""
  echo -e "${YELLOW}  Skipping test audit: ${AUDIT_SCRIPT} not found.${NC}"
fi

# --- Build Completion Notification ---
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))

# Format duration as human-readable string
if [[ $ELAPSED -ge 3600 ]]; then
  DURATION_FMT="$((ELAPSED / 3600))h $((ELAPSED % 3600 / 60))m"
else
  DURATION_FMT="$((ELAPSED / 60))m $((ELAPSED % 60))s"
fi

if [[ $FAILED -gt 0 || $BLOCKED -gt 0 || $AUDIT_EXIT -ne 0 ]]; then
  NOTIFY_STATUS="FAILED"
else
  NOTIFY_STATUS="PASSED"
fi

NOTIFY_SUMMARY="${MANIFEST_NAME}: ${PASSED} passed, ${FAILED} failed (${DURATION_FMT})"
send_notification "$NOTIFY_STATUS" "$NOTIFY_SUMMARY"

# Exit with failure if any tasks failed or test audit found gaps
if [[ $FAILED -gt 0 || $BLOCKED -gt 0 || $AUDIT_EXIT -ne 0 ]]; then
  exit 1
fi
