#!/usr/bin/env bash
# ============================================================================
# Meritum — Fee Navigator Pipeline Loop
#
# Self-driving audit→fix→verify loop for enrichment extraction patterns.
# Each iteration: enrich → audit → prompt Claude → re-enrich → validate → commit.
#
# Usage:
#   ./scripts/pipeline-loop.sh [options]
#
# Options:
#   --max-iterations N   Max loop iterations (default: 5)
#   --dry-run            Show audit findings without invoking Claude
#   --no-commit          Skip git checkpointing
#   --verbose            Show full Claude output
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TSX="${PROJECT_ROOT}/apps/api/node_modules/.bin/tsx"
ENRICH_SCRIPT="${PROJECT_ROOT}/scripts/enrich-hsc-data.ts"
AUDIT_SCRIPT="${PROJECT_ROOT}/scripts/audit-fee-navigator.ts"
VALIDATE_SCRIPT="${PROJECT_ROOT}/scripts/validate-fee-navigator-data.ts"
ENRICH_SOURCE="${PROJECT_ROOT}/scripts/enrich-hsc-data.ts"
HSC_DATA="${PROJECT_ROOT}/scripts/data/fee-navigator/hsc-codes.json"
AUDIT_FINDINGS="${PROJECT_ROOT}/scripts/data/fee-navigator/audit-findings.json"
LOG_DIR="${PROJECT_ROOT}/logs/pipeline-loop"

MAX_ITERATIONS=5
DRY_RUN=false
NO_COMMIT=false
VERBOSE=false

# ============================================================================
# Parse Arguments
# ============================================================================

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-iterations)
      MAX_ITERATIONS="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --no-commit)
      NO_COMMIT=true
      shift
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--max-iterations N] [--dry-run] [--no-commit] [--verbose]"
      exit 1
      ;;
  esac
done

# ============================================================================
# Helpers
# ============================================================================

timestamp() {
  date '+%Y-%m-%d %H:%M:%S'
}

log() {
  echo "[$(timestamp)] $*"
}

log_section() {
  echo ""
  echo "============================================"
  echo "  $*"
  echo "============================================"
}

ensure_log_dir() {
  mkdir -p "$LOG_DIR"
}

# ============================================================================
# Preflight Checks
# ============================================================================

preflight() {
  log_section "Preflight Checks"

  if [[ ! -x "$TSX" ]]; then
    log "ERROR: tsx not found at $TSX"
    exit 1
  fi
  log "tsx: OK"

  if [[ ! -f "$ENRICH_SCRIPT" ]]; then
    log "ERROR: enrich-hsc-data.ts not found"
    exit 1
  fi
  log "enrich-hsc-data.ts: OK"

  if [[ ! -f "$AUDIT_SCRIPT" ]]; then
    log "ERROR: audit-fee-navigator.ts not found"
    exit 1
  fi
  log "audit-fee-navigator.ts: OK"

  if [[ ! -f "$VALIDATE_SCRIPT" ]]; then
    log "ERROR: validate-fee-navigator-data.ts not found"
    exit 1
  fi
  log "validate-fee-navigator-data.ts: OK"

  if [[ ! -f "$HSC_DATA" ]]; then
    log "ERROR: hsc-codes.json not found — run the scraper first"
    exit 1
  fi
  log "hsc-codes.json: OK ($(wc -l < "$HSC_DATA") lines)"

  if ! command -v claude &>/dev/null; then
    log "ERROR: claude CLI not found"
    exit 1
  fi
  log "claude CLI: OK"

  if ! command -v git &>/dev/null; then
    log "ERROR: git not found"
    exit 1
  fi
  log "git: OK"

  ensure_log_dir
}

# ============================================================================
# Step 1: Run Enrichment
# ============================================================================

run_enrich() {
  local iter=$1
  local log_file="${LOG_DIR}/iteration-${iter}-enrich.log"

  log "Running enrichment..."
  if "$TSX" "$ENRICH_SCRIPT" > "$log_file" 2>&1; then
    log "Enrichment: OK"
    return 0
  else
    log "WARNING: Enrichment exited with non-zero (may be network issue)"
    log "Log: $log_file"
    # Non-fatal — enrichment may fail on network but notes-based extraction still works
    return 0
  fi
}

# ============================================================================
# Step 2: Run Audit
# ============================================================================

run_audit() {
  local iter=$1
  local previous_flag=""
  local log_file="${LOG_DIR}/iteration-${iter}-audit.log"

  if [[ $iter -gt 1 ]] && [[ -f "$AUDIT_FINDINGS" ]]; then
    previous_flag="--previous $AUDIT_FINDINGS"
  fi

  log "Running audit (iteration $iter)..."
  # shellcheck disable=SC2086
  if "$TSX" "$AUDIT_SCRIPT" --iteration "$iter" $previous_flag > "$log_file" 2>&1; then
    # Copy output to findings path (audit script also writes it, but let's be safe)
    cp "$log_file" "${LOG_DIR}/iteration-${iter}-audit-output.json"
    log "Audit: OK"
    return 0
  else
    log "ERROR: Audit script failed"
    log "Log: $log_file"
    return 1
  fi
}

# ============================================================================
# Step 3: Check If Actionable
# ============================================================================

is_actionable() {
  if [[ ! -f "$AUDIT_FINDINGS" ]]; then
    log "No audit findings file — nothing to do"
    return 1
  fi

  local actionable
  actionable=$(node -e "const d=JSON.parse(require('fs').readFileSync('$AUDIT_FINDINGS','utf-8')); console.log(d.actionable ? 'true' : 'false')")

  if [[ "$actionable" == "true" ]]; then
    return 0
  else
    return 1
  fi
}

get_total_gap() {
  if [[ ! -f "$AUDIT_FINDINGS" ]]; then
    echo "0"
    return
  fi
  node -e "const d=JSON.parse(require('fs').readFileSync('$AUDIT_FINDINGS','utf-8')); console.log(d.totalGap)"
}

# ============================================================================
# Step 4: Build and Run Claude Prompt
# ============================================================================

build_prompt() {
  local findings
  findings=$(cat "$AUDIT_FINDINGS")

  local source
  source=$(cat "$ENRICH_SOURCE")

  cat <<PROMPT_EOF
You are fixing enrichment extraction patterns for the Meritum Fee Navigator pipeline.

## Current Audit Findings

The following JSON describes gaps between keyword matches in notes text and extracted structured fields. Each finding shows sample codes and the notes text patterns that are NOT being matched by current extraction regexes.

\`\`\`json
${findings}
\`\`\`

## Current Source: enrich-hsc-data.ts

\`\`\`typescript
${source}
\`\`\`

## Instructions

1. Analyze each finding carefully. Look at the samplePatterns — these are actual notes text snippets that the current regex patterns are NOT matching.
2. For each dimension with a "high" or "medium" severity finding, improve or add regex patterns in the corresponding extraction function to match the unmatched patterns.
3. Be conservative: only add patterns that clearly indicate the dimension in question. Do not over-match.
4. Common issues to fix:
   - "May be claimed in addition to HSC X" is POSITIVE (allowed together), NOT a bundling exclusion. Only "May NOT be claimed with" or "not payable in addition to" are exclusions.
   - "claimed by" without "only" doesn't necessarily mean a specialty restriction.
   - Notes starting with "Refer to notes following HSC" often contain age/frequency rules in referenced code's notes — not directly extractable here.
5. Only modify \`scripts/enrich-hsc-data.ts\`. Do not modify any other files.
6. After making changes, output \`[LOOP_COMPLETE]\` on a new line.
7. If you cannot make further improvements, output \`[LOOP_BLOCKED] reason: <one-line description>\` instead.
PROMPT_EOF
}

run_claude() {
  local iter=$1
  local log_file="${LOG_DIR}/iteration-${iter}-claude.log"
  local prompt

  prompt=$(build_prompt)

  if [[ "$DRY_RUN" == "true" ]]; then
    log "DRY RUN: Would send prompt to Claude (${#prompt} chars)"
    log "Findings summary:"
    node -e "
      const d = JSON.parse(require('fs').readFileSync('$AUDIT_FINDINGS', 'utf-8'));
      for (const f of d.findings) {
        console.log('  ' + f.id + ' [' + f.severity + '] ' + f.dimension + ': ' + f.unmatchedCount + ' unmatched');
      }
      console.log('  Total gap: ' + d.totalGap);
    "
    return 1  # Signal dry-run stop
  fi

  log "Invoking Claude (prompt: ${#prompt} chars)..."

  if claude -p "$prompt" --output-format text > "$log_file" 2>&1; then
    log "Claude completed"
  else
    log "WARNING: Claude exited with non-zero status"
  fi

  if [[ "$VERBOSE" == "true" ]]; then
    log "--- Claude output ---"
    cat "$log_file"
    log "--- End Claude output ---"
  fi

  # Check for blocked signal
  if grep -q '\[LOOP_BLOCKED\]' "$log_file"; then
    local reason
    reason=$(grep '\[LOOP_BLOCKED\]' "$log_file" | head -1 | sed 's/.*\[LOOP_BLOCKED\]\s*//')
    log "Claude signaled BLOCKED: $reason"
    return 2
  fi

  # Check for completion signal
  if grep -q '\[LOOP_COMPLETE\]' "$log_file"; then
    log "Claude signaled COMPLETE"
    return 0
  fi

  log "WARNING: Claude output did not contain [LOOP_COMPLETE] or [LOOP_BLOCKED]"
  log "Proceeding anyway — will validate output"
  return 0
}

# ============================================================================
# Step 5: Re-enrich After Claude Edits
# ============================================================================

run_reenrich() {
  local iter=$1
  local log_file="${LOG_DIR}/iteration-${iter}-reenrich.log"

  log "Re-running enrichment with updated patterns..."
  if "$TSX" "$ENRICH_SCRIPT" > "$log_file" 2>&1; then
    log "Re-enrichment: OK"
    return 0
  else
    log "WARNING: Re-enrichment exited with non-zero (may be network issue)"
    return 0
  fi
}

# ============================================================================
# Step 6: Validate
# ============================================================================

run_validate() {
  local iter=$1
  local log_file="${LOG_DIR}/iteration-${iter}-validate.log"

  log "Running validation..."
  if "$TSX" "$VALIDATE_SCRIPT" --json > "$log_file" 2>&1; then
    local result
    result=$(node -e "const d=JSON.parse(require('fs').readFileSync('$log_file','utf-8')); console.log(d.result)")
    if [[ "$result" == "PASS" ]]; then
      log "Validation: PASS"
      return 0
    else
      log "Validation: FAIL (result=$result)"
      return 1
    fi
  else
    log "Validation script error"
    return 1
  fi
}

# ============================================================================
# Step 7: Rollback
# ============================================================================

rollback() {
  log "Rolling back changes..."
  cd "$PROJECT_ROOT"
  git checkout -- scripts/enrich-hsc-data.ts scripts/data/fee-navigator/hsc-codes.json 2>/dev/null || true
  log "Rollback complete"
}

# ============================================================================
# Step 8: Git Checkpoint
# ============================================================================

git_checkpoint() {
  local iter=$1

  if [[ "$NO_COMMIT" == "true" ]]; then
    log "Skipping git checkpoint (--no-commit)"
    return 0
  fi

  cd "$PROJECT_ROOT"
  git add scripts/enrich-hsc-data.ts scripts/data/fee-navigator/hsc-codes.json scripts/data/fee-navigator/audit-findings.json 2>/dev/null || true
  if git diff --cached --quiet; then
    log "No changes to commit"
    return 0
  fi

  local gap
  gap=$(get_total_gap)
  git commit --no-verify -m "pipeline-loop: iteration $iter (gap=$gap)" > /dev/null 2>&1
  log "Git checkpoint: committed (iteration $iter, gap=$gap)"
}

# ============================================================================
# Main Loop
# ============================================================================

main() {
  preflight

  log_section "Pipeline Loop Starting"
  log "Max iterations: $MAX_ITERATIONS"
  log "Dry run: $DRY_RUN"
  log "No commit: $NO_COMMIT"
  log "Verbose: $VERBOSE"

  local prev_gap=""
  local stall_count=0

  cd "$PROJECT_ROOT"

  for ((iter = 1; iter <= MAX_ITERATIONS; iter++)); do
    log_section "Iteration $iter / $MAX_ITERATIONS"

    # Step 1: Enrich (applies current patterns)
    run_enrich "$iter"

    # Step 2: Audit
    if ! run_audit "$iter"; then
      log "Audit failed — stopping"
      break
    fi

    # Step 3: Check if actionable
    if ! is_actionable; then
      log "No actionable findings — all dimensions meet targets"
      log_section "CONVERGED after $iter iteration(s)"
      break
    fi

    local current_gap
    current_gap=$(get_total_gap)
    log "Total gap: $current_gap (previous: ${prev_gap:-none})"

    # Stall detection
    if [[ -n "$prev_gap" ]] && [[ "$current_gap" == "$prev_gap" ]]; then
      stall_count=$((stall_count + 1))
      log "Stall detected ($stall_count consecutive)"
      if [[ $stall_count -ge 2 ]]; then
        log "Gap stalled for 2 consecutive iterations — stopping"
        log_section "STALLED at gap=$current_gap after $iter iteration(s)"
        break
      fi
    else
      stall_count=0
    fi
    prev_gap="$current_gap"

    # Step 4: Run Claude
    local claude_result=0
    run_claude "$iter" || claude_result=$?

    if [[ $claude_result -eq 1 ]]; then
      # Dry run
      log_section "DRY RUN — stopping after audit"
      break
    elif [[ $claude_result -eq 2 ]]; then
      # Claude blocked
      log_section "BLOCKED after $iter iteration(s)"
      break
    fi

    # Step 5: Re-enrich with Claude's fixes
    run_reenrich "$iter"

    # Step 6: Validate
    if ! run_validate "$iter"; then
      log "Validation failed after Claude's edits — rolling back"
      rollback
      log_section "VALIDATION FAILURE — rolled back, stopping after $iter iteration(s)"
      break
    fi

    # Step 9: Git checkpoint
    git_checkpoint "$iter"

    # Check if this was the last iteration
    if [[ $iter -eq $MAX_ITERATIONS ]]; then
      log_section "MAX ITERATIONS ($MAX_ITERATIONS) reached"
    fi
  done

  # Final summary
  log_section "Pipeline Loop Summary"
  local final_gap
  final_gap=$(get_total_gap)
  log "Final gap: $final_gap"
  log "Logs: $LOG_DIR/"
}

main "$@"
