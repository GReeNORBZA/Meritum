#!/usr/bin/env bash
# ============================================================================
# audit-test-coverage.sh — Post-run test gap detection
#
# Scans a domain config JSON and reports which tasks have test gaps:
# missing test files, insufficient test counts, or tests that were
# specified in the config but not found in the actual source.
#
# Language-aware: reads the config's "language" field (default: typescript)
# to use the correct test-counting patterns and coverage tool.
#
# Usage:
#   ./scripts/audit-test-coverage.sh configs/domain-05-provider-manifests.json
#   ./scripts/audit-test-coverage.sh configs/domain-01-iam.json --verbose
#
# Output:
#   Summary report with pass/fail per task, plus total gap count.
#   Exit code 0 = no gaps, 1 = gaps found.
#
# Run this AFTER a task-runner build to catch any tests that slipped through.
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CONFIG_FILE="${1:-}"
VERBOSE=false

for arg in "$@"; do
  [[ "$arg" == "--verbose" ]] && VERBOSE=true
done

if [[ -z "$CONFIG_FILE" || ! -f "$CONFIG_FILE" ]]; then
  echo -e "${RED}Usage: $0 <config-json> [--verbose]${NC}"
  exit 1
fi

# Parse config with node (available in any JS project)
AUDIT_SCRIPT=$(cat <<'JSEOF'
const fs = require('fs');
const path = require('path');

const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf-8'));
const verbose = process.argv.includes('--verbose');
const language = config.language || 'typescript';

// Language-specific test counting patterns (must match verify-tests.sh)
const TEST_PATTERNS = {
  typescript:  /^\s*(it|test)(\.(only|skip|todo))?\s*\(/gm,
  python:      /^\s*(async\s+)?def\s+test_/gm,
  go:          /^\s*func\s+Test\w+\s*\(/gm,
  rust:        /#\[test\]/gm,
  java:        /@Test/gm,
};

const testPattern = TEST_PATTERNS[language] || TEST_PATTERNS.typescript;

const results = [];
let totalExpected = 0;
let totalFound = 0;
let totalMissingFiles = 0;
let tasksWithTests = 0;
let tasksFullyCovered = 0;

for (const section of config.sections) {
  for (const task of section.tasks) {
    if (!task.tests || task.tests.length === 0) continue;

    tasksWithTests++;
    const expected = task.tests.length;
    totalExpected += expected;

    // Determine test file path
    let testFile = task.testFile;
    if (!testFile) {
      // Try vitest pattern
      let match = task.verify.match(/vitest\s+run\s+(.+?)(?:\s|$)/);
      if (match) testFile = match[1].trim();
      // Try pytest pattern
      if (!testFile) {
        match = task.verify.match(/pytest\s+(.+?)(?:\s|$)/);
        if (match) testFile = match[1].trim();
      }
      // Try go test pattern
      if (!testFile) {
        match = task.verify.match(/go\s+test\s+.*?(\.\/.+?)(?:\s|$)/);
        if (match) testFile = match[1].trim();
      }
    }

    if (!testFile) {
      results.push({
        id: task.id,
        status: 'NO_FILE_PATH',
        expected,
        found: 0,
        file: '(unknown)',
        missing: task.tests,
      });
      continue;
    }

    if (!fs.existsSync(testFile)) {
      totalMissingFiles++;
      results.push({
        id: task.id,
        status: 'FILE_MISSING',
        expected,
        found: 0,
        file: testFile,
        missing: task.tests,
      });
      continue;
    }

    const content = fs.readFileSync(testFile, 'utf-8');

    // Count actual test cases using language-specific pattern
    const testMatches = content.match(testPattern) || [];
    const found = testMatches.length;
    totalFound += found;

    // Check which specific tests are present (fuzzy match on description)
    const missing = [];
    for (const testDesc of task.tests) {
      // Normalize: lowercase, collapse whitespace
      const needle = testDesc.toLowerCase().replace(/\s+/g, ' ').trim();
      const contentLower = content.toLowerCase();
      // Check if the test description appears in the file (in an it/test call)
      if (!contentLower.includes(needle)) {
        missing.push(testDesc);
      }
    }

    const status = found >= expected && missing.length === 0 ? 'PASS' :
                   found >= expected ? 'PARTIAL' : 'INSUFFICIENT';

    if (status === 'PASS') tasksFullyCovered++;

    results.push({
      id: task.id,
      status,
      expected,
      found,
      file: testFile,
      missing,
    });
  }
}

// Output report
console.log('');
console.log('═══════════════════════════════════════════════════════════════');
console.log(`  Test Coverage Audit: ${config.domainName} [${language}]`);
console.log('═══════════════════════════════════════════════════════════════');
console.log('');

let hasGaps = false;

for (const r of results) {
  if (r.status === 'PASS') {
    console.log(`  ✓ ${r.id}: ${r.found}/${r.expected} tests (${r.file})`);
  } else if (r.status === 'FILE_MISSING') {
    hasGaps = true;
    console.log(`  ✗ ${r.id}: FILE MISSING — ${r.file} (expected ${r.expected} tests)`);
  } else if (r.status === 'NO_FILE_PATH') {
    hasGaps = true;
    console.log(`  ? ${r.id}: Cannot determine test file path (expected ${r.expected} tests)`);
  } else {
    hasGaps = true;
    console.log(`  ✗ ${r.id}: ${r.found}/${r.expected} tests (${r.file})`);
    if (verbose && r.missing.length > 0) {
      for (const m of r.missing) {
        console.log(`      MISSING: ${m}`);
      }
    }
  }
}

console.log('');
console.log('───────────────────────────────────────────────────────────────');
console.log(`  Language:                  ${language}`);
console.log(`  Tasks with tests defined:  ${tasksWithTests}`);
console.log(`  Fully covered:             ${tasksFullyCovered}`);
console.log(`  With gaps:                 ${tasksWithTests - tasksFullyCovered}`);
console.log(`  Missing test files:        ${totalMissingFiles}`);
console.log(`  Total tests expected:      ${totalExpected}`);
console.log(`  Total tests found:         ${totalFound}`);
console.log(`  Test gap:                  ${totalExpected - totalFound} missing test(s)`);
console.log('───────────────────────────────────────────────────────────────');

if (hasGaps) {
  console.log('');
  console.log('  RESULT: GAPS FOUND');
  if (!verbose) {
    console.log('  Run with --verbose to see missing test descriptions.');
  }
  console.log('');
  process.exit(1);
} else {
  console.log('');
  console.log('  RESULT: ALL TESTS PRESENT');
  console.log('');
  process.exit(0);
}
JSEOF
)

# Capture the exit code from Phase 1 so we can use it at the end
PHASE1_EXIT=0
node -e "$AUDIT_SCRIPT" -- "$CONFIG_FILE" "$@" || PHASE1_EXIT=$?

# ============================================================================
# Phase 2: Coverage threshold check (ADVISORY — does not affect exit code)
#
# Runs a coverage tool and checks that source files referenced by the
# config's modulePath meet a minimum line-coverage threshold.
#
# Language-aware: uses vitest for TypeScript/JavaScript, pytest-cov for Python,
# go test -cover for Go, cargo tarpaulin for Rust, jacoco for Java.
#
# Gated on:
#   - The relevant coverage tool being available
#   - The config having at least one task with tests defined
# ============================================================================

COVERAGE_THRESHOLD="${COVERAGE_THRESHOLD:-60}"

# Extract modulePath, language, coverageCommand, and check if config has tasks with tests
COVERAGE_META=$(node -e "
const fs = require('fs');
const config = JSON.parse(fs.readFileSync(process.argv[1], 'utf-8'));
const modulePath = config.modulePath || '';
const language = config.language || 'typescript';
// coverageCommand: custom test runner prefix for coverage (e.g., 'pnpm --filter api')
// Falls back to auto-detection based on lock files and package.json workspaces
const coverageCommand = config.coverageCommand || '';
let hasTests = false;
for (const section of (config.sections || [])) {
  for (const task of (section.tasks || [])) {
    if (task.tests && task.tests.length > 0) { hasTests = true; break; }
  }
  if (hasTests) break;
}
console.log(JSON.stringify({ modulePath, hasTests, language, coverageCommand }));
" "$CONFIG_FILE" 2>/dev/null) || COVERAGE_META='{"modulePath":"","hasTests":false,"language":"typescript","coverageCommand":""}'

MODULE_PATH=$(echo "$COVERAGE_META" | node -e "const d=require('fs').readFileSync('/dev/stdin','utf-8');console.log(JSON.parse(d).modulePath)")
HAS_TESTS=$(echo "$COVERAGE_META" | node -e "const d=require('fs').readFileSync('/dev/stdin','utf-8');console.log(JSON.parse(d).hasTests)")
CONFIG_LANGUAGE=$(echo "$COVERAGE_META" | node -e "const d=require('fs').readFileSync('/dev/stdin','utf-8');console.log(JSON.parse(d).language)")
COVERAGE_CMD=$(echo "$COVERAGE_META" | node -e "const d=require('fs').readFileSync('/dev/stdin','utf-8');console.log(JSON.parse(d).coverageCommand)")

if [[ "$HAS_TESTS" != "true" ]]; then
  if $VERBOSE; then
    echo ""
    echo -e "${YELLOW}  Coverage Report: Skipped (no tasks with tests defined)${NC}"
  fi
  exit "$PHASE1_EXIT"
fi

# --- Language-specific coverage ---
run_typescript_coverage() {
  # Determine the test runner prefix command.
  # Priority: config.coverageCommand > auto-detect from lock files
  local runner_prefix="$COVERAGE_CMD"

  if [[ -z "$runner_prefix" ]]; then
    # Auto-detect: check for common JS package managers and monorepo patterns
    if command -v pnpm &>/dev/null; then
      runner_prefix="pnpm"
      # If this is a pnpm workspace (pnpm-workspace.yaml exists), try to find the right filter
      if [[ -f "pnpm-workspace.yaml" ]]; then
        # Try to infer workspace name from modulePath (e.g., "apps/api/src" → "api")
        local workspace_name
        workspace_name=$(echo "$MODULE_PATH" | sed -E 's|^apps/([^/]+).*|\1|; s|^packages/([^/]+).*|\1|')
        if [[ -n "$workspace_name" && "$workspace_name" != "$MODULE_PATH" ]]; then
          runner_prefix="pnpm --filter ${workspace_name}"
        fi
      fi
    elif command -v yarn &>/dev/null; then
      runner_prefix="yarn"
    elif command -v npx &>/dev/null; then
      runner_prefix="npx"
    else
      echo -e "${YELLOW}  Coverage Report: Skipped (no JS package manager found)${NC}"
      return 1
    fi
  fi

  echo -e "${BLUE}  Using runner: ${runner_prefix}${NC}"

  # Check if vitest is available
  VITEST_AVAILABLE=false
  ${runner_prefix} exec -- node -e "require.resolve('vitest')" &>/dev/null 2>&1 && VITEST_AVAILABLE=true
  # Also try without exec (non-monorepo setups)
  if [[ "$VITEST_AVAILABLE" != "true" ]]; then
    node -e "require.resolve('vitest')" &>/dev/null 2>&1 && VITEST_AVAILABLE=true
  fi

  if [[ "$VITEST_AVAILABLE" != "true" ]]; then
    echo -e "${YELLOW}  Coverage Report: Skipped (vitest not installed)${NC}"
    return 1
  fi

  COVERAGE_PROVIDER_AVAILABLE=false
  node -e "require.resolve('@vitest/coverage-v8')" &>/dev/null 2>&1 && COVERAGE_PROVIDER_AVAILABLE=true
  if [[ "$COVERAGE_PROVIDER_AVAILABLE" != "true" ]]; then
    ${runner_prefix} exec -- node -e "require.resolve('@vitest/coverage-v8')" &>/dev/null 2>&1 && COVERAGE_PROVIDER_AVAILABLE=true
  fi
  if [[ "$COVERAGE_PROVIDER_AVAILABLE" != "true" ]]; then
    node -e "require.resolve('@vitest/coverage-istanbul')" &>/dev/null 2>&1 && COVERAGE_PROVIDER_AVAILABLE=true
  fi
  if [[ "$COVERAGE_PROVIDER_AVAILABLE" != "true" ]]; then
    ${runner_prefix} exec -- node -e "require.resolve('@vitest/coverage-istanbul')" &>/dev/null 2>&1 && COVERAGE_PROVIDER_AVAILABLE=true
  fi

  if [[ "$COVERAGE_PROVIDER_AVAILABLE" != "true" ]]; then
    echo -e "${YELLOW}  Coverage Report: Skipped (@vitest/coverage-v8 or @vitest/coverage-istanbul not installed)${NC}"
    return 1
  fi

  COVERAGE_DIR=".coverage-tmp"
  COVERAGE_JSON="${COVERAGE_DIR}/coverage-summary.json"

  echo -e "${BLUE}  Running vitest with coverage (threshold: ${COVERAGE_THRESHOLD}%)...${NC}"

  ${runner_prefix} vitest run \
    --coverage \
    --coverage.reporter=json \
    --coverage.reportsDirectory="$COVERAGE_DIR" \
    2>/dev/null || true

  if [[ ! -f "$COVERAGE_JSON" ]]; then
    echo -e "${YELLOW}  Coverage Report: Could not generate coverage data.${NC}"
    rm -rf "$COVERAGE_DIR"
    return 1
  fi

  # Parse coverage results
  node -e "
const fs = require('fs');
const coverageData = JSON.parse(fs.readFileSync(process.argv[1], 'utf-8'));
const modulePath = process.argv[2];
const threshold = parseInt(process.argv[3], 10);

const results = [];
let belowCount = 0;
let checkedCount = 0;

for (const [filePath, metrics] of Object.entries(coverageData)) {
  if (filePath === 'total') continue;
  if (modulePath && !filePath.includes(modulePath)) continue;
  if (filePath.includes('.test.') || filePath.includes('.spec.') || filePath.includes('__tests__')) continue;

  checkedCount++;
  const lineCoverage = metrics.lines ? metrics.lines.pct : 0;
  const below = lineCoverage < threshold;
  if (below) belowCount++;
  results.push({ file: filePath, coverage: lineCoverage, below });
}

results.sort((a, b) => {
  if (a.below !== b.below) return a.below ? -1 : 1;
  return a.coverage - b.coverage;
});

for (const r of results) {
  const icon = r.below ? '!' : ' ';
  const pct = r.coverage.toFixed(1).padStart(6);
  console.log('  ' + icon + ' ' + pct + '%  ' + r.file);
}

console.log('');
console.log('-------------------------------------------------------------------');
console.log('  Files checked:        ' + checkedCount);
console.log('  Below threshold:      ' + belowCount);
console.log('  Threshold:            ' + threshold + '%');
console.log('-------------------------------------------------------------------');

if (belowCount > 0) {
  console.log('');
  console.log('  WARNING: ' + belowCount + ' file(s) below ' + threshold + '% line coverage.');
  console.log('  (This is advisory only and does not fail the audit.)');
} else if (checkedCount > 0) {
  console.log('');
  console.log('  All ' + checkedCount + ' file(s) meet the ' + threshold + '% coverage threshold.');
} else {
  console.log('');
  console.log('  No source files found under modulePath: ' + modulePath);
}
console.log('');
" "$COVERAGE_JSON" "$MODULE_PATH" "$COVERAGE_THRESHOLD" 2>/dev/null || echo "  Could not parse coverage data."

  rm -rf "$COVERAGE_DIR"
  return 0
}

run_python_coverage() {
  if ! command -v pytest &>/dev/null; then
    echo -e "${YELLOW}  Coverage Report: Skipped (pytest not available)${NC}"
    return 1
  fi

  if ! python -c "import pytest_cov" 2>/dev/null; then
    echo -e "${YELLOW}  Coverage Report: Skipped (pytest-cov not installed)${NC}"
    return 1
  fi

  echo -e "${BLUE}  Running pytest with coverage (threshold: ${COVERAGE_THRESHOLD}%)...${NC}"
  pytest --cov="$MODULE_PATH" --cov-report=term-missing --cov-fail-under=0 2>/dev/null || true
  echo ""
  echo -e "${YELLOW}  (Advisory: check output above for files below ${COVERAGE_THRESHOLD}% line coverage)${NC}"
  return 0
}

run_go_coverage() {
  if ! command -v go &>/dev/null; then
    echo -e "${YELLOW}  Coverage Report: Skipped (go not available)${NC}"
    return 1
  fi

  echo -e "${BLUE}  Running go test with coverage (threshold: ${COVERAGE_THRESHOLD}%)...${NC}"
  go test -coverprofile=coverage.out "./${MODULE_PATH}/..." 2>/dev/null || true

  if [[ -f coverage.out ]]; then
    go tool cover -func=coverage.out 2>/dev/null || true
    rm -f coverage.out
  else
    echo -e "${YELLOW}  Could not generate coverage data.${NC}"
  fi
  echo ""
  echo -e "${YELLOW}  (Advisory: check output above for files below ${COVERAGE_THRESHOLD}% line coverage)${NC}"
  return 0
}

run_rust_coverage() {
  if ! command -v cargo &>/dev/null; then
    echo -e "${YELLOW}  Coverage Report: Skipped (cargo not available)${NC}"
    return 1
  fi

  if command -v cargo-tarpaulin &>/dev/null; then
    echo -e "${BLUE}  Running cargo tarpaulin with coverage (threshold: ${COVERAGE_THRESHOLD}%)...${NC}"
    cargo tarpaulin --out Stdout 2>/dev/null || true
  else
    echo -e "${YELLOW}  Coverage Report: Skipped (cargo-tarpaulin not installed; install with: cargo install cargo-tarpaulin)${NC}"
    return 1
  fi
  echo ""
  echo -e "${YELLOW}  (Advisory: check output above for files below ${COVERAGE_THRESHOLD}% line coverage)${NC}"
  return 0
}

run_java_coverage() {
  echo -e "${YELLOW}  Coverage Report: Skipped (Java/JaCoCo coverage requires build tool integration — run manually)${NC}"
  return 1
}

# Run language-specific Phase 2
echo ""
echo '═══════════════════════════════════════════════════════════════'
echo "  Coverage Report [${CONFIG_LANGUAGE}]"
echo '═══════════════════════════════════════════════════════════════'
echo ""

case "$CONFIG_LANGUAGE" in
  typescript|javascript|ts|js)
    run_typescript_coverage || true
    ;;
  python|py)
    run_python_coverage || true
    ;;
  go|golang)
    run_go_coverage || true
    ;;
  rust|rs)
    run_rust_coverage || true
    ;;
  java|kotlin|jvm)
    run_java_coverage || true
    ;;
  *)
    echo -e "${YELLOW}  Coverage Report: No coverage integration for language '${CONFIG_LANGUAGE}'.${NC}"
    echo -e "${YELLOW}  Supported: typescript, python, go, rust, java${NC}"
    ;;
esac

# Exit with Phase 1's result (coverage is advisory only)
exit "$PHASE1_EXIT"
