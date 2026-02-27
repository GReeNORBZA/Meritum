#!/usr/bin/env bash
# ============================================================================
# validate-config.sh — Validates task runner config JSON files
#
# Checks config files against the expected schema used by the task runner
# orchestration system. Validates required fields, field types, task ID
# patterns, dependency references, and cross-config prerequisite references.
#
# Usage:
#   ./scripts/validate-config.sh configs/domain-05-provider-manifests.json
#   ./scripts/validate-config.sh configs/*.json
#   ./scripts/validate-config.sh configs/*.json --verbose
#
# Exit codes:
#   0 — All configs pass validation
#   1 — One or more configs have errors
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Parse Arguments ---
VERBOSE=false
CONFIG_FILES=()

for arg in "$@"; do
  case "$arg" in
    --verbose) VERBOSE=true ;;
    *)         CONFIG_FILES+=("$arg") ;;
  esac
done

if [[ ${#CONFIG_FILES[@]} -eq 0 ]]; then
  echo -e "${RED}Usage: $0 <config-json>... [--verbose]${NC}"
  echo -e "${RED}Example: $0 configs/*.json${NC}"
  exit 1
fi

# Verify at least one file exists
VALID_FILES=()
for f in "${CONFIG_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    VALID_FILES+=("$f")
  else
    echo -e "${YELLOW}WARN: File not found, skipping: $f${NC}"
  fi
done

if [[ ${#VALID_FILES[@]} -eq 0 ]]; then
  echo -e "${RED}No valid config files found.${NC}"
  exit 1
fi

echo -e "${BLUE}Validating ${#VALID_FILES[@]} config file(s)...${NC}"
echo ""

# --- Validation via Node.js ---
TOTAL_PASSED=0
TOTAL_FAILED=0

for CONFIG_FILE in "${VALID_FILES[@]}"; do
  RESULT=$(node -e '
const fs = require("fs");
const path = require("path");

const configPath = process.argv[1];
const verbose = process.argv[2] === "true";
const errors = [];
const warnings = [];

// --- Helpers ---
function err(msg) { errors.push("ERROR: " + msg); }
function warn(msg) { warnings.push("WARN: " + msg); }
function info(msg) { if (verbose) console.error("  [verbose] " + msg); }

// --- Load JSON ---
let config;
try {
  const raw = fs.readFileSync(configPath, "utf-8");
  config = JSON.parse(raw);
} catch (e) {
  err("Failed to parse JSON: " + e.message);
  console.log(JSON.stringify({ errors, warnings }));
  process.exit(0);
}

// --- Required top-level fields ---
const requiredFields = [
  "domainNumber", "domainName", "manifestFile",
  "promptPrefix", "modulePath", "prerequisites", "sections"
];

for (const field of requiredFields) {
  if (config[field] === undefined || config[field] === null) {
    err("Missing required top-level field: " + field);
  }
}

// Exit early if critical fields are missing
if (errors.length > 0 && (config.sections === undefined || config.domainNumber === undefined)) {
  console.log(JSON.stringify({ errors, warnings }));
  process.exit(0);
}

// --- Field type / format checks ---
const domainNumber = config.domainNumber;
if (typeof domainNumber !== "string") {
  err("domainNumber must be a string, got " + typeof domainNumber);
}

if (typeof config.domainName !== "string") {
  err("domainName must be a string, got " + typeof config.domainName);
}

if (typeof config.manifestFile !== "string") {
  err("manifestFile must be a string, got " + typeof config.manifestFile);
} else if (!config.manifestFile.endsWith(".tasks")) {
  err("manifestFile must end in .tasks, got: " + config.manifestFile);
}

if (typeof config.promptPrefix !== "string") {
  err("promptPrefix must be a string, got " + typeof config.promptPrefix);
}

if (typeof config.modulePath !== "string") {
  err("modulePath must be a string, got " + typeof config.modulePath);
}

// --- Optional language field ---
const SUPPORTED_LANGUAGES = ["typescript", "python", "go", "rust", "java"];
if (config.language !== undefined) {
  if (typeof config.language !== "string") {
    err("language must be a string if present, got " + typeof config.language);
  } else if (!SUPPORTED_LANGUAGES.includes(config.language)) {
    err("language must be one of [" + SUPPORTED_LANGUAGES.join(", ") + "], got: " + config.language);
  } else {
    info("language: " + config.language);
  }
} else {
  warn("No \"language\" field — defaulting to typescript. Add \"language\": \"<lang>\" to your config for non-TypeScript projects.");
}

// --- Optional coverageCommand field ---
if (config.coverageCommand !== undefined && typeof config.coverageCommand !== "string") {
  err("coverageCommand must be a string if present, got " + typeof config.coverageCommand);
} else if (config.coverageCommand) {
  info("coverageCommand: " + config.coverageCommand);
}

// --- Prerequisites ---
if (!Array.isArray(config.prerequisites)) {
  err("prerequisites must be an array, got " + typeof config.prerequisites);
} else {
  info("prerequisites: [" + config.prerequisites.join(", ") + "]");

  // Check each prerequisite references a known config
  const configDir = path.dirname(configPath);
  for (const prereq of config.prerequisites) {
    if (typeof prereq !== "string") {
      err("prerequisite entry must be a string, got " + typeof prereq);
      continue;
    }
    // Look for configs/{prereq}*.json in the same directory as the config
    const candidates = fs.readdirSync(configDir).filter(f =>
      f.startsWith(prereq) && f.endsWith(".json")
    );
    if (candidates.length === 0) {
      warn("Prerequisite \"" + prereq + "\" does not match any config file in " + configDir + "/");
    } else {
      info("Prerequisite \"" + prereq + "\" matched: " + candidates.join(", "));
    }
  }
}

// --- Sections ---
if (!Array.isArray(config.sections)) {
  err("sections must be an array, got " + typeof config.sections);
  console.log(JSON.stringify({ errors, warnings }));
  process.exit(0);
}

if (config.sections.length === 0) {
  err("sections must be a non-empty array");
  console.log(JSON.stringify({ errors, warnings }));
  process.exit(0);
}

// Collect all task IDs for dependency and duplicate checks
const allTaskIds = new Set();
const duplicateIds = [];
const taskIdPattern = /^D\d{2}-\d{3}$/;
const taskOrder = new Map();
let totalTasks = 0;

for (let si = 0; si < config.sections.length; si++) {
  const section = config.sections[si];
  const sLabel = "sections[" + si + "]";

  if (typeof section.title !== "string") {
    err(sLabel + ".title must be a string" + (section.title === undefined ? " (missing)" : ", got " + typeof section.title));
  } else {
    info(sLabel + ".title = \"" + section.title + "\"");
  }

  if (!Array.isArray(section.tasks)) {
    err(sLabel + ".tasks must be an array" + (section.tasks === undefined ? " (missing)" : ", got " + typeof section.tasks));
    continue;
  }

  if (section.tasks.length === 0) {
    err(sLabel + ".tasks must be a non-empty array");
    continue;
  }

  for (let ti = 0; ti < section.tasks.length; ti++) {
    const task = section.tasks[ti];
    const tLabel = sLabel + ".tasks[" + ti + "]";
    totalTasks++;

    // --- Required task fields ---
    // id
    if (typeof task.id !== "string") {
      err(tLabel + ".id must be a string" + (task.id === undefined ? " (missing)" : ", got " + typeof task.id));
    } else {
      if (!taskIdPattern.test(task.id)) {
        err(tLabel + ".id must match pattern D##-### (e.g. D05-001), got: " + task.id);
      }
      // Domain number consistency
      if (typeof domainNumber === "string") {
        const expectedPrefix = "D" + domainNumber;
        if (!task.id.startsWith(expectedPrefix + "-")) {
          err(tLabel + ".id \"" + task.id + "\" should start with \"" + expectedPrefix + "-\" (domainNumber is \"" + domainNumber + "\")");
        }
      }
      // Duplicate check
      if (allTaskIds.has(task.id)) {
        duplicateIds.push(task.id);
      } else {
        allTaskIds.add(task.id);
      }
      // Track execution order for dependency ordering validation
      taskOrder.set(task.id, totalTasks - 1);
      info(tLabel + " = " + task.id + ": " + (task.description || "(no description)").substring(0, 60));
    }

    // description
    if (typeof task.description !== "string") {
      err(tLabel + ".description must be a string" + (task.description === undefined ? " (missing)" : ", got " + typeof task.description));
    }

    // verify
    if (typeof task.verify !== "string") {
      err(tLabel + ".verify must be a string" + (task.verify === undefined ? " (missing)" : ", got " + typeof task.verify));
    }

    // build — required, must be array or string
    if (task.build === undefined || task.build === null) {
      err(tLabel + ".build is required (must be a string or array)");
    } else if (typeof task.build !== "string" && !Array.isArray(task.build)) {
      err(tLabel + ".build must be a string or array, got " + typeof task.build);
    }

    // --- Optional fields type checks ---
    if (task.frd !== undefined && !Array.isArray(task.frd)) {
      err(tLabel + ".frd must be an array if present, got " + typeof task.frd);
    }
    if (task.security !== undefined && !Array.isArray(task.security)) {
      err(tLabel + ".security must be an array if present, got " + typeof task.security);
    }
    if (task.depends !== undefined && !Array.isArray(task.depends)) {
      err(tLabel + ".depends must be an array if present, got " + typeof task.depends);
    }
    if (task.tests !== undefined && !Array.isArray(task.tests)) {
      err(tLabel + ".tests must be an array if present, got " + typeof task.tests);
    }
    if (task.testFile !== undefined && typeof task.testFile !== "string") {
      err(tLabel + ".testFile must be a string if present, got " + typeof task.testFile);
    }
    if (task.context !== undefined && typeof task.context !== "string" && !Array.isArray(task.context)) {
      err(tLabel + ".context must be a string or array if present, got " + typeof task.context);
    }

    // --- tests/testFile consistency ---
    if (Array.isArray(task.tests) && task.tests.length > 0) {
      if (task.testFile === undefined || task.testFile === null || task.testFile === "") {
        // No testFile specified — verify command must contain "vitest run"
        if (typeof task.verify === "string" && !task.verify.includes("vitest run")) {
          warn(tLabel + " (" + (task.id || "?") + "): has tests but no testFile, and verify command does not contain \"vitest run\"");
        }
      }
    }
  }
}

// --- Duplicate IDs ---
if (duplicateIds.length > 0) {
  for (const dup of duplicateIds) {
    err("Duplicate task ID: " + dup);
  }
}

// --- Dependency references ---
for (let si = 0; si < config.sections.length; si++) {
  const section = config.sections[si];
  if (!Array.isArray(section.tasks)) continue;
  for (let ti = 0; ti < section.tasks.length; ti++) {
    const task = section.tasks[ti];
    const tLabel = "sections[" + si + "].tasks[" + ti + "]";
    if (Array.isArray(task.depends)) {
      for (const dep of task.depends) {
        if (typeof dep !== "string") {
          err(tLabel + ".depends entry must be a string, got " + typeof dep);
        } else if (!allTaskIds.has(dep)) {
          err(tLabel + " (" + (task.id || "?") + "): depends on \"" + dep + "\" which does not exist in this config");
        } else if (task.id && taskOrder.has(task.id) && taskOrder.has(dep)) {
          const depIdx = taskOrder.get(dep);
          const taskIdx = taskOrder.get(task.id);
          if (depIdx >= taskIdx) {
            warn(tLabel + " (" + task.id + "): depends on \"" + dep + "\" which appears AFTER it in execution order (index " + depIdx + " vs " + taskIdx + ")");
          }
        }
      }
    }
  }
}

info("Total tasks: " + totalTasks + ", unique IDs: " + allTaskIds.size);

console.log(JSON.stringify({ errors, warnings, totalTasks }));
' "$CONFIG_FILE" "$VERBOSE" 2>&1)

  # Separate verbose output (stderr lines forwarded to stdout) from JSON result
  JSON_LINE=$(echo "$RESULT" | grep -E '^\{' | tail -1)
  VERBOSE_LINES=$(echo "$RESULT" | grep -v -E '^\{' || true)

  if [[ -n "$VERBOSE_LINES" ]]; then
    echo "$VERBOSE_LINES"
  fi

  if [[ -z "$JSON_LINE" ]]; then
    echo -e "${RED}FAIL${NC}: $CONFIG_FILE — internal error (no JSON output from validator)"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
    continue
  fi

  # Extract errors and warnings from JSON
  ERROR_COUNT=$(echo "$JSON_LINE" | node -e "
    const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf-8'));
    console.log(d.errors ? d.errors.length : 0);
  ")
  WARN_COUNT=$(echo "$JSON_LINE" | node -e "
    const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf-8'));
    console.log(d.warnings ? d.warnings.length : 0);
  ")
  TASK_COUNT=$(echo "$JSON_LINE" | node -e "
    const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf-8'));
    console.log(d.totalTasks || 0);
  ")

  # Print errors
  if [[ "$ERROR_COUNT" -gt 0 ]]; then
    echo -e "${RED}FAIL${NC}: $CONFIG_FILE (${TASK_COUNT} tasks, ${ERROR_COUNT} error(s), ${WARN_COUNT} warning(s))"
    echo "$JSON_LINE" | node -e "
      const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf-8'));
      for (const e of d.errors) console.log('  \x1b[0;31m' + e + '\x1b[0m');
    "
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
  else
    echo -e "${GREEN}PASS${NC}: $CONFIG_FILE (${TASK_COUNT} tasks, ${WARN_COUNT} warning(s))"
    TOTAL_PASSED=$((TOTAL_PASSED + 1))
  fi

  # Print warnings
  if [[ "$WARN_COUNT" -gt 0 ]]; then
    echo "$JSON_LINE" | node -e "
      const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf-8'));
      for (const w of d.warnings) console.log('  \x1b[1;33m' + w + '\x1b[0m');
    "
  fi

  echo ""
done

# --- Summary ---
TOTAL=$((TOTAL_PASSED + TOTAL_FAILED))
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}Validation Summary${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "  Configs checked: ${TOTAL}"
echo -e "  ${GREEN}Passed: ${TOTAL_PASSED}${NC}"
if [[ "$TOTAL_FAILED" -gt 0 ]]; then
  echo -e "  ${RED}Failed: ${TOTAL_FAILED}${NC}"
else
  echo -e "  Failed: 0"
fi
echo -e "${BLUE}============================================${NC}"

if [[ "$TOTAL_FAILED" -gt 0 ]]; then
  exit 1
fi
exit 0
