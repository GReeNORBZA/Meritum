#!/usr/bin/env bash
# ============================================================================
# init-project.sh — Interactive scaffolding for the task runner system
#
# Walks through project setup and generates:
#   1. CLAUDE.md from the template (with placeholders filled in)
#   2. preamble.txt (project-specific context for every task prompt)
#   3. A skeleton config JSON for the first domain
#   4. Copies orchestration scripts into place
#   5. Creates required directories
#
# Usage:
#   ./scripts/init-project.sh                  # Interactive mode
#   ./scripts/init-project.sh --non-interactive # Use defaults (for CI testing)
#
# Prerequisites:
#   - Node.js (for generate-tasks.js)
#   - The CLAUDE-TEMPLATE.md file in the same directory as this script's parent
# ============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Determine script and project root ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Parse arguments ---
NON_INTERACTIVE=false
for arg in "$@"; do
  case "$arg" in
    --non-interactive) NON_INTERACTIVE=true ;;
  esac
done

# --- Helpers ---
prompt() {
  local varname="$1"
  local question="$2"
  local default="${3:-}"

  if [[ "$NON_INTERACTIVE" == true ]]; then
    eval "$varname=\"$default\""
    return
  fi

  if [[ -n "$default" ]]; then
    echo -en "${CYAN}${question}${NC} [${default}]: "
    read -r input
    eval "$varname=\"${input:-$default}\""
  else
    echo -en "${CYAN}${question}${NC}: "
    read -r input
    eval "$varname=\"$input\""
  fi
}

prompt_choice() {
  local varname="$1"
  local question="$2"
  shift 2
  local options=("$@")

  if [[ "$NON_INTERACTIVE" == true ]]; then
    eval "$varname=\"${options[0]}\""
    return
  fi

  echo -e "${CYAN}${question}${NC}"
  for i in "${!options[@]}"; do
    echo -e "  ${BOLD}$((i+1)))${NC} ${options[$i]}"
  done
  echo -en "  Choice [1]: "
  read -r choice
  choice="${choice:-1}"

  if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
    eval "$varname=\"${options[$((choice-1))]}\""
  else
    eval "$varname=\"${options[0]}\""
  fi
}

hr() {
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ============================================================================
# STEP 1: Collect project information
# ============================================================================
echo ""
hr
echo -e "${BOLD}  Task Runner — Project Setup${NC}"
hr
echo ""
echo -e "This will set up the task runner orchestration system for your project."
echo -e "It creates CLAUDE.md, preamble.txt, a config skeleton, and required directories."
echo ""

prompt PROJECT_NAME "Project name" "my-project"
prompt COMPANY_NAME "Company/organization name" ""
prompt PROJECT_DESC "One-line project description" ""

prompt_choice LANGUAGE "Primary programming language:" \
  "typescript" "python" "go" "rust" "java"

echo ""
echo -e "${BLUE}Language: ${LANGUAGE}${NC}"

# --- Language-specific defaults ---
case "$LANGUAGE" in
  typescript)
    DEFAULT_BACKEND="Fastify 5.x"
    DEFAULT_ORM="Drizzle ORM"
    DEFAULT_TEST="Vitest + Supertest"
    DEFAULT_PKG_MGR="pnpm"
    DEFAULT_VALIDATION="Zod"
    DEFAULT_DB="PostgreSQL 16"
    ;;
  python)
    DEFAULT_BACKEND="FastAPI"
    DEFAULT_ORM="SQLAlchemy"
    DEFAULT_TEST="pytest"
    DEFAULT_PKG_MGR="poetry"
    DEFAULT_VALIDATION="Pydantic"
    DEFAULT_DB="PostgreSQL 16"
    ;;
  go)
    DEFAULT_BACKEND="Go + Chi"
    DEFAULT_ORM="sqlx"
    DEFAULT_TEST="go test + testify"
    DEFAULT_PKG_MGR="go modules"
    DEFAULT_VALIDATION="go-playground/validator"
    DEFAULT_DB="PostgreSQL 16"
    ;;
  rust)
    DEFAULT_BACKEND="Axum"
    DEFAULT_ORM="sqlx"
    DEFAULT_TEST="cargo test"
    DEFAULT_PKG_MGR="cargo"
    DEFAULT_VALIDATION="validator"
    DEFAULT_DB="PostgreSQL 16"
    ;;
  java)
    DEFAULT_BACKEND="Spring Boot 3.x"
    DEFAULT_ORM="Spring Data JPA"
    DEFAULT_TEST="JUnit 5 + MockMvc"
    DEFAULT_PKG_MGR="Maven"
    DEFAULT_VALIDATION="Jakarta Validation"
    DEFAULT_DB="PostgreSQL 16"
    ;;
esac

echo ""
hr
echo -e "${BOLD}  Tech Stack${NC}"
hr
echo ""

prompt BACKEND "Backend framework" "$DEFAULT_BACKEND"
prompt FRONTEND "Frontend framework (or 'None')" "None"
prompt DATABASE "Database" "$DEFAULT_DB"
prompt ORM "ORM / query builder" "$DEFAULT_ORM"
prompt TEST_FRAMEWORK "Test framework" "$DEFAULT_TEST"
prompt VALIDATION "Validation library" "$DEFAULT_VALIDATION"
prompt PKG_MANAGER "Package manager" "$DEFAULT_PKG_MGR"

echo ""
hr
echo -e "${BOLD}  Infrastructure${NC}"
hr
echo ""

prompt HOSTING "Hosting / deployment" "Docker Compose"
prompt REGION "Region / data residency" ""
prompt REGULATORY "Regulatory requirements (or 'None')" "None"

echo ""
hr
echo -e "${BOLD}  First Domain / Module${NC}"
hr
echo ""
echo -e "The task runner organizes work into 'domains' (groups of related tasks)."
echo -e "Let's create your first domain config."
echo ""

prompt DOMAIN_NUMBER "Domain number (e.g., 01)" "01"
prompt DOMAIN_NAME "Domain name (e.g., User Management)" "Core Setup"
prompt MODULE_PATH "Module path in source (e.g., apps/api/src/domains/users)" "src"

# ============================================================================
# STEP 2: Create directories
# ============================================================================
echo ""
hr
echo -e "${BOLD}  Creating project structure...${NC}"
hr
echo ""

mkdir -p "$PROJECT_ROOT/configs"
mkdir -p "$PROJECT_ROOT/scripts/tasks/prompts/d${DOMAIN_NUMBER}"
mkdir -p "$PROJECT_ROOT/.build-state"
mkdir -p "$PROJECT_ROOT/logs/build"

echo -e "${GREEN}  ✓ configs/${NC}"
echo -e "${GREEN}  ✓ scripts/tasks/prompts/d${DOMAIN_NUMBER}/${NC}"
echo -e "${GREEN}  ✓ .build-state/${NC}"
echo -e "${GREEN}  ✓ logs/build/${NC}"

# ============================================================================
# STEP 3: Create preamble.txt
# ============================================================================
PREAMBLE_FILE="$PROJECT_ROOT/preamble.txt"

if [[ -f "$PREAMBLE_FILE" ]]; then
  echo -e "${YELLOW}  ! preamble.txt already exists — skipping${NC}"
else
  PREAMBLE_LINES=()
  PREAMBLE_LINES+=("Project: ${PROJECT_NAME}")
  [[ -n "$COMPANY_NAME" ]] && PREAMBLE_LINES+=("Company: ${COMPANY_NAME}")
  [[ -n "$PROJECT_DESC" ]] && PREAMBLE_LINES+=("Description: ${PROJECT_DESC}")
  PREAMBLE_LINES+=("Stack: ${BACKEND} + ${ORM} + ${DATABASE}")
  [[ "$FRONTEND" != "None" ]] && PREAMBLE_LINES+=("Frontend: ${FRONTEND}")
  PREAMBLE_LINES+=("Testing: ${TEST_FRAMEWORK}")
  [[ "$REGULATORY" != "None" ]] && PREAMBLE_LINES+=("Regulatory: ${REGULATORY}")
  PREAMBLE_LINES+=("Refer to CLAUDE.md for all coding conventions, module structure, and testing requirements.")

  printf '%s\n' "${PREAMBLE_LINES[@]}" > "$PREAMBLE_FILE"
  echo -e "${GREEN}  ✓ preamble.txt${NC}"
fi

# ============================================================================
# STEP 4: Create skeleton config JSON
# ============================================================================
CONFIG_FILE="$PROJECT_ROOT/configs/domain-${DOMAIN_NUMBER}-$(echo "$DOMAIN_NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-').json"

if [[ -f "$CONFIG_FILE" ]]; then
  echo -e "${YELLOW}  ! $(basename "$CONFIG_FILE") already exists — skipping${NC}"
else
  DOMAIN_SLUG="d${DOMAIN_NUMBER}"
  MANIFEST_BASENAME="domain-${DOMAIN_NUMBER}-$(echo "$DOMAIN_NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')"

  cat > "$CONFIG_FILE" <<EOJSON
{
  "domainNumber": "${DOMAIN_NUMBER}",
  "domainName": "${DOMAIN_NAME}",
  "language": "${LANGUAGE}",
  "manifestFile": "${MANIFEST_BASENAME}.tasks",
  "promptPrefix": "${DOMAIN_SLUG}",
  "modulePath": "${MODULE_PATH}",
  "prerequisites": [],
  "sections": [
    {
      "title": "${DOMAIN_NAME} — Initial Setup",
      "tasks": [
        {
          "id": "D${DOMAIN_NUMBER}-001",
          "description": "Scaffold ${DOMAIN_NAME} module structure",
          "build": [
            "Create the directory structure and entry files for the ${DOMAIN_NAME} module.",
            "",
            "Follow the module structure defined in CLAUDE.md."
          ],
          "verify": "echo 'TODO: add your verify command here'",
          "tests": [],
          "depends": []
        }
      ]
    }
  ]
}
EOJSON
  echo -e "${GREEN}  ✓ $(basename "$CONFIG_FILE")${NC}"
fi

# ============================================================================
# STEP 5: Create CLAUDE.md from template
# ============================================================================
CLAUDE_MD="$PROJECT_ROOT/CLAUDE.md"
TEMPLATE_FILE="$PROJECT_ROOT/CLAUDE-TEMPLATE.md"

if [[ -f "$CLAUDE_MD" ]]; then
  echo -e "${YELLOW}  ! CLAUDE.md already exists — skipping (review CLAUDE-TEMPLATE.md to update)${NC}"
elif [[ ! -f "$TEMPLATE_FILE" ]]; then
  echo -e "${YELLOW}  ! CLAUDE-TEMPLATE.md not found — skipping CLAUDE.md generation${NC}"
  echo -e "${YELLOW}    Copy CLAUDE-TEMPLATE.md to your project root and re-run, or create CLAUDE.md manually.${NC}"
else
  # Perform placeholder substitutions
  sed \
    -e "s|\[PROJECT NAME\]|${PROJECT_NAME}|g" \
    -e "s|\[product name / URL\]|${PROJECT_NAME}|g" \
    -e "s|\[company name\]|${COMPANY_NAME:-[company name]}|g" \
    -e "s|\[hosting provider, region, any residency requirements\]|${HOSTING}${REGION:+, ${REGION}}|g" \
    -e "s|\[applicable regulations, if any — e.g., HIPAA, GDPR, SOC2, PCI-DSS, or \"None\"\]|${REGULATORY}|g" \
    -e "s|\[e.g., TypeScript (strict mode)\]|${LANGUAGE}|g" \
    -e "s|\[e.g., Fastify 5.x / Express 4.x / Django 5.x / Go + Chi\]|${BACKEND}|g" \
    -e "s|\[e.g., Next.js 15 (App Router) / SvelteKit / Vue 3 / None\]|${FRONTEND}|g" \
    -e "s|\[e.g., PostgreSQL 16 / MySQL 8 / MongoDB 7 / SQLite\]|${DATABASE}|g" \
    -e "s|\[e.g., Drizzle ORM / Prisma / SQLAlchemy / GORM / raw SQL\]|${ORM}|g" \
    -e "s|\[e.g., Vitest + Supertest / Jest / pytest / go test\]|${TEST_FRAMEWORK}|g" \
    -e "s|\[e.g., Zod / Yup / Joi / Pydantic / class-validator\]|${VALIDATION}|g" \
    -e "s|\[e.g., pnpm / npm / yarn / pip / go modules\]|${PKG_MANAGER}|g" \
    "$TEMPLATE_FILE" > "$CLAUDE_MD"

  echo -e "${GREEN}  ✓ CLAUDE.md (generated from template — review and fill remaining [BRACKETED] placeholders)${NC}"
fi

# ============================================================================
# STEP 6: Create .gitignore entries
# ============================================================================
GITIGNORE="$PROJECT_ROOT/.gitignore"

add_gitignore() {
  local pattern="$1"
  if [[ -f "$GITIGNORE" ]]; then
    if ! grep -qF "$pattern" "$GITIGNORE" 2>/dev/null; then
      echo "$pattern" >> "$GITIGNORE"
      return 0
    fi
    return 1
  else
    echo "$pattern" > "$GITIGNORE"
    return 0
  fi
}

GITIGNORE_ADDED=false
add_gitignore ".build-state/" && GITIGNORE_ADDED=true
add_gitignore "logs/build/" && GITIGNORE_ADDED=true
add_gitignore ".coverage-tmp/" && GITIGNORE_ADDED=true

if [[ "$GITIGNORE_ADDED" == true ]]; then
  echo -e "${GREEN}  ✓ .gitignore updated (added .build-state/, logs/build/, .coverage-tmp/)${NC}"
else
  echo -e "${GREEN}  ✓ .gitignore already has required entries${NC}"
fi

# ============================================================================
# STEP 7: Verify scripts are in place
# ============================================================================
echo ""
hr
echo -e "${BOLD}  Checking orchestration scripts...${NC}"
hr
echo ""

SCRIPTS=(
  "scripts/generate-tasks.js"
  "scripts/validate-config.sh"
  "scripts/verify-tests.sh"
  "scripts/audit-test-coverage.sh"
  "task-runner.sh"
)

ALL_PRESENT=true
for script in "${SCRIPTS[@]}"; do
  if [[ -f "$PROJECT_ROOT/$script" ]]; then
    echo -e "${GREEN}  ✓ ${script}${NC}"
  else
    echo -e "${RED}  ✗ ${script} — missing${NC}"
    ALL_PRESENT=false
  fi
done

if [[ "$ALL_PRESENT" != true ]]; then
  echo ""
  echo -e "${YELLOW}  Some orchestration scripts are missing. Copy them from the template project.${NC}"
fi

# ============================================================================
# STEP 8: Generate initial manifest
# ============================================================================
echo ""
hr
echo -e "${BOLD}  Generating initial manifest...${NC}"
hr
echo ""

if command -v node &>/dev/null && [[ -f "$PROJECT_ROOT/scripts/generate-tasks.js" && -f "$CONFIG_FILE" ]]; then
  node "$PROJECT_ROOT/scripts/generate-tasks.js" "$CONFIG_FILE" 2>&1 | sed 's/^/  /'
  echo ""
  echo -e "${GREEN}  ✓ Manifest and prompts generated${NC}"
else
  echo -e "${YELLOW}  ! Could not generate manifest (Node.js or generate-tasks.js not available)${NC}"
  echo -e "${YELLOW}    Run manually: node scripts/generate-tasks.js $(basename "$CONFIG_FILE")${NC}"
fi

# ============================================================================
# DONE
# ============================================================================
echo ""
hr
echo -e "${BOLD}${GREEN}  Setup complete!${NC}"
hr
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo ""
echo -e "  1. ${CYAN}Review and edit CLAUDE.md${NC}"
echo -e "     Fill in remaining [BRACKETED] placeholders — especially module structure,"
echo -e "     database conventions, and API conventions."
echo ""
echo -e "  2. ${CYAN}Edit your domain config${NC}"
echo -e "     ${CONFIG_FILE}"
echo -e "     Add real tasks with descriptions, verify commands, and test definitions."
echo ""
echo -e "  3. ${CYAN}Regenerate manifest after editing config${NC}"
echo -e "     node scripts/generate-tasks.js $(basename "$CONFIG_FILE")"
echo ""
echo -e "  4. ${CYAN}Run the task runner${NC}"
echo -e "     ./task-runner.sh scripts/tasks/$(basename "${CONFIG_FILE%.json}.tasks") --dry-run"
echo ""
echo -e "  5. ${CYAN}Add more domains${NC}"
echo -e "     Create additional config JSONs in configs/ for each domain."
echo -e "     Use \"prerequisites\" to define build order between domains."
echo ""
