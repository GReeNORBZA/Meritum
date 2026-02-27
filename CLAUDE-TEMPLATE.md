# CLAUDE.md — [PROJECT NAME]

<!--
  TEMPLATE INSTRUCTIONS (delete this block when using):

  This is a generalized CLAUDE.md template for use with the task-runner
  orchestration system. It serves two purposes:

  1. Claude Code reads it automatically on every session, so it defines
     how Claude writes code in your project.
  2. The task runner prepends a preamble to each prompt, but CLAUDE.md
     provides the persistent rules that every task inherits.

  HOW TO FILL THIS OUT:
  - Replace all [BRACKETED] placeholders with your project's specifics.
  - Delete any sections that don't apply (e.g., remove "Tenant Isolation"
    if your app isn't multi-tenant).
  - Add sections for domain-specific concerns (e.g., regulatory compliance,
    industry-specific validation rules).
  - The more precise you are, the better Claude's output. Vague instructions
    produce inconsistent code. Specific examples produce consistent code.

  WHAT MAKES A GOOD CLAUDE.md:
  - Concrete examples (show the pattern, don't just describe it)
  - Explicit "do / don't" rules (Claude follows prohibitions reliably)
  - File paths and naming conventions (reduces guesswork)
  - Code snippets for repeated patterns (Claude will match the style)
  - A clear "definition of done" (what must be true before moving on)
-->

## Project Overview

[1-3 sentences: what the product does and who it serves.]

- **Product:** [product name / URL]
- **Company:** [company name]
- **Infrastructure:** [hosting provider, region, any residency requirements]
- **Regulatory:** [applicable regulations, if any — e.g., HIPAA, GDPR, SOC2, PCI-DSS, or "None"]

## Tech Stack

<!--
  List every technology choice. Claude uses this to:
  - Import the right libraries (not alternatives)
  - Use the correct API patterns (e.g., Fastify vs Express middleware)
  - Generate compatible code across the project
  Be specific about versions — "React 19" produces different code than "React 18".
-->

| Layer | Technology |
|-------|-----------|
| Language | [e.g., TypeScript (strict mode)] |
| Backend | [e.g., Fastify 5.x / Express 4.x / Django 5.x / Go + Chi] |
| Frontend | [e.g., Next.js 15 (App Router) / SvelteKit / Vue 3 / None] |
| Database | [e.g., PostgreSQL 16 / MySQL 8 / MongoDB 7 / SQLite] |
| ORM/Query | [e.g., Drizzle ORM / Prisma / SQLAlchemy / GORM / raw SQL] |
| Auth | [e.g., Lucia / NextAuth / Passport / custom JWT] |
| Testing | [e.g., Vitest + Supertest / Jest / pytest / go test] |
| Validation | [e.g., Zod / Yup / Joi / Pydantic / class-validator] |
| Package Manager | [e.g., pnpm / npm / yarn / pip / go modules] |
| Monorepo | [e.g., Turborepo + pnpm workspaces / Nx / None] |
| Deployment | [e.g., Vercel / AWS ECS / Docker Compose / fly.io] |

<!--
  Add rows for any other significant choices: email provider, file storage,
  real-time (WebSocket/SSE), queue system, cache, CDN, etc.
-->

## Project Structure

<!--
  Show the actual directory tree. This is the single most important section
  for Claude's accuracy — it tells Claude where to put new files and where
  to find existing ones. Update this as the project evolves.
-->

```
[project-name]/
├── CLAUDE.md
├── [config files: tsconfig.json, turbo.json, pyproject.toml, go.mod, etc.]
├── [app directories]
│   ├── [backend]/
│   │   ├── src/
│   │   │   ├── [module-pattern]/    # [describe what goes here]
│   │   │   ├── [shared-code]/       # [describe what goes here]
│   │   │   └── [entry-point]        # [e.g., server.ts, main.go, app.py]
│   │   └── test/
│   │       ├── [unit tests location]
│   │       └── [integration tests location]
│   └── [frontend]/
│       ├── src/
│       │   ├── [pages/routes]/
│       │   ├── [components]/
│       │   └── [shared code]/
│       └── test/
├── [shared packages, if monorepo]/
│   └── [shared]/
│       └── src/
└── docs/
    └── [requirements location]
```

## Module Structure

<!--
  Define the file pattern that every module/feature/domain follows.
  This is your "cookie cutter" — Claude will replicate this pattern
  exactly for every new module. The more consistent your codebase,
  the better Claude performs.

  If your project doesn't have a formal module pattern, define one here.
  Even "each feature gets a folder with index.ts, types.ts, and
  feature.test.ts" is valuable.
-->

Every module in `[path to modules]` follows this structure:

```
[modules]/{name}/
├── {name}.[routes/controller/router].[ext]    # [Route/endpoint definitions]
├── {name}.[handlers/views/resolvers].[ext]    # [Request handling — thin layer]
├── {name}.service.[ext]                       # [Business logic — all rules live here]
├── {name}.repository.[ext]                    # [Database queries — only file that touches DB]
├── {name}.schema.[ext]                        # [Validation schemas]
└── {name}.test.[ext]                          # [Unit tests for service layer]
```

**Rules:**
- [e.g., Handlers never call repositories directly. Always go through the service.]
- [e.g., Repositories never contain business logic. Only data access.]
- [e.g., Services receive dependencies via function parameters, not global imports (testable).]
- [e.g., Routes define request/response schemas for automatic validation.]

<!--
  Adapt the pattern to your stack. A Django project might use:
    {name}/models.py, views.py, serializers.py, urls.py, tests.py
  A Go project might use:
    {name}/handler.go, service.go, repository.go, model.go, handler_test.go
  The point is consistency, not a specific pattern.
-->

## Database Conventions

### Naming

<!--
  Be explicit. Claude will follow whatever convention you define here
  for every new table, column, and migration it creates.
-->

- Tables: [e.g., `snake_case`, plural — `users`, `orders`, `line_items`]
- Columns: [e.g., `snake_case` — `created_at`, `order_total`]
- Primary keys: [e.g., `{singular}_id` as UUID — `user_id`, `order_id`]
- Foreign keys: [e.g., match the referenced column name — `user_id REFERENCES users(user_id)`]
- Timestamps: [e.g., `created_at`, `updated_at` on every table, type TIMESTAMPTZ, default now()]
- Booleans: [e.g., `is_` prefix — `is_active`, `is_verified`]

### Schema & Migrations

- [e.g., Define tables in `packages/shared/src/schemas/db/` using Drizzle schema syntax]
- [e.g., Migrations generated via `drizzle-kit generate`, stored in `apps/api/drizzle/migrations/`]
- [e.g., Never edit generated migration files manually]

### Tenant Isolation

<!--
  DELETE this section if your app is not multi-tenant.
  If it IS multi-tenant, this is your most critical security control.
  Be extremely explicit about how scoping works.
-->

Every query that touches [tenant-scoped data] must include `WHERE [tenant_id_column] = :authenticatedTenantId`. This is enforced at the repository layer. Never rely on the handler to pass the correct tenant ID — extract it from the authenticated session context inside the repository function.

```[language]
// CORRECT — repository extracts tenant ID from context
async function getItems(ctx: AuthContext, filters: ItemFilters) {
  return db.select().from(items)
    .where(eq(items.[tenantIdColumn], ctx.[tenantId]))
    .where(/* ...additional filters... */);
}

// WRONG — handler passes tenant ID as a parameter
async function getItems(tenantId: string, filters: ItemFilters) { ... }
```

### Soft Deletes

<!--
  DELETE if you don't use soft deletes. If you do, specify which tables
  and what the column name/convention is.
-->

- [e.g., Use `is_active BOOLEAN DEFAULT true` on: users, organizations, projects]
- [e.g., Add `.where(eq(table.isActive, true))` to all default queries]
- [e.g., Hard deletes only for: cache entries, expired sessions, temporary tokens]

## API Conventions

### URL Pattern

```
[e.g., /api/v1/{resource}]
[e.g., /api/v1/{resource}/{id}]
[e.g., /api/v1/{resource}/{id}/{sub-resource}]
```

### Request/Response Format

- [e.g., All responses: `{ data: T }` for success, `{ error: { code: string, message: string } }` for errors]
- [e.g., Pagination: `{ data: T[], pagination: { total, page, pageSize, hasMore } }`]
- [e.g., Dates: ISO 8601 strings]
- [e.g., Money: string with 2 decimal places ("100.00") — never floating point]
- [e.g., IDs: UUID strings]

### HTTP Status Codes

- 200: [e.g., Success (GET, PUT, PATCH)]
- 201: [e.g., Created (POST)]
- 204: [e.g., No content (DELETE)]
- 400: [e.g., Validation error]
- 401: [e.g., Not authenticated]
- 403: [e.g., Forbidden]
- 404: [e.g., Not found (also used for unauthorized access to avoid leaking existence)]
- 409: [e.g., Conflict]
- 422: [e.g., Business rule violation]
- 500: [e.g., Internal server error — no details exposed]

## Authentication & Authorization

<!--
  Describe your auth model. Include the shape of the auth context object
  that's available on every authenticated request — Claude will reference
  this when writing handlers and repository functions.
-->

### Auth Context

Every authenticated request has an auth context available:

```[language]
interface AuthContext {
  userId: string;
  [tenantId]: string;           // [if multi-tenant]
  role: [role union type];
  [additional fields as needed]
}
```

### Permission Checking

<!--
  Show how permissions are enforced in routes. Give a concrete example.
-->

```[language]
// Example: permission guard on a route
[your framework's route definition with auth middleware]
```

## Error Handling

<!--
  Define your error class hierarchy or error handling pattern.
  Show the actual code pattern — Claude will reuse it everywhere.
-->

```[language]
// [path to error definitions]
[your error class hierarchy or error factory pattern]
```

[e.g., The error handler catches AppError instances and formats the response. Unexpected errors return 500 with no internal details exposed.]

## Logging

<!--
  What to log and what never to log. The "never log" list is especially
  important — it prevents Claude from accidentally introducing PII leaks.
-->

- [e.g., Structured JSON via Pino]
- [e.g., Every log entry includes: requestId, userId (if authenticated), action]
- **Never log:** [e.g., passwords, tokens, PII, credit card numbers, API keys]
- **Always log:** [e.g., auth events, state transitions, permission checks, API errors]

## Testing Strategy

<!--
  Define what tests are required, where they live, and how to run them.
  Be explicit about what "tested" means for your project.
-->

### Unit Tests

- [e.g., Test service layer functions in isolation]
- [e.g., Mock repositories / external dependencies]
- Located in: [path]
- Run: [command]

### Integration Tests

- [e.g., Test full API request/response cycle]
- [e.g., Use test database]
- Located in: [path]
- Run: [command]

### E2E Tests

<!--
  DELETE if you don't have E2E tests.
-->

- Located in: [path]
- Run: [command]

### Security Tests

<!--
  DELETE if security tests are not a requirement for your project.
  If they ARE required, define the categories and what each must cover.
  The categories below are adapted from the Meritum pattern — keep the
  ones that apply and remove the rest.
-->

Security tests live in `[path]` with one file per category:

| Category | What It Tests | Applies To |
|----------|--------------|------------|
| Authentication (authn) | Every route returns 401 without session | All authenticated routes |
| Authorization (authz) | Permission-based access enforced | Routes with role/permission guards |
| Tenant isolation (scoping) | No cross-tenant data leakage | All multi-tenant queries |
| Input validation (input) | SQL injection, XSS, type coercion rejected | All user input fields |
| Data leakage (leakage) | No sensitive data in errors, headers, logs | All routes handling sensitive data |
| Audit trail (audit) | State changes produce audit records | All state-changing actions |

### Test Fixtures

<!--
  If you have shared test fixture factories, show the pattern here.
  Claude will reuse these instead of creating ad-hoc test data.
-->

```[language]
// [path to fixture factory]
[your fixture factory pattern]
```

## Environment Variables

<!--
  List all environment variables. This tells Claude what config is available
  and prevents it from hardcoding values. Use placeholder values.
  Group by concern (database, auth, external services, app config).
-->

```env
# Database
DATABASE_URL=[connection string pattern]

# Auth
[auth-related vars]

# External Services
[API keys, endpoints, etc.]

# App
NODE_ENV=production
[PORT, HOST, etc.]
```

## Domain / Feature Build Order

<!--
  If your project has multiple domains/features with dependencies between
  them, define the build order here. This is critical for the task runner —
  it determines which manifests to run first.

  DELETE this section if your project doesn't have a meaningful build order.

  IMPORTANT: Also add a "prerequisites" array to each domain's config JSON
  so the task runner enforces build order automatically. For example:

    {
      "domainName": "Provider Management",
      "prerequisites": ["domain-01-iam", "domain-02-reference"],
      ...
    }

  The prerequisite names must match the manifest basenames (without .tasks)
  of the domains they depend on. The task runner checks for completion
  markers in .build-state/ and hard-blocks if any prerequisite is missing.
-->

Build domains in this order. Each domain's requirements are in `[docs location]`.

1. **[Domain/Feature 1]** — [why it's first — e.g., "Foundation. Auth, sessions, RBAC."] `prerequisites: []`
2. **[Domain/Feature 2]** — [dependency rationale] `prerequisites: ["domain-01"]`
3. **[Domain/Feature 3]** — [dependency rationale] `prerequisites: ["domain-01", "domain-02"]`
[... continue for all domains/features]

## Git & Repository Configuration

<!--
  Tell Claude how git is configured so it doesn't attempt SSH when
  you're using HTTPS, or vice versa.
-->

- **Repository:** [URL]
- **Authentication:** [e.g., gh CLI over HTTPS / SSH key / token]
- **Branch strategy:** [e.g., main + feature branches / trunk-based / gitflow]

## Working With This Codebase

### Build-Test-Fix Loop (MANDATORY)

**Never move to the next file or task until the current one passes all tests.** After writing any code, immediately follow this loop:

```
1. WRITE code ([describe the typical order: e.g., repository → service → handler → route])
2. RUN relevant tests:
   - After writing [layer]:  [specific test command]
   - After writing [layer]:  [specific test command]
   - After writing everything: [full test command]
3. READ test output. If failures exist:
   a. Identify the root cause from the error message and stack trace
   b. Fix the code (not the test, unless the test itself is wrong)
   c. Re-run ONLY the failing test file (faster feedback)
   d. Repeat until green
4. MOVE to the next file only when all tests pass
```

**Context window management during fix loops:**
- Run only the specific failing test file, not the full suite, to minimize output
- If a fix loop exceeds 3 iterations on the same failure, stop and add a `// TODO: FAILING —` comment with the error details, then move on. The task runner will flag this.

### When Invoked by the Task Runner

When your prompt starts with `[TASK]`, you are being invoked by the automated task runner. Follow these rules:

1. Read the task description carefully — it specifies exactly which files to create/modify
2. Read only the requirements sections referenced in the task (not entire docs)
3. Complete the build-test-fix loop for every file
4. Write ALL tests listed in the "Required Tests" section — the verify step counts test definitions (language-specific: `it()`/`test()` for TypeScript, `def test_*` for Python, `func Test*` for Go, `#[test]` for Rust, `@Test` for Java) and fails if fewer than expected exist. Every test must contain at least one assertion. Trivial assertions are banned.
5. After all tests pass, output exactly this on a new line: `[TASK_COMPLETE]`
6. If tests fail after 5 fix attempts, output: `[TASK_BLOCKED] reason: <one-line description>`
7. Do not ask questions — make reasonable decisions based on CLAUDE.md and the requirements
8. If your prompt starts with `[TASK] [RETRY N/M]`, a previous attempt failed. The failure output is included — read it carefully, diagnose the root cause, and fix it before re-running tests

### Task Runner CLI

```bash
./task-runner.sh <manifest-file> [options]

Options:
  --resume             Resume after the last completed task (reads .progress file)
  --dry-run            Print what would execute without invoking Claude
  --only=<task-id>     Run a single specific task, skipping all others
  --config=<file>      Specify config JSON (auto-detected from manifest name if omitted)
  --webhook=<url>      POST build results to this URL on completion
  --no-checkpoint      Disable git commit/rollback after each task
  --no-preflight       Skip environment verification checks
  --clean-logs         Prune old log dirs and exit (no tasks run)
  --non-interactive    Never prompt for input (auto-continue on failure); auto-enabled when stdin is not a terminal (e.g., CI)
  --parallel[=N]       Run up to N tasks concurrently within each section (default N=2); sections still run sequentially

Environment variables:
  TASK_RUNNER_WEBHOOK  Default webhook URL (overridden by --webhook)
  COVERAGE_THRESHOLD   Minimum line coverage % for advisory report (default: 60)
  LOG_RETENTION        Number of recent log dirs to keep per manifest (default: 10)
  DATABASE_URL         If set, preflight checks database connectivity

Other scripts:
  ./scripts/build-status.sh              Show cross-domain build status dashboard
  ./scripts/build-status.sh --verbose    Include latest failure details
```

### Task Runner Safety Features

The task runner provides these automatic safety mechanisms. They run in order before, during, and after task execution.

#### Pre-Build

- **Config validation:** If `validate-config.sh` exists and a config JSON is available, validates the config's schema before starting — required fields, task ID format, duplicate IDs, dependency references (including execution order), test/testFile consistency, prerequisite existence, and language field validity. Blocks the build if validation fails.
- **Concurrent build lock:** Acquires a PID-based lock file (`.build-state/{manifest}.lock`) before starting. If another instance is already running the same manifest, blocks with an error. Stale locks (PID no longer running) are auto-removed. Lock is released on exit via trap.
- **Preamble resolution:** A project-specific preamble is prepended to every task prompt. Resolution order: (1) `"preamble"` field in config JSON (string or array), (2) `preamble.txt` in project root, (3) generic fallback. This keeps project-specific context out of the runner script itself.
- **Preflight checks:** Verifies the environment before any tasks execute — Claude CLI available, Node.js installed (required by orchestration scripts), language-specific toolchain (e.g., pnpm for TypeScript, python + poetry for Python, go for Go, cargo for Rust, java + maven for Java), git working tree clean, database reachable (if `DATABASE_URL` set), dependencies present (language-aware: checks for lock files and dependency directories). Fails fast before burning API calls on a broken environment. Disable with `--no-preflight`.
- **Cross-domain prerequisites:** If the config JSON has a `"prerequisites"` array (e.g., `["domain-01-iam", "domain-02-reference"]`), the runner checks `.build-state/{name}.completed` markers for each. Hard-blocks the build if any prerequisite domain hasn't completed successfully. Ensures domains are built in dependency order.
- **Prompt staleness detection:** Scans prompt `.md` files for backtick-quoted file paths and checks each exists in the codebase. If stale references are found and a config file is available, auto-regenerates prompts from the config via `generate-tasks.js`. Warns and continues if some references remain stale after regeneration.

#### During Build

- **Retry with failure context:** Failed tasks are retried up to `MAX_RETRIES` times (default: 2). On retry, the previous attempt's verification output (last 50 lines) is prepended to the prompt so Claude can see what went wrong and fix it.
- **Git checkpointing:** After each passed task, the runner commits the working state (`git commit --no-verify`). If the next task fails after all retries, the runner rolls back to the last checkpoint (`git checkout -- . && git clean -fd`) so subsequent tasks start from known-good code. In `--parallel` mode, checkpoints happen per section instead of per task. Disable with `--no-checkpoint`.
- **Verify timeout:** Verification commands are wrapped in a `VERIFY_TIMEOUT` (default: 120 seconds). If a test suite hangs (deadlock, network wait), the verify step is killed and the task is marked as failed rather than blocking the build forever.
- **Test count enforcement:** When a task defines required tests, the verify step runs `verify-tests.sh` which counts test definitions using language-specific patterns (see Multi-Language Support below) and fails if fewer than expected exist.
- **Test quality enforcement:** `verify-tests.sh` also checks that each test contains at least one assertion (language-specific patterns), and bans trivial assertions. A test that exists but asserts nothing meaningful still fails verification.
- **Parallel execution:** With `--parallel=N`, tasks within the same manifest section run concurrently (up to N at a time). Sections still run sequentially — a section doesn't start until the previous one completes. This is safe because tasks in the same section should be independent (e.g., multiple schema definitions, or multiple repository implementations). Structure your config sections accordingly: group independent tasks together, use section boundaries as dependency barriers.

#### Post-Build

- **Completion markers:** If all tasks pass (0 failures, 0 blocked), the runner writes `.build-state/{manifest-name}.completed` with metadata (timestamp, task counts). This marker is what downstream domains check in their prerequisite validation.
- **Post-run test audit:** Scans the config JSON against actual source files and reports test gaps — missing test files, insufficient test counts, or specific test descriptions not found in code. The build fails if gaps exist. Run with `--verbose` to see which specific test descriptions are missing.
- **Coverage threshold (advisory):** Runs a language-appropriate coverage tool (vitest for TypeScript, pytest-cov for Python, go test -cover for Go, cargo tarpaulin for Rust) and reports which source files fall below the `COVERAGE_THRESHOLD` (default 60%). This is advisory only — it does not fail the build. Gated on the relevant coverage tool being installed.
- **Build notifications:** On completion, sends a desktop notification (Linux `notify-send` / macOS `osascript`) and, if `--webhook=<url>` or `TASK_RUNNER_WEBHOOK` is set, POSTs a JSON payload with status, pass/fail counts, duration, and log directory path.
- **Log rotation:** After each build, automatically prunes old log directories for the current manifest, keeping the newest `LOG_RETENTION` (default: 10). Run `--clean-logs` to manually trigger cleanup without running tasks.

### Orchestration File Structure

<!--
  This section documents the files that power the task runner orchestration.
  DELETE this section if you're not using the task runner system.
-->

```
[project-root]/
├── task-runner.sh                     # Main orchestration script
├── preamble.txt                       # Project preamble prepended to every task prompt
├── scripts/
│   ├── init-project.sh               # Interactive project scaffolding
│   ├── generate-tasks.js              # Config JSON → manifest + prompt files
│   ├── validate-config.sh             # Config JSON schema validation
│   ├── verify-tests.sh                # Test count + quality enforcement
│   ├── audit-test-coverage.sh         # Post-run gap detection + coverage
│   ├── build-status.sh               # Cross-domain build status dashboard
│   └── check-prompt-staleness.sh      # Prompt file freshness check
├── configs/
│   ├── domain-01-[name].json          # Task definitions per domain
│   ├── domain-02-[name].json
│   └── ...
├── scripts/tasks/
│   ├── domain-01-[name].tasks         # Generated manifests
│   ├── prompts/d01/                   # Generated prompt files
│   │   ├── D01-001.md
│   │   └── ...
│   └── ...
├── .build-state/                      # Completion markers (gitignored)
│   ├── domain-01-[name].completed
│   └── ...
└── logs/build/                        # Build logs per run (gitignored)
    └── domain-01-[name]-YYYYMMDD-HHMMSS/
```

### Getting Started (New Projects)

Run the interactive scaffolding script to set up a new project:

```bash
./scripts/init-project.sh
```

This walks you through project name, language, tech stack, and first domain, then generates:
- `CLAUDE.md` from the template (with your answers filled in)
- `preamble.txt` (project context prepended to every task prompt)
- A skeleton config JSON in `configs/`
- An initial manifest and prompt files
- Required directories (`.build-state/`, `logs/build/`)
- `.gitignore` entries for build artifacts

After scaffolding, review and edit `CLAUDE.md` to fill remaining `[BRACKETED]` placeholders — especially module structure, database conventions, and API conventions.

### Multi-Language Support

The orchestration system is language-aware. Add a `"language"` field to your config JSON to control how test counting, assertion validation, prompt generation, and coverage reporting work for your project's language.

**Supported languages:** `typescript` (default), `python`, `go`, `rust`, `java`

```json
{
  "domainNumber": "01",
  "domainName": "User Management",
  "language": "python",
  ...
}
```

If `language` is omitted, all tooling defaults to `typescript` for backward compatibility.

**What the language field controls:**

| Tool | TypeScript | Python | Go | Rust | Java |
|------|-----------|--------|-----|------|------|
| **Test counting** (`verify-tests.sh`) | `it()`/`test()` | `def test_*()` | `func Test*()` | `#[test]` | `@Test` |
| **Assertion counting** | `expect()`/`assert()` | `assert`/`self.assert*` | `assert.*`/`require.*` | `assert!`/`assert_eq!` | `assert*()`/`verify()` |
| **Trivial assertion ban** | `expect(true)` etc. | `assert True` etc. | `assert.True(t, true)` | `assert!(true)` | `assertTrue(true)` |
| **Prompt templates** (`generate-tasks.js`) | `it('desc', ...)` | `def test_desc():` | `func TestDesc(t)` | `#[test] fn desc()` | `@Test void desc()` |
| **Coverage tool** (`audit-test-coverage.sh`) | vitest + v8 | pytest-cov | go test -cover | cargo tarpaulin | JaCoCo (manual) |
| **Preflight checks** (`task-runner.sh`) | pnpm/yarn/npm + node_modules | python + poetry/pip | go | cargo + rustc | java + mvn/gradle |

**Additional config fields for coverage:**

```json
{
  "language": "typescript",
  "coverageCommand": "pnpm --filter api",  // Optional: custom test runner prefix for coverage
  ...
}
```

If `coverageCommand` is omitted, the audit script auto-detects based on lock files and monorepo structure (e.g., infers `pnpm --filter api` from `modulePath: "apps/api/src"`).

### Standard Development Workflow (Interactive)

When given a task interactively:
1. Identify which [domain/module/feature] is affected
2. Read the requirements doc for that [domain/module/feature] if you need context
3. Follow the module structure exactly
4. [e.g., Add validation schemas in the shared package, not in the API]
5. [e.g., Write the repository, service, handler, and routes in that order]
6. **Run tests after each file. Fix failures before moving to the next file.**
7. [e.g., Add security tests if applicable]
8. Run all tests to ensure nothing breaks: [full test command]

### Completion Checklist

<!--
  Define what "done" means for a unit of work. This is your quality gate.
  Claude will check this before declaring a task complete.
  Adapt to your project — not every project needs security tests,
  but every project benefits from a clear definition of done.
-->

A [domain/module/feature] is **not complete** until all of the following exist and pass:

- [ ] [e.g., Database schema defined]
- [ ] [e.g., Validation schemas defined]
- [ ] [e.g., Repository layer with tenant scoping on every query]
- [ ] [e.g., Service layer with business logic]
- [ ] [e.g., Handler layer (thin)]
- [ ] [e.g., Routes with validation and auth guards]
- [ ] [e.g., Unit tests for service layer]
- [ ] [e.g., Integration tests for API endpoints]
- [ ] [e.g., Security tests (whichever categories apply)]

**Do not:**
- [e.g., Skip the service layer and put logic in handlers]
- [e.g., Put validation schemas in the API instead of the shared package]
- [e.g., Use raw SQL without going through the ORM]
- [e.g., Access another module's tables directly — use its service or internal API]
- [e.g., Return detailed error messages that could leak system internals]
- [e.g., Log passwords, tokens, PII, or API keys]
- [e.g., Mark a module as complete without passing tests]
