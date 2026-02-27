# Meritum Build Orchestration System

Automates Claude Code invocations for the build-test-fix workflow, solving the context window problem by giving each work unit a fresh, scoped Claude Code session.

The system has three layers: **config JSON files** define every task, **generators** produce manifests and prompts from those configs, and the **task runner** executes them sequentially with automated verification and retry.

## Architecture

```
Config JSON files (configs/*.json)         Specialized generators
~1.2 MB of structured task definitions     (build-hc-config.js, etc.)
            │                                        │
            ▼                                        ▼
      generate-tasks.js ◄──── reads config JSON ─────┘
            │
    ┌───────┴───────┐
    │               │
    ▼               ▼
.tasks manifests  prompt .md files
(22 files)        (530 files)
    │               │
    └───────┬───────┘
            │
            ▼
      task-runner.sh
      (Bash orchestrator)
            │
  For each task line:
            │
    ┌───────┴────────┐
    │                │
    ▼                ▼
claude CLI       verify command
(fresh context)  (vitest / validate-article / verify-frd)
    │                │
    │       ┌────────┴────────┐
    │       │                 │
    │     PASS              FAIL
    │     (next task)       (retry with error context,
    │                        up to MAX_RETRIES=2)
    │
  Each invocation receives:
  - [TASK] prefix
  - 6-line project preamble
  - Prompt .md content
  - On retry: [RETRY] prefix + last 50 lines of failure output

  Claude Code also auto-loads:
  - CLAUDE.md (~25K tokens of conventions)
```

## Context Strategy (Three Tiers)

The system manages context window budget across three tiers:

### Tier 1: Always Present (~25K tokens)
- **CLAUDE.md** — loaded automatically by Claude Code on every invocation
- **6-line project preamble** — injected by task-runner.sh into every prompt (regulatory constraints, security rules, stack summary)

### Tier 2: Per-Task (varies, target <5K tokens)
- **Task prompt** — the `.md` file with build instructions, FRD excerpts, security rules, test specs
- **`context` field** — optional excerpts from PROJECT_CONTEXT.md, included only when the task needs domain knowledge beyond what's in the FRD excerpt

Use the `context` field in the config JSON when a task requires understanding of:
- Cross-domain interfaces (e.g., claim service needs ProviderContext shape)
- Regulatory rules (e.g., WCB timing tier calculation needs tier definitions)
- Business workflow (e.g., batch assembly needs Thursday cycle understanding)

### Tier 3: Never Auto-Included
- **PROJECT_CONTEXT.md** — full project context document. Not loaded by default. Referenced manually in interactive Claude Code sessions when you need to explain "why" rather than "what."
- **Full FRD documents** — 15–67 KB each. Never loaded whole. Relevant sections excerpted into task prompts.

### Why Not Include Everything?
Claude Code's context window must accommodate: instructions (~25K) + task prompt (~3K) + reading existing code files (~20K for a domain module) + writing new code + test output + fix iterations. Loading PROJECT_CONTEXT.md (~15K) on every task would cut the working space by ~25%, causing fix loops to hit the window ceiling sooner.

## File Structure

```
scripts/
├── task-runner.sh                # The orchestrator (run this)
├── generate-tasks.js             # Config JSON → manifest + prompts
├── build-hc-config.js            # Programmatic help centre config builder
├── extract-frd.js                # .docx → .md FRD extraction (one-time)
├── validate-article.js           # Single help centre article quality gate
├── validate-all-articles.js      # Comprehensive help centre suite validator
├── verify-frd.sh                 # FRD document quality gate
└── tasks/
    ├── domain-01-iam.tasks       # Domain manifests (14 core domains)
    ├── domain-02-reference.tasks
    ├── domain-04-claim-core.tasks
    ├── domain-04-ahcip.tasks
    ├── domain-04-wcb.tasks
    ├── domain-05-provider.tasks
    ├── domain-06-patient.tasks
    ├── domain-07-intelligence.tasks
    ├── domain-08-analytics.tasks
    ├── domain-09-notification.tasks
    ├── domain-10-mobile.tasks
    ├── domain-11-onboarding.tasks
    ├── domain-12-platform.tasks
    ├── domain-13-support.tasks
    ├── help-centre.tasks         # Help centre articles (44 tasks)
    ├── frd-update.tasks          # FRD documentation sync (14 tasks)
    ├── ima-legal-requirements.tasks  # IMA/HIA compliance features (29 tasks)
    ├── domain-15-pricing-fix.tasks   # Supplementary task sets
    ├── domain-16-clinic-tier.tasks
    ├── domain-17-pricing-lifecycle.tasks
    ├── domain-18-referral-program.tasks
    ├── domain-19-policy-alignment.tasks
    └── prompts/
        ├── d01/ through d13/     # Domain prompt files
        ├── d04a/                 # AHCIP pathway prompts
        ├── d04w/                 # WCB pathway prompts
        ├── d15/ through d19/     # Supplementary domain prompts
        ├── hc/                   # Help centre article prompts (44 files)
        ├── frd/                  # FRD update prompts (14 files)
        └── ima/                  # IMA legal requirements prompts (29 files)

configs/
├── domain-01-iam.json            # Domain config JSONs (14 files)
├── domain-02-reference-manifests.json
├── ...
├── domain-13-support-manifests.json
└── help-centre.json              # Help centre config (generated by build-hc-config.js)
```

## Tools Reference

### task-runner.sh — The Orchestrator

Sequentially executes a `.tasks` manifest by invoking the `claude` CLI for each task, then verifying the output.

```bash
./scripts/task-runner.sh <manifest-file> [--resume] [--dry-run]
```

**Configuration constants:**
- `MAX_RETRIES=2` — retry a failed task up to 2 times
- `RETRY_DELAY=5` — seconds between retries
- `TASK_TIMEOUT=600` — 10 minutes per Claude Code invocation

**Signals recognized in Claude output:**
- `[TASK_COMPLETE]` — task succeeded, move to next
- `[TASK_BLOCKED] reason: ...` — task cannot proceed, skip without retrying

### generate-tasks.js — Config to Manifest/Prompt Generator

Reads a config JSON and produces two outputs: a `.tasks` manifest and individual `.md` prompt files.

```bash
node scripts/generate-tasks.js configs/domain-01-iam.json
```

**Config JSON schema:**
```json
{
  "domainNumber": "01",
  "domainName": "Identity & Access Management",
  "manifestFile": "domain-01-iam.tasks",
  "promptPrefix": "d01",
  "modulePath": "apps/api/src/domains/iam",
  "sections": [
    {
      "title": "Section Title",
      "tasks": [
        {
          "id": "D01-001",
          "description": "Human-readable task description",
          "verify": "pnpm --filter shared build",
          "build": ["Line 1", "Line 2"],
          "frd": ["FRD excerpt line 1"],
          "context": ["Optional context line"],
          "security": ["Security rule 1"],
          "depends": ["D01-000"],
          "tests": ["test description 1"]
        }
      ]
    }
  ]
}
```

Required fields per task: `id`, `description`, `verify`, `build`, `frd`. Optional: `context`, `security`, `depends`, `tests`.

**Generated prompt structure:**
```markdown
# Task {ID}: {Description}
## What to Build
## Project Context          (if context field provided)
## FRD Reference
## Critical Security Rules  (if security field provided)
## Prerequisites            (if depends field provided)
## Tests to Write           (if tests field provided)
## Run After Completion
```

### build-hc-config.js — Help Centre Config Builder

Programmatically generates `configs/help-centre.json` for all 43 help centre articles plus 1 validation task. Unlike domain configs (hand-authored JSON), this is a JavaScript builder that injects shared context (voice/style rules, front matter schema) into every task.

```bash
node scripts/build-hc-config.js
# Then generate manifests and prompts:
node scripts/generate-tasks.js configs/help-centre.json
```

**What it defines per article:**
- Category, slug, article type (procedural/reference), priority, review cycle
- Word count target (procedural: 300-600, reference: 600-1000)
- Content scope and cross-link targets
- FRD references for factual accuracy
- Shared voice/style rules injected into every task's `context` field

**Article categories (6):** getting-started, submitting-claims, after-submission, your-account, billing-reference, security-compliance.

### extract-frd.js — FRD Document Extractor

One-time utility that converts `.docx` FRD files in `docs/frd/` to markdown in `docs/frd/extracted/`. Uses Python (`python-docx`) under the hood. The extracted `.md` files are referenced by FRD update tasks and were used when authoring the help centre config.

```bash
node scripts/extract-frd.js
# Requires: python3 with python-docx installed
```

**Output:** Heading-aware markdown with table extraction. One `.md` file per `.docx` in `docs/frd/extracted/`.

### validate-article.js — Single Article Quality Gate

Per-article validator used as the verify command for each help centre task (HC-001 through HC-043).

```bash
node scripts/validate-article.js help-centre/getting-started/setting-up-your-professional-profile.md
```

**Checks (10):**
1. File exists and is non-empty
2. Starts with YAML front matter delimiter (`---`)
3. Front matter parseable with closing delimiter
4. All 8 required fields present: `title`, `category`, `slug`, `description`, `priority`, `last_reviewed`, `review_cycle`, `type`
5. Category is one of the 6 valid slugs
6. Priority is 1, 2, or 3
7. Review cycle is `quarterly`, `annual`, or `on-change`
8. No em dashes (U+2014) or `--` used as em dashes
9. No placeholder language (`coming soon`, `TBD`, `placeholder`, etc.)
10. Word count within range for article type (procedural: 300-600, reference: 600-1000)

### validate-all-articles.js — Comprehensive Help Centre Validator

Full-suite validator used as the verify command for the HC-099 final validation task.

```bash
node scripts/validate-all-articles.js
```

**Four-step validation:**
1. Verify all 43 expected articles exist and are non-empty
2. Run `validate-article.js` on every article
3. Scan all cross-links (`/help-centre/...`) and verify targets exist on disk
4. Report: total found, validated, missing, broken links, word count per category

### verify-frd.sh — FRD Document Quality Gate

Bash script used as the verify command for each FRD update task (FRD-01 through FRD-14).

```bash
./scripts/verify-frd.sh <frd-file-path> [min-words]
```

**Checks:**
- File exists and is non-empty
- Word count meets minimum threshold (configurable per task, default 500)
- First 10 lines contain "Meritum", "Domain", or "Functional Requirements"
- At least 3 markdown headings
- Warns (non-blocking) on TODO/TBD/FIXME/PLACEHOLDER text

## Task Sets

### Core Domain Builds (14 manifests, ~370 tasks)

Each domain follows a consistent build progression:

| Range | Layer | Typical Verify Command |
|-------|-------|----------------------|
| 001-009 | Schema & constants | `pnpm --filter shared build` |
| 010-019 | Repository layer | Unit tests |
| 020-029 | Service layer | Unit tests |
| 030-039 | Routes & handlers | Integration tests |
| 040-049 | Security tests (6 categories) | Individual security test files |
| 099 | Full validation | Full domain test suite |

**Build order (critical path):** D01 (IAM) → D12 (Platform) → D02 (Reference) → D05 (Provider) → D06 (Patient) → D11 (Onboarding) → D09 (Notification) → D04.0 (Claim Core) → D04.1 (AHCIP) → D04.2 (WCB) → D07 (Intelligence) → D08 (Analytics) → D10 (Mobile) → D13 (Support)

### Help Centre Articles (1 manifest, 44 tasks)

Generates 43 physician-facing help articles across 6 categories plus 1 validation task. Each article task writes a complete markdown file with YAML front matter. Verified by `validate-article.js` per task and `validate-all-articles.js` for the final HC-099 task.

```bash
# Regenerate config (if build-hc-config.js changed):
node scripts/build-hc-config.js

# Regenerate manifests and prompts:
node scripts/generate-tasks.js configs/help-centre.json

# Run:
./scripts/task-runner.sh scripts/tasks/help-centre.tasks
```

### FRD Documentation Sync (1 manifest, 14 tasks)

One task per domain. Each task reads the actual implementation code and the current FRD markdown, then reconciles the documentation in-place. Verified by `verify-frd.sh` with domain-specific minimum word counts (800-3000 depending on domain complexity).

```bash
# Prerequisite (one-time): extract .docx FRDs to markdown
node scripts/extract-frd.js

# Run:
./scripts/task-runner.sh scripts/tasks/frd-update.tasks
```

### IMA Legal Requirements (1 manifest, 29 tasks)

Implements HIA compliance features across 8 phases: schema/constants, cross-cutting changes, secondary email, IMA amendment system, breach notification, patient access export, complete health information export, and data destruction. Follows the standard domain build pattern (schema → repository → service → routes → security tests → final validation).

```bash
./scripts/task-runner.sh scripts/tasks/ima-legal-requirements.tasks
```

### Supplementary Task Sets (5 manifests)

Additional feature work that extends existing domains rather than building new ones:

| Manifest | Tasks | Purpose |
|----------|-------|---------|
| `domain-15-pricing-fix.tasks` | 4 | Pricing gap closure (Batch 0) |
| `domain-16-clinic-tier.tasks` | 26 | Clinic/practice tier pricing |
| `domain-17-pricing-lifecycle.tasks` | 15 | Pricing lifecycle management |
| `domain-18-referral-program.tasks` | 16 | Referral program |
| `domain-19-policy-alignment.tasks` | 15 | Policy alignment |

## Usage

```bash
# Build a core domain from scratch
./scripts/task-runner.sh scripts/tasks/domain-05-provider.tasks

# Preview what would run (no execution)
./scripts/task-runner.sh scripts/tasks/domain-05-provider.tasks --dry-run

# Resume after a failure (skips completed tasks)
./scripts/task-runner.sh scripts/tasks/domain-05-provider.tasks --resume

# Build help centre articles
./scripts/task-runner.sh scripts/tasks/help-centre.tasks

# Sync FRD documentation with implementation
./scripts/task-runner.sh scripts/tasks/frd-update.tasks

# Build IMA compliance features
./scripts/task-runner.sh scripts/tasks/ima-legal-requirements.tasks
```

## Task Manifest Format

```
# Comments start with #
## Section headers start with ## (logged, not executed)

TASK_ID | DESCRIPTION | PROMPT_FILE | VERIFY_COMMAND
```

- **TASK_ID**: Unique identifier (e.g., D05-010, HC-001, FRD-01, IMA-020). Used for logging and resume.
- **DESCRIPTION**: Human-readable description.
- **PROMPT_FILE**: Path to the markdown file containing the Claude Code prompt.
- **VERIFY_COMMAND**: Shell command that returns exit 0 on success. Varies by task type — see Tools Reference.

## Writing Good Task Prompts

Each prompt file should contain:

1. **What to Build** — exactly which files to create or modify
2. **FRD Reference** — the specific tables, fields, or rules from the FRD (copied in, not referenced by file path). Keep this to the minimum needed for the task.
3. **Critical Security Rules** — any security constraints that apply to this task
4. **Tests to Write** — test function signatures with descriptions
5. **Run After Completion** — the exact test command to run

Keep prompts under 200 lines. If a task requires more context, split it into smaller tasks.

## Retry Behaviour

When a task's verify command fails:
1. The runner captures the last 50 lines of test output
2. Re-invokes Claude Code with a `[RETRY]` prefix containing the failure output
3. Claude Code reads the failure, fixes the code, and re-runs tests
4. Up to MAX_RETRIES (default: 2) retries per task
5. If still failing after retries: logs as FAILED, asks whether to continue or abort

## Logs

Each run creates a log directory:
```
logs/build/{manifest-name}-{timestamp}/
├── summary.log              # Pass/fail for each task
├── .progress                # Completed tasks (for --resume)
├── D05-001.log              # Claude Code output for task
├── D05-001-verify-attempt0.log  # Verify command output
└── ...
```

## Tips

- **Start small:** Run one domain manifest at a time. Don't chain all 14 domains.
- **Review between domains:** After a domain completes, review the code before starting the next domain. The task runner is not a "set and forget" tool.
- **Fix blocked tasks manually:** When a task is BLOCKED, open an interactive Claude Code session to debug. The log files have the failure context.
- **Iterate on prompts:** If a task consistently fails, the prompt probably needs more context or the task is too large. Split it.
- **Regenerate after config changes:** If you edit a config JSON or `build-hc-config.js`, re-run `generate-tasks.js` (or `build-hc-config.js` first for help centre) to update the manifests and prompts.
- **FRD extraction is one-time:** Run `extract-frd.js` once after receiving new `.docx` FRDs. The extracted `.md` files are what the FRD update tasks read and modify.
