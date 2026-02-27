# Help Centre Content Generation Pipeline — Continuation Prompt

Paste everything below the line into a new Claude Code chat window.

---

# Help Centre Content Generation — Run the Pipeline

## What Already Exists

The help centre content pipeline is fully built and ready to execute. All components below are in place; do NOT modify them unless troubleshooting a failure.

### Pipeline Components
- `scripts/task-runner.sh` — Build orchestrator (invokes `claude -p` per task, retries on failure, logs results)
- `scripts/generate-tasks.js` — Manifest + prompt generator (consumes config JSON)
- `scripts/validate-article.js` — Article quality checker (front matter, word count 300-600 procedural / 600-1000 reference, no em dashes, no placeholder language, required fields including `type: procedural|reference`)
- `scripts/build-hc-config.js` — Config generator (produced `configs/help-centre.json`)
- `configs/help-centre.json` — Config with all 44 tasks (43 articles + 1 final validation)
- `scripts/tasks/help-centre.tasks` — Generated manifest (44 tasks across 9 sections)
- `scripts/tasks/prompts/hc/HC-001.md` through `HC-099.md` — 44 prompt files with curated FRD content and style rules
- `docs/frd/extracted/*.md` — 16 pre-extracted FRD documents (markdown versions of the .docx FRDs)
- `help-centre/` — Output directory with 6 category subdirectories already created:
  - `getting-started/`, `submitting-claims/`, `after-submission/`, `billing-reference/`, `your-account/`, `security-compliance/`

### Task Inventory (43 articles + 1 validation = 44 tasks)

**Tier 1 — Required at launch (14 tasks):**
- HC-001 to HC-007: Getting Started (setting up profile, BA numbers, practice locations, WCB billing, delegates, submission preferences, first Thursday submission)
- HC-008 to HC-013: Submitting Claims Core (EMR import, mobile entry, manual claims, flags/suggestions overview, rules engine, advice engine)
- HC-014: How the Thursday submission cycle works

**Tier 2 — Required within first month (14 tasks):**
- HC-015 to HC-016: Submitting Claims Remaining (submission preferences explained, WCB claims)
- HC-017 to HC-020: After Submission (assessment results, rejection codes, resubmitting, tracking patterns)
- HC-021 to HC-028: Your Account (subscription, billing switch, practice account, referral program, cancelling, data export, profile updates, delegates)

**Tier 3 — High-value reference content (15 tasks):**
- HC-029 to HC-038: Alberta Billing Reference (AHCIP overview, Thursday cycle, SOMB, RRNP, PCPCM, WCB billing, after-hours, explanatory codes, business arrangements, H-Link)
- HC-039 to HC-043: Security & Compliance (data protection, HIA/IMA, Canadian residency, delegate separation, admin boundaries)

**Final:** HC-099: Cross-link validation + existence check for all 43 articles

## How to Run

```bash
cd /home/developer/Desktop/projects/meritum
./scripts/task-runner.sh scripts/tasks/help-centre.tasks
```

To resume after interruption:
```bash
./scripts/task-runner.sh scripts/tasks/help-centre.tasks --resume
```

Each task invokes `claude -p` with the prompt from `scripts/tasks/prompts/hc/HC-XXX.md`, then runs `node scripts/validate-article.js` on the output file. Failed tasks retry twice before prompting to continue or abort.

## Your Job

1. Run the pipeline with the command above.
2. Monitor for failures. If a task fails all retries, diagnose the issue.
3. Common failure modes:
   - **Word count out of range** — article too short or too long for its type (procedural: 300-600, reference: 600-1000)
   - **Missing front matter field** — the `type` field (`procedural` or `reference`) is required but non-standard; ensure it is present
   - **Em dash detected** — content brief forbids em dashes (U+2014 and `--` as em dash); the validator catches these
   - **Placeholder language** — content brief forbids "coming soon", "TBD", "to be determined", "placeholder", "more details to follow"
4. If a task repeatedly fails, read the prompt file (`scripts/tasks/prompts/hc/HC-XXX.md`) and the validation error from the log (`logs/build/help-centre-{timestamp}/HC-XXX-verify-attempt*.log`), then either fix the article manually or adjust the prompt and re-run.
5. After all 43 article tasks pass, HC-099 runs a final cross-link validation.

## Project Reference Files

The following two files define the project conventions and context. They are automatically loaded by Claude Code via CLAUDE.md, but are included here for your reference so you understand the project you are generating content for.

<details>
<summary>CLAUDE.md (coding conventions, project structure, security rules)</summary>

The CLAUDE.md is at the project root and is automatically loaded. Key points relevant to help centre content generation:

- When invoked by the task runner (prompt starts with `[TASK]`): do not ask questions, make reasonable decisions, output `[TASK_COMPLETE]` when done
- If tests fail after 5 fix attempts, output `[TASK_BLOCKED] reason: <description>`
- The task runner prepends a code-focused preamble about Fastify/Drizzle/security; this is irrelevant for content tasks but harmless — follow the article-writing instructions in the prompt itself

</details>

<details>
<summary>PROJECT_CONTEXT.md (business overview, domain summaries, architecture)</summary>

Key facts for content accuracy:

- **Product:** Meritum Health Technologies — self-serve billing platform for Alberta physicians
- **Payers:** AHCIP (Alberta Health Care Insurance Plan, ~95% volume) and WCB Alberta (~5% volume)
- **Users:** Rural GPs and specialists; billing delegates
- **Pricing:** $279/month standard, $2,790/year (~17% savings), $199/month early bird (first 100 physicians, 12 months)
- **Regulatory:** Health Information Act (Alberta), IMA required per physician, Canadian data residency (DigitalOcean Toronto)
- **AHCIP cycle:** Weekly Thursday submission via H-Link, Friday assessments
- **WCB:** 8 form types, timing-based fee tiers (same-day highest, 15+ days lowest)
- **Intelligence:** Rules engine (deterministic, ~105 rules) + Advice engine (self-hosted LLM, suggestions only, never auto-modifies)
- **PCPCM:** Dual-BA arrangement, in-basket codes route to PCPCM BA, out-of-basket to FFS BA
- **RRNP:** Premium 7-30%+ based on community code
- **Auth:** Mandatory TOTP MFA, 24h absolute / 60min idle session expiry
- **Delegates:** Configurable permissions per physician-delegate pair, context switching explicit and logged

</details>

## Content Brief Summary (from docs/meritum-help-centre-prompt-v2.docx)

The help centre content brief specifies:

### Voice & Style
- Lead with the answer. First sentence resolves the question.
- Numbered steps for procedural content; paragraphs for conceptual.
- 300-600 words procedural, 600-1000 words reference.
- Use platform terminology exactly ("submission preferences" not "submission settings").
- "physician" not "doctor" or "provider".
- Spell out abbreviations on first use per article.
- No em dashes. No placeholder language. No marketing language.
- No copyrighted rate tables. Reference and link to official sources.
- Write like a knowledgeable colleague, not a chatbot.

### Front Matter Schema (every article)
```yaml
---
title: "Article Title"
category: getting-started | submitting-claims | after-submission | billing-reference | your-account | security-compliance
slug: article-slug
description: "Brief description for search and index page."
priority: 1 | 2 | 3
last_reviewed: 2026-02-25
review_cycle: quarterly | annual | on-change
type: procedural | reference
---
```

### Review Cycles
- **on-change:** Categories 1-2 (mirror platform UI, update when UI changes)
- **quarterly:** Category 4 (reference rates, codes, eligibility criteria)
- **annual:** Categories 5-6 (account management, security/compliance)

### Blocked Articles
- PCPCM reconciliation (Category 3) — blocked, no FRD available. Do NOT generate.

## Validation Script Reference

`scripts/validate-article.js` checks:
1. File exists and is non-empty
2. Starts with `---` (YAML front matter)
3. All required fields present: title, category, slug, description, priority, last_reviewed, review_cycle, type
4. Category is valid (6 allowed values)
5. Priority is 1, 2, or 3
6. Review cycle is quarterly, annual, or on-change
7. No em dashes (U+2014 or `--` as em dash)
8. No placeholder language (coming soon, TBD, placeholder, etc.)
9. Word count in range for article type (procedural: 300-600, reference: 600-1000)
10. Body is not empty after front matter

Does NOT check (deferred to HC-099): cross-link targets exist, abbreviation expansion, subjective quality.
