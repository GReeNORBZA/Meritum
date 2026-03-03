# Fee Navigator Pipeline — V2 Continuation Prompt

Paste everything below the line into a new Claude Code chat to continue the pipeline work.

---

## Prompt

I'm continuing the Fee Navigator pipeline work for the Meritum project. The enrichment pipeline loop has **converged** — all extraction targets are met or exceeded. The next phase is completing the remaining V2 FRD tasks (scraper safety, seed fixes, validation hardening, data cleanup) and then re-scraping to produce production-ready reference data.

### Project Location

- Monorepo: `/workspace/projects`
- tsx: `./apps/api/node_modules/.bin/tsx`

### Where We Left Off (2026-03-03, post-V3 enrichment)

The enrichment improvement loop ran 5 iterations and converged. Here are the final metrics:

| Dimension | Start (V2) | Final (V3) | Target | Status |
|-----------|------------|------------|--------|--------|
| bundlingExclusions | 218 | **360** | 350 | Exceeded |
| ageRestriction | 28 | **242** | 50 | Exceeded |
| frequencyRestriction | 34 | **55** | 40 | Exceeded |
| specialtyRestrictions | 104 | **119** | 120 | -1 (no more extractable patterns) |
| requiresReferral | 45 | **47** | 50 | -3 (remaining are audit false positives) |
| requiresAnesthesia | 12 | **21** | 15 | Exceeded |
| maxPerDay | 5 | **19** | 10 | Exceeded |
| **Total gap** | **189** | **4** | 0 | **97.9% closed** |

### V2 FRD Task Status

The V2 FRD (`docs/frd/Meritum_Fee_Navigator_Pipeline_V2_FRD.md`) defines 24 tasks (SCR-110 through SCR-180) across 8 phases. The enrichment loop addressed Phase 1 and Phase 2 tasks. Here's what's done vs. remaining:

#### DONE (completed by V3 enrichment loop)

| Task | Description | How It Was Resolved |
|------|-------------|---------------------|
| SCR-110 | Fix HSC code extraction from text | V1 already fixed (space-tolerant regex, letter-prefix codes); V3 confirmed working |
| SCR-111 | Fix age restriction extraction | V3 added `and\s+younger`, `up to X years`, `age X to Y years` → 28 → 242 |
| SCR-112 | Fix frequency/anesthesia extraction | V3 added word-form numbers (one→twenty), `anesthetic` variant → freq 34→55, maxPerDay 5→19, anesthesia 12→21 |
| SCR-120 | Fix specialty restriction extraction | V3 added AACC/UCC/ICU/ED location extraction, `payable only to`, CPSA-approved, `physicians with X specialty`, colon-delimited list parsing → 104→119 |
| SCR-121 | Fix GR 1.33 numeric-only codes | V1 already fixed (`{0,3}` suffix allows zero alpha chars) |

#### REMAINING (need to be done)

| Phase | Task | Description | Priority | Complexity |
|-------|------|-------------|----------|------------|
| 3 | SCR-130 | Add discovery cache invalidation on re-scrape | P0 | Low |
| 3 | SCR-131 | Add circuit breaker on mass scrape failure (50+ consecutive errors → stop) | P1 | Medium |
| 3 | SCR-132 | Fix governing rule range detection (dynamic, not hardcoded 1–19) | P1 | Low |
| 3 | SCR-133 | Fix metadata `rootSectionKeys` tracking (always reports 0) | P1 | Low |
| 4 | SCR-140 | Fix `fetchWithRetry` body timeout (AbortController for response body) | P1 | Medium |
| 4 | SCR-141 | Decode HTML named entities (`&nbsp;`, `&ndash;`, `&mdash;`, `&rsquo;`, `&lsquo;`) | P3 | Low |
| 4 | SCR-142 | Improve `validateResponse` block detection (check full body, not first 2000 chars) | P3 | Low |
| 5 | **SCR-150** | **Fix modifier eligibility deduplication (add `calls` to unique index)** | **P0** | **Medium** |
| 5 | SCR-151 | Fix `m.calls \|\| null` falsy check (use explicit `=== ''`) | P2 | Low |
| 5 | **SCR-152** | **Fix explanatory code `category` field dropped by seed** | **P1** | **Low** |
| 5 | SCR-153 | Filter self-referencing bundling pairs (codeA === codeB) + fix description direction | P2 | Low |
| 5 | **SCR-154** | **Wrap seed inserts in transaction** | **P2** | **Medium** |
| 5 | SCR-155 | Widen `action` varchar(30) margin in schema | P3 | Low |
| 6 | SCR-160 | Tighten validation completeness thresholds (HSC ≥ 3050, modifiers ≥ 40000) | P3 | Low |
| 6 | SCR-161 | Add modifier row deduplication check to validation | P3 | Low |
| 6 | SCR-162 | Make enrichment stats validate against minimums (not unconditional pass) | P3 | Low |
| 6 | SCR-163 | Add GR reference resolution check to validation | P3 | Low |
| 7 | SCR-170 | Normalize specialty restrictions (filter 58 garbage fragment values) | P1 | Low |
| 7 | SCR-171 | Clean modifier descriptions (remove AMA footer text) | P3 | Low |
| 7 | SCR-172 | Verify 65 visit-type codes with zero modifiers (scraping gap or expected?) | P3 | Low |
| 8 | **SCR-180** | **Re-scrape & verify with all fixes applied** | **P0** | **High** |

### What To Do

Work through the remaining V2 tasks in priority order. The critical path is:

```bash
cd /workspace/projects

# Step 0: Review current state
./apps/api/node_modules/.bin/tsx scripts/audit-fee-navigator.ts --metrics-only
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts

# Step 1: Read the V2 FRD for task details
# docs/frd/Meritum_Fee_Navigator_Pipeline_V2_FRD.md

# Step 2: Work through tasks in dependency order
# Phase 3 (scraper safety) → Phase 4 (utils) → Phase 5 (seed) → Phase 6 (validation) → Phase 7 (cleanup) → Phase 8 (re-scrape)

# Step 3: After all fixes, re-scrape
./apps/api/node_modules/.bin/tsx scripts/scrape-fee-navigator.ts

# Step 4: Re-enrich
./apps/api/node_modules/.bin/tsx scripts/enrich-hsc-data.ts

# Step 5: Validate
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts

# Step 6: Verify seed runs without errors (if DB is available)
# ./apps/api/node_modules/.bin/tsx apps/api/src/seed.ts
```

### Critical Path Tasks (Do First)

1. **SCR-150**: Fix modifier eligibility deduplication — the seed CRASHES without this. Add `calls` column to the unique composite index on `hsc_modifier_eligibility` table in `packages/shared/src/schemas/db/reference.schema.ts`. Then deduplicate the 4,955 rows that share all columns except `calls`.

2. **SCR-154**: Wrap seed inserts in a transaction — partial seed on crash leaves DB inconsistent.

3. **SCR-152**: Fix explanatory code `category` field — seed currently drops the `category` value scraped from Fee Navigator and hardcodes `severity: 'INFO'`.

4. **SCR-130**: Invalidate discovery cache on re-scrape — without this, re-scraping reuses the old code list silently.

5. **SCR-131**: Add circuit breaker — without this, 50+ consecutive failures just keep hammering the server.

6. **SCR-180**: Re-scrape with all fixes applied — this must be last.

### Key File Locations

| File | Purpose |
|------|---------|
| `docs/frd/Meritum_Fee_Navigator_Pipeline_V2_FRD.md` | Full V2 FRD with task specs and code samples |
| `configs/scraper-pipeline-v2-manifests.json` | Task runner config for V2 tasks |
| `scripts/scrape-fee-navigator.ts` | Main scraper script |
| `scripts/enrich-hsc-data.ts` | Enrichment script (extraction patterns) |
| `scripts/validate-fee-navigator-data.ts` | Validation script |
| `scripts/audit-fee-navigator.ts` | Audit script (gap analysis) |
| `scripts/lib/fee-navigator-utils.ts` | Shared utilities (fetchWithRetry, decodeHtmlEntities) |
| `scripts/data/fee-navigator/` | All scraped/enriched JSON data |
| `packages/shared/src/schemas/db/reference.schema.ts` | Drizzle schema for reference data tables |
| `apps/api/src/seed.ts` | Seed script that imports JSON into database |
| `apps/api/src/domains/reference/` | Domain 2 implementation (service, repository, handlers, routes) |

### Task Runner

You can use the task runner for V2 tasks:

```bash
# Run all V2 tasks
./task-runner.sh scripts/tasks/scraper-pipeline-v2.tasks

# Run a single task
./task-runner.sh scripts/tasks/scraper-pipeline-v2.tasks --only=SCR-150

# Resume after last completed
./task-runner.sh scripts/tasks/scraper-pipeline-v2.tasks --resume
```

### Important Context

- The enrichment script fetches 2 live pages from `apps.albertadoctors.org` (GR 4 for referrals, GR 1 for facility). This takes ~30-45 seconds and requires network access.
- The scraper fetches individual HSC code pages from `apps.albertadoctors.org/fee-navigator/hsc/`. Full scrape takes 30-60 minutes.
- Notes text uses "." directly followed by next sentence with no space. Regex patterns must handle this via `\.(?!\d)` sentence boundaries.
- "May be claimed in addition to HSC X" is POSITIVE (allowed together). Only "May NOT be claimed with" or "not payable in addition to" are exclusions.
- The seed script is idempotent — it checks for existing data and skips if found.
- The `hsc_modifier_eligibility` table has 4,955 duplicate rows that differ only in the `calls` column. SCR-150 must resolve this before seed can run.
- The specialty restriction gap of 1 and referral gap of 3 are audit measurement limits, not real extraction gaps. The audit's keyword regex matches some non-requirement contexts.
- V3 enrichment introduced category marker codes (`*VISIT`, `*PROCEDURE`, `*SURGICAL_ASSIST`, `*ANESTHETIC`, `*INCLUDED`, `*SOLE_PROCEDURE`) for generic bundling exclusions that don't reference specific HSC codes. The seed/schema should handle these gracefully.

### Enrichment V3 Changes Summary

The following extraction functions were significantly rewritten in V3 (commit `77e73bd`):

| Function | Lines | What Changed |
|----------|-------|--------------|
| `normalizeSpecialty` | ~87-110 | Added "physicians with X specialty" → extract specialty name; CPSA-approved physician handling |
| `extractSpecialtyRestrictions` | ~115-146 | Added `payable only to` trigger; location-based AACC/UCC/ICU/ED extraction; `[:\s]+` separator (handles "by:" with no space) |
| `addExclusions` (NEW) | ~148-160 | Helper function for deduped exclusion insertion |
| `extractBundlingExclusions` | ~165-350 | Complete rewrite: 17 pattern groups (A-R) using template strings; handles both "claimed" and "billed" verbs; inverted subjects; parenthetical code lists; range exclusions; temporal exclusions; generic category markers |
| `AGE_PATTERNS` | ~270-285 | Added `and\s+younger` variant; `up to X` patterns; `age X to Y years` range |
| `WORD_NUMBERS` + `parseNumberOrWord` (NEW) | ~295-310 | Word-to-digit conversion (one→twenty) for frequency extraction |
| `extractFrequencyLimit` | ~320-420 | Rewrote with word-form number support; parenthetical groups; hospitalization/weekday/weekend periods; word-number-aware "maximum of N" pattern |
| `extractAnesthesiaRequirement` | ~425-430 | Added `anesthetic` alongside `anesthesia`; `requiring sedation`; `under conscious/procedural sedation` |
| Main loop (Phase 1) | ~670-680 | Added notes-based referral detection supplement to GR 4.4.8 |
