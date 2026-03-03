# Fee Navigator Scraper — Continuation Context

Use this file to resume work in a new conversation. Paste the relevant sections below as your opening prompt.

---

## Continuation Prompt

I'm continuing work on the AMA Fee Navigator scraper & enrichment pipeline V2 fixes for the Meritum project. The V1 pipeline (18 tasks, SCR-001 through SCR-070) is complete and committed. The V2 review found 33 additional issues organized into 26 tasks (SCR-110 through SCR-180) across 8 phases. All orchestration artifacts (FRD, config JSON, task manifest, prompt files) have been created. I need to execute the V2 pipeline now.

### Project Structure
- Monorepo at `/workspace/projects` (pnpm + turbo)
- API: `apps/api/` (Fastify + Drizzle ORM + PostgreSQL)
- Shared schemas: `packages/shared/src/schemas/db/reference.schema.ts`
- Scraper: `scripts/scrape-fee-navigator.ts` (TypeScript + cheerio)
- Enrichment: `scripts/enrich-hsc-data.ts` (TypeScript + cheerio)
- Exploration: `scripts/explore-fee-navigator.ts` (TypeScript + Playwright)
- Shared utilities: `scripts/lib/fee-navigator-utils.ts`
- Validation: `scripts/validate-fee-navigator-data.ts`
- Scraped data: `scripts/data/fee-navigator/`
- Seed script: `apps/api/src/seed.ts`
- Run tsx via: `./apps/api/node_modules/.bin/tsx`

### Current Data (2026-03-03, post-V1-pipeline)

| File | Records |
|------|---------|
| `hsc-codes.json` | 3,089 HSC codes |
| `hsc-modifiers.json` | 41,328 per-code modifier rows (4,955 duplicates) |
| `modifiers.json` | 42 modifier definitions |
| `governing-rules.json` | 19 governing rules |
| `explanatory-codes.json` | 123 explanatory codes |

**Current Enrichment Results (pre-V2 baseline):**
- 3,089 codes with category (100%)
- 332 codes with requiresReferral=true
- 115 codes with specialty restrictions (58 garbage fragment values)
- 135 codes with bundling exclusions (318 additional codes with notes missed)
- 27 facility designations (14 in-office, 13 out-of-office)
- 23 age restrictions (~216 additional missed by regex gaps)
- 21 frequency restrictions (~41 additional missed)
- 174 codes with billingTips, 100 with commonTerms
- 0 duplicates in HSC codes, 0 validation errors

### V2 Pipeline Overview (26 Tasks, 8 Phases)

**Phase 1 — Enrichment Regex Fixes (SCR-110, SCR-111, SCR-112):**
- SCR-110: Fix `extractHscCodesFromText` — space-aware regex, `match.index` context fix, letter-prefix codes
- SCR-111: Fix `extractAgeRestriction` — add "under X years" pattern, fix anesthesia regex, remove compound dead code
- SCR-112: Fix `extractFrequencyLimit` — "once every N years", "per shift", compound patterns

**Phase 2 — Enrichment Coverage Expansion (SCR-120, SCR-121):**
- SCR-120: Fix specialty extraction — colon-delimited lists, semicolons, "those" filter
- SCR-121: Fix GR 1.33 `codePattern` — allow codes without alpha suffix

**Phase 3 — Scraper Safety & Robustness (SCR-130, SCR-131, SCR-132, SCR-133):**
- SCR-130: Discovery cache invalidation (`--force-discovery` flag + 7-day staleness)
- SCR-131: Circuit breaker (20 consecutive errors → abort)
- SCR-132: Dynamic governing rule top-level discovery (replace hardcoded 1–19)
- SCR-133: Fix metadata `rootSectionKeys: 0` → actual count

**Phase 4 — Shared Utilities Hardening (SCR-140, SCR-141, SCR-142):**
- SCR-140: Fix `fetchWithRetry` timeout to cover body transfer (move `clearTimeout` after `resp.text()`)
- SCR-141: Add named HTML entity decoding (`&nbsp;`, `&ndash;`, `&mdash;`, smart quotes)
- SCR-142: Extend `validateResponse` check window (2000→5000 chars) + new indicators

**Phase 5 — Seed & Schema Fixes (SCR-150 through SCR-155):**
- SCR-150: Deduplicate modifier rows in scraper + add `calls` to unique index
- SCR-151: Fix `m.calls || null` → explicit `=== ''` check
- SCR-152: Map explanatory code category to severity (not hardcoded 'INFO')
- SCR-153: Filter self-referencing bundling pairs + fix description direction
- SCR-154: Wrap all seed inserts in transaction
- SCR-155: Widen `action` varchar(30) → varchar(50)

**Phase 6 — Validation Hardening (SCR-160 through SCR-163):**
- SCR-160: Tighten completeness thresholds
- SCR-161: Add modifier row dedup check
- SCR-162: Replace unconditional `pass()` with minimum thresholds
- SCR-163: Add GR reference resolution cross-check

**Phase 7 — Data Quality & Cleanup (SCR-170, SCR-171, SCR-172):**
- SCR-170: Normalize specialty restrictions (filter garbage fragments)
- SCR-171: Clean modifier descriptions (remove AMA footer)
- SCR-172: Visit-codes-without-modifiers audit

**Phase 8 — Re-scrape & Verify (SCR-180):**
- Full pipeline re-run with `--force-discovery` and verify improvements

### Orchestration Artifacts (all created)

| Artifact | Path |
|----------|------|
| **V2 FRD** | `docs/frd/Meritum_Fee_Navigator_Pipeline_V2_FRD.md` |
| **Config JSON** | `configs/scraper-pipeline-v2-manifests.json` |
| **Task manifest** | `scripts/tasks/scraper-pipeline-v2.tasks` (26 tasks) |
| **Prompt files** | `scripts/tasks/prompts/scr-v2/SCR-*.md` (26 files) |
| **V1 FRD** | `docs/frd/Meritum_Fee_Navigator_Pipeline_FRD.md` (939 lines) |
| **V1 manifest** | `scripts/tasks/scraper-pipeline.tasks` (18 tasks — all complete) |

### Key Files to Modify (V2)

| File | Tasks |
|------|-------|
| `scripts/enrich-hsc-data.ts` | SCR-110, 111, 112, 120, 121, 170 |
| `scripts/scrape-fee-navigator.ts` | SCR-130, 131, 132, 133, 150, 171 |
| `scripts/lib/fee-navigator-utils.ts` | SCR-140, 141, 142 |
| `scripts/validate-fee-navigator-data.ts` | SCR-160, 161, 162, 163, 172 |
| `packages/shared/src/schemas/db/reference.schema.ts` | SCR-150, 155 |
| `apps/api/src/seed.ts` | SCR-151, 152, 153, 154 |

### Key Function Locations (current line numbers)

**`scripts/enrich-hsc-data.ts`:**
- `extractSpecialtyRestrictions` — line 88
- `extractBundlingExclusions` — line 120
- `extractHscCodesFromText` — line 163
- `AGE_PATTERNS` — line 187
- `extractAgeRestriction` — line 203
- Compound age dead code — lines 227–241
- `extractFrequencyLimit` — line 254
- `freqPattern` — line 291
- `extractAnesthesiaRequirement` — line 314
- `parseGR448` — line 324
- `parseGR133` — line 382
- GR 1.33 `codePattern` — line 407

**`scripts/scrape-fee-navigator.ts`:**
- `discoverAllHscCodes` cache check — line 289
- `scrapeHscCodes` main loop — line 554
- Error handling in loop — lines 597–602
- `parseModifierPage` — line 619
- `scrapeGoverningRules` hardcoded range — line 774
- `metadata.rootSectionKeys: 0` — line 1021

**`scripts/lib/fee-navigator-utils.ts`:**
- `validateResponse` — line 33
- `fetchWithRetry` — line 59
- `clearTimeout(timer)` too early — line 74
- `decodeHtmlEntities` — line 109

**`apps/api/src/seed.ts`:**
- `m.calls || null` — line 828
- Explanatory code severity hardcode — lines 927–934
- Bundling pairs loop — lines 938–978

### Drizzle Schema (key tables, current state)

- `hsc_codes`: hscCode(10), description(text), baseFee(decimal 10,2), feeType(20), **category(100)**, specialtyRestrictions(jsonb[]), facilityRestrictions(jsonb[]), maxPerDay(int), maxPerVisit(int), requiresReferral(bool), selfReferralBlocked(bool), modifierEligibility(jsonb[]), surchargeEligible(bool), governingRuleReferences(jsonb[]), ageRestriction(jsonb), frequencyRestriction(jsonb), requiresAnesthesia(bool), pcpcmBasket(20), shadowBillingEligible(bool), facilityDesignation(20), notes(text), helpText(text), **billingTips(text)**, **commonTerms(jsonb string[])**, versionId(uuid FK), effectiveFrom(date), effectiveTo(date)
- `hsc_modifier_eligibility`: hscCode(10), modifierType(10), subCode(20), calls(20), explicit(bool), action(30), amount(20), versionId(uuid FK), effectiveFrom(date) — **unique on (hscCode, modifierType, subCode, versionId) — needs `calls` added**
- `modifier_definitions`: modifierCode(10), name(100), description(text), type(20), calculationMethod(20), calculationParams(jsonb), applicableHscFilter(jsonb), combinableWith(jsonb[]), exclusiveWith(jsonb[]), governingRuleReference(20), versionId(uuid FK)
- `governing_rules`: ruleId(20), ruleName(200), ruleCategory(30), description(text), ruleLogic(jsonb), severity(10), errorMessage(text), sourceReference(100), sourceUrl(text), versionId(uuid FK)
- `explanatory_codes`: explCode(10), description(text), severity(10), commonCause(text), suggestedAction(text), helpText(text), versionId(uuid FK)
- `bundling_rules`: codeA(10), codeB(10), relationship(30), description(text), overrideAllowed(bool), sourceReference(100), isActive(bool) — **unique on (codeA, codeB)**

### Quick Commands

```bash
cd /workspace/projects

# Run V2 task runner
./task-runner.sh scripts/tasks/scraper-pipeline-v2.tasks

# Or run individual tasks
./task-runner.sh scripts/tasks/scraper-pipeline-v2.tasks --only=SCR-110

# Run validation standalone
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts

# Build shared package
pnpm --filter shared build

# Run reference tests (199 tests)
pnpm --filter api vitest run src/domains/reference/reference.test.ts

# Re-scrape (includes post-scrape validation)
./apps/api/node_modules/.bin/tsx scripts/scrape-fee-navigator.ts --force-discovery

# Re-enrich (includes post-enrichment validation)
./apps/api/node_modules/.bin/tsx scripts/enrich-hsc-data.ts

# Data integrity check
./apps/api/node_modules/.bin/tsx -e '
import fs from "node:fs";
const hsc = JSON.parse(fs.readFileSync("scripts/data/fee-navigator/hsc-codes.json","utf-8"));
const mods = JSON.parse(fs.readFileSync("scripts/data/fee-navigator/hsc-modifiers.json","utf-8"));
console.log("HSC codes:", hsc.length);
console.log("Modifier rows:", mods.length);
console.log("Modifier row dupes:", mods.length - new Set(mods.map((m:any) => `${m.hscCode}|${m.type}|${m.code}|${m.calls}`)).size);
console.log("With referral:", hsc.filter((h:any) => h.requiresReferral).length);
console.log("With bundling:", hsc.filter((h:any) => h.bundlingExclusions?.length > 0).length);
console.log("With specialty:", hsc.filter((h:any) => h.specialtyRestrictions?.length > 0).length);
console.log("With age:", hsc.filter((h:any) => h.ageRestriction).length);
console.log("With frequency:", hsc.filter((h:any) => h.frequencyRestriction).length);
console.log("With category:", hsc.filter((h:any) => h.category).length);
console.log("With billingTips:", hsc.filter((h:any) => h.billingTips).length);
console.log("With commonTerms:", hsc.filter((h:any) => h.commonTerms?.length > 0).length);
console.log("Duplicates:", hsc.length - new Set(hsc.map((h:any) => h.hscCode)).size);
'
```

### V1 Pipeline Summary (Complete)

All 18 V1 tasks (SCR-001 through SCR-070) have been committed. See `docs/frd/Meritum_Fee_Navigator_Pipeline_FRD.md` for V1 details.

### V2 Expected Improvements

After all 26 V2 tasks are complete:
- Bundling exclusions: 135 → 300+ codes
- Age restrictions: 23 → 50+ codes
- Frequency restrictions: 21 → 40+ codes
- Specialty restrictions: 115 → 115+ (garbage fragments filtered, possible count increase)
- Modifier row duplicates: 4,955 → 0
- Validation errors: 0
- Explanatory code severity: 3 distinct values (not all 'INFO')
- Metadata rootSectionKeys: actual count (not 0)

### Git Commits (newest first)

```
<latest>  Pipeline V1: 18 scraper/enrichment fixes (SCR-001 through SCR-070)
7f48c5f   Update tests for enrichment fields and facilityDesignation
5428891   Expose enrichment fields in seed mapping and API responses
a405240   Add enrichment script, fix specialty regex, and re-scrape data
642dfb0   Add facilityDesignation column and export hscModifierEligibility table
38196dd   Fix data quality issues: fee type mapping, surcharge detection, governing rules
175ee57   Add AMA Fee Navigator scraper, seed data, web app scaffolding, and project docs
```

### Why This Matters

The fee calculation engine (`apps/api/src/domains/ahcip/ahcip.service.ts`, `computeFeeBreakdown()` at lines 1332-1437) and 19 validation checks (A1–A19, lines 652-990) directly consume every field in the `hsc_codes` table. Incorrect scraped data means incorrect fee calculations, claim rejections, overpayment, or compliance violations across ~350,000 annual AHCIP claims.
