# Fee Navigator Scraper — Continuation Context

Use this file to resume work in a new conversation. Paste the relevant sections below as your opening prompt.

---

## Continuation Prompt

I'm continuing a review of the AMA Fee Navigator scraper & enrichment pipeline for the Meritum project. All 18 pipeline fix tasks (SCR-001 through SCR-070) have been completed. I'd like to review the scraper code and data quality in this session. Here's the full context:

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

### What Exists Today

**Scraper** (`scripts/scrape-fee-navigator.ts`) — cheerio-based, no JS execution:
- Phase 1: AJAX tree expansion (`POST /fee-navigator/hsc?ajax=expanded`) with dynamic root section key discovery
- Phase 2: Detail pages (`GET /fee-navigator/hsc/{code}?ajax=detail`) parsed with cheerio
- Phase 3: Modifier pages with dynamic modifier code discovery (3 methods + fallback)
- Phase 4: Governing rules + sub-rule discovery and merging
- Phase 5: Explanatory codes (AJAX tree expansion)
- Map-based deduplication for crash-safe resume
- Post-scrape validation integrated via execSync

**Enrichment** (`scripts/enrich-hsc-data.ts`) — post-processing:
- Parses notes text with regex: specialty restrictions, bundling exclusions (sentence-bounded), age restrictions (tagged discriminated union), frequency limits, anesthesia requirements
- Fetches GR 4.4.8 for referral requirements (scoped section parsing, 332 codes)
- Fetches GR 1.33 for facility designations (text-classified set prevents Z-suffix override, 27 codes)
- Post-enrichment validation integrated via execSync

**Shared Utilities** (`scripts/lib/fee-navigator-utils.ts`):
- `fetchWithRetry` with AbortController 30s timeout, 429/503 backoff, CAPTCHA/block detection
- `decodeHtmlEntities` with full `&#NNN;`, `&#xNN;` support, `&amp;` last
- `validateResponse` for AJAX wrapper and block indicator checks
- `sleep`, `saveJson`, `loadJson`, `ensureDir`, constants

**Validation** (`scripts/validate-fee-navigator-data.ts`):
- File existence, completeness thresholds, format validation, dedup check
- Cross-file consistency (modifier hscCodes, modifier types)
- Enrichment field type validation

### Current Data (2026-03-03, post-pipeline-fix)

| File | Records |
|------|---------|
| `hsc-codes.json` | 3,089 HSC codes |
| `hsc-modifiers.json` | 41,328 per-code modifier rows |
| `modifiers.json` | 42 modifier definitions |
| `governing-rules.json` | 19 governing rules |
| `explanatory-codes.json` | 123 explanatory codes |

**Enrichment Results:**
- 3,089 codes with category (100%)
- 332 codes with requiresReferral=true
- 115 codes with specialty restrictions
- 135 codes with bundling exclusions
- 27 facility designations (14 in-office, 13 out-of-office)
- 23 age restrictions, 21 frequency restrictions
- 174 codes with billingTips, 100 with commonTerms
- 0 duplicates, 0 validation errors

**Seed** (`apps/api/src/seed.ts`) loads scraped JSON into:
- `hsc_codes` table (3,089 rows with category, billingTips, commonTerms)
- `hsc_modifier_eligibility` table (41,328 rows)
- `modifier_definitions` table (42 rows with `applicableHscFilter`)
- `governing_rules` table (19 rows)
- `explanatory_codes` table (123 rows)
- `bundling_rules` table (canonical codeA < codeB ordering)

**Tests:** 199/199 reference service tests pass.

### Pipeline Fix Summary (All 18 Tasks Complete)

**Phase 1 — Shared Infrastructure (SCR-001, SCR-002):**
- Extracted duplicated utilities into `scripts/lib/fee-navigator-utils.ts`
- AbortController 30s timeout, complete entity decoding, CAPTCHA/block detection

**Phase 2 — Scraper Correctness (SCR-010, SCR-011, SCR-012):**
- `baseFee` comma stripping: `.replace(/,/g, '')`
- Surcharge detection includes SURT sub-codes
- Map-based resume dedup (hscMap, hscModMap keyed by hscCode)
- `CATEGORY_FEE_TYPE_MAP` priority prefix lookup table + console.warn for unknowns

**Phase 3 — Dynamic Discovery (SCR-020, SCR-021, SCR-022):**
- `discoverRootSectionKeys()` replaces hardcoded 19 keys
- `discoverModifierCodes()` with 3 discovery methods + tree expansion fallback
- `discoverSubRulePages()` scans parent rules for sub-rule links, fetches and merges

**Phase 4 — Enrichment Correctness (SCR-040, SCR-041, SCR-042, SCR-043):**
- `AgePattern { tag, regex }` + switch on tag (replaces `pattern.source.includes()`)
- GR 4.4.8: regex boundary scopes to 4.4.8 section, link extraction requires "4.4.8" context
- GR 1.33: `textClassified` set prevents Z-suffix heuristic override
- Bundling: `(?:[^.]|\.(?=\d))*?` for sentence-bounded matching, context-aware HSC validation (skip `$`/"fee")

**Phase 5 — Schema Alignment (SCR-050, SCR-051, SCR-052):**
- Added `category` (varchar 100), `billingTips` (text), `commonTerms` (jsonb string[]) to hsc_codes schema
- Seed, service interface, mapping, and tests all updated
- Bundling rules seeding was already present (verified)

**Phase 6 — Validation (SCR-060, SCR-061):**
- Created `scripts/validate-fee-navigator-data.ts` with 7 check categories
- Wired into scraper and enrichment `main()` via execSync (exit code 2 on failure)

**Phase 7 — Cleanup (SCR-070):**
- Removed unused `ElementHandle` import
- Cached JSON loading in `loadScrapedCode` (avoids 9x re-parse of 2.4 MB file)
- Named handlers + `removeListener` for dialog and request event listeners

### Why This Matters

The fee calculation engine (`apps/api/src/domains/ahcip/ahcip.service.ts`, `computeFeeBreakdown()` at lines 1332-1437) and 19 validation checks (A1-A19, lines 652-990) directly consume every field in the `hsc_codes` table. Incorrect scraped data means incorrect fee calculations, claim rejections, overpayment, or compliance violations across ~350,000 annual AHCIP claims.

### Key HTML Parsing Details

- HSC detail page: `h2.code` (code), `h1.title` (description), `table.basic-info` (category + base rate + common terms), `div.modifiers table` (modifier rows: Type, Code, # of calls, Explicit, Action, Amount), `div.note` (notes), `div.billing-tips` (tips), `div.governing-rules` (rule refs)
- Tree expansion: POST to `?ajax=expanded` with `expanded={keys}&expand={key}`, returns XML with HTML-entity-encoded `<content>`
- Detail AJAX: GET `?ajax=detail` returns XML with `<content>` containing the record HTML
- Expandable nodes: `class="node expandable" data-key="{numeric}"`, Viewable: `class="node viewable" href="/fee-navigator/hsc/{code}"`

### Drizzle Schema (key tables, current state)

- `hsc_codes`: hscCode(10), description(text), baseFee(decimal 10,2), feeType(20), **category(100)**, specialtyRestrictions(jsonb[]), facilityRestrictions(jsonb[]), maxPerDay(int), maxPerVisit(int), requiresReferral(bool), selfReferralBlocked(bool), modifierEligibility(jsonb[]), surchargeEligible(bool), governingRuleReferences(jsonb[]), ageRestriction(jsonb), frequencyRestriction(jsonb), requiresAnesthesia(bool), pcpcmBasket(20), shadowBillingEligible(bool), facilityDesignation(20), notes(text), helpText(text), **billingTips(text)**, **commonTerms(jsonb string[])**, versionId(uuid FK), effectiveFrom(date), effectiveTo(date)
- `hsc_modifier_eligibility`: hscCode(10), modifierType(10), subCode(20), calls(20), explicit(bool), action(30), amount(20), versionId(uuid FK), effectiveFrom(date)
- `modifier_definitions`: modifierCode(10), name(100), description(text), type(20), calculationMethod(20), calculationParams(jsonb), applicableHscFilter(jsonb), combinableWith(jsonb[]), exclusiveWith(jsonb[]), governingRuleReference(20), versionId(uuid FK)
- `governing_rules`: ruleId(20), ruleName(200), ruleCategory(30), description(text), ruleLogic(jsonb), severity(10), errorMessage(text), sourceReference(100), sourceUrl(text), versionId(uuid FK)
- `explanatory_codes`: explCode(10), description(text), severity(10), commonCause(text), suggestedAction(text), helpText(text), versionId(uuid FK)
- `bundling_rules`: codeA(10), codeB(10), relationship(30), description(text), overrideAllowed(bool), sourceReference(100), isActive(bool) — **unique on (codeA, codeB)**

### Fields NOT Available from Fee Navigator (out of scope)

These columns exist in the schema but require external data sources (SOMB PDF, AHCIP manual, PCPCM docs):
- `referralValidityDays`, `combinationGroup`, `shadowBillingEligible`, `afterHoursEligible`, `premium351Eligible`
- `requiresDiagnosticCode`, `requiresFacility`, `minCalls`, `maxCalls`, `isTimeBased`, `minTime`, `maxTime`
- `pcpcmBasket` (from PCPCM program docs, not Fee Navigator)
- `facilityRestrictions` (from AHCIP manual, not Fee Navigator)

### Files Modified by Pipeline

| File | Status |
|------|--------|
| `scripts/lib/fee-navigator-utils.ts` | CREATED (SCR-001), modified (SCR-002) |
| `scripts/scrape-fee-navigator.ts` | Modified (SCR-010, 011, 012, 020, 021, 022, 061) |
| `scripts/enrich-hsc-data.ts` | Modified (SCR-040, 041, 042, 043, 061) |
| `scripts/validate-fee-navigator-data.ts` | CREATED (SCR-060) |
| `scripts/explore-fee-navigator.ts` | Modified (SCR-070) |
| `packages/shared/src/schemas/db/reference.schema.ts` | Modified (SCR-050, 052) |
| `apps/api/src/seed.ts` | Modified (SCR-050, 052) |
| `apps/api/src/domains/reference/reference.service.ts` | Modified (SCR-050, 052) |
| `apps/api/src/domains/reference/reference.test.ts` | Modified (SCR-050, 052) |

### Quick Commands

```bash
cd /workspace/projects

# Run validation standalone
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts

# Build shared package
pnpm --filter shared build

# Run reference tests (199 tests)
pnpm --filter api vitest run src/domains/reference/reference.test.ts

# Re-scrape (includes post-scrape validation)
./apps/api/node_modules/.bin/tsx scripts/scrape-fee-navigator.ts

# Re-enrich (includes post-enrichment validation)
./apps/api/node_modules/.bin/tsx scripts/enrich-hsc-data.ts

# Data integrity check
./apps/api/node_modules/.bin/tsx -e '
import fs from "node:fs";
const hsc = JSON.parse(fs.readFileSync("scripts/data/fee-navigator/hsc-codes.json","utf-8"));
const mods = JSON.parse(fs.readFileSync("scripts/data/fee-navigator/hsc-modifiers.json","utf-8"));
console.log("HSC codes:", hsc.length);
console.log("Modifier rows:", mods.length);
console.log("With referral:", hsc.filter((h:any) => h.requiresReferral).length);
console.log("With bundling:", hsc.filter((h:any) => h.bundlingExclusions?.length > 0).length);
console.log("With specialty:", hsc.filter((h:any) => h.specialtyRestrictions?.length > 0).length);
console.log("With age:", hsc.filter((h:any) => h.ageRestriction).length);
console.log("With category:", hsc.filter((h:any) => h.category).length);
console.log("With billingTips:", hsc.filter((h:any) => h.billingTips).length);
console.log("With commonTerms:", hsc.filter((h:any) => h.commonTerms?.length > 0).length);
console.log("Duplicates:", hsc.length - new Set(hsc.map((h:any) => h.hscCode)).size);
'
```

### FRD & Task Manifest (for reference)

- **FRD:** `docs/frd/Meritum_Fee_Navigator_Pipeline_FRD.md` (939 lines)
- **Task manifest:** `scripts/tasks/scraper-pipeline.tasks` (18 tasks, 7 phases — all complete)
- **Task prompts:** `scripts/tasks/prompts/scr/SCR-*.md` (18 files)

### Git Commits (newest first, pre-pipeline-fix)

```
7f48c5f Update tests for enrichment fields and facilityDesignation
5428891 Expose enrichment fields in seed mapping and API responses
a405240 Add enrichment script, fix specialty regex, and re-scrape data
642dfb0 Add facilityDesignation column and export hscModifierEligibility table
38196dd Fix data quality issues: fee type mapping, surcharge detection, governing rules
175ee57 Add AMA Fee Navigator scraper, seed data, web app scaffolding, and project docs
```

Note: The 18 pipeline fix tasks (SCR-001 through SCR-070) have been applied but not yet committed.
