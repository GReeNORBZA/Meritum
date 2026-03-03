# Fee Navigator Scraper — Continuation Context

Use this file to resume work in a new conversation. Paste the relevant sections below as your opening prompt.

---

## Continuation Prompt

I'm continuing work on the AMA Fee Navigator scraper & enrichment pipeline for the Meritum project. V1 (18 tasks, SCR-001 through SCR-070) and V2 (26 tasks, SCR-110 through SCR-180) are both complete and committed. I need you to re-audit the pipeline, identify remaining issues, and develop a V3 improvement plan.

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

### Current Data (2026-03-03, post-V2-pipeline)

| Metric | V1 Baseline | Post-V2 |
|--------|-------------|---------|
| HSC codes | 3,089 | 3,089 |
| Modifier rows | 41,328 | 41,328 |
| Modifier row dupes | 0 | 0 |
| Bundling exclusions | 135 | 218 (+61%) |
| Age restrictions | 23 | 28 (+22%) |
| Frequency restrictions | 21 | 29 (+38%) |
| Requires anesthesia | 0 | 12 (new) |
| Specialty restrictions | 115 | 104 (garbage filtered) |
| Requires referral | 332 | 45 (live GR 4.4.8 change) |
| Facility designation | 27 | 27 |
| Category | 3,089 | 3,089 |
| Billing tips | 174 | 174 |
| Common terms | 100 | 100 |
| Validation errors | 0 | 0 |
| Reference tests | 199 pass | 199 pass |

### Known Issues / Areas for V3 Investigation

1. **Referral count regression (332 → 45):** The live GR 4.4.8 page returns different content than the original cached scrape. The `parseGR448` function now only finds 48 codes in the section text. Investigate whether:
   - The original 332 came from individual HSC code notes rather than GR 4.4.8
   - The GR 4 AJAX endpoint returns a truncated section
   - A full-page fetch (non-AJAX) gets more content
   - Individual code notes contain "referral required" patterns that should be extracted separately

2. **Bundling exclusions still below target (218 vs 300+ target):** V2 FRD targeted 300+. The regex improvements helped but there may be additional patterns in notes text:
   - "not to be used with", "exclusive of", "includes", "in lieu of"
   - Governing rule-based bundling (e.g., GR 6 combination rules)
   - Cross-reference table patterns in GR pages

3. **Specialty restrictions dropped (115 → 104):** The normalization filter removed garbage fragments but may have been too aggressive. Audit the filtered values to ensure no legitimate specialties were removed.

4. **Age/frequency still below V2 FRD targets:** Age (28 vs 50+ target), frequency (29 vs 40+ target). Investigate:
   - "patients under X" patterns where number precedes "years" keyword
   - "pediatric" / "geriatric" as implicit age restrictions
   - "per admission", "per encounter" as frequency patterns
   - Governing rule-based restrictions that aren't in individual code notes

5. **No full re-scrape was performed:** V2 only re-ran enrichment on existing data. A full re-scrape with `--force-discovery` would:
   - Apply the deduplication logic to freshly scraped modifier rows
   - Apply the modifier description cleanup
   - Update governing rules with dynamic discovery
   - Capture any new codes added to Fee Navigator since last scrape

6. **maxPerVisit count is 0:** The `perVisitMatch` regex may not be matching any patterns. Audit notes text for visit-limit patterns.

7. **Explore script not utilized:** `scripts/explore-fee-navigator.ts` uses Playwright for browser-based exploration. It could be used to:
   - Verify AJAX vs full-page content differences
   - Discover additional data in JavaScript-rendered sections
   - Audit the GR 4.4.8 section visually

### Key Files (current state post-V2)

| File | Description |
|------|-------------|
| `scripts/enrich-hsc-data.ts` | Enrichment with V2 regex fixes, specialty normalization |
| `scripts/scrape-fee-navigator.ts` | Scraper with circuit breaker, cache staleness, dynamic GR discovery, modifier dedup |
| `scripts/lib/fee-navigator-utils.ts` | Shared utils with body-timeout fix, entity decoding, extended block detection |
| `scripts/validate-fee-navigator-data.ts` | Validation with enrichment minimums, dedup check, GR cross-ref, visit audit |
| `packages/shared/src/schemas/db/reference.schema.ts` | Schema with widened action varchar, updated unique index |
| `apps/api/src/seed.ts` | Seed with transaction wrapping, severity mapping, self-ref filtering |

### Key Function Locations

**`scripts/enrich-hsc-data.ts`:**
- `normalizeSpecialty` — line ~84
- `extractSpecialtyRestrictions` — line ~102
- `extractBundlingExclusions` — line ~134
- `extractHscCodesFromText` — line ~177 (V2: space-aware, letter-prefix, match.index)
- `AGE_PATTERNS` — line ~201 (V2: added "under X years" patterns)
- `extractAgeRestriction` — line ~218
- `extractFrequencyLimit` — line ~233 (V2: shift/session/admission, "once every N")
- `extractAnesthesiaRequirement` — line ~299 (V2: widened regex)
- `parseGR448` — line ~309
- `parseGR133` — line ~367
- GR 1.33 `codePattern` — line ~402 (V2: allows codes without alpha suffix)

**`scripts/scrape-fee-navigator.ts`:**
- `FORCE_DISCOVERY`, `CACHE_MAX_AGE_MS`, `CIRCUIT_BREAKER_THRESHOLD` — line ~29
- `deduplicateModifierRows` — line ~378
- `discoverAllHscCodes` — returns `{ codes, rootSectionKeyCount }` — line ~301
- `scrapeHscCodes` — circuit breaker loop — line ~540
- `discoverTopLevelRuleIds` — dynamic GR discovery — line ~784
- `scrapeGoverningRules` — uses dynamic IDs — line ~819
- `parseModifierPage` — AMA footer cleanup — line ~663
- metadata `rootSectionKeys` — uses actual count — line ~1060

### V1 + V2 Pipeline Summary

| Pipeline | Tasks | Commit |
|----------|-------|--------|
| V1 | SCR-001 through SCR-070 (18 tasks) | `4909806` |
| V2 | SCR-110 through SCR-180 (26 tasks) | `0c1e03d` |

### Orchestration Artifacts

| Artifact | Path |
|----------|------|
| V1 FRD | `docs/frd/Meritum_Fee_Navigator_Pipeline_FRD.md` |
| V2 FRD | `docs/frd/Meritum_Fee_Navigator_Pipeline_V2_FRD.md` |
| V2 Config | `configs/scraper-pipeline-v2-manifests.json` |
| V2 Manifest | `scripts/tasks/scraper-pipeline-v2.tasks` |
| V2 Prompts | `scripts/tasks/prompts/scr-v2/SCR-*.md` |

### Quick Commands

```bash
cd /workspace/projects

# Data integrity check
./apps/api/node_modules/.bin/tsx -e '
import fs from "node:fs";
const hsc = JSON.parse(fs.readFileSync("scripts/data/fee-navigator/hsc-codes.json","utf-8"));
const mods = JSON.parse(fs.readFileSync("scripts/data/fee-navigator/hsc-modifiers.json","utf-8"));
console.log("HSC codes:", hsc.length);
console.log("Modifier rows:", mods.length);
console.log("Modifier row dupes:", mods.length - new Set(mods.map((m) => `${m.hscCode}|${m.type}|${m.code}|${m.calls}`)).size);
console.log("With referral:", hsc.filter((h) => h.requiresReferral).length);
console.log("With bundling:", hsc.filter((h) => h.bundlingExclusions?.length > 0).length);
console.log("With specialty:", hsc.filter((h) => h.specialtyRestrictions?.length > 0).length);
console.log("With age:", hsc.filter((h) => h.ageRestriction).length);
console.log("With frequency:", hsc.filter((h) => h.frequencyRestriction).length);
console.log("With anesthesia:", hsc.filter((h) => h.requiresAnesthesia).length);
console.log("With category:", hsc.filter((h) => h.category).length);
console.log("With billingTips:", hsc.filter((h) => h.billingTips).length);
console.log("With commonTerms:", hsc.filter((h) => h.commonTerms?.length > 0).length);
console.log("MaxPerDay:", hsc.filter((h) => h.maxPerDay !== null && h.maxPerDay !== undefined).length);
console.log("MaxPerVisit:", hsc.filter((h) => h.maxPerVisit !== null && h.maxPerVisit !== undefined).length);
console.log("Duplicates:", hsc.length - new Set(hsc.map((h) => h.hscCode)).size);
'

# Run validation
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts

# Run enrichment (fetches 2 GR pages from live site)
./apps/api/node_modules/.bin/tsx scripts/enrich-hsc-data.ts

# Full re-scrape (3,089 codes — takes ~20-30 minutes)
./apps/api/node_modules/.bin/tsx scripts/scrape-fee-navigator.ts --force-discovery

# Build shared package
pnpm --filter shared build

# Run reference tests (199 tests)
pnpm --filter api vitest run src/domains/reference/reference.test.ts

# Audit notes text for specific patterns (example: find "referral" patterns)
./apps/api/node_modules/.bin/tsx -e '
import fs from "node:fs";
const hsc = JSON.parse(fs.readFileSync("scripts/data/fee-navigator/hsc-codes.json","utf-8"));
const matches = hsc.filter(h => h.notes && /referral/i.test(h.notes));
console.log(`${matches.length} codes mention "referral" in notes`);
for (const m of matches.slice(0, 10)) {
  const snippet = m.notes.match(/.{0,60}referral.{0,60}/i)?.[0] ?? "";
  console.log(`  ${m.hscCode}: ...${snippet}...`);
}
'
```

### Approach for V3

1. **Audit first:** Read the current source files and data to identify all remaining gaps.
2. **Sample notes text:** Look at actual notes for codes missing enrichment fields to find patterns the regexes miss.
3. **Compare GR page content:** Fetch GR 4 full page vs AJAX to understand the referral regression.
4. **Draft V3 task list:** Organize findings into tasks with clear verification criteria.
5. **Execute fixes:** Implement, re-enrich, validate.

### Why This Matters

The fee calculation engine (`apps/api/src/domains/ahcip/ahcip.service.ts`, `computeFeeBreakdown()`) and 19 validation checks (A1-A19) directly consume every field in the `hsc_codes` table. Incorrect scraped data means incorrect fee calculations, claim rejections, overpayment, or compliance violations across ~350,000 annual AHCIP claims.

### Git History (newest first)

```
0c1e03d  Complete Fee Navigator V2 pipeline fixes (SCR-110 through SCR-180)
4909806  Complete Fee Navigator scraper pipeline fixes (SCR-001 through SCR-070)
7f48c5f  Update tests for enrichment fields and facilityDesignation
5428891  Expose enrichment fields in seed mapping and API responses
a405240  Add enrichment script, fix specialty regex, and re-scrape data
642dfb0  Add facilityDesignation column and export hscModifierEligibility table
38196dd  Fix data quality issues: fee type mapping, surcharge detection, governing rules
175ee57  Add AMA Fee Navigator scraper, seed data, web app scaffolding, and project docs
```
