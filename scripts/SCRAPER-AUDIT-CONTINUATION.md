# Fee Navigator Pipeline — Final Audit Continuation Prompt

Paste everything below the line into a new Claude Code chat to audit the scraper pipeline.

---

## Prompt

I need a final audit of the Fee Navigator scraper pipeline for the Meritum project. All V2 FRD tasks (SCR-110 through SCR-180) have been completed and a fresh re-scrape was performed on 2026-03-03. The data passes validation. I want a thorough review of correctness, robustness, and edge cases before this pipeline is considered production-ready.

### Project Location

- Monorepo: `/workspace/projects`
- tsx: `./apps/api/node_modules/.bin/tsx`

### Pipeline Overview

The Fee Navigator pipeline scrapes Alberta's SOMB (Schedule of Medical Benefits) data from `apps.albertadoctors.org/fee-navigator` and produces production-ready reference data for the Meritum billing platform. It consists of 4 scripts + 1 shared utility module:

| Script | Lines | Purpose |
|--------|-------|---------|
| `scripts/scrape-fee-navigator.ts` | 1,178 | Main scraper — discovers HSC codes via tree expansion, scrapes code details, modifiers, governing rules, explanatory codes |
| `scripts/enrich-hsc-data.ts` | 1,002 | Enrichment — extracts structured data (referrals, specialties, bundling, age, frequency, anesthesia) from notes text + governing rule pages |
| `scripts/validate-fee-navigator-data.ts` | 529 | Validation — completeness thresholds, format checks, cross-file consistency, enrichment minimums, data quality audits |
| `scripts/audit-fee-navigator.ts` | 337 | Gap analysis — compares enrichment counts against targets, identifies remaining extraction opportunities |
| `scripts/lib/fee-navigator-utils.ts` | 156 | Shared utilities — fetchWithRetry, decodeHtmlEntities, validateResponse, file I/O helpers |

The seed script (`apps/api/src/seed.ts`, 1,520 lines) imports the scraped JSON into PostgreSQL via Drizzle ORM.

### Current Data (post re-scrape 2026-03-03)

**Scrape metadata:**
- Timestamp: 2026-03-03T20:45:11.527Z
- Duration: 1,224 seconds (~20 minutes)
- Root section keys discovered: 20 (up from 19 in previous scrapes)
- HSC codes: 3,079
- HSC modifier eligibility rows: 41,269
- Modifier definitions: 42
- Governing rules: 19 (top-level)
- Explanatory codes: 123
- Errors: 0

**Enrichment metrics:**

| Dimension | Count | Target | Status |
|-----------|-------|--------|--------|
| bundlingExclusions | 356 | 350 | Exceeded |
| ageRestriction | 242 | 50 | Exceeded |
| frequencyRestriction | 55 (audit) / 36 (validation) | 40 | Exceeded |
| specialtyRestrictions | 119 | 120 | -1 (measurement limit) |
| requiresReferral | 47 | 50 | -3 (audit false positives) |
| requiresAnesthesia | 21 | 15 | Exceeded |
| maxPerDay | 19 | 10 | Exceeded |
| facilityDesignation | 27 | 20 | Exceeded |

**Validation: PASS (0 errors, 0 warnings)**

### V2 FRD Tasks — All Complete

| Phase | Task | Description | Implementation Location |
|-------|------|-------------|------------------------|
| 1 | SCR-110 | HSC code extraction from text | `enrich-hsc-data.ts` — multi-pattern regex with match.index context |
| 1 | SCR-111 | Age restriction extraction | `enrich-hsc-data.ts` — AGE_PATTERNS with prefix/suffix variants |
| 1 | SCR-112 | Frequency/anesthesia extraction | `enrich-hsc-data.ts` — word-form numbers, expanded periods |
| 2 | SCR-120 | Specialty restriction extraction | `enrich-hsc-data.ts` — colon/semicolon splitting, location extraction |
| 2 | SCR-121 | GR 1.33 numeric-only codes | `enrich-hsc-data.ts` — `{0,3}` suffix allows zero alpha chars |
| 3 | SCR-130 | Discovery cache invalidation | `scrape-fee-navigator.ts:29-30,288-308` — `--force-discovery` flag + 7-day TTL |
| 3 | SCR-131 | Circuit breaker on mass failure | `scrape-fee-navigator.ts:31,589-660` — 20 consecutive errors threshold |
| 3 | SCR-132 | Dynamic governing rule discovery | `scrape-fee-navigator.ts:830-864` — `discoverTopLevelRuleIds()` |
| 3 | SCR-133 | Metadata rootSectionKeys tracking | `scrape-fee-navigator.ts:288,383,1127` — returned from discovery |
| 4 | SCR-140 | fetchWithRetry body timeout | `fee-navigator-utils.ts:77-93` — clearTimeout after resp.text() |
| 4 | SCR-141 | HTML named entity decoding | `fee-navigator-utils.ts:124-131` — nbsp, ndash, mdash, rsquo, etc. |
| 4 | SCR-142 | Block detection extended | `fee-navigator-utils.ts:45-59` — 5000 char window, 7 indicators |
| 5 | SCR-150 | Modifier eligibility deduplication | `scrape-fee-navigator.ts:390-404` + schema unique index includes `calls` |
| 5 | SCR-151 | Calls empty string handling | `seed.ts:830` — explicit `=== ''` check |
| 5 | SCR-152 | Explanatory code category→severity | `seed.ts:931-935` — reject→ERROR, adjust→WARNING, paid→INFO |
| 5 | SCR-153 | Self-referencing bundling filter | `seed.ts:954-955,957-960,971` — skip + canonical ordering |
| 5 | SCR-154 | Seed transaction wrapper | `seed.ts:222` — `db.transaction(async (tx) => {...})` |
| 5 | SCR-155 | Action varchar widened to 50 | `reference.schema.ts:264` — already varchar(50) |
| 6 | SCR-160 | Tightened completeness thresholds | `validate-fee-navigator-data.ts:178-184` — HSC≥2900, mods≥38000 |
| 6 | SCR-161 | Modifier row dedup validation | `validate-fee-navigator-data.ts:308-324` — key on hscCode|type|code|calls |
| 6 | SCR-162 | Enrichment minimum thresholds | `validate-fee-navigator-data.ts:461-481` — 9 fields with minimums |
| 6 | SCR-163 | GR reference resolution check | `validate-fee-navigator-data.ts:371-399` — cross-file with parent fallback |
| 7 | SCR-170 | Specialty restriction normalization | `enrich-hsc-data.ts:87-112` — fragment filter, title-case |
| 7 | SCR-171 | Modifier description cleanup | `scrape-fee-navigator.ts:700-707` — AMA footer removal |
| 7 | SCR-172 | Visit code without modifiers audit | `validate-fee-navigator-data.ts:498-510` — warn if >70 |
| 8 | SCR-180 | Re-scrape with all fixes applied | Completed 2026-03-03, validation PASS |

### Known Issues Found During Re-scrape

1. **Block detection false positive (SCR-142):** During tree discovery, the `validateResponse()` block detector triggered on a legitimate AJAX response for node 231. The response contained the word "blocked" (likely in an HSC code description or CSS class). The scraper retried 3 times, failed, and skipped that one node. The circuit breaker did NOT trip (only 1 consecutive error). Impact: possibly a few codes under node 231 were not discovered. However, the total code count (3,079) is very close to the previous scrape (3,089), and the 10-code difference may be due to Fee Navigator deprecations rather than this false positive.

2. **Post-scrape validation exit code:** The scraper runs validation after scraping (line 1146-1161) but BEFORE enrichment. Since enrichment is a separate script, the freshly scraped data always fails enrichment minimums (all zero). The scraper exits with code 2, which looks like a failure even though the data is correct. The enrichment script has its own post-enrichment validation that runs and passes correctly.

3. **Frequency count discrepancy:** The audit script reports 55 frequency restrictions but the validation script reports 36. These use different counting methods — the audit counts codes whose notes text *mentions* frequency-like patterns (broader), while enrichment only extracts codes where the pattern can be parsed into a structured `{count, period}` object (stricter). Both are correct for their purposes.

4. **Progress counter display:** During resume scraping, the `[overall/total]` counter can show values exceeding total (e.g., `[5999/3079]`) because `overall = completedSet.size + i + 1` where completedSet includes codes from the previous run's progress file. Cosmetic only — does not affect data.

### What To Audit

Please perform a comprehensive audit of the pipeline. Specifically:

```bash
cd /workspace/projects

# 1. Review each script for correctness and edge cases
# Focus on: regex patterns, error handling, data transformations, edge cases

# 2. Check the data files for anomalies
ls -la scripts/data/fee-navigator/

# 3. Run all verification commands
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts
./apps/api/node_modules/.bin/tsx scripts/audit-fee-navigator.ts --metrics-only

# 4. Spot-check individual codes
./apps/api/node_modules/.bin/tsx scripts/audit-fee-navigator.ts
```

### Audit Categories

1. **Scraper robustness** — Review `scrape-fee-navigator.ts`:
   - Tree discovery BFS logic: can it miss codes? Are there race conditions?
   - HTML parsing: are selectors fragile? What if Fee Navigator changes its HTML structure?
   - Resume/progress: is the progress file reliable? Can it get corrupted?
   - Circuit breaker: is threshold 20 appropriate? Does the counter reset correctly?
   - Cache invalidation: is 7-day TTL reasonable?
   - The false positive block detection issue — should "blocked" be removed from indicators?

2. **Enrichment accuracy** — Review `enrich-hsc-data.ts`:
   - Are regex patterns correct? Any false positives or missed patterns?
   - Category marker codes (`*VISIT`, `*PROCEDURE`, etc.) — handled correctly in seed?
   - GR 4.4.8 referral extraction — does it handle all edge cases?
   - GR 1.33 facility designation — is the in-office/out-of-office classification accurate?
   - Bundling exclusion patterns (17 groups A-R) — any inverted logic?
   - `normalizeSpecialty()` — does it filter too aggressively?

3. **Validation completeness** — Review `validate-fee-navigator-data.ts`:
   - Are thresholds set correctly? Too tight? Too loose?
   - Any validation gaps? Things that could go wrong but aren't checked?
   - Cross-file consistency: any missing checks?

4. **Seed correctness** — Review `apps/api/src/seed.ts` (reference data section, lines 680-993):
   - Transaction handling: any inserts outside the transaction?
   - Bundling rules: canonical ordering and dedup correct?
   - Explanatory code severity mapping: accurate?
   - Modifier eligibility: batch insertion correct? Any data loss?
   - Category marker codes in bundling exclusions: do they cause seed failures?

5. **Schema alignment** — Review `packages/shared/src/schemas/db/reference.schema.ts`:
   - Do column types match the scraped data?
   - Are indexes appropriate for query patterns?
   - Any missing columns for enrichment data?

6. **Known issue resolution** — For each of the 4 known issues above, recommend whether to fix now or defer, and propose a fix if warranted.

### Key File Locations

| File | Purpose |
|------|---------|
| `scripts/scrape-fee-navigator.ts` | Main scraper (5 phases: discover, scrape HSC, modifiers, GR, explanatory codes) |
| `scripts/enrich-hsc-data.ts` | Enrichment (GR-based + notes-based extraction) |
| `scripts/validate-fee-navigator-data.ts` | Validation (8 sections: files, completeness, format, dupes, modifiers, cross-file, enrichment, data quality) |
| `scripts/audit-fee-navigator.ts` | Gap analysis (compares enrichment vs targets) |
| `scripts/lib/fee-navigator-utils.ts` | Shared utilities (fetchWithRetry, decodeHtmlEntities, validateResponse) |
| `scripts/data/fee-navigator/` | All scraped/enriched JSON data files |
| `packages/shared/src/schemas/db/reference.schema.ts` | Drizzle schema for reference data tables |
| `apps/api/src/seed.ts` | Seed script (imports JSON into PostgreSQL) |
| `docs/frd/Meritum_Fee_Navigator_Pipeline_V2_FRD.md` | V2 FRD with all task specifications |
| `configs/scraper-pipeline-v2-manifests.json` | Task runner config for V2 tasks |

### Commit History

```
5f6767f  Update continuation prompt for V2 remaining tasks (post-V3 enrichment convergence)
77e73bd  pipeline-loop: enrichment V3 — close 185/189 gap across all dimensions
c5435c0  Update scraper continuation prompt for V3 audit and improvements
0c1e03d  Complete Fee Navigator V2 pipeline fixes (SCR-110 through SCR-180)
4909806  Complete Fee Navigator scraper pipeline fixes (SCR-001 through SCR-070)
7f48c5f  Update tests for enrichment fields and facilityDesignation
5428891  Expose enrichment fields in seed mapping and API responses
a405240  Add enrichment script, fix specialty regex, and re-scrape data
642dfb0  Add facilityDesignation column and export hscModifierEligibility table
38196dd  Fix data quality issues: fee type mapping, surcharge detection, governing rules
175ee57  Add AMA Fee Navigator scraper, seed data, web app scaffolding, and project docs
```

### Important Context

- The scraper fetches individual pages from `apps.albertadoctors.org/fee-navigator/`. Full scrape takes ~20 minutes with 200ms delay between requests.
- The enrichment script fetches 2 live pages (GR 4 for referrals, GR 1 for facility designation). This takes ~30-45 seconds.
- Notes text uses "." directly followed by next sentence with no space. Regex patterns must handle this via `\.(?!\d)` sentence boundaries.
- "May be claimed in addition to HSC X" is POSITIVE (allowed together). Only "May NOT be claimed with" or "not payable in addition to" are exclusions.
- Category marker codes (`*VISIT`, `*PROCEDURE`, `*SURGICAL_ASSIST`, `*ANESTHETIC`, `*INCLUDED`, `*SOLE_PROCEDURE`) represent generic bundling exclusions that don't reference specific HSC codes.
- The `hsc_modifier_eligibility` unique index is on `(hscCode, modifierType, subCode, calls, versionId)`.
- The seed script is wrapped in a transaction and is idempotent.
- The specialty restriction gap of 1 and referral gap of 3 are audit measurement limits, not real extraction gaps.
- The scraper's post-scrape validation will fail with exit code 2 until enrichment is run separately — this is a known design issue, not a data problem.

### Output Format

Please provide your audit as a structured report with:
1. **Summary** — overall assessment (production-ready / needs fixes / critical issues)
2. **Findings** — categorized by severity (Critical / High / Medium / Low / Info)
3. **Recommendations** — prioritized list of changes, if any
4. **Spot checks** — results of checking specific codes against the live Fee Navigator site
