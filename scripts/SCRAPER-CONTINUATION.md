# Fee Navigator Scraper — Continuation Context

Use this file to resume work in a new conversation. Paste the relevant sections below as your opening prompt.

---

## Continuation Prompt

I'm continuing work on the AMA Fee Navigator scraper for the Meritum project. Here's where we left off:

### Project Structure
- Monorepo at `/home/developer/Desktop/projects` (pnpm + turbo)
- API: `apps/api/` (Fastify + Drizzle ORM + PostgreSQL)
- Shared schemas: `packages/shared/src/schemas/db/reference.schema.ts`
- Scraper: `scripts/scrape-fee-navigator.ts` (TypeScript + cheerio)
- Exploration script: `scripts/explore-fee-navigator.ts` (TypeScript + Playwright)
- Scraped data: `scripts/data/fee-navigator/`
- Seed script: `apps/api/src/seed.ts`
- Run tsx via: `apps/api/node_modules/.bin/tsx` or `npx tsx`

### What Was Built

**Scraper** (`scripts/scrape-fee-navigator.ts`) — cheerio-based, no JS execution:
- Phase 1: AJAX tree expansion (`POST /fee-navigator/hsc?ajax=expanded`) to discover all HSC codes
- Phase 2: Detail pages (`GET /fee-navigator/hsc/{code}?ajax=detail`) parsed with cheerio
- Phase 3: Modifier pages (`/fee-navigator/modifiers/{code}`)
- Phase 4: Governing rules (`/fee-navigator/governing-rules/{n}`)
- Phase 5: Explanatory codes (AJAX tree expansion on `/fee-navigator/explanatory-codes`)

**Scraped Output** (in `scripts/data/fee-navigator/`):

| File | Records | Size |
|------|---------|------|
| `hsc-codes.json` | 3,089 HSC codes | 2.4 MB |
| `hsc-modifiers.json` | 41,328 per-code modifier rows | 6.7 MB |
| `modifiers.json` | 42 modifier definitions | 187 KB |
| `governing-rules.json` | 19 governing rules | 166 KB |
| `explanatory-codes.json` | 123 explanatory codes | 15 KB |
| `scrape-metadata.json` | Run metadata | 234 B |

**Task 4: Modifier Eligibility Data** (COMPLETED):
- Added `hsc_modifier_eligibility` table to Drizzle schema (`reference.schema.ts`)
  - Columns: hscCode, modifierType, subCode, calls, explicit, action, amount, versionId, effectiveFrom, effectiveTo
  - Indexes: (hscCode, versionId), (modifierType, versionId), unique(hscCode, modifierType, subCode, versionId)
- Updated `seed.ts` to load `hsc-modifiers.json` and insert 41,328 eligibility rows in batches of 500
- Seed also builds `applicableHscFilter` on `modifier_definitions`: `{all: true}` if >2500 codes, `{codes: [...]}` otherwise
- Added `findModifierEligibilityForHsc()` and `findHscCodesForModifierType()` to `reference.repository.ts`
- Added `modifierEligibilityDetail` array to `getHscDetail()` in `reference.service.ts`
- All tests pass (14,178 passed; 37 pre-existing failures in unrelated domains)

**Seed script** (`apps/api/src/seed.ts`) loads:
- 3,089 HSC codes, 41,328 modifier eligibility rows, 42 modifiers, 19 governing rules, 123 explanatory codes
- Version label: `SOMB 2025 Q1 - Fee Navigator`

### Current Task: Explore Missing Data

The scraper uses **cheerio** (server-side HTML parsing) which **cannot**:
- Execute JavaScript or trigger pop-ups/modals
- See dynamically loaded content (lazy-loaded panels, AJAX on click)
- Interact with tooltips, hover states, or accordion panels
- Detect content behind tabs or expandable sections

**Exploration script** (`scripts/explore-fee-navigator.ts`) was written to investigate this. It uses **Playwright** (headless Chromium) to:

1. **Discover navigation structure** — Visit all main sections, collect all internal links
2. **Monitor network traffic** — Capture AJAX requests triggered during page interaction
3. **Deep-explore sample HSC pages** — For 9 diverse codes (03.03A, 01.01A, 03.04A, 08.19A, 13.99J, 03.01A, 03.08A, 73.21, 95.09):
   - Discover all visible sections (headings, labeled divs)
   - Find clickable elements that might trigger popups
   - Click modal/dialog triggers and capture content
   - Detect tabs and load their content
   - Probe tooltips (title attrs, data-tooltip, hover-triggered)
   - Find hidden/collapsed sections (display:none, aria-hidden, `<details>`)
   - Collect all links (internal, external, popup-opening)
   - Check for iframes
   - Extract all data-* attributes
4. **Compare browser content vs scraped data** — Check for 26+ field patterns visible in browser text that the scraper might miss (specialtyRestrictions, maxPerDay, requiresReferral, combinationGroup, shadowBilling, pcpcm, etc.)
5. **Screenshot a detail page** for visual reference
6. **Compare AJAX detail vs full page** — Measure content size difference
7. **Output**: `exploration-report.json` with full findings + console summary

### How to Run the Exploration

```bash
cd /home/developer/Desktop/projects

# Install Playwright (if not already)
pnpm add -D playwright
npx playwright install chromium

# Run the exploration
npx tsx scripts/explore-fee-navigator.ts

# Review results
cat scripts/data/fee-navigator/exploration-report.json | python3 -m json.tool | head -100

# View the screenshot
# scripts/data/fee-navigator/exploration-screenshot-03.03A.png
```

### Schema Fields Not Yet Populated

These `hsc_codes` columns exist in the schema but are seeded with defaults because the scraper doesn't extract them:

| Column | Default | Possible Source |
|--------|---------|-----------------|
| `specialtyRestrictions` | `[]` | May be in Fee Navigator detail page or separate doc |
| `facilityRestrictions` | `[]` | May be in Fee Navigator detail page or separate doc |
| `maxPerDay` | `null` | Governing rules or billing rules section |
| `maxPerVisit` | `null` | Governing rules or billing rules section |
| `requiresReferral` | `false` | Fee Navigator or AHCIP manual |
| `referralValidityDays` | `null` | AHCIP manual |
| `combinationGroup` | `null` | Bundling rules / governing rules |
| `pcpcmBasket` | `'not_applicable'` | PCPCM program documentation |
| `shadowBillingEligible` | `false` | AMA documentation |

### Known Data Quality Items

1. **Fee type mapping** — `categoryToFeeType()` maps category letter (V, P, M, C, L, R, A, T) to fee types. 1,655 codes mapped to "OTHER". Check: `python3 -c "import json,sys,collections; d=json.load(open('scripts/data/fee-navigator/hsc-codes.json')); print(collections.Counter(h['category'] for h in d).most_common(20))"`

2. **03.03A base fee discrepancy** — Scraper: $25.09 vs original seed: $78.12. The $25.09 is the base rate before SKLL modifiers.

3. **Missing external data** — ICD-9 DI codes (~14,000), WCB codes, PCPCM baskets, functional centres (~2,000+), RRNP communities, bundling rules

### Key HTML Parsing Details

- HSC detail page structure: `h2.code` (code), `h1.title` (description), `table.basic-info` (category + base rate + common terms), `div.modifiers table` (modifier rows: Type, Code, # of calls, Explicit, Action, Amount), `div.note` (notes), `div.billing-tips` (tips)
- Tree expansion: POST to `?ajax=expanded` with `expanded={keys}&expand={key}`, returns XML with HTML-entity-encoded `<content>`
- Detail AJAX: GET `?ajax=detail` returns XML with `<content>` containing the record HTML
- Expandable nodes: `class="node expandable" data-key="{numeric}"`, Viewable: `class="node viewable" href="/fee-navigator/hsc/{code}"`

### Drizzle Schema (key tables)

- `hsc_codes`: hscCode(10), description(text), baseFee(decimal 10,2), feeType(20), specialtyRestrictions(jsonb[]), facilityRestrictions(jsonb[]), maxPerDay(int), maxPerVisit(int), requiresReferral(bool), modifierEligibility(jsonb[]), surchargeEligible(bool), pcpcmBasket(20), shadowBillingEligible(bool), notes(text), helpText(text), versionId(uuid FK), effectiveFrom(date)
- `hsc_modifier_eligibility`: hscCode(10), modifierType(10), subCode(20), calls(20), explicit(bool), action(30), amount(20), versionId(uuid FK), effectiveFrom(date) — **NEW in Task 4**
- `modifier_definitions`: modifierCode(10), name(100), description(text), type(20), calculationMethod(20), calculationParams(jsonb), applicableHscFilter(jsonb), combinableWith(jsonb[]), exclusiveWith(jsonb[]), governingRuleReference(20), versionId(uuid FK)
- `governing_rules`: ruleId(20), ruleName(200), ruleCategory(30), description(text), ruleLogic(jsonb), severity(10), errorMessage(text), sourceReference(100), sourceUrl(text), versionId(uuid FK)
- `explanatory_codes`: explCode(10), description(text), severity(10), commonCause(text), suggestedAction(text), helpText(text), versionId(uuid FK)

### How to Re-run

```bash
cd /home/developer/Desktop/projects

# Re-run cheerio scraper (uses cached discovery if available)
npx tsx scripts/scrape-fee-navigator.ts

# Run Playwright exploration (requires: pnpm add -D playwright && npx playwright install chromium)
npx tsx scripts/explore-fee-navigator.ts

# Verify data counts
python3 -c "import json; d=json.load(open('scripts/data/fee-navigator/hsc-codes.json')); print(len(d), 'codes')"
python3 -c "import json; d=json.load(open('scripts/data/fee-navigator/hsc-modifiers.json')); print(len(d), 'modifier eligibility rows')"

# Run tests
cd apps/api && pnpm test
```

### Next Steps After Exploration

Based on what the exploration script finds:

1. **If popups/modals contain data** → Rewrite scraper using Playwright instead of cheerio, or add a Playwright supplemental pass that clicks triggers and captures modal content
2. **If tabs/hidden sections have data** → Add section-specific parsing to the cheerio scraper (if content is in the initial HTML but just visually hidden) or add Playwright interaction
3. **If new AJAX endpoints are discovered** → Add fetching of those endpoints to the cheerio scraper
4. **If no additional data found** → The schema fields like `specialtyRestrictions`, `maxPerDay`, etc. likely come from other sources (AHCIP Physician's Manual, PCPCM documentation) not from the Fee Navigator website
