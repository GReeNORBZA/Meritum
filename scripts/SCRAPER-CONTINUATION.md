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
- Scraped data: `scripts/data/fee-navigator/`
- Seed script: `apps/api/src/seed.ts`
- Run tsx via: `apps/api/node_modules/.bin/tsx`

### What Was Built

**Scraper** (`scripts/scrape-fee-navigator.ts`):
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

**Seed script** (`apps/api/src/seed.ts`) updated to:
- Load all scraped JSON via `loadScrapedData()` helper
- Insert 3,089 HSC codes in batches of 500
- Insert 42 modifiers, 19 governing rules, 123 explanatory codes
- Version label: `SOMB 2025 Q1 - Fee Navigator`
- DI codes, functional centres, RRNP communities kept as manual entries

### Known Data Quality Items to Investigate

1. **Fee type mapping** — `categoryToFeeType()` maps category letter (V, P, M, C, L, R, A, T) to fee types. 1,655 codes mapped to "OTHER" (category letters not in the switch). Run: `cat scripts/data/fee-navigator/hsc-codes.json | python3 -c "import json,sys,collections; d=json.load(sys.stdin); print(collections.Counter(h['category'] for h in d).most_common(20))"`

2. **03.03A base fee discrepancy** — The scraper got $25.09 but the original seed had $78.12. The $25.09 is correct per the Fee Navigator (it's the base rate before specialty modifiers; the $78.12 may have been a SKLL/GP-adjusted rate). Worth verifying.

3. **Modifier eligibility extraction** — Currently extracts unique modifier TYPE codes (e.g., SKLL, AGE, CARE) from the modifier table, not the specific sub-codes (SKLL/ANES, SKLL/GP, etc.). The full sub-code data is in `hsc-modifiers.json`.

4. **Surcharge detection** — Only checks for `type === 'SURC'` in modifier rows. Some surcharge-eligible codes might use different patterns.

5. **Governing rules text truncation** — `fullText` is the entire page text content (can be very long). Seed inserts truncate to 10,000 chars. Some rules (GR 4, GR 13) have hundreds of HSC code references.

6. **Missing data not from Fee Navigator** — ICD-9 DI codes (~14,000), WCB codes, PCPCM baskets, functional centres (~2,000+), RRNP communities, bundling rules, specialty/facility restrictions, maxPerDay/maxPerVisit limits.

7. **Counter display bug** — The scraper's progress counter double-counts in Phase 2 when resuming (shows `[6157/3089]`). Cosmetic only; data is correct. Already fixed in the script but the original run used the unfixed version.

### Key HTML Parsing Details

- HSC detail page structure: `h2.code` (code), `h1.title` (description), `table.basic-info` (category + base rate), `div.modifiers table` (modifier rows with columns: Type, Code, # of calls, Explicit, Action, Amount), `div.note` (notes), `div.billing-tips` (tips)
- Tree expansion: POST to `?ajax=expanded` with `expanded={comma-separated-keys}&expand={key}`, returns XML with HTML-entity-encoded `<content>` containing `<ul><li>` tree nodes
- Expandable nodes: `class="node expandable" data-key="{numeric}"`, Viewable nodes: `class="node viewable" data-key="{code}" href="/fee-navigator/hsc/{code}"`
- Detail AJAX: GET `?ajax=detail` returns XML with `<content>` containing the record HTML

### Drizzle Schema (key tables)

- `hsc_codes`: hscCode(10), description(text), baseFee(decimal 10,2), feeType(20), specialtyRestrictions(jsonb[]), facilityRestrictions(jsonb[]), maxPerDay(int), maxPerVisit(int), requiresReferral(bool), modifierEligibility(jsonb[]), surchargeEligible(bool), pcpcmBasket(20), shadowBillingEligible(bool), notes(text), helpText(text), versionId(uuid FK), effectiveFrom(date)
- `modifier_definitions`: modifierCode(10), name(100), description(text), type(20), calculationMethod(20), calculationParams(jsonb), applicableHscFilter(jsonb), combinableWith(jsonb[]), exclusiveWith(jsonb[]), governingRuleReference(20), versionId(uuid FK)
- `governing_rules`: ruleId(20), ruleName(200), ruleCategory(30), description(text), ruleLogic(jsonb), severity(10), errorMessage(text), sourceReference(100), sourceUrl(text), versionId(uuid FK)
- `explanatory_codes`: explCode(10), description(text), severity(10), commonCause(text), suggestedAction(text), helpText(text), versionId(uuid FK)

### How to Re-run

```bash
cd /home/developer/Desktop/projects

# Re-run scraper (uses cached discovery if available)
apps/api/node_modules/.bin/tsx scripts/scrape-fee-navigator.ts

# Verify data
python3 -c "import json; d=json.load(open('scripts/data/fee-navigator/hsc-codes.json')); print(len(d), 'codes')"

# Check seed compiles
cd apps/api && node_modules/.bin/tsx -e "import * as ts from 'typescript'; import * as fs from 'fs'; const r = ts.transpileModule(fs.readFileSync('src/seed.ts','utf-8'), {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.NodeNext,moduleResolution:ts.ModuleResolutionKind.NodeNext}}); console.log(r.diagnostics?.length ? 'ERRORS' : 'OK')"
```
