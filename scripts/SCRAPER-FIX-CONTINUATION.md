# Fee Navigator Pipeline — Post-Audit Fix Prompt

Paste everything below the line into a new Claude Code chat to apply all fixes identified in the 2026-03-03 audit.

---

## Prompt

I need you to fix all issues identified in the Fee Navigator scraper pipeline audit. The audit was performed on 2026-03-03 after a successful re-scrape and enrichment pass. Validation passes (0 errors, 0 warnings) and all enrichment dimensions meet targets. However, the audit found 28 issues across 4 severity levels.

**Do NOT re-run the scraper or enrichment scripts.** These fixes are code-only changes to the pipeline scripts, schema, and seed. After all fixes, run validation to confirm nothing broke.

### Project Location

- Monorepo: `/workspace/projects`
- tsx: `./apps/api/node_modules/.bin/tsx`

### Pipeline Files to Modify

| File | Lines | Changes |
|------|-------|---------|
| `scripts/lib/fee-navigator-utils.ts` | 156 | Block detection, atomic writes, `&apos;` entity |
| `scripts/scrape-fee-navigator.ts` | 1,178 | Modifier discovery, BFS regex, exit code, lock file, progress counter |
| `scripts/enrich-hsc-data.ts` | 1,002 | Code normalization, backup before write, frequency regex, specialty fix, referral fix |
| `scripts/validate-fee-navigator-data.ts` | 529 | Code normalization check |
| `scripts/audit-fee-navigator.ts` | 337 | No changes needed |
| `packages/shared/src/schemas/db/reference.schema.ts` | 892 | NULL unique index fix |
| `apps/api/src/seed.ts` | ~1,520 | Category marker filter, severity mapping, version label, re-seed support |

---

## CRITICAL Fixes (P0) — Must complete before seed can run

### C-1: Category markers exceed `varchar(10)` in bundling_rules table

**File:** `apps/api/src/seed.ts`, lines 949-975 (bundling rules insertion loop)

**Problem:** Six category markers are extracted by enrichment: `*INCLUDED` (9), `*VISIT` (6), `*PROCEDURE` (10), `*ANESTHETIC` (11), `*SOLE_PROCEDURE` (15), `*SURGICAL_ASSIST` (16). Three exceed the `varchar(10)` limit on `bundling_rules.code_a`/`code_b` (`reference.schema.ts:768-769`). PostgreSQL will throw `ERROR: value too long for type character varying(10)`, rolling back the entire seed transaction. 8 bundling pairs are affected.

**Fix:** Filter out `*`-prefixed markers in the seed bundling loop. These represent generic category exclusions, not specific code pairs, and don't belong in the pairwise bundling table. Add this check at the top of the inner loop, after line 953 (`for (const excl of h.bundlingExclusions)`):

```typescript
// Skip category markers — these are generic exclusions, not specific code pairs
if (excl.excludedCode.startsWith('*')) continue;
```

This reduces the bundling pair count from 815 to ~807 (8 pairs removed). The category markers are still preserved in `hsc_codes.bundling_exclusions` JSONB column for display purposes.

### C-2: Explanatory code severity mapping is broken

**File:** `apps/api/src/seed.ts`, lines 930-946

**Problem:** The keyword-matching logic checks for `"reject"`, `"adjust"`, `"paid"`, `"approv"` in category names — but **no AHCIP category contains the word "reject"**. Result: the `ERROR` branch is dead code. 119 of 123 explanatory codes map to `INFO`, including hard rejections like "NOT REGISTERED" (code 01), "INELIGIBLE PATIENT" (code 22), "INELIGIBLE PRACTITIONER" (code 10), "INELIGIBLE SERVICES" (code 20).

The 13 actual categories in the scraped data are:
- `ACRONYMS AND SPECIAL PROCESSING CODES`
- `ADDITIONAL COMPENSATION IN ACCORDANCE WITH GR 2.6`
- `ADJUSTMENTS`
- `ALTERNATE PAYMENT PLAN`
- `ANESTHESIA`
- `CONSULTATIONS/VISITS`
- `DENTAL ASSESSMENT`
- `HOSPITAL RECIPROCAL`
- `INELIGIBLE SERVICES`
- `MINOR PROCEDURES`
- `PATIENT REGISTRATION`
- `PRACTITIONER REGISTRATION`
- `SURGICAL PROCEDURES`

**Fix:** Replace the keyword-matching logic (lines 931-935) with an explicit category-to-severity map:

```typescript
const EXPL_SEVERITY_MAP: Record<string, string> = {
  'PATIENT REGISTRATION': 'ERROR',
  'PRACTITIONER REGISTRATION': 'ERROR',
  'INELIGIBLE SERVICES': 'ERROR',
  'ADJUSTMENTS': 'WARNING',
  'SURGICAL PROCEDURES': 'WARNING',
  'MINOR PROCEDURES': 'WARNING',
  'ANESTHESIA': 'WARNING',
  'CONSULTATIONS/VISITS': 'WARNING',
  'DENTAL ASSESSMENT': 'WARNING',
  'HOSPITAL RECIPROCAL': 'INFO',
  'ALTERNATE PAYMENT PLAN': 'INFO',
  'ADDITIONAL COMPENSATION IN ACCORDANCE WITH GR 2.6': 'INFO',
  'ACRONYMS AND SPECIAL PROCESSING CODES': 'INFO',
};
```

Then replace the `let severity = 'INFO'; if/else` block with:
```typescript
const severity = EXPL_SEVERITY_MAP[e.category] ?? 'INFO';
```

---

## HIGH Fixes (P1) — Fix before production

### H-1: Block detection false positive — "blocked" substring too broad

**File:** `scripts/lib/fee-navigator-utils.ts`, line 51

**Problem:** `lower.includes('blocked')` in `validateResponse()` triggers on legitimate content containing the word "blocked" (e.g., "self-referral blocked" in HSC notes, CSS class names). During the 2026-03-03 scrape, node 231 was skipped due to this false positive, potentially missing a few codes (total 3,079 vs previous 3,089).

**Fix:** Replace the bare `'blocked'` check at line 51 with specific block phrases:

```typescript
lower.includes('you have been blocked') ||
lower.includes('your ip has been blocked') ||
lower.includes('access has been blocked') ||
lower.includes('your access is blocked') ||
```

Keep all other indicators (`captcha`, `access denied`, `rate limit exceeded`, `too many requests`, `cloudflare`, `please verify you are human`).

### H-2: Modifier discovery race condition

**File:** `scripts/scrape-fee-navigator.ts`, line 207

**Problem:** Method 3 (tree expansion for modifiers) only runs if `codes.size === 0` after methods 1-2. If methods 1-2 find **some but not all** modifier codes, method 3 is skipped entirely and hidden categories are never expanded. Currently all 42 modifiers are found via methods 1-2, but a Fee Navigator layout change that splits modifiers between visible links and expandable categories would silently lose modifiers.

**Fix:** Change the condition at line 207 from:
```typescript
if (expandableKeys.length > 0 && codes.size === 0) {
```
to:
```typescript
if (expandableKeys.length > 0) {
```

This always expands categories and merges results, regardless of how many codes methods 1-2 already found. The deduplication via `codes` Set handles overlaps.

### H-3: Non-atomic file writes across all scripts

**File:** `scripts/lib/fee-navigator-utils.ts`, lines 143-148 (`saveJson` function)

**Problem:** `fs.writeFileSync()` is not atomic. If the process crashes mid-write (OOM, SIGKILL), the JSON file is truncated/corrupt. This affects the scraper's progress file, the hsc-codes.json, hsc-modifiers.json, and the enrichment output. The enrichment script writes a 3.6MB file in-place with no backup.

**Fix:** Update `saveJson` to use write-to-temp-then-rename:

```typescript
export function saveJson(outputDir: string, filename: string, data: unknown): void {
  ensureDir(outputDir);
  const filePath = path.join(outputDir, filename);
  const tmpPath = filePath + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2));
  fs.renameSync(tmpPath, filePath);  // atomic on same filesystem
  console.log(`  Saved ${filePath}`);
}
```

Also update `loadJson` to handle corrupt files gracefully:

```typescript
export function loadJson<T>(outputDir: string, filename: string): T | null {
  const filePath = path.join(outputDir, filename);
  if (fs.existsSync(filePath)) {
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    } catch (err) {
      console.warn(`  [WARN] Could not parse ${filePath}: ${(err as Error).message}`);
      return null;
    }
  }
  return null;
}
```

Additionally, update the enrichment script (`enrich-hsc-data.ts`, line 933) to:
1. Create a backup before modifying: copy `hsc-codes.json` to `hsc-codes.pre-enrichment.json`
2. Use atomic write (write to `.tmp` then rename)

```typescript
// Backup original before enrichment
const backupPath = hscPath + '.pre-enrichment.json';
fs.copyFileSync(hscPath, backupPath);
console.log(`  Backup saved to ${backupPath}`);

// Atomic write
const tmpPath = hscPath + '.tmp';
fs.writeFileSync(tmpPath, JSON.stringify(hscCodes, null, 2));
fs.renameSync(tmpPath, hscPath);
console.log(`  Enriched hsc-codes.json written to ${hscPath}`);
```

### H-4: No concurrent scrape protection

**File:** `scripts/scrape-fee-navigator.ts`, near the top of `main()` (after line 1097)

**Problem:** No lock file. Two simultaneous scraper instances would race on all JSON output files, causing corrupt data or silent overwrites.

**Fix:** Add a simple PID-based lock file at the start of `main()`:

```typescript
const LOCK_FILE = path.join(OUTPUT_DIR, '.scraper.lock');

function acquireLock(): void {
  if (fs.existsSync(LOCK_FILE)) {
    const pid = parseInt(fs.readFileSync(LOCK_FILE, 'utf-8').trim(), 10);
    try {
      process.kill(pid, 0); // Check if process is still running
      console.error(`Another scraper instance is running (PID ${pid}). Exiting.`);
      process.exit(1);
    } catch {
      console.warn(`  [WARN] Stale lock file found (PID ${pid} not running). Removing.`);
      fs.unlinkSync(LOCK_FILE);
    }
  }
  fs.writeFileSync(LOCK_FILE, String(process.pid));
}

function releaseLock(): void {
  if (fs.existsSync(LOCK_FILE)) {
    fs.unlinkSync(LOCK_FILE);
  }
}
```

Call `acquireLock()` at the start of `main()`, `releaseLock()` at the end, and add a `process.on('exit', releaseLock)` handler. Also add `'.scraper.lock'` to `.gitignore` if not already there.

---

## MEDIUM Fixes (P2) — Fix for robustness

### M-1: NULL unique index on `hsc_modifier_eligibility`

**File:** `packages/shared/src/schemas/db/reference.schema.ts`, lines 281-288

**Problem:** The unique index on `(hscCode, modifierType, subCode, calls, versionId)` uses PostgreSQL's default `NULLS DISTINCT` behavior. Since 72% of rows (29,772 of 41,269) have `calls = NULL` (converted from empty string in seed), the unique constraint doesn't actually enforce uniqueness for most rows.

**Fix:** Change the seed's empty-string handling (`apps/api/src/seed.ts`, line 830) from `null` to a sentinel value:

```typescript
calls: m.calls === '' ? '-' : m.calls,
```

Also update the validation script (`scripts/validate-fee-navigator-data.ts`, line 311) dedup key to match:
```typescript
const key = `${m.hscCode}|${m.type}|${m.code}|${m.calls}`;
```
(This already uses the raw `calls` value including empty string, so it's consistent with the scraper's dedup. No change needed in the validation script itself, but the seed must match.)

### M-2: Post-scrape validation exit code 2

**File:** `scripts/scrape-fee-navigator.ts`, lines 1146-1161

**Problem:** The scraper runs validation AFTER scraping but BEFORE enrichment. Since enrichment hasn't run yet, all enrichment minimums are zero, causing validation to fail with exit code 2. This looks like a failure even though the data is correct.

**Fix:** Pass a `--skip-enrichment` flag to the post-scrape validation:

In `scrape-fee-navigator.ts`, change line 1154:
```typescript
execSync(`"${tsxPath}" "${validateScript}" --skip-enrichment`, { stdio: 'inherit' });
```

In `validate-fee-navigator-data.ts`, add a flag check before the enrichment section (before line 461):
```typescript
const skipEnrichment = process.argv.includes('--skip-enrichment');
```

Then wrap the enrichment minimums loop (lines 473-481) in:
```typescript
if (!skipEnrichment) {
  // existing enrichment minimum checks...
} else {
  if (!jsonMode) console.log('  (Enrichment checks skipped — run after enrichment)');
}
```

### M-3: Frequency regex gaps — missing "twice" and edge cases

**File:** `scripts/enrich-hsc-data.ts`

**Problem:** The `extractFrequencyLimit()` function misses 4 valid patterns:
1. `"twice"` is not in `WORD_NUMBERS` map (line 518-522)
2. Parenthetical interruptions between "maximum of N" and "per day"
3. Non-standard nouns like `"communication"` instead of `"claims"`
4. `"Only one [noun] per [period]"` pattern not covered

**Fix:**

Add `"twice"` to the WORD_NUMBERS map at line 522:
```typescript
const WORD_NUMBERS: Record<string, number> = {
  once: 1, twice: 2,  // <-- add these
  one: 1, two: 2, three: 3, four: 4, five: 5,
  six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
  eleven: 11, twelve: 12, fifteen: 15, twenty: 20,
};
```

Update the `NUM` regex fragment at line 531 to include `twice`:
```typescript
const NUM = String.raw`(?:(\d+)\s*|(\b(?:once|twice|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|fifteen|twenty)\b)\s*)`;
```

Update `parseNumberOrWord` to handle the map correctly (it already does via `WORD_NUMBERS[wordGroup.toLowerCase()]`).

Add an additional pattern after the existing frequency patterns (around line 640) to catch "Only one/two [noun] per [period]":
```typescript
// Fallback: "Only one/two [noun] per [period]"
if (!result.restriction && !result.maxPerDay) {
  const onlyPattern = new RegExp(
    String.raw`[Oo]nly\s+${NUM}(?:\([^)]*\)\s*)?(?:\w+\s+){0,3}(?:may\s+be\s+(?:claimed|billed)\s+)?per\s+(?:patient\s*,?\s*(?:per\s*)?)?(?:physician\s*,?\s*(?:per\s*)?)?(day|calendar year|benefit year|year|calendar month|month|calendar week|week|lifetime|shift|session)`,
    'i',
  );
  const onlyMatch = notes.match(onlyPattern);
  if (onlyMatch) {
    const count = parseNumberOrWord(onlyMatch[1], onlyMatch[2]) ?? 1;
    const period = onlyMatch[3].toLowerCase().replace(/\s+/g, '_');
    if (period === 'day') {
      result.maxPerDay = count;
    } else {
      result.restriction = { text: onlyMatch[0].trim(), count, period };
    }
  }
}
```

### M-4: BFS tree expansion uses raw regex instead of Cheerio

**File:** `scripts/scrape-fee-navigator.ts`, lines 329-342

**Problem:** The inner HTML from tree expansion is parsed with a raw regex `class="node expandable" data-key="(\d+)"` instead of Cheerio. If Fee Navigator changes class order (`expandable node` instead of `node expandable`) or adds attributes between `class` and `data-key`, entire subtrees would be silently missed.

**Fix:** Replace the raw regex parsing with Cheerio:

```typescript
async function expandNode(
  expandedKeys: string[],
  expandKey: string,
): Promise<{ expandables: string[]; viewables: string[] }> {
  const body = `expanded=${expandedKeys.join(',')}&expand=${expandKey}`;

  const xml = await fetchWithRetry(expandUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  const html = decodeHtmlEntities(xml);
  if (!html) return { expandables: [], viewables: [] };

  const $ = cheerio.load(html);

  const expandables: string[] = [];
  $('div.node.expandable, a.node.expandable, [class*="expandable"]').each((_i, el) => {
    const key = $(el).attr('data-key');
    if (key && /^\d+$/.test(key)) expandables.push(key);
  });

  const viewables: string[] = [];
  $('a[href*="/fee-navigator/hsc/"]').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const match = href.match(/\/fee-navigator\/hsc\/([^"?&#]+)/);
    if (match) viewables.push(decodeURIComponent(match[1]));
  });

  return { expandables, viewables };
}
```

### M-5: Explanatory code detail fetch errors silently swallowed

**File:** `scripts/scrape-fee-navigator.ts`, lines 1053-1055

**Problem:** The catch block is completely empty — no error counting, no logging, no reporting. Impossible to know how many detail fetches failed.

**Fix:** Add error tracking:

```typescript
let detailFetchErrors = 0;
// ... (in the loop)
} catch (err) {
  detailFetchErrors++;
  // Detail page may not exist for all codes; keep what we have
}
// ... (after the loop)
if (detailFetchErrors > 0) {
  console.log(`  ${detailFetchErrors} detail page fetches failed (using tree-expansion descriptions as fallback)`);
}
```

Add `detailFetchErrors` to the returned errors array if the count exceeds a threshold (e.g., >10):
```typescript
if (detailFetchErrors > 10) {
  errors.push(`${detailFetchErrors} explanatory code detail fetches failed — descriptions may be incomplete`);
}
```

### M-6: Bundling exclusion code normalization mismatch

**File:** `scripts/enrich-hsc-data.ts`, function `extractHscCodesFromText` (lines 433-458)

**Problem:** The `extractHscCodesFromText()` function extracts codes from notes text as-is. When notes write `65.7B` without a space, it's extracted as `65.7B` — but the canonical form in `hsc-codes.json` is `65.7 B`. Three bundling exclusions on code `54.6` are affected:
- `65.7B` → should be `65.7 B` (exists)
- `65.8B` → should be `65.8 B` (exists)
- `65.8C` → should be `65.8 C` (does not exist — phantom code)

At billing time, bundling rule lookups would fail to match because the DB stores `65.7B` while claims use `65.7 B`.

**Fix:** Add a normalization step to `extractBundlingExclusions()`. After extracting codes, normalize them against the canonical code set. Add a parameter to receive the canonical codes:

At the top of the `main()` function, build a normalization map:
```typescript
// Build code normalization map: "03.7A" -> "03.7 A", etc.
const canonicalCodes = new Set(hscCodes.map(h => h.hscCode));
const codeNormMap = new Map<string, string>();
for (const canonical of canonicalCodes) {
  // Create no-space variant as lookup key
  const noSpace = canonical.replace(/\s+/g, '');
  if (noSpace !== canonical) {
    codeNormMap.set(noSpace, canonical);
  }
}
```

Then in `extractHscCodesFromText`, add normalization at the end before returning:
```typescript
return [...new Set(codes)].map(c => {
  const noSpace = c.replace(/\s+/g, '');
  return codeNormMap.get(noSpace) ?? c;
});
```

Pass `codeNormMap` into the enrichment functions or make it module-level.

### M-7: Specialty extraction false positive on conditional phrases

**File:** `scripts/enrich-hsc-data.ts`, function `normalizeSpecialty` (lines 87-111)

**Problem:** Code `03.03AI` has notes "03.05A may be claimed by the receiving physician after 30 minutes of time related to care of the patient has been spent" — this is extracted as a specialty restriction. The string "the receiving physician after 30 minutes of time related to care of the patient has been spent" passes `normalizeSpecialty()` because it doesn't match any rejection filter.

**Fix:** Add a length-based filter and a numeric content filter to `normalizeSpecialty()`:

```typescript
// Filter values that are too long to be a specialty name (likely a sentence fragment)
if (trimmed.length > 60) return null;

// Filter values containing numeric time/quantity phrases (likely conditional clauses)
if (/\d+\s*(?:minutes?|hours?|days?|months?|years?|times?)/.test(trimmed)) return null;
```

Add these checks after the existing `length < 4` filter at line 90.

### M-8: Referral false negative — "referral is supplied by" not matched

**File:** `scripts/enrich-hsc-data.ts`, lines 859-863

**Problem:** Code `X313A` notes say "May only be claimed when the referral is supplied by a urologist (UROL) or general surgeon (GNSG)" — the enrichment regex doesn't match "referral is supplied by".

**Fix:** Expand the notes-based referral pattern at line 860:

```typescript
if (/(?:referral\s+(?:must|is\s+required|required|is\s+supplied)|must\s+be\s+referred|requires?\s+(?:a\s+)?referral|when\s+the\s+referral\s+is\s+(?:supplied|provided))/i.test(hsc.notes)) {
```

### M-9: Partial re-scrape after enrichment creates inconsistent state

**File:** `scripts/scrape-fee-navigator.ts`, lines 570-584

**Problem:** If you scrape → enrich → resume-scrape, the resumed output has a mix of enriched records (from the progress file) and non-enriched records (freshly scraped). No warning is produced.

**Fix:** Detect enrichment fields on loaded data and warn:

After line 583 (`console.log(...Resuming from previous run...)`), add:
```typescript
// Warn if existing data has enrichment fields (will be lost for re-scraped codes)
const hasEnrichment = existingHsc.some(h =>
  h.requiresReferral !== undefined ||
  h.specialtyRestrictions !== undefined ||
  h.bundlingExclusions !== undefined
);
if (hasEnrichment) {
  console.warn('  [WARN] Existing hsc-codes.json contains enrichment fields.');
  console.warn('  Re-scraped codes will lose enrichment. Run enrich-hsc-data.ts after scraping completes.');
}
```

---

## LOW Fixes (P3) — Quality improvements

### L-1: Version label stale

**File:** `apps/api/src/seed.ts`, lines 758-762

**Fix:** Update the version metadata to reflect the actual data:
```typescript
versionLabel: 'SOMB 2025-2026 - Fee Navigator (scraped 2026-03-03)',
effectiveFrom: '2025-04-01',  // Keep this — it's the SOMB effective date, not the scrape date
```

### L-2: `&apos;` entity not handled

**File:** `scripts/lib/fee-navigator-utils.ts`, line 131

**Fix:** Add before the `&amp;` replacement (line 134):
```typescript
.replace(/&apos;/g, "'")
```

### L-3: Progress counter overflow display

**File:** `scripts/scrape-fee-navigator.ts`, line 593

**Fix:** Change the counter to use only the remaining-codes index:
```typescript
const overall = i + 1;
// ...
console.log(`  [${overall}/${remaining.length}] Scraped ${code} ...`);
```

### L-4: rootSectionKeyCount is 0 when cache is used

**File:** `scripts/scrape-fee-navigator.ts`, line 301

**Fix:** Load the previous metadata to get the cached count:
```typescript
if (cacheAge < CACHE_MAX_AGE_MS) {
  // ...
  const prevMeta = loadJson<ScrapeMetadata>(OUTPUT_DIR, 'scrape-metadata.json');
  return { codes: cached, rootSectionKeyCount: prevMeta?.counts?.rootSectionKeys ?? 0 };
}
```

### L-5: Dead fee type categories

**File:** `scripts/scrape-fee-navigator.ts`, lines 108-121

**Info only — no fix needed.** `CONSULTATION`, `LABORATORY`, `RADIOLOGY` are defined in the fee type map but never produced by any current Fee Navigator category. These are forward-compatible entries in case the SOMB adds new category prefixes. Leave them as-is.

### L-6: `applicableHscFilter { all: true }` never triggers

**File:** `apps/api/src/seed.ts`, lines 891-895

**Info only — no fix needed.** The 2,500-code threshold is never exceeded (max is BMI at 2,008). The branch is dead code but harmless. Leave as-is for future-proofing.

### L-7: No FK from `hsc_modifier_eligibility.hscCode` to `hsc_codes`

**Info only — defer to schema hardening pass.** Adding a FK would require a composite index on `(hsc_code, version_id)` in `hsc_codes` and matching the FK reference. This is a schema migration concern, not a scraper fix.

### L-8: Seed has no re-seed path

**File:** `apps/api/src/seed.ts`, lines 212-218

**Fix:** Add a `--force` flag that truncates seeded tables before re-inserting:

```typescript
const forceReseed = process.argv.includes('--force');

const existing = await db.select({ userId: users.userId })
  .from(users).where(eq(users.userId, DR_CHEN_ID));

if (existing.length > 0 && !forceReseed) {
  console.log('Seed data already exists (dr-chen found). Skipping. Use --force to re-seed.');
  await pool.end();
  return;
}

if (forceReseed && existing.length > 0) {
  console.log('  --force: Truncating existing seed data...');
  // Truncate in reverse dependency order with CASCADE
  await db.execute(sql`TRUNCATE TABLE bundling_rules CASCADE`);
  await db.execute(sql`TRUNCATE TABLE explanatory_codes CASCADE`);
  await db.execute(sql`TRUNCATE TABLE governing_rules CASCADE`);
  await db.execute(sql`TRUNCATE TABLE hsc_modifier_eligibility CASCADE`);
  await db.execute(sql`TRUNCATE TABLE modifier_definitions CASCADE`);
  await db.execute(sql`TRUNCATE TABLE hsc_codes CASCADE`);
  await db.execute(sql`TRUNCATE TABLE reference_data_versions CASCADE`);
  // ... (add other seeded tables as needed)
  console.log('  Truncation complete. Re-seeding...');
}
```

**Note:** Only implement the reference-data portion of `--force` now. Full seed reset (users, providers, etc.) is a larger concern for a separate task.

---

## Deferred Items (not in scope for this fix pass)

These were identified in the audit but are deferred to future work:

| Item | Reason to Defer |
|------|-----------------|
| **GR fullText loses HTML structure** | Requires storing raw HTML alongside text. Architectural decision for Domain 2 Reference Data API. |
| **No data freshness detection** | Requires content hashing infrastructure. Plan for next scrape cycle. |
| **User-Agent impersonation** | Will change to honest UA (`Meritum-SOMB-Scraper/1.0`) before go-live. Not needed for development. |
| **No `robots.txt` check** | `apps.albertadoctors.org/robots.txt` returns 404 (no file exists). Will add `robots.txt` fetching before go-live. |
| **Discovery cache doesn't detect deprecated codes** | Low impact. Periodic `--force-discovery` scrapes handle this. |
| **HTML parser brittleness (no fallback selectors)** | Significant refactor. Plan for scraper V3 with selector versioning. |
| **No FK from hsc_modifier_eligibility to hsc_codes** | Schema migration concern. Defer to schema hardening pass. |

---

## Verification

After all fixes, run these commands to verify nothing broke:

```bash
cd /workspace/projects

# 1. Validation should still pass
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts

# 2. Audit metrics should be unchanged
./apps/api/node_modules/.bin/tsx scripts/audit-fee-navigator.ts --metrics-only

# 3. TypeScript compilation should pass
npx tsc --noEmit -p apps/api/tsconfig.json

# 4. Verify the category marker filter works (should output 0 oversized pairs)
node -e '
var hsc = require("./scripts/data/fee-navigator/hsc-codes.json");
var pairs = new Map();
hsc.forEach(function(h){
  if(h.bundlingExclusions){
    h.bundlingExclusions.forEach(function(e){
      if(e.excludedCode.startsWith("*")) return;
      if(h.hscCode === e.excludedCode) return;
      var a = h.hscCode < e.excludedCode ? h.hscCode : e.excludedCode;
      var b = h.hscCode < e.excludedCode ? e.excludedCode : h.hscCode;
      if(a.length > 10 || b.length > 10) pairs.set(a+":"+b, {a:a,b:b});
    });
  }
});
console.log("Oversized bundling pairs after filter:", pairs.size);
'

# 5. Verify explanatory code severity distribution
node -e '
var codes = require("./scripts/data/fee-navigator/explanatory-codes.json");
var map = {
  "PATIENT REGISTRATION": "ERROR",
  "PRACTITIONER REGISTRATION": "ERROR",
  "INELIGIBLE SERVICES": "ERROR",
  "ADJUSTMENTS": "WARNING",
  "SURGICAL PROCEDURES": "WARNING",
  "MINOR PROCEDURES": "WARNING",
  "ANESTHESIA": "WARNING",
  "CONSULTATIONS/VISITS": "WARNING",
  "DENTAL ASSESSMENT": "WARNING",
};
var counts = {ERROR: 0, WARNING: 0, INFO: 0};
codes.forEach(function(c){ counts[map[c.category] || "INFO"]++; });
console.log("Severity distribution:", JSON.stringify(counts));
'
```

Expected output:
- Validation: `PASS (0 errors, 0 warnings)` (or 0 errors with `--skip-enrichment` caveat)
- Audit metrics: unchanged from pre-fix values
- TypeScript: no errors
- Oversized pairs: `0`
- Severity distribution: `{"ERROR": ~30, "WARNING": ~50, "INFO": ~43}` (approximate)

---

## Implementation Order

Apply fixes in this order to minimize interdependencies:

1. **`scripts/lib/fee-navigator-utils.ts`** — H-1 (block detection), H-3 (atomic writes), L-2 (`&apos;`)
2. **`scripts/scrape-fee-navigator.ts`** — H-2 (modifier discovery), H-4 (lock file), M-2 (exit code), M-4 (BFS cheerio), M-5 (detail fetch logging), M-9 (enrichment warning), L-3 (counter), L-4 (cache count)
3. **`scripts/enrich-hsc-data.ts`** — H-3 (backup + atomic write), M-3 (frequency regex), M-6 (code normalization), M-7 (specialty filter), M-8 (referral pattern)
4. **`scripts/validate-fee-navigator-data.ts`** — M-2 (`--skip-enrichment` flag)
5. **`packages/shared/src/schemas/db/reference.schema.ts`** — no changes (M-1 is a seed-side fix)
6. **`apps/api/src/seed.ts`** — C-1 (category marker filter), C-2 (severity mapping), M-1 (NULL calls sentinel), L-1 (version label), L-8 (re-seed support)
7. **Run verification commands**

### After Fixes — Re-run Enrichment

After applying M-6 (code normalization) and M-7 (specialty filter), re-run the enrichment script to update the data:

```bash
./apps/api/node_modules/.bin/tsx scripts/enrich-hsc-data.ts
```

This will:
- Fix the 3 bundling exclusion codes with space mismatches
- Remove the false positive specialty restriction on `03.03AI`
- Add the missing referral flag on `X313A`
- Extract ~4 additional frequency restrictions (from "twice", "only one" patterns)
- Validation should still pass after re-enrichment

### Commit

After all fixes pass verification, commit with a message like:
```
fix(scraper): apply 28 audit findings from 2026-03-03 pipeline review

Critical: filter category markers from bundling rules, fix explanatory
code severity mapping. High: tighten block detection, fix modifier
discovery race condition, add atomic writes and lock file. Medium:
frequency regex gaps, code normalization, specialty/referral regex
improvements. Low: version label, entity decoding, counter display.
```
