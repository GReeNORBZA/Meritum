# Meritum — Fee Navigator Scraper & Enrichment Pipeline

Functional Requirements — V2 Correctness, Robustness & Data Quality

SCR Domain | Critical Path: Prerequisite to Domain 2 Seed & Domain 4.1 Validation

Meritum Health Technologies Inc.

Version 2.0 | March 2026

CONFIDENTIAL

---

# Table of Contents

1. [Domain Overview](#1-domain-overview)
2. [Review Findings Summary](#2-review-findings-summary)
3. [Phase 1 — Enrichment Regex Fixes](#3-phase-1--enrichment-regex-fixes)
4. [Phase 2 — Enrichment Coverage Expansion](#4-phase-2--enrichment-coverage-expansion)
5. [Phase 3 — Scraper Safety & Robustness](#5-phase-3--scraper-safety--robustness)
6. [Phase 4 — Shared Utilities Hardening](#6-phase-4--shared-utilities-hardening)
7. [Phase 5 — Seed & Schema Fixes](#7-phase-5--seed--schema-fixes)
8. [Phase 6 — Validation Hardening](#8-phase-6--validation-hardening)
9. [Phase 7 — Data Quality & Cleanup](#9-phase-7--data-quality--cleanup)
10. [Phase 8 — Re-scrape & Verify](#10-phase-8--re-scrape--verify)
11. [Task Dependency Graph](#11-task-dependency-graph)

---

# 1. Domain Overview

## 1.1 Purpose

This FRD addresses all findings from the March 2026 V2 code review of the Fee Navigator scraper and enrichment pipeline. The V1 FRD (18 tasks, SCR-001 through SCR-070) has been fully implemented. This V2 review found 40+ additional issues ranging from critical data loss (935 codes with notes producing zero enrichment) to low-impact cleanup.

## 1.2 Scope

All issues discovered during the V2 comprehensive review, organized into 8 phases:

- **12 enrichment regex bugs** causing missed extraction (age, frequency, anesthesia, bundling, specialty)
- **5 scraper safety gaps** (circuit breaker, cache invalidation, metadata drift, GR range)
- **3 shared utility gaps** (body timeout, named entities, validateResponse edge cases)
- **6 seed/schema bugs** (duplicate modifier rows, missing category, self-referencing bundling, transaction safety)
- **5 validation gaps** (thresholds, modifier dedup, enrichment minimums, GR resolution)
- **4 data quality issues** (modifier description cleanup, specialty normalization, code verification)
- **1 re-scrape & verify task** to apply fixes to live data

## 1.3 Out of Scope

Same as V1 FRD Section 1.3 — no changes to out-of-scope items.

## 1.4 Dependencies

| Depends On | Reason |
|---|---|
| V1 pipeline (SCR-001 through SCR-070) fully committed | V2 builds on V1's infrastructure |
| Node.js 20+ with native `fetch` | AbortController support |
| Existing scrape output in `scripts/data/fee-navigator/` | Enrichment reads hsc-codes.json |
| DB schema `packages/shared/src/schemas/db/reference.schema.ts` | Schema alignment tasks modify columns |

| Provides To | Reason |
|---|---|
| Domain 2 seed pipeline | Correct, complete JSON for database insertion |
| Domain 4.1 validation engine | Accurate HSC fields for checks A1–A19 |
| Domain 7 AI Coach | Correct notes, governing rule references, bundling data |

---

# 2. Review Findings Summary

## 2.1 P0 — Critical Data Loss

| # | Finding | Impact | Task |
|---|---|---|---|
| 1 | 935 codes with notes text produce zero enrichment (318 bundling, 216 age, 41 frequency missed) | ~30% of enrichable codes have no structured data extracted | SCR-110, SCR-111, SCR-112 |
| 2 | `extractHscCodesFromText` regex `/\b(\d{2}\.\d{2,3}[A-Z]{0,3})\b/g` fails on HSC codes with spaces (e.g., "03.7 A", "E  1") | Space-containing codes never matched in bundling exclusions | SCR-110 |
| 3 | "under X years of age" age pattern not captured (no "younger/under/and under" keyword after age) | ~216 age restrictions missed entirely | SCR-111 |
| 4 | "once every N years" frequency not captured (uses "every" not "per") | ~41 frequency limits missed | SCR-112 |
| 5 | Discovery cache (`_discovered-codes.json`) never invalidated — stale cache prevents detecting new codes | Re-scrape silently reuses old code list even if Fee Navigator adds codes | SCR-130 |
| 6 | Seed crashes on unique index violation: `hsc_modifier_eligibility` has 4,955 duplicate rows from scraper | Seed fails entirely, no reference data loaded | SCR-150 |

## 2.2 P1 — High Impact

| # | Finding | Impact | Task |
|---|---|---|---|
| 7 | Anesthesia regex requires "general" — misses "under anesthesia", "requires anesthesia" without "general" | Anesthesia-required codes incorrectly flagged false | SCR-111 |
| 8 | No circuit breaker on mass scrape failure — 50+ consecutive errors and scraper keeps going | Hours of wasted requests against a possibly-down server | SCR-131 |
| 9 | Specialty restrictions contain 58 sentence-fragment garbage values (e.g., "physicians working in") | Garbage specialty data in DB, incorrect A6 validation | SCR-170 |
| 10 | Governing rule range hardcoded 1–19 in `scrapeGoverningRules` despite dynamic sub-rule discovery | New top-level rules (20+) silently missed | SCR-132 |
| 11 | Metadata `rootSectionKeys` always set to 0 (line 1021 of scraper) | Drift detection useless — always 0 compared against actual count | SCR-133 |
| 12 | Explanatory code `category` field scraped but dropped by seed — `severity` hardcoded to 'INFO' | Loss of category grouping for explanatory codes | SCR-152 |
| 13 | `fetchWithRetry` AbortController timeout doesn't cover response body transfer | Slow body download can hang indefinitely after headers received | SCR-140 |
| 14 | Colon-delimited specialty lists not split (e.g., "May only be claimed by Psychiatry: Adult Psychiatry") | Specialty extracted as single string with colon | SCR-120 |

## 2.3 P2 — Medium Impact

| # | Finding | Impact | Task |
|---|---|---|---|
| 15 | `indexOf` bug: `text.indexOf(code)` finds first occurrence, not the current match position — context check unreliable | May skip valid HSC codes or include invalid ones | SCR-110 |
| 16 | Compound age restriction dead code: AGE_PATTERNS already matches "under X years" individually, so compound block never triggers | No functional impact but confusing dead code | SCR-111 |
| 17 | "per shift" frequency period not in freqPattern alternation | Shift-based frequency limits missed | SCR-112 |
| 18 | "maximum of X calls or Y hours" compound frequency not parsed | Compound frequency limits recorded as simple count | SCR-112 |
| 19 | GR 1.33 `codePattern` requires alpha suffix (`[A-Z]{1,3}`) — misses codes like "03.03" without suffix | Numeric-only codes in GR 1.33 not captured | SCR-121 |
| 20 | `m.calls \|\| null` in seed — empty string is falsy so `calls=""` becomes `null` | Correct but fragile — explicit `=== ''` check is safer | SCR-151 |
| 21 | Self-referencing bundling pairs (codeA === codeB) not filtered | Meaningless "code cannot be billed with itself" rows | SCR-153 |
| 22 | Bundling rule description always says `${h.hscCode} may not be claimed with ${excl.excludedCode}` — after canonical reorder, direction is wrong | Description text misleading when codeA/codeB are swapped | SCR-153 |
| 23 | No transaction wrapper around seed inserts | Partial seed on crash leaves DB in inconsistent state | SCR-154 |
| 24 | Modifier eligibility unique index missing `calls` column | 4,955 rows that differ only in `calls` treated as duplicates | SCR-150 |

## 2.4 P3 — Low Impact

| # | Finding | Impact | Task |
|---|---|---|---|
| 25 | Modifier definition descriptions include AMA footer text and repeated content | Noise in descriptions shown to physicians | SCR-171 |
| 26 | Named HTML entities (`&nbsp;`, `&ndash;`, `&mdash;`, `&rsquo;`, `&lsquo;`) not decoded | Rare entities appear as raw text in descriptions | SCR-141 |
| 27 | Validation thresholds too loose (HSC ≥ 3000 passes with 3001 but current data has 3089) | A 3% data loss wouldn't be detected | SCR-160 |
| 28 | No modifier row deduplication check in validation | 4,955 duplicates pass validation silently | SCR-161 |
| 29 | Enrichment stats always pass (unconditional `pass()` calls) | Zero enrichment would still show green | SCR-162 |
| 30 | No GR reference resolution check in validation | GR references like "4.4.8" that don't match any rule go undetected | SCR-163 |
| 31 | `action` varchar(30) tight margin for modifier actions | Long action descriptions could truncate | SCR-155 |
| 32 | 65 visit-type codes have zero modifier rows — may indicate scraping issue | Possible missed modifiers for visit codes | SCR-172 |
| 33 | `validateResponse` only checks first 2000 chars for block indicators | Block page with late indicators may be missed | SCR-142 |

---

# 3. Phase 1 — Enrichment Regex Fixes

## SCR-110: Fix HSC code extraction from text

**Problem**: Three bugs in `extractHscCodesFromText` (line 163 of `enrich-hsc-data.ts`):

1. The regex `/\b(\d{2}\.\d{2,3}[A-Z]{0,3})\b/g` cannot match HSC codes with embedded spaces like "03.7 A", "E  1", or "E121A" (letter-prefixed codes).

2. The context check at line 172 uses `text.indexOf(code)` which finds the *first* occurrence of the code in the text, not the current regex match position. If the same code appears twice with different context, the wrong context is checked.

3. The function only recognizes numeric-prefix codes (`\d{2}\.`), not letter-prefix codes (`E`, `X` prefixed).

**Solution**:

```typescript
function extractHscCodesFromText(text: string): string[] {
  const codes: string[] = [];
  // Pattern 1: Standard numeric codes (with optional space before alpha suffix)
  //   e.g., "03.03A", "03.7 A", "15.3", "48.15B"
  const numericPattern = /\b(\d{2}\.\d{1,3}\s?[A-Z]{0,3})\b/g;
  // Pattern 2: Letter-prefixed codes
  //   e.g., "E  1", "E 10", "E103", "E121A", "X 38"
  const letterPattern = /\b([A-Z]\s*\d{1,3}[A-Z]?)\b/g;

  for (const pattern of [numericPattern, letterPattern]) {
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const code = match[1];
      // Use match.index for context, not indexOf
      const contextStart = Math.max(0, match.index - 10);
      const context = text.slice(contextStart, match.index);
      if (!context.includes('$') && !context.match(/fee\s*$/i)) {
        // Normalize spaces for consistency
        codes.push(code.replace(/\s+/g, ' ').trim());
      }
    }
  }
  return [...new Set(codes)];
}
```

**Key changes**:
- Added space-tolerant regex for numeric codes: `\d{2}\.\d{1,3}\s?[A-Z]{0,3}`
- Added letter-prefix pattern for E/X codes
- Fixed context check to use `match.index` instead of `text.indexOf(code)`
- Deduplicate results

**Verify**: Run enrichment, count bundling exclusions. Should increase from 135 to ~318+ codes.

## SCR-111: Fix age restriction extraction

**Problem**: Three issues in `extractAgeRestriction` (line 203):

1. **Missing "under X years" without qualifier**: The current AGE_PATTERNS require a trailing word like "younger", "under", or "and under". But Fee Navigator notes also use "under 18 years of age" (the keyword "under" appears *before* the number, not after). This pattern is not matched.

2. **Anesthesia regex too restrictive**: `extractAnesthesiaRequirement` (line 314) requires "general" before "anesthesia" or uses `requires?\s+(?:general\s+)?anesthesia`. But notes also say "under anesthesia" or "performed under anesthesia" without "general".

3. **Compound age dead code**: The compound check at lines 227–241 can never trigger because the `max_years` pattern in AGE_PATTERNS already matches "under X years", returning before reaching the compound block.

**Solution**:

```typescript
const AGE_PATTERNS: AgePattern[] = [
  // Order matters: more specific patterns first
  { tag: 'range_years', regex: /between\s+(\d+)\s*and\s*(\d+)\s*years/i },
  { tag: 'range_ages',  regex: /aged?\s+(\d+)\s*(?:to|-)\s*(\d+)/i },
  { tag: 'max_months', regex: /(\d+)\s*months?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+under)/i },
  { tag: 'max_months', regex: /(?:under|younger\s+than)\s+(\d+)\s*months/i },
  { tag: 'max_years',  regex: /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+under)/i },
  { tag: 'max_years',  regex: /(?:under|younger\s+than)\s+(\d+)\s*years/i },
  { tag: 'min_years',  regex: /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i },
  { tag: 'min_years',  regex: /(?:over|older\s+than)\s+(\d+)\s*years/i },
  { tag: 'min_months', regex: /(\d+)\s*months?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i },
];
```

Remove the compound dead code block (lines 227–241).

Fix anesthesia regex:

```typescript
function extractAnesthesiaRequirement(notes: string): boolean {
  return /(?:under\s+(?:general\s+)?anesthesia|requires?\s+(?:general\s+)?anesthesia|procedural\s+sedation)/i.test(notes);
}
```

**Verify**: Run enrichment, count age restrictions. Should increase from 23 to ~50+. Count anesthesia codes — should increase.

## SCR-112: Fix frequency restriction extraction

**Problem**: Three gaps in `extractFrequencyLimit` (line 254):

1. **"once every N years" not captured**: The general frequency regex uses `(?:per|every|each)` but only after a count word. Notes like "once every 3 years" should match but may fail because "every" appears after "once" without the expected structure.

2. **"per shift" not in period alternation**: Line 291 lists periods: `year|calendar year|...`. "shift" is not included.

3. **"maximum of X calls or Y hours" compound frequency**: Some notes describe compound limits like "maximum of 15 calls or 6 hours per day". Only the first part is captured.

**Solution**:

```typescript
const freqPattern =
  /(?:(?:once|(\d+)\s*times?)|(?:a\s+)?maximum\s+(?:of\s+)?(\d+)(?:\s+(?:calls?|claims?|sessions?))?)\s*(?:per|every|each|in\s+a)\s*(?:patient\s*,?\s*(?:per\s*)?)?(?:physician\s*,?\s*(?:per\s*)?)?(year|calendar year|benefit year|lifetime|12[- ]?month|pregnancy|calendar week|calendar month|week|month|365[- ]?day|shift|session|admission)/i;
```

Key changes:
- Added `in\s+a` as alternative to `per|every|each` (for "once in a lifetime")
- Added `shift`, `session`, `admission` to period list

**Verify**: Run enrichment, count frequency restrictions. Should increase from 21 to ~40+.

---

# 4. Phase 2 — Enrichment Coverage Expansion

## SCR-120: Fix specialty restriction extraction

**Problem**: `extractSpecialtyRestrictions` (line 88) doesn't split colon-delimited specialty lists. Notes like "May only be claimed by Psychiatry: Adult Psychiatry" extract as a single string "Psychiatry: Adult Psychiatry" instead of splitting into ["Psychiatry", "Adult Psychiatry"]. Additionally, the splitting regex doesn't handle semicolons.

**Solution**:

```typescript
function extractSpecialtyRestrictions(notes: string): string[] {
  const restrictions: string[] = [];
  const pattern =
    /(?:May only be claimed by|only\s+.*?claimed by)\s+(.+?)(?:\.(?!\d)|$)/gi;
  let match;
  while ((match = pattern.exec(notes)) !== null) {
    const raw = match[1].trim();
    // Split on comma, or, and, semicolon, colon (when followed by space + capital letter)
    const parts = raw
      .split(/\s*(?:,(?!\d)\s*(?:or|and)\s*|,(?!\d)\s*|;\s*|\s+or\s+|\s+and\s+|:\s+(?=[A-Z]))\s*/i)
      .map((s) => s.trim())
      .filter(
        (s) =>
          s.length > 2 &&
          !s.match(
            /^(?:a|an|the|physicians?|who|with|working|in|at|for|those)$/i,
          ),
      );
    restrictions.push(...parts);
  }
  return [...new Set(restrictions)];
}
```

**Verify**: Run enrichment, count specialty restrictions. Verify no garbage fragments remain.

## SCR-121: Fix GR 1.33 code pattern

**Problem**: In `parseGR133` (line 407), the code pattern requires at least one alpha suffix character: `/\b(\d{2}\.\d{2}[A-Z]{1,3})\b/g`. This misses codes like "03.03" that appear without an alpha suffix in GR 1.33 text.

**Solution**:

```typescript
// Allow zero or more alpha suffix characters
const codePattern = /\b(\d{2}\.\d{2,3}[A-Z]{0,3})\b/g;
```

**Verify**: Run enrichment, compare facility designation counts. Verify no false positives from version numbers.

---

# 5. Phase 3 — Scraper Safety & Robustness

## SCR-130: Add discovery cache invalidation

**Problem**: `discoverAllHscCodes()` (line 285) caches discovered codes in `_discovered-codes.json` and reuses them on subsequent runs. There is no flag to force re-discovery. If the Fee Navigator adds new sections or codes, re-scraping with the stale cache misses them entirely.

**Solution**:

Add a `--force-discovery` CLI flag and a staleness check:

```typescript
const FORCE_DISCOVERY = process.argv.includes('--force-discovery');
const CACHE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

async function discoverAllHscCodes(): Promise<string[]> {
  if (!FORCE_DISCOVERY) {
    const cachePath = path.join(OUTPUT_DIR, '_discovered-codes.json');
    if (fs.existsSync(cachePath)) {
      const stat = fs.statSync(cachePath);
      const ageMs = Date.now() - stat.mtimeMs;
      if (ageMs < CACHE_MAX_AGE_MS) {
        const cached = loadJson<string[]>(OUTPUT_DIR, '_discovered-codes.json');
        if (cached && cached.length > 0) {
          console.log(`  Found cached discovery (${cached.length} codes, ${Math.round(ageMs / 3600000)}h old). Reusing.`);
          console.log(`  Use --force-discovery to re-discover.`);
          return cached;
        }
      } else {
        console.log(`  Discovery cache is ${Math.round(ageMs / 86400000)}d old — re-discovering.`);
      }
    }
  }
  // ... existing discovery logic ...
}
```

**Verify**: Run scraper with `--force-discovery` flag. Verify discovery runs fresh.

## SCR-131: Add circuit breaker for mass failure

**Problem**: In `scrapeHscCodes` (line 554), if the server goes down or starts returning errors, the scraper silently logs errors and continues through all remaining codes. With 3,089 codes, this can waste hours of requests.

**Solution**:

Add a consecutive-error counter with configurable threshold:

```typescript
const CIRCUIT_BREAKER_THRESHOLD = 20; // Consecutive errors to trigger abort

let consecutiveErrors = 0;

for (let i = 0; i < remaining.length; i++) {
  const code = remaining[i];
  try {
    // ... existing scrape logic ...
    consecutiveErrors = 0; // Reset on success
  } catch (err) {
    consecutiveErrors++;
    errors.push(`Error scraping ${code}: ${(err as Error).message}`);
    console.error(`  [${overall}/${codes.length}] ERROR ${code}: ${(err as Error).message}`);

    if (consecutiveErrors >= CIRCUIT_BREAKER_THRESHOLD) {
      console.error(`\n  *** CIRCUIT BREAKER: ${CIRCUIT_BREAKER_THRESHOLD} consecutive errors. Aborting scrape. ***`);
      console.error(`  Last error: ${(err as Error).message}`);
      console.error(`  ${hscMap.size} codes scraped successfully before failure.\n`);
      break;
    }
  }
}
```

**Verify**: Scraper compiles. Manual test: temporarily set threshold to 1 and trigger an error to verify break behavior.

## SCR-132: Dynamic governing rule discovery

**Problem**: `scrapeGoverningRules` (line 774) uses a hardcoded `for (let i = 1; i <= 19; i++)` loop. If the Fee Navigator adds GR 20+, they are silently missed. The sub-rule discovery at line 807 is already dynamic, but top-level discovery is not.

**Solution**:

```typescript
async function discoverTopLevelRuleIds(): Promise<string[]> {
  console.log('  Discovering top-level governing rule IDs...');
  const html = await fetchWithRetry(`${BASE_URL}/governing-rules`);
  const $ = cheerio.load(html);

  const ruleIds = new Set<string>();

  // Method 1: Links to governing rule pages
  $('a[href*="/governing-rules/"]').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const match = href.match(/\/governing-rules\/(\d+)(?:\?|$|#)/);
    if (match) ruleIds.add(match[1]);
  });

  // Method 2: Expandable/viewable tree nodes
  $('div.node.viewable, a.node.viewable, div.node.expandable').each((_i, el) => {
    const key = $(el).attr('data-key');
    if (key && /^\d+$/.test(key)) ruleIds.add(key);
  });

  // Fallback: if discovery finds nothing, use 1-19
  if (ruleIds.size === 0) {
    console.warn('  [WARN] No governing rules discovered from listing page — falling back to 1-19');
    for (let i = 1; i <= 19; i++) ruleIds.add(String(i));
  }

  const sorted = Array.from(ruleIds).sort((a, b) => parseInt(a) - parseInt(b));
  console.log(`  Found ${sorted.length} top-level governing rules: [${sorted.join(', ')}]`);
  return sorted;
}
```

Replace `for (let i = 1; i <= 19; i++)` with a call to `discoverTopLevelRuleIds()`.

**Verify**: Scraper compiles. Log output shows discovered rule count.

## SCR-133: Fix metadata rootSectionKeys count

**Problem**: Line 1021 of the scraper sets `rootSectionKeys: 0`. The discovered root section keys count is not passed through from `discoverAllHscCodes` to `main()`.

**Solution**:

Return the discovered key count from `discoverAllHscCodes`:

```typescript
async function discoverAllHscCodes(): Promise<{ codes: string[]; rootSectionKeyCount: number }> {
  // ... existing discovery ...
  const rootKeys = await discoverRootSectionKeys();
  // ... expand tree using rootKeys ...
  return { codes: Array.from(allCodes), rootSectionKeyCount: rootKeys.length };
}
```

In `main()`:

```typescript
const { codes, rootSectionKeyCount } = await discoverAllHscCodes();
// ...
const metadata: ScrapeMetadata = {
  // ...
  counts: {
    rootSectionKeys: rootSectionKeyCount,
    // ...
  },
};
```

**Verify**: After scrape, check `scrape-metadata.json` → `counts.rootSectionKeys` should be ≥ 19 (not 0).

---

# 6. Phase 4 — Shared Utilities Hardening

## SCR-140: Cover response body transfer in timeout

**Problem**: In `fetchWithRetry` (line 66 of `fee-navigator-utils.ts`), the `AbortController` timer is cleared at line 74 after `await fetch()` resolves. But `fetch()` resolves when *headers* are received — the body may still be streaming. If the body stalls, `await resp.text()` at line 87 hangs indefinitely since the timer is already cleared.

**Solution**:

Move `clearTimeout` to after the body is fully read:

```typescript
try {
  const resp = await fetch(url, {
    ...options,
    signal: controller.signal,
    headers: { ...HEADERS, ...(options.headers as Record<string, string>) },
  });

  if (resp.status === 429 || resp.status === 503) {
    clearTimeout(timer);
    // ... backoff logic ...
    continue;
  }
  if (!resp.ok) {
    clearTimeout(timer);
    throw new Error(`HTTP ${resp.status} for ${url}`);
  }

  const body = await resp.text(); // Timer still running — body stall will trigger abort
  clearTimeout(timer);

  validateResponse(url, body);
  return body;
}
```

**Verify**: Scraper and enrichment scripts compile without errors.

## SCR-141: Add common named HTML entity decoding

**Problem**: `decodeHtmlEntities` (line 109 of `fee-navigator-utils.ts`) handles `&lt;`, `&gt;`, `&quot;`, `&#39;`, `&#x27;`, numeric entities, and `&amp;`. But it doesn't handle common named entities like `&nbsp;`, `&ndash;`, `&mdash;`, `&rsquo;`, `&lsquo;`, `&ldquo;`, `&rdquo;` which may appear in Fee Navigator content.

**Solution**:

Add named entity replacements before the numeric entity handlers:

```typescript
export function decodeHtmlEntities(xml: string): string {
  const contentMatch = xml.match(/<content>([\s\S]*?)<\/content>/);
  if (!contentMatch) return '';
  return contentMatch[1]
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&nbsp;/g, '\u00A0')
    .replace(/&ndash;/g, '\u2013')
    .replace(/&mdash;/g, '\u2014')
    .replace(/&rsquo;/g, '\u2019')
    .replace(/&lsquo;/g, '\u2018')
    .replace(/&rdquo;/g, '\u201D')
    .replace(/&ldquo;/g, '\u201C')
    .replace(/&hellip;/g, '\u2026')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&amp;/g, '&'); // MUST be last
}
```

**Verify**: `tsx --eval "import './scripts/lib/fee-navigator-utils.ts'"` compiles.

## SCR-142: Extend validateResponse block indicator check

**Problem**: `validateResponse` (line 33) only checks the first 2000 characters of the response body for block/CAPTCHA indicators. A block page with a large preamble could have the indicator beyond 2000 chars.

**Solution**:

Increase the check window and add additional indicators:

```typescript
export function validateResponse(url: string, body: string): void {
  if (url.includes('?ajax=')) {
    if (!body.includes('<content>') && body.trim().length > 0) {
      throw new Error(
        `Invalid AJAX response from ${url}: missing <content> wrapper. ` +
        `Response starts with: ${body.slice(0, 200)}`,
      );
    }
  }

  // Check more of the response for block indicators
  const checkLen = Math.min(body.length, 5000);
  const lower = body.slice(0, checkLen).toLowerCase();
  if (
    lower.includes('captcha') ||
    lower.includes('access denied') ||
    lower.includes('rate limit exceeded') ||
    lower.includes('too many requests') ||
    lower.includes('blocked') ||
    lower.includes('cloudflare') ||
    lower.includes('please verify you are human')
  ) {
    throw new Error(
      `Possible block detected from ${url}: response contains block indicators. ` +
      `Response starts with: ${body.slice(0, 200)}`,
    );
  }
}
```

**Verify**: `tsx --eval "import './scripts/lib/fee-navigator-utils.ts'"` compiles.

---

# 7. Phase 5 — Seed & Schema Fixes

## SCR-150: Fix modifier eligibility deduplication

**Problem**: The `hsc_modifier_eligibility` table has a unique index on `(hsc_code, modifier_type, sub_code, version_id)` but the scraped data contains rows that are identical on those columns but differ in the `calls` column. This results in 4,955 duplicate rows that cause a unique constraint violation when seeding.

**Solution** — two-part fix:

### A. Deduplicate in scraper output

In `scrapeHscCodes` after building modifier rows, deduplicate before saving:

```typescript
// Deduplicate modifier rows per code: key on (type, code, calls)
function deduplicateModifierRows(rows: HscModifierRow[]): HscModifierRow[] {
  const seen = new Set<string>();
  return rows.filter((r) => {
    const key = `${r.hscCode}|${r.type}|${r.code}|${r.calls}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
```

Call after flattening modifier rows in the save step.

### B. Update unique index in schema

Add `calls` to the unique constraint in `reference.schema.ts`:

```typescript
// In hscModifierEligibility table definition
// Change unique index from:
//   uniqueIndex('hsc_mod_elig_unique').on(table.hscCode, table.modifierType, table.subCode, table.versionId)
// To:
uniqueIndex('hsc_mod_elig_unique').on(table.hscCode, table.modifierType, table.subCode, table.calls, table.versionId)
```

Generate and apply migration.

**Verify**: Run `pnpm --filter shared build`. Count rows before/after dedup.

## SCR-151: Fix calls empty string handling in seed

**Problem**: Line 828 of `seed.ts` uses `m.calls || null`. Since empty string is falsy, this converts empty-string calls to `null`. While functionally acceptable, it silently coerces data and should be explicit.

**Solution**:

```typescript
calls: m.calls === '' ? null : m.calls,
```

**Verify**: Seed compiles.

## SCR-152: Preserve explanatory code category in seed

**Problem**: Line 927–934 of `seed.ts` maps explanatory codes but drops the `category` field and hardcodes `severity: 'INFO'`. The scraper extracts the category (e.g., "Paid", "Adjusted", "Rejected") which maps to severity.

**Solution**:

Map the scraped category to the severity column:

```typescript
await db.insert(explanatoryCodes).values(
  scrapedExplCodes.map((e) => {
    // Map category to severity
    const catLower = (e.category || '').toLowerCase();
    let severity = 'INFO';
    if (catLower.includes('reject')) severity = 'ERROR';
    else if (catLower.includes('adjust')) severity = 'WARNING';
    else if (catLower.includes('paid') || catLower.includes('approv')) severity = 'INFO';

    return {
      explCode: e.code,
      description: e.description,
      severity,
      commonCause: null,
      suggestedAction: null,
      helpText: null,
      versionId: REF_VERSION_ID,
      effectiveFrom: '2025-04-01',
    };
  }),
);
```

**Verify**: Seed compiles. After seeding, verify explanatory codes have non-uniform severity values.

## SCR-153: Filter self-referencing bundling pairs and fix description

**Problem**: Two issues in bundling rule seeding (line 938–978 of `seed.ts`):

1. Self-referencing pairs where `h.hscCode === excl.excludedCode` create meaningless `codeA === codeB` rows.
2. After canonical reordering (codeA < codeB), the description still says `${h.hscCode} may not be claimed with ${excl.excludedCode}` which may reverse the original direction.

**Solution**:

```typescript
for (const h of scrapedHsc) {
  if (!h.bundlingExclusions?.length) continue;
  for (const excl of h.bundlingExclusions) {
    // Skip self-referencing pairs
    if (h.hscCode === excl.excludedCode) continue;

    const [codeA, codeB] =
      h.hscCode < excl.excludedCode
        ? [h.hscCode, excl.excludedCode]
        : [excl.excludedCode, h.hscCode];
    const key = `${codeA}:${codeB}`;
    if (!bundlingPairs.has(key)) {
      const rel =
        excl.relationship === 'same_day_exclusion'
          ? 'SAME_DAY_EXCLUSION'
          : 'NOT_CLAIMABLE_WITH';
      bundlingPairs.set(key, {
        codeA,
        codeB,
        relationship: rel,
        // Use canonical ordering in description
        description: `${codeA} and ${codeB} may not be claimed together`,
      });
    }
  }
}
```

**Verify**: Seed compiles. Verify no rows where codeA === codeB.

## SCR-154: Wrap seed inserts in transaction

**Problem**: The seed script performs ~20 sequential `db.insert()` calls without a transaction. If any insert fails midway, the database is left in a partially seeded state. The existing idempotency check (line 213–218) only checks if the first user exists, so re-running after a partial failure may skip seeding entirely while reference data is incomplete.

**Solution**:

Wrap all inserts in a Drizzle transaction:

```typescript
async function main() {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL ?? '...' });
  const db = drizzle(pool);

  // Idempotency check
  const existing = await db.select({ userId: users.userId }).from(users).where(eq(users.userId, DR_CHEN_ID));
  if (existing.length > 0) {
    console.log('Seed data already exists. Skipping.');
    await pool.end();
    return;
  }

  console.log('Seeding test data...\n');

  await db.transaction(async (tx) => {
    // Replace all `db.insert(...)` with `tx.insert(...)`
    // ... all existing seed inserts ...
  });

  console.log('\nSeed complete!');
  await pool.end();
}
```

**Verify**: Seed compiles. Simulate failure (e.g., bad data) — verify rollback.

## SCR-155: Widen action varchar margin

**Problem**: The `action` column in `hsc_modifier_eligibility` is `varchar(30)`. Some modifier actions from the Fee Navigator may be longer. Current data max is ~25 chars but is close to the limit.

**Solution**:

Change to `varchar(50)` in `reference.schema.ts`:

```typescript
action: varchar('action', { length: 50 }),
```

Generate migration.

**Verify**: `pnpm --filter shared build` passes.

---

# 8. Phase 6 — Validation Hardening

## SCR-160: Tighten completeness thresholds

**Problem**: Current thresholds (line 152 of `validate-fee-navigator-data.ts`) are set at minimum expected values. With 3,089 HSC codes, a threshold of 3,000 allows nearly 3% data loss without detection.

**Solution**:

Set thresholds closer to known counts with a ~5% margin:

```typescript
const THRESHOLDS: Array<[string, number, number]> = [
  ['HSC codes', hscCodes.length, 2900],           // was 3000 — allow for some margin but catch major drops
  ['Modifier rows', hscModifiers.length, 38000],   // was 40000 — tighter to catch ~8% loss
  ['Modifier definitions', modifiers.length, 38],   // was 40 — tighter
  ['Governing rules', govRules.length, 15],         // keep — already tight
  ['Explanatory codes', explCodes.length, 100],     // keep — already tight
];
```

**Verify**: `tsx scripts/validate-fee-navigator-data.ts` passes with current data.

## SCR-161: Add modifier row deduplication check

**Problem**: Validation does not check for duplicate modifier rows. The scraper can produce 4,955 duplicate rows that pass validation.

**Solution**:

Add a dedup check in section E (modifier row validation):

```typescript
// E2: No duplicate modifier rows
const modRowKeys = new Set<string>();
let modRowDupes = 0;
for (const m of hscModifiers) {
  const key = `${m.hscCode}|${m.type}|${m.code}|${m.calls}`;
  if (modRowKeys.has(key)) {
    modRowDupes++;
  }
  modRowKeys.add(key);
}

if (modRowDupes === 0) {
  pass('No duplicate modifier rows');
} else {
  fail(`${modRowDupes} duplicate modifier row(s) found`);
}
```

**Verify**: `tsx scripts/validate-fee-navigator-data.ts` — should report duplicates before SCR-150 fix, pass after.

## SCR-162: Add enrichment minimum thresholds

**Problem**: The enrichment validation section (lines 366–374) uses unconditional `pass()` calls. A scrape that produces zero enrichment (e.g., if all notes were lost) would still show all green.

**Solution**:

Add minimum thresholds for enrichment fields:

```typescript
const ENRICHMENT_MINIMUMS: Array<[string, number, number]> = [
  ['requiresReferral', withReferral, 300],
  ['specialtyRestrictions', withSpecialty, 100],
  ['bundlingExclusions', withBundling, 120],
  ['ageRestriction', withAge, 20],
  ['frequencyRestriction', withFrequency, 15],
  ['facilityDesignation', withFacility, 20],
  ['category', withCategory, hscCodes.length * 0.95],  // >95% should have category
  ['billingTips', withBillingTips, 150],
  ['commonTerms', withCommonTerms, 80],
];

for (const [label, count, min] of ENRICHMENT_MINIMUMS) {
  if (count >= min) {
    pass(`${label}: ${count} codes (minimum: ${min})`);
  } else {
    fail(`${label}: ${count} codes — below minimum ${min}`);
  }
}
```

**Verify**: `tsx scripts/validate-fee-navigator-data.ts` passes with current data, fails if enrichment counts drop.

## SCR-163: Add governing rule reference resolution check

**Problem**: HSC codes reference governing rules like "4.4.8" in their `governingRuleReferences` array. Validation does not check whether these references resolve to actual rules in `governing-rules.json`.

**Solution**:

Add cross-file check in section F:

```typescript
// F3: GR references from HSC codes resolve to governing rules
const grRuleNumbers = new Set(govRules.map((r) => r.ruleNumber));
const unresolvedGrRefs = new Set<string>();
for (const hsc of hscCodes) {
  if (!hsc.governingRuleReferences) continue;
  for (const ref of hsc.governingRuleReferences) {
    // Check if the ref or its parent rule exists
    const parentId = ref.split('.')[0];
    if (!grRuleNumbers.has(ref) && !grRuleNumbers.has(parentId)) {
      unresolvedGrRefs.add(ref);
    }
  }
}

if (unresolvedGrRefs.size === 0) {
  pass('All governing rule references resolve');
} else {
  warn(`${unresolvedGrRefs.size} governing rule reference(s) do not resolve: ${[...unresolvedGrRefs].slice(0, 5).join(', ')}`);
}
```

**Verify**: `tsx scripts/validate-fee-navigator-data.ts` reports unresolved refs (if any) as warnings.

---

# 9. Phase 7 — Data Quality & Cleanup

## SCR-170: Normalize specialty restrictions

**Problem**: Data quality review found 58 specialty restriction values that are sentence fragments (e.g., "physicians working in", "those with", "with training in"). These are extracted because the regex split produces partial strings.

**Solution**:

Add a post-extraction cleanup step:

```typescript
function normalizeSpecialty(raw: string): string | null {
  const trimmed = raw.trim();
  // Skip common fragment patterns
  if (/^(?:physicians?\s|those\s|with\s|working\s|in\s|at\s|for\s|by\s)/i.test(trimmed)) {
    return null;
  }
  // Skip very short values
  if (trimmed.length < 4) return null;
  // Skip values that end with prepositions (fragment indicators)
  if (/\s(?:in|at|for|by|with|of|who|that)$/i.test(trimmed)) return null;
  // Title-case normalize
  return trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
}

function extractSpecialtyRestrictions(notes: string): string[] {
  // ... existing extraction ...
  return [...new Set(
    restrictions
      .map(normalizeSpecialty)
      .filter((s): s is string => s !== null)
  )];
}
```

**Verify**: Run enrichment, verify specialty count remains ≥100 and no garbage fragments remain.

## SCR-171: Clean modifier definition descriptions

**Problem**: Some modifier definition descriptions contain the AMA website footer text ("Alberta Medical Association...") and/or repeated modifier name text.

**Solution**:

Add cleanup in `parseModifierPage`:

```typescript
// Clean up description: remove footer text and de-duplicate
let description = descParts.join(' ').replace(/\s+/g, ' ').trim() || name;

// Remove AMA footer if present
description = description.replace(/\s*Alberta Medical Association.*$/i, '').trim();
// Remove repeated modifier name from start of description
if (name && description.startsWith(name)) {
  description = description.slice(name.length).trim();
  if (description.startsWith('-') || description.startsWith(':')) {
    description = description.slice(1).trim();
  }
  // If nothing left, use name as description
  if (!description) description = name;
}
```

**Verify**: Scraper compiles. Inspect modifier descriptions after scrape for cleanliness.

## SCR-172: Audit visit codes without modifiers

**Problem**: 65 visit-type codes (feeType=VISIT) have zero modifier rows. This could indicate a scraping issue or genuinely modifier-free codes.

**Solution**:

Add a data quality check to validation:

```typescript
// H. Data Quality Audit
console.log('\nData quality:');

// H1: Visit codes without modifiers
const visitCodesWithoutMods = hscCodes.filter(
  (h) => h.feeType === 'VISIT' && !hscModifiers.some((m) => m.hscCode === h.hscCode),
);
if (visitCodesWithoutMods.length <= 70) {
  pass(`Visit codes without modifiers: ${visitCodesWithoutMods.length} (within expected range)`);
} else {
  warn(`Visit codes without modifiers: ${visitCodesWithoutMods.length} — may indicate scraping issue`);
}
```

This is a warning, not an error — some visit codes genuinely have no modifiers.

**Verify**: `tsx scripts/validate-fee-navigator-data.ts` reports visit code audit results.

---

# 10. Phase 8 — Re-scrape & Verify

## SCR-180: Re-run full pipeline and validate

**Problem**: After all fixes are applied, the scraped data files need to be regenerated to reflect the improvements.

**Solution**:

1. Run scraper with `--force-discovery` to ensure fresh discovery
2. Run enrichment to re-extract structured data with fixed regexes
3. Run validation to confirm all checks pass
4. Run reference tests to confirm seed compatibility
5. Compare before/after counts to verify improvements

```bash
# Step 1: Re-scrape
./apps/api/node_modules/.bin/tsx scripts/scrape-fee-navigator.ts --force-discovery

# Step 2: Re-enrich
./apps/api/node_modules/.bin/tsx scripts/enrich-hsc-data.ts

# Step 3: Validate
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts

# Step 4: Build shared + run tests
pnpm --filter shared build && pnpm --filter api vitest run src/domains/reference/reference.test.ts
```

**Expected improvements**:
- Bundling exclusions: 135 → 300+
- Age restrictions: 23 → 50+
- Frequency restrictions: 21 → 40+
- Anesthesia codes: increase
- Zero validation errors
- Zero modifier row duplicates

**Verify**: All validation passes, all tests pass, no data regression.

---

# 11. Task Dependency Graph

```
Phase 1: Enrichment Regex Fixes
  SCR-110 ──┐
  SCR-111 ──┤ (independent)
  SCR-112 ──┘

Phase 2: Enrichment Coverage Expansion
  SCR-120 ──┐ (depends on Phase 1)
  SCR-121 ──┘

Phase 3: Scraper Safety & Robustness
  SCR-130 ──┐
  SCR-131 ──┤ (independent)
  SCR-132 ──┤
  SCR-133 ──┘

Phase 4: Shared Utilities Hardening
  SCR-140 ──┐
  SCR-141 ──┤ (independent)
  SCR-142 ──┘

Phase 5: Seed & Schema Fixes
  SCR-150 ──┐
  SCR-151 ──┤
  SCR-152 ──┤ (independent)
  SCR-153 ──┤
  SCR-154 ──┤
  SCR-155 ──┘

Phase 6: Validation Hardening
  SCR-160 ──┐ (depends on Phase 5 for modifier dedup)
  SCR-161 ──┤
  SCR-162 ──┤
  SCR-163 ──┘

Phase 7: Data Quality & Cleanup
  SCR-170 ──┐ (depends on Phase 1)
  SCR-171 ──┤
  SCR-172 ──┘ (depends on Phase 6)

Phase 8: Re-scrape & Verify
  SCR-180      (depends on ALL previous phases)
```

**Section execution order**: Phases 1–5 can run independently (parallelizable). Phase 6 after Phase 5. Phase 7 after Phases 1 and 6. Phase 8 must be last.

---

*End of FRD V2*
