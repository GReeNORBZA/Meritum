# Meritum — Fee Navigator Scraper & Enrichment Pipeline

Functional Requirements — Correctness, Robustness & Data Quality

SCR Domain | Critical Path: Prerequisite to Domain 2 Seed & Domain 4.1 Validation

Meritum Health Technologies Inc.

Version 1.0 | March 2026

CONFIDENTIAL

---

# Table of Contents

1. [Domain Overview](#1-domain-overview)
2. [Review Findings Summary](#2-review-findings-summary)
3. [Phase 1 — Shared Infrastructure](#3-phase-1--shared-infrastructure)
4. [Phase 2 — Scraper Correctness](#4-phase-2--scraper-correctness)
5. [Phase 3 — Dynamic Discovery](#5-phase-3--dynamic-discovery)
6. [Phase 4 — Enrichment Correctness](#6-phase-4--enrichment-correctness)
7. [Phase 5 — Data Completeness & Schema Alignment](#7-phase-5--data-completeness--schema-alignment)
8. [Phase 6 — Pipeline Validation](#8-phase-6--pipeline-validation)
9. [Phase 7 — Exploration Script Cleanup](#9-phase-7--exploration-script-cleanup)
10. [Task Dependency Graph](#10-task-dependency-graph)

---

# 1. Domain Overview

## 1.1 Purpose

The Fee Navigator scraper and enrichment pipeline is the primary data ingestion pathway for the Meritum rules engine. It extracts Health Service Codes (HSCs), modifier eligibility, governing rules, and explanatory codes from the Alberta Medical Association's Fee Navigator website and transforms them into structured data consumed by:

- **Domain 4.1 AHCIP Claim Pathway** — fee calculation (`computeFeeBreakdown`), 19 validation checks (A1–A19)
- **Domain 7 Intelligence Engine** — AI Coach billing suggestions
- **Domain 2 Reference Data** — all downstream search, lookup, and admin APIs

Every field scraped flows through: **scrape → enrich → seed.ts → hsc_codes table → validation engine → claim submission**. A single incorrect field (wrong `baseFee`, missing `requiresReferral`, incorrect `surchargeEligible`) cascades into claim rejections, incorrect payments, or compliance violations across ~350,000 annual AHCIP claims.

## 1.2 Scope

This FRD addresses every finding from the March 2026 code review of the three pipeline scripts:

1. `scripts/scrape-fee-navigator.ts` — Cheerio-based HSC scraper
2. `scripts/enrich-hsc-data.ts` — Post-processing enrichment
3. `scripts/explore-fee-navigator.ts` — Playwright exploration script

Specifically:

- **7 correctness bugs** (P1–P2) that produce incorrect or duplicated data
- **6 robustness gaps** that cause hangs, data loss, or silent failures
- **5 data quality improvements** for higher extraction accuracy
- **3 data completeness gaps** where scraped data is discarded before reaching the database
- **Shared infrastructure extraction** to eliminate code duplication
- **Pipeline self-validation** to detect regressions on re-scrape

## 1.3 Out of Scope

- Data sets not available from the Fee Navigator website (PCPCM baskets, WCB codes, ICD crosswalk, functional centres, RRNP communities, statutory holidays)
- Fields requiring SOMB PDF extraction (`referralValidityDays`, `combinationGroup`, `shadowBillingEligible`, `afterHoursEligible`, `premium351Eligible`, `requiresDiagnosticCode`, `requiresFacility`, `minCalls`, `maxCalls`, `isTimeBased`, `minTime`, `maxTime`)
- Rewriting the scraper to use Playwright (the exploration script confirmed Cheerio captures all data present in the AJAX responses)
- Modifying the fee calculation engine (Domain 4.1)
- Admin staging/publishing workflow changes (Domain 2 D02-022/D02-023)

## 1.4 Dependencies

| Depends On | Reason |
|---|---|
| Node.js 20+ with native `fetch` | AbortController timeout support |
| Existing scrape output in `scripts/data/fee-navigator/` | Enrichment reads hsc-codes.json |
| DB schema `packages/shared/src/schemas/db/reference.schema.ts` | Schema alignment tasks add columns |
| Seed script `apps/api/src/seed.ts` | Seed alignment tasks update field mapping |

| Provides To | Reason |
|---|---|
| Domain 2 seed pipeline | Correct, complete JSON files for database insertion |
| Domain 4.1 validation engine | Accurate HSC fields for checks A1–A19 |
| Domain 7 AI Coach | Correct notes, governing rule references, bundling data |

## 1.5 Critical Design Constraint: Idempotent Re-Scrape

The pipeline must be designed for repeated execution over time as the Fee Navigator content changes (quarterly SOMB updates). This means:

- **Deterministic output**: Same input HTML → same JSON output (no random ordering, no timestamp-dependent logic in parsing)
- **Crash recovery**: Partial scrape can be resumed without data duplication
- **Backwards compatibility**: New enrichment fields must not break existing seed.ts mapping (use `?? defaultValue` patterns)
- **Validation**: Post-scrape validation ensures data integrity before any downstream consumption

---

# 2. Review Findings Summary

All findings from the code review, mapped to the tasks that address them.

## 2.1 P1 — Correctness Bugs (Must Fix)

| # | Finding | Impact | Task |
|---|---|---|---|
| 1 | `baseFee` comma stripping uses `.replace(',', '')` — only removes first comma | Fees ≥ $1,000 with commas parsed incorrectly | SCR-010 |
| 2 | `decodeHtmlEntities` misses `&#NNN;` decimal and `&#xNN;` hex entities beyond hardcoded set | Content with uncommon entities silently corrupted | SCR-002 |
| 3 | `extractAgeRestriction` determines which pattern matched via `patternStr.includes()` on regex source string | Brittle; refactoring any regex silently breaks age classification | SCR-040 |
| 4 | `parseGR448` Strategy 3 adds HSC codes from *any* element on the GR 4 page containing "referr" text | ~332 referral codes may include false positives from GR 4.1–4.3 | SCR-041 |

## 2.2 P2 — Significant Issues

| # | Finding | Impact | Task |
|---|---|---|---|
| 5 | No `AbortController` timeout on `fetch` calls | Hung connection blocks scraper indefinitely | SCR-002 |
| 6 | Progress resume pushes `existingHsc` without dedup — crash between scrape and save creates duplicates | Duplicate HSC entries in hsc-codes.json | SCR-011 |
| 7 | `surchargeEligible` only checks `modCode.includes('SURC')`, misses SURT sub-codes | Codes with SURT modifiers not flagged surcharge-eligible | SCR-010 |
| 8 | `categoryToFeeType` maps by first letter only with fragile secondary checks | New categories starting with same letter misclassified | SCR-012 |
| 9 | GR sub-rules (4.4.8, 6.8.1, etc.) not scraped as dedicated pages | Sub-rule-specific HSC references may be missed | SCR-022 |
| 10 | GR 1.33 Z-suffix heuristic unconditionally moves Z-codes to out-of-office | Overrides correct text-based classification if a Z-code is legitimately in-office | SCR-042 |
| 11 | `extractBundlingExclusions` regex `.*?` spans multiple sentences after whitespace collapse | Matches unrelated "with" prepositions in subsequent sentences | SCR-043 |
| 12 | 135 extracted `bundlingExclusions` are enriched but never seeded to `bundling_rules` table | Enrichment work discarded; bundling check A19 has no data | SCR-051 |
| 13 | `billingTips` and `commonTerms` scraped but not seeded | Useful data for search/display discarded | SCR-052 |

## 2.3 P3 — Maintenance & Quality

| # | Finding | Impact | Task |
|---|---|---|---|
| 14 | Hardcoded `ROOT_SECTION_KEYS` (19 keys) | New tree sections missed on re-scrape | SCR-020 |
| 15 | Hardcoded `MODIFIER_CODES` (42 codes) | New modifiers missed on re-scrape | SCR-021 |
| 16 | `extractHscCodesFromText` regex matches any `XX.XX` — can match version numbers | False-positive HSC references in bundling/governing rule extraction | SCR-043 |
| 17 | `fetchWithRetry`, `sleep`, `decodeHtmlEntities` duplicated across scripts | Fixes applied in one script but not the other | SCR-001 |
| 18 | No CAPTCHA/block detection — server returns 200 with error page | Scraper silently saves garbage HTML as data | SCR-002 |
| 19 | `explore-fee-navigator.ts`: unused import, JSON re-parsing, event listener leaks | Minor cleanup for maintainability | SCR-070 |

---

# 3. Phase 1 — Shared Infrastructure

## SCR-001: Extract shared scraper utilities

**Problem**: `fetchWithRetry`, `sleep`, `decodeHtmlEntities`, and configuration constants are duplicated between `scrape-fee-navigator.ts` and `enrich-hsc-data.ts`. Bug fixes must be applied in both places.

**Solution**: Create `scripts/lib/fee-navigator-utils.ts` containing:

- `sleep(ms)` — Promise-based delay
- `fetchWithRetry(url, options, retries)` — with retry, backoff, and timeout (see SCR-002)
- `decodeHtmlEntities(xml)` — XML content extraction with full entity decoding (see SCR-002)
- `saveJson(outputDir, filename, data)` — atomic JSON write
- `loadJson<T>(outputDir, filename)` — typed JSON load with null fallback
- `ensureDir(dir)` — recursive mkdir
- Shared constants: `BASE_URL`, `HEADERS`, `MAX_RETRIES`, `DELAY_MS`

Update both scripts to import from the shared module. Remove duplicated functions.

**Verify**: Both scripts compile without errors; TypeScript strict mode passes.

## SCR-002: Harden fetch and entity decoding

**Problem**: Three independent issues in the shared utilities:
1. No request timeout — hung connections block indefinitely
2. `decodeHtmlEntities` misses `&#NNN;` and `&#xNN;` entities
3. No detection of error/CAPTCHA pages returned as HTTP 200

**Solution** (all in `scripts/lib/fee-navigator-utils.ts`):

### A. Request timeout via AbortController

```typescript
async function fetchWithRetry(
  url: string,
  options: RequestInit = {},
  retries = MAX_RETRIES,
  timeoutMs = 30_000,
): Promise<string> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: { ...HEADERS, ...(options.headers as Record<string, string>) },
      });
      clearTimeout(timer);
      // ... existing retry logic ...
    } catch (err) {
      clearTimeout(timer);
      // Handle AbortError as timeout
      if ((err as Error).name === 'AbortError') {
        console.warn(`  [TIMEOUT] ${url} after ${timeoutMs}ms (attempt ${attempt}/${retries})`);
      }
      // ... existing backoff ...
    }
  }
}
```

### B. Complete entity decoding

Replace manual entity replacement with comprehensive decoding:

```typescript
function decodeHtmlEntities(xml: string): string {
  const contentMatch = xml.match(/<content>([\s\S]*?)<\/content>/);
  if (!contentMatch) return '';
  return contentMatch[1]
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&amp;/g, '&'); // Must be last — other entities may contain &
}
```

Note: `&amp;` replacement MUST be last because earlier replacements may produce `&` characters that should not be double-decoded.

### C. Response body validation

Add a validation check after successful fetch to detect error/CAPTCHA pages:

```typescript
function validateResponse(url: string, body: string): void {
  // AJAX detail responses should contain XML <content> wrapper
  if (url.includes('?ajax=')) {
    if (!body.includes('<content>')) {
      throw new Error(`Invalid AJAX response from ${url}: missing <content> wrapper (possible CAPTCHA or error page)`);
    }
  }
  // Check for common block indicators
  const lower = body.toLowerCase();
  if (lower.includes('captcha') || lower.includes('access denied') || lower.includes('rate limit')) {
    throw new Error(`Possible block detected from ${url}: response contains block indicators`);
  }
}
```

Call `validateResponse(url, body)` before returning from `fetchWithRetry`.

**Verify**: `npx tsc --noEmit scripts/lib/fee-navigator-utils.ts` compiles cleanly.

---

# 4. Phase 2 — Scraper Correctness

## SCR-010: Fix fee parsing and surcharge detection

**Problem**: Two bugs in `parseHscDetailHtml`:

1. Line 351: `feeMatch[1].replace(',', '')` only removes the first comma. Fees like `$1,234.56` become `1234.56` correctly, but `$1,234,567.89` would become `1234,567.89`.

2. Line 435-437: `surchargeEligible` checks `modCode.includes('SURC')` but not `modCode.includes('SURT')`. The SURT modifier type (surcharge time-based) also indicates surcharge eligibility.

**Solution**:

```typescript
// Fix 1: Global comma replace (line 351)
baseFee = feeMatch ? feeMatch[1].replace(/,/g, '') : null;

// Fix 2: Expanded surcharge detection (line 435-437)
if (type === 'SURC' || type === 'SURT' || modCode.includes('SURC') || modCode.includes('SURT')) {
  surchargeEligible = true;
}
```

**Verify**: Run scraper on a single code to confirm output format: `node -e "..."` spot check.

## SCR-011: Fix progress resume deduplication

**Problem**: When resuming from a crash, `existingHsc` (loaded from hsc-codes.json) and `existingMods` are pushed into the arrays. If a code was scraped and added to the arrays but the progress file wasn't saved (crash between line 512 and 523), the code won't be in `completedSet` and will be re-scraped, creating duplicate entries.

**Solution**: Use a `Map` keyed by `hscCode` instead of an array for in-memory storage during scraping, then convert to array for JSON output. Apply same dedup logic to modifier rows.

```typescript
// Replace arrays with Maps for dedup
const hscMap = new Map<string, HscCode>();
const hscModifierMap = new Map<string, HscModifierRow[]>();

// Load previous progress into Maps
const existingHsc = loadJson<HscCode[]>(OUTPUT_DIR, 'hsc-codes.json') ?? [];
for (const h of existingHsc) {
  hscMap.set(h.hscCode, h);
}
// ... similarly for modifiers, keyed by hscCode ...

// On each successful scrape:
hscMap.set(result.hsc.hscCode, result.hsc);
hscModifierMap.set(result.hsc.hscCode, result.modifierRows);

// On save:
const hscCodes = Array.from(hscMap.values());
const hscModifiers = Array.from(hscModifierMap.values()).flat();
```

**Verify**: Simulate crash recovery by running scraper, stopping mid-run, and resuming. Verify no duplicates: `node -e "const d=require('./scripts/data/fee-navigator/hsc-codes.json'); const codes=d.map(h=>h.hscCode); const dupes=codes.filter((c,i)=>codes.indexOf(c)!==i); console.log('Duplicates:', dupes.length)"` → should be 0.

## SCR-012: Improve categoryToFeeType mapping

**Problem**: The first-letter switch at line 169-199 is fragile. Categories starting with the same letter have different meanings (e.g., 'C' for both Consultation and Anaesthetic). Secondary `.startsWith()` checks are ad hoc.

**Solution**: Replace with a priority-ordered full-string prefix lookup, falling back to letter match only for genuinely unknown categories:

```typescript
/** Category prefix → fee type, checked in order (longest prefix first) */
const CATEGORY_FEE_TYPE_MAP: Array<[string, string]> = [
  // Specific prefixes (checked first)
  ['C Ana',      'ANESTHESIA'],
  ['R Surg',     'PROCEDURE'],
  // Single-letter prefixes
  ['V',          'VISIT'],
  ['P',          'PROCEDURE'],
  ['M',          'FIXED'],
  ['C',          'CONSULTATION'],
  ['L',          'LABORATORY'],
  ['R',          'RADIOLOGY'],
  ['A',          'ANESTHESIA'],
  ['T',          'THERAPEUTIC'],
];

function categoryToFeeType(category: string | null): string {
  if (!category) return 'UNKNOWN';
  const cat = category.trim();

  // Numeric-prefixed categories are Major Procedures
  if (/^\d+\s/.test(cat)) return 'PROCEDURE';

  for (const [prefix, feeType] of CATEGORY_FEE_TYPE_MAP) {
    if (cat.startsWith(prefix)) return feeType;
  }

  console.warn(`  [WARN] Unknown category: "${cat}" — defaulting to OTHER`);
  return 'OTHER';
}
```

The `console.warn` ensures new categories are visible in scrape logs rather than silently mapped to OTHER.

**Verify**: After re-scrape, count OTHER fee types: `node -e "const d=require('./scripts/data/fee-navigator/hsc-codes.json'); const other=d.filter(h=>h.feeType==='OTHER'); console.log('OTHER:', other.length); if(other.length>0) other.slice(0,5).forEach(h=>console.log(' ',h.hscCode,h.category))"` — should be 0 or near-0 with identified categories.

---

# 5. Phase 3 — Dynamic Discovery

## SCR-020: Dynamic root section discovery

**Problem**: `ROOT_SECTION_KEYS` is hardcoded to 19 keys. If the Fee Navigator adds or removes top-level sections, codes will be missed or the scraper will error.

**Solution**: Fetch the main HSC page and extract root expandable nodes dynamically:

```typescript
async function discoverRootSectionKeys(): Promise<string[]> {
  console.log('  Discovering root section keys from HSC main page...');
  const html = await fetchWithRetry(`${BASE_URL}/hsc`);
  const $ = cheerio.load(html);

  const keys: string[] = [];
  $('div.node.expandable, a.node.expandable').each((_i, el) => {
    const key = $(el).attr('data-key');
    if (key && /^\d+$/.test(key)) {
      keys.push(key);
    }
  });

  if (keys.length === 0) {
    throw new Error('No root section keys found on HSC main page — site structure may have changed');
  }

  console.log(`  Found ${keys.length} root section keys: [${keys.join(', ')}]`);
  return keys;
}
```

Replace `ROOT_SECTION_KEYS` constant usage in `discoverAllHscCodes` with a call to `discoverRootSectionKeys()`. Log a warning if the discovered count differs from the previous scrape's count (stored in metadata).

**Verify**: Run discovery phase only and compare output to known 19 keys.

## SCR-021: Dynamic modifier code discovery

**Problem**: `MODIFIER_CODES` is hardcoded to 42 codes. New modifiers added to the Fee Navigator will be missed.

**Solution**: Fetch the modifiers listing page and extract modifier codes dynamically:

```typescript
async function discoverModifierCodes(): Promise<string[]> {
  console.log('  Discovering modifier codes from modifiers listing page...');
  const html = await fetchWithRetry(`${BASE_URL}/modifiers`);
  const $ = cheerio.load(html);

  const codes: string[] = [];
  // Viewable nodes in the modifier tree have the modifier code in their href or data-key
  $('a.node.viewable, a[href*="/fee-navigator/modifiers/"]').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const match = href.match(/\/fee-navigator\/modifiers\/([^?&#]+)/);
    if (match) {
      codes.push(decodeURIComponent(match[1]));
    }
  });

  // Deduplicate
  const unique = [...new Set(codes)];

  if (unique.length === 0) {
    throw new Error('No modifier codes found on modifiers listing page — site structure may have changed');
  }

  console.log(`  Found ${unique.length} modifier codes`);
  return unique;
}
```

If the listing page uses tree expansion (like HSC), also expand tree nodes to discover nested modifiers.

**Verify**: Compare discovered count to known 42; log any new/removed codes.

## SCR-022: Scrape governing rule sub-sections

**Problem**: The scraper fetches `/governing-rules/1` through `/governing-rules/19` as top-level pages, but sub-rules like 4.4.8, 6.8.1, etc., may have dedicated pages at URLs like `/governing-rules/4.4.8`. The enrichment script already compensates for GR 4.4.8, but other sub-rules may exist.

**Solution**: After scraping the 19 top-level rules, extract sub-rule references from their content and attempt to fetch dedicated sub-rule pages:

```typescript
async function discoverSubRules(parentRules: GoverningRule[]): Promise<string[]> {
  const subRuleUrls = new Set<string>();

  for (const rule of parentRules) {
    // Extract sub-rule references from links in the full text HTML
    // Pattern: /governing-rules/X.Y.Z where X.Y.Z has at least one dot
    const linkPattern = /\/governing-rules\/([\d]+\.[\d.]+)/g;
    let match;
    while ((match = linkPattern.exec(rule.fullText)) !== null) {
      subRuleUrls.add(match[1]);
    }
  }

  return Array.from(subRuleUrls);
}
```

For each discovered sub-rule URL, attempt to fetch its detail page. If it exists, merge its `referencedHscCodes` into the parent rule's data.

**Verify**: Log any sub-rule pages found. Validate that GR 4.4.8 HSC references are captured.

---

# 6. Phase 4 — Enrichment Correctness

## SCR-040: Refactor age restriction extraction

**Problem**: `extractAgeRestriction` matches a pattern via regex, then determines *which* pattern matched by checking `pattern.source.includes('younger|under')` — inspecting the regex source string. This is brittle: refactoring any regex silently changes the classification.

**Solution**: Replace with explicitly tagged patterns using a discriminated union:

```typescript
interface AgePattern {
  tag: 'max_months' | 'max_years' | 'min_years' | 'min_months' | 'range_years' | 'range_ages';
  regex: RegExp;
}

const AGE_PATTERNS: AgePattern[] = [
  { tag: 'max_months', regex: /(\d+)\s*months?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+under)/i },
  { tag: 'max_years',  regex: /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+under)/i },
  { tag: 'min_years',  regex: /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i },
  { tag: 'min_months', regex: /(\d+)\s*months?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i },
  { tag: 'range_years', regex: /between\s+(\d+)\s*and\s*(\d+)\s*years/i },
  { tag: 'range_ages',  regex: /aged?\s+(\d+)\s*(?:to|-)\s*(\d+)/i },
];

function extractAgeRestriction(notes: string): AgeRestriction | null {
  for (const { tag, regex } of AGE_PATTERNS) {
    const match = notes.match(regex);
    if (!match) continue;

    switch (tag) {
      case 'max_months':  return { text: match[0], maxMonths: parseInt(match[1], 10) };
      case 'max_years':   return { text: match[0], maxYears: parseInt(match[1], 10) };
      case 'min_years':   return { text: match[0], minYears: parseInt(match[1], 10) };
      case 'min_months':  return { text: match[0], minMonths: parseInt(match[1], 10) };
      case 'range_years':
      case 'range_ages':  return { text: match[0], minYears: parseInt(match[1], 10), maxYears: parseInt(match[2], 10) };
    }
  }

  // Compound: both "under X" and "over Y" in same notes
  const underMatch = notes.match(/(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+under)/i);
  const overMatch = notes.match(/(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i);
  if (underMatch && overMatch) {
    return {
      text: `${underMatch[0]} and ${overMatch[0]}`,
      maxYears: parseInt(underMatch[1], 10),
      minYears: parseInt(overMatch[1], 10),
    };
  }

  return null;
}
```

**Verify**: Run enrichment and compare age restriction counts before/after. Spot-check 10 codes with known age restrictions.

## SCR-041: Tighten GR 4.4.8 referral parsing

**Problem**: `parseGR448` Strategy 3 (lines 439-456) iterates *all* `<li>`, `<p>`, `<td>` elements on the entire GR 4 page and adds any HSC code found in an element whose text contains "referr" or "4.4.8". Since the GR 4 page contains sub-sections 4.1–4.9+, this produces false positives from unrelated sections.

**Solution**: Replace the three-strategy approach with a single, scoped extraction:

1. **Extract the GR 4.4.8 section text only** — use regex or DOM traversal to isolate the 4.4.8 subsection from the full GR 4 page, bounded by the start of 4.4.8 and the start of the next sub-section (4.4.9 or 4.5).

2. **Within that section only**, extract HSC code references from both links and text patterns.

3. **Asterisk detection** for self-referral blocked remains within the scoped section.

```typescript
function parseGR448(html: string): {
  requiresReferral: Set<string>;
  selfReferralBlocked: Set<string>;
} {
  const $ = cheerio.load(html);
  const requiresReferral = new Set<string>();
  const selfReferralBlocked = new Set<string>();

  const fullText = $('body').text();

  // Isolate the 4.4.8 section text — bounded by next sub-section
  const section448Match = fullText.match(
    /4\.4\.8\b[\s\S]*?(?=\b4\.4\.9\b|\b4\.5\b|\b4\.6\b|$)/i,
  );

  if (!section448Match) {
    console.warn('  [WARN] Could not locate GR 4.4.8 section in GR 4 page');
    return { requiresReferral, selfReferralBlocked };
  }

  const sectionText = section448Match[0];

  // Extract HSC codes from the scoped section text
  const codePattern = /\b(\d{2}\.\d{2,3}[A-Z]{0,3})\s*(\*)?/g;
  let match;
  while ((match = codePattern.exec(sectionText)) !== null) {
    requiresReferral.add(match[1]);
    if (match[2] === '*') {
      selfReferralBlocked.add(match[1]);
    }
  }

  // Also extract from links within the page that are in 4.4.8 context
  // Find the DOM section containing 4.4.8
  $('a[href*="/fee-navigator/hsc/"]').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const codeMatch = href.match(/\/fee-navigator\/hsc\/([^?&#]+)/);
    if (!codeMatch) return;

    // Check if this link's surrounding text is within the 4.4.8 section
    const parentText = $(el).closest('div, section, li, td').text();
    if (parentText.includes('4.4.8') || sectionText.includes($(el).text().trim())) {
      const code = decodeURIComponent(codeMatch[1]);
      requiresReferral.add(code);
    }
  });

  return { requiresReferral, selfReferralBlocked };
}
```

**Verify**: Compare referral code count before/after. If count drops significantly, manually verify the removed codes against the official 4.4.8 list. Log all codes for audit.

## SCR-042: Fix GR 1.33 facility designation parsing

**Problem**: The Z-suffix heuristic (lines 529-534) unconditionally moves all Z-suffix codes from `inOffice` to `outOfOffice`, even if the text-based parsing correctly classified them.

**Solution**:

1. Apply the Z-suffix heuristic only for codes that were *not* explicitly classified by text parsing (i.e., codes found via link extraction without clear in-office/out-of-office context).
2. Log when the heuristic overrides text-based classification so discrepancies are visible.
3. Add a `confidence` field to track whether classification came from text parsing (high) or heuristic (low).

```typescript
// Track which codes were classified by text vs. heuristic
const textClassified = new Set<string>();

// During text-based extraction, mark codes as text-classified
// ... (in the inOfficeMatch / outOfOfficeMatch sections)
textClassified.add(code);

// Z-suffix heuristic: only apply to codes NOT already classified by text
for (const code of [...inOffice]) {
  if (code.endsWith('Z') && !textClassified.has(code)) {
    console.log(`  [GR 1.33] Heuristic: moving ${code} from in-office to out-of-office (Z suffix)`);
    inOffice.delete(code);
    outOfOffice.add(code);
  } else if (code.endsWith('Z') && textClassified.has(code)) {
    console.log(`  [GR 1.33] Keeping ${code} as in-office despite Z suffix (text-classified)`);
  }
}
```

**Verify**: Run enrichment and review log output. Verify in-office/out-of-office counts match expectations (14 in-office, 13 out-of-office from last scrape).

## SCR-043: Fix bundling exclusion extraction

**Problem**: Two issues:

1. `extractBundlingExclusions` regex uses `.*?` between trigger phrase and "with/in addition to" — after whitespace collapse in scraping (`.replace(/\s+/g, ' ')`), this can span multiple sentences.

2. `extractHscCodesFromText` matches any `\d{2}\.\d{2,3}[A-Z]{0,3}` — could match version numbers or decimal values.

**Solution**:

### A. Sentence-bounded bundling regex

Limit the match to the same sentence by replacing `.*?` with a character class that excludes period-followed-by-space (sentence boundaries):

```typescript
// Old: /(?:May not be claimed|...).*?(?:with|in addition to)\s+HSC.../
// New: Use [^.] instead of .*? to stay within a single sentence,
// but allow periods followed by digits (HSC codes contain periods)
const withPattern =
  /(?:May not be claimed|not\s+(?:be\s+)?payable|not\s+(?:be\s+)?claimed|shall not be (?:submitted|claimed))(?:[^.]|\.(?=\d))*?(?:with|in addition to)\s+HSC[s]?\s+([\d.,\s/andor\w]+?)(?:\.(?!\d)|$)/gi;
```

The key change: `(?:[^.]|\.(?=\d))*?` matches any character except period, OR a period followed by a digit. This keeps the match within a sentence while allowing HSC code periods (e.g., `03.08A`).

### B. Stricter HSC code validation

Add validation that extracted codes match known HSC format:

```typescript
function extractHscCodesFromText(text: string): string[] {
  const codePattern = /\b(\d{2}\.\d{2,3}[A-Z]{0,3})\b/g;
  const codes: string[] = [];
  let match;
  while ((match = codePattern.exec(text)) !== null) {
    const code = match[1];
    // Validate: must have at least one digit after the period
    // and the numeric part must be in valid HSC range (01-99)
    const prefix = parseInt(code.split('.')[0], 10);
    if (prefix >= 1 && prefix <= 99) {
      codes.push(code);
    }
  }
  return codes;
}
```

**Verify**: Run enrichment, compare bundling exclusion count. Spot-check 20 codes with bundling exclusions against Fee Navigator notes text.

---

# 7. Phase 5 — Data Completeness & Schema Alignment

## SCR-050: Add category column to schema and persist through pipeline

**Problem**: The raw `category` string (e.g., "V Visit", "C Consultation", "14 Major Procedure") is scraped and used to derive `feeType`, but is not stored in the database. The category contains richer information than the derived fee type and is useful for filtering and display.

**Solution**:

1. Add `category` column to `hsc_codes` table in `reference.schema.ts`:
   ```typescript
   category: varchar('category', { length: 100 }),
   ```

2. Generate and apply database migration.

3. Update `seed.ts` to map `category` field from scraped JSON.

4. Update `reference.service.ts` `HscDetailResult` interface and `getHscDetail` to include `category`.

**Verify**: `pnpm --filter shared build && pnpm --filter api vitest run src/domains/reference/reference.test.ts`

## SCR-051: Seed bundling exclusions to bundling_rules table

**Problem**: The enrichment script extracts 135 bundling exclusions from notes text (with `excludedCode` and `relationship` fields), but these are never inserted into the `bundling_rules` table. The validation check A19 depends on bundling rules data.

**Solution**:

1. In `seed.ts`, after HSC codes are inserted, extract bundling exclusions from the enriched `hsc-codes.json` and insert into `bundling_rules`:

```typescript
// Extract bundling rules from enriched HSC data
const bundlingPairs = new Map<string, { codeA: string; codeB: string; relationship: string }>();

for (const hsc of scrapedHsc) {
  if (!hsc.bundlingExclusions?.length) continue;
  for (const excl of hsc.bundlingExclusions) {
    // Canonical ordering: codeA < codeB
    const [codeA, codeB] = [hsc.hscCode, excl.excludedCode].sort();
    const key = `${codeA}:${codeB}`;
    if (!bundlingPairs.has(key)) {
      bundlingPairs.set(key, {
        codeA,
        codeB,
        relationship: excl.relationship,
      });
    }
  }
}

// Insert bundling rules
const bundlingValues = Array.from(bundlingPairs.values());
for (let i = 0; i < bundlingValues.length; i += 500) {
  const batch = bundlingValues.slice(i, i + 500);
  await db.insert(bundlingRules).values(
    batch.map((b) => ({
      codeA: b.codeA,
      codeB: b.codeB,
      relationship: b.relationship,
      description: `Extracted from Fee Navigator notes: ${b.codeA} ${b.relationship.replace(/_/g, ' ')} ${b.codeB}`,
      sourceReference: 'Fee Navigator notes text',
      isActive: true,
    })),
  );
}
console.log(`    Bundling rules: ${bundlingValues.length} pairs inserted`);
```

2. The `bundlingExclusions` array must remain on the enriched JSON (already there) — no schema change needed for the JSON file.

**Verify**: `pnpm --filter api vitest run src/domains/reference/reference.test.ts` — seed inserts without unique constraint violations.

## SCR-052: Persist billingTips and commonTerms

**Problem**: The scraper extracts `billingTips` (string) and `commonTerms` (string array) from HSC detail pages, but neither is seeded into the database. `commonTerms` are useful for search/autocomplete; `billingTips` complement `helpText`.

**Solution**:

1. Add columns to `hsc_codes` in `reference.schema.ts`:
   ```typescript
   billingTips: text('billing_tips'),
   commonTerms: jsonb('common_terms')
     .notNull()
     .default(sql`'[]'::jsonb`)
     .$type<string[]>(),
   ```

2. Generate and apply database migration.

3. Update `seed.ts` mapping:
   ```typescript
   billingTips: h.billingTips ?? null,
   commonTerms: h.commonTerms ?? [],
   ```

4. Update `HscDetailResult` in `reference.service.ts` and the `getHscDetail` mapping.

5. Add `commonTerms` to the GIN trigram index for search:
   ```typescript
   index('hsc_codes_common_terms_gin_idx').using(
     'gin',
     sql`to_tsvector('english', coalesce(array_to_string(${table.commonTerms}::text[], ' '), ''))`,
   ),
   ```

**Verify**: `pnpm --filter shared build && pnpm --filter api vitest run src/domains/reference/reference.test.ts`

---

# 8. Phase 6 — Pipeline Validation

## SCR-060: Add post-scrape validation script

**Problem**: There is no automated check that scraped data is complete and correctly formatted. A regression (site structure change, CAPTCHA block, partial scrape) could go unnoticed.

**Solution**: Create `scripts/validate-fee-navigator-data.ts` that reads the JSON output files and validates:

### A. Completeness checks
- hsc-codes.json: count ≥ 3,000 (current: 3,089)
- hsc-modifiers.json: count ≥ 40,000 (current: 41,328)
- modifiers.json: count ≥ 40 (current: 42)
- governing-rules.json: count ≥ 15 (current: 19)
- explanatory-codes.json: count ≥ 100 (current: 123)

### B. Format validation per record
- Every HSC code: `hscCode` matches `/^\d{2}\.\d{2,3}[A-Z]{0,3}$/`
- Every HSC code: `feeType` is one of known values
- Every HSC code: `baseFee` is null or matches `/^\d+\.\d{2}$/`
- Every HSC code: `modifierEligibility` is array of strings
- Every HSC code: `governingRuleReferences` is array of strings matching `/^\d+(\.\d+)*$/`
- Every modifier row: `hscCode`, `type`, `code`, `action` are non-empty strings
- No duplicate `hscCode` values in hsc-codes.json

### C. Enrichment validation (if enrichment fields present)
- `requiresReferral` is boolean (not undefined)
- `specialtyRestrictions` is array
- `bundlingExclusions` is array of `{ excludedCode, relationship }`
- `ageRestriction` is null or object with `text` field
- `frequencyRestriction` is null or object with `text`, `count`, `period`

### D. Cross-file consistency
- Every `hscCode` in hsc-modifiers.json exists in hsc-codes.json
- Every modifier `type` in hsc-modifiers.json exists in modifiers.json `modifierCode`

### E. Regression detection
- Compare counts against scrape-metadata.json from previous run
- Warn if any count drops by more than 5%

Exit code 0 on pass, 1 on any failure. Output summary to stdout.

**Verify**: `npx tsx scripts/validate-fee-navigator-data.ts` exits 0 against current data.

## SCR-061: Integrate validation into scraper pipeline

**Problem**: The validation script exists but isn't wired into the scrape/enrich workflow.

**Solution**:

1. At the end of `scrape-fee-navigator.ts` `main()`, after saving metadata, invoke validation:
   ```typescript
   console.log('\n=== Running post-scrape validation ===\n');
   const { execSync } = await import('node:child_process');
   try {
     execSync('npx tsx scripts/validate-fee-navigator-data.ts', { stdio: 'inherit' });
   } catch {
     console.error('\n  *** POST-SCRAPE VALIDATION FAILED ***');
     console.error('  Review the validation output above before using this data.\n');
     process.exit(2); // Distinct exit code for validation failure
   }
   ```

2. At the end of `enrich-hsc-data.ts` `main()`, run validation again (enrichment adds fields that must also be validated).

**Verify**: Run scraper end-to-end; validation runs automatically and passes.

---

# 9. Phase 7 — Exploration Script Cleanup

## SCR-070: Clean up exploration script

**Problem**: Three minor issues in `explore-fee-navigator.ts`:

1. `ElementHandle` imported but unused (line 23)
2. `loadScrapedCode` reads and parses the 2.4 MB JSON file on every call (9 times for 9 sample codes)
3. `page.on('dialog')` and `page.on('request')` listeners accumulate without removal

**Solution**:

1. Remove `ElementHandle` from import statement.
2. Cache JSON parse result:
   ```typescript
   let _scrapedCodesCache: Record<string, unknown>[] | null = null;
   function loadScrapedCode(hscCode: string): Record<string, unknown> | null {
     if (!_scrapedCodesCache) {
       const filePath = path.join(OUTPUT_DIR, 'hsc-codes.json');
       if (!fs.existsSync(filePath)) return null;
       _scrapedCodesCache = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
     }
     return _scrapedCodesCache!.find((c: any) => c.hscCode === hscCode) ?? null;
   }
   ```
3. Use `page.removeAllListeners('dialog')` and `page.removeAllListeners('request')` at the end of probe functions, or use `page.once()` for the dialog handler.

**Verify**: `npx tsc --noEmit scripts/explore-fee-navigator.ts` compiles cleanly.

---

# 10. Task Dependency Graph

```
SCR-001 ──► SCR-002 ──► SCR-010 ──► SCR-011 ──► SCR-012
                   │                                  │
                   └──► SCR-020 ──► SCR-021 ──► SCR-022
                                                      │
            SCR-040 ──► SCR-041 ──► SCR-042 ──► SCR-043
                                                      │
            SCR-050 ──► SCR-051 ──► SCR-052           │
                                       │              │
                                       └──► SCR-060 ◄─┘
                                              │
                                           SCR-061
                                              │
                                           SCR-070
```

**Phase 1** (SCR-001, SCR-002): Shared infrastructure — must be first since all other scripts import from it.

**Phase 2** (SCR-010, SCR-011, SCR-012): Scraper correctness — depends on shared utils.

**Phase 3** (SCR-020, SCR-021, SCR-022): Dynamic discovery — depends on shared utils.

**Phase 4** (SCR-040, SCR-041, SCR-042, SCR-043): Enrichment correctness — independent of Phase 2/3 but shares utils.

**Phase 5** (SCR-050, SCR-051, SCR-052): Schema & seed alignment — can proceed once enrichment is correct.

**Phase 6** (SCR-060, SCR-061): Validation — must be last since it validates all prior work.

**Phase 7** (SCR-070): Exploration cleanup — independent, can run any time after SCR-001.

---

# Appendix A: File Inventory

| File | Action | Tasks |
|---|---|---|
| `scripts/lib/fee-navigator-utils.ts` | **CREATE** | SCR-001, SCR-002 |
| `scripts/scrape-fee-navigator.ts` | MODIFY | SCR-010, SCR-011, SCR-012, SCR-020, SCR-021, SCR-022, SCR-061 |
| `scripts/enrich-hsc-data.ts` | MODIFY | SCR-040, SCR-041, SCR-042, SCR-043, SCR-061 |
| `scripts/validate-fee-navigator-data.ts` | **CREATE** | SCR-060 |
| `scripts/explore-fee-navigator.ts` | MODIFY | SCR-070 |
| `packages/shared/src/schemas/db/reference.schema.ts` | MODIFY | SCR-050, SCR-052 |
| `apps/api/src/seed.ts` | MODIFY | SCR-050, SCR-051, SCR-052 |
| `apps/api/src/domains/reference/reference.service.ts` | MODIFY | SCR-050, SCR-052 |
| `apps/api/src/domains/reference/reference.test.ts` | MODIFY | SCR-050, SCR-052 |

# Appendix B: Re-Scrape Verification Checklist

After all tasks are complete, run the full pipeline and verify:

```bash
# 1. Run scraper
npx tsx scripts/scrape-fee-navigator.ts

# 2. Run enrichment
npx tsx scripts/enrich-hsc-data.ts

# 3. Run validation (should exit 0)
npx tsx scripts/validate-fee-navigator-data.ts

# 4. Verify counts
node -e "
  const hsc = require('./scripts/data/fee-navigator/hsc-codes.json');
  const mods = require('./scripts/data/fee-navigator/hsc-modifiers.json');
  console.log('HSC codes:', hsc.length);
  console.log('Modifier rows:', mods.length);
  console.log('With referral:', hsc.filter(h=>h.requiresReferral).length);
  console.log('With bundling:', hsc.filter(h=>h.bundlingExclusions?.length>0).length);
  console.log('With specialty:', hsc.filter(h=>h.specialtyRestrictions?.length>0).length);
  console.log('With age:', hsc.filter(h=>h.ageRestriction).length);
  console.log('Fee type OTHER:', hsc.filter(h=>h.feeType==='OTHER').length);
  console.log('Duplicates:', hsc.length - new Set(hsc.map(h=>h.hscCode)).size);
"

# 5. Run tests
pnpm --filter shared build
pnpm --filter api vitest run src/domains/reference/reference.test.ts
```

Expected outputs:
- HSC codes ≥ 3,000
- Modifier rows ≥ 40,000
- Duplicates: 0
- Fee type OTHER: 0 or near-0
- All tests pass
