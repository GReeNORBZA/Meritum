# Fee Navigator Pipeline — Hardening Pass

Paste everything below the line into a new Claude Code chat to apply all deferred hardening items from the 2026-03-03 audit.

---

## Prompt

I need you to implement the deferred hardening items from the Fee Navigator scraper pipeline audit. These were identified during the 2026-03-03 review but deferred as low-priority. Now we're ready to tackle them.

**Do NOT re-run the scraper or enrichment scripts.** These are code-only changes. After all fixes, run validation and TypeScript checks to confirm nothing broke.

### Project Location

- Monorepo: `/workspace/projects`
- tsx: `./apps/api/node_modules/.bin/tsx`

### Files to Modify

| File | Changes |
|------|---------|
| `scripts/lib/fee-navigator-utils.ts` | Honest User-Agent, robots.txt check |
| `scripts/scrape-fee-navigator.ts` | Content hashing, deprecated code detection, selector resilience, robots.txt gate |
| `packages/shared/src/schemas/db/reference.schema.ts` | FK from hsc_modifier_eligibility to hsc_codes, NULLS NOT DISTINCT on unique index |
| `apps/api/src/seed.ts` | GR fullText HTML preservation (store raw + plain text) |

---

## Item 1: Honest User-Agent

**File:** `scripts/lib/fee-navigator-utils.ts`, lines 18-23

**Problem:** The scraper impersonates Chrome:
```typescript
'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
```
This is deceptive. Before go-live, the scraper must identify itself honestly.

**Fix:** Replace the User-Agent string:
```typescript
'User-Agent': 'Meritum-SOMB-Scraper/1.0 (+https://meritum.ca; contact@meritum.ca)',
```

Keep `Referer` and `X-Requested-With` as-is — the site requires them for AJAX responses.

**Risk:** The Fee Navigator site may block non-browser user agents. To mitigate, add a `--stealth` flag that falls back to the Chrome UA for development/testing:

```typescript
const STEALTH_MODE = process.argv.includes('--stealth');

export const HEADERS: Record<string, string> = {
  'User-Agent': STEALTH_MODE
    ? 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    : 'Meritum-SOMB-Scraper/1.0 (+https://meritum.ca; contact@meritum.ca)',
  Referer: `${BASE_URL}/hsc`,
  'X-Requested-With': 'XMLHttpRequest',
};
```

Also export `STEALTH_MODE` so the scraper main script can log it:
```typescript
export const STEALTH_MODE = process.argv.includes('--stealth');
```

In `scrape-fee-navigator.ts`, add to the startup banner after the `Output:` line:
```typescript
console.log(`  User-Agent: ${STEALTH_MODE ? 'stealth (Chrome)' : 'honest (Meritum-SOMB-Scraper/1.0)'}`);
```

Import `STEALTH_MODE` from the utils module.

---

## Item 2: robots.txt Check

**File:** `scripts/lib/fee-navigator-utils.ts` (new function) + `scripts/scrape-fee-navigator.ts` (gate in main)

**Problem:** The scraper doesn't check robots.txt before scraping. `apps.albertadoctors.org/robots.txt` currently returns 404 (no file), but this could change at any time.

**Fix:** Add a robots.txt fetcher to the utils module:

```typescript
/**
 * Check robots.txt for the target host. Returns an object indicating
 * whether scraping is allowed and any crawl-delay.
 */
export async function checkRobotsTxt(baseUrl: string): Promise<{
  allowed: boolean;
  crawlDelay: number | null;
  raw: string | null;
}> {
  const url = new URL(baseUrl);
  const robotsUrl = `${url.protocol}//${url.host}/robots.txt`;

  try {
    const resp = await fetch(robotsUrl, {
      headers: { 'User-Agent': HEADERS['User-Agent'] },
    });

    if (resp.status === 404) {
      // No robots.txt — everything is allowed
      return { allowed: true, crawlDelay: null, raw: null };
    }

    if (!resp.ok) {
      console.warn(`  [WARN] robots.txt returned HTTP ${resp.status} — proceeding with caution`);
      return { allowed: true, crawlDelay: null, raw: null };
    }

    const body = await resp.text();

    // Parse for our user-agent or wildcard
    const lines = body.split('\n').map(l => l.trim().toLowerCase());
    let inOurSection = false;
    let inWildcard = false;
    let disallowed = false;
    let crawlDelay: number | null = null;

    for (const line of lines) {
      if (line.startsWith('user-agent:')) {
        const ua = line.replace('user-agent:', '').trim();
        inOurSection = ua === 'meritum-somb-scraper' || ua === 'meritum';
        inWildcard = ua === '*';
      } else if (inOurSection || inWildcard) {
        if (line.startsWith('disallow:')) {
          const path = line.replace('disallow:', '').trim();
          // Check if our target paths are disallowed
          if (path === '/' || path === '/fee-navigator' || path === '/fee-navigator/') {
            disallowed = true;
          }
        }
        if (line.startsWith('crawl-delay:')) {
          const delay = parseFloat(line.replace('crawl-delay:', '').trim());
          if (!isNaN(delay)) crawlDelay = delay;
        }
      }
    }

    // Our specific UA section takes precedence over wildcard
    return { allowed: !disallowed, crawlDelay, raw: body };
  } catch (err) {
    console.warn(`  [WARN] Could not fetch robots.txt: ${(err as Error).message} — proceeding`);
    return { allowed: true, crawlDelay: null, raw: null };
  }
}
```

In `scrape-fee-navigator.ts`, add a robots.txt gate at the start of `main()`, after `acquireLock()`:

```typescript
// Check robots.txt
const robotsResult = await checkRobotsTxt(BASE_URL);
if (!robotsResult.allowed) {
  console.error('  robots.txt disallows scraping /fee-navigator. Aborting.');
  console.error('  Contact the AMA to request scraping permission.');
  releaseLock();
  process.exit(1);
}
if (robotsResult.crawlDelay !== null) {
  console.log(`  robots.txt crawl-delay: ${robotsResult.crawlDelay}s (adjusting delay)`);
  // Override DELAY_MS if crawl-delay is higher
  // Note: DELAY_MS is imported as const; create a local mutable version
}
if (robotsResult.raw) {
  console.log(`  robots.txt found (${robotsResult.raw.length} bytes)`);
} else {
  console.log('  robots.txt: not found (404) — no restrictions');
}
```

Import `checkRobotsTxt` from the utils module.

---

## Item 3: Content Hashing for Data Freshness Detection

**File:** `scripts/scrape-fee-navigator.ts`

**Problem:** When resuming a scrape or running against a cache, there's no way to detect whether Fee Navigator content has actually changed. The 7-day TTL on the discovery cache is a blunt instrument — the data might change daily or stay stable for months.

**Fix:** Add content hashing to the scrape metadata. After each completed scrape, hash the output files and store the hashes in `scrape-metadata.json`.

Add a `computeFileHash` function to `scripts/lib/fee-navigator-utils.ts`:

```typescript
import * as crypto from 'node:crypto';

/** Compute SHA-256 hash of a file's contents */
export function computeFileHash(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}
```

In `scrape-fee-navigator.ts`, after the final save (before saving metadata), compute hashes:

```typescript
import { computeFileHash } from './lib/fee-navigator-utils.js';

// ... after final save ...

// Compute content hashes for freshness detection
const contentHashes: Record<string, string> = {};
for (const file of ['hsc-codes.json', 'hsc-modifiers.json', 'modifiers.json', 'governing-rules.json', 'explanatory-codes.json']) {
  const filePath = path.join(OUTPUT_DIR, file);
  if (fs.existsSync(filePath)) {
    contentHashes[file] = computeFileHash(filePath);
  }
}
```

Add `contentHashes` to the `ScrapeMetadata` interface and the metadata object:

```typescript
interface ScrapeMetadata {
  timestamp: string;
  durationSeconds: number;
  counts: { /* ... existing ... */ };
  errors: string[];
  contentHashes?: Record<string, string>;  // SHA-256 per output file
  previousHashes?: Record<string, string>; // from the previous run
}
```

Before computing new hashes, load previous metadata to compare:

```typescript
const prevMetadata = loadJson<ScrapeMetadata>(OUTPUT_DIR, 'scrape-metadata.json');

// ... compute contentHashes ...

// Compare with previous hashes
if (prevMetadata?.contentHashes) {
  const changed: string[] = [];
  const unchanged: string[] = [];
  for (const [file, hash] of Object.entries(contentHashes)) {
    if (prevMetadata.contentHashes[file] === hash) {
      unchanged.push(file);
    } else {
      changed.push(file);
    }
  }
  if (changed.length === 0) {
    console.log('\n  Content hashes: ALL FILES UNCHANGED from previous scrape');
  } else {
    console.log(`\n  Content changes detected: ${changed.join(', ')}`);
    console.log(`  Unchanged: ${unchanged.join(', ')}`);
  }
}

const metadata: ScrapeMetadata = {
  // ... existing fields ...
  contentHashes,
  previousHashes: prevMetadata?.contentHashes ?? undefined,
};
```

---

## Item 4: Deprecated Code Detection

**File:** `scripts/scrape-fee-navigator.ts`

**Problem:** If a code is removed from Fee Navigator between scrapes, the discovery cache still contains it. The scraper will try to fetch its detail page, get a 404 or empty response, log an error, and move on — but the code remains in `hsc-codes.json` from the previous run's progress data. There's no explicit detection or reporting of deprecated codes.

**Fix:** After discovery completes, compare the new code set against the previous scrape's code set and report differences.

After `discoverAllHscCodes()` returns, add:

```typescript
// Detect deprecated codes (present in previous scrape but absent from discovery)
const prevHscCodes = loadJson<Array<{ hscCode: string }>>(OUTPUT_DIR, 'hsc-codes.json');
if (prevHscCodes && prevHscCodes.length > 0) {
  const prevCodeSet = new Set(prevHscCodes.map(h => h.hscCode));
  const currentCodeSet = new Set(codes);

  const deprecated = [...prevCodeSet].filter(c => !currentCodeSet.has(c));
  const newCodes = [...currentCodeSet].filter(c => !prevCodeSet.has(c));

  if (deprecated.length > 0) {
    console.warn(`\n  [WARN] ${deprecated.length} codes from previous scrape not found in discovery:`);
    for (const code of deprecated.slice(0, 20)) {
      console.warn(`    - ${code}`);
    }
    if (deprecated.length > 20) {
      console.warn(`    ... and ${deprecated.length - 20} more`);
    }
    console.warn('  These codes may have been removed from Fee Navigator.');
    console.warn('  They will remain in hsc-codes.json from the previous run but should be reviewed.\n');
    allErrors.push(`${deprecated.length} codes from previous scrape not found in current discovery: ${deprecated.slice(0, 5).join(', ')}${deprecated.length > 5 ? '...' : ''}`);
  }

  if (newCodes.length > 0) {
    console.log(`  ${newCodes.length} new codes discovered (not in previous scrape)`);
  }
}
```

Also add deprecated code tracking to the metadata:

```typescript
interface ScrapeMetadata {
  // ... existing ...
  codeChanges?: {
    deprecated: string[];  // codes removed since last scrape
    added: string[];       // codes new since last scrape
  };
}
```

---

## Item 5: GR fullText HTML Preservation

**File:** `scripts/scrape-fee-navigator.ts` (parseGoverningRulePage) + `packages/shared/src/schemas/db/reference.schema.ts` (governing_rules table) + `apps/api/src/seed.ts`

**Problem:** `parseGoverningRulePage()` at line 809 does:
```typescript
const fullText = record.text().replace(/\s+/g, ' ').trim();
```
This strips all HTML structure — lists become run-on text, sub-sections lose their headings, and cross-references lose their links. GR 4's fullText is 33,339 chars of flat text. When displayed in the UI, physicians can't distinguish sub-rules (4.4.8 vs 4.4.9) or navigate to referenced HSC codes.

**Fix (two-column approach):** Store both the sanitized HTML and the plain text.

### Step 1: Schema change

Add a `description_html` column to the `governing_rules` table:

```typescript
// In packages/shared/src/schemas/db/reference.schema.ts, governing_rules table
descriptionHtml: text('description_html'),  // Sanitized HTML from Fee Navigator
```

Add it after the existing `description` column (line 304). The existing `description` column keeps the plain text version for search indexing.

### Step 2: Scraper change

In `parseGoverningRulePage()`, capture both the HTML and the plain text:

```typescript
function parseGoverningRulePage(
  ruleNumber: string,
  html: string,
): GoverningRule | null {
  const $ = cheerio.load(html);

  const record = $('div.contents');
  if (!record.length) return null;

  const title =
    record.find('h1.title').text().trim() ||
    record.find('h3').first().text().trim() ||
    record.find('h1').text().trim() ||
    '';

  // Plain text for search indexing (existing behavior)
  const fullText = record.text().replace(/\s+/g, ' ').trim();

  // Sanitized HTML for UI rendering — strip scripts/styles but keep structure
  const rawHtml = record.html() ?? '';
  const $sanitized = cheerio.load(rawHtml);
  $sanitized('script, style, link, meta').remove();
  // Remove AMA disclaimer footer if present
  $sanitized('div.disclaimer, .footer-note').remove();
  const fullHtml = $sanitized.html()?.trim() ?? null;

  // Referenced HSC codes
  const referencedHscCodes = new Set<string>();
  record.find('a[href*="/fee-navigator/hsc/"]').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const codeMatch = href.match(/\/fee-navigator\/hsc\/([^?&#]+)/);
    if (codeMatch) {
      referencedHscCodes.add(decodeURIComponent(codeMatch[1]));
    }
  });

  return {
    ruleNumber,
    title: title || `Governing Rule ${ruleNumber}`,
    fullText,
    fullHtml,
    referencedHscCodes: Array.from(referencedHscCodes),
  };
}
```

Update the `GoverningRule` interface to include `fullHtml`:
```typescript
interface GoverningRule {
  ruleNumber: string;
  title: string;
  fullText: string;
  fullHtml: string | null;
  referencedHscCodes: string[];
}
```

### Step 3: Seed change

In `apps/api/src/seed.ts`, map the new field when inserting governing rules:

```typescript
await tx.insert(governingRules).values(
  scrapedRules.map((r) => ({
    ruleId: `GR-${r.ruleNumber}`,
    ruleName: r.title,
    ruleCategory: 'GENERAL',
    description: r.fullText,
    descriptionHtml: r.fullHtml ?? null,
    ruleLogic: { referencedHscCodes: r.referencedHscCodes },
    // ... rest unchanged ...
  })),
);
```

Update the `ScrapedGoverningRule` interface in seed.ts to include `fullHtml`:
```typescript
interface ScrapedGoverningRule {
  ruleNumber: string;
  title: string;
  fullText: string;
  fullHtml?: string | null;
  referencedHscCodes: string[];
}
```

### Step 4: Generate migration

After the schema change, run:
```bash
cd /workspace/projects && npx drizzle-kit generate
```

This will generate a migration that adds the `description_html` column. The column is nullable so existing data won't break.

---

## Item 6: Selector Resilience (HTML Parser Hardening)

**File:** `scripts/scrape-fee-navigator.ts`

**Problem:** The scraper uses CSS selectors tightly coupled to Fee Navigator's HTML structure. If the AMA changes class names, element hierarchy, or table layouts, the scraper silently returns empty data. There are 20+ distinct selectors:

**Critical selectors (data extraction fails if broken):**
- `h2.code` — HSC code heading (line 419)
- `h1.title` — description (line 423)
- `div.note` — notes text (line 429)
- `table.basic-info tr` — category, base fee, common terms (line 437)
- `div.billing-tips` — billing tips (line 457)
- `div.governing-rules` — GR references (line 462)
- `div.modifiers table tr` — modifier eligibility rows (line 508)
- `div.contents` — governing rule / modifier page content (lines 697, 809)

**Discovery selectors (code discovery fails if broken):**
- `div.node.expandable, a.node.expandable` — tree expansion (lines 150, 202, 332)
- `a.node.viewable` — viewable code links (lines 184, 193, 1028)
- `a[href*="/fee-navigator/hsc/"]` — HSC code links (line 338)

**Fix:** Add a selector versioning system with fallback chains. Create a new file `scripts/lib/fee-navigator-selectors.ts`:

```typescript
/**
 * Fee Navigator HTML selector definitions with fallback chains.
 * Each selector has a primary (current) and fallback alternatives.
 * When the primary fails, fallbacks are tried in order.
 */

interface SelectorDef {
  /** Human-readable name for logging */
  name: string;
  /** Primary CSS selector (current Fee Navigator layout) */
  primary: string;
  /** Fallback selectors, tried in order if primary matches nothing */
  fallbacks: string[];
}

export const SELECTORS = {
  // --- Discovery ---
  expandableNode: {
    name: 'expandable tree node',
    primary: 'div.node.expandable, a.node.expandable',
    fallbacks: [
      '[class*="expandable"][data-key]',
      '[data-expandable][data-key]',
      '.tree-node[data-key]:not(.viewable)',
    ],
  },
  viewableNode: {
    name: 'viewable tree node',
    primary: 'a.node.viewable',
    fallbacks: [
      '[class*="viewable"][data-key]',
      'a[data-viewable][data-key]',
      '.tree-node a[href]',
    ],
  },
  hscLink: {
    name: 'HSC code link',
    primary: 'a[href*="/fee-navigator/hsc/"]',
    fallbacks: [
      'a[href*="/hsc/"]',
      'a[data-hsc-code]',
    ],
  },

  // --- HSC Detail Page ---
  codeHeading: {
    name: 'HSC code heading',
    primary: 'h2.code',
    fallbacks: ['h2[class*="code"]', '.code-heading', 'h2:first-of-type'],
  },
  title: {
    name: 'page title',
    primary: 'h1.title',
    fallbacks: ['h1[class*="title"]', '.page-title', 'h1:first-of-type'],
  },
  noteBlock: {
    name: 'notes block',
    primary: 'div.note',
    fallbacks: ['div[class*="note"]', '.notes', '.billing-note'],
  },
  basicInfoTable: {
    name: 'basic info table',
    primary: 'table.basic-info tr',
    fallbacks: ['table[class*="basic"] tr', '.info-table tr', 'table:first-of-type tr'],
  },
  billingTips: {
    name: 'billing tips',
    primary: 'div.billing-tips',
    fallbacks: ['div[class*="billing-tip"]', '.tips', '[data-billing-tips]'],
  },
  governingRulesBlock: {
    name: 'governing rules block',
    primary: 'div.governing-rules',
    fallbacks: ['div[class*="governing"]', '.rules-section', '[data-governing-rules]'],
  },
  modifierTable: {
    name: 'modifier table',
    primary: 'div.modifiers table tr',
    fallbacks: ['div[class*="modifier"] table tr', '.modifier-table tr', 'table.modifiers tr'],
  },
  contentBlock: {
    name: 'content block',
    primary: 'div.contents',
    fallbacks: ['div[class*="content"]', '.page-content', 'main', 'article'],
  },
} as const satisfies Record<string, SelectorDef>;

/**
 * Try the primary selector first; if it matches nothing, try fallbacks in order.
 * Returns the first selector that produces matches, or the primary if none work.
 * Logs a warning when a fallback is used.
 */
export function resolveSelector(
  $: cheerio.CheerioAPI,
  selectorDef: SelectorDef,
): { selector: string; usedFallback: boolean } {
  if ($(selectorDef.primary).length > 0) {
    return { selector: selectorDef.primary, usedFallback: false };
  }

  for (const fallback of selectorDef.fallbacks) {
    if ($(fallback).length > 0) {
      console.warn(
        `  [SELECTOR] ${selectorDef.name}: primary "${selectorDef.primary}" failed, using fallback "${fallback}"`,
      );
      return { selector: fallback, usedFallback: true };
    }
  }

  // No fallback worked either — return primary and let caller handle empty result
  console.warn(
    `  [SELECTOR] ${selectorDef.name}: no selectors matched (primary + ${selectorDef.fallbacks.length} fallbacks)`,
  );
  return { selector: selectorDef.primary, usedFallback: false };
}
```

Then in `scrape-fee-navigator.ts`, replace hard-coded selectors with `resolveSelector()` calls in the key parsing functions. For example, in `parseHscDetailHtml`:

```typescript
import { SELECTORS, resolveSelector } from './lib/fee-navigator-selectors.js';

// Before:
const codeHeading = $('h2.code').text().replace('Health Service Code', '').trim();

// After:
const { selector: codeSel } = resolveSelector($, SELECTORS.codeHeading);
const codeHeading = $(codeSel).text().replace('Health Service Code', '').trim();
```

**Important:** Do NOT convert every single selector call in this pass. Focus on the **data extraction selectors** (the "Critical selectors" list above). The discovery selectors already have multiple attempts built into the BFS logic and are less brittle.

Also add a selector health summary to the scrape metadata:

```typescript
interface ScrapeMetadata {
  // ... existing ...
  selectorHealth?: {
    totalResolutions: number;
    fallbacksUsed: number;
    failedSelectors: string[];
  };
}
```

---

## Item 7: FK from hsc_modifier_eligibility to hsc_codes

**File:** `packages/shared/src/schemas/db/reference.schema.ts`

**Problem:** The `hsc_modifier_eligibility` table has `hsc_code VARCHAR(10)` and `version_id UUID` columns but no FK to `hsc_codes`. This means:
1. Modifier eligibility rows can reference non-existent HSC codes
2. The unique index on `(hsc_code, modifier_type, sub_code, calls, version_id)` uses `NULLS DISTINCT` by default, so rows with `calls = NULL` (now fixed to `'-'` sentinel) aren't properly deduplicated

The `hsc_codes` table has an index on `(hsc_code, version_id)` but it's not a unique constraint, so it can't serve as an FK target without upgrading it.

### Step 1: Add unique constraint on hsc_codes

The `hsc_codes` table currently has (line 135):
```typescript
index('hsc_codes_hsc_code_version_id_idx').on(table.hscCode, table.versionId),
```

Change this to a unique index:
```typescript
uniqueIndex('hsc_codes_hsc_code_version_id_unique_idx').on(table.hscCode, table.versionId),
```

This enforces that no two HSC code records share the same `(hsc_code, version_id)` pair, which is the expected invariant.

### Step 2: Add FK from hsc_modifier_eligibility to hsc_codes

This requires a **composite FK** because the relationship is on `(hsc_code, version_id)`, not a single column. Drizzle ORM doesn't support multi-column FKs via the `.references()` helper, so use the `foreignKey` helper from the table definition:

```typescript
import { foreignKey } from 'drizzle-orm/pg-core';

export const hscModifierEligibility = pgTable(
  'hsc_modifier_eligibility',
  {
    // ... existing columns unchanged ...
  },
  (table) => [
    // ... existing indexes ...

    // FK to hsc_codes on (hsc_code, version_id)
    foreignKey({
      columns: [table.hscCode, table.versionId],
      foreignColumns: [hscCodes.hscCode, hscCodes.versionId],
    }),
  ],
);
```

**Note:** This FK will enforce referential integrity — modifier eligibility rows can only reference HSC codes that actually exist. Since both tables are populated in the same seed transaction, this is safe.

### Step 3: Generate migration

After the schema change:
```bash
cd /workspace/projects && npx drizzle-kit generate
```

Review the generated migration to confirm it adds:
1. A unique constraint on `hsc_codes(hsc_code, version_id)`
2. A FK from `hsc_modifier_eligibility(hsc_code, version_id)` to `hsc_codes(hsc_code, version_id)`

---

## Implementation Order

1. **`scripts/lib/fee-navigator-utils.ts`** — Item 1 (User-Agent), Item 2 (robots.txt), Item 3 (content hashing helper)
2. **`scripts/lib/fee-navigator-selectors.ts`** — Item 6 (new file — selector definitions)
3. **`scripts/scrape-fee-navigator.ts`** — Item 2 (robots.txt gate), Item 3 (content hashing in metadata), Item 4 (deprecated code detection), Item 5 (GR HTML preservation), Item 6 (selector resilience in parseHscDetailHtml)
4. **`packages/shared/src/schemas/db/reference.schema.ts`** — Item 5 (descriptionHtml column), Item 7 (unique constraint + FK)
5. **`apps/api/src/seed.ts`** — Item 5 (map descriptionHtml field)
6. **Generate migration** for schema changes

---

## Verification

After all changes:

```bash
cd /workspace/projects

# 1. Validation should still pass (no data changes)
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts

# 2. TypeScript compilation for modified scripts
npx tsc --noEmit -p apps/api/tsconfig.json 2>&1 | grep -E "fee-navigator-utils|fee-navigator-selectors|scrape-fee|enrich-hsc|seed\.ts"

# 3. Verify the new selector module compiles
./apps/api/node_modules/.bin/tsx -e 'import { SELECTORS } from "./scripts/lib/fee-navigator-selectors.js"; console.log(Object.keys(SELECTORS).length, "selectors defined");'

# 4. Verify robots.txt function works
./apps/api/node_modules/.bin/tsx -e '
import { checkRobotsTxt } from "./scripts/lib/fee-navigator-utils.js";
const result = await checkRobotsTxt("https://apps.albertadoctors.org/fee-navigator");
console.log("robots.txt result:", JSON.stringify(result, null, 2));
'

# 5. Verify content hash function works
./apps/api/node_modules/.bin/tsx -e '
import { computeFileHash } from "./scripts/lib/fee-navigator-utils.js";
const hash = computeFileHash("./scripts/data/fee-navigator/hsc-codes.json");
console.log("hsc-codes.json SHA-256:", hash);
'

# 6. Generate migration (review before applying)
npx drizzle-kit generate
```

### After Verification — Re-scrape

Since Items 3 (content hashing), 4 (deprecated code detection), 5 (GR HTML preservation), and 6 (selector resilience) change scraper behavior, a re-scrape is needed to populate the new fields:

```bash
./apps/api/node_modules/.bin/tsx scripts/scrape-fee-navigator.ts --force-discovery
./apps/api/node_modules/.bin/tsx scripts/enrich-hsc-data.ts
./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts
```

This will:
- Populate `fullHtml` on governing rules
- Generate content hashes in scrape-metadata.json
- Report any deprecated codes since last discovery
- Log selector resolution health

### Commit

```
feat(scraper): pipeline hardening — UA, robots.txt, content hashing, selector resilience

- Honest User-Agent with --stealth fallback for dev
- robots.txt check before scraping with crawl-delay support
- SHA-256 content hashing for data freshness detection
- Deprecated code detection between scrapes
- GR fullText HTML preservation (descriptionHtml column)
- Selector versioning with fallback chains
- FK from hsc_modifier_eligibility to hsc_codes
```
