#!/usr/bin/env tsx
// ============================================================================
// Meritum — AMA Fee Navigator Scraper
// Scrapes HSC codes, modifiers, governing rules, and explanatory codes
// from https://apps.albertadoctors.org/fee-navigator
//
// Usage: cd /home/developer/Desktop/projects && npx tsx scripts/scrape-fee-navigator.ts
// ============================================================================

import * as cheerio from 'cheerio';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  sleep,
  fetchWithRetry,
  decodeHtmlEntities,
  saveJson,
  loadJson,
  ensureDir,
  BASE_URL,
  DELAY_MS,
} from './lib/fee-navigator-utils.js';

// ============================================================================
// Configuration
// ============================================================================

const BATCH_SAVE_SIZE = 100; // Save progress every N codes
const FORCE_DISCOVERY = process.argv.includes('--force-discovery');
const CACHE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7-day TTL for discovery cache
const CIRCUIT_BREAKER_THRESHOLD = 20; // Abort after this many consecutive errors
const OUTPUT_DIR = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  'data',
  'fee-navigator',
);


// ============================================================================
// Types
// ============================================================================

interface HscCode {
  hscCode: string;
  description: string;
  baseFee: string | null;
  category: string | null;
  feeType: string;
  modifierEligibility: string[];
  surchargeEligible: boolean;
  notes: string | null;
  helpText: string | null;
  commonTerms: string[];
  billingTips: string | null;
  governingRuleReferences: string[];
}

interface HscModifierRow {
  hscCode: string;
  type: string;
  code: string;
  calls: string;
  explicit: string;
  action: string;
  amount: string;
}

interface ModifierDefinition {
  modifierCode: string;
  name: string;
  description: string;
  subCodes: Array<{ code: string; description: string }>;
}

interface GoverningRule {
  ruleNumber: string;
  title: string;
  fullText: string;
  referencedHscCodes: string[];
}

interface ExplanatoryCode {
  code: string;
  description: string;
  category: string;
}

interface ScrapeMetadata {
  timestamp: string;
  durationSeconds: number;
  counts: {
    rootSectionKeys: number;
    hscCodes: number;
    hscModifierRows: number;
    modifiers: number;
    governingRules: number;
    governingRuleSubRules: number;
    explanatoryCodes: number;
  };
  errors: string[];
}

// ============================================================================
// Fee Type Mapping
// ============================================================================

/** Category prefix → fee type, checked in order (longest match wins) */
const CATEGORY_FEE_TYPE_MAP: Array<[string, string]> = [
  // Specific multi-word prefixes first (before their single-letter fallbacks)
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

/** Map category string to fee type */
function categoryToFeeType(category: string | null): string {
  if (!category) return 'UNKNOWN';
  const cat = category.trim();

  // Numeric-prefixed categories are Major Procedures (e.g., "14 Major Procedure ...")
  if (/^\d+\s/.test(cat)) return 'PROCEDURE';

  for (const [prefix, feeType] of CATEGORY_FEE_TYPE_MAP) {
    if (cat.startsWith(prefix)) return feeType;
  }

  console.warn(`  [WARN] Unknown category for fee type mapping: "${cat}" — defaulting to OTHER`);
  return 'OTHER';
}


// ============================================================================
// Dynamic Discovery Functions
// ============================================================================

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
    throw new Error(
      'No root section keys found on HSC main page — the site structure may have changed. ' +
      'Check https://apps.albertadoctors.org/fee-navigator/hsc manually.',
    );
  }

  // Warn if count changed from previous scrape
  const prevMetadata = loadJson<ScrapeMetadata>(OUTPUT_DIR, 'scrape-metadata.json');
  if (prevMetadata?.counts?.rootSectionKeys && prevMetadata.counts.rootSectionKeys !== keys.length) {
    console.warn(
      `  [WARN] Root section count changed: ${prevMetadata.counts.rootSectionKeys} → ${keys.length}`,
    );
  }

  console.log(`  Found ${keys.length} root section keys: [${keys.join(', ')}]`);
  return keys;
}

async function discoverModifierCodes(): Promise<string[]> {
  console.log('  Discovering modifier codes from modifiers listing page...');
  const html = await fetchWithRetry(`${BASE_URL}/modifiers`);
  const $ = cheerio.load(html);

  const codes = new Set<string>();

  // Method 1: Extract from viewable node links
  $('a.node.viewable, a[href*="/fee-navigator/modifiers/"]').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const match = href.match(/\/fee-navigator\/modifiers\/([^?&#]+)/);
    if (match) {
      codes.add(decodeURIComponent(match[1]));
    }
  });

  // Method 2: Extract from data-key attributes on viewable nodes
  $('div.node.viewable, a.node.viewable').each((_i, el) => {
    const key = $(el).attr('data-key');
    if (key && /^[A-Z0-9]+$/.test(key)) {
      codes.add(key);
    }
  });

  // Method 3: If page uses tree expansion, expand categories
  const expandableKeys: string[] = [];
  $('div.node.expandable, a.node.expandable').each((_i, el) => {
    const key = $(el).attr('data-key');
    if (key) expandableKeys.push(key);
  });

  if (expandableKeys.length > 0) {
    console.log(`  Found ${expandableKeys.length} expandable categories, expanding...`);
    const expandUrl = `${BASE_URL}/modifiers?ajax=expanded`;
    for (const key of expandableKeys) {
      try {
        const body = `expanded=${key}&expand=${key}`;
        const xml = await fetchWithRetry(expandUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });
        const innerHtml = decodeHtmlEntities(xml);
        if (innerHtml) {
          const $inner = cheerio.load(innerHtml);
          $inner('a[href*="/fee-navigator/modifiers/"]').each((_i, el) => {
            const href = $inner(el).attr('href') ?? '';
            const match = href.match(/\/fee-navigator\/modifiers\/([^?&#]+)/);
            if (match) codes.add(decodeURIComponent(match[1]));
          });
        }
        await sleep(100);
      } catch (err) {
        console.warn(`  [WARN] Error expanding modifier category ${key}: ${(err as Error).message}`);
      }
    }
  }

  const unique = Array.from(codes).sort();

  if (unique.length === 0) {
    throw new Error(
      'No modifier codes found on modifiers listing page — the site structure may have changed. ' +
      'Check https://apps.albertadoctors.org/fee-navigator/modifiers manually.',
    );
  }

  console.log(`  Found ${unique.length} modifier codes`);
  return unique;
}

async function discoverSubRulePages(
  parentRules: GoverningRule[],
): Promise<string[]> {
  const subRuleIds = new Set<string>();

  // Method 1: Extract sub-rule URLs from parent rule content
  for (const rule of parentRules) {
    const linkPattern = /\/governing-rules\/([\d]+\.[\d]+(?:\.[\d]+)*)/g;
    let match;
    while ((match = linkPattern.exec(rule.fullText)) !== null) {
      const subRuleId = match[1];
      if (subRuleId.includes('.')) {
        subRuleIds.add(subRuleId);
      }
    }
  }

  // Method 2: Check the governing rules listing page
  try {
    const listingHtml = await fetchWithRetry(`${BASE_URL}/governing-rules`);
    const $ = cheerio.load(listingHtml);
    $('a[href*="/governing-rules/"]').each((_i, el) => {
      const href = $(el).attr('href') ?? '';
      const match = href.match(/\/governing-rules\/([\d]+\.[\d]+(?:\.[\d]+)*)/);
      if (match) {
        subRuleIds.add(match[1]);
      }
    });
  } catch (err) {
    console.warn(`  [WARN] Could not fetch governing rules listing: ${(err as Error).message}`);
  }

  const subRules = Array.from(subRuleIds).sort();
  console.log(`  Discovered ${subRules.length} sub-rule pages: [${subRules.join(', ')}]`);
  return subRules;
}

// ============================================================================
// Phase 1: Discover all HSC codes via tree expansion
// ============================================================================

async function discoverAllHscCodes(): Promise<{ codes: string[]; rootSectionKeyCount: number }> {
  console.log('\n=== Phase 1: Discovering HSC codes via tree expansion ===\n');

  // Check for cached discovery (skip if --force-discovery or cache is stale)
  const cachePath = path.join(OUTPUT_DIR, '_discovered-codes.json');
  if (!FORCE_DISCOVERY && fs.existsSync(cachePath)) {
    const cacheAge = Date.now() - fs.statSync(cachePath).mtimeMs;
    const cached = loadJson<string[]>(OUTPUT_DIR, '_discovered-codes.json');
    if (cached && cached.length > 0) {
      if (cacheAge < CACHE_MAX_AGE_MS) {
        const ageDays = Math.round(cacheAge / (24 * 60 * 60 * 1000) * 10) / 10;
        console.log(`  Found cached discovery: ${cached.length} codes (${ageDays} days old). Reusing.`);
        console.log(`  (Use --force-discovery to bypass cache)`);
        const prevMeta = loadJson<ScrapeMetadata>(OUTPUT_DIR, 'scrape-metadata.json');
        return { codes: cached, rootSectionKeyCount: prevMeta?.counts?.rootSectionKeys ?? 0 };
      } else {
        console.log(`  Discovery cache is stale (>7 days). Re-discovering...`);
      }
    }
  } else if (FORCE_DISCOVERY) {
    console.log(`  --force-discovery: bypassing cache`);
  }

  const allCodes = new Set<string>();
  const expandUrl = `${BASE_URL}/hsc?ajax=expanded`;

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

  const rootKeys = await discoverRootSectionKeys();

  // BFS queue: [keyToExpand, expandedKeysSoFar[]]
  const queue: Array<[string, string[]]> = rootKeys.map((k) => [k, [k]]);

  let requestCount = 0;

  while (queue.length > 0) {
    const [key, expanded] = queue.shift()!;
    try {
      const { expandables, viewables } = await expandNode(expanded, key);
      viewables.forEach((c) => allCodes.add(c));

      for (const e of expandables) {
        queue.push([e, [...expanded, e]]);
      }

      requestCount++;
      if (requestCount % 50 === 0) {
        console.log(
          `  [Discovery] ${requestCount} requests, ${allCodes.size} codes found, ${queue.length} nodes remaining`,
        );
      }

      await sleep(50); // Light delay for tree expansion
    } catch (err) {
      console.warn(`  [Discovery] Error expanding node ${key}: ${(err as Error).message}`);
    }
  }

  const codes = Array.from(allCodes).sort();
  console.log(
    `\n  Discovery complete: ${codes.length} codes found in ${requestCount} requests\n`,
  );

  // Cache discovery results
  saveJson(OUTPUT_DIR, '_discovered-codes.json', codes);

  return { codes, rootSectionKeyCount: rootKeys.length };
}

// ============================================================================
// Modifier Row Deduplication (SCR-150)
// ============================================================================

function deduplicateModifierRows(rows: HscModifierRow[]): HscModifierRow[] {
  const seen = new Set<string>();
  const unique: HscModifierRow[] = [];
  for (const row of rows) {
    const key = `${row.hscCode}|${row.type}|${row.code}|${row.calls}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(row);
    }
  }
  if (unique.length < rows.length) {
    console.log(`  Deduplicated modifier rows: ${rows.length} → ${unique.length} (${rows.length - unique.length} duplicates removed)`);
  }
  return unique;
}

// ============================================================================
// Phase 2: Scrape each HSC code detail page
// ============================================================================

function parseHscDetailHtml(
  hscCode: string,
  html: string,
): { hsc: HscCode; modifierRows: HscModifierRow[] } | null {
  const $ = cheerio.load(html);

  // Code heading
  const codeHeading = $('h2.code').text().replace('Health Service Code', '').trim();
  const code = codeHeading || hscCode;

  // Description
  const description = $('h1.title').text().trim();
  if (!description) {
    return null;
  }

  // Notes
  const noteEl = $('div.note');
  const notes = noteEl.length ? noteEl.text().replace(/\s+/g, ' ').trim() : null;

  // Basic info table
  let category: string | null = null;
  let baseFee: string | null = null;
  const commonTerms: string[] = [];

  $('table.basic-info tr').each((_i, row) => {
    const th = $(row).find('th').text().trim();
    const td = $(row).find('td').text().trim();

    if (th.includes('Category')) {
      category = td;
    } else if (th.includes('Base rate') || th.includes('base rate')) {
      // Extract dollar amount: "$25.09" -> "25.09"
      const feeMatch = td.match(/\$?([\d,]+\.\d{2})/);
      baseFee = feeMatch ? feeMatch[1].replace(/,/g, '') : null;
    } else if (th.includes('Common terms')) {
      $(row)
        .find('li')
        .each((_j, li) => {
          commonTerms.push($(li).text().trim());
        });
    }
  });

  // Billing tips
  const tipsEl = $('div.billing-tips');
  const billingTips = tipsEl.length ? tipsEl.text().replace(/\s+/g, ' ').trim() : null;

  // Governing rule references (div.governing-rules section)
  const governingRuleReferences: string[] = [];
  const govRulesEl = $('div.governing-rules');
  if (govRulesEl.length) {
    // Try structured list first: ul > li with div.title containing rule numbers
    govRulesEl.find('li').each((_i, el) => {
      const titleText = $(el).find('div.title, .title').text().trim();
      if (titleText) {
        // Extract rule number (e.g., "1.31", "4.4.8", "4.3.1")
        const ruleMatch = titleText.match(/^(\d+(?:\.\d+)*)/);
        if (ruleMatch) {
          governingRuleReferences.push(ruleMatch[1]);
        }
      }
    });

    // Fallback: extract rule numbers from links to governing-rules pages
    if (governingRuleReferences.length === 0) {
      govRulesEl.find('a[href*="/governing-rules/"]').each((_i, el) => {
        const href = $(el).attr('href') ?? '';
        const ruleMatch = href.match(/\/governing-rules\/([\d.]+)/);
        if (ruleMatch) {
          governingRuleReferences.push(ruleMatch[1]);
        }
      });
    }

    // Final fallback: regex on the full text for rule number patterns
    if (governingRuleReferences.length === 0) {
      const govText = govRulesEl.text();
      const matches = govText.match(/\b(\d+\.\d+(?:\.\d+)*)\b/g);
      if (matches) {
        const seen = new Set<string>();
        for (const m of matches) {
          if (!seen.has(m)) {
            seen.add(m);
            governingRuleReferences.push(m);
          }
        }
      }
    }
  }

  // Modifier rows
  const modifierRows: HscModifierRow[] = [];
  const modifierCodes = new Set<string>();
  let surchargeEligible = false;

  $('div.modifiers table tr').each((_i, row) => {
    const tds = $(row).find('td');
    if (tds.length === 0) return; // Skip header row

    const type = tds.eq(0).text().trim();
    const modCode = tds.eq(1).text().trim();
    const calls = tds.eq(2).text().trim();
    const explicit = tds.eq(3).text().trim();
    const action = tds.eq(4).text().trim();
    const amount = tds.eq(5).text().trim();

    modifierRows.push({
      hscCode: code,
      type,
      code: modCode,
      calls,
      explicit,
      action,
      amount,
    });

    modifierCodes.add(type);
    if (type === 'SURC' || type === 'SURT' || modCode.includes('SURC') || modCode.includes('SURT')) {
      surchargeEligible = true;
    }
  });

  const feeType = categoryToFeeType(category);

  return {
    hsc: {
      hscCode: code,
      description,
      baseFee,
      category,
      feeType,
      modifierEligibility: Array.from(modifierCodes),
      surchargeEligible,
      notes,
      helpText: [description, notes, billingTips].filter(Boolean).join('\n\n'),
      commonTerms,
      billingTips,
      governingRuleReferences,
    },
    modifierRows,
  };
}

async function scrapeHscCodes(
  codes: string[],
): Promise<{ hscCodes: HscCode[]; hscModifiers: HscModifierRow[]; errors: string[] }> {
  console.log('\n=== Phase 2: Scraping HSC code detail pages ===\n');

  // Use Maps for automatic deduplication on resume
  const hscMap = new Map<string, HscCode>();
  const hscModMap = new Map<string, HscModifierRow[]>();
  const errors: string[] = [];

  // Load progress if available
  const progressFile = '_scrape-progress.json';
  const progress = loadJson<{ completed: string[] }>(OUTPUT_DIR, progressFile);
  const completedSet = new Set(progress?.completed ?? []);

  // Load previously scraped data into Maps
  const existingHsc = loadJson<HscCode[]>(OUTPUT_DIR, 'hsc-codes.json') ?? [];
  const existingMods = loadJson<HscModifierRow[]>(OUTPUT_DIR, 'hsc-modifiers.json') ?? [];

  if (existingHsc.length > 0 && completedSet.size > 0) {
    for (const h of existingHsc) {
      hscMap.set(h.hscCode, h);
    }
    for (const m of existingMods) {
      if (!hscModMap.has(m.hscCode)) {
        hscModMap.set(m.hscCode, []);
      }
      hscModMap.get(m.hscCode)!.push(m);
    }
    console.log(`  Resuming from previous run: ${completedSet.size} already scraped`);

    // Warn if existing data has enrichment fields (will be lost for re-scraped codes)
    const hasEnrichment = existingHsc.some(h =>
      (h as Record<string, unknown>).requiresReferral !== undefined ||
      (h as Record<string, unknown>).specialtyRestrictions !== undefined ||
      (h as Record<string, unknown>).bundlingExclusions !== undefined
    );
    if (hasEnrichment) {
      console.warn('  [WARN] Existing hsc-codes.json contains enrichment fields.');
      console.warn('  Re-scraped codes will lose enrichment. Run enrich-hsc-data.ts after scraping completes.');
    }
  }

  const remaining = codes.filter((c) => !completedSet.has(c));
  console.log(`  ${remaining.length} codes to scrape (${completedSet.size} already done)\n`);

  let consecutiveErrors = 0;

  for (let i = 0; i < remaining.length; i++) {
    const code = remaining[i];
    const overall = i + 1;

    try {
      const url = `${BASE_URL}/hsc/${encodeURIComponent(code)}?ajax=detail`;
      const xml = await fetchWithRetry(url);
      const html = decodeHtmlEntities(xml);

      if (!html) {
        errors.push(`Empty response for ${code}`);
        console.warn(`  [${overall}/${remaining.length}] ${code} — empty response`);
        consecutiveErrors++;
        if (consecutiveErrors >= CIRCUIT_BREAKER_THRESHOLD) {
          console.error(`\n  *** CIRCUIT BREAKER: ${consecutiveErrors} consecutive errors — aborting scrape ***`);
          console.error(`  Saving progress before exit. Resume by re-running the scraper.\n`);
          break;
        }
        continue;
      }

      const result = parseHscDetailHtml(code, html);
      if (!result) {
        errors.push(`Could not parse ${code}`);
        console.warn(`  [${overall}/${remaining.length}] ${code} — parse failed`);
        consecutiveErrors++;
        if (consecutiveErrors >= CIRCUIT_BREAKER_THRESHOLD) {
          console.error(`\n  *** CIRCUIT BREAKER: ${consecutiveErrors} consecutive errors — aborting scrape ***`);
          console.error(`  Saving progress before exit. Resume by re-running the scraper.\n`);
          break;
        }
        continue;
      }

      // Success — reset circuit breaker
      consecutiveErrors = 0;

      // Map-based storage: automatically overwrites any existing entry for this code
      hscMap.set(result.hsc.hscCode, result.hsc);
      hscModMap.set(result.hsc.hscCode, result.modifierRows);
      completedSet.add(code);

      const fee = result.hsc.baseFee ? `$${result.hsc.baseFee}` : 'no fee';
      console.log(
        `  [${overall}/${remaining.length}] Scraped ${code} (${fee}, ${result.modifierRows.length} modifiers)`,
      );

      // Save progress periodically
      if ((i + 1) % BATCH_SAVE_SIZE === 0) {
        const hscCodes = Array.from(hscMap.values());
        const hscModifiers = Array.from(hscModMap.values()).flat();
        saveJson(OUTPUT_DIR, 'hsc-codes.json', hscCodes);
        saveJson(OUTPUT_DIR, 'hsc-modifiers.json', hscModifiers);
        saveJson(OUTPUT_DIR, progressFile, { completed: Array.from(completedSet) });
        console.log(`  --- Saved progress: ${hscCodes.length} codes ---`);
      }

      await sleep(DELAY_MS);
    } catch (err) {
      errors.push(`Error scraping ${code}: ${(err as Error).message}`);
      console.error(
        `  [${overall}/${remaining.length}] ERROR ${code}: ${(err as Error).message}`,
      );
      consecutiveErrors++;
      if (consecutiveErrors >= CIRCUIT_BREAKER_THRESHOLD) {
        console.error(`\n  *** CIRCUIT BREAKER: ${consecutiveErrors} consecutive errors — aborting scrape ***`);
        console.error(`  Saving progress before exit. Resume by re-running the scraper.\n`);
        break;
      }
    }
  }

  // Final save — convert Maps to arrays, deduplicate modifiers
  const hscCodes = Array.from(hscMap.values());
  const hscModifiers = deduplicateModifierRows(Array.from(hscModMap.values()).flat());
  saveJson(OUTPUT_DIR, 'hsc-codes.json', hscCodes);
  saveJson(OUTPUT_DIR, 'hsc-modifiers.json', hscModifiers);
  saveJson(OUTPUT_DIR, progressFile, { completed: Array.from(completedSet) });

  return { hscCodes, hscModifiers, errors };
}

// ============================================================================
// Phase 3: Scrape modifiers
// ============================================================================

function parseModifierPage(
  modifierCode: string,
  html: string,
): ModifierDefinition | null {
  const $ = cheerio.load(html);

  // The modifier record
  const record = $('div.contents');
  if (!record.length) return null;

  // Name from h1 or h2
  const name =
    record.find('h1.title').text().trim() ||
    record.find('h1').text().trim() ||
    '';

  // Description
  const descParts: string[] = [];
  record.find('p, .description').each((_i, el) => {
    const text = $(el).text().trim();
    if (text) descParts.push(text);
  });
  let description = descParts.join(' ').replace(/\s+/g, ' ').trim() || name;
  // Remove AMA footer text
  description = description.replace(/\s*Alberta Medical Association.*$/i, '').trim();
  // Remove leading modifier name duplication
  if (name && description.toLowerCase().startsWith(name.toLowerCase())) {
    description = description.slice(name.length).replace(/^[\s:.\-–]+/, '').trim();
  }
  // Fallback to name if nothing remains
  if (!description) description = name;

  // Sub-codes from table
  const subCodes: Array<{ code: string; description: string }> = [];
  record.find('table tr').each((_i, row) => {
    const tds = $(row).find('td');
    if (tds.length >= 2) {
      subCodes.push({
        code: tds.eq(0).text().trim(),
        description: tds.eq(1).text().trim(),
      });
    }
  });

  return {
    modifierCode,
    name: name || modifierCode,
    description,
    subCodes,
  };
}

async function scrapeModifiers(): Promise<{
  modifiers: ModifierDefinition[];
  errors: string[];
}> {
  console.log('\n=== Phase 3: Scraping modifier definitions ===\n');

  const modifierCodes = await discoverModifierCodes();
  const modifiers: ModifierDefinition[] = [];
  const errors: string[] = [];

  for (let i = 0; i < modifierCodes.length; i++) {
    const code = modifierCodes[i];
    try {
      const url = `${BASE_URL}/modifiers/${encodeURIComponent(code)}?ajax=detail`;
      const xml = await fetchWithRetry(url);
      const html = decodeHtmlEntities(xml);

      if (!html) {
        // Try full page instead
        const fullHtml = await fetchWithRetry(
          `${BASE_URL}/modifiers/${encodeURIComponent(code)}`,
        );
        const result = parseModifierPage(code, fullHtml);
        if (result) {
          modifiers.push(result);
          console.log(
            `  [${i + 1}/${modifierCodes.length}] ${code}: ${result.name} (${result.subCodes.length} sub-codes)`,
          );
        } else {
          errors.push(`Could not parse modifier ${code}`);
          console.warn(
            `  [${i + 1}/${modifierCodes.length}] ${code} — parse failed`,
          );
        }
      } else {
        const result = parseModifierPage(code, html);
        if (result) {
          modifiers.push(result);
          console.log(
            `  [${i + 1}/${modifierCodes.length}] ${code}: ${result.name} (${result.subCodes.length} sub-codes)`,
          );
        } else {
          errors.push(`Could not parse modifier ${code}`);
        }
      }

      await sleep(DELAY_MS);
    } catch (err) {
      errors.push(`Error scraping modifier ${code}: ${(err as Error).message}`);
      console.error(`  [${i + 1}/${modifierCodes.length}] ERROR ${code}: ${(err as Error).message}`);
    }
  }

  saveJson(OUTPUT_DIR, 'modifiers.json', modifiers);
  return { modifiers, errors };
}

// ============================================================================
// Phase 4: Scrape governing rules
// ============================================================================

function parseGoverningRulePage(
  ruleNumber: string,
  html: string,
): GoverningRule | null {
  const $ = cheerio.load(html);

  const record = $('div.contents');
  if (!record.length) return null;

  // Title
  const title =
    record.find('h1.title').text().trim() ||
    record.find('h3').first().text().trim() ||
    record.find('h1').text().trim() ||
    '';

  // Full text — get all text content
  const fullText = record
    .text()
    .replace(/\s+/g, ' ')
    .trim();

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
    referencedHscCodes: Array.from(referencedHscCodes),
  };
}

async function discoverTopLevelRuleIds(): Promise<number[]> {
  console.log('  Discovering top-level governing rule IDs...');
  const ids = new Set<number>();

  try {
    const html = await fetchWithRetry(`${BASE_URL}/governing-rules`);
    const $ = cheerio.load(html);

    // Extract from links matching /governing-rules/N
    $('a[href*="/governing-rules/"]').each((_i, el) => {
      const href = $(el).attr('href') ?? '';
      const match = href.match(/\/governing-rules\/(\d+)(?:\?|$|#)/);
      if (match) ids.add(parseInt(match[1], 10));
    });

    // Also check expandable/viewable tree nodes
    $('div.node.expandable, a.node.expandable, div.node.viewable, a.node.viewable').each((_i, el) => {
      const key = $(el).attr('data-key');
      if (key && /^\d+$/.test(key)) {
        ids.add(parseInt(key, 10));
      }
    });
  } catch (err) {
    console.warn(`  [WARN] Could not discover governing rule IDs: ${(err as Error).message}`);
  }

  if (ids.size === 0) {
    console.warn('  [WARN] No governing rule IDs discovered — falling back to 1-19');
    return Array.from({ length: 19 }, (_, i) => i + 1);
  }

  const sorted = Array.from(ids).sort((a, b) => a - b);
  console.log(`  Found ${sorted.length} top-level rule IDs: [${sorted.join(', ')}]`);
  return sorted;
}

async function scrapeGoverningRules(): Promise<{
  rules: GoverningRule[];
  errors: string[];
}> {
  console.log('\n=== Phase 4: Scraping governing rules ===\n');

  const rules: GoverningRule[] = [];
  const errors: string[] = [];

  // Dynamically discover top-level rule IDs
  const topLevelIds = await discoverTopLevelRuleIds();
  console.log(`  Scraping ${topLevelIds.length} top-level governing rules...\n`);

  for (let idx = 0; idx < topLevelIds.length; idx++) {
    const ruleId = topLevelIds[idx];
    try {
      // Try AJAX first, fall back to full page
      let html: string;
      try {
        const xml = await fetchWithRetry(
          `${BASE_URL}/governing-rules/${ruleId}?ajax=detail`,
        );
        html = decodeHtmlEntities(xml);
        if (!html) throw new Error('empty');
      } catch {
        html = await fetchWithRetry(`${BASE_URL}/governing-rules/${ruleId}`);
      }

      const result = parseGoverningRulePage(String(ruleId), html);
      if (result) {
        rules.push(result);
        console.log(
          `  [${idx + 1}/${topLevelIds.length}] GR ${ruleId}: ${result.title.slice(0, 60)} (${result.referencedHscCodes.length} HSC refs)`,
        );
      } else {
        errors.push(`Could not parse governing rule ${ruleId}`);
        console.warn(`  [${idx + 1}/${topLevelIds.length}] GR ${ruleId} — parse failed`);
      }

      await sleep(DELAY_MS);
    } catch (err) {
      errors.push(`Error scraping GR ${ruleId}: ${(err as Error).message}`);
      console.error(`  [${idx + 1}/${topLevelIds.length}] ERROR GR ${ruleId}: ${(err as Error).message}`);
    }
  }

  // Discover and fetch sub-rule pages (SCR-022)
  const subRuleIds = await discoverSubRulePages(rules);
  let subRuleCount = 0;

  for (const subRuleId of subRuleIds) {
    try {
      let html: string;
      try {
        const xml = await fetchWithRetry(`${BASE_URL}/governing-rules/${subRuleId}?ajax=detail`);
        html = decodeHtmlEntities(xml);
        if (!html) throw new Error('empty');
      } catch {
        html = await fetchWithRetry(`${BASE_URL}/governing-rules/${subRuleId}`);
      }

      const result = parseGoverningRulePage(subRuleId, html);
      if (result && result.referencedHscCodes.length > 0) {
        // Merge HSC refs into parent rule
        const parentId = subRuleId.split('.')[0];
        const parentRule = rules.find((r) => r.ruleNumber === parentId);
        if (parentRule) {
          const existingCodes = new Set(parentRule.referencedHscCodes);
          for (const code of result.referencedHscCodes) {
            existingCodes.add(code);
          }
          parentRule.referencedHscCodes = Array.from(existingCodes);
          console.log(
            `  Sub-rule ${subRuleId}: ${result.referencedHscCodes.length} HSC refs merged into GR ${parentId}`,
          );
        }

        // Store as its own entry
        rules.push(result);
        subRuleCount++;
        console.log(
          `  Scraped sub-rule ${subRuleId}: ${result.title.slice(0, 60)} (${result.referencedHscCodes.length} HSC refs)`,
        );
      }

      await sleep(DELAY_MS);
    } catch {
      console.log(`  Sub-rule ${subRuleId}: page not found or empty (skipping)`);
    }
  }

  if (subRuleCount > 0) {
    console.log(`  ${subRuleCount} sub-rules added`);
  }

  saveJson(OUTPUT_DIR, 'governing-rules.json', rules);
  return { rules, errors };
}

// ============================================================================
// Phase 5: Scrape explanatory codes
// ============================================================================

async function scrapeExplanatoryCodes(): Promise<{
  codes: ExplanatoryCode[];
  errors: string[];
}> {
  console.log('\n=== Phase 5: Scraping explanatory codes ===\n');

  const allCodes: ExplanatoryCode[] = [];
  const errors: string[] = [];

  try {
    // Step 1: Get the main page to find expandable category nodes
    const mainHtml = await fetchWithRetry(`${BASE_URL}/explanatory-codes`);
    const $main = cheerio.load(mainHtml);

    // Find expandable category nodes with data-key
    const categories: Array<{ key: string; title: string }> = [];
    $main('div.node.expandable').each((_i, el) => {
      const key = $main(el).attr('data-key') ?? '';
      const title = $main(el).find('div.title').text().trim();
      if (key) {
        categories.push({ key, title });
      }
    });

    console.log(`  Found ${categories.length} expandable categories`);

    // Step 2: Expand each category via AJAX to find viewable codes
    const expandUrl = `${BASE_URL}/explanatory-codes?ajax=expanded`;

    for (const cat of categories) {
      try {
        const body = `expanded=${cat.key}&expand=${cat.key}`;
        const xml = await fetchWithRetry(expandUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Referer: `${BASE_URL}/explanatory-codes`,
          },
          body,
        });

        const html = decodeHtmlEntities(xml);
        if (!html) continue;

        // Parse viewable nodes: they have code and title divs
        const $ = cheerio.load(html);
        $('a.node.viewable').each((_i, el) => {
          const code = $(el).find('div.code').text().trim();
          const title = $(el).find('div.title').text().trim();
          if (code) {
            allCodes.push({
              code,
              description: title,
              category: cat.title,
            });
          }
        });

        await sleep(100);
      } catch (err) {
        errors.push(
          `Error expanding explanatory codes category ${cat.title}: ${(err as Error).message}`,
        );
      }
    }

    console.log(`  Discovered ${allCodes.length} explanatory codes from tree expansion`);

    // Step 3: Optionally fetch each code's detail page for more info
    let detailFetchErrors = 0;
    for (let i = 0; i < allCodes.length; i++) {
      const ec = allCodes[i];
      try {
        const url = `${BASE_URL}/explanatory-codes/${encodeURIComponent(ec.code)}?ajax=detail`;
        const xml = await fetchWithRetry(url);
        const html = decodeHtmlEntities(xml);
        if (html) {
          const $ = cheerio.load(html);
          const detailDesc =
            $('h1.title').text().trim() ||
            $('div.contents p').first().text().trim();
          if (detailDesc && detailDesc.length > ec.description.length) {
            ec.description = detailDesc;
          }
        }
      } catch {
        detailFetchErrors++;
        // Detail page may not exist for all codes; keep what we have
      }

      if ((i + 1) % 20 === 0) {
        console.log(
          `  [${i + 1}/${allCodes.length}] Enriching explanatory codes...`,
        );
      }
      await sleep(100);
    }
    if (detailFetchErrors > 0) {
      console.log(`  ${detailFetchErrors} detail page fetches failed (using tree-expansion descriptions as fallback)`);
    }
    if (detailFetchErrors > 10) {
      errors.push(`${detailFetchErrors} explanatory code detail fetches failed — descriptions may be incomplete`);
    }
  } catch (err) {
    errors.push(
      `Error fetching explanatory codes: ${(err as Error).message}`,
    );
    console.error(`  ERROR: ${(err as Error).message}`);
  }

  // Deduplicate by code
  const uniqueCodes = new Map<string, ExplanatoryCode>();
  for (const code of allCodes) {
    if (!uniqueCodes.has(code.code)) {
      uniqueCodes.set(code.code, code);
    }
  }
  const deduped = Array.from(uniqueCodes.values());

  saveJson(OUTPUT_DIR, 'explanatory-codes.json', deduped);
  return { codes: deduped, errors };
}

// ============================================================================
// Main
// ============================================================================

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

async function main(): Promise<void> {
  const startTime = Date.now();
  const allErrors: string[] = [];

  console.log('=========================================');
  console.log('  AMA Fee Navigator Scraper');
  console.log(`  Output: ${OUTPUT_DIR}`);
  console.log('=========================================');

  ensureDir(OUTPUT_DIR);
  acquireLock();
  process.on('exit', releaseLock);

  // Phase 1: Discover all HSC codes
  const { codes, rootSectionKeyCount } = await discoverAllHscCodes();

  // Phase 2: Scrape each HSC code detail page
  const { hscCodes, hscModifiers, errors: hscErrors } = await scrapeHscCodes(codes);
  allErrors.push(...hscErrors);

  // Phase 3: Scrape modifiers
  const { modifiers, errors: modErrors } = await scrapeModifiers();
  allErrors.push(...modErrors);

  // Phase 4: Scrape governing rules
  const { rules, errors: grErrors } = await scrapeGoverningRules();
  allErrors.push(...grErrors);

  // Phase 5: Scrape explanatory codes
  const { codes: explCodes, errors: explErrors } =
    await scrapeExplanatoryCodes();
  allErrors.push(...explErrors);

  // Save metadata
  const durationSeconds = Math.round((Date.now() - startTime) / 1000);
  const topLevelRuleCount = rules.filter((r) => !r.ruleNumber.includes('.')).length;
  const subRuleCount = rules.length - topLevelRuleCount;
  const metadata: ScrapeMetadata = {
    timestamp: new Date().toISOString(),
    durationSeconds,
    counts: {
      rootSectionKeys: rootSectionKeyCount,
      hscCodes: hscCodes.length,
      hscModifierRows: hscModifiers.length,
      modifiers: modifiers.length,
      governingRules: rules.length,
      governingRuleSubRules: subRuleCount,
      explanatoryCodes: explCodes.length,
    },
    errors: allErrors,
  };
  saveJson(OUTPUT_DIR, 'scrape-metadata.json', metadata);

  // Clean up progress file
  const progressPath = path.join(OUTPUT_DIR, '_scrape-progress.json');
  if (fs.existsSync(progressPath)) {
    fs.unlinkSync(progressPath);
  }

  // Run post-scrape validation
  console.log('\n=== Running post-scrape validation ===\n');
  try {
    const { execSync } = await import('node:child_process');
    const validateScript = path.join(
      path.dirname(new URL(import.meta.url).pathname),
      'validate-fee-navigator-data.ts',
    );
    const tsxPath = path.join(process.cwd(), 'apps', 'api', 'node_modules', '.bin', 'tsx');
    execSync(`"${tsxPath}" "${validateScript}" --skip-enrichment`, { stdio: 'inherit' });
    console.log('\n  Post-scrape validation: PASSED\n');
  } catch {
    console.error('\n  *** POST-SCRAPE VALIDATION FAILED ***');
    console.error('  Review the validation output above before using this data.');
    console.error('  The scraped data may be incomplete or corrupted.\n');
    process.exit(2);
  }

  console.log('\n=========================================');
  console.log('  Scrape Complete!');
  console.log(`  Duration: ${Math.floor(durationSeconds / 60)}m ${durationSeconds % 60}s`);
  console.log(`  HSC codes: ${hscCodes.length}`);
  console.log(`  HSC modifier rows: ${hscModifiers.length}`);
  console.log(`  Modifiers: ${modifiers.length}`);
  console.log(`  Governing rules: ${rules.length}`);
  console.log(`  Explanatory codes: ${explCodes.length}`);
  console.log(`  Errors: ${allErrors.length}`);
  console.log('=========================================');
}

main().catch((err) => {
  console.error('Scraper failed:', err);
  process.exit(1);
});
