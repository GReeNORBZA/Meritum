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

// ============================================================================
// Configuration
// ============================================================================

const BASE_URL = 'https://apps.albertadoctors.org/fee-navigator';
const DELAY_MS = 200; // Polite crawling delay between requests
const MAX_RETRIES = 3;
const BATCH_SAVE_SIZE = 100; // Save progress every N codes
const OUTPUT_DIR = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  'data',
  'fee-navigator',
);

const HEADERS: Record<string, string> = {
  'User-Agent':
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  Referer: `${BASE_URL}/hsc`,
  'X-Requested-With': 'XMLHttpRequest',
};

// Root section data-keys from the HSC main page tree
const ROOT_SECTION_KEYS = [
  2, 147, 232, 246, 351, 385, 466, 526, 679, 704, 879, 952, 1090, 1322, 1342,
  1390, 1394, 1421, 1462,
];

// All 42 modifier codes from the modifiers listing page
const MODIFIER_CODES = [
  'AGE', 'ANEU', 'ANU', 'ARFC', 'BMI', 'CAGE', 'CALL', 'CARE', 'CMPD',
  'CMPX', 'INCS', 'LEVL', 'LMTS', 'LVP', 'NBPG', 'NBTR', 'NOFL', 'RECO',
  'REDO', 'REPT', 'ROLE', 'SAQU', 'SAU', 'SESU', 'SKLL', 'SOSU', 'SSOU',
  'SSPU', 'SUBD', 'SURC', 'SURT', 'TELE', 'TRAY', 'TSAR', 'UGA', 'UNDP',
  'VANE', 'XRAY', '2ANU', '2MNU', '2MPU', '2MSU',
];

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
    hscCodes: number;
    hscModifierRows: number;
    modifiers: number;
    governingRules: number;
    explanatoryCodes: number;
  };
  errors: string[];
}

// ============================================================================
// Utility functions
// ============================================================================

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetry(
  url: string,
  options: RequestInit = {},
  retries = MAX_RETRIES,
): Promise<string> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const resp = await fetch(url, {
        ...options,
        headers: { ...HEADERS, ...(options.headers as Record<string, string>) },
      });
      if (resp.status === 429 || resp.status === 503) {
        const backoff = Math.pow(2, attempt) * 1000;
        console.warn(
          `  [RETRY] ${resp.status} on ${url} — waiting ${backoff}ms (attempt ${attempt}/${retries})`,
        );
        await sleep(backoff);
        continue;
      }
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      return await resp.text();
    } catch (err) {
      if (attempt === retries) throw err;
      const backoff = Math.pow(2, attempt) * 1000;
      console.warn(
        `  [RETRY] Error on ${url}: ${(err as Error).message} — waiting ${backoff}ms (attempt ${attempt}/${retries})`,
      );
      await sleep(backoff);
    }
  }
  throw new Error(`Failed after ${retries} retries: ${url}`);
}

function decodeHtmlEntities(xml: string): string {
  const contentMatch = xml.match(/<content>([\s\S]*?)<\/content>/);
  if (!contentMatch) return '';
  // The content is HTML-escaped inside XML
  return contentMatch[1]
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'");
}

/** Map category string to fee type */
function categoryToFeeType(category: string | null): string {
  if (!category) return 'UNKNOWN';
  const cat = category.trim();

  // Numeric-prefixed categories are Major Procedures (e.g. "14 Major Procedure ...")
  if (/^\d+\s/.test(cat)) return 'PROCEDURE';

  const letter = cat.charAt(0).toUpperCase();
  switch (letter) {
    case 'V':
      return 'VISIT';
    case 'P':
      return 'PROCEDURE';
    case 'M':
      return 'FIXED';
    case 'C':
      // "C Anaesthetic" is anesthesia, not consultation
      return cat.startsWith('C Ana') ? 'ANESTHESIA' : 'CONSULTATION';
    case 'L':
      return 'LABORATORY';
    case 'R':
      // "R Surgical Assist" is procedural, not radiology
      return cat.startsWith('R Surg') ? 'PROCEDURE' : 'RADIOLOGY';
    case 'A':
      return 'ANESTHESIA';
    case 'T':
      return 'THERAPEUTIC';
    default:
      return 'OTHER';
  }
}

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function saveJson(filename: string, data: unknown): void {
  ensureDir(OUTPUT_DIR);
  const filePath = path.join(OUTPUT_DIR, filename);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  console.log(`  Saved ${filePath}`);
}

function loadProgress<T>(filename: string): T | null {
  const filePath = path.join(OUTPUT_DIR, filename);
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  }
  return null;
}

// ============================================================================
// Phase 1: Discover all HSC codes via tree expansion
// ============================================================================

async function discoverAllHscCodes(): Promise<string[]> {
  console.log('\n=== Phase 1: Discovering HSC codes via tree expansion ===\n');

  // Check for cached discovery
  const cached = loadProgress<string[]>('_discovered-codes.json');
  if (cached && cached.length > 0) {
    console.log(`  Found cached discovery: ${cached.length} codes. Reusing.`);
    return cached;
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

    // Expandable nodes have numeric data-key
    const expandables =
      html.match(/class="node expandable" data-key="(\d+)"/g)?.map((m) => {
        const match = m.match(/data-key="(\d+)"/);
        return match ? match[1] : '';
      }).filter(Boolean) ?? [];

    // Viewable nodes have code as data-key and href
    const viewables =
      html.match(/href="\/fee-navigator\/hsc\/([^"]+)"/g)?.map((m) => {
        const match = m.match(/href="\/fee-navigator\/hsc\/([^"]+)"/);
        return match ? decodeURIComponent(match[1]) : '';
      }).filter(Boolean) ?? [];

    return { expandables, viewables };
  }

  // BFS queue: [keyToExpand, expandedKeysSoFar[]]
  const queue: Array<[string, string[]]> = ROOT_SECTION_KEYS.map((k) => [
    String(k),
    [String(k)],
  ]);

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
  saveJson('_discovered-codes.json', codes);

  return codes;
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
      baseFee = feeMatch ? feeMatch[1].replace(',', '') : null;
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
    if (type === 'SURC' || type === 'SURT' || modCode.includes('SURC')) {
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
    },
    modifierRows,
  };
}

async function scrapeHscCodes(
  codes: string[],
): Promise<{ hscCodes: HscCode[]; hscModifiers: HscModifierRow[]; errors: string[] }> {
  console.log('\n=== Phase 2: Scraping HSC code detail pages ===\n');

  const hscCodes: HscCode[] = [];
  const hscModifiers: HscModifierRow[] = [];
  const errors: string[] = [];

  // Load progress if available
  const progressFile = '_scrape-progress.json';
  const progress = loadProgress<{ completed: string[] }>(progressFile);
  const completedSet = new Set(progress?.completed ?? []);

  // Load previously scraped data
  const existingHsc = loadProgress<HscCode[]>('hsc-codes.json') ?? [];
  const existingMods = loadProgress<HscModifierRow[]>('hsc-modifiers.json') ?? [];

  if (existingHsc.length > 0 && completedSet.size > 0) {
    hscCodes.push(...existingHsc);
    hscModifiers.push(...existingMods);
    console.log(`  Resuming from previous run: ${completedSet.size} already scraped`);
  }

  const remaining = codes.filter((c) => !completedSet.has(c));
  console.log(`  ${remaining.length} codes to scrape (${completedSet.size} already done)\n`);

  for (let i = 0; i < remaining.length; i++) {
    const code = remaining[i];
    const overall = i + 1;

    try {
      const url = `${BASE_URL}/hsc/${encodeURIComponent(code)}?ajax=detail`;
      const xml = await fetchWithRetry(url);
      const html = decodeHtmlEntities(xml);

      if (!html) {
        errors.push(`Empty response for ${code}`);
        console.warn(`  [${overall}/${codes.length}] ${code} — empty response`);
        continue;
      }

      const result = parseHscDetailHtml(code, html);
      if (!result) {
        errors.push(`Could not parse ${code}`);
        console.warn(`  [${overall}/${codes.length}] ${code} — parse failed`);
        continue;
      }

      hscCodes.push(result.hsc);
      hscModifiers.push(...result.modifierRows);
      completedSet.add(code);

      const fee = result.hsc.baseFee ? `$${result.hsc.baseFee}` : 'no fee';
      console.log(
        `  [${overall}/${codes.length}] Scraped ${code} (${fee}, ${result.modifierRows.length} modifiers)`,
      );

      // Save progress periodically
      if ((i + 1) % BATCH_SAVE_SIZE === 0) {
        saveJson('hsc-codes.json', hscCodes);
        saveJson('hsc-modifiers.json', hscModifiers);
        saveJson(progressFile, { completed: Array.from(completedSet) });
        console.log(`  --- Saved progress: ${hscCodes.length} codes ---`);
      }

      await sleep(DELAY_MS);
    } catch (err) {
      errors.push(`Error scraping ${code}: ${(err as Error).message}`);
      console.error(
        `  [${overall}/${codes.length}] ERROR ${code}: ${(err as Error).message}`,
      );
    }
  }

  // Final save
  saveJson('hsc-codes.json', hscCodes);
  saveJson('hsc-modifiers.json', hscModifiers);
  saveJson(progressFile, { completed: Array.from(completedSet) });

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
  const description = descParts.join(' ').replace(/\s+/g, ' ').trim() || name;

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

  const modifiers: ModifierDefinition[] = [];
  const errors: string[] = [];

  for (let i = 0; i < MODIFIER_CODES.length; i++) {
    const code = MODIFIER_CODES[i];
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
            `  [${i + 1}/${MODIFIER_CODES.length}] ${code}: ${result.name} (${result.subCodes.length} sub-codes)`,
          );
        } else {
          errors.push(`Could not parse modifier ${code}`);
          console.warn(
            `  [${i + 1}/${MODIFIER_CODES.length}] ${code} — parse failed`,
          );
        }
      } else {
        const result = parseModifierPage(code, html);
        if (result) {
          modifiers.push(result);
          console.log(
            `  [${i + 1}/${MODIFIER_CODES.length}] ${code}: ${result.name} (${result.subCodes.length} sub-codes)`,
          );
        } else {
          errors.push(`Could not parse modifier ${code}`);
        }
      }

      await sleep(DELAY_MS);
    } catch (err) {
      errors.push(`Error scraping modifier ${code}: ${(err as Error).message}`);
      console.error(`  [${i + 1}/${MODIFIER_CODES.length}] ERROR ${code}: ${(err as Error).message}`);
    }
  }

  saveJson('modifiers.json', modifiers);
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

async function scrapeGoverningRules(): Promise<{
  rules: GoverningRule[];
  errors: string[];
}> {
  console.log('\n=== Phase 4: Scraping governing rules ===\n');

  const rules: GoverningRule[] = [];
  const errors: string[] = [];

  // Rules 1-19 (some may have sub-rules like 6.8.1)
  for (let i = 1; i <= 19; i++) {
    try {
      // Try AJAX first, fall back to full page
      let html: string;
      try {
        const xml = await fetchWithRetry(
          `${BASE_URL}/governing-rules/${i}?ajax=detail`,
        );
        html = decodeHtmlEntities(xml);
        if (!html) throw new Error('empty');
      } catch {
        html = await fetchWithRetry(`${BASE_URL}/governing-rules/${i}`);
      }

      const result = parseGoverningRulePage(String(i), html);
      if (result) {
        rules.push(result);
        console.log(
          `  [${i}/19] GR ${i}: ${result.title.slice(0, 60)} (${result.referencedHscCodes.length} HSC refs)`,
        );
      } else {
        errors.push(`Could not parse governing rule ${i}`);
        console.warn(`  [${i}/19] GR ${i} — parse failed`);
      }

      await sleep(DELAY_MS);
    } catch (err) {
      errors.push(`Error scraping GR ${i}: ${(err as Error).message}`);
      console.error(`  [${i}/19] ERROR GR ${i}: ${(err as Error).message}`);
    }
  }

  saveJson('governing-rules.json', rules);
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
        // Detail page may not exist for all codes; keep what we have
      }

      if ((i + 1) % 20 === 0) {
        console.log(
          `  [${i + 1}/${allCodes.length}] Enriching explanatory codes...`,
        );
      }
      await sleep(100);
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

  saveJson('explanatory-codes.json', deduped);
  return { codes: deduped, errors };
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  const startTime = Date.now();
  const allErrors: string[] = [];

  console.log('=========================================');
  console.log('  AMA Fee Navigator Scraper');
  console.log(`  Output: ${OUTPUT_DIR}`);
  console.log('=========================================');

  ensureDir(OUTPUT_DIR);

  // Phase 1: Discover all HSC codes
  const codes = await discoverAllHscCodes();

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
  const metadata: ScrapeMetadata = {
    timestamp: new Date().toISOString(),
    durationSeconds,
    counts: {
      hscCodes: hscCodes.length,
      hscModifierRows: hscModifiers.length,
      modifiers: modifiers.length,
      governingRules: rules.length,
      explanatoryCodes: explCodes.length,
    },
    errors: allErrors,
  };
  saveJson('scrape-metadata.json', metadata);

  // Clean up progress file
  const progressPath = path.join(OUTPUT_DIR, '_scrape-progress.json');
  if (fs.existsSync(progressPath)) {
    fs.unlinkSync(progressPath);
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
