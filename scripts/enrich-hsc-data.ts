#!/usr/bin/env tsx
// ============================================================================
// Meritum — HSC Data Enrichment Script
// Post-processes scraped hsc-codes.json by fetching GR 4.4.8 (referral
// requirements) and GR 1.33 (facility designations) from Fee Navigator.
//
// Usage: cd /workspace/projects && npx tsx scripts/enrich-hsc-data.ts
// ============================================================================

import * as cheerio from 'cheerio';
import * as fs from 'node:fs';
import * as path from 'node:path';

// ============================================================================
// Configuration
// ============================================================================

const BASE_URL = 'https://apps.albertadoctors.org/fee-navigator';
const MAX_RETRIES = 3;

const HEADERS: Record<string, string> = {
  'User-Agent':
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  Referer: `${BASE_URL}/governing-rules`,
  'X-Requested-With': 'XMLHttpRequest',
};

const DATA_DIR = path.join(
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
  // Enriched fields — GR-based
  requiresReferral?: boolean;
  selfReferralBlocked?: boolean;
  facilityDesignation?: 'in_office' | 'out_of_office' | null;
  // Enriched fields — notes-based
  specialtyRestrictions?: string[];
  bundlingExclusions?: BundlingExclusion[];
  ageRestriction?: AgeRestriction | null;
  maxPerDay?: number | null;
  maxPerVisit?: number | null;
  frequencyRestriction?: FrequencyRestriction | null;
  requiresAnesthesia?: boolean;
}

interface BundlingExclusion {
  excludedCode: string;
  relationship: 'not_claimable_with' | 'same_day_exclusion';
}

interface AgeRestriction {
  text: string;
  minYears?: number;
  maxYears?: number;
  minMonths?: number;
  maxMonths?: number;
}

interface FrequencyRestriction {
  text: string;
  count: number;
  period: string;
}

// ============================================================================
// Utilities
// ============================================================================

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetry(
  url: string,
  retries = MAX_RETRIES,
): Promise<string> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const resp = await fetch(url, { headers: HEADERS });
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
  return contentMatch[1]
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'");
}

// ============================================================================
// Notes Text Extraction — Structured data from notes field
// ============================================================================

/**
 * Extract specialty restrictions from notes text.
 * Pattern: "May only be claimed by [specialty]"
 */
function extractSpecialtyRestrictions(notes: string): string[] {
  const restrictions: string[] = [];
  // Notes use "." directly followed by next sentence (no space).
  // Terminate at period NOT followed by a digit (avoids matching periods in HSC codes).
  const pattern =
    /(?:May only be claimed by|only\s+.*?claimed by)\s+(.+?)(?:\.(?!\d)|$)/gi;
  let match;
  while ((match = pattern.exec(notes)) !== null) {
    // Split on "or" / "and" / commas for multi-specialty restrictions
    const raw = match[1].trim();
    const parts = raw
      .split(/\s*(?:,(?!\d)\s*(?:or|and)\s*|,(?!\d)\s*|\s+or\s+|\s+and\s+)\s*/i)
      .map((s) => s.trim())
      .filter(
        (s) =>
          s.length > 2 &&
          !s.match(
            /^(?:a|an|the|physicians?|who|with|working|in|at|for)$/i,
          ),
      );
    restrictions.push(...parts);
  }
  return [...new Set(restrictions)];
}

/**
 * Extract bundling/combination exclusions and same-day restrictions from notes.
 * Patterns:
 *   - "May not be claimed with HSC XX.XXX"
 *   - "not payable ... in addition to HSC XX.XXX"
 *   - "May not be claimed on the same day as HSC XX.XXX"
 */
function extractBundlingExclusions(
  _sourceCode: string,
  notes: string,
): BundlingExclusion[] {
  const exclusions: BundlingExclusion[] = [];
  const seen = new Set<string>();

  // Pattern 1: Direct "not claimed with" pattern
  // Terminator: period NOT followed by digit (sentence end, not code-internal period)
  const withPattern =
    /(?:May not be claimed|not\s+(?:be\s+)?payable|not\s+(?:be\s+)?claimed|shall not be (?:submitted|claimed)).*?(?:with|in addition to)\s+HSC[s]?\s+([\d.,\s/andor\w]+?)(?:\.(?!\d)|$)/gi;
  let match;
  while ((match = withPattern.exec(notes)) !== null) {
    const codes = extractHscCodesFromText(match[1]);
    for (const code of codes) {
      const key = `not_claimable_with:${code}`;
      if (!seen.has(key)) {
        seen.add(key);
        exclusions.push({ excludedCode: code, relationship: 'not_claimable_with' });
      }
    }
  }

  // Pattern 2: Same-day exclusions
  const sameDayPattern =
    /(?:May not be claimed|not\s+(?:be\s+)?claimed|shall not be (?:submitted|claimed)).*?(?:on the same day|same date of service|same shift|same visit|same encounter|same session).*?(?:as\s+)?(?:HSC[s]?\s+)?([\d.,\s/andor\w]+?)(?:\.(?!\d)|$)/gi;
  while ((match = sameDayPattern.exec(notes)) !== null) {
    const codes = extractHscCodesFromText(match[1]);
    for (const code of codes) {
      const key = `same_day_exclusion:${code}`;
      if (!seen.has(key)) {
        seen.add(key);
        exclusions.push({ excludedCode: code, relationship: 'same_day_exclusion' });
      }
    }
  }

  return exclusions;
}

/**
 * Extract HSC code references from a text fragment.
 * Matches patterns like: 01.03, 03.08A, 48.15B, 95.14C
 */
function extractHscCodesFromText(text: string): string[] {
  const codePattern = /\b(\d{2}\.\d{2,3}[A-Z]{0,3})\b/g;
  const codes: string[] = [];
  let match;
  while ((match = codePattern.exec(text)) !== null) {
    codes.push(match[1]);
  }
  return codes;
}

/**
 * Extract age restrictions from notes text.
 * Patterns:
 *   - "patients aged 12 months or younger"
 *   - "18 years of age and under"
 *   - "65 years and older"
 */
function extractAgeRestriction(notes: string): AgeRestriction | null {
  // Match various age patterns
  const agePatterns = [
    // "X months or younger/under"
    /(\d+)\s*months?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+under)/i,
    // "X years of age and under / or younger"
    /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+under)/i,
    // "X years of age and older / or older"
    /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i,
    // "X months or older"
    /(\d+)\s*months?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i,
    // "between X and Y years"
    /between\s+(\d+)\s*and\s*(\d+)\s*years/i,
    // "aged X to Y"
    /aged?\s+(\d+)\s*(?:to|-)\s*(\d+)/i,
  ];

  for (const pattern of agePatterns) {
    const match = notes.match(pattern);
    if (!match) continue;

    const patternStr = pattern.source;

    // Determine what was matched
    if (patternStr.includes('months') && patternStr.includes('younger|under')) {
      return {
        text: match[0],
        maxMonths: parseInt(match[1], 10),
      };
    }
    if (patternStr.includes('years') && patternStr.includes('younger|under')) {
      return {
        text: match[0],
        maxYears: parseInt(match[1], 10),
      };
    }
    if (patternStr.includes('years') && patternStr.includes('older|over')) {
      return {
        text: match[0],
        minYears: parseInt(match[1], 10),
      };
    }
    if (patternStr.includes('months') && patternStr.includes('older|over')) {
      return {
        text: match[0],
        minMonths: parseInt(match[1], 10),
      };
    }
    if (patternStr.includes('between') || patternStr.includes('to|-')) {
      return {
        text: match[0],
        minYears: parseInt(match[1], 10),
        maxYears: parseInt(match[2], 10),
      };
    }
  }

  // Also check for compound restrictions: "18 and under ... 65 and older"
  const underMatch = notes.match(
    /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+under)/i,
  );
  const overMatch = notes.match(
    /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i,
  );

  if (underMatch && overMatch) {
    return {
      text: `${underMatch[0]} and ${overMatch[0]}`,
      maxYears: parseInt(underMatch[1], 10),
      minYears: parseInt(overMatch[1], 10),
    };
  }

  return null;
}

/**
 * Extract frequency limits from notes text.
 * Patterns:
 *   - "once per year"
 *   - "4 times per patient per calendar year"
 *   - "maximum of 15 calls per patient per benefit year"
 *   - "once per patient per day"
 */
function extractFrequencyLimit(notes: string): {
  maxPerDay: number | null;
  maxPerVisit: number | null;
  restriction: FrequencyRestriction | null;
} {
  const result = {
    maxPerDay: null as number | null,
    maxPerVisit: null as number | null,
    restriction: null as FrequencyRestriction | null,
  };

  // Pattern: "once/X times per day"
  const perDayMatch = notes.match(
    /(?:(?:once|(\d+)\s*times?)|(?:a\s+)?maximum\s+(?:of\s+)?(\d+))\s*(?:per|each)\s*(?:patient\s*,?\s*per\s*)?(?:physician\s*,?\s*per\s*)?day/i,
  );
  if (perDayMatch) {
    result.maxPerDay = perDayMatch[1]
      ? parseInt(perDayMatch[1], 10)
      : perDayMatch[2]
        ? parseInt(perDayMatch[2], 10)
        : 1;
  }

  // Pattern: "once/X times per visit"
  const perVisitMatch = notes.match(
    /(?:(?:once|(\d+)\s*times?)|(?:a\s+)?maximum\s+(?:of\s+)?(\d+))\s*(?:per|each)\s*(?:patient\s*,?\s*per\s*)?visit/i,
  );
  if (perVisitMatch) {
    result.maxPerVisit = perVisitMatch[1]
      ? parseInt(perVisitMatch[1], 10)
      : perVisitMatch[2]
        ? parseInt(perVisitMatch[2], 10)
        : 1;
  }

  // General frequency pattern for non-day/visit periods
  const freqPattern =
    /(?:(?:once|(\d+)\s*times?)|(?:a\s+)?maximum\s+(?:of\s+)?(\d+)(?:\s+(?:calls?|claims?|sessions?))?)\s*(?:per|every|each)\s*(?:patient\s*,?\s*(?:per\s*)?)?(?:physician\s*,?\s*(?:per\s*)?)?(year|calendar year|benefit year|lifetime|12[- ]?month|pregnancy|calendar week|calendar month|week|month|365[- ]?day)/i;
  const freqMatch = notes.match(freqPattern);
  if (freqMatch) {
    const count = freqMatch[1]
      ? parseInt(freqMatch[1], 10)
      : freqMatch[2]
        ? parseInt(freqMatch[2], 10)
        : 1;
    const period = freqMatch[3].toLowerCase().replace(/\s+/g, '_');
    result.restriction = {
      text: freqMatch[0].trim(),
      count,
      period,
    };
  }

  return result;
}

/**
 * Extract anesthesia requirements from notes text.
 * Pattern: "under general anesthesia" / "procedural sedation"
 */
function extractAnesthesiaRequirement(notes: string): boolean {
  return /(?:under\s+general\s+anesthesia|requires?\s+(?:general\s+)?anesthesia)/i.test(
    notes,
  );
}

// ============================================================================
// Parse GR 4.4.8 — Referral Requirements
// ============================================================================

function parseGR448(html: string): {
  requiresReferral: Set<string>;
  selfReferralBlocked: Set<string>;
} {
  const $ = cheerio.load(html);
  const requiresReferral = new Set<string>();
  const selfReferralBlocked = new Set<string>();

  // Get the full text content to search for GR 4.4.8 section
  const fullText = $.text();

  // Strategy 1: Find internal-link anchors to HSC codes in the 4.4.8 section
  // The GR 4 page contains multiple sub-sections. Look for 4.4.8 content.
  const allText = $('body').text();

  // Find all HSC code references via links
  $('a[href*="/fee-navigator/hsc/"], a.internal-link').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const codeMatch = href.match(/\/fee-navigator\/hsc\/([^?&#]+)/);
    if (codeMatch) {
      const code = decodeURIComponent(codeMatch[1]);
      requiresReferral.add(code);
    }
  });

  // Strategy 2: Extract HSC codes from text near "4.4.8" and "referring"
  // Look for patterns like "03.08A*" or "03.08A" in text
  const section448Match = allText.match(
    /4\.4\.8[\s\S]*?(?:referring|referral)[\s\S]*?(?=4\.4\.9|\b4\.5\b|$)/i,
  );

  if (section448Match) {
    const sectionText = section448Match[0];

    // Extract HSC codes (format: XX.XXY or XX.XXYY where X=digit, Y=letter)
    const codePattern = /\b(\d{2}\.\d{2}[A-Z]{1,3})\s*(\*)?/g;
    let match;
    while ((match = codePattern.exec(sectionText)) !== null) {
      const code = match[1];
      const hasAsterisk = match[2] === '*';
      requiresReferral.add(code);
      if (hasAsterisk) {
        selfReferralBlocked.add(code);
      }
    }
  }

  // Strategy 3: Parse structured list items
  // GR pages may use <li> elements or structured divs with HSC codes
  $('li, p, td').each((_i, el) => {
    const text = $(el).text();
    // Match HSC code patterns followed by optional asterisk
    const codePattern = /\b(\d{2}\.\d{2}[A-Z]{1,3})\s*(\*)?/g;
    let match;
    while ((match = codePattern.exec(text)) !== null) {
      // Only include if we're in a section that mentions referral
      if (
        fullText.includes('4.4.8') &&
        (text.includes('referr') || text.includes('4.4.8'))
      ) {
        requiresReferral.add(match[1]);
        if (match[2] === '*') {
          selfReferralBlocked.add(match[1]);
        }
      }
    }
  });

  return { requiresReferral, selfReferralBlocked };
}

// ============================================================================
// Parse GR 1.33 — Facility Designations
// ============================================================================

function parseGR133(html: string): {
  inOffice: Set<string>;
  outOfOffice: Set<string>;
} {
  const $ = cheerio.load(html);
  const inOffice = new Set<string>();
  const outOfOffice = new Set<string>();

  const allText = $('body').text();

  // Find the 1.33 section about "in office" and "out of office"
  const section133Match = allText.match(
    /1\.33[\s\S]*?(?=1\.34|\b1\.4\b|\b2\.\b|$)/i,
  );

  if (section133Match) {
    const sectionText = section133Match[0];

    // Split into "in office" and "out of office" subsections
    // Look for the "in office" designated codes
    const inOfficeMatch = sectionText.match(
      /(?:in.office|in\soffice)[\s\S]*?(?:out.of.office|$)/i,
    );
    const outOfOfficeMatch = sectionText.match(
      /out.of.office[\s\S]*/i,
    );

    const codePattern = /\b(\d{2}\.\d{2}[A-Z]{1,3})\b/g;

    if (inOfficeMatch) {
      let match;
      while ((match = codePattern.exec(inOfficeMatch[0])) !== null) {
        inOffice.add(match[1]);
      }
    }

    if (outOfOfficeMatch) {
      let match;
      while ((match = codePattern.exec(outOfOfficeMatch[0])) !== null) {
        outOfOffice.add(match[1]);
      }
    }
  }

  // Also try extracting from links
  $('a[href*="/fee-navigator/hsc/"]').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const codeMatch = href.match(/\/fee-navigator\/hsc\/([^?&#]+)/);
    if (!codeMatch) return;

    const code = decodeURIComponent(codeMatch[1]);

    // Check surrounding text context
    const parentText = $(el).parent().text();
    if (parentText.match(/in.office/i) && !parentText.match(/out.of.office/i)) {
      inOffice.add(code);
    } else if (parentText.match(/out.of.office/i)) {
      outOfOffice.add(code);
    }
  });

  // Common pattern: "out of office" codes end in Z (e.g., 03.03AZ)
  // "in office" codes are the non-Z variants
  // Use this as a heuristic to sort codes that weren't clearly categorized
  for (const code of [...inOffice]) {
    if (code.endsWith('Z')) {
      inOffice.delete(code);
      outOfOffice.add(code);
    }
  }

  return { inOffice, outOfOffice };
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  console.log('=========================================');
  console.log('  HSC Data Enrichment');
  console.log('=========================================\n');

  // Load existing hsc-codes.json
  const hscPath = path.join(DATA_DIR, 'hsc-codes.json');
  if (!fs.existsSync(hscPath)) {
    throw new Error(`hsc-codes.json not found at ${hscPath}. Run the scraper first.`);
  }
  const hscCodes: HscCode[] = JSON.parse(fs.readFileSync(hscPath, 'utf-8'));
  console.log(`  Loaded ${hscCodes.length} HSC codes\n`);

  // Fetch GR 4 page (contains 4.4.8 referral requirements)
  console.log('  Fetching GR 4 page...');
  let gr4Html: string;
  try {
    const xml = await fetchWithRetry(`${BASE_URL}/governing-rules/4?ajax=detail`);
    gr4Html = decodeHtmlEntities(xml);
    if (!gr4Html) {
      gr4Html = await fetchWithRetry(`${BASE_URL}/governing-rules/4`);
    }
  } catch {
    gr4Html = await fetchWithRetry(`${BASE_URL}/governing-rules/4`);
  }
  console.log(`  GR 4 HTML: ${gr4Html.length} chars`);

  const { requiresReferral, selfReferralBlocked } = parseGR448(gr4Html);
  console.log(`  GR 4.4.8: ${requiresReferral.size} codes require referral, ${selfReferralBlocked.size} self-referral blocked\n`);

  await sleep(500);

  // Fetch GR 1 page (contains 1.33 facility designations)
  console.log('  Fetching GR 1 page...');
  let gr1Html: string;
  try {
    const xml = await fetchWithRetry(`${BASE_URL}/governing-rules/1?ajax=detail`);
    gr1Html = decodeHtmlEntities(xml);
    if (!gr1Html) {
      gr1Html = await fetchWithRetry(`${BASE_URL}/governing-rules/1`);
    }
  } catch {
    gr1Html = await fetchWithRetry(`${BASE_URL}/governing-rules/1`);
  }
  console.log(`  GR 1 HTML: ${gr1Html.length} chars`);

  const { inOffice, outOfOffice } = parseGR133(gr1Html);
  console.log(`  GR 1.33: ${inOffice.size} in-office codes, ${outOfOffice.size} out-of-office codes\n`);

  // ---- Phase 1: GR-based enrichment ----
  let referralCount = 0;
  let selfBlockedCount = 0;
  let inOfficeCount = 0;
  let outOfOfficeCount = 0;

  for (const hsc of hscCodes) {
    // Referral requirements
    hsc.requiresReferral = requiresReferral.has(hsc.hscCode);
    hsc.selfReferralBlocked = selfReferralBlocked.has(hsc.hscCode);

    if (hsc.requiresReferral) referralCount++;
    if (hsc.selfReferralBlocked) selfBlockedCount++;

    // Facility designation
    if (inOffice.has(hsc.hscCode)) {
      hsc.facilityDesignation = 'in_office';
      inOfficeCount++;
    } else if (outOfOffice.has(hsc.hscCode)) {
      hsc.facilityDesignation = 'out_of_office';
      outOfOfficeCount++;
    } else {
      hsc.facilityDesignation = null;
    }
  }

  console.log('  GR-based enrichment complete\n');

  // ---- Phase 2: Notes text extraction ----
  console.log('  Extracting structured data from notes text...');

  let specialtyCount = 0;
  let bundlingCount = 0;
  let ageCount = 0;
  let freqCount = 0;
  let maxPerDayCount = 0;
  let maxPerVisitCount = 0;
  let anesthesiaCount = 0;

  for (const hsc of hscCodes) {
    const notes = hsc.notes;
    if (!notes) {
      hsc.specialtyRestrictions = [];
      hsc.bundlingExclusions = [];
      hsc.ageRestriction = null;
      hsc.maxPerDay = null;
      hsc.maxPerVisit = null;
      hsc.frequencyRestriction = null;
      hsc.requiresAnesthesia = false;
      continue;
    }

    // Specialty restrictions
    hsc.specialtyRestrictions = extractSpecialtyRestrictions(notes);
    if (hsc.specialtyRestrictions.length > 0) specialtyCount++;

    // Bundling/combination exclusions
    hsc.bundlingExclusions = extractBundlingExclusions(hsc.hscCode, notes);
    if (hsc.bundlingExclusions.length > 0) bundlingCount++;

    // Age restrictions
    hsc.ageRestriction = extractAgeRestriction(notes);
    if (hsc.ageRestriction) ageCount++;

    // Frequency limits
    const freq = extractFrequencyLimit(notes);
    hsc.maxPerDay = freq.maxPerDay;
    hsc.maxPerVisit = freq.maxPerVisit;
    hsc.frequencyRestriction = freq.restriction;
    if (freq.maxPerDay !== null) maxPerDayCount++;
    if (freq.maxPerVisit !== null) maxPerVisitCount++;
    if (freq.restriction) freqCount++;

    // Anesthesia requirements
    hsc.requiresAnesthesia = extractAnesthesiaRequirement(notes);
    if (hsc.requiresAnesthesia) anesthesiaCount++;
  }

  // Write enriched data back
  fs.writeFileSync(hscPath, JSON.stringify(hscCodes, null, 2));
  console.log(`  Enriched hsc-codes.json written to ${hscPath}`);

  console.log('\n=========================================');
  console.log('  Enrichment Summary');
  console.log('-----------------------------------------');
  console.log('  GR-based:');
  console.log(`    Requires referral: ${referralCount}`);
  console.log(`    Self-referral blocked: ${selfBlockedCount}`);
  console.log(`    In-office designated: ${inOfficeCount}`);
  console.log(`    Out-of-office designated: ${outOfOfficeCount}`);
  console.log('-----------------------------------------');
  console.log('  Notes-based:');
  console.log(`    Specialty restrictions: ${specialtyCount}`);
  console.log(`    Bundling exclusions: ${bundlingCount}`);
  console.log(`    Age restrictions: ${ageCount}`);
  console.log(`    Frequency restrictions: ${freqCount}`);
  console.log(`    Max per day: ${maxPerDayCount}`);
  console.log(`    Max per visit: ${maxPerVisitCount}`);
  console.log(`    Requires anesthesia: ${anesthesiaCount}`);
  console.log('=========================================');

  // Verify some known codes
  const verificationCodes = ['03.08A', '01.01A', '08.19A', '01.42', '09.04A', '03.04AZ'];
  console.log('\n  Verification:');
  for (const code of verificationCodes) {
    const found = hscCodes.find((h) => h.hscCode === code);
    if (found) {
      console.log(
        `    ${code}: referral=${found.requiresReferral}, selfBlocked=${found.selfReferralBlocked}, facility=${found.facilityDesignation}`,
      );
      if (found.specialtyRestrictions?.length)
        console.log(`      specialty: [${found.specialtyRestrictions.join(', ')}]`);
      if (found.bundlingExclusions?.length)
        console.log(
          `      bundling: ${found.bundlingExclusions.map((b) => `${b.excludedCode}(${b.relationship})`).join(', ')}`,
        );
      if (found.ageRestriction)
        console.log(`      age: ${JSON.stringify(found.ageRestriction)}`);
      if (found.frequencyRestriction)
        console.log(`      freq: ${JSON.stringify(found.frequencyRestriction)}`);
      if (found.maxPerDay !== null) console.log(`      maxPerDay: ${found.maxPerDay}`);
      if (found.maxPerVisit !== null) console.log(`      maxPerVisit: ${found.maxPerVisit}`);
      if (found.requiresAnesthesia) console.log(`      anesthesia: required`);
    }
  }
}

main().catch((err) => {
  console.error('Enrichment failed:', err);
  process.exit(1);
});
