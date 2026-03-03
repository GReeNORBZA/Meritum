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
import {
  sleep,
  fetchWithRetry,
  decodeHtmlEntities,
  BASE_URL,
} from './lib/fee-navigator-utils.js';

// ============================================================================
// Configuration
// ============================================================================

const DATA_DIR = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  'data',
  'fee-navigator',
);

// Module-level code normalization map, built in main() before enrichment
let codeNormMap = new Map<string, string>();

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
// Notes Text Extraction — Structured data from notes field
// ============================================================================

/**
 * Normalize a specialty string: filter garbage fragments, title-case.
 */
function normalizeSpecialty(s: string): string | null {
  let trimmed = s.trim();
  // Filter too short
  if (trimmed.length < 4) return null;

  // Filter values that are too long to be a specialty name (likely a sentence fragment)
  if (trimmed.length > 60) return null;

  // Filter values containing numeric time/quantity phrases (likely conditional clauses)
  if (/\d+\s*(?:minutes?|hours?|days?|months?|years?|times?)/.test(trimmed)) return null;

  // Extract specialty from "physicians with [a/an] X specialty" pattern
  const withSpecialtyMatch = trimmed.match(/^physicians?\s+with\s+(?:an?\s+)?(.+?)\s+specialty$/i);
  if (withSpecialtyMatch) {
    trimmed = withSpecialtyMatch[1].trim();
    if (trimmed.length < 4) return null;
    return trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  }

  // Handle "physicians who have been approved by the CPSA"
  if (/^physicians?\s+who\s+have\s+been\s+approved/i.test(trimmed)) {
    return 'CPSA-approved physician';
  }

  // Filter values starting with common fragment prefixes
  if (/^(?:physicians?|those|with|working|in|at|for|by)\b/i.test(trimmed)) return null;
  // Filter values ending with prepositions
  if (/\b(?:in|at|for|by|with|of|who|that)$/i.test(trimmed)) return null;
  // Title-case the first character
  return trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
}

/**
 * Extract specialty restrictions from notes text.
 * Pattern: "May only be claimed by [specialty]"
 */
function extractSpecialtyRestrictions(notes: string): string[] {
  const restrictions: string[] = [];
  // Notes use "." directly followed by next sentence (no space).
  // Terminate at period NOT followed by a digit (avoids matching periods in HSC codes).
  const pattern =
    /(?:May only be claimed by|only\s+.*?claimed by|payable only to)[:\s]+(.+?)(?:\.(?!\d)|$)/gi;
  let match;
  while ((match = pattern.exec(notes)) !== null) {
    const raw = match[1].trim();

    // Check for location-based restrictions (AACC, UCC, ICU, emergency department)
    const locationMatch = raw.match(/(?:physicians?\s+)?(?:working\s+|on[- ]site\s+|on\s+rotation\s+duty\s+)?(?:in|at)\s+(?:an?\s+)?(.+)/i);
    if (locationMatch) {
      const loc = locationMatch[1].trim();
      // Extract known location abbreviations
      const locationTerms: string[] = [];
      if (/\bAACC\b/i.test(loc)) locationTerms.push('AACC physician');
      if (/\bUCC\b/i.test(loc)) locationTerms.push('UCC physician');
      if (/\bICU\b/i.test(loc)) locationTerms.push('ICU physician');
      if (/\bemergency\s+department\b/i.test(loc)) locationTerms.push('Emergency department physician');
      if (/\bemergency\s+room\b/i.test(loc)) locationTerms.push('Emergency room physician');
      if (locationTerms.length > 0) {
        restrictions.push(...locationTerms);
        continue;
      }
    }

    // Split on "or" / "and" / commas / colons / semicolons for multi-specialty restrictions
    const parts = raw
      .split(/\s*(?:,(?!\d)\s*(?:or|and)\s*|,(?!\d)\s*|\s+or\s+|\s+and\s+|;\s*|:\s*(?=[A-Z]))\s*/i)
      .map((s) => s.trim())
      .filter(
        (s) =>
          s.length > 2 &&
          !s.match(
            /^(?:a|an|the|physicians?|who|with|working|in|at|for|those)$/i,
          ),
      )
      .map(normalizeSpecialty)
      .filter((s): s is string => s !== null);
    restrictions.push(...parts);
  }
  return [...new Set(restrictions)];
}

/**
 * Helper: add extracted codes to the exclusions list with deduplication.
 */
function addExclusions(
  text: string,
  relationship: BundlingExclusion['relationship'],
  exclusions: BundlingExclusion[],
  seen: Set<string>,
): void {
  const codes = extractHscCodesFromText(text);
  for (const code of codes) {
    const key = `${relationship}:${code}`;
    if (!seen.has(key)) {
      seen.add(key);
      exclusions.push({ excludedCode: code, relationship });
    }
  }
}

/**
 * Extract bundling/combination exclusions and same-day restrictions from notes.
 * Handles both "HSC"-prefixed and bare code references, and both "claimed" and "billed" verbs.
 */
function extractBundlingExclusions(
  _sourceCode: string,
  notes: string,
): BundlingExclusion[] {
  const exclusions: BundlingExclusion[] = [];
  const seen = new Set<string>();

  // Common prohibition verbs (claimed OR billed)
  const NOT_VERB = String.raw`(?:May not be (?:claimed|billed)|not\s+(?:be\s+)?(?:payable|claimed|billed)|shall not be (?:submitted|claimed|billed)|cannot\s+be\s+(?:claimed|billed|submitted))`;
  // Optional "HSC(s)" prefix before code references
  const HSC_OPT = String.raw`(?:HSC[s]?\s+)?`;
  // Code capture group (greedy enough to capture comma-separated lists)
  const CODE_LIST = String.raw`([\d.,\s/andor\w]+?)`;
  // Sentence boundary: period NOT followed by digit, or end of string
  const SENT_END = String.raw`(?:\.(?!\d)|$)`;
  // Non-period content or period-before-digit (navigate within a sentence)
  const IN_SENT = String.raw`(?:[^.]|\.(?=\d))*?`;

  let match;

  // ---- Group A: Prohibition + preposition + codes (standard) ----
  // "not claimed/billed with|in addition to|in association with|in conjunction with [HSC] XX.XX"
  const groupAPattern = new RegExp(
    `${NOT_VERB}${IN_SENT}(?:with|in addition to|in association with|in conjunction with)\\s+${HSC_OPT}${CODE_LIST}${SENT_END}`,
    'gi',
  );
  while ((match = groupAPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group B: Same-day/shift/encounter exclusions ----
  // "not claimed/billed on the same day/shift/encounter [as] [HSC] XX.XX"
  const groupBPattern = new RegExp(
    `${NOT_VERB}${IN_SENT}(?:on the same day|same date of service|same shift|same visit|same encounter|same session|same calendar week)${IN_SENT}(?:as\\s+)?${HSC_OPT}${CODE_LIST}${SENT_END}`,
    'gi',
  );
  while ((match = groupBPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'same_day_exclusion', exclusions, seen);
  }

  // ---- Group C: Inverted subject — "HSC(s) XX.XX may not be claimed in addition/on same day" ----
  // "HSC XX.XX may not be claimed in addition"
  const invertedAdditionPattern =
    /HSC[s]?\s+([\d.,\s/andor\w]+?)\s+may not be (?:claimed|billed)(?:\s+in addition|\s+(?:with|in association with|in conjunction with)\s)/gi;
  while ((match = invertedAdditionPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // "HSC(s) XX.XX may not be claimed on the same day/shift/encounter"
  const invertedTemporalPattern =
    /HSC[s]?\s+([\d.,\s/andor\w]+?)\s+may not be (?:claimed|billed)\s+(?:on the same|at the same|in the same)\s+(?:day|date|shift|encounter|session|visit)/gi;
  while ((match = invertedTemporalPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'same_day_exclusion', exclusions, seen);
  }

  // ---- Group D: Subject-list — "HSCs XX, YY and ZZ may not be claimed on same shift" ----
  const subjectListPattern =
    /HSC[s]?\s+([\d.,\s/andor\w]+?)\s+may not be (?:claimed|billed)\s+(?:on|at|in)\s+the\s+same\s+(?:shift|day|encounter|visit|session)/gi;
  while ((match = subjectListPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'same_day_exclusion', exclusions, seen);
  }

  // ---- Group E: Mutual exclusion — "Only one of HSCs XX, YY or ZZ may be claimed" ----
  const mutualExclusionPattern =
    /Only one\s+(?:of\s+)?HSC[s]?\s+([\d.,\s/andor\w]+?)\s+may be (?:claimed|billed)/gi;
  while ((match = mutualExclusionPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group F: Callback/parenthetical — "(HSCs XX, YY) may not be claimed in addition" ----
  const callbackParenPattern =
    /\(HSC[s]?\s+([\d.,\s/andor\w]+?)\)\s+may not be (?:claimed|billed)\s+in addition/gi;
  while ((match = callbackParenPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group G: "in lieu of" (substitution) ----
  const lieuPattern = new RegExp(
    `(?:in lieu of)\\s+${HSC_OPT}${CODE_LIST}${SENT_END}`,
    'gi',
  );
  while ((match = lieuPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group H: "is included in" / "included in the benefit for" ----
  const includedInPattern = new RegExp(
    `(?:is\\s+included\\s+in|included\\s+in\\s+(?:the\\s+)?(?:benefit|fee)\\s+(?:for|of))\\s+${HSC_OPT}${CODE_LIST}${SENT_END}`,
    'gi',
  );
  while ((match = includedInPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group I: "not separately payable/billable" ----
  const notSeparatelyPattern = new RegExp(
    `not\\s+separately\\s+(?:payable|billable|claimable)${IN_SENT}(?:with|from|when\\s+claimed\\s+with)\\s+${HSC_OPT}${CODE_LIST}${SENT_END}`,
    'gi',
  );
  while ((match = notSeparatelyPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group J: "replaces" / "supersedes" ----
  const replacesPattern = new RegExp(
    `(?:replaces|supersedes)\\s+${HSC_OPT}${CODE_LIST}${SENT_END}`,
    'gi',
  );
  while ((match = replacesPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group K: "not payable in the same calendar week as" ----
  const calendarWeekPattern = new RegExp(
    `not\\s+payable\\s+in\\s+the\\s+same\\s+calendar\\s+week\\s+as\\s+${HSC_OPT}${CODE_LIST}${SENT_END}`,
    'gi',
  );
  while ((match = calendarWeekPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'same_day_exclusion', exclusions, seen);
  }

  // ---- Group L: "Benefits XX through YY may not be claimed" (range-based, orthopedic codes) ----
  const rangePattern =
    /(?:Benefits?\s+)?(\d{2}\.\d{1,3}[A-Z]*)\s+through\s+(\d{2}\.\d{1,3}[A-Z]*)\s+(?:\([^)]*\)\s+)?may not be (?:claimed|billed)/gi;
  while ((match = rangePattern.exec(notes)) !== null) {
    // Extract the range endpoints as exclusions
    addExclusions(match[1] + ', ' + match[2], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group M: "anesthetic rate for XX.XX may not be claimed" ----
  const anesthRatePattern =
    /(?:anesthetic\s+)?rate\s+for\s+(?:HSC\s+)?(\d{2}\.\d{1,3}[A-Z]*)\s+may not be (?:claimed|billed)/gi;
  while ((match = anesthRatePattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group N: "Neither HSCs XX or YY are payable if HSC ZZ" ----
  const neitherPattern =
    /Neither\s+HSC[s]?\s+([\d.,\s/andor\w]+?)\s+(?:are|is)\s+payable/gi;
  while ((match = neitherPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group O: Prohibition with parenthetical code list ----
  // "May not be claimed in addition to X (HSC YY.YY, ZZ.ZZ)" or "... examinations (03.04A, 03.08A)"
  const parenCodePattern =
    /(?:May not be (?:claimed|billed)|not\s+(?:be\s+)?(?:payable|claimed|billed))(?:[^.]*?)\((?:HSC[s]?\s+)?([\d.,\s/andor\w]+?)\)/gi;
  while ((match = parenCodePattern.exec(notes)) !== null) {
    // Only add if the parenthetical contains actual HSC codes
    const codesInParen = extractHscCodesFromText(match[1]);
    if (codesInParen.length > 0) {
      addExclusions(match[1], 'not_claimable_with', exclusions, seen);
    }
  }

  // ---- Group P: Temporal exclusion — "not claimed within N days of XX.XX" ----
  const temporalPattern =
    /(?:May not be (?:claimed|billed)|not\s+(?:be\s+)?(?:claimed|billed))(?:[^.]*?)(?:within\s+\d+\s+days?\s+(?:of|subsequent\s+to|following|after|prior\s+to))\s+(?:an?\s+)?(?:HSC\s+)?(\d{2}\.\d{1,3}[A-Z]{0,3})/gi;
  while ((match = temporalPattern.exec(notes)) !== null) {
    addExclusions(match[1], 'not_claimable_with', exclusions, seen);
  }

  // ---- Group Q: Range in parentheses — "(HSCs XX.XX through YY.YY)" ----
  const parenRangePattern =
    /\(HSC[s]?\s+(\d{2}\.\d{1,3}[A-Z]*)\s+through\s+(\d{2}\.\d{1,3}[A-Z]*)\)/gi;
  while ((match = parenRangePattern.exec(notes)) !== null) {
    // Check context: only add if in a prohibition sentence
    const contextStart = Math.max(0, match.index - 200);
    const context = notes.substring(contextStart, match.index);
    if (/(?:may not|not\s+(?:be\s+)?(?:claimed|billed|payable)|shall not|cannot)/i.test(context)) {
      addExclusions(match[1] + ', ' + match[2], 'not_claimable_with', exclusions, seen);
    }
  }

  // ---- Group R: Generic category exclusions ----
  // "May not be claimed in addition to any other visit/procedure/consultation"
  // Uses category markers (*VISIT, *PROCEDURE, etc.) instead of specific codes
  const CATEGORY_MAP: [RegExp, string][] = [
    [/(?:any\s+other\s+)?(?:visit|consultation)\s+(?:or\s+(?:consultation|assessment)\s+)?(?:on|at|by)\s/i, '*VISIT'],
    [/(?:any\s+other\s+)?visit,?\s*consultation\s+or\s+assessment/i, '*VISIT'],
    [/(?:a|any\s+other)\s+visit\s+at\s+the\s+same/i, '*VISIT'],
    [/(?:any\s+other\s+)?(?:procedure|procedures)\s*(?:on|at|by)\s/i, '*PROCEDURE'],
    [/(?:any\s+other\s+)?(?:procedure|procedures)\s*$/i, '*PROCEDURE'],
    [/(?:a\s+)?surgical\s+assist\s*\(/i, '*SURGICAL_ASSIST'],
    [/(?:any\s+other\s+)?anesthetic\s+services?/i, '*ANESTHETIC'],
    [/another\s+procedure/i, '*PROCEDURE'],
  ];

  // ---- Group R-pre: "No additional payment/benefit for" (procedure included) ----
  const noAdditionalPattern =
    /(?:no additional (?:payment|benefit)\s+for)\s+(.+?)(?:\.(?!\d)|$)/gi;
  while ((match = noAdditionalPattern.exec(notes)) !== null) {
    const fragment = match[1].trim();
    // Extract any HSC codes in the fragment
    const codes = extractHscCodesFromText(fragment);
    if (codes.length > 0) {
      for (const code of codes) {
        const key = `not_claimable_with:${code}`;
        if (!seen.has(key)) {
          seen.add(key);
          exclusions.push({ excludedCode: code, relationship: 'not_claimable_with' });
        }
      }
    } else {
      // Generic "no additional payment for [procedure]" — use category marker
      const key = `not_claimable_with:*INCLUDED_${fragment.toUpperCase().replace(/\s+/g, '_').substring(0, 30)}`;
      if (!seen.has(key)) {
        seen.add(key);
        exclusions.push({
          excludedCode: `*INCLUDED`,
          relationship: 'not_claimable_with',
        });
      }
    }
  }

  // ---- Group R-sole: "Sole procedure only" ----
  if (/sole\s+procedure/i.test(notes)) {
    const key = 'not_claimable_with:*SOLE_PROCEDURE';
    if (!seen.has(key)) {
      seen.add(key);
      exclusions.push({ excludedCode: '*SOLE_PROCEDURE', relationship: 'not_claimable_with' });
    }
  }

  const genericExclPattern =
    /(?:May not be (?:claimed|billed)|not\s+(?:be\s+)?(?:payable|claimed|billed))(?:[^.]*?)(?:in addition to|with|in association with)\s+((?:any\s+other\s+|another\s+|a\s+)(?:visit|consultation|procedure|assessment|examination|service|surgical|anesthetic|call)[^.]*?)(?:\.(?!\d)|$)/gi;
  while ((match = genericExclPattern.exec(notes)) !== null) {
    const fragment = match[1].trim();
    for (const [catRegex, marker] of CATEGORY_MAP) {
      if (catRegex.test(fragment)) {
        const key = `not_claimable_with:${marker}`;
        if (!seen.has(key)) {
          seen.add(key);
          exclusions.push({ excludedCode: marker, relationship: 'not_claimable_with' });
        }
        break;
      }
    }
  }

  return exclusions;
}

/**
 * Extract HSC code references from a text fragment.
 * Matches patterns like: 01.03, 03.08A, 03.7 A, 48.15B, 95.14C, E  1, X 38
 */
function extractHscCodesFromText(text: string): string[] {
  const codes: string[] = [];

  // Pattern 1: Standard numeric codes (space-tolerant for codes like "03.7 A")
  const numericPattern = /\b(\d{2}\.\d{1,3}\s?[A-Z]{0,3})\b/g;
  let match;
  while ((match = numericPattern.exec(text)) !== null) {
    const code = match[1];
    const prefix = parseInt(code.split('.')[0], 10);
    if (prefix >= 1 && prefix <= 99) {
      // Skip if preceded by $ or "fee" (looks like a dollar amount)
      const contextStart = Math.max(0, match.index - 10);
      const context = text.slice(contextStart, match.index);
      if (!context.includes('$') && !context.match(/fee\s*$/i)) {
        codes.push(code);
      }
    }
  }

  // Pattern 2: Letter-prefix codes (E/X-prefixed, e.g., "E  1", "E103", "E121A", "X 38")
  const letterPattern = /\b([A-Z]\s*\d{1,3}[A-Z]?)\b/g;
  while ((match = letterPattern.exec(text)) !== null) {
    codes.push(match[1]);
  }

  return [...new Set(codes)].map(c => {
    const noSpace = c.replace(/\s+/g, '');
    return codeNormMap.get(noSpace) ?? c;
  });
}

interface AgePattern {
  tag: 'max_months' | 'max_years' | 'min_years' | 'min_months' | 'range_years' | 'range_ages';
  regex: RegExp;
}

const AGE_PATTERNS: AgePattern[] = [
  { tag: 'max_months', regex: /(\d+)\s*months?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+(?:under|younger))/i },
  { tag: 'max_months', regex: /(?:under|younger\s+than)\s+(\d+)\s*months/i },
  { tag: 'max_months', regex: /(?:up\s+to)\s+(\d+)\s*months/i },
  { tag: 'max_years',  regex: /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|and\s+(?:under|younger))/i },
  { tag: 'max_years',  regex: /(?:under|younger\s+than)\s+(\d+)\s*years/i },
  { tag: 'max_years',  regex: /(?:up\s+to)\s+(\d+)\s*years/i },
  { tag: 'min_years',  regex: /(\d+)\s*years?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i },
  { tag: 'min_years',  regex: /(?:over|older\s+than)\s+(\d+)\s*years/i },
  { tag: 'min_months', regex: /(\d+)\s*months?\s*(?:of age\s+)?(?:or\s+)?(?:older|over|and\s+(?:older|over))/i },
  { tag: 'range_years', regex: /between\s+(\d+)\s*and\s*(\d+)\s*years/i },
  { tag: 'range_ages',  regex: /aged?\s+(\d+)\s*(?:to|-)\s*(\d+)/i },
  { tag: 'range_ages',  regex: /age\s+(\d+)\s+to\s+(\d+)\s+years/i },
];

/**
 * Extract age restrictions from notes text.
 * Patterns:
 *   - "patients aged 12 months or younger"
 *   - "18 years of age and under"
 *   - "65 years and older"
 */
function extractAgeRestriction(notes: string): AgeRestriction | null {
  for (const { tag, regex } of AGE_PATTERNS) {
    const match = notes.match(regex);
    if (!match) continue;

    switch (tag) {
      case 'max_months':
        return { text: match[0], maxMonths: parseInt(match[1], 10) };
      case 'max_years':
        return { text: match[0], maxYears: parseInt(match[1], 10) };
      case 'min_years':
        return { text: match[0], minYears: parseInt(match[1], 10) };
      case 'min_months':
        return { text: match[0], minMonths: parseInt(match[1], 10) };
      case 'range_years':
      case 'range_ages':
        return {
          text: match[0],
          minYears: parseInt(match[1], 10),
          maxYears: parseInt(match[2], 10),
        };
    }
  }

  return null;
}

/**
 * Convert word-form numbers to digits.
 */
const WORD_NUMBERS: Record<string, number> = {
  once: 1, twice: 2,
  one: 1, two: 2, three: 3, four: 4, five: 5,
  six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
  eleven: 11, twelve: 12, fifteen: 15, twenty: 20,
};

function parseNumberOrWord(digitGroup: string | undefined, wordGroup: string | undefined): number | null {
  if (digitGroup) return parseInt(digitGroup, 10);
  if (wordGroup) return WORD_NUMBERS[wordGroup.toLowerCase()] ?? null;
  return null;
}

// Regex fragment matching digit or word-form numbers
const NUM = String.raw`(?:(\d+)\s*|(\b(?:once|twice|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|fifteen|twenty)\b)\s*)`;

/**
 * Extract frequency limits from notes text.
 * Patterns:
 *   - "once per year"
 *   - "4 times per patient per calendar year"
 *   - "maximum of 15 calls per patient per benefit year"
 *   - "once per patient per day"
 *   - "maximum of two claims per patient per physician per day"
 *   - "maximum of three (any combination of HSC ...) per day"
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

  // Pattern: "maximum of N (...optional parenthetical...) claims? per patient per physician per day"
  const perDayMaxPattern = new RegExp(
    String.raw`(?:a\s+)?maximum\s+(?:of\s+)?${NUM}(?:\([^)]*\)\s*)?(?:claims?\s+)?(?:may\s+be\s+claimed\s+)?(?:per|each)\s*(?:patient\s*,?\s*(?:per\s*)?)?(?:physician\s*,?\s*(?:per\s*)?)?(?:per\s+)?day`,
    'i',
  );
  const perDayMaxMatch = notes.match(perDayMaxPattern);
  if (perDayMaxMatch) {
    const n = parseNumberOrWord(perDayMaxMatch[1], perDayMaxMatch[2]);
    if (n !== null) result.maxPerDay = n;
  }

  // Pattern: "once/X times per day"
  if (result.maxPerDay === null) {
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

  // General frequency pattern for non-day/visit periods (word + digit numbers)
  const freqPattern = new RegExp(
    String.raw`(?:(?:once|${NUM}times?)|(?:a\s+)?maximum\s+(?:of\s+)?${NUM}(?:\([^)]*\)\s*)?(?:\s*(?:calls?|claims?|sessions?|visits?))?)` +
    String.raw`\s*(?:may\s+be\s+claimed\s+)?(?:per|every|each|in\s+a)\s*(?:patient\s*,?\s*(?:per\s*)?)?(?:physician\s*,?\s*(?:per\s*)?)?(year|calendar year|benefit year|lifetime|12[- ]?month|pregnancy|calendar week|calendar month|week|month|365[- ]?day|shift|session|admission|hospitalization|weekday|weekend\s*day)`,
    'i',
  );
  const freqMatch = notes.match(freqPattern);
  if (freqMatch) {
    // Groups: freqMatch[1]=digit_count1, [2]=word_count1, [3]=digit_count2, [4]=word_count2, [5]=period
    const count = parseNumberOrWord(freqMatch[1], freqMatch[2])
      ?? parseNumberOrWord(freqMatch[3], freqMatch[4])
      ?? 1;
    const period = freqMatch[5].toLowerCase().replace(/\s+/g, '_');
    result.restriction = {
      text: freqMatch[0].trim(),
      count,
      period,
    };
  }

  // Fallback: "once every N years/months" pattern (e.g., "once every 3 years")
  if (!result.restriction) {
    const everyMatch = notes.match(
      /once\s+every\s+(\d+)\s*(years?|months?|weeks?)/i,
    );
    if (everyMatch) {
      result.restriction = {
        text: everyMatch[0].trim(),
        count: 1,
        period: `every_${everyMatch[1]}_${everyMatch[2].toLowerCase().replace(/\s+/g, '_')}`,
      };
    }
  }

  // Fallback: "maximum of N per weekday/weekend day" (digit or word)
  if (!result.restriction) {
    const weekdayPattern = new RegExp(
      String.raw`(?:a\s+)?maximum\s+(?:of\s+)?${NUM}(?:\([^)]*\)\s*)?(?:.*?)(?:per\s+)?(weekday|weekend\s*day)`,
      'i',
    );
    const weekdayMatch = notes.match(weekdayPattern);
    if (weekdayMatch) {
      const count = parseNumberOrWord(weekdayMatch[1], weekdayMatch[2]) ?? 1;
      const period = weekdayMatch[3].toLowerCase().replace(/\s+/g, '_');
      result.restriction = {
        text: weekdayMatch[0].trim(),
        count,
        period,
      };
    }
  }

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

  return result;
}

/**
 * Extract anesthesia requirements from notes text.
 * Pattern: "under general anesthesia" / "procedural sedation" / "requiring sedation"
 */
function extractAnesthesiaRequirement(notes: string): boolean {
  return /(?:under\s+(?:general\s+)?(?:anesthesia|anesthetic)|requires?\s+(?:general\s+)?(?:anesthesia|anesthetic)|requiring\s+(?:procedural\s+)?sedation|procedural\s+sedation|with\s+(?:general\s+)?(?:anesthesia|anesthetic)|under\s+(?:conscious|procedural)\s+sedation|performed\s+under\s+(?:general\s+)?(?:anesthesia|anesthetic))/i.test(
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

  const fullText = $('body').text();

  // Step 1: Isolate the 4.4.8 section text only
  const section448Match = fullText.match(
    /4\.4\.8\b([\s\S]*?)(?=\b4\.4\.9\b|\b4\.5\b|\b4\.6\b|\b4\.7\b|\b5\.\b|$)/i,
  );

  if (!section448Match) {
    console.warn('  [WARN] Could not locate GR 4.4.8 section in GR 4 page');
    return { requiresReferral, selfReferralBlocked };
  }

  const sectionText = section448Match[0];
  console.log(`  GR 4.4.8 section: ${sectionText.length} chars extracted from GR 4 page`);

  // Step 2: Extract HSC codes from the scoped section text
  const codePattern = /\b(\d{2}\.\d{2,3}[A-Z]{0,3})\s*(\*)?/g;
  let match;
  while ((match = codePattern.exec(sectionText)) !== null) {
    requiresReferral.add(match[1]);
    if (match[2] === '*') {
      selfReferralBlocked.add(match[1]);
    }
  }

  // Step 3: Also extract from links, but ONLY if surrounding context mentions "4.4.8"
  $('a[href*="/fee-navigator/hsc/"]').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const codeMatch = href.match(/\/fee-navigator\/hsc\/([^?&#]+)/);
    if (!codeMatch) return;

    const parentText = $(el).closest('div, section, li, td, tr').text();
    if (parentText.includes('4.4.8')) {
      const code = decodeURIComponent(codeMatch[1]);
      requiresReferral.add(code);
    }
  });

  console.log(
    `  GR 4.4.8 parsed: ${requiresReferral.size} codes require referral, ` +
    `${selfReferralBlocked.size} self-referral blocked`,
  );

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
  const textClassified = new Set<string>();

  const allText = $('body').text();

  const section133Match = allText.match(
    /1\.33[\s\S]*?(?=1\.34|\b1\.4\b|\b2\.\b|$)/i,
  );

  if (section133Match) {
    const sectionText = section133Match[0];

    const inOfficeMatch = sectionText.match(
      /(?:in.office|in\soffice)[\s\S]*?(?:out.of.office|$)/i,
    );
    const outOfOfficeMatch = sectionText.match(
      /out.of.office[\s\S]*/i,
    );

    const codePattern = /\b(\d{2}\.\d{2,3}[A-Z]{0,3})\b/g;

    if (inOfficeMatch) {
      let match;
      while ((match = codePattern.exec(inOfficeMatch[0])) !== null) {
        inOffice.add(match[1]);
        textClassified.add(match[1]);
      }
    }

    if (outOfOfficeMatch) {
      let match;
      while ((match = codePattern.exec(outOfOfficeMatch[0])) !== null) {
        outOfOffice.add(match[1]);
        textClassified.add(match[1]);
      }
    }
  }

  $('a[href*="/fee-navigator/hsc/"]').each((_i, el) => {
    const href = $(el).attr('href') ?? '';
    const codeMatch = href.match(/\/fee-navigator\/hsc\/([^?&#]+)/);
    if (!codeMatch) return;

    const code = decodeURIComponent(codeMatch[1]);
    if (textClassified.has(code)) return;

    const parentText = $(el).parent().text();
    if (parentText.match(/in.office/i) && !parentText.match(/out.of.office/i)) {
      inOffice.add(code);
    } else if (parentText.match(/out.of.office/i)) {
      outOfOffice.add(code);
    }
  });

  // Z-suffix heuristic: only apply to codes NOT already classified by text
  for (const code of [...inOffice]) {
    if (code.endsWith('Z') && !textClassified.has(code)) {
      console.log(`  [GR 1.33] Heuristic: moving ${code} from in-office to out-of-office (Z suffix, not text-classified)`);
      inOffice.delete(code);
      outOfOffice.add(code);
    } else if (code.endsWith('Z') && textClassified.has(code)) {
      console.log(`  [GR 1.33] Keeping text-classified ${code} as in-office despite Z suffix`);
    }
  }

  console.log(`  GR 1.33: ${inOffice.size} in-office, ${outOfOffice.size} out-of-office (${textClassified.size} text-classified)`);

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

  // Build code normalization map: "03.7A" -> "03.7 A", etc.
  const canonicalCodes = new Set(hscCodes.map(h => h.hscCode));
  codeNormMap = new Map<string, string>();
  for (const canonical of canonicalCodes) {
    const noSpace = canonical.replace(/\s+/g, '');
    if (noSpace !== canonical) {
      codeNormMap.set(noSpace, canonical);
    }
  }
  if (codeNormMap.size > 0) {
    console.log(`  Code normalization map: ${codeNormMap.size} entries\n`);
  }

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
    // Referral requirements (GR-based first, then notes-based supplement)
    hsc.requiresReferral = requiresReferral.has(hsc.hscCode);
    hsc.selfReferralBlocked = selfReferralBlocked.has(hsc.hscCode);

    // Notes-based referral detection (supplement GR 4.4.8)
    if (!hsc.requiresReferral && hsc.notes) {
      if (/(?:referral\s+(?:must|is\s+required|required|is\s+supplied)|must\s+be\s+referred|requires?\s+(?:a\s+)?referral|when\s+the\s+referral\s+is\s+(?:supplied|provided))/i.test(hsc.notes)) {
        hsc.requiresReferral = true;
      }
    }

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

  // Backup original before enrichment
  const backupPath = hscPath.replace(/\.json$/, '.pre-enrichment.json');
  fs.copyFileSync(hscPath, backupPath);
  console.log(`  Backup saved to ${backupPath}`);

  // Atomic write
  const tmpPath = hscPath + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(hscCodes, null, 2));
  fs.renameSync(tmpPath, hscPath);
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

  // Run post-enrichment validation
  console.log('\n=== Running post-enrichment validation ===\n');
  try {
    const { execSync } = await import('node:child_process');
    const validateScript = path.join(
      path.dirname(new URL(import.meta.url).pathname),
      'validate-fee-navigator-data.ts',
    );
    const tsxPath = path.join(process.cwd(), 'apps', 'api', 'node_modules', '.bin', 'tsx');
    execSync(`"${tsxPath}" "${validateScript}"`, { stdio: 'inherit' });
    console.log('\n  Post-enrichment validation: PASSED\n');
  } catch {
    console.error('\n  *** POST-ENRICHMENT VALIDATION FAILED ***');
    console.error('  Review the validation output above before using this data.');
    console.error('  The enrichment may have corrupted the data.\n');
    process.exit(2);
  }
}

main().catch((err) => {
  console.error('Enrichment failed:', err);
  process.exit(1);
});
