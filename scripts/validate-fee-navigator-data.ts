#!/usr/bin/env tsx
// ============================================================================
// Fee Navigator Data Validation Script (SCR-060)
//
// Validates completeness, format, and cross-file consistency of scraped data.
// Exit code 0 = pass, 1 = errors found.
//
// Usage: ./apps/api/node_modules/.bin/tsx scripts/validate-fee-navigator-data.ts
// ============================================================================

import * as fs from 'node:fs';
import * as path from 'node:path';

const DATA_DIR = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  'data',
  'fee-navigator',
);

let errors = 0;
let warnings = 0;

function pass(msg: string): void {
  console.log(`  \u2713 ${msg}`);
}
function fail(msg: string): void {
  console.log(`  \u2717 ${msg}`);
  errors++;
}
function warn(msg: string): void {
  console.log(`  \u26A0 ${msg}`);
  warnings++;
}

function loadJson<T>(filename: string): T | null {
  const filePath = path.join(DATA_DIR, filename);
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

// ============================================================================
// A. File Existence
// ============================================================================

console.log('\n=== Fee Navigator Data Validation ===\n');
console.log('Files:');

const REQUIRED_FILES = [
  'hsc-codes.json',
  'hsc-modifiers.json',
  'modifiers.json',
  'governing-rules.json',
  'explanatory-codes.json',
];

const fileExists: Record<string, boolean> = {};
for (const file of REQUIRED_FILES) {
  const filePath = path.join(DATA_DIR, file);
  if (fs.existsSync(filePath)) {
    const stats = fs.statSync(filePath);
    const sizeKb = Math.round(stats.size / 1024);
    fileExists[file] = true;
    pass(`${file} (${sizeKb} KB)`);
  } else {
    fileExists[file] = false;
    fail(`${file} — MISSING`);
  }
}

// Check optional metadata file
const metadataPath = path.join(DATA_DIR, 'scrape-metadata.json');
if (fs.existsSync(metadataPath)) {
  pass('scrape-metadata.json');
} else {
  warn('scrape-metadata.json — missing (optional)');
}

// If core files are missing, abort early
if (!fileExists['hsc-codes.json'] || !fileExists['hsc-modifiers.json']) {
  console.log(`\nResult: FAIL (${errors} errors, ${warnings} warnings)`);
  console.log('Cannot continue validation without core data files.\n');
  process.exit(1);
}

// ============================================================================
// Load all data
// ============================================================================

interface HscRecord {
  hscCode: string;
  description: string;
  baseFee: string | null;
  feeType: string;
  category?: string | null;
  modifierEligibility: string[];
  surchargeEligible: boolean;
  governingRuleReferences?: string[];
  requiresReferral?: boolean;
  selfReferralBlocked?: boolean;
  specialtyRestrictions?: string[];
  bundlingExclusions?: Array<{ excludedCode: string; relationship: string }>;
  ageRestriction?: { text: string; minYears?: number; maxYears?: number; minMonths?: number; maxMonths?: number } | null;
  frequencyRestriction?: { text: string; count: number; period: string } | null;
  facilityDesignation?: string | null;
  maxPerDay?: number | null;
  maxPerVisit?: number | null;
  requiresAnesthesia?: boolean;
  billingTips?: string | null;
  commonTerms?: string[];
  notes?: string | null;
  helpText?: string | null;
}

interface ModifierRow {
  hscCode: string;
  type: string;
  code: string;
  calls: string;
  explicit: string;
  action: string;
  amount: string;
}

interface ModifierDef {
  modifierCode: string;
  name: string;
  description: string;
}

interface GoverningRule {
  ruleNumber: string;
  title: string;
}

interface ExplanatoryCode {
  code: string;
  description: string;
}

const hscCodes = loadJson<HscRecord[]>('hsc-codes.json') ?? [];
const hscModifiers = loadJson<ModifierRow[]>('hsc-modifiers.json') ?? [];
const modifiers = loadJson<ModifierDef[]>('modifiers.json') ?? [];
const govRules = loadJson<GoverningRule[]>('governing-rules.json') ?? [];
const explCodes = loadJson<ExplanatoryCode[]>('explanatory-codes.json') ?? [];

// ============================================================================
// B. Completeness Thresholds
// ============================================================================

console.log('\nCompleteness:');

const THRESHOLDS: Array<[string, number, number]> = [
  ['HSC codes', hscCodes.length, 3000],
  ['Modifier rows', hscModifiers.length, 40000],
  ['Modifier definitions', modifiers.length, 40],
  ['Governing rules', govRules.length, 15],
  ['Explanatory codes', explCodes.length, 100],
];

for (const [label, count, threshold] of THRESHOLDS) {
  if (count >= threshold) {
    pass(`${label}: ${count.toLocaleString()} (threshold: ${threshold.toLocaleString()})`);
  } else {
    fail(`${label}: ${count.toLocaleString()} — below threshold ${threshold.toLocaleString()}`);
  }
}

// ============================================================================
// C. HSC Code Format Validation
// ============================================================================

console.log('\nFormat:');

// HSC code formats from Fee Navigator:
// - Standard: "03.03A", "03.7 A", "15.3" (numeric.numeric + optional alpha)
// - Lab/special: "E  1", "E 10", "E103", "E121A", "X 38" (letter prefix + digits + optional alpha)
const HSC_CODE_REGEX = /^(\d{2}\.\d{1,3}\s?[A-Z]{0,3}|[A-Z]\s*\d{1,3}[A-Z]?)$/;
const BASE_FEE_REGEX = /^\d+\.\d{2}$/;
const VALID_FEE_TYPES = new Set([
  'VISIT', 'PROCEDURE', 'FIXED', 'CONSULTATION', 'LABORATORY',
  'RADIOLOGY', 'ANESTHESIA', 'THERAPEUTIC', 'OTHER', 'UNKNOWN',
]);
const GR_REF_REGEX = /^\d+(\.\d+)*$/;

let formatErrors = 0;
const formatIssues: string[] = [];

for (const hsc of hscCodes) {
  if (!HSC_CODE_REGEX.test(hsc.hscCode)) {
    formatErrors++;
    if (formatIssues.length < 5) formatIssues.push(`Invalid hscCode format: ${hsc.hscCode}`);
  }
  if (!hsc.description || hsc.description.length < 2) {
    formatErrors++;
    if (formatIssues.length < 5) formatIssues.push(`Empty/short description: ${hsc.hscCode}`);
  }
  if (!VALID_FEE_TYPES.has(hsc.feeType)) {
    formatErrors++;
    if (formatIssues.length < 5) formatIssues.push(`Invalid feeType '${hsc.feeType}' for ${hsc.hscCode}`);
  }
  if (hsc.baseFee !== null && !BASE_FEE_REGEX.test(hsc.baseFee)) {
    formatErrors++;
    if (formatIssues.length < 5) formatIssues.push(`Invalid baseFee '${hsc.baseFee}' for ${hsc.hscCode}`);
  }
  if (!Array.isArray(hsc.modifierEligibility)) {
    formatErrors++;
    if (formatIssues.length < 5) formatIssues.push(`modifierEligibility not array: ${hsc.hscCode}`);
  }
  if (typeof hsc.surchargeEligible !== 'boolean') {
    formatErrors++;
    if (formatIssues.length < 5) formatIssues.push(`surchargeEligible not boolean: ${hsc.hscCode}`);
  }
  if (hsc.governingRuleReferences) {
    for (const ref of hsc.governingRuleReferences) {
      if (!GR_REF_REGEX.test(ref)) {
        formatErrors++;
        if (formatIssues.length < 5) formatIssues.push(`Invalid GR ref '${ref}' for ${hsc.hscCode}`);
      }
    }
  }
}

if (formatErrors === 0) {
  pass('All HSC codes pass format validation');
} else {
  fail(`${formatErrors} format errors found`);
  for (const issue of formatIssues) {
    console.log(`    - ${issue}`);
  }
  if (formatErrors > 5) console.log(`    ... and ${formatErrors - 5} more`);
}

// ============================================================================
// D. No Duplicates
// ============================================================================

const hscCodeSet = new Set<string>();
let dupes = 0;
for (const hsc of hscCodes) {
  if (hscCodeSet.has(hsc.hscCode)) {
    dupes++;
  }
  hscCodeSet.add(hsc.hscCode);
}

if (dupes === 0) {
  pass('No duplicate HSC codes');
} else {
  fail(`${dupes} duplicate HSC code(s) found`);
}

// ============================================================================
// E. Modifier Row Validation
// ============================================================================

let modRowErrors = 0;
for (const m of hscModifiers) {
  // hscCode, type, and code are required; action and amount may be empty strings for some modifiers (e.g., NBTR)
  if (!m.hscCode || !m.type || !m.code) {
    modRowErrors++;
  }
}

if (modRowErrors === 0) {
  pass('All modifier rows have required fields');
} else {
  fail(`${modRowErrors} modifier rows with missing fields`);
}

// ============================================================================
// F. Cross-file Consistency
// ============================================================================

console.log('\nCross-file:');

// F1: Every hscCode in modifiers exists in hsc-codes
const modHscMissing = new Set<string>();
for (const m of hscModifiers) {
  if (!hscCodeSet.has(m.hscCode)) {
    modHscMissing.add(m.hscCode);
  }
}

if (modHscMissing.size === 0) {
  pass('All modifier hscCodes found in hsc-codes.json');
} else {
  fail(`${modHscMissing.size} modifier hscCode(s) not in hsc-codes.json`);
  const sample = [...modHscMissing].slice(0, 5);
  console.log(`    Sample: ${sample.join(', ')}`);
}

// F2: Every modifier type exists in modifiers.json
const modCodeSet = new Set(modifiers.map((m) => m.modifierCode));
const modTypeMissing = new Set<string>();
for (const m of hscModifiers) {
  if (!modCodeSet.has(m.type)) {
    modTypeMissing.add(m.type);
  }
}

if (modTypeMissing.size === 0) {
  pass('All modifier types found in modifiers.json');
} else {
  fail(`${modTypeMissing.size} modifier type(s) not in modifiers.json: ${[...modTypeMissing].join(', ')}`);
}

// ============================================================================
// G. Enrichment Validation
// ============================================================================

console.log('\nEnrichment:');

let withReferral = 0;
let withSpecialty = 0;
let withBundling = 0;
let withAge = 0;
let withFrequency = 0;
let withFacility = 0;
let withCategory = 0;
let withBillingTips = 0;
let withCommonTerms = 0;
let enrichErrors = 0;

for (const hsc of hscCodes) {
  if (hsc.requiresReferral === true) withReferral++;
  if (hsc.specialtyRestrictions && hsc.specialtyRestrictions.length > 0) withSpecialty++;
  if (hsc.bundlingExclusions && hsc.bundlingExclusions.length > 0) withBundling++;
  if (hsc.ageRestriction) withAge++;
  if (hsc.frequencyRestriction) withFrequency++;
  if (hsc.category) withCategory++;
  if (hsc.billingTips) withBillingTips++;
  if (hsc.commonTerms && hsc.commonTerms.length > 0) withCommonTerms++;

  if (hsc.facilityDesignation) {
    withFacility++;
    if (hsc.facilityDesignation !== 'in_office' && hsc.facilityDesignation !== 'out_of_office') {
      enrichErrors++;
    }
  }

  // Validate enrichment field types
  if (hsc.requiresReferral !== undefined && typeof hsc.requiresReferral !== 'boolean') {
    enrichErrors++;
  }
  if (hsc.specialtyRestrictions !== undefined && !Array.isArray(hsc.specialtyRestrictions)) {
    enrichErrors++;
  }
  if (hsc.bundlingExclusions !== undefined && !Array.isArray(hsc.bundlingExclusions)) {
    enrichErrors++;
  }
  if (hsc.bundlingExclusions) {
    for (const excl of hsc.bundlingExclusions) {
      if (!excl.excludedCode || !excl.relationship) enrichErrors++;
    }
  }
  if (hsc.ageRestriction !== undefined && hsc.ageRestriction !== null) {
    if (!hsc.ageRestriction.text) enrichErrors++;
  }
  if (hsc.frequencyRestriction !== undefined && hsc.frequencyRestriction !== null) {
    if (!hsc.frequencyRestriction.text || typeof hsc.frequencyRestriction.count !== 'number' || !hsc.frequencyRestriction.period) {
      enrichErrors++;
    }
  }
}

pass(`requiresReferral: ${withReferral} codes`);
pass(`specialtyRestrictions: ${withSpecialty} codes`);
pass(`bundlingExclusions: ${withBundling} codes`);
pass(`ageRestriction: ${withAge} codes`);
pass(`frequencyRestriction: ${withFrequency} codes`);
pass(`facilityDesignation: ${withFacility} codes`);
pass(`category: ${withCategory} codes`);
pass(`billingTips: ${withBillingTips} codes`);
pass(`commonTerms: ${withCommonTerms} codes`);

if (enrichErrors === 0) {
  pass('All enrichment fields pass type validation');
} else {
  fail(`${enrichErrors} enrichment type errors found`);
}

// ============================================================================
// Summary
// ============================================================================

console.log(
  `\nResult: ${errors === 0 ? 'PASS' : 'FAIL'} (${errors} errors, ${warnings} warnings)\n`,
);

process.exit(errors > 0 ? 1 : 0);
