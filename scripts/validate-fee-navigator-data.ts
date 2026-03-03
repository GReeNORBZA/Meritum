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

const jsonMode = process.argv.includes('--json');
const skipEnrichment = process.argv.includes('--skip-enrichment');

let errors = 0;
let warnings = 0;

interface CheckRecord {
  section: string;
  name: string;
  status: 'pass' | 'fail' | 'warn';
  value?: number;
  threshold?: number;
}

const checks: CheckRecord[] = [];
let currentSection = 'General';

function pass(msg: string): void {
  if (!jsonMode) console.log(`  \u2713 ${msg}`);
}
function fail(msg: string): void {
  if (!jsonMode) console.log(`  \u2717 ${msg}`);
  errors++;
}
function warn(msg: string): void {
  if (!jsonMode) console.log(`  \u26A0 ${msg}`);
  warnings++;
}
function recordCheck(name: string, status: 'pass' | 'fail' | 'warn', value?: number, threshold?: number): void {
  checks.push({ section: currentSection, name, status, value, threshold });
}

function loadJson<T>(filename: string): T | null {
  const filePath = path.join(DATA_DIR, filename);
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

// ============================================================================
// A. File Existence
// ============================================================================

if (!jsonMode) console.log('\n=== Fee Navigator Data Validation ===\n');
if (!jsonMode) console.log('Files:');
currentSection = 'Files';

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
    recordCheck(file, 'pass');
  } else {
    fileExists[file] = false;
    fail(`${file} — MISSING`);
    recordCheck(file, 'fail');
  }
}

// Check optional metadata file
const metadataPath = path.join(DATA_DIR, 'scrape-metadata.json');
if (fs.existsSync(metadataPath)) {
  pass('scrape-metadata.json');
  recordCheck('scrape-metadata.json', 'pass');
} else {
  warn('scrape-metadata.json — missing (optional)');
  recordCheck('scrape-metadata.json', 'warn');
}

// If core files are missing, abort early
if (!fileExists['hsc-codes.json'] || !fileExists['hsc-modifiers.json']) {
  if (jsonMode) {
    console.log(JSON.stringify({ result: 'FAIL', errors, warnings, checks }));
  } else {
    console.log(`\nResult: FAIL (${errors} errors, ${warnings} warnings)`);
    console.log('Cannot continue validation without core data files.\n');
  }
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

if (!jsonMode) console.log('\nCompleteness:');
currentSection = 'Completeness';

const THRESHOLDS: Array<[string, number, number]> = [
  ['HSC codes', hscCodes.length, 2900],
  ['Modifier rows', hscModifiers.length, 38000],
  ['Modifier definitions', modifiers.length, 38],
  ['Governing rules', govRules.length, 15],
  ['Explanatory codes', explCodes.length, 100],
];

for (const [label, count, threshold] of THRESHOLDS) {
  if (count >= threshold) {
    pass(`${label}: ${count.toLocaleString()} (threshold: ${threshold.toLocaleString()})`);
    recordCheck(label, 'pass', count, threshold);
  } else {
    fail(`${label}: ${count.toLocaleString()} — below threshold ${threshold.toLocaleString()}`);
    recordCheck(label, 'fail', count, threshold);
  }
}

// ============================================================================
// C. HSC Code Format Validation
// ============================================================================

if (!jsonMode) console.log('\nFormat:');
currentSection = 'Format';

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
  recordCheck('HSC code format', 'pass');
} else {
  fail(`${formatErrors} format errors found`);
  recordCheck('HSC code format', 'fail', formatErrors);
  if (!jsonMode) {
    for (const issue of formatIssues) {
      console.log(`    - ${issue}`);
    }
    if (formatErrors > 5) console.log(`    ... and ${formatErrors - 5} more`);
  }
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
  recordCheck('No duplicate HSC codes', 'pass');
} else {
  fail(`${dupes} duplicate HSC code(s) found`);
  recordCheck('No duplicate HSC codes', 'fail', dupes);
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
  recordCheck('Modifier row fields', 'pass');
} else {
  fail(`${modRowErrors} modifier rows with missing fields`);
  recordCheck('Modifier row fields', 'fail', modRowErrors);
}

// E2: Modifier row deduplication check
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
  recordCheck('No duplicate modifier rows', 'pass');
} else {
  fail(`${modRowDupes} duplicate modifier rows (key: hscCode|type|code|calls)`);
  recordCheck('No duplicate modifier rows', 'fail', modRowDupes);
}

// ============================================================================
// F. Cross-file Consistency
// ============================================================================

if (!jsonMode) console.log('\nCross-file:');
currentSection = 'Cross-file';

// F1: Every hscCode in modifiers exists in hsc-codes
const modHscMissing = new Set<string>();
for (const m of hscModifiers) {
  if (!hscCodeSet.has(m.hscCode)) {
    modHscMissing.add(m.hscCode);
  }
}

if (modHscMissing.size === 0) {
  pass('All modifier hscCodes found in hsc-codes.json');
  recordCheck('Modifier hscCodes in hsc-codes', 'pass');
} else {
  fail(`${modHscMissing.size} modifier hscCode(s) not in hsc-codes.json`);
  recordCheck('Modifier hscCodes in hsc-codes', 'fail', modHscMissing.size);
  if (!jsonMode) {
    const sample = [...modHscMissing].slice(0, 5);
    console.log(`    Sample: ${sample.join(', ')}`);
  }
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
  recordCheck('Modifier types in modifiers', 'pass');
} else {
  fail(`${modTypeMissing.size} modifier type(s) not in modifiers.json: ${[...modTypeMissing].join(', ')}`);
  recordCheck('Modifier types in modifiers', 'fail', modTypeMissing.size);
}

// F3: Governing rule reference resolution
const grRuleNumbers = new Set(govRules.map((r) => r.ruleNumber));
let unresolvedGrRefs = 0;
const unresolvedSample: string[] = [];
for (const hsc of hscCodes) {
  if (!hsc.governingRuleReferences) continue;
  for (const ref of hsc.governingRuleReferences) {
    // Check exact match or parent rule number
    const parentRule = ref.split('.')[0];
    if (!grRuleNumbers.has(ref) && !grRuleNumbers.has(parentRule)) {
      unresolvedGrRefs++;
      if (unresolvedSample.length < 5) {
        unresolvedSample.push(`${hsc.hscCode} → GR ${ref}`);
      }
    }
  }
}

if (unresolvedGrRefs === 0) {
  pass('All governing rule references resolve');
  recordCheck('GR reference resolution', 'pass');
} else {
  warn(`${unresolvedGrRefs} unresolved governing rule references (sub-rules may lack dedicated entries)`);
  recordCheck('GR reference resolution', 'warn', unresolvedGrRefs);
  if (!jsonMode) {
    for (const s of unresolvedSample) {
      console.log(`    - ${s}`);
    }
  }
}

// ============================================================================
// G. Enrichment Validation
// ============================================================================

if (!jsonMode) console.log('\nEnrichment:');
currentSection = 'Enrichment';

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

const ENRICHMENT_MINIMUMS: Array<[string, number, number]> = [
  ['requiresReferral', withReferral, 40],
  ['specialtyRestrictions', withSpecialty, 100],
  ['bundlingExclusions', withBundling, 120],
  ['ageRestriction', withAge, 20],
  ['frequencyRestriction', withFrequency, 15],
  ['facilityDesignation', withFacility, 20],
  ['category', withCategory, Math.floor(hscCodes.length * 0.95)],
  ['billingTips', withBillingTips, 150],
  ['commonTerms', withCommonTerms, 80],
];

if (!skipEnrichment) {
  for (const [label, count, min] of ENRICHMENT_MINIMUMS) {
    if (count >= min) {
      pass(`${label}: ${count} codes (min: ${min})`);
      recordCheck(label, 'pass', count, min);
    } else {
      fail(`${label}: ${count} codes — below minimum ${min}`);
      recordCheck(label, 'fail', count, min);
    }
  }
} else {
  if (!jsonMode) console.log('  (Enrichment checks skipped — run after enrichment)');
}

if (enrichErrors === 0) {
  pass('All enrichment fields pass type validation');
  recordCheck('Enrichment type validation', 'pass');
} else {
  fail(`${enrichErrors} enrichment type errors found`);
  recordCheck('Enrichment type validation', 'fail', enrichErrors);
}

// ============================================================================
// H. Data Quality Audits
// ============================================================================

if (!jsonMode) console.log('\nData Quality:');
currentSection = 'Data Quality';

// H1: Visit codes without modifiers
const modifierHscSet = new Set(hscModifiers.map((m) => m.hscCode));
const visitCodesWithoutMods = hscCodes.filter(
  (h) => h.feeType === 'VISIT' && !modifierHscSet.has(h.hscCode),
);

if (visitCodesWithoutMods.length <= 70) {
  pass(`Visit codes without modifiers: ${visitCodesWithoutMods.length} (within expected range)`);
  recordCheck('Visit codes without modifiers', 'pass', visitCodesWithoutMods.length, 70);
} else {
  warn(`Visit codes without modifiers: ${visitCodesWithoutMods.length} — may indicate scraping issue (expected ≤70)`);
  recordCheck('Visit codes without modifiers', 'warn', visitCodesWithoutMods.length, 70);
}

// ============================================================================
// Summary
// ============================================================================

if (jsonMode) {
  console.log(JSON.stringify({
    result: errors === 0 ? 'PASS' : 'FAIL',
    errors,
    warnings,
    checks,
  }, null, 2));
} else {
  console.log(
    `\nResult: ${errors === 0 ? 'PASS' : 'FAIL'} (${errors} errors, ${warnings} warnings)\n`,
  );
}

process.exit(errors > 0 ? 1 : 0);
