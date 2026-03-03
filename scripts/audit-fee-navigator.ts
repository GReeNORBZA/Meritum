#!/usr/bin/env tsx
// ============================================================================
// Meritum — Fee Navigator Enrichment Audit
//
// Analyzes hsc-codes.json to find codes whose notes contain enrichment-relevant
// keywords but whose structured fields are empty/null. Produces machine-readable
// findings JSON for the pipeline loop.
//
// Usage:
//   cd /workspace/projects && npx tsx scripts/audit-fee-navigator.ts
//   npx tsx scripts/audit-fee-navigator.ts --iteration 2
//   npx tsx scripts/audit-fee-navigator.ts --metrics-only
//   npx tsx scripts/audit-fee-navigator.ts --previous scripts/data/fee-navigator/audit-findings.json
// ============================================================================

import * as fs from 'node:fs';
import * as path from 'node:path';

// ============================================================================
// Configuration
// ============================================================================

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
  requiresReferral?: boolean;
  selfReferralBlocked?: boolean;
  facilityDesignation?: 'in_office' | 'out_of_office' | null;
  specialtyRestrictions?: string[];
  bundlingExclusions?: Array<{ excludedCode: string; relationship: string }>;
  ageRestriction?: { text: string; minYears?: number; maxYears?: number; minMonths?: number; maxMonths?: number } | null;
  maxPerDay?: number | null;
  maxPerVisit?: number | null;
  frequencyRestriction?: { text: string; count: number; period: string } | null;
  requiresAnesthesia?: boolean;
}

interface DimensionMetrics {
  current: number;
  target: number;
  gap: number;
  severity: 'high' | 'medium' | 'low';
}

interface SamplePattern {
  code: string;
  sentence: string;
}

interface Finding {
  id: string;
  dimension: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  unmatchedCount: number;
  sampleCodes: string[];
  samplePatterns: SamplePattern[];
}

interface AuditResult {
  timestamp: string;
  iteration: number;
  metrics: Record<string, DimensionMetrics>;
  findings: Finding[];
  actionable: boolean;
  totalGap: number;
  previousTotalGap: number | null;
}

// ============================================================================
// Dimension Definitions
// ============================================================================

interface DimensionDef {
  name: string;
  target: number;
  keywords: RegExp;
  isEmpty: (d: HscCode) => boolean;
  getCurrent: (data: HscCode[]) => number;
  extractSentence: (notes: string) => string | null;
}

const DIMENSIONS: DimensionDef[] = [
  {
    name: 'bundlingExclusions',
    target: 350,
    keywords: /not.*claim|not.*bill|exclusive|in lieu|includes HSC|not.*payable|shall not.*(?:submit|claim)|in addition to|conjunction|not to be (?:used|claimed)/i,
    isEmpty: (d) => !d.bundlingExclusions || d.bundlingExclusions.length === 0,
    getCurrent: (data) => data.filter(d => d.bundlingExclusions && d.bundlingExclusions.length > 0).length,
    extractSentence: (notes) => {
      const match = notes.match(/[^.]*(?:not.*claim|not.*bill|exclusive|in lieu|includes HSC|not.*payable|shall not|in addition to|conjunction|not to be (?:used|claimed))[^.]*\.?/i);
      return match ? match[0].trim().substring(0, 200) : null;
    },
  },
  {
    name: 'ageRestriction',
    target: 50,
    keywords: /\d+\s*(?:years?|months?)\s*(?:of age\s+)?(?:or\s+)?(?:younger|under|older|over|and\s+(?:under|over|older|younger))|(?:under|over|younger|older)\s+(?:than\s+)?\d+\s*(?:years?|months?)|(?:aged?\s+\d+|pediatric|geriatric|newborn|neonate|infant)/i,
    isEmpty: (d) => !d.ageRestriction,
    getCurrent: (data) => data.filter(d => d.ageRestriction).length,
    extractSentence: (notes) => {
      const match = notes.match(/[^.]*(?:\d+\s*(?:years?|months?)\s*(?:of age)?|pediatric|geriatric|newborn|neonate|infant|aged?\s+\d+)[^.]*\.?/i);
      return match ? match[0].trim().substring(0, 200) : null;
    },
  },
  {
    name: 'frequencyRestriction',
    target: 40,
    keywords: /per (?:year|month|week|shift|calendar|benefit|lifetime|session|admission|12.?month|365.?day)|once (?:per|every)|maximum.*per|limit.*per/i,
    isEmpty: (d) => !d.frequencyRestriction && (d.maxPerDay === null || d.maxPerDay === undefined) && (d.maxPerVisit === null || d.maxPerVisit === undefined),
    getCurrent: (data) => data.filter(d => d.frequencyRestriction || d.maxPerDay !== null || d.maxPerVisit !== null).length,
    extractSentence: (notes) => {
      const match = notes.match(/[^.]*(?:per (?:year|month|week|shift|calendar|benefit|lifetime|session|admission)|once (?:per|every)|maximum.*per|limit.*per)[^.]*\.?/i);
      return match ? match[0].trim().substring(0, 200) : null;
    },
  },
  {
    name: 'specialtyRestrictions',
    target: 120,
    keywords: /(?:may only be |only\s+.*?)claimed by|restricted to|only.*(?:physicians?|specialists?)\s+(?:in|with|who)/i,
    isEmpty: (d) => !d.specialtyRestrictions || d.specialtyRestrictions.length === 0,
    getCurrent: (data) => data.filter(d => d.specialtyRestrictions && d.specialtyRestrictions.length > 0).length,
    extractSentence: (notes) => {
      const match = notes.match(/[^.]*(?:(?:may only be |only\s+.*?)claimed by|restricted to|only.*(?:physicians?|specialists?))[^.]*\.?/i);
      return match ? match[0].trim().substring(0, 200) : null;
    },
  },
  {
    name: 'requiresReferral',
    target: 50,
    keywords: /referral|referred/i,
    isEmpty: (d) => !d.requiresReferral,
    getCurrent: (data) => data.filter(d => d.requiresReferral === true).length,
    extractSentence: (notes) => {
      const match = notes.match(/[^.]*(?:referral|referred)[^.]*\.?/i);
      return match ? match[0].trim().substring(0, 200) : null;
    },
  },
  {
    name: 'requiresAnesthesia',
    target: 15,
    keywords: /(?:under\s+(?:general\s+)?an[ae]sthesia|requires?\s+(?:general\s+)?an[ae]sthesia|procedural\s+sedation|an[ae]sthesia\s+specialist?y?)/i,
    isEmpty: (d) => !d.requiresAnesthesia,
    getCurrent: (data) => data.filter(d => d.requiresAnesthesia === true).length,
    extractSentence: (notes) => {
      const match = notes.match(/[^.]*(?:an[ae]sthesia|sedation)[^.]*\.?/i);
      return match ? match[0].trim().substring(0, 200) : null;
    },
  },
  {
    name: 'maxPerDay',
    target: 10,
    keywords: /per day|per diem|daily maximum|per patient per day|one.*per.*day/i,
    isEmpty: (d) => d.maxPerDay === null || d.maxPerDay === undefined,
    getCurrent: (data) => data.filter(d => d.maxPerDay !== null && d.maxPerDay !== undefined).length,
    extractSentence: (notes) => {
      const match = notes.match(/[^.]*(?:per day|per diem|daily|per patient per day)[^.]*\.?/i);
      return match ? match[0].trim().substring(0, 200) : null;
    },
  },
];

// ============================================================================
// Parse CLI Arguments
// ============================================================================

function parseArgs(): { iteration: number; metricsOnly: boolean; previousPath: string | null } {
  const args = process.argv.slice(2);
  let iteration = 1;
  let metricsOnly = false;
  let previousPath: string | null = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--iteration' && args[i + 1]) {
      iteration = parseInt(args[i + 1], 10);
      i++;
    } else if (args[i] === '--metrics-only') {
      metricsOnly = true;
    } else if (args[i] === '--previous' && args[i + 1]) {
      previousPath = args[i + 1];
      i++;
    }
  }

  return { iteration, metricsOnly, previousPath };
}

// ============================================================================
// Severity Calculation
// ============================================================================

function calcSeverity(gap: number, target: number): 'high' | 'medium' | 'low' {
  if (target === 0) return 'low';
  const ratio = gap / target;
  if (ratio > 0.5) return 'high';
  if (ratio > 0.2) return 'medium';
  return 'low';
}

// ============================================================================
// Pattern Grouping
// ============================================================================

function groupPatterns(patterns: SamplePattern[]): SamplePattern[] {
  // Deduplicate by sentence and return top 5 most representative
  const seen = new Set<string>();
  const unique: SamplePattern[] = [];
  for (const p of patterns) {
    const key = p.sentence.toLowerCase().substring(0, 80);
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(p);
    }
    if (unique.length >= 5) break;
  }
  return unique;
}

// ============================================================================
// Main Audit
// ============================================================================

function audit(data: HscCode[], iteration: number, previousPath: string | null): AuditResult {
  let previousTotalGap: number | null = null;
  if (previousPath && fs.existsSync(previousPath)) {
    const prev: AuditResult = JSON.parse(fs.readFileSync(previousPath, 'utf-8'));
    previousTotalGap = prev.totalGap;
  }

  const metrics: Record<string, DimensionMetrics> = {};
  const findings: Finding[] = [];
  let totalGap = 0;
  let findingId = 1;

  for (const dim of DIMENSIONS) {
    const current = dim.getCurrent(data);
    const gap = Math.max(0, dim.target - current);
    const severity = calcSeverity(gap, dim.target);
    metrics[dim.name] = { current, target: dim.target, gap, severity };
    totalGap += gap;

    if (gap <= 0) continue;

    // Find codes where notes match keywords but field is empty
    const unmatched = data.filter(d => d.notes && dim.keywords.test(d.notes) && dim.isEmpty(d));

    if (unmatched.length === 0) continue;

    // Extract sample patterns
    const allPatterns: SamplePattern[] = [];
    for (const code of unmatched) {
      const sentence = dim.extractSentence(code.notes || '');
      if (sentence) {
        allPatterns.push({ code: code.hscCode, sentence });
      }
    }

    const samplePatterns = groupPatterns(allPatterns);
    const sampleCodes = unmatched.slice(0, 5).map(d => d.hscCode);

    findings.push({
      id: `F-${String(findingId).padStart(3, '0')}`,
      dimension: dim.name,
      severity,
      description: `${unmatched.length} codes have ${dim.name}-related language in notes but no extracted ${dim.name}`,
      unmatchedCount: unmatched.length,
      sampleCodes,
      samplePatterns,
    });
    findingId++;
  }

  const actionable = findings.some(f => f.severity !== 'low' && f.unmatchedCount > 0);

  return {
    timestamp: new Date().toISOString(),
    iteration,
    metrics,
    findings,
    actionable,
    totalGap,
    previousTotalGap,
  };
}

// ============================================================================
// Entry Point
// ============================================================================

function main(): void {
  const { iteration, metricsOnly, previousPath } = parseArgs();

  // Load hsc-codes.json
  const hscPath = path.join(DATA_DIR, 'hsc-codes.json');
  if (!fs.existsSync(hscPath)) {
    console.error(`hsc-codes.json not found at ${hscPath}. Run the scraper and enrichment first.`);
    process.exit(1);
  }

  const data: HscCode[] = JSON.parse(fs.readFileSync(hscPath, 'utf-8'));

  const result = audit(data, iteration, previousPath);

  if (metricsOnly) {
    console.log(JSON.stringify(result.metrics, null, 2));
    process.exit(0);
  }

  // Write findings to file
  const findingsPath = path.join(DATA_DIR, 'audit-findings.json');
  fs.writeFileSync(findingsPath, JSON.stringify(result, null, 2));

  // Output to stdout
  console.log(JSON.stringify(result, null, 2));
}

main();
