#!/usr/bin/env node
/**
 * validate-article.js — Help Centre Article Quality Checker
 *
 * Validates a help centre markdown article against the content brief (Section 8.4).
 * Used as the verify command in the help-centre task pipeline.
 *
 * Usage:
 *   node scripts/validate-article.js help-centre/getting-started/setting-up-your-professional-profile.md
 *
 * Exit codes:
 *   0 = pass
 *   1 = fail (details printed to stderr)
 */

const fs = require('fs');
const path = require('path');

const filePath = process.argv[2];
if (!filePath) {
  console.error('Usage: node scripts/validate-article.js <file-path>');
  process.exit(1);
}

const errors = [];

// --- Check 1: File exists and is non-empty ---
if (!fs.existsSync(filePath)) {
  console.error(`FAIL: File does not exist: ${filePath}`);
  process.exit(1);
}

const content = fs.readFileSync(filePath, 'utf-8');
if (content.trim().length === 0) {
  console.error(`FAIL: File is empty: ${filePath}`);
  process.exit(1);
}

// --- Check 2: Starts with YAML front matter delimiter ---
if (!content.startsWith('---')) {
  errors.push('File does not start with YAML front matter delimiter (---)');
}

// --- Parse front matter ---
const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
if (!fmMatch) {
  errors.push('Could not parse YAML front matter (missing closing ---)');
  printAndExit();
}

const fmBlock = fmMatch[1];
const body = content.slice(fmMatch[0].length).trim();

// Simple YAML parser: extract key-value pairs (handles quoted and unquoted values)
function parseFrontMatter(block) {
  const fields = {};
  for (const line of block.split('\n')) {
    const match = line.match(/^(\w[\w_]*):\s*(.+)$/);
    if (match) {
      let val = match[2].trim();
      // Strip surrounding quotes
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      fields[match[1]] = val;
    }
  }
  return fields;
}

const fm = parseFrontMatter(fmBlock);

// --- Check 3: Required front matter fields ---
const requiredFields = ['title', 'category', 'slug', 'description', 'priority', 'last_reviewed', 'review_cycle', 'type'];
for (const field of requiredFields) {
  if (!fm[field]) {
    errors.push(`Missing required front matter field: ${field}`);
  }
}

// --- Check 4: Valid category ---
const validCategories = [
  'getting-started',
  'submitting-claims',
  'after-submission',
  'billing-reference',
  'your-account',
  'security-compliance'
];
if (fm.category && !validCategories.includes(fm.category)) {
  errors.push(`Invalid category "${fm.category}". Must be one of: ${validCategories.join(', ')}`);
}

// --- Check 5: Valid priority ---
if (fm.priority && !['1', '2', '3'].includes(fm.priority)) {
  errors.push(`Invalid priority "${fm.priority}". Must be 1, 2, or 3`);
}

// --- Check 6: Valid review_cycle ---
const validCycles = ['quarterly', 'annual', 'on-change'];
if (fm.review_cycle && !validCycles.includes(fm.review_cycle)) {
  errors.push(`Invalid review_cycle "${fm.review_cycle}". Must be one of: ${validCycles.join(', ')}`);
}

// --- Check 7: No em dashes ---
if (content.includes('\u2014')) {
  errors.push('Contains em dash character (U+2014). Use semicolons or colons instead');
}
if (body.match(/(?<!\w)--(?!\w)/)) {
  errors.push('Contains "--" used as em dash. Use semicolons or colons instead');
}

// --- Check 8: No placeholder language ---
const placeholderPatterns = [
  /coming soon/i,
  /to be determined/i,
  /\bTBD\b/,
  /\bplaceholder\b/i,
  /more details to follow/i
];
for (const pattern of placeholderPatterns) {
  if (pattern.test(body)) {
    errors.push(`Contains placeholder language matching: ${pattern}`);
  }
}

// --- Check 9: Word count by article type ---
const validTypes = ['procedural', 'reference'];
if (fm.type && !validTypes.includes(fm.type)) {
  errors.push(`Invalid type "${fm.type}". Must be one of: ${validTypes.join(', ')}`);
}

if (body) {
  const wordCount = body.split(/\s+/).filter(w => w.length > 0).length;

  if (fm.type === 'procedural') {
    if (wordCount < 300) {
      errors.push(`Word count ${wordCount} is below minimum 300 for procedural articles`);
    }
    if (wordCount > 600) {
      errors.push(`Word count ${wordCount} exceeds maximum 600 for procedural articles`);
    }
  } else if (fm.type === 'reference') {
    if (wordCount < 600) {
      errors.push(`Word count ${wordCount} is below minimum 600 for reference articles`);
    }
    if (wordCount > 1000) {
      errors.push(`Word count ${wordCount} exceeds maximum 1000 for reference articles`);
    }
  }
}

// --- Check 10: Body is not empty ---
if (!body || body.length === 0) {
  errors.push('Article body is empty (no content after front matter)');
}

// --- Report ---
function printAndExit() {
  if (errors.length > 0) {
    console.error(`FAIL: ${filePath}`);
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }
  console.log(`PASS: ${filePath}`);
  process.exit(0);
}

printAndExit();
