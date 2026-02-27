#!/usr/bin/env node
/**
 * validate-all-articles.js — Comprehensive Help Centre Validation
 *
 * Performs four validation steps:
 *   1. Verify all 43 expected articles exist and are non-empty
 *   2. Run validate-article.js on every article
 *   3. Check that all cross-links (/help-centre/...) resolve to existing files
 *   4. Report summary: total found, validated, missing, broken links, total word count
 *
 * Usage:
 *   node scripts/validate-all-articles.js
 *
 * Exit codes:
 *   0 = all checks pass
 *   1 = one or more checks failed
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const HC_DIR = path.join(ROOT, 'help-centre');

// ── Step 0: Define the expected 43 articles ──────────────────────────

const EXPECTED_ARTICLES = {
  'getting-started': [
    'setting-up-your-professional-profile.md',
    'adding-your-business-arrangement-numbers.md',
    'configuring-your-practice-locations.md',
    'setting-up-wcb-billing.md',
    'inviting-a-delegate.md',
    'choosing-your-submission-preferences.md',
    'your-first-thursday-submission.md',
  ],
  'submitting-claims': [
    'importing-encounters-from-your-emr.md',
    'using-mobile-claim-entry.md',
    'creating-claims-manually.md',
    'understanding-flags-and-suggestions-on-your-claims.md',
    'how-the-rules-engine-works.md',
    'how-the-advice-engine-works.md',
    'how-the-thursday-submission-cycle-works.md',
    'submission-preferences-explained.md',
    'submitting-wcb-claims.md',
  ],
  'after-submission': [
    'understanding-your-assessment-results.md',
    'reading-rejection-codes.md',
    'correcting-and-resubmitting-refused-claims.md',
    'tracking-rejection-patterns.md',
  ],
  'your-account': [
    'understanding-your-subscription.md',
    'switching-between-monthly-and-annual-billing.md',
    'managing-your-practice-account.md',
    'the-referral-program.md',
    'cancelling-your-subscription.md',
    'exporting-your-data.md',
    'updating-your-profile.md',
    'managing-delegates.md',
  ],
  'billing-reference': [
    'ahcip-fee-for-service-billing-how-the-system-works.md',
    'the-thursday-submission-cycle-explained.md',
    'understanding-the-schedule-of-medical-benefits.md',
    'rrnp-rural-and-remote-northern-program.md',
    'pcpcm-primary-care-panel-and-continuity-model.md',
    'wcb-alberta-billing-for-physicians.md',
    'after-hours-billing-and-time-premiums.md',
    'common-ahcip-explanatory-codes-and-what-they-mean.md',
    'business-arrangements-in-alberta.md',
    'h-link-what-it-is-and-how-electronic-claims-submission-works.md',
  ],
  'security-compliance': [
    'how-meritum-protects-your-data.md',
    'hia-compliance-and-the-information-manager-agreement.md',
    'canadian-data-residency.md',
    'delegate-access-and-data-separation.md',
    'practice-admin-access-boundaries.md',
  ],
};

// ── Counters ─────────────────────────────────────────────────────────

let totalExpected = 0;
let totalFound = 0;
let totalValidated = 0;
let totalWordCount = 0;
const missingArticles = [];
const validationFailures = [];
const brokenLinks = [];
let hasErrors = false;

// Count expected
for (const category of Object.keys(EXPECTED_ARTICLES)) {
  totalExpected += EXPECTED_ARTICLES[category].length;
}

// ── Step 1: Verify all 43 articles exist and are non-empty ───────────

console.log('═══════════════════════════════════════════════════════════');
console.log('  STEP 1: Checking article existence');
console.log('═══════════════════════════════════════════════════════════\n');

for (const [category, articles] of Object.entries(EXPECTED_ARTICLES)) {
  for (const article of articles) {
    const filePath = path.join(HC_DIR, category, article);
    const relPath = `help-centre/${category}/${article}`;

    if (!fs.existsSync(filePath)) {
      missingArticles.push(relPath);
      console.log(`  MISSING: ${relPath}`);
    } else {
      const content = fs.readFileSync(filePath, 'utf-8');
      if (content.trim().length === 0) {
        missingArticles.push(`${relPath} (empty)`);
        console.log(`  EMPTY:   ${relPath}`);
      } else {
        totalFound++;
        console.log(`  OK:      ${relPath}`);
      }
    }
  }
}

console.log(`\n  Found: ${totalFound}/${totalExpected} articles`);
if (missingArticles.length > 0) {
  hasErrors = true;
  console.log(`  Missing: ${missingArticles.length}`);
}
console.log('');

// ── Step 2: Validate each article with validate-article.js ──────────

console.log('═══════════════════════════════════════════════════════════');
console.log('  STEP 2: Running validate-article.js on each article');
console.log('═══════════════════════════════════════════════════════════\n');

const validateScript = path.join(ROOT, 'scripts', 'validate-article.js');

for (const [category, articles] of Object.entries(EXPECTED_ARTICLES)) {
  for (const article of articles) {
    const filePath = path.join(HC_DIR, category, article);
    const relPath = `help-centre/${category}/${article}`;

    if (!fs.existsSync(filePath) || fs.readFileSync(filePath, 'utf-8').trim().length === 0) {
      continue; // Already flagged in step 1
    }

    try {
      execSync(`node "${validateScript}" "${filePath}"`, {
        cwd: ROOT,
        stdio: 'pipe',
        encoding: 'utf-8',
      });
      totalValidated++;
      console.log(`  PASS: ${relPath}`);
    } catch (err) {
      hasErrors = true;
      const stderr = err.stderr ? err.stderr.trim() : 'Unknown error';
      validationFailures.push({ path: relPath, errors: stderr });
      console.log(`  FAIL: ${relPath}`);
      // Print indented error details
      for (const line of stderr.split('\n')) {
        console.log(`         ${line}`);
      }
    }
  }
}

console.log(`\n  Validated: ${totalValidated}/${totalFound} articles`);
if (validationFailures.length > 0) {
  console.log(`  Failures: ${validationFailures.length}`);
}
console.log('');

// ── Step 3: Check cross-links resolve ────────────────────────────────

console.log('═══════════════════════════════════════════════════════════');
console.log('  STEP 3: Checking cross-links');
console.log('═══════════════════════════════════════════════════════════\n');

const crossLinkPattern = /\[([^\]]*)\]\(\/help-centre\/([^)]+)\)/g;
let totalLinks = 0;
let validLinks = 0;

for (const [category, articles] of Object.entries(EXPECTED_ARTICLES)) {
  for (const article of articles) {
    const filePath = path.join(HC_DIR, category, article);
    const relPath = `help-centre/${category}/${article}`;

    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf-8');
    let match;

    while ((match = crossLinkPattern.exec(content)) !== null) {
      totalLinks++;
      const linkText = match[1];
      let linkTarget = match[2];

      // Remove any trailing anchor (#...)
      linkTarget = linkTarget.split('#')[0];

      // The link path is like "category/slug" — map to file on disk
      // Links may or may not include .md extension
      let targetPath;
      if (linkTarget.endsWith('.md')) {
        targetPath = path.join(HC_DIR, linkTarget);
      } else {
        // Try with .md extension appended to the last segment
        targetPath = path.join(HC_DIR, linkTarget + '.md');
      }

      if (fs.existsSync(targetPath)) {
        validLinks++;
      } else {
        // Also try interpreting the link target as a directory with the slug as filename
        const altPath = path.join(HC_DIR, linkTarget);
        if (fs.existsSync(altPath)) {
          validLinks++;
        } else {
          hasErrors = true;
          brokenLinks.push({
            source: relPath,
            linkText,
            target: `/help-centre/${linkTarget}`,
          });
          console.log(`  BROKEN: ${relPath}`);
          console.log(`          Link: [${linkText}](/help-centre/${linkTarget})`);
          console.log(`          Expected file: ${targetPath}`);
        }
      }
    }
  }
}

if (brokenLinks.length === 0) {
  console.log('  All cross-links resolve correctly.');
}
console.log(`\n  Total links: ${totalLinks}`);
console.log(`  Valid: ${validLinks}`);
console.log(`  Broken: ${brokenLinks.length}`);
console.log('');

// ── Step 4: Word count summary ───────────────────────────────────────

console.log('═══════════════════════════════════════════════════════════');
console.log('  STEP 4: Word count summary');
console.log('═══════════════════════════════════════════════════════════\n');

for (const [category, articles] of Object.entries(EXPECTED_ARTICLES)) {
  let categoryWordCount = 0;

  for (const article of articles) {
    const filePath = path.join(HC_DIR, category, article);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf-8');
    const fmMatch = content.match(/^---\r?\n[\s\S]*?\r?\n---/);
    const body = fmMatch ? content.slice(fmMatch[0].length).trim() : content.trim();
    const wordCount = body.split(/\s+/).filter(w => w.length > 0).length;

    totalWordCount += wordCount;
    categoryWordCount += wordCount;
  }

  console.log(`  ${category}: ${categoryWordCount} words (${articles.length} articles)`);
}

console.log('');

// ── Final Report ─────────────────────────────────────────────────────

console.log('═══════════════════════════════════════════════════════════');
console.log('  FINAL REPORT');
console.log('═══════════════════════════════════════════════════════════\n');

console.log(`  Expected articles:      ${totalExpected}`);
console.log(`  Articles found:         ${totalFound}`);
console.log(`  Articles validated:     ${totalValidated}`);
console.log(`  Missing articles:       ${missingArticles.length}`);
console.log(`  Validation failures:    ${validationFailures.length}`);
console.log(`  Cross-links checked:    ${totalLinks}`);
console.log(`  Broken cross-links:     ${brokenLinks.length}`);
console.log(`  Total word count:       ${totalWordCount}`);
console.log('');

if (missingArticles.length > 0) {
  console.log('  Missing articles:');
  for (const m of missingArticles) {
    console.log(`    - ${m}`);
  }
  console.log('');
}

if (validationFailures.length > 0) {
  console.log('  Validation failures:');
  for (const f of validationFailures) {
    console.log(`    - ${f.path}`);
  }
  console.log('');
}

if (brokenLinks.length > 0) {
  console.log('  Broken cross-links:');
  for (const b of brokenLinks) {
    console.log(`    - ${b.source} -> ${b.target}`);
  }
  console.log('');
}

if (hasErrors) {
  console.log('  RESULT: FAIL\n');
  process.exit(1);
} else {
  console.log('  RESULT: PASS\n');
  process.exit(0);
}
