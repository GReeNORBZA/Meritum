#!/usr/bin/env tsx
// ============================================================================
// Fee Navigator — Browser-Based Data Exploration Script
//
// The existing scraper uses cheerio (server-side HTML parsing) which CANNOT:
//   - Execute JavaScript or trigger pop-ups/modals
//   - See dynamically loaded content (lazy-loaded panels, AJAX on click)
//   - Interact with tooltips, hover states, or accordion panels
//   - Detect content behind tabs or expandable sections
//
// This script uses Playwright (headless browser) to explore the Fee Navigator
// site and identify data that the cheerio scraper may be missing.
//
// Usage:
//   cd /home/developer/Desktop/projects
//   pnpm add -D playwright @playwright/test
//   npx playwright install chromium
//   npx tsx scripts/explore-fee-navigator.ts
//
// Output: scripts/data/fee-navigator/exploration-report.json
// ============================================================================

import { chromium, type Browser, type Page, type ElementHandle } from 'playwright';
import * as fs from 'node:fs';
import * as path from 'node:path';

// ============================================================================
// Configuration
// ============================================================================

const BASE_URL = 'https://apps.albertadoctors.org/fee-navigator';
const OUTPUT_DIR = path.join(path.dirname(new URL(import.meta.url).pathname), 'data', 'fee-navigator');
const DELAY_MS = 1500; // Wait for dynamic content to load

// Sample codes to explore in depth (diverse categories)
const SAMPLE_HSC_CODES = [
  '03.03A',   // Visit — used as reference throughout
  '01.01A',   // M+ Designated Minor Procedure
  '03.04A',   // Consultation or office visit
  '08.19A',   // Procedure / surgical
  '13.99J',   // Anaesthesia
  '03.01A',   // Common GP visit code
  '03.08A',   // Hospital visit
  '73.21',    // Radiology
  '95.09',    // Lab / test
];

// ============================================================================
// Types
// ============================================================================

interface ExplorationResult {
  url: string;
  hscCode: string;
  visibleSections: string[];
  clickableElements: ClickableElement[];
  popupsFound: PopupContent[];
  tabsFound: TabContent[];
  tooltipsFound: TooltipContent[];
  hiddenSections: HiddenSection[];
  allTextContent: string;
  allLinks: LinkInfo[];
  iframesFound: string[];
  dataAttributes: Record<string, string>[];
  missingFromScraper: string[];
}

interface ClickableElement {
  tag: string;
  text: string;
  href: string | null;
  classes: string;
  onclick: string | null;
  dataAttributes: Record<string, string>;
}

interface PopupContent {
  triggerElement: string;
  triggerText: string;
  dialogContent: string;
  dialogTitle: string | null;
}

interface TabContent {
  tabLabel: string;
  tabContent: string;
  isActive: boolean;
}

interface TooltipContent {
  triggerElement: string;
  triggerText: string;
  tooltipText: string;
}

interface HiddenSection {
  selector: string;
  content: string;
  reason: string; // "display:none", "visibility:hidden", "aria-hidden", etc.
}

interface LinkInfo {
  text: string;
  href: string;
  isExternal: boolean;
  opensPopup: boolean;
}

interface PageComparison {
  hscCode: string;
  fieldsInBrowser: string[];
  fieldsInScraper: string[];
  missingFromScraper: string[];
  extraInBrowser: string[];
}

interface ExplorationReport {
  timestamp: string;
  pagesExplored: number;
  results: ExplorationResult[];
  comparisons: PageComparison[];
  globalFindings: GlobalFindings;
}

interface GlobalFindings {
  hasJavaScriptPopups: boolean;
  hasDynamicTabs: boolean;
  hasTooltips: boolean;
  hasHiddenSections: boolean;
  hasIframes: boolean;
  uniqueDataFields: string[];
  navigationLinks: string[];
  potentialMissingEndpoints: string[];
  summary: string[];
}

// ============================================================================
// Load existing scraped data for comparison
// ============================================================================

function loadScrapedCode(hscCode: string): Record<string, unknown> | null {
  const filePath = path.join(OUTPUT_DIR, 'hsc-codes.json');
  if (!fs.existsSync(filePath)) return null;
  const allCodes = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  return allCodes.find((c: { hscCode: string }) => c.hscCode === hscCode) ?? null;
}

// ============================================================================
// Helper: wait and scroll to load lazy content
// ============================================================================

async function waitForDynamicContent(page: Page): Promise<void> {
  await page.waitForLoadState('networkidle').catch(() => {});
  await page.waitForTimeout(DELAY_MS);

  // Scroll to bottom to trigger lazy loading
  await page.evaluate(() => {
    window.scrollTo(0, document.body.scrollHeight);
  });
  await page.waitForTimeout(500);

  // Scroll back up
  await page.evaluate(() => {
    window.scrollTo(0, 0);
  });
  await page.waitForTimeout(300);
}

// ============================================================================
// Probe 1: Discover all visible sections on an HSC detail page
// ============================================================================

async function discoverSections(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const sections: string[] = [];
    const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
    headings.forEach((h) => {
      const text = h.textContent?.trim();
      if (text) sections.push(`${h.tagName}: ${text}`);
    });

    // Also look for labeled sections via class or id
    const divs = document.querySelectorAll('div[class], section[class], div[id]');
    divs.forEach((d) => {
      const cls = d.getAttribute('class') || '';
      const id = d.getAttribute('id') || '';
      const hasContent = (d.textContent?.trim().length ?? 0) > 10;
      if (hasContent && (cls || id)) {
        sections.push(`DIV.${cls || id}: ${d.textContent?.trim().slice(0, 80)}`);
      }
    });

    return [...new Set(sections)];
  });
}

// ============================================================================
// Probe 2: Find all clickable elements that might trigger popups
// ============================================================================

async function findClickableElements(page: Page): Promise<ClickableElement[]> {
  return page.evaluate(() => {
    const elements: ClickableElement[] = [];
    const clickables = document.querySelectorAll(
      'a, button, [onclick], [data-toggle], [data-bs-toggle], ' +
      '[role="button"], [tabindex="0"], .clickable, .expandable, ' +
      '[data-target], [data-modal], [aria-haspopup], [data-popup], ' +
      '[data-tooltip], [title]:not(head title)',
    );

    clickables.forEach((el) => {
      const text = el.textContent?.trim().slice(0, 100) ?? '';
      const tag = el.tagName.toLowerCase();
      const href = el.getAttribute('href');

      // Skip tree navigation nodes (already handled by scraper)
      if (el.classList.contains('node') && (el.classList.contains('expandable') || el.classList.contains('viewable'))) {
        return;
      }

      // Collect data attributes
      const dataAttrs: Record<string, string> = {};
      for (const attr of el.attributes) {
        if (attr.name.startsWith('data-')) {
          dataAttrs[attr.name] = attr.value;
        }
      }

      elements.push({
        tag,
        text,
        href,
        classes: el.getAttribute('class') ?? '',
        onclick: el.getAttribute('onclick'),
        dataAttributes: dataAttrs,
      });
    });

    return elements;
  });
}

// ============================================================================
// Probe 3: Click elements and detect popups/modals/dialogs
// ============================================================================

async function probeForPopups(page: Page): Promise<PopupContent[]> {
  const popups: PopupContent[] = [];

  // Listen for dialog events
  page.on('dialog', async (dialog) => {
    popups.push({
      triggerElement: 'browser-dialog',
      triggerText: '',
      dialogContent: dialog.message(),
      dialogTitle: dialog.type(),
    });
    await dialog.dismiss();
  });

  // Find elements that look like they trigger popups
  const popupTriggers = await page.$$(
    '[data-toggle="modal"], [data-bs-toggle="modal"], ' +
    '[data-popup], [aria-haspopup="true"], [aria-haspopup="dialog"], ' +
    'a[target="_blank"], a[href^="javascript:"], ' +
    'button:not(.node), [onclick*="modal"], [onclick*="popup"], ' +
    '[onclick*="dialog"], [onclick*="window.open"]',
  );

  for (const trigger of popupTriggers) {
    const triggerText = await trigger.textContent() ?? '';
    const triggerTag = await trigger.evaluate((el) => el.tagName.toLowerCase());

    try {
      // Take a snapshot before clicking
      const beforeModals = await page.$$('.modal, .dialog, .popup, [role="dialog"], [role="alertdialog"]');
      const beforeCount = beforeModals.length;

      // Click the trigger
      await trigger.click({ timeout: 2000 }).catch(() => {});
      await page.waitForTimeout(800);

      // Check for new modals/dialogs
      const afterModals = await page.$$('.modal, .dialog, .popup, [role="dialog"], [role="alertdialog"], .overlay');
      if (afterModals.length > beforeCount) {
        for (const modal of afterModals.slice(beforeCount)) {
          const content = await modal.textContent() ?? '';
          const title = await modal.$eval('.modal-title, .dialog-title, h2, h3', (el) => el.textContent?.trim() ?? '').catch(() => null);
          popups.push({
            triggerElement: triggerTag,
            triggerText: triggerText.trim().slice(0, 100),
            dialogContent: content.trim().slice(0, 2000),
            dialogTitle: title,
          });

          // Try to close it
          await modal.$eval('.close, .modal-close, button[aria-label="Close"]', (el: HTMLElement) => el.click()).catch(() => {});
          await page.keyboard.press('Escape');
          await page.waitForTimeout(300);
        }
      }

      // Check for new page/popup windows
      // (handled via browser context newPage events below)
    } catch {
      // Element may have become stale
    }
  }

  return popups;
}

// ============================================================================
// Probe 4: Detect tabs and their content
// ============================================================================

async function probeTabs(page: Page): Promise<TabContent[]> {
  const tabs: TabContent[] = [];

  // Common tab selectors
  const tabSelectors = [
    '.nav-tabs .nav-link, .nav-tabs .nav-item a',
    '[role="tab"]',
    '.tab, .tabs .tab-link',
    '.ui-tabs-nav a',
    '[data-toggle="tab"], [data-bs-toggle="tab"]',
  ];

  for (const selector of tabSelectors) {
    const tabElements = await page.$$(selector);
    for (const tab of tabElements) {
      const label = await tab.textContent() ?? '';
      const isActive = await tab.evaluate(
        (el) => el.classList.contains('active') || el.getAttribute('aria-selected') === 'true',
      );

      // Click the tab to load its content
      try {
        await tab.click({ timeout: 2000 });
        await page.waitForTimeout(500);

        // Get the associated panel content
        const panelId = await tab.evaluate((el) => {
          return el.getAttribute('data-target') ||
            el.getAttribute('href')?.replace('#', '') ||
            el.getAttribute('aria-controls') ||
            '';
        });

        let content = '';
        if (panelId) {
          content = await page.$eval(`#${panelId}, [aria-labelledby="${panelId}"]`, (el) => el.textContent?.trim() ?? '').catch(() => '');
        }

        // If no panel found, get the visible tab-pane content
        if (!content) {
          content = await page.$eval('.tab-pane.active, .tab-content .active, [role="tabpanel"]:not([hidden])', (el) => el.textContent?.trim() ?? '').catch(() => '');
        }

        tabs.push({
          tabLabel: label.trim(),
          tabContent: content.slice(0, 2000),
          isActive,
        });
      } catch {
        tabs.push({
          tabLabel: label.trim(),
          tabContent: '[click failed]',
          isActive,
        });
      }
    }
  }

  return tabs;
}

// ============================================================================
// Probe 5: Find tooltips and hover-triggered content
// ============================================================================

async function probeTooltips(page: Page): Promise<TooltipContent[]> {
  const tooltips: TooltipContent[] = [];

  // Elements with title attributes (native tooltips)
  const titledElements = await page.$$('[title]:not(head title)');
  for (const el of titledElements) {
    const text = await el.textContent() ?? '';
    const title = await el.getAttribute('title') ?? '';
    const tag = await el.evaluate((e) => e.tagName.toLowerCase());
    tooltips.push({
      triggerElement: tag,
      triggerText: text.trim().slice(0, 100),
      tooltipText: title,
    });
  }

  // Elements with data-tooltip, data-tippy-content, etc.
  const tooltipElements = await page.$$(
    '[data-tooltip], [data-tippy-content], [data-original-title], ' +
    '[data-content], [aria-describedby]',
  );
  for (const el of tooltipElements) {
    const text = await el.textContent() ?? '';
    const tag = await el.evaluate((e) => e.tagName.toLowerCase());
    const tooltipText =
      await el.getAttribute('data-tooltip') ??
      await el.getAttribute('data-tippy-content') ??
      await el.getAttribute('data-original-title') ??
      await el.getAttribute('data-content') ??
      '';

    // Also try hovering to trigger dynamic tooltips
    try {
      await el.hover({ timeout: 1000 });
      await page.waitForTimeout(500);

      // Check for newly appeared tooltip elements
      const visibleTooltip = await page.$('.tooltip.show, .tippy-box, [role="tooltip"]:not([hidden])');
      if (visibleTooltip) {
        const dynamicText = await visibleTooltip.textContent() ?? '';
        tooltips.push({
          triggerElement: tag,
          triggerText: text.trim().slice(0, 100),
          tooltipText: dynamicText.trim() || tooltipText,
        });
        continue;
      }
    } catch {
      // Hover failed
    }

    if (tooltipText) {
      tooltips.push({
        triggerElement: tag,
        triggerText: text.trim().slice(0, 100),
        tooltipText,
      });
    }
  }

  return tooltips;
}

// ============================================================================
// Probe 6: Find hidden/collapsed sections
// ============================================================================

async function findHiddenSections(page: Page): Promise<HiddenSection[]> {
  return page.evaluate(() => {
    const hidden: HiddenSection[] = [];
    const allElements = document.querySelectorAll('div, section, details, aside, [hidden]');

    allElements.forEach((el) => {
      const htmlEl = el as HTMLElement;
      const content = htmlEl.textContent?.trim() ?? '';
      if (content.length < 10) return; // Skip trivially empty

      const style = window.getComputedStyle(htmlEl);
      let reason = '';

      if (style.display === 'none') reason = 'display:none';
      else if (style.visibility === 'hidden') reason = 'visibility:hidden';
      else if (htmlEl.getAttribute('aria-hidden') === 'true') reason = 'aria-hidden';
      else if (htmlEl.hasAttribute('hidden')) reason = 'hidden attribute';
      else if (style.opacity === '0') reason = 'opacity:0';
      else if (style.height === '0px' && style.overflow === 'hidden') reason = 'height:0 overflow:hidden';
      else if (htmlEl.tagName === 'DETAILS' && !htmlEl.hasAttribute('open')) reason = 'collapsed <details>';

      if (reason) {
        const cls = htmlEl.getAttribute('class') ?? '';
        const id = htmlEl.getAttribute('id') ?? '';
        hidden.push({
          selector: `${htmlEl.tagName.toLowerCase()}${id ? '#' + id : ''}${cls ? '.' + cls.split(' ').join('.') : ''}`,
          content: content.slice(0, 1000),
          reason,
        });
      }
    });

    return hidden;
  });
}

// ============================================================================
// Probe 7: Collect all links on the page
// ============================================================================

async function collectLinks(page: Page): Promise<LinkInfo[]> {
  return page.evaluate((baseUrl) => {
    const links: LinkInfo[] = [];
    document.querySelectorAll('a[href]').forEach((a) => {
      const href = a.getAttribute('href') ?? '';
      const text = a.textContent?.trim() ?? '';

      // Skip tree navigation
      if (a.classList.contains('node')) return;

      links.push({
        text: text.slice(0, 100),
        href,
        isExternal: !href.startsWith('/') && !href.startsWith(baseUrl),
        opensPopup: a.getAttribute('target') === '_blank' ||
          href.startsWith('javascript:') ||
          !!a.getAttribute('onclick')?.includes('window.open'),
      });
    });
    return links;
  }, BASE_URL);
}

// ============================================================================
// Probe 8: Check for iframes
// ============================================================================

async function findIframes(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const iframes: string[] = [];
    document.querySelectorAll('iframe').forEach((iframe) => {
      iframes.push(iframe.src || iframe.getAttribute('srcdoc')?.slice(0, 200) || '[no src]');
    });
    return iframes;
  });
}

// ============================================================================
// Probe 9: Extract ALL data attributes from the page
// ============================================================================

async function extractDataAttributes(page: Page): Promise<Record<string, string>[]> {
  return page.evaluate(() => {
    const results: Record<string, string>[] = [];
    document.querySelectorAll('[data-key], [data-id], [data-code], [data-type], [data-value]').forEach((el) => {
      const attrs: Record<string, string> = {};
      for (const attr of el.attributes) {
        if (attr.name.startsWith('data-')) {
          attrs[attr.name] = attr.value;
        }
      }
      attrs['_tag'] = el.tagName.toLowerCase();
      attrs['_text'] = (el.textContent?.trim() ?? '').slice(0, 100);
      results.push(attrs);
    });
    return results;
  });
}

// ============================================================================
// Probe 10: Compare browser content vs scraped data
// ============================================================================

function compareWithScrapedData(
  hscCode: string,
  browserText: string,
): PageComparison {
  const scraped = loadScrapedCode(hscCode);
  const fieldsInScraper = scraped ? Object.keys(scraped) : [];

  // Extract structured data hints from browser text
  const browserFields: string[] = [];

  // Check for field labels in the browser content
  const fieldPatterns: Array<[string, RegExp]> = [
    ['category', /category/i],
    ['baseRate', /base\s*rate/i],
    ['description', /description/i],
    ['commonTerms', /common\s*terms?/i],
    ['notes', /note[s]?:/i],
    ['billingTips', /billing\s*tips?/i],
    ['modifiers', /modifier[s]?/i],
    ['specialtyRestrictions', /specialty|specialties/i],
    ['facilityRestrictions', /facility|facilities/i],
    ['maxPerDay', /max(imum)?\s*(per\s*day|daily)/i],
    ['maxPerVisit', /max(imum)?\s*per\s*visit/i],
    ['requiresReferral', /referral/i],
    ['combinationGroup', /combination|group/i],
    ['shadowBilling', /shadow\s*billing/i],
    ['pcpcm', /pcpcm|basket/i],
    ['governingRule', /governing\s*rule/i],
    ['effectiveDate', /effective\s*date/i],
    ['prerequisite', /prerequisite/i],
    ['restriction', /restriction/i],
    ['timeUnit', /time\s*unit|per\s*unit/i],
    ['ageLimit', /age\s*limit|age\s*restrict/i],
    ['genderRestriction', /gender|sex\s*restrict/i],
    ['diagnosticCode', /diagnostic\s*code|icd/i],
    ['relatedCodes', /related\s*codes?|see\s*also/i],
    ['claimRules', /claim\s*rules?/i],
    ['paymentRules', /payment\s*rules?/i],
    ['serviceLocation', /service\s*location|location\s*restrict/i],
  ];

  for (const [field, pattern] of fieldPatterns) {
    if (pattern.test(browserText)) {
      browserFields.push(field);
    }
  }

  const missingFromScraper = browserFields.filter((f) => !fieldsInScraper.includes(f));

  return {
    hscCode,
    fieldsInBrowser: browserFields,
    fieldsInScraper,
    missingFromScraper,
    extraInBrowser: browserFields.filter(
      (f) => !fieldsInScraper.includes(f) && !['governingRule', 'effectiveDate', 'restriction'].includes(f),
    ),
  };
}

// ============================================================================
// Explore a single HSC detail page
// ============================================================================

async function exploreHscPage(
  page: Page,
  hscCode: string,
): Promise<ExplorationResult> {
  const url = `${BASE_URL}/hsc/${encodeURIComponent(hscCode)}`;
  console.log(`\n  Exploring: ${url}`);

  await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
  await waitForDynamicContent(page);

  // Run all probes
  console.log(`    Discovering sections...`);
  const visibleSections = await discoverSections(page);

  console.log(`    Finding clickable elements...`);
  const clickableElements = await findClickableElements(page);

  console.log(`    Probing for popups/modals...`);
  const popupsFound = await probeForPopups(page);

  console.log(`    Probing tabs...`);
  const tabsFound = await probeTabs(page);

  console.log(`    Probing tooltips...`);
  const tooltipsFound = await probeTooltips(page);

  console.log(`    Finding hidden sections...`);
  const hiddenSections = await findHiddenSections(page);

  console.log(`    Collecting links...`);
  const allLinks = await collectLinks(page);

  console.log(`    Checking for iframes...`);
  const iframesFound = await findIframes(page);

  console.log(`    Extracting data attributes...`);
  const dataAttributes = await extractDataAttributes(page);

  // Full page text for comparison
  const allTextContent = await page.evaluate(() => document.body.textContent?.trim() ?? '');

  // Compare with scraped data
  const comparison = compareWithScrapedData(hscCode, allTextContent);

  console.log(`    Sections: ${visibleSections.length}, Clickables: ${clickableElements.length}`);
  console.log(`    Popups: ${popupsFound.length}, Tabs: ${tabsFound.length}, Tooltips: ${tooltipsFound.length}`);
  console.log(`    Hidden: ${hiddenSections.length}, Links: ${allLinks.length}, iframes: ${iframesFound.length}`);
  if (comparison.missingFromScraper.length > 0) {
    console.log(`    *** MISSING FROM SCRAPER: ${comparison.missingFromScraper.join(', ')}`);
  }

  return {
    url,
    hscCode,
    visibleSections,
    clickableElements,
    popupsFound,
    tabsFound,
    tooltipsFound,
    hiddenSections,
    allTextContent: allTextContent.slice(0, 5000),
    allLinks,
    iframesFound,
    dataAttributes,
    missingFromScraper: comparison.missingFromScraper,
  };
}

// ============================================================================
// Explore navigation pages for undiscovered sections
// ============================================================================

async function exploreNavigationPages(page: Page): Promise<string[]> {
  console.log('\n=== Exploring navigation structure ===\n');

  const allNavLinks: string[] = [];

  // Visit the main fee-navigator page
  await page.goto(BASE_URL, { waitUntil: 'networkidle', timeout: 30000 });
  await waitForDynamicContent(page);

  // Find all navigation links
  const navLinks = await page.evaluate((baseUrl) => {
    const links: string[] = [];
    document.querySelectorAll('a[href]').forEach((a) => {
      const href = a.getAttribute('href') ?? '';
      if (href.startsWith('/fee-navigator') || href.startsWith(baseUrl)) {
        links.push(href);
      }
    });
    return [...new Set(links)];
  }, BASE_URL);

  allNavLinks.push(...navLinks);
  console.log(`  Found ${navLinks.length} navigation links on main page`);

  // Visit each major section
  const sections = ['hsc', 'modifiers', 'governing-rules', 'explanatory-codes'];
  for (const section of sections) {
    const sectionUrl = `${BASE_URL}/${section}`;
    try {
      await page.goto(sectionUrl, { waitUntil: 'networkidle', timeout: 15000 });
      await waitForDynamicContent(page);

      const sectionLinks = await page.evaluate((bu) => {
        const links: string[] = [];
        document.querySelectorAll('a[href]').forEach((a) => {
          const href = a.getAttribute('href') ?? '';
          if (href.startsWith('/fee-navigator') || href.startsWith(bu)) {
            links.push(href);
          }
        });
        return [...new Set(links)];
      }, BASE_URL);

      allNavLinks.push(...sectionLinks);
      console.log(`  Found ${sectionLinks.length} links in /${section}`);
    } catch (err) {
      console.warn(`  Error exploring /${section}: ${(err as Error).message}`);
    }
  }

  return [...new Set(allNavLinks)];
}

// ============================================================================
// Explore the AJAX endpoints by monitoring network traffic
// ============================================================================

async function monitorNetworkRequests(
  page: Page,
  hscCode: string,
): Promise<string[]> {
  const ajaxUrls: string[] = [];

  page.on('request', (request) => {
    const url = request.url();
    if (url.includes('fee-navigator') && request.resourceType() !== 'image') {
      ajaxUrls.push(`${request.method()} ${url}`);
    }
  });

  // Navigate to the page and interact with it
  await page.goto(`${BASE_URL}/hsc/${encodeURIComponent(hscCode)}`, {
    waitUntil: 'networkidle',
    timeout: 30000,
  });
  await waitForDynamicContent(page);

  // Click on anything interactive
  const interactiveElements = await page.$$('button, [role="button"], [data-toggle], details summary');
  for (const el of interactiveElements.slice(0, 10)) {
    try {
      await el.click({ timeout: 1000 });
      await page.waitForTimeout(500);
    } catch {
      // Element may not be clickable
    }
  }

  return ajaxUrls;
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  console.log('=========================================');
  console.log('  Fee Navigator — Browser Exploration');
  console.log('  Detecting data missing from scraper');
  console.log('=========================================');

  let browser: Browser | null = null;

  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      viewport: { width: 1920, height: 1080 },
    });

    // Capture any new pages (popups)
    const popupPages: Page[] = [];
    context.on('page', (newPage) => {
      popupPages.push(newPage);
      console.log(`    *** NEW POPUP WINDOW DETECTED: ${newPage.url()}`);
    });

    const page = await context.newPage();

    // ---- Phase 1: Explore navigation ----
    const navLinks = await exploreNavigationPages(page);

    // ---- Phase 2: Monitor network for a sample code ----
    console.log('\n=== Monitoring network traffic for 03.03A ===\n');
    const networkRequests = await monitorNetworkRequests(page, '03.03A');
    console.log(`  Captured ${networkRequests.length} network requests:`);
    networkRequests.forEach((r) => console.log(`    ${r}`));

    // ---- Phase 3: Deep-explore sample HSC pages ----
    console.log('\n=== Deep exploration of sample HSC pages ===\n');
    const results: ExplorationResult[] = [];
    const comparisons: PageComparison[] = [];

    for (const code of SAMPLE_HSC_CODES) {
      try {
        const result = await exploreHscPage(page, code);
        results.push(result);

        const comparison = compareWithScrapedData(code, result.allTextContent);
        comparisons.push(comparison);
      } catch (err) {
        console.error(`  Error exploring ${code}: ${(err as Error).message}`);
      }
    }

    // ---- Phase 4: Check for popup pages that were opened ----
    if (popupPages.length > 0) {
      console.log(`\n=== ${popupPages.length} popup pages detected ===\n`);
      for (const popup of popupPages) {
        console.log(`  Popup URL: ${popup.url()}`);
        const popupContent = await popup.textContent('body').catch(() => '');
        console.log(`  Content preview: ${popupContent?.slice(0, 200)}`);
      }
    }

    // ---- Phase 5: Take screenshots of a detail page ----
    console.log('\n=== Taking screenshots ===\n');
    await page.goto(`${BASE_URL}/hsc/03.03A`, { waitUntil: 'networkidle', timeout: 30000 });
    await waitForDynamicContent(page);
    const screenshotPath = path.join(OUTPUT_DIR, 'exploration-screenshot-03.03A.png');
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log(`  Saved full-page screenshot: ${screenshotPath}`);

    // ---- Phase 6: Try AJAX detail endpoint vs full page ----
    console.log('\n=== Comparing AJAX detail vs full page ===\n');
    const ajaxUrl = `${BASE_URL}/hsc/03.03A?ajax=detail`;
    await page.goto(ajaxUrl, { waitUntil: 'networkidle', timeout: 15000 });
    const ajaxContent = await page.content();
    const ajaxTextLength = ajaxContent.length;

    await page.goto(`${BASE_URL}/hsc/03.03A`, { waitUntil: 'networkidle', timeout: 15000 });
    const fullContent = await page.content();
    const fullTextLength = fullContent.length;

    console.log(`  AJAX detail response: ${ajaxTextLength} chars`);
    console.log(`  Full page response: ${fullTextLength} chars`);
    console.log(`  Difference: ${fullTextLength - ajaxTextLength} chars (full page has more)`);

    // ---- Compile global findings ----
    const globalFindings: GlobalFindings = {
      hasJavaScriptPopups: popupPages.length > 0 || results.some((r) => r.popupsFound.length > 0),
      hasDynamicTabs: results.some((r) => r.tabsFound.length > 0),
      hasTooltips: results.some((r) => r.tooltipsFound.length > 0),
      hasHiddenSections: results.some((r) => r.hiddenSections.length > 0),
      hasIframes: results.some((r) => r.iframesFound.length > 0),
      uniqueDataFields: [...new Set(results.flatMap((r) => r.missingFromScraper))],
      navigationLinks: [...new Set(navLinks)],
      potentialMissingEndpoints: networkRequests.filter((r) =>
        !r.includes('?ajax=detail') && !r.includes('?ajax=expanded'),
      ),
      summary: [],
    };

    // Build summary
    const summary: string[] = [];
    if (globalFindings.hasJavaScriptPopups) {
      summary.push('FOUND: JavaScript popups/modals contain additional data');
    }
    if (globalFindings.hasDynamicTabs) {
      summary.push('FOUND: Tab-based content that requires interaction to reveal');
    }
    if (globalFindings.hasTooltips) {
      summary.push('FOUND: Tooltips contain additional field descriptions');
    }
    if (globalFindings.hasHiddenSections) {
      summary.push('FOUND: Hidden/collapsed sections with content not visible on initial load');
    }
    if (globalFindings.hasIframes) {
      summary.push('FOUND: Iframes embedding additional content');
    }
    if (globalFindings.uniqueDataFields.length > 0) {
      summary.push(`FOUND: ${globalFindings.uniqueDataFields.length} data fields visible in browser but not captured by scraper: ${globalFindings.uniqueDataFields.join(', ')}`);
    }
    if (globalFindings.potentialMissingEndpoints.length > 0) {
      summary.push(`FOUND: ${globalFindings.potentialMissingEndpoints.length} AJAX endpoints not used by current scraper`);
    }
    if (summary.length === 0) {
      summary.push('No significant additional data sources found beyond what the cheerio scraper captures');
    }
    globalFindings.summary = summary;

    // ---- Save report ----
    const report: ExplorationReport = {
      timestamp: new Date().toISOString(),
      pagesExplored: results.length,
      results,
      comparisons,
      globalFindings,
    };

    const reportPath = path.join(OUTPUT_DIR, 'exploration-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`\n  Saved exploration report: ${reportPath}`);

    // ---- Print summary ----
    console.log('\n=========================================');
    console.log('  EXPLORATION SUMMARY');
    console.log('=========================================\n');
    for (const line of summary) {
      console.log(`  ${line}`);
    }
    console.log(`\n  Pages explored: ${results.length}`);
    console.log(`  Total popups detected: ${results.reduce((n, r) => n + r.popupsFound.length, 0)}`);
    console.log(`  Total tabs detected: ${results.reduce((n, r) => n + r.tabsFound.length, 0)}`);
    console.log(`  Total tooltips detected: ${results.reduce((n, r) => n + r.tooltipsFound.length, 0)}`);
    console.log(`  Total hidden sections: ${results.reduce((n, r) => n + r.hiddenSections.length, 0)}`);
    console.log(`  Total iframes: ${results.reduce((n, r) => n + r.iframesFound.length, 0)}`);
    console.log(`  Navigation links found: ${navLinks.length}`);
    console.log(`  Network requests captured: ${networkRequests.length}`);
    console.log('=========================================');

    await browser.close();
  } catch (err) {
    console.error('Exploration failed:', err);
    if (browser) await browser.close();
    process.exit(1);
  }
}

main();
