// ============================================================================
// Fee Navigator HTML selector definitions with fallback chains.
// Each selector has a primary (current) and fallback alternatives.
// When the primary fails, fallbacks are tried in order.
// ============================================================================

import type { CheerioAPI } from 'cheerio';

interface SelectorDef {
  /** Human-readable name for logging */
  name: string;
  /** Primary CSS selector (current Fee Navigator layout) */
  primary: string;
  /** Fallback selectors, tried in order if primary matches nothing */
  fallbacks: string[];
}

export const SELECTORS = {
  // --- Discovery ---
  expandableNode: {
    name: 'expandable tree node',
    primary: 'div.node.expandable, a.node.expandable',
    fallbacks: [
      '[class*="expandable"][data-key]',
      '[data-expandable][data-key]',
      '.tree-node[data-key]:not(.viewable)',
    ],
  },
  viewableNode: {
    name: 'viewable tree node',
    primary: 'a.node.viewable',
    fallbacks: [
      '[class*="viewable"][data-key]',
      'a[data-viewable][data-key]',
      '.tree-node a[href]',
    ],
  },
  hscLink: {
    name: 'HSC code link',
    primary: 'a[href*="/fee-navigator/hsc/"]',
    fallbacks: [
      'a[href*="/hsc/"]',
      'a[data-hsc-code]',
    ],
  },

  // --- HSC Detail Page ---
  codeHeading: {
    name: 'HSC code heading',
    primary: 'h2.code',
    fallbacks: ['h2[class*="code"]', '.code-heading', 'h2:first-of-type'],
  },
  title: {
    name: 'page title',
    primary: 'h1.title',
    fallbacks: ['h1[class*="title"]', '.page-title', 'h1:first-of-type'],
  },
  noteBlock: {
    name: 'notes block',
    primary: 'div.note',
    fallbacks: ['div[class*="note"]', '.notes', '.billing-note'],
  },
  basicInfoTable: {
    name: 'basic info table',
    primary: 'table.basic-info tr',
    fallbacks: ['table[class*="basic"] tr', '.info-table tr', 'table:first-of-type tr'],
  },
  billingTips: {
    name: 'billing tips',
    primary: 'div.billing-tips',
    fallbacks: ['div[class*="billing-tip"]', '.tips', '[data-billing-tips]'],
  },
  governingRulesBlock: {
    name: 'governing rules block',
    primary: 'div.governing-rules',
    fallbacks: ['div[class*="governing"]', '.rules-section', '[data-governing-rules]'],
  },
  modifierTable: {
    name: 'modifier table',
    primary: 'div.modifiers table tr',
    fallbacks: ['div[class*="modifier"] table tr', '.modifier-table tr', 'table.modifiers tr'],
  },
  contentBlock: {
    name: 'content block',
    primary: 'div.contents',
    fallbacks: ['div[class*="content"]', '.page-content', 'main', 'article'],
  },
} as const satisfies Record<string, SelectorDef>;

/**
 * Try the primary selector first; if it matches nothing, try fallbacks in order.
 * Returns the first selector that produces matches, or the primary if none work.
 * Logs a warning when a fallback is used.
 */
export function resolveSelector(
  $: CheerioAPI,
  selectorDef: SelectorDef,
): { selector: string; usedFallback: boolean } {
  if ($(selectorDef.primary).length > 0) {
    return { selector: selectorDef.primary, usedFallback: false };
  }

  for (const fallback of selectorDef.fallbacks) {
    if ($(fallback).length > 0) {
      console.warn(
        `  [SELECTOR] ${selectorDef.name}: primary "${selectorDef.primary}" failed, using fallback "${fallback}"`,
      );
      return { selector: fallback, usedFallback: true };
    }
  }

  // No fallback worked either — return primary and let caller handle empty result
  console.warn(
    `  [SELECTOR] ${selectorDef.name}: no selectors matched (primary + ${selectorDef.fallbacks.length} fallbacks)`,
  );
  return { selector: selectorDef.primary, usedFallback: false };
}
