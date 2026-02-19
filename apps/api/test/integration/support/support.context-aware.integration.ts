// ============================================================================
// Domain 13: Context-Aware Help — Integration Tests
// Tests help button from different pages routes to correct category/articles.
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import { HelpCategory } from '@meritum/shared/constants/support.constants.js';

// ---------------------------------------------------------------------------
// Seed article data by category
// ---------------------------------------------------------------------------

const AHCIP_ARTICLE = {
  articleId: '00000000-aaaa-0000-0000-000000000010',
  slug: 'ahcip-claim-creation',
  title: 'Creating an AHCIP Claim',
  category: HelpCategory.AHCIP_BILLING,
  content: 'Step-by-step guide to creating an AHCIP claim.',
  summary: 'How to create an AHCIP claim.',
  searchVector: '',
  relatedCodes: null,
  sombVersion: null,
  isPublished: true,
  helpfulCount: 0,
  notHelpfulCount: 0,
  sortOrder: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const ACCOUNT_ARTICLE = {
  articleId: '00000000-aaaa-0000-0000-000000000020',
  slug: 'account-settings-guide',
  title: 'Managing Your Account Settings',
  category: HelpCategory.ACCOUNT_AND_BILLING,
  content: 'How to update your profile, billing info, and preferences.',
  summary: 'Account and billing settings guide.',
  searchVector: '',
  relatedCodes: null,
  sombVersion: null,
  isPublished: true,
  helpfulCount: 0,
  notHelpfulCount: 0,
  sortOrder: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const EXPLANATORY_CODE_ARTICLE = {
  articleId: '00000000-aaaa-0000-0000-000000000030',
  slug: 'explanatory-code-55',
  title: 'Explanatory Code 55 — Duplicate Claim',
  category: HelpCategory.AHCIP_BILLING,
  content: 'Explanatory code 55 means the claim is a duplicate.',
  summary: 'What to do when you receive code 55.',
  searchVector: '',
  relatedCodes: ['55'],
  sombVersion: null,
  isPublished: true,
  helpfulCount: 0,
  notHelpfulCount: 0,
  sortOrder: 2,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const ALL_ARTICLES = [AHCIP_ARTICLE, ACCOUNT_ARTICLE, EXPLANATORY_CODE_ARTICLE];

// ---------------------------------------------------------------------------
// Mock articles repository
// ---------------------------------------------------------------------------

function createMockArticlesRepo() {
  return {
    search: vi.fn(async () => []),

    getBySlug: vi.fn(async (slug: string) => {
      return ALL_ARTICLES.find((a) => a.slug === slug && a.isPublished) ?? null;
    }),

    listByCategory: vi.fn(async (category: string, limit = 20) => {
      return ALL_ARTICLES
        .filter((a) => a.category === category && a.isPublished)
        .slice(0, limit)
        .map((a) => ({
          articleId: a.articleId,
          slug: a.slug,
          title: a.title,
          summary: a.summary,
        }));
    }),

    findByRelatedCode: vi.fn(async (code: string) => {
      return ALL_ARTICLES
        .filter((a) => a.isPublished && a.relatedCodes && (a.relatedCodes as string[]).includes(code))
        .map((a) => ({
          articleId: a.articleId,
          slug: a.slug,
          title: a.title,
          summary: a.summary,
        }));
    }),

    incrementFeedback: vi.fn(async () => {}),
    createFeedback: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock audit repo
// ---------------------------------------------------------------------------

function createMockAuditRepo() {
  return { appendAuditLog: vi.fn(async () => {}) };
}

// ============================================================================
// Tests — uses service directly (getContextualHelp is not exposed via routes)
// ============================================================================

describe('Context-Aware Help Integration Tests', () => {
  let helpCentreService: any;
  let mockArticlesRepo: ReturnType<typeof createMockArticlesRepo>;

  beforeAll(async () => {
    const { createHelpCentreService, _resetRateLimiter } = await import(
      '../../../src/domains/support/services/help-centre.service.js'
    );

    _resetRateLimiter();

    mockArticlesRepo = createMockArticlesRepo();
    helpCentreService = createHelpCentreService({
      articlesRepo: mockArticlesRepo as any,
      auditRepo: createMockAuditRepo(),
    });
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // =========================================================================
  // Context URL → Category Mapping
  // =========================================================================

  describe('Context URL to category mapping', () => {
    it('help button from claim page (/claims/new) returns AHCIP_BILLING articles', async () => {
      const result = await helpCentreService.getContextualHelp('/claims/new');

      expect(result.type).toBe('category');
      expect(result.category).toBe(HelpCategory.AHCIP_BILLING);
      expect(result.articles).toBeDefined();
      expect(result.articles.length).toBeGreaterThan(0);

      // Verify the repo was called with AHCIP_BILLING category
      expect(mockArticlesRepo.listByCategory).toHaveBeenCalledWith(
        HelpCategory.AHCIP_BILLING,
      );
    });

    it('help from claim edit page (/claims/abc-123/edit) returns AHCIP_BILLING', async () => {
      const result = await helpCentreService.getContextualHelp('/claims/abc-123/edit');

      expect(result.type).toBe('category');
      expect(result.category).toBe(HelpCategory.AHCIP_BILLING);
    });

    it('help from settings page (/settings/profile) returns ACCOUNT_AND_BILLING articles', async () => {
      const result = await helpCentreService.getContextualHelp('/settings/profile');

      expect(result.type).toBe('category');
      expect(result.category).toBe(HelpCategory.ACCOUNT_AND_BILLING);
      expect(result.articles).toBeDefined();
      expect(result.articles.length).toBeGreaterThan(0);
    });

    it('help from settings billing (/settings/billing) returns ACCOUNT_AND_BILLING', async () => {
      const result = await helpCentreService.getContextualHelp('/settings/billing');

      expect(result.type).toBe('category');
      expect(result.category).toBe(HelpCategory.ACCOUNT_AND_BILLING);
    });

    it('help from full URL (https://meritum.ca/settings/profile) extracts path', async () => {
      const result = await helpCentreService.getContextualHelp(
        'https://meritum.ca/settings/profile',
      );

      expect(result.type).toBe('category');
      expect(result.category).toBe(HelpCategory.ACCOUNT_AND_BILLING);
    });
  });

  // =========================================================================
  // Rejection Code → Related Articles
  // =========================================================================

  describe('Rejection code context', () => {
    it('rejected claim with explanatory code finds article for that code', async () => {
      const result = await helpCentreService.getContextualHelp(
        '/claims/abc-123/rejected',
        { explanatory_code: '55' },
      );

      expect(result.type).toBe('related_codes');
      expect(result.articles).toBeDefined();
      expect(result.articles.length).toBeGreaterThan(0);
      expect(result.articles[0].slug).toBe('explanatory-code-55');

      expect(mockArticlesRepo.findByRelatedCode).toHaveBeenCalledWith('55');
    });

    it('rejected claim with rejection_code finds article', async () => {
      const result = await helpCentreService.getContextualHelp(
        '/claims/abc-123/rejected',
        { rejection_code: '55' },
      );

      expect(result.type).toBe('related_codes');
      expect(result.articles.length).toBeGreaterThan(0);
    });

    it('rejected claim with error_codes array finds article for first code', async () => {
      const result = await helpCentreService.getContextualHelp(
        '/claims/abc-123/rejected',
        { error_codes: ['55', '101'] },
      );

      expect(result.type).toBe('related_codes');
      expect(mockArticlesRepo.findByRelatedCode).toHaveBeenCalledWith('55');
    });
  });

  // =========================================================================
  // No Match → Search Page Fallback
  // =========================================================================

  describe('No context match', () => {
    it('help with no context returns search page fallback', async () => {
      const result = await helpCentreService.getContextualHelp('/unknown/page');

      expect(result.type).toBe('search_page');
      expect(result.searchPageUrl).toBe('/help/search');
      expect(result.articles).toBeUndefined();
    });

    it('unmatched URL with no metadata returns search page', async () => {
      const result = await helpCentreService.getContextualHelp(
        '/some/random/page',
        null,
      );

      expect(result.type).toBe('search_page');
      expect(result.searchPageUrl).toBe('/help/search');
    });

    it('rejected claim with unknown code and no matching article returns search page', async () => {
      // findByRelatedCode returns empty for unknown code
      mockArticlesRepo.findByRelatedCode.mockResolvedValueOnce([]);

      const result = await helpCentreService.getContextualHelp(
        '/claims/abc-123/rejected',
        { explanatory_code: '999' },
      );

      expect(result.type).toBe('search_page');
    });
  });

  // =========================================================================
  // WCB and other category mappings
  // =========================================================================

  describe('Other category mappings', () => {
    it('WCB page (/wcb/new-claim) maps to WCB_BILLING', async () => {
      const result = await helpCentreService.getContextualHelp('/wcb/new-claim');

      expect(result.type).toBe('category');
      expect(result.category).toBe(HelpCategory.WCB_BILLING);
    });

    it('analytics page (/analytics/revenue) maps to GETTING_STARTED', async () => {
      const result = await helpCentreService.getContextualHelp('/analytics/revenue');

      expect(result.type).toBe('category');
      expect(result.category).toBe(HelpCategory.GETTING_STARTED);
    });

    it('onboarding page (/onboarding/step-1) maps to GETTING_STARTED', async () => {
      const result = await helpCentreService.getContextualHelp('/onboarding/step-1');

      expect(result.type).toBe('category');
      expect(result.category).toBe(HelpCategory.GETTING_STARTED);
    });
  });
});
