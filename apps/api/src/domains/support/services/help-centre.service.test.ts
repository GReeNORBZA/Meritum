import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  createHelpCentreService,
  sanitiseSearchQuery,
  _resetRateLimiter,
  type AuditRepo,
  type ContextMetadata,
} from './help-centre.service.js';
import { SupportAuditAction, HelpCategory } from '@meritum/shared/constants/support.constants.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Mock article data
// ---------------------------------------------------------------------------

function makeArticle(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    articleId: overrides.articleId ?? crypto.randomUUID(),
    slug: overrides.slug ?? 'test-article',
    title: overrides.title ?? 'Test Article',
    category: overrides.category ?? HelpCategory.AHCIP_BILLING,
    content: overrides.content ?? 'Some article content.',
    summary: overrides.summary ?? 'A summary.',
    searchVector: null,
    relatedCodes: overrides.relatedCodes ?? null,
    sombVersion: overrides.sombVersion ?? null,
    isPublished: overrides.isPublished ?? true,
    helpfulCount: overrides.helpfulCount ?? 0,
    notHelpfulCount: overrides.notHelpfulCount ?? 0,
    sortOrder: overrides.sortOrder ?? 0,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

function makeSearchResult(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    articleId: overrides.articleId ?? crypto.randomUUID(),
    slug: overrides.slug ?? 'search-result',
    title: overrides.title ?? 'Search Result',
    category: overrides.category ?? HelpCategory.AHCIP_BILLING,
    summary: overrides.summary ?? 'A summary.',
    rank: overrides.rank ?? 0.5,
  };
}

function makeListItem(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    articleId: overrides.articleId ?? crypto.randomUUID(),
    slug: overrides.slug ?? 'list-item',
    title: overrides.title ?? 'List Item',
    summary: overrides.summary ?? 'A summary.',
  };
}

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockArticlesRepo() {
  return {
    search: vi.fn(async () => [] as any[]),
    getBySlug: vi.fn(async () => null as any),
    listByCategory: vi.fn(async () => [] as any[]),
    findByRelatedCode: vi.fn(async () => [] as any[]),
    incrementFeedback: vi.fn(async () => {}),
    createFeedback: vi.fn(async () => {}),
    create: vi.fn(async () => ({} as any)),
    update: vi.fn(async () => null as any),
    publish: vi.fn(async () => null as any),
    unpublish: vi.fn(async () => null as any),
  };
}

function createMockAuditRepo(): AuditRepo & { appendAuditLog: ReturnType<typeof vi.fn> } {
  return {
    appendAuditLog: vi.fn(async (entry) => entry),
  };
}

// ---------------------------------------------------------------------------
// sanitiseSearchQuery
// ---------------------------------------------------------------------------

describe('sanitiseSearchQuery', () => {
  it('strips tsquery special characters', () => {
    expect(sanitiseSearchQuery("test & query | <script>")).toBe('test query script');
  });

  it('strips all tsquery operators: & | ! ( ) : * < >', () => {
    expect(sanitiseSearchQuery('a&b|c!d(e)f:g*h<i>j')).toBe('a b c d e f g h i j');
  });

  it('trims whitespace', () => {
    expect(sanitiseSearchQuery('  hello world  ')).toBe('hello world');
  });

  it('collapses multiple spaces', () => {
    expect(sanitiseSearchQuery('a    b   c')).toBe('a b c');
  });

  it('limits to 200 characters', () => {
    const long = 'a'.repeat(300);
    expect(sanitiseSearchQuery(long).length).toBe(200);
  });

  it('returns empty string for only special chars', () => {
    expect(sanitiseSearchQuery('&|!():*<>')).toBe('');
  });

  it('handles empty string', () => {
    expect(sanitiseSearchQuery('')).toBe('');
  });

  it('preserves normal search terms', () => {
    expect(sanitiseSearchQuery('common rejection codes')).toBe('common rejection codes');
  });
});

// ---------------------------------------------------------------------------
// searchArticles
// ---------------------------------------------------------------------------

describe('searchArticles', () => {
  let articlesRepo: ReturnType<typeof createMockArticlesRepo>;
  let auditRepo: ReturnType<typeof createMockAuditRepo>;
  let service: ReturnType<typeof createHelpCentreService>;
  let nowMs: number;

  beforeEach(() => {
    _resetRateLimiter();
    articlesRepo = createMockArticlesRepo();
    auditRepo = createMockAuditRepo();
    nowMs = Date.now();
    service = createHelpCentreService({
      articlesRepo: articlesRepo as any,
      auditRepo,
      now: () => nowMs,
    });
  });

  it('returns ranked results from the repo', async () => {
    const results = [
      makeSearchResult({ rank: 0.9, title: 'Best Match' }),
      makeSearchResult({ rank: 0.3, title: 'Partial Match' }),
    ];
    articlesRepo.search.mockResolvedValueOnce(results);

    const out = await service.searchArticles(PROVIDER_A, 'rejection codes', 10, 0);
    expect(out).toEqual(results);
    expect(articlesRepo.search).toHaveBeenCalledWith('rejection codes', 10, 0);
  });

  it('returns empty for empty query after sanitisation', async () => {
    const out = await service.searchArticles(PROVIDER_A, '&|!():*<>');
    expect(out).toEqual([]);
    expect(articlesRepo.search).not.toHaveBeenCalled();
  });

  it('sanitises the query before passing to repo', async () => {
    articlesRepo.search.mockResolvedValueOnce([]);
    await service.searchArticles(PROVIDER_A, 'test & <script>alert(1)</script>');
    expect(articlesRepo.search).toHaveBeenCalledWith('test script alert 1 /script', 20, 0);
  });

  it('uses default limit and offset', async () => {
    articlesRepo.search.mockResolvedValueOnce([]);
    await service.searchArticles(PROVIDER_A, 'billing');
    expect(articlesRepo.search).toHaveBeenCalledWith('billing', 20, 0);
  });

  it('creates audit log for search', async () => {
    articlesRepo.search.mockResolvedValueOnce([]);
    await service.searchArticles(PROVIDER_A, 'billing');

    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: PROVIDER_A,
        action: SupportAuditAction.HELP_SEARCHED,
        category: 'support',
        resourceType: 'help_article',
        detail: { query: 'billing', resultCount: 0 },
      }),
    );
  });

  it('rate-limits audit log (no duplicate within 1 minute)', async () => {
    articlesRepo.search.mockResolvedValue([]);

    await service.searchArticles(PROVIDER_A, 'first');
    await service.searchArticles(PROVIDER_A, 'second');

    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
  });

  it('allows audit log after rate-limit window expires', async () => {
    articlesRepo.search.mockResolvedValue([]);

    await service.searchArticles(PROVIDER_A, 'first');
    // Advance time past 1-minute window
    nowMs += 61_000;
    await service.searchArticles(PROVIDER_A, 'second');

    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(2);
  });

  it('rate-limits per provider independently', async () => {
    articlesRepo.search.mockResolvedValue([]);

    await service.searchArticles(PROVIDER_A, 'query');
    await service.searchArticles(PROVIDER_B, 'query');

    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(2);
  });
});

// ---------------------------------------------------------------------------
// getArticle
// ---------------------------------------------------------------------------

describe('getArticle', () => {
  let articlesRepo: ReturnType<typeof createMockArticlesRepo>;
  let auditRepo: ReturnType<typeof createMockAuditRepo>;
  let service: ReturnType<typeof createHelpCentreService>;
  let nowMs: number;

  beforeEach(() => {
    _resetRateLimiter();
    articlesRepo = createMockArticlesRepo();
    auditRepo = createMockAuditRepo();
    nowMs = Date.now();
    service = createHelpCentreService({
      articlesRepo: articlesRepo as any,
      auditRepo,
      now: () => nowMs,
    });
  });

  it('returns article by slug', async () => {
    const article = makeArticle({ slug: 'how-to-bill' });
    articlesRepo.getBySlug.mockResolvedValueOnce(article);

    const out = await service.getArticle(PROVIDER_A, 'how-to-bill');
    expect(out).toEqual(article);
    expect(articlesRepo.getBySlug).toHaveBeenCalledWith('how-to-bill');
  });

  it('returns null for non-existent article', async () => {
    articlesRepo.getBySlug.mockResolvedValueOnce(null);
    const out = await service.getArticle(PROVIDER_A, 'does-not-exist');
    expect(out).toBeNull();
  });

  it('does not audit view when article is not found', async () => {
    articlesRepo.getBySlug.mockResolvedValueOnce(null);
    await service.getArticle(PROVIDER_A, 'missing');
    expect(auditRepo.appendAuditLog).not.toHaveBeenCalled();
  });

  it('audits article view', async () => {
    const article = makeArticle({ slug: 'billing-guide', articleId: 'art-123' });
    articlesRepo.getBySlug.mockResolvedValueOnce(article);

    await service.getArticle(PROVIDER_A, 'billing-guide');

    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: PROVIDER_A,
        action: SupportAuditAction.ARTICLE_VIEWED,
        category: 'support',
        resourceType: 'help_article',
        resourceId: 'art-123',
        detail: { slug: 'billing-guide' },
      }),
    );
  });

  it('rate-limits article view audit (1 per minute per provider)', async () => {
    const article = makeArticle();
    articlesRepo.getBySlug.mockResolvedValue(article);

    await service.getArticle(PROVIDER_A, 'a');
    await service.getArticle(PROVIDER_A, 'b');

    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// listByCategory
// ---------------------------------------------------------------------------

describe('listByCategory', () => {
  let articlesRepo: ReturnType<typeof createMockArticlesRepo>;
  let auditRepo: ReturnType<typeof createMockAuditRepo>;
  let service: ReturnType<typeof createHelpCentreService>;

  beforeEach(() => {
    _resetRateLimiter();
    articlesRepo = createMockArticlesRepo();
    auditRepo = createMockAuditRepo();
    service = createHelpCentreService({
      articlesRepo: articlesRepo as any,
      auditRepo,
    });
  });

  it('delegates to repo with correct params', async () => {
    const items = [makeListItem(), makeListItem()];
    articlesRepo.listByCategory.mockResolvedValueOnce(items);

    const out = await service.listByCategory(HelpCategory.AHCIP_BILLING, 10, 5);
    expect(out).toEqual(items);
    expect(articlesRepo.listByCategory).toHaveBeenCalledWith(HelpCategory.AHCIP_BILLING, 10, 5);
  });

  it('uses default limit and offset', async () => {
    articlesRepo.listByCategory.mockResolvedValueOnce([]);
    await service.listByCategory(HelpCategory.WCB_BILLING);
    expect(articlesRepo.listByCategory).toHaveBeenCalledWith(HelpCategory.WCB_BILLING, 20, 0);
  });
});

// ---------------------------------------------------------------------------
// getContextualHelp
// ---------------------------------------------------------------------------

describe('getContextualHelp', () => {
  let articlesRepo: ReturnType<typeof createMockArticlesRepo>;
  let auditRepo: ReturnType<typeof createMockAuditRepo>;
  let service: ReturnType<typeof createHelpCentreService>;

  beforeEach(() => {
    _resetRateLimiter();
    articlesRepo = createMockArticlesRepo();
    auditRepo = createMockAuditRepo();
    service = createHelpCentreService({
      articlesRepo: articlesRepo as any,
      auditRepo,
    });
  });

  it('resolves /claims/new to AHCIP_BILLING category', async () => {
    const items = [makeListItem({ title: 'AHCIP Guide' })];
    articlesRepo.listByCategory.mockResolvedValueOnce(items);

    const result = await service.getContextualHelp('/claims/new');
    expect(result.type).toBe('category');
    expect(result.category).toBe(HelpCategory.AHCIP_BILLING);
    expect(result.articles).toEqual(items);
    expect(articlesRepo.listByCategory).toHaveBeenCalledWith(HelpCategory.AHCIP_BILLING);
  });

  it('resolves /claims/123/edit to AHCIP_BILLING category', async () => {
    articlesRepo.listByCategory.mockResolvedValueOnce([]);
    const result = await service.getContextualHelp('/claims/abc-def/edit');
    expect(result.type).toBe('category');
    expect(result.category).toBe(HelpCategory.AHCIP_BILLING);
  });

  it('resolves /wcb/forms to WCB_BILLING category', async () => {
    articlesRepo.listByCategory.mockResolvedValueOnce([]);
    const result = await service.getContextualHelp('/wcb/forms');
    expect(result.type).toBe('category');
    expect(result.category).toBe(HelpCategory.WCB_BILLING);
  });

  it('resolves /settings/profile to ACCOUNT_AND_BILLING category', async () => {
    articlesRepo.listByCategory.mockResolvedValueOnce([]);
    const result = await service.getContextualHelp('/settings/profile');
    expect(result.type).toBe('category');
    expect(result.category).toBe(HelpCategory.ACCOUNT_AND_BILLING);
  });

  it('resolves /analytics/dashboard to GETTING_STARTED category', async () => {
    articlesRepo.listByCategory.mockResolvedValueOnce([]);
    const result = await service.getContextualHelp('/analytics/dashboard');
    expect(result.type).toBe('category');
    expect(result.category).toBe(HelpCategory.GETTING_STARTED);
  });

  it('resolves /onboarding/step-1 to GETTING_STARTED category', async () => {
    articlesRepo.listByCategory.mockResolvedValueOnce([]);
    const result = await service.getContextualHelp('/onboarding/step-1');
    expect(result.type).toBe('category');
    expect(result.category).toBe(HelpCategory.GETTING_STARTED);
  });

  it('handles full URLs (not just paths)', async () => {
    articlesRepo.listByCategory.mockResolvedValueOnce([]);
    const result = await service.getContextualHelp('https://meritum.ca/wcb/claim-123');
    expect(result.type).toBe('category');
    expect(result.category).toBe(HelpCategory.WCB_BILLING);
  });

  it('resolves rejection code from contextMetadata when URL has null category', async () => {
    const items = [makeListItem({ title: 'Rejection Code E123' })];
    articlesRepo.findByRelatedCode.mockResolvedValueOnce(items);

    const result = await service.getContextualHelp(
      '/claims/some-id/rejected',
      { rejection_code: 'E123' },
    );
    expect(result.type).toBe('related_codes');
    expect(result.articles).toEqual(items);
    expect(articlesRepo.findByRelatedCode).toHaveBeenCalledWith('E123');
  });

  it('resolves explanatory_code from contextMetadata', async () => {
    const items = [makeListItem({ title: 'Explanatory Code X456' })];
    articlesRepo.findByRelatedCode.mockResolvedValueOnce(items);

    const result = await service.getContextualHelp(
      '/claims/some-id/rejected',
      { explanatory_code: 'X456' },
    );
    expect(result.type).toBe('related_codes');
    expect(result.articles).toEqual(items);
    expect(articlesRepo.findByRelatedCode).toHaveBeenCalledWith('X456');
  });

  it('uses first error_code from error_codes array', async () => {
    const items = [makeListItem()];
    articlesRepo.findByRelatedCode.mockResolvedValueOnce(items);

    const result = await service.getContextualHelp(
      '/claims/some-id/rejected',
      { error_codes: ['ERR01', 'ERR02'] },
    );
    expect(result.type).toBe('related_codes');
    expect(articlesRepo.findByRelatedCode).toHaveBeenCalledWith('ERR01');
  });

  it('falls back to search_page when no articles for rejection code', async () => {
    articlesRepo.findByRelatedCode.mockResolvedValueOnce([]);

    const result = await service.getContextualHelp(
      '/claims/some-id/rejected',
      { rejection_code: 'UNKNOWN' },
    );
    expect(result.type).toBe('search_page');
    expect(result.searchPageUrl).toBe('/help/search');
  });

  it('returns search_page for unrecognised URLs', async () => {
    const result = await service.getContextualHelp('/some/unknown/page');
    expect(result.type).toBe('search_page');
    expect(result.searchPageUrl).toBe('/help/search');
  });

  it('returns search_page when no contextMetadata provided for null-category mapping', async () => {
    const result = await service.getContextualHelp('/claims/some-id/rejected');
    expect(result.type).toBe('search_page');
    expect(result.searchPageUrl).toBe('/help/search');
  });

  it('returns search_page when contextMetadata has no codes', async () => {
    const result = await service.getContextualHelp(
      '/claims/some-id/rejected',
      { some_other_key: 'value' } as ContextMetadata,
    );
    expect(result.type).toBe('search_page');
  });
});

// ---------------------------------------------------------------------------
// submitFeedback
// ---------------------------------------------------------------------------

describe('submitFeedback', () => {
  let articlesRepo: ReturnType<typeof createMockArticlesRepo>;
  let auditRepo: ReturnType<typeof createMockAuditRepo>;
  let service: ReturnType<typeof createHelpCentreService>;

  beforeEach(() => {
    _resetRateLimiter();
    articlesRepo = createMockArticlesRepo();
    auditRepo = createMockAuditRepo();
    service = createHelpCentreService({
      articlesRepo: articlesRepo as any,
      auditRepo,
    });
  });

  it('records helpful feedback and increments counter', async () => {
    const article = makeArticle({ slug: 'billing-guide', articleId: 'art-99' });
    articlesRepo.getBySlug.mockResolvedValueOnce(article);

    const result = await service.submitFeedback('billing-guide', PROVIDER_A, true);

    expect(result).toEqual({ success: true });
    expect(articlesRepo.createFeedback).toHaveBeenCalledWith('art-99', PROVIDER_A, true);
    expect(articlesRepo.incrementFeedback).toHaveBeenCalledWith('art-99', true);
  });

  it('records not-helpful feedback and increments counter', async () => {
    const article = makeArticle({ slug: 'confusing-article', articleId: 'art-77' });
    articlesRepo.getBySlug.mockResolvedValueOnce(article);

    const result = await service.submitFeedback('confusing-article', PROVIDER_A, false);

    expect(result).toEqual({ success: true });
    expect(articlesRepo.createFeedback).toHaveBeenCalledWith('art-77', PROVIDER_A, false);
    expect(articlesRepo.incrementFeedback).toHaveBeenCalledWith('art-77', false);
  });

  it('returns { success: false } for non-existent article', async () => {
    articlesRepo.getBySlug.mockResolvedValueOnce(null);

    const result = await service.submitFeedback('no-such-article', PROVIDER_A, true);

    expect(result).toEqual({ success: false });
    expect(articlesRepo.createFeedback).not.toHaveBeenCalled();
    expect(articlesRepo.incrementFeedback).not.toHaveBeenCalled();
  });

  it('creates audit log entry for feedback', async () => {
    const article = makeArticle({ slug: 'feedback-test', articleId: 'art-55' });
    articlesRepo.getBySlug.mockResolvedValueOnce(article);

    await service.submitFeedback('feedback-test', PROVIDER_A, true);

    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: PROVIDER_A,
        action: SupportAuditAction.ARTICLE_FEEDBACK,
        category: 'support',
        resourceType: 'help_article',
        resourceId: 'art-55',
        detail: { slug: 'feedback-test', isHelpful: true },
      }),
    );
  });

  it('does not audit when article not found', async () => {
    articlesRepo.getBySlug.mockResolvedValueOnce(null);

    await service.submitFeedback('missing-slug', PROVIDER_A, false);

    expect(auditRepo.appendAuditLog).not.toHaveBeenCalled();
  });
});
