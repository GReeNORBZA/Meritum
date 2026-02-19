// ============================================================================
// Domain 13: Help Centre Service
// Search, context-aware routing, feedback.
// ============================================================================

import {
  CONTEXT_HELP_MAPPINGS,
  SupportAuditAction,
  type HelpCategory,
} from '@meritum/shared/constants/support.constants.js';
import type {
  HelpArticlesRepository,
  ArticleSearchResult,
  ArticleListItem,
} from '../repos/help-articles.repo.js';
import type { SelectHelpArticle } from '@meritum/shared/schemas/db/support.schema.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditRepo {
  appendAuditLog(entry: {
    userId?: string | null;
    action: string;
    category: string;
    resourceType?: string | null;
    resourceId?: string | null;
    detail?: Record<string, unknown> | null;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<unknown>;
}

export interface ContextMetadata {
  rejection_code?: string;
  explanatory_code?: string;
  error_codes?: string[];
  [key: string]: unknown;
}

export interface ContextualHelpResult {
  type: 'category' | 'related_codes' | 'search_page';
  category?: HelpCategory;
  articles?: ArticleListItem[];
  searchPageUrl?: string;
}

interface HelpCentreDeps {
  articlesRepo: HelpArticlesRepository;
  auditRepo: AuditRepo;
  now?: () => number; // injectable for rate-limit testing
}

// ---------------------------------------------------------------------------
// Search Query Sanitisation
// ---------------------------------------------------------------------------

const TSQUERY_SPECIAL_CHARS = /[&|!():<>*]/g;
const MAX_QUERY_LENGTH = 200;

/**
 * Sanitise a search query for use with websearch_to_tsquery.
 * - Strip tsquery special characters: & | ! ( ) : * < >
 * - Trim whitespace
 * - Limit to 200 characters
 */
export function sanitiseSearchQuery(raw: string): string {
  return raw
    .replace(TSQUERY_SPECIAL_CHARS, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_QUERY_LENGTH);
}

// ---------------------------------------------------------------------------
// In-Memory Rate Limiter (per-provider, per-action)
// ---------------------------------------------------------------------------

const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute

interface RateLimitEntry {
  lastTimestamp: number;
}

const rateLimitMap = new Map<string, RateLimitEntry>();

function shouldAudit(
  providerId: string,
  action: string,
  nowMs: number,
): boolean {
  const key = `${providerId}:${action}`;
  const entry = rateLimitMap.get(key);
  if (entry && nowMs - entry.lastTimestamp < RATE_LIMIT_WINDOW_MS) {
    return false;
  }
  rateLimitMap.set(key, { lastTimestamp: nowMs });
  return true;
}

// Exported for testing only — clears rate limit state between tests.
export function _resetRateLimiter(): void {
  rateLimitMap.clear();
}

// ---------------------------------------------------------------------------
// Context-Aware Help Pattern Matching
// ---------------------------------------------------------------------------

/**
 * Convert a CONTEXT_HELP_MAPPINGS pattern (e.g. "/claims/* /edit") to a regex.
 * Supports `*` wildcard matching one or more path segments.
 */
function patternToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, (ch) =>
    ch === '*' ? '[^?#]+' : `\\${ch}`,
  );
  return new RegExp(`^${escaped}(\\?.*)?$`);
}

function matchContextUrl(
  contextUrl: string,
): (typeof CONTEXT_HELP_MAPPINGS)[number] | null {
  // Extract pathname from URL (handles full URLs and path-only strings)
  let pathname: string;
  try {
    pathname = new URL(contextUrl, 'https://meritum.ca').pathname;
  } catch {
    pathname = contextUrl;
  }

  for (const mapping of CONTEXT_HELP_MAPPINGS) {
    const re = patternToRegex(mapping.pattern);
    if (re.test(pathname)) {
      return mapping;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Service Factory
// ---------------------------------------------------------------------------

export function createHelpCentreService(deps: HelpCentreDeps) {
  const { articlesRepo, auditRepo } = deps;
  const getNow = deps.now ?? (() => Date.now());

  return {
    /**
     * Search articles via full-text search.
     * Sanitises the query to prevent tsquery injection.
     * Rate-limited audit log: max 1 per minute per provider.
     */
    async searchArticles(
      providerId: string,
      query: string,
      limit = 20,
      offset = 0,
    ): Promise<ArticleSearchResult[]> {
      const sanitised = sanitiseSearchQuery(query);
      if (!sanitised) return [];

      const results = await articlesRepo.search(sanitised, limit, offset);

      // Rate-limited audit
      if (shouldAudit(providerId, SupportAuditAction.HELP_SEARCHED, getNow())) {
        await auditRepo.appendAuditLog({
          userId: providerId,
          action: SupportAuditAction.HELP_SEARCHED,
          category: 'support',
          resourceType: 'help_article',
          detail: { query: sanitised, resultCount: results.length },
        });
      }

      return results;
    },

    /**
     * Fetch a single article by slug.
     * Rate-limited audit log: max 1 per minute per provider.
     */
    async getArticle(
      providerId: string,
      slug: string,
    ): Promise<SelectHelpArticle | null> {
      const article = await articlesRepo.getBySlug(slug);
      if (!article) return null;

      // Rate-limited audit
      if (shouldAudit(providerId, SupportAuditAction.ARTICLE_VIEWED, getNow())) {
        await auditRepo.appendAuditLog({
          userId: providerId,
          action: SupportAuditAction.ARTICLE_VIEWED,
          category: 'support',
          resourceType: 'help_article',
          resourceId: article.articleId,
          detail: { slug },
        });
      }

      return article;
    },

    /**
     * List published articles in a category.
     */
    async listByCategory(
      category: string,
      limit = 20,
      offset = 0,
    ): Promise<ArticleListItem[]> {
      return articlesRepo.listByCategory(category, limit, offset);
    },

    /**
     * Resolve a page URL + optional metadata to contextual help content.
     *
     * 1. Match contextUrl against CONTEXT_HELP_MAPPINGS.
     * 2. If matched to a category -> return articles in that category.
     * 3. If contextMetadata contains a rejection/explanatory code ->
     *    search by related_codes.
     * 4. If no match -> return search page URL.
     */
    async getContextualHelp(
      contextUrl: string,
      contextMetadata?: ContextMetadata | null,
    ): Promise<ContextualHelpResult> {
      const mapping = matchContextUrl(contextUrl);

      // Step 1 & 2: matched to a category
      if (mapping && mapping.category !== null) {
        const articles = await articlesRepo.listByCategory(mapping.category);
        return {
          type: 'category',
          category: mapping.category,
          articles,
        };
      }

      // Step 3: rejection/explanatory code from context metadata
      if (contextMetadata) {
        const code =
          contextMetadata.rejection_code ??
          contextMetadata.explanatory_code ??
          (contextMetadata.error_codes?.length
            ? contextMetadata.error_codes[0]
            : undefined);

        if (code) {
          const articles = await articlesRepo.findByRelatedCode(code);
          if (articles.length > 0) {
            return {
              type: 'related_codes',
              articles,
            };
          }
        }
      }

      // Step 4: no match — return search page
      return {
        type: 'search_page',
        searchPageUrl: '/help/search',
      };
    },

    /**
     * Submit article feedback (helpful / not helpful).
     * Creates/updates feedback record, increments article counters.
     * Audit log: support.article_feedback.
     */
    async submitFeedback(
      articleSlug: string,
      providerId: string,
      isHelpful: boolean,
    ): Promise<{ success: boolean }> {
      const article = await articlesRepo.getBySlug(articleSlug);
      if (!article) return { success: false };

      // Upsert feedback record
      await articlesRepo.createFeedback(article.articleId, providerId, isHelpful);

      // Increment article-level counter
      await articlesRepo.incrementFeedback(article.articleId, isHelpful);

      // Audit log (not rate-limited — feedback is infrequent)
      await auditRepo.appendAuditLog({
        userId: providerId,
        action: SupportAuditAction.ARTICLE_FEEDBACK,
        category: 'support',
        resourceType: 'help_article',
        resourceId: article.articleId,
        detail: { slug: articleSlug, isHelpful },
      });

      return { success: true };
    },
  };
}

export type HelpCentreService = ReturnType<typeof createHelpCentreService>;
