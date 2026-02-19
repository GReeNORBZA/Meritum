import { eq, and, sql, asc } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  helpArticles,
  articleFeedback,
  type InsertHelpArticle,
  type SelectHelpArticle,
} from '@meritum/shared/schemas/db/support.schema.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ArticleSearchResult {
  articleId: string;
  slug: string;
  title: string;
  category: string;
  summary: string | null;
  rank: number;
}

export interface ArticleListItem {
  articleId: string;
  slug: string;
  title: string;
  summary: string | null;
}

// ---------------------------------------------------------------------------
// Help Articles Repository
// ---------------------------------------------------------------------------

export function createHelpArticlesRepository(db: NodePgDatabase) {
  return {
    /**
     * Full-text search against search_vector.
     * Uses to_tsquery('english', query) and ts_rank for ranking.
     * Only returns published articles.
     */
    async search(
      query: string,
      limit = 20,
      offset = 0,
    ): Promise<ArticleSearchResult[]> {
      const tsQuery = sql`to_tsquery('english', ${query})`;
      const rank = sql<number>`ts_rank(${helpArticles.searchVector}, ${tsQuery})`;

      const rows = await db
        .select({
          articleId: helpArticles.articleId,
          slug: helpArticles.slug,
          title: helpArticles.title,
          category: helpArticles.category,
          summary: helpArticles.summary,
          rank,
        })
        .from(helpArticles)
        .where(
          and(
            eq(helpArticles.isPublished, true),
            sql`${helpArticles.searchVector} @@ ${tsQuery}`,
          ),
        )
        .orderBy(sql`${rank} DESC`)
        .limit(limit)
        .offset(offset);

      return rows;
    },

    /**
     * Fetch full article by slug. Only published articles.
     * Returns null if not found or unpublished.
     */
    async getBySlug(slug: string): Promise<SelectHelpArticle | null> {
      const rows = await db
        .select()
        .from(helpArticles)
        .where(
          and(
            eq(helpArticles.slug, slug),
            eq(helpArticles.isPublished, true),
          ),
        )
        .limit(1);

      return rows[0] ?? null;
    },

    /**
     * List published articles in a category, ordered by sort_order.
     */
    async listByCategory(
      category: string,
      limit = 50,
      offset = 0,
    ): Promise<ArticleListItem[]> {
      const rows = await db
        .select({
          articleId: helpArticles.articleId,
          slug: helpArticles.slug,
          title: helpArticles.title,
          summary: helpArticles.summary,
        })
        .from(helpArticles)
        .where(
          and(
            eq(helpArticles.category, category),
            eq(helpArticles.isPublished, true),
          ),
        )
        .orderBy(asc(helpArticles.sortOrder))
        .limit(limit)
        .offset(offset);

      return rows;
    },

    /**
     * Search related_codes JSONB array for the given code.
     * Returns published articles where related_codes @> [code].
     * Used for rejection/explanatory code lookups.
     */
    async findByRelatedCode(code: string): Promise<ArticleListItem[]> {
      const rows = await db
        .select({
          articleId: helpArticles.articleId,
          slug: helpArticles.slug,
          title: helpArticles.title,
          summary: helpArticles.summary,
        })
        .from(helpArticles)
        .where(
          and(
            eq(helpArticles.isPublished, true),
            sql`${helpArticles.relatedCodes} @> ${JSON.stringify([code])}::jsonb`,
          ),
        )
        .orderBy(asc(helpArticles.sortOrder));

      return rows;
    },

    /**
     * Atomically increment helpful_count or not_helpful_count.
     */
    async incrementFeedback(
      articleId: string,
      isHelpful: boolean,
    ): Promise<void> {
      if (isHelpful) {
        await db
          .update(helpArticles)
          .set({
            helpfulCount: sql`${helpArticles.helpfulCount} + 1`,
          })
          .where(eq(helpArticles.articleId, articleId));
      } else {
        await db
          .update(helpArticles)
          .set({
            notHelpfulCount: sql`${helpArticles.notHelpfulCount} + 1`,
          })
          .where(eq(helpArticles.articleId, articleId));
      }
    },

    /**
     * Insert feedback for an article from a physician.
     * On conflict (article_id, provider_id) update the is_helpful value.
     */
    async createFeedback(
      articleId: string,
      providerId: string,
      isHelpful: boolean,
    ): Promise<void> {
      await db
        .insert(articleFeedback)
        .values({
          articleId,
          providerId,
          isHelpful,
        })
        .onConflictDoUpdate({
          target: [articleFeedback.articleId, articleFeedback.providerId],
          set: { isHelpful },
        });
    },

    // -----------------------------------------------------------------------
    // Admin methods (content management — support team/admin only)
    // -----------------------------------------------------------------------

    /**
     * Create a new help article.
     * Slug auto-generated from title if not provided.
     */
    async create(data: InsertHelpArticle): Promise<SelectHelpArticle> {
      const slug = data.slug || slugify(data.title);
      const searchVector = sql`to_tsvector('english', ${data.title} || ' ' || ${data.content})`;

      const rows = await db
        .insert(helpArticles)
        .values({
          ...data,
          slug,
          searchVector,
        })
        .returning();

      return rows[0];
    },

    /**
     * Update article content. search_vector auto-updated if title or content change.
     */
    async update(
      articleId: string,
      data: Partial<Omit<InsertHelpArticle, 'articleId'>>,
    ): Promise<SelectHelpArticle | null> {
      const setClauses: Record<string, unknown> = { ...data, updatedAt: new Date() };

      // Regenerate search_vector if title or content changed
      if (data.title !== undefined || data.content !== undefined) {
        // We need current values for the fields not being updated
        const current = await db
          .select({ title: helpArticles.title, content: helpArticles.content })
          .from(helpArticles)
          .where(eq(helpArticles.articleId, articleId))
          .limit(1);

        if (current.length === 0) return null;

        const newTitle = data.title ?? current[0].title;
        const newContent = data.content ?? current[0].content;
        setClauses.searchVector = sql`to_tsvector('english', ${newTitle} || ' ' || ${newContent})`;
      }

      const rows = await db
        .update(helpArticles)
        .set(setClauses)
        .where(eq(helpArticles.articleId, articleId))
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Set is_published = true.
     */
    async publish(articleId: string): Promise<SelectHelpArticle | null> {
      const rows = await db
        .update(helpArticles)
        .set({ isPublished: true, updatedAt: new Date() })
        .where(eq(helpArticles.articleId, articleId))
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Set is_published = false.
     */
    async unpublish(articleId: string): Promise<SelectHelpArticle | null> {
      const rows = await db
        .update(helpArticles)
        .set({ isPublished: false, updatedAt: new Date() })
        .where(eq(helpArticles.articleId, articleId))
        .returning();

      return rows[0] ?? null;
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function slugify(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

export type HelpArticlesRepository = ReturnType<typeof createHelpArticlesRepository>;
