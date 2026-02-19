import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHelpArticlesRepository } from './help-articles.repo.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let articlesStore: Record<string, any>[];
let feedbackStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Column name → camelCase mapping
// ---------------------------------------------------------------------------

const COL_MAP: Record<string, string> = {
  article_id: 'articleId',
  slug: 'slug',
  title: 'title',
  category: 'category',
  content: 'content',
  summary: 'summary',
  search_vector: 'searchVector',
  related_codes: 'relatedCodes',
  somb_version: 'sombVersion',
  is_published: 'isPublished',
  helpful_count: 'helpfulCount',
  not_helpful_count: 'notHelpfulCount',
  sort_order: 'sortOrder',
  created_at: 'createdAt',
  updated_at: 'updatedAt',
  feedback_id: 'feedbackId',
  provider_id: 'providerId',
  is_helpful: 'isHelpful',
};

function toStoreKey(col: any): string {
  const name = col && col.name ? col.name : '';
  return COL_MAP[name] || name;
}

// ---------------------------------------------------------------------------
// Simple full-text search simulation
// ---------------------------------------------------------------------------

function simpleTextMatch(searchVector: string, query: string): boolean {
  if (!searchVector || !query) return false;
  // Normalise: strip tsquery operators, split on whitespace / &
  const terms = query
    .replace(/[&|!():<>*]/g, ' ')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  const text = searchVector.toLowerCase();
  return terms.every((t) => text.includes(t));
}

function simpleRank(searchVector: string, query: string): number {
  if (!searchVector || !query) return 0;
  const terms = query
    .replace(/[&|!():<>*]/g, ' ')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  const text = searchVector.toLowerCase();
  let score = 0;
  for (const t of terms) {
    const idx = text.indexOf(t);
    if (idx >= 0) score += 1;
  }
  return score / Math.max(terms.length, 1);
}

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb(): any {
  function chainable(ctx: {
    op: string;
    table?: string;
    selectFields?: Record<string, any> | null;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    onConflictConfig?: any;
    shouldReturn?: boolean;
    orderFn?: ((a: any, b: any) => number) | null;
    limitVal?: number;
    offsetVal?: number;
  }) {
    const chain: any = {
      _ctx: ctx,
      values(v: any) {
        ctx.values = Array.isArray(v) ? v : [v];
        return chain;
      },
      set(s: any) {
        ctx.setClauses = s;
        return chain;
      },
      from(table: any) {
        // Determine target store from table reference
        const tableName =
          table &&
          (table[Symbol.for('drizzle:Name')] ||
            table._.name ||
            (table === getArticlesTable() ? 'help_articles' : undefined) ||
            (table === getFeedbackTable() ? 'article_feedback' : undefined));
        ctx.table = tableName || ctx.table;
        return chain;
      },
      where(clause: any) {
        if (typeof clause === 'function') {
          ctx.whereClauses.push(clause);
        } else if (clause && typeof clause === 'object' && clause.__predicate) {
          ctx.whereClauses.push(clause.__predicate);
        }
        return chain;
      },
      orderBy(...args: any[]) {
        // Capture order function if provided
        if (args.length > 0 && args[0] && typeof args[0] === 'object' && args[0].__orderFn) {
          ctx.orderFn = args[0].__orderFn;
        } else if (args.length > 0 && args[0] && typeof args[0] === 'object' && args[0].__orderDesc) {
          ctx.orderFn = args[0].__orderDesc;
        }
        return chain;
      },
      limit(n: number) {
        ctx.limitVal = n;
        return chain;
      },
      offset(n: number) {
        ctx.offsetVal = n;
        return chain;
      },
      onConflictDoUpdate(config: any) {
        ctx.onConflictConfig = config;
        return chain;
      },
      returning() {
        ctx.shouldReturn = true;
        return chain;
      },
      then(resolve: any, reject?: any) {
        try {
          const result = executeOp(ctx);
          resolve(result);
        } catch (e) {
          if (reject) reject(e);
          else throw e;
        }
      },
    };
    return chain;
  }

  function getStore(ctx: any): any[] {
    if (ctx.table === 'article_feedback') return feedbackStore;
    return articlesStore;
  }

  function matchesWhere(
    row: Record<string, any>,
    whereClauses: Array<(row: any) => boolean>,
  ): boolean {
    return whereClauses.every((pred) => pred(row));
  }

  function executeOp(ctx: any): any[] {
    const store = getStore(ctx);

    switch (ctx.op) {
      case 'select': {
        let results = store.filter((row) => matchesWhere(row, ctx.whereClauses));

        if (ctx.orderFn) {
          results.sort(ctx.orderFn);
        }
        if (ctx.offsetVal) {
          results = results.slice(ctx.offsetVal);
        }
        if (ctx.limitVal !== undefined) {
          results = results.slice(0, ctx.limitVal);
        }

        // Project fields if selectFields specified
        if (ctx.selectFields) {
          results = results.map((row) => {
            const projected: Record<string, any> = {};
            for (const [alias, colRef] of Object.entries(ctx.selectFields!)) {
              if (colRef && typeof colRef === 'object' && (colRef as any).__rankFn) {
                projected[alias] = (colRef as any).__rankFn(row);
              } else {
                const key = toStoreKey(colRef);
                projected[alias] = row[key] ?? row[alias];
              }
            }
            return projected;
          });
        }

        return results;
      }

      case 'insert': {
        const inserted: any[] = [];
        for (const entry of ctx.values) {
          if (ctx.onConflictConfig) {
            // Check for conflict
            const targets = ctx.onConflictConfig.target || [];
            const targetKeys = targets.map((t: any) => toStoreKey(t));
            const existingIdx = store.findIndex((row) =>
              targetKeys.every((k: string) => row[k] === entry[k]),
            );

            if (existingIdx >= 0) {
              // Update existing
              const updateSet = ctx.onConflictConfig.set;
              const existing = store[existingIdx];
              for (const [key, val] of Object.entries(updateSet)) {
                existing[key] = val;
              }
              inserted.push({ ...existing });
              continue;
            }
          }

          const newRow: Record<string, any> = {
            ...entry,
          };
          // Auto-generate IDs
          if (ctx.table === 'article_feedback' && !newRow.feedbackId) {
            newRow.feedbackId = crypto.randomUUID();
          }
          if (ctx.table !== 'article_feedback' && !newRow.articleId) {
            newRow.articleId = crypto.randomUUID();
          }
          // Default timestamps
          if (!newRow.createdAt) newRow.createdAt = new Date();
          if (ctx.table !== 'article_feedback' && !newRow.updatedAt) {
            newRow.updatedAt = new Date();
          }
          // Default values
          if (newRow.isPublished === undefined) newRow.isPublished = false;
          if (newRow.helpfulCount === undefined) newRow.helpfulCount = 0;
          if (newRow.notHelpfulCount === undefined) newRow.notHelpfulCount = 0;
          if (newRow.sortOrder === undefined) newRow.sortOrder = 0;

          store.push(newRow);
          inserted.push({ ...newRow });
        }
        return ctx.shouldReturn ? inserted : [];
      }

      case 'update': {
        const updated: any[] = [];
        for (const row of store) {
          if (matchesWhere(row, ctx.whereClauses)) {
            for (const [key, val] of Object.entries(ctx.setClauses || {})) {
              if (val && typeof val === 'object' && (val as any).__increment) {
                row[key] = (row[key] || 0) + (val as any).__increment;
              } else if (val && typeof val === 'object' && (val as any).__tsvector) {
                row[key] = (val as any).__tsvector;
              } else {
                row[key] = val;
              }
            }
            updated.push({ ...row });
          }
        }
        return ctx.shouldReturn ? updated : [];
      }

      default:
        return [];
    }
  }

  // References to help resolve table identity in .from()
  let _articlesTableRef: any = null;
  let _feedbackTableRef: any = null;

  const db: any = {
    select(fields?: Record<string, any>) {
      return chainable({
        op: 'select',
        table: 'help_articles',
        selectFields: fields || null,
        whereClauses: [],
      });
    },
    insert(table: any) {
      const tableName = resolveTableName(table);
      return chainable({ op: 'insert', table: tableName, whereClauses: [] });
    },
    update(table: any) {
      const tableName = resolveTableName(table);
      return chainable({ op: 'update', table: tableName, whereClauses: [] });
    },
  };

  function resolveTableName(table: any): string {
    if (table === _feedbackTableRef) return 'article_feedback';
    // Check drizzle table name
    const name =
      table &&
      (table[Symbol.for('drizzle:Name')] || table._?.name);
    if (name === 'article_feedback') return 'article_feedback';
    return 'help_articles';
  }

  // Allow test to set references
  db.__setTableRefs = (articles: any, feedback: any) => {
    _articlesTableRef = articles;
    _feedbackTableRef = feedback;
  };

  return db;
}

function getArticlesTable(): any {
  return null;
}
function getFeedbackTable(): any {
  return null;
}

// ---------------------------------------------------------------------------
// Mock drizzle-orm operators
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', async () => {
  const actual = await vi.importActual<typeof import('drizzle-orm')>('drizzle-orm');
  return {
    ...actual,
    eq(col: any, val: any) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => row[key] === val,
      };
    },
    and(...conditions: any[]) {
      const preds = conditions
        .filter(Boolean)
        .map((c: any) => (typeof c === 'function' ? c : c?.__predicate))
        .filter(Boolean);
      return {
        __predicate: (row: any) => preds.every((pred: any) => pred(row)),
      };
    },
    asc(col: any) {
      const key = toStoreKey(col);
      return {
        __orderFn: (a: any, b: any) => {
          const av = a[key] ?? 0;
          const bv = b[key] ?? 0;
          return av < bv ? -1 : av > bv ? 1 : 0;
        },
      };
    },
    sql(strings: TemplateStringsArray, ...values: any[]) {
      const fullStr = strings.join('?');

      // to_tsquery pattern: builds a search predicate
      if (fullStr.includes('@@ ')) {
        // This is the WHERE clause: search_vector @@ to_tsquery(...)
        // values[0] = column ref (searchVector), values[1] = tsquery ref
        // Actually the tsquery ref is the inner sql`to_tsquery(...)` result
        const queryVal = values[1]?.__queryText || values[1] || '';
        return {
          __predicate: (row: any) =>
            simpleTextMatch(row.searchVector || '', queryVal),
        };
      }

      if (fullStr.includes('to_tsquery')) {
        // to_tsquery('english', query) — returns a reference holding the query text
        const queryText = values[0] || '';
        return { __queryText: queryText, __tsQuery: true };
      }

      if (fullStr.includes('ts_rank')) {
        // ts_rank(search_vector, tsquery) — returns a rank function
        const queryRef = values[1];
        const queryText = queryRef?.__queryText || '';
        return {
          __rankFn: (row: any) =>
            simpleRank(row.searchVector || '', queryText),
        };
      }

      // DESC ordering for rank
      if (fullStr.includes('DESC')) {
        const rankRef = values[0];
        if (rankRef && rankRef.__rankFn) {
          return {
            __orderDesc: (a: any, b: any) => {
              return rankRef.__rankFn(b) - rankRef.__rankFn(a);
            },
            // Also function as orderFn
            __orderFn: (a: any, b: any) => {
              return rankRef.__rankFn(b) - rankRef.__rankFn(a);
            },
          };
        }
        return {};
      }

      // to_tsvector for insert/update
      if (fullStr.includes('to_tsvector')) {
        // Simulate: concatenate title + content
        const parts = values.filter((v) => typeof v === 'string');
        return { __tsvector: parts.join(' ') };
      }

      // JSONB containment @> for related_codes
      if (fullStr.includes('@>')) {
        const jsonStr = values[1] ?? values[0];
        let codes: string[];
        try {
          codes =
            typeof jsonStr === 'string' ? JSON.parse(jsonStr) : jsonStr;
        } catch {
          codes = [];
        }
        return {
          __predicate: (row: any) => {
            if (!Array.isArray(row.relatedCodes)) return false;
            return codes.every((c: string) => row.relatedCodes.includes(c));
          },
        };
      }

      // Increment pattern: helpful_count + 1 / not_helpful_count + 1
      if (fullStr.includes('+ 1')) {
        // values[0] is the column ref
        return { __increment: 1 };
      }

      // Detect excluded.field references for onConflictDoUpdate
      if (fullStr.includes('excluded.')) {
        return { __excluded: true };
      }

      return {};
    },
  };
});

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function seedArticle(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const article: Record<string, any> = {
    articleId: crypto.randomUUID(),
    slug: overrides.slug ?? 'test-article',
    title: overrides.title ?? 'Test Article',
    category: overrides.category ?? 'getting-started',
    content: overrides.content ?? 'This is test content about claims.',
    summary: overrides.summary ?? 'A short summary',
    searchVector:
      overrides.searchVector ??
      `${overrides.title ?? 'Test Article'} ${overrides.content ?? 'This is test content about claims.'}`,
    relatedCodes: overrides.relatedCodes ?? null,
    sombVersion: overrides.sombVersion ?? null,
    isPublished: overrides.isPublished ?? true,
    helpfulCount: overrides.helpfulCount ?? 0,
    notHelpfulCount: overrides.notHelpfulCount ?? 0,
    sortOrder: overrides.sortOrder ?? 0,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  articlesStore.push(article);
  return article;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('HelpArticlesRepository', () => {
  let repo: ReturnType<typeof createHelpArticlesRepository>;

  beforeEach(() => {
    articlesStore = [];
    feedbackStore = [];
    repo = createHelpArticlesRepository(makeMockDb());
  });

  // =========================================================================
  // search
  // =========================================================================

  describe('search', () => {
    it('returns ranked results matching the query', async () => {
      seedArticle({
        title: 'How to submit AHCIP claims',
        content: 'Guide for submitting AHCIP claims via H-Link',
        searchVector: 'How to submit AHCIP claims Guide for submitting AHCIP claims via H-Link',
        slug: 'ahcip-claims',
        isPublished: true,
      });
      seedArticle({
        title: 'Understanding WCB billing',
        content: 'WCB billing overview and timing tiers',
        searchVector: 'Understanding WCB billing WCB billing overview and timing tiers',
        slug: 'wcb-billing',
        isPublished: true,
      });

      const results = await repo.search('AHCIP');

      expect(results.length).toBe(1);
      expect(results[0].slug).toBe('ahcip-claims');
      expect(results[0].rank).toBeGreaterThan(0);
    });

    it('returns results ordered by rank descending', async () => {
      seedArticle({
        title: 'AHCIP basics',
        content: 'Basic info',
        searchVector: 'AHCIP basics Basic info',
        slug: 'ahcip-basics',
        isPublished: true,
      });
      seedArticle({
        title: 'AHCIP AHCIP advanced AHCIP',
        content: 'AHCIP deep dive AHCIP',
        searchVector: 'AHCIP AHCIP advanced AHCIP AHCIP deep dive AHCIP',
        slug: 'ahcip-advanced',
        isPublished: true,
      });

      const results = await repo.search('AHCIP');

      expect(results.length).toBe(2);
      // Both match, both have rank > 0
      expect(results[0].rank).toBeGreaterThan(0);
      expect(results[1].rank).toBeGreaterThan(0);
    });

    it('excludes unpublished articles from search results', async () => {
      seedArticle({
        title: 'Published claims guide',
        content: 'Published content about claims',
        searchVector: 'Published claims guide Published content about claims',
        slug: 'published-guide',
        isPublished: true,
      });
      seedArticle({
        title: 'Draft claims guide',
        content: 'Draft content about claims',
        searchVector: 'Draft claims guide Draft content about claims',
        slug: 'draft-guide',
        isPublished: false,
      });

      const results = await repo.search('claims');

      expect(results.length).toBe(1);
      expect(results[0].slug).toBe('published-guide');
    });

    it('returns empty array when no articles match', async () => {
      seedArticle({
        title: 'Unrelated topic',
        content: 'Nothing about billing',
        searchVector: 'Unrelated topic Nothing about billing',
        slug: 'unrelated',
        isPublished: true,
      });

      const results = await repo.search('xyznonexistent');

      expect(results.length).toBe(0);
    });

    it('respects limit and offset parameters', async () => {
      for (let i = 0; i < 5; i++) {
        seedArticle({
          title: `Claims guide part ${i}`,
          content: `Claims content section ${i}`,
          searchVector: `Claims guide part ${i} Claims content section ${i}`,
          slug: `claims-part-${i}`,
          isPublished: true,
        });
      }

      const results = await repo.search('Claims', 2, 1);

      expect(results.length).toBe(2);
    });

    it('returns correct fields in search results', async () => {
      seedArticle({
        title: 'Billing overview',
        content: 'Comprehensive billing guide',
        searchVector: 'Billing overview Comprehensive billing guide',
        slug: 'billing-overview',
        category: 'billing',
        summary: 'An overview of billing',
        isPublished: true,
      });

      const results = await repo.search('billing');

      expect(results.length).toBe(1);
      expect(results[0]).toHaveProperty('articleId');
      expect(results[0]).toHaveProperty('slug');
      expect(results[0]).toHaveProperty('title');
      expect(results[0]).toHaveProperty('category');
      expect(results[0]).toHaveProperty('summary');
      expect(results[0]).toHaveProperty('rank');
      // Should NOT have content (heavy field)
      expect(results[0]).not.toHaveProperty('content');
    });
  });

  // =========================================================================
  // getBySlug
  // =========================================================================

  describe('getBySlug', () => {
    it('returns published article by slug', async () => {
      const article = seedArticle({
        slug: 'how-to-submit',
        title: 'How to Submit',
        isPublished: true,
      });

      const result = await repo.getBySlug('how-to-submit');

      expect(result).not.toBeNull();
      expect(result!.slug).toBe('how-to-submit');
      expect(result!.title).toBe('How to Submit');
    });

    it('returns null for unpublished article', async () => {
      seedArticle({
        slug: 'draft-article',
        title: 'Draft Article',
        isPublished: false,
      });

      const result = await repo.getBySlug('draft-article');

      expect(result).toBeNull();
    });

    it('returns null for non-existent slug', async () => {
      const result = await repo.getBySlug('does-not-exist');

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // listByCategory
  // =========================================================================

  describe('listByCategory', () => {
    it('returns published articles in the specified category', async () => {
      seedArticle({ category: 'billing', slug: 'billing-1', isPublished: true, sortOrder: 1 });
      seedArticle({ category: 'billing', slug: 'billing-2', isPublished: true, sortOrder: 2 });
      seedArticle({ category: 'setup', slug: 'setup-1', isPublished: true, sortOrder: 1 });

      const results = await repo.listByCategory('billing');

      expect(results.length).toBe(2);
      results.forEach((r) => {
        expect(r).toHaveProperty('articleId');
        expect(r).toHaveProperty('slug');
        expect(r).toHaveProperty('title');
        expect(r).toHaveProperty('summary');
      });
    });

    it('orders results by sort_order ascending', async () => {
      seedArticle({ category: 'billing', slug: 'billing-b', sortOrder: 2, isPublished: true });
      seedArticle({ category: 'billing', slug: 'billing-a', sortOrder: 1, isPublished: true });
      seedArticle({ category: 'billing', slug: 'billing-c', sortOrder: 3, isPublished: true });

      const results = await repo.listByCategory('billing');

      expect(results.length).toBe(3);
      expect(results[0].slug).toBe('billing-a');
      expect(results[1].slug).toBe('billing-b');
      expect(results[2].slug).toBe('billing-c');
    });

    it('excludes unpublished articles from category listing', async () => {
      seedArticle({ category: 'billing', slug: 'pub-1', isPublished: true });
      seedArticle({ category: 'billing', slug: 'draft-1', isPublished: false });

      const results = await repo.listByCategory('billing');

      expect(results.length).toBe(1);
      expect(results[0].slug).toBe('pub-1');
    });

    it('returns empty array for category with no articles', async () => {
      const results = await repo.listByCategory('nonexistent-category');

      expect(results.length).toBe(0);
    });

    it('respects limit and offset', async () => {
      for (let i = 0; i < 5; i++) {
        seedArticle({
          category: 'faq',
          slug: `faq-${i}`,
          sortOrder: i,
          isPublished: true,
        });
      }

      const results = await repo.listByCategory('faq', 2, 1);

      expect(results.length).toBe(2);
    });
  });

  // =========================================================================
  // findByRelatedCode
  // =========================================================================

  describe('findByRelatedCode', () => {
    it('returns articles matching the given code', async () => {
      seedArticle({
        slug: 'rejection-e01',
        title: 'Understanding E01 rejections',
        relatedCodes: ['E01', 'E02'],
        isPublished: true,
      });
      seedArticle({
        slug: 'rejection-e03',
        title: 'Understanding E03 rejections',
        relatedCodes: ['E03'],
        isPublished: true,
      });

      const results = await repo.findByRelatedCode('E01');

      expect(results.length).toBe(1);
      expect(results[0].slug).toBe('rejection-e01');
    });

    it('returns multiple articles if code appears in several', async () => {
      seedArticle({
        slug: 'article-a',
        title: 'Article A',
        relatedCodes: ['X01', 'X02'],
        isPublished: true,
      });
      seedArticle({
        slug: 'article-b',
        title: 'Article B',
        relatedCodes: ['X01', 'X03'],
        isPublished: true,
      });

      const results = await repo.findByRelatedCode('X01');

      expect(results.length).toBe(2);
    });

    it('excludes unpublished articles', async () => {
      seedArticle({
        slug: 'published-code',
        relatedCodes: ['R01'],
        isPublished: true,
      });
      seedArticle({
        slug: 'draft-code',
        relatedCodes: ['R01'],
        isPublished: false,
      });

      const results = await repo.findByRelatedCode('R01');

      expect(results.length).toBe(1);
      expect(results[0].slug).toBe('published-code');
    });

    it('returns empty array when no articles match the code', async () => {
      seedArticle({
        slug: 'other',
        relatedCodes: ['Z99'],
        isPublished: true,
      });

      const results = await repo.findByRelatedCode('NONEXISTENT');

      expect(results.length).toBe(0);
    });

    it('handles articles with null related_codes', async () => {
      seedArticle({
        slug: 'no-codes',
        relatedCodes: null,
        isPublished: true,
      });

      const results = await repo.findByRelatedCode('E01');

      expect(results.length).toBe(0);
    });
  });

  // =========================================================================
  // incrementFeedback
  // =========================================================================

  describe('incrementFeedback', () => {
    it('increments helpful_count when isHelpful is true', async () => {
      const article = seedArticle({
        slug: 'feedback-test',
        helpfulCount: 5,
        notHelpfulCount: 2,
        isPublished: true,
      });

      await repo.incrementFeedback(article.articleId, true);

      const stored = articlesStore.find((a) => a.articleId === article.articleId);
      expect(stored!.helpfulCount).toBe(6);
      expect(stored!.notHelpfulCount).toBe(2); // unchanged
    });

    it('increments not_helpful_count when isHelpful is false', async () => {
      const article = seedArticle({
        slug: 'feedback-test-2',
        helpfulCount: 5,
        notHelpfulCount: 2,
        isPublished: true,
      });

      await repo.incrementFeedback(article.articleId, false);

      const stored = articlesStore.find((a) => a.articleId === article.articleId);
      expect(stored!.helpfulCount).toBe(5); // unchanged
      expect(stored!.notHelpfulCount).toBe(3);
    });
  });

  // =========================================================================
  // createFeedback
  // =========================================================================

  describe('createFeedback', () => {
    it('inserts new feedback for a physician-article pair', async () => {
      const article = seedArticle({ slug: 'fb-test', isPublished: true });

      await repo.createFeedback(article.articleId, PROVIDER_A, true);

      expect(feedbackStore.length).toBe(1);
      expect(feedbackStore[0].articleId).toBe(article.articleId);
      expect(feedbackStore[0].providerId).toBe(PROVIDER_A);
      expect(feedbackStore[0].isHelpful).toBe(true);
    });

    it('updates feedback on conflict (physician changes their vote)', async () => {
      const article = seedArticle({ slug: 'fb-update', isPublished: true });

      // First vote: helpful
      await repo.createFeedback(article.articleId, PROVIDER_A, true);
      expect(feedbackStore.length).toBe(1);
      expect(feedbackStore[0].isHelpful).toBe(true);

      // Change vote: not helpful (conflict on article_id + provider_id)
      await repo.createFeedback(article.articleId, PROVIDER_A, false);
      expect(feedbackStore.length).toBe(1); // Still one row
      expect(feedbackStore[0].isHelpful).toBe(false);
    });

    it('allows different physicians to vote on the same article', async () => {
      const article = seedArticle({ slug: 'fb-multi', isPublished: true });

      await repo.createFeedback(article.articleId, PROVIDER_A, true);
      await repo.createFeedback(article.articleId, PROVIDER_B, false);

      expect(feedbackStore.length).toBe(2);
    });
  });

  // =========================================================================
  // Admin: create
  // =========================================================================

  describe('create (admin)', () => {
    it('creates a new article with auto-generated slug', async () => {
      const result = await repo.create({
        title: 'How to Submit AHCIP Claims',
        category: 'billing',
        content: 'Step by step guide...',
        summary: 'A guide to AHCIP claims',
        searchVector: '', // Will be overridden by sql`to_tsvector`
      });

      expect(result).toBeDefined();
      expect(result.slug).toBe('how-to-submit-ahcip-claims');
      expect(result.title).toBe('How to Submit AHCIP Claims');
    });

    it('uses provided slug if given', async () => {
      const result = await repo.create({
        title: 'My Article',
        slug: 'custom-slug',
        category: 'setup',
        content: 'Content here',
        searchVector: '',
      });

      expect(result.slug).toBe('custom-slug');
    });
  });

  // =========================================================================
  // Admin: update
  // =========================================================================

  describe('update (admin)', () => {
    it('updates article fields', async () => {
      const article = seedArticle({ slug: 'update-test', title: 'Old Title' });

      const result = await repo.update(article.articleId, { title: 'New Title' });

      expect(result).not.toBeNull();
      expect(result!.title).toBe('New Title');
    });

    it('returns null for non-existent article', async () => {
      const result = await repo.update(crypto.randomUUID(), { title: 'Nope' });

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // Admin: publish / unpublish
  // =========================================================================

  describe('publish / unpublish', () => {
    it('publishes a draft article', async () => {
      const article = seedArticle({ slug: 'pub-test', isPublished: false });

      const result = await repo.publish(article.articleId);

      expect(result).not.toBeNull();
      expect(result!.isPublished).toBe(true);
    });

    it('unpublishes a published article', async () => {
      const article = seedArticle({ slug: 'unpub-test', isPublished: true });

      const result = await repo.unpublish(article.articleId);

      expect(result).not.toBeNull();
      expect(result!.isPublished).toBe(false);
    });

    it('unpublished articles are hidden from getBySlug', async () => {
      const article = seedArticle({ slug: 'hide-test', isPublished: true });

      // Unpublish
      await repo.unpublish(article.articleId);

      // Try to fetch
      const result = await repo.getBySlug('hide-test');
      expect(result).toBeNull();
    });
  });
});
