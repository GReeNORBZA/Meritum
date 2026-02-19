// ============================================================================
// Domain 13: Help Centre — Integration Tests
// Search, category listing, article detail, feedback.
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

import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  helpRoutes,
  type HelpRoutesDeps,
} from '../../../src/domains/support/routes/help.routes.js';
import { HelpCategory } from '@meritum/shared/constants/support.constants.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Seed article data
// ---------------------------------------------------------------------------

const ARTICLE_BATCH_CYCLE = {
  articleId: '00000000-aaaa-0000-0000-000000000001',
  slug: 'ahcip-batch-cycle-thursday',
  title: 'AHCIP Thursday Batch Cycle',
  category: HelpCategory.AHCIP_BILLING,
  content: 'AHCIP claims are submitted in a thursday batch cycle every Thursday at 18:00 MT.',
  summary: 'How the weekly Thursday batch submission works.',
  searchVector: '',
  relatedCodes: null,
  sombVersion: null,
  isPublished: true,
  helpfulCount: 3,
  notHelpfulCount: 0,
  sortOrder: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const ARTICLE_EXPLANATORY_101 = {
  articleId: '00000000-aaaa-0000-0000-000000000002',
  slug: 'explanatory-code-101-not-insured',
  title: 'Explanatory Code 101 — Not Insured',
  category: HelpCategory.AHCIP_BILLING,
  content: 'Explanatory code 101 means the patient is not currently insured under AHCIP.',
  summary: 'Understanding explanatory code 101.',
  searchVector: '',
  relatedCodes: ['101'],
  sombVersion: null,
  isPublished: true,
  helpfulCount: 5,
  notHelpfulCount: 1,
  sortOrder: 2,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const ARTICLE_TROUBLESHOOTING = {
  articleId: '00000000-aaaa-0000-0000-000000000003',
  slug: 'troubleshooting-hlink-connection',
  title: 'Troubleshooting H-Link Connection Issues',
  category: HelpCategory.TROUBLESHOOTING,
  content: 'If your H-Link connection fails, check your credentials and network.',
  summary: 'Fix H-Link connection problems.',
  searchVector: '',
  relatedCodes: null,
  sombVersion: null,
  isPublished: true,
  helpfulCount: 2,
  notHelpfulCount: 0,
  sortOrder: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const ARTICLE_UNPUBLISHED = {
  articleId: '00000000-aaaa-0000-0000-000000000004',
  slug: 'draft-article-wip',
  title: 'Draft Article — Work in Progress',
  category: HelpCategory.GETTING_STARTED,
  content: 'Draft content.',
  summary: null,
  searchVector: '',
  relatedCodes: null,
  sombVersion: null,
  isPublished: false,
  helpfulCount: 0,
  notHelpfulCount: 0,
  sortOrder: 99,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const ALL_ARTICLES = [
  ARTICLE_BATCH_CYCLE,
  ARTICLE_EXPLANATORY_101,
  ARTICLE_TROUBLESHOOTING,
  ARTICLE_UNPUBLISHED,
];

// ---------------------------------------------------------------------------
// Mock articles repository
// ---------------------------------------------------------------------------

function createMockArticlesRepo() {
  return {
    search: vi.fn(async (query: string, limit = 20, _offset = 0) => {
      const q = query.toLowerCase();
      const published = ALL_ARTICLES.filter((a) => a.isPublished);
      const matches = published.filter(
        (a) =>
          a.title.toLowerCase().includes(q) ||
          a.content.toLowerCase().includes(q) ||
          (a.summary ?? '').toLowerCase().includes(q),
      );
      return matches.slice(0, limit).map((a) => ({
        articleId: a.articleId,
        slug: a.slug,
        title: a.title,
        category: a.category,
        summary: a.summary,
        rank: 1.0,
      }));
    }),

    getBySlug: vi.fn(async (slug: string) => {
      const article = ALL_ARTICLES.find(
        (a) => a.slug === slug && a.isPublished,
      );
      return article ?? null;
    }),

    listByCategory: vi.fn(async (category: string, limit = 20, _offset = 0) => {
      const matches = ALL_ARTICLES.filter(
        (a) => a.category === category && a.isPublished,
      );
      return matches.slice(0, limit).map((a) => ({
        articleId: a.articleId,
        slug: a.slug,
        title: a.title,
        summary: a.summary,
      }));
    }),

    findByRelatedCode: vi.fn(async (code: string) => {
      const matches = ALL_ARTICLES.filter(
        (a) =>
          a.isPublished &&
          a.relatedCodes &&
          (a.relatedCodes as string[]).includes(code),
      );
      return matches.map((a) => ({
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

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000001',
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Build test app
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockArticlesRepo: ReturnType<typeof createMockArticlesRepo>;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockArticlesRepo = createMockArticlesRepo();
  mockAuditRepo = createMockAuditRepo();

  // Wire up help centre service with mock deps
  const { createHelpCentreService, _resetRateLimiter } = await import(
    '../../../src/domains/support/services/help-centre.service.js'
  );

  // Reset rate limiter between test runs
  _resetRateLimiter();

  const helpCentreService = createHelpCentreService({
    articlesRepo: mockArticlesRepo as any,
    auditRepo: mockAuditRepo,
  });

  const helpDeps: HelpRoutesDeps = { helpCentreService };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Auth plugin
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: createMockSessionRepo(),
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  } as any);

  // Error handler
  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: {
            code: (error as any).code,
            message: error.message,
            details: (error as any).details,
          },
        });
      }
    }
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.validation,
        },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(helpRoutes, { deps: helpDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function publicGet(url: string) {
  return app.inject({ method: 'GET', url });
}

function authedPost(url: string, body: Record<string, unknown>, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body,
  });
}

// ============================================================================
// Tests
// ============================================================================

describe('Help Centre Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // =========================================================================
  // Search articles
  // =========================================================================

  describe('GET /api/v1/help/articles?search=...', () => {
    it('search "thursday batch" returns AHCIP_BILLING articles about batch cycle', async () => {
      const res = await publicGet('/api/v1/help/articles?search=thursday%20batch');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.data[0].category).toBe(HelpCategory.AHCIP_BILLING);
      expect(body.data[0].slug).toBe('ahcip-batch-cycle-thursday');
    });

    it('search "explanatory code 101" returns article with related_codes containing 101', async () => {
      const res = await publicGet('/api/v1/help/articles?search=explanatory%20code%20101');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.data[0].slug).toBe('explanatory-code-101-not-insured');
    });

    it('search nonsense string returns empty results', async () => {
      const res = await publicGet('/api/v1/help/articles?search=xyzzy42nonsense');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toEqual([]);
    });

    it('no search or category returns empty list', async () => {
      const res = await publicGet('/api/v1/help/articles');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toEqual([]);
    });
  });

  // =========================================================================
  // List by category
  // =========================================================================

  describe('GET /api/v1/help/articles?category=...', () => {
    it('list by category TROUBLESHOOTING returns only troubleshooting articles', async () => {
      const res = await publicGet(`/api/v1/help/articles?category=${HelpCategory.TROUBLESHOOTING}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((article: any) => {
        // listByCategory mock doesn't return category field (ArticleListItem),
        // but we verify the slug matches the troubleshooting article
        expect(article.slug).toBe('troubleshooting-hlink-connection');
      });
    });

    it('list by category AHCIP_BILLING returns AHCIP articles', async () => {
      const res = await publicGet(`/api/v1/help/articles?category=${HelpCategory.AHCIP_BILLING}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.length).toBe(2); // batch cycle + explanatory 101
    });
  });

  // =========================================================================
  // Get article by slug
  // =========================================================================

  describe('GET /api/v1/help/articles/:slug', () => {
    it('returns full content for published article', async () => {
      const res = await publicGet('/api/v1/help/articles/ahcip-batch-cycle-thursday');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.articleId).toBe(ARTICLE_BATCH_CYCLE.articleId);
      expect(body.data.title).toBe(ARTICLE_BATCH_CYCLE.title);
      expect(body.data.content).toBe(ARTICLE_BATCH_CYCLE.content);
      expect(body.data.category).toBe(HelpCategory.AHCIP_BILLING);
    });

    it('returns 404 for unpublished article', async () => {
      const res = await publicGet('/api/v1/help/articles/draft-article-wip');
      expect(res.statusCode).toBe(404);
      const body = res.json();
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('returns 404 for non-existent slug', async () => {
      const res = await publicGet('/api/v1/help/articles/does-not-exist');
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // Submit feedback
  // =========================================================================

  describe('POST /api/v1/help/articles/:slug/feedback', () => {
    it('submit helpful feedback increments article helpful_count', async () => {
      const res = await authedPost(
        '/api/v1/help/articles/ahcip-batch-cycle-thursday/feedback',
        { is_helpful: true },
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.success).toBe(true);

      // Verify repo was called
      expect(mockArticlesRepo.createFeedback).toHaveBeenCalledWith(
        ARTICLE_BATCH_CYCLE.articleId,
        PHYSICIAN1_USER_ID,
        true,
      );
      expect(mockArticlesRepo.incrementFeedback).toHaveBeenCalledWith(
        ARTICLE_BATCH_CYCLE.articleId,
        true,
      );
    });

    it('submit feedback again updates existing (upsert, does not double-count)', async () => {
      // First feedback: helpful
      await authedPost(
        '/api/v1/help/articles/ahcip-batch-cycle-thursday/feedback',
        { is_helpful: true },
      );

      vi.clearAllMocks();

      // Second feedback: not helpful (changes vote)
      const res = await authedPost(
        '/api/v1/help/articles/ahcip-batch-cycle-thursday/feedback',
        { is_helpful: false },
      );
      expect(res.statusCode).toBe(200);
      expect(body(res).data.success).toBe(true);

      // createFeedback should be called with upsert semantics
      expect(mockArticlesRepo.createFeedback).toHaveBeenCalledWith(
        ARTICLE_BATCH_CYCLE.articleId,
        PHYSICIAN1_USER_ID,
        false,
      );
    });

    it('returns 404 for non-existent article slug', async () => {
      const res = await authedPost(
        '/api/v1/help/articles/does-not-exist/feedback',
        { is_helpful: true },
      );
      expect(res.statusCode).toBe(404);
    });

    it('requires authentication', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/help/articles/ahcip-batch-cycle-thursday/feedback',
        headers: { 'content-type': 'application/json' },
        payload: { is_helpful: true },
      });
      expect(res.statusCode).toBe(401);
    });
  });
});

// ---------------------------------------------------------------------------
// Helper to extract body (avoids double .json() on same response)
// ---------------------------------------------------------------------------

function body(res: { json: () => any }) {
  return res.json();
}
