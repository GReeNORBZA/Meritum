// ============================================================================
// Domain 13: Help Centre Routes — Unit Tests
// Tests: route registration, Zod validation, service method dispatch,
// public vs authenticated access, 404 for unknown slugs.
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before any imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeEach } from 'vitest';

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
import { authPluginFp } from '../../../plugins/auth.plugin.js';
import { helpRoutes, type HelpRoutesDeps } from './help.routes.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-0000-4000-8000-000000000001';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');

// ---------------------------------------------------------------------------
// Mock session deps for auth plugin
// ---------------------------------------------------------------------------

function makeSessionDeps(userId: string, role: string) {
  return {
    sessionRepo: {
      findSessionByTokenHash: async (hash: string) => {
        if (hash !== SESSION_HASH) return undefined;
        return {
          session: {
            sessionId: 'sess-1',
            userId,
            tokenHash: SESSION_HASH,
            ipAddress: '127.0.0.1',
            userAgent: 'test',
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
            revokedReason: null,
          },
          user: {
            userId,
            role,
            subscriptionStatus: 'ACTIVE',
          },
        };
      },
      refreshSession: async () => {},
      listActiveSessions: async () => [],
    },
    auditRepo: {
      appendAuditLog: async () => {},
    },
    events: {
      emit: () => true,
      on: () => {},
    },
  };
}

// ---------------------------------------------------------------------------
// Mock article fixtures
// ---------------------------------------------------------------------------

function makeArticle(overrides: Record<string, unknown> = {}) {
  return {
    articleId: '00000000-0000-4000-8000-000000000010',
    slug: 'how-to-submit-claims',
    title: 'How to Submit Claims',
    category: 'AHCIP_BILLING',
    content: 'Step 1: Open the claim form...',
    summary: 'Learn how to submit AHCIP claims',
    searchVector: '',
    relatedCodes: null,
    sombVersion: null,
    isPublished: true,
    helpfulCount: 5,
    notHelpfulCount: 1,
    sortOrder: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

function makeSearchResult(overrides: Record<string, unknown> = {}) {
  return {
    articleId: '00000000-0000-4000-8000-000000000010',
    slug: 'how-to-submit-claims',
    title: 'How to Submit Claims',
    category: 'AHCIP_BILLING',
    summary: 'Learn how to submit AHCIP claims',
    rank: 0.5,
    ...overrides,
  };
}

function makeListItem(overrides: Record<string, unknown> = {}) {
  return {
    articleId: '00000000-0000-4000-8000-000000000010',
    slug: 'how-to-submit-claims',
    title: 'How to Submit Claims',
    summary: 'Learn how to submit AHCIP claims',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// App builder
// ---------------------------------------------------------------------------

async function buildTestApp(
  serviceMock: Record<string, any>,
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const sessionDeps = makeSessionDeps(PHYSICIAN_ID, 'physician');
  await app.register(authPluginFp, { sessionDeps } as any);

  const deps: HelpRoutesDeps = {
    helpCentreService: serviceMock as any,
  };

  await app.register(helpRoutes, { deps });
  await app.ready();

  return app;
}

// ---------------------------------------------------------------------------
// Helpers: inject requests
// ---------------------------------------------------------------------------

function publicGet(app: FastifyInstance, url: string) {
  return app.inject({ method: 'GET', url });
}

function authedGet(app: FastifyInstance, url: string, token = SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function authedPost(
  app: FastifyInstance,
  url: string,
  body: unknown,
  token = SESSION_TOKEN,
) {
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

function publicPost(app: FastifyInstance, url: string, body: unknown) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body,
  });
}

// ============================================================================
// Tests
// ============================================================================

describe('Help Centre Routes', () => {
  // -----------------------------------------------------------------------
  // GET /api/v1/help/articles — search
  // -----------------------------------------------------------------------

  describe('GET /api/v1/help/articles', () => {
    it('returns search results when search param is provided', async () => {
      const mockService = {
        searchArticles: vi.fn().mockResolvedValue([makeSearchResult()]),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(app, '/api/v1/help/articles?search=claims');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);
      expect(body.data[0].slug).toBe('how-to-submit-claims');
      expect(mockService.searchArticles).toHaveBeenCalledWith(
        'anonymous',
        'claims',
        20,
        0,
      );

      await app.close();
    });

    it('returns category listing when category param is provided', async () => {
      const mockService = {
        listByCategory: vi.fn().mockResolvedValue([makeListItem()]),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles?category=AHCIP_BILLING',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);
      expect(mockService.listByCategory).toHaveBeenCalledWith(
        'AHCIP_BILLING',
        20,
        0,
      );

      await app.close();
    });

    it('returns empty array when no search or category provided', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await publicGet(app, '/api/v1/help/articles');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toEqual([]);

      await app.close();
    });

    it('passes limit and offset to search', async () => {
      const mockService = {
        searchArticles: vi.fn().mockResolvedValue([]),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles?search=billing&limit=10&offset=5',
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.searchArticles).toHaveBeenCalledWith(
        'anonymous',
        'billing',
        10,
        5,
      );

      await app.close();
    });

    it('passes limit and offset to category listing', async () => {
      const mockService = {
        listByCategory: vi.fn().mockResolvedValue([]),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles?category=GETTING_STARTED&limit=5&offset=10',
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.listByCategory).toHaveBeenCalledWith(
        'GETTING_STARTED',
        5,
        10,
      );

      await app.close();
    });

    it('is accessible without authentication (public)', async () => {
      const mockService = {
        searchArticles: vi.fn().mockResolvedValue([]),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(app, '/api/v1/help/articles?search=test');

      expect(res.statusCode).toBe(200);

      await app.close();
    });

    it('rejects invalid category with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles?category=INVALID_CATEGORY',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects search exceeding 200 characters with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const longSearch = 'a'.repeat(201);
      const res = await publicGet(
        app,
        `/api/v1/help/articles?search=${longSearch}`,
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects limit below 1 with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await publicGet(app, '/api/v1/help/articles?search=test&limit=0');

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects limit above 50 with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles?search=test&limit=51',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects negative offset with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles?search=test&offset=-1',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/help/articles/:slug — get by slug
  // -----------------------------------------------------------------------

  describe('GET /api/v1/help/articles/:slug', () => {
    it('returns article when slug is found', async () => {
      const article = makeArticle();
      const mockService = {
        getArticle: vi.fn().mockResolvedValue(article),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles/how-to-submit-claims',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.slug).toBe('how-to-submit-claims');
      expect(body.data.title).toBe('How to Submit Claims');
      expect(mockService.getArticle).toHaveBeenCalledWith(
        'anonymous',
        'how-to-submit-claims',
      );

      await app.close();
    });

    it('returns 404 for unknown slug', async () => {
      const mockService = {
        getArticle: vi.fn().mockResolvedValue(null),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles/nonexistent-article',
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');

      await app.close();
    });

    it('is accessible without authentication (public)', async () => {
      const mockService = {
        getArticle: vi.fn().mockResolvedValue(makeArticle()),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles/how-to-submit-claims',
      );

      expect(res.statusCode).toBe(200);

      await app.close();
    });

    it('rejects invalid slug format with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles/INVALID_SLUG!',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects slug with uppercase letters with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles/Invalid-Slug',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 404 for slug exceeding 200 characters', async () => {
      const mockService = {
        getArticle: vi.fn().mockResolvedValue(null),
      };
      const app = await buildTestApp(mockService);

      const longSlug = 'a'.repeat(201);
      const res = await publicGet(app, `/api/v1/help/articles/${longSlug}`);

      // Long slugs either fail Zod validation (400) or pass through and
      // match no article (404). Both are acceptable — no data leaks.
      expect([400, 404]).toContain(res.statusCode);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/help/articles/:slug/feedback — submit feedback
  // -----------------------------------------------------------------------

  describe('POST /api/v1/help/articles/:slug/feedback', () => {
    it('submits feedback when authenticated', async () => {
      const mockService = {
        submitFeedback: vi.fn().mockResolvedValue({ success: true }),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/help/articles/how-to-submit-claims/feedback',
        { is_helpful: true },
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.success).toBe(true);
      expect(mockService.submitFeedback).toHaveBeenCalledWith(
        'how-to-submit-claims',
        PHYSICIAN_ID,
        true,
      );

      await app.close();
    });

    it('submits not-helpful feedback', async () => {
      const mockService = {
        submitFeedback: vi.fn().mockResolvedValue({ success: true }),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/help/articles/how-to-submit-claims/feedback',
        { is_helpful: false },
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.submitFeedback).toHaveBeenCalledWith(
        'how-to-submit-claims',
        PHYSICIAN_ID,
        false,
      );

      await app.close();
    });

    it('returns 404 when article not found', async () => {
      const mockService = {
        submitFeedback: vi.fn().mockResolvedValue({ success: false }),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/help/articles/nonexistent-article/feedback',
        { is_helpful: true },
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');

      await app.close();
    });

    it('returns 401 without authentication', async () => {
      const mockService = {
        submitFeedback: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const res = await publicPost(
        app,
        '/api/v1/help/articles/how-to-submit-claims/feedback',
        { is_helpful: true },
      );

      expect(res.statusCode).toBe(401);
      expect(mockService.submitFeedback).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 401 with invalid session token', async () => {
      const mockService = {
        submitFeedback: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/help/articles/how-to-submit-claims/feedback',
        { is_helpful: true },
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);
      expect(mockService.submitFeedback).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects missing is_helpful field with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/help/articles/how-to-submit-claims/feedback',
        {},
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects non-boolean is_helpful with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/help/articles/how-to-submit-claims/feedback',
        { is_helpful: 'yes' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects invalid slug format with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/help/articles/INVALID!/feedback',
        { is_helpful: true },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // Public endpoints do not leak session info
  // -----------------------------------------------------------------------

  describe('public endpoint safety', () => {
    it('public article list does not include session data in response', async () => {
      const mockService = {
        searchArticles: vi.fn().mockResolvedValue([makeSearchResult()]),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(app, '/api/v1/help/articles?search=claims');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Response should not contain any session or user data
      const bodyStr = JSON.stringify(body);
      expect(bodyStr).not.toContain('session');
      expect(bodyStr).not.toContain('userId');
      expect(bodyStr).not.toContain('providerId');

      await app.close();
    });

    it('public article detail does not include session data in response', async () => {
      const mockService = {
        getArticle: vi.fn().mockResolvedValue(makeArticle()),
      };
      const app = await buildTestApp(mockService);

      const res = await publicGet(
        app,
        '/api/v1/help/articles/how-to-submit-claims',
      );

      expect(res.statusCode).toBe(200);
      const bodyStr = res.body;
      expect(bodyStr).not.toContain('session');
      expect(bodyStr).not.toContain(PHYSICIAN_ID);

      await app.close();
    });
  });
});
