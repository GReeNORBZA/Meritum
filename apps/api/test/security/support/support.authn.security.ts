// ============================================================================
// Domain 13: Support System — Authentication Enforcement (Security)
// Verifies every authenticated route returns 401 without valid session.
// 5 authenticated routes x 3 auth failure modes = 15 test cases
// + 2 public route verifications + sanity + leakage checks.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { helpRoutes } from '../../../src/domains/support/routes/help.routes.js';
import { ticketRoutes } from '../../../src/domains/support/routes/ticket.routes.js';
import type { HelpRoutesDeps } from '../../../src/domains/support/routes/help.routes.js';
import type { TicketRoutesDeps } from '../../../src/domains/support/routes/ticket.routes.js';

// ---------------------------------------------------------------------------
// Helper: hashToken (same SHA-256 used by auth plugin)
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const VALID_SESSION_TOKEN = randomBytes(32).toString('hex');
const VALID_SESSION_TOKEN_HASH = hashToken(VALID_SESSION_TOKEN);
const VALID_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const VALID_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_SESSION_TOKEN_HASH = hashToken(EXPIRED_SESSION_TOKEN);
const EXPIRED_SESSION_ID = 'cccc0000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockSession {
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}

interface MockUser {
  userId: string;
  role: string;
  subscriptionStatus: string;
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];

// ---------------------------------------------------------------------------
// Mock session repository (consumed by auth plugin)
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return { session, user };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Stub handler deps (not exercised — requests should never reach handlers
// for unauthenticated requests on protected routes)
// ---------------------------------------------------------------------------

const FIXED_DATE = new Date('2026-01-01T00:00:00.000Z');

function createStubHelpDeps(): HelpRoutesDeps {
  return {
    helpCentreService: {
      searchArticles: vi.fn(async () => []),
      listByCategory: vi.fn(async () => []),
      getArticle: vi.fn(async (_providerId: string, slug: string) => ({
        articleId: '11111111-0000-0000-0000-000000000001',
        slug,
        title: 'Test Article',
        content: 'Test content for the article.',
        category: 'GETTING_STARTED',
        status: 'PUBLISHED',
        helpfulCount: 0,
        notHelpfulCount: 0,
        createdAt: FIXED_DATE,
        updatedAt: FIXED_DATE,
      })),
      submitFeedback: vi.fn(async () => ({ success: true })),
      getContextualHelp: vi.fn(async () => ({
        type: 'search_page' as const,
        searchPageUrl: '/help',
      })),
      getFeedbackRateLimit: vi.fn(async () => ({ allowed: true })),
    } as any,
  };
}

function createStubTicketDeps(): TicketRoutesDeps {
  return {
    supportTicketService: {
      createTicket: vi.fn(async () => ({})),
      listTickets: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
      getTicket: vi.fn(async () => null),
      rateTicket: vi.fn(async () => null),
      transitionTicket: vi.fn(async () => null),
      checkSlaBreach: vi.fn(async () => []),
    } as any,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: { appendAuditLog: vi.fn(async () => {}) },
    events: { emit: vi.fn() },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(helpRoutes, { deps: createStubHelpDeps() });
  await testApp.register(ticketRoutes, { deps: createStubTicketDeps() });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createTamperedCookie(): string {
  return randomBytes(32).toString('hex').replace(/[0-9a-f]$/, 'x');
}

// ---------------------------------------------------------------------------
// Route specs — 5 authenticated support endpoints
// ---------------------------------------------------------------------------

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const AUTHENTICATED_ROUTES: RouteSpec[] = [
  // ---- Help routes (1 authenticated endpoint) ----
  {
    method: 'POST',
    url: '/api/v1/help/articles/getting-started/feedback',
    payload: { is_helpful: true },
    description: 'Submit article feedback',
  },

  // ---- Ticket routes (4 authenticated endpoints) ----
  {
    method: 'POST',
    url: '/api/v1/support/tickets',
    payload: { subject: 'Bug report', description: 'Something is broken' },
    description: 'Create support ticket',
  },
  {
    method: 'GET',
    url: '/api/v1/support/tickets',
    description: 'List support tickets',
  },
  {
    method: 'GET',
    url: `/api/v1/support/tickets/${DUMMY_UUID}`,
    description: 'Get ticket details',
  },
  {
    method: 'POST',
    url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
    payload: { rating: 5, comment: 'Great support' },
    description: 'Submit ticket rating',
  },
];

// ---------------------------------------------------------------------------
// Assertion: exactly 5 authenticated routes
// ---------------------------------------------------------------------------

if (AUTHENTICATED_ROUTES.length !== 5) {
  throw new Error(
    `Expected 5 authenticated routes but found ${AUTHENTICATED_ROUTES.length}. ` +
      'Update the route specs to match the registered support routes.',
  );
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Support System Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];

    // Seed a valid user + active session (for sanity checks)
    users.push({
      userId: VALID_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push({
      sessionId: VALID_SESSION_ID,
      userId: VALID_USER_ID,
      tokenHash: VALID_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Seed an expired/revoked session
    sessions.push({
      sessionId: EXPIRED_SESSION_ID,
      userId: VALID_USER_ID,
      tokenHash: EXPIRED_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000),
      lastActiveAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
      revoked: true,
      revokedReason: 'expired_absolute',
    });
  });

  // =========================================================================
  // No Cookie — each authenticated route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 without session cookie`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Expired/Revoked Cookie — each authenticated route returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with expired session`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Tampered Cookie — each authenticated route returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with tampered cookie`, async () => {
        const tamperedToken = createTamperedCookie();
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${tamperedToken}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Public routes — accessible WITHOUT auth, return valid data
  // =========================================================================

  describe('Public help routes work without authentication', () => {
    it('GET /api/v1/help/articles returns 200 without session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles?category=GETTING_STARTED',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(Array.isArray(body.data)).toBe(true);

      // Must NOT contain any session or user-specific info
      const rawBody = res.body;
      expect(rawBody).not.toContain('session');
      expect(rawBody).not.toContain('userId');
      expect(rawBody).not.toContain('providerId');
      expect(rawBody).not.toContain(VALID_USER_ID);
    });

    it('GET /api/v1/help/articles/:slug returns 200 without session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles/getting-started',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.slug).toBe('getting-started');
      expect(body.data.title).toBeDefined();
      expect(body.data.content).toBeDefined();

      // Must NOT contain any session or user-specific info
      const rawBody = res.body;
      expect(rawBody).not.toContain('session');
      expect(rawBody).not.toContain('userId');
      expect(rawBody).not.toContain('providerId');
      expect(rawBody).not.toContain(VALID_USER_ID);
    });

    it('GET /api/v1/help/articles returns same content regardless of auth status', async () => {
      // Without auth
      const resNoAuth = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles?category=GETTING_STARTED',
      });

      // With valid auth
      const resWithAuth = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles?category=GETTING_STARTED',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });

      expect(resNoAuth.statusCode).toBe(200);
      expect(resWithAuth.statusCode).toBe(200);

      // Both should return identical data structures
      const bodyNoAuth = JSON.parse(resNoAuth.body);
      const bodyWithAuth = JSON.parse(resWithAuth.body);
      expect(bodyNoAuth.data).toEqual(bodyWithAuth.data);
    });

    it('GET /api/v1/help/articles/:slug returns same content regardless of auth status', async () => {
      // Without auth
      const resNoAuth = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles/getting-started',
      });

      // With valid auth
      const resWithAuth = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles/getting-started',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });

      expect(resNoAuth.statusCode).toBe(200);
      expect(resWithAuth.statusCode).toBe(200);

      const bodyNoAuth = JSON.parse(resNoAuth.body);
      const bodyWithAuth = JSON.parse(resWithAuth.body);
      expect(bodyNoAuth.data).toEqual(bodyWithAuth.data);
    });
  });

  // =========================================================================
  // Sanity: valid session cookie is accepted (confirms test setup works)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/support/tickets returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/support/tickets',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/help/articles/getting-started/feedback returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/help/articles/getting-started/feedback',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
        payload: { is_helpful: true },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/support/tickets returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
        payload: { subject: 'Test', description: 'Test ticket' },
      });

      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // 401 response body must not leak support/ticket/article data
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response does not contain stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/support/tickets',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('401 response does not contain internal identifiers', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        payload: { subject: 'Bug', description: 'Something broke' },
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
    });

    it('401 response does not leak ticket, article, or patient data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/support/tickets/${DUMMY_UUID}`,
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('ticket');
      expect(rawBody).not.toContain('article');
      expect(rawBody).not.toContain('patient');
      expect(rawBody).not.toContain('screenshot');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
        payload: { rating: 5, comment: 'Great' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });
  });
});
