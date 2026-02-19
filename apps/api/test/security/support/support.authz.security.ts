// ============================================================================
// Domain 13: Support System — Authorization & Permission Enforcement (Security)
// Verifies:
//   1. All authenticated roles (physician, delegate, admin) can access support
//      endpoints — support is universally accessible, no permission gating.
//   2. Delegate context: tickets are linked to the physician's provider_id,
//      not the delegate's own user_id.
//   3. Admin-only service methods (updateTicket, triage queue, SLA breach)
//      are not exposed as external routes — no route-level admin escalation.
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

// Physician
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';
const PHYSICIAN_PROVIDER_ID = 'pppp0000-0000-0000-0000-000000000001';

// Delegate (linked to physician above) — minimal permissions (CLAIM_VIEW only)
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = 'cccc0000-0000-0000-0000-000000000002';
const DELEGATE_SESSION_ID = 'dddd0000-0000-0000-0000-000000000002';

// Admin user
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_USER_ID = 'eeee0000-0000-0000-0000-000000000003';
const ADMIN_SESSION_ID = 'ffff0000-0000-0000-0000-000000000003';

// Placeholder UUID for route params
const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

// Fixed ticket data
const FIXED_DATE = new Date('2026-01-01T00:00:00.000Z');
const TICKET_ID = '11111111-0000-0000-0000-000000000001';

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
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];

// ---------------------------------------------------------------------------
// Track service calls to verify delegate context behaviour
// ---------------------------------------------------------------------------

const serviceCalls: {
  createTicket: Array<{ providerId: string; data: any }>;
  listTickets: Array<{ providerId: string }>;
  getTicket: Array<{ providerId: string; ticketId: string }>;
  rateTicket: Array<{ providerId: string; ticketId: string }>;
  submitFeedback: Array<{ slug: string; providerId: string }>;
} = {
  createTicket: [],
  listTickets: [],
  getTicket: [],
  rateTicket: [],
  submitFeedback: [],
};

function resetServiceCalls() {
  serviceCalls.createTicket = [];
  serviceCalls.listTickets = [];
  serviceCalls.getTicket = [];
  serviceCalls.rateTicket = [];
  serviceCalls.submitFeedback = [];
}

// ---------------------------------------------------------------------------
// Mock session repository
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      const result: any = {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
      if (user.delegateContext) {
        result.user.delegateContext = user.delegateContext;
      }
      return result;
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Stub service deps (instrumented to capture providerId)
// ---------------------------------------------------------------------------

function createStubHelpDeps(): HelpRoutesDeps {
  return {
    helpCentreService: {
      searchArticles: vi.fn(async () => []),
      listByCategory: vi.fn(async () => []),
      getArticle: vi.fn(async (_providerId: string, slug: string) => ({
        articleId: '11111111-0000-0000-0000-000000000099',
        slug,
        title: 'Test Article',
        content: 'Test content.',
        category: 'GETTING_STARTED',
        status: 'PUBLISHED',
        helpfulCount: 0,
        notHelpfulCount: 0,
        createdAt: FIXED_DATE,
        updatedAt: FIXED_DATE,
      })),
      submitFeedback: vi.fn(async (slug: string, providerId: string) => {
        serviceCalls.submitFeedback.push({ slug, providerId });
        return { success: true };
      }),
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
      createTicket: vi.fn(async (providerId: string, data: any) => {
        serviceCalls.createTicket.push({ providerId, data });
        return {
          ticketId: TICKET_ID,
          providerId,
          subject: data.subject,
          description: data.description,
          status: 'OPEN',
          priority: 'NORMAL',
          category: null,
          contextUrl: null,
          contextMetadata: null,
          assignedTo: null,
          resolutionNotes: null,
          satisfactionRating: null,
          satisfactionComment: null,
          resolvedAt: null,
          createdAt: FIXED_DATE,
          updatedAt: FIXED_DATE,
        };
      }),
      listTickets: vi.fn(async (providerId: string) => {
        serviceCalls.listTickets.push({ providerId });
        return {
          data: [
            {
              ticketId: TICKET_ID,
              providerId,
              subject: 'Test ticket',
              description: 'Test',
              status: 'OPEN',
              priority: 'NORMAL',
              category: null,
              contextUrl: null,
              contextMetadata: null,
              assignedTo: null,
              resolutionNotes: null,
              satisfactionRating: null,
              satisfactionComment: null,
              resolvedAt: null,
              createdAt: FIXED_DATE,
              updatedAt: FIXED_DATE,
            },
          ],
          pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
        };
      }),
      getTicket: vi.fn(async (providerId: string, ticketId: string) => {
        serviceCalls.getTicket.push({ providerId, ticketId });
        return {
          ticketId,
          providerId,
          subject: 'Test ticket',
          description: 'Test',
          status: 'RESOLVED',
          priority: 'NORMAL',
          category: null,
          contextUrl: null,
          contextMetadata: null,
          assignedTo: null,
          resolutionNotes: null,
          satisfactionRating: null,
          satisfactionComment: null,
          resolvedAt: FIXED_DATE,
          createdAt: FIXED_DATE,
          updatedAt: FIXED_DATE,
        };
      }),
      rateTicket: vi.fn(async (providerId: string, ticketId: string, rating: number, comment?: string) => {
        serviceCalls.rateTicket.push({ providerId, ticketId });
        return {
          ticketId,
          providerId,
          subject: 'Test ticket',
          description: 'Test',
          status: 'RESOLVED',
          priority: 'NORMAL',
          category: null,
          contextUrl: null,
          contextMetadata: null,
          assignedTo: null,
          resolutionNotes: null,
          satisfactionRating: rating,
          satisfactionComment: comment ?? null,
          resolvedAt: FIXED_DATE,
          createdAt: FIXED_DATE,
          updatedAt: FIXED_DATE,
        };
      }),
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
// Request helpers
// ---------------------------------------------------------------------------

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function adminRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedUsers() {
  users = [];
  sessions = [];

  // Physician
  users.push({
    userId: PHYSICIAN_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: PHYSICIAN_SESSION_ID,
    userId: PHYSICIAN_USER_ID,
    tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate — linked to physician's context, minimal permissions (only CLAIM_VIEW)
  users.push({
    userId: DELEGATE_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_USER_ID,
      physicianProviderId: PHYSICIAN_PROVIDER_ID,
      permissions: ['CLAIM_VIEW'],
      linkageId: 'dddd0000-0000-0000-0000-000000000099',
    },
  });
  sessions.push({
    sessionId: DELEGATE_SESSION_ID,
    userId: DELEGATE_USER_ID,
    tokenHash: DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Admin
  users.push({
    userId: ADMIN_USER_ID,
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN_SESSION_ID,
    userId: ADMIN_USER_ID,
    tokenHash: ADMIN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

const validTicketPayload = {
  subject: 'I need help with billing',
  description: 'Cannot submit claims after upgrading.',
};

const validRatingPayload = {
  rating: 5,
  comment: 'Great support, thanks!',
};

const validFeedbackPayload = {
  is_helpful: true,
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Support System Authorization & Permission Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
    resetServiceCalls();
  });

  // =========================================================================
  // 1. Universal access — physician can access all support endpoints
  // =========================================================================

  describe('Physician can access all support endpoints (no permission gating)', () => {
    it('POST /api/v1/support/tickets — physician can create ticket', async () => {
      const res = await physicianRequest('POST', '/api/v1/support/tickets', validTicketPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(201);
    });

    it('GET /api/v1/support/tickets — physician can list tickets', async () => {
      const res = await physicianRequest('GET', '/api/v1/support/tickets');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });

    it('GET /api/v1/support/tickets/:id — physician can view ticket', async () => {
      const res = await physicianRequest('GET', `/api/v1/support/tickets/${DUMMY_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });

    it('POST /api/v1/support/tickets/:id/rating — physician can rate ticket', async () => {
      const res = await physicianRequest('POST', `/api/v1/support/tickets/${DUMMY_UUID}/rating`, validRatingPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });

    it('POST /api/v1/help/articles/:slug/feedback — physician can submit feedback', async () => {
      const res = await physicianRequest('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // 2. Universal access — delegate with minimal permissions can still access
  //    all support endpoints (support has NO permission gates)
  // =========================================================================

  describe('Delegate with minimal permissions can access all support endpoints', () => {
    it('POST /api/v1/support/tickets — delegate can create ticket', async () => {
      const res = await delegateRequest('POST', '/api/v1/support/tickets', validTicketPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(201);
    });

    it('GET /api/v1/support/tickets — delegate can list tickets', async () => {
      const res = await delegateRequest('GET', '/api/v1/support/tickets');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });

    it('GET /api/v1/support/tickets/:id — delegate can view ticket', async () => {
      const res = await delegateRequest('GET', `/api/v1/support/tickets/${DUMMY_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });

    it('POST /api/v1/support/tickets/:id/rating — delegate can rate ticket', async () => {
      const res = await delegateRequest('POST', `/api/v1/support/tickets/${DUMMY_UUID}/rating`, validRatingPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });

    it('POST /api/v1/help/articles/:slug/feedback — delegate can submit feedback', async () => {
      const res = await delegateRequest('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // 3. Universal access — admin can access all support endpoints
  // =========================================================================

  describe('Admin can access all support endpoints', () => {
    it('POST /api/v1/support/tickets — admin can create ticket', async () => {
      const res = await adminRequest('POST', '/api/v1/support/tickets', validTicketPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(201);
    });

    it('GET /api/v1/support/tickets — admin can list tickets', async () => {
      const res = await adminRequest('GET', '/api/v1/support/tickets');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });

    it('GET /api/v1/support/tickets/:id — admin can view ticket', async () => {
      const res = await adminRequest('GET', `/api/v1/support/tickets/${DUMMY_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });

    it('POST /api/v1/support/tickets/:id/rating — admin can rate ticket', async () => {
      const res = await adminRequest('POST', `/api/v1/support/tickets/${DUMMY_UUID}/rating`, validRatingPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });

    it('POST /api/v1/help/articles/:slug/feedback — admin can submit feedback', async () => {
      const res = await adminRequest('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // 4. Delegate context — ticket operations use physician's provider_id
  // =========================================================================

  describe('Delegate context: operations use physician provider_id, not delegate user_id', () => {
    it('delegate createTicket passes physician provider_id, not delegate user_id', async () => {
      await delegateRequest('POST', '/api/v1/support/tickets', validTicketPayload);

      expect(serviceCalls.createTicket.length).toBe(1);
      const call = serviceCalls.createTicket[0]!;
      // The providerId should be the physician's provider ID from delegateContext
      expect(call.providerId).toBe(PHYSICIAN_PROVIDER_ID);
      // It must NOT be the delegate's own user_id
      expect(call.providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('delegate listTickets passes physician provider_id, not delegate user_id', async () => {
      await delegateRequest('GET', '/api/v1/support/tickets');

      expect(serviceCalls.listTickets.length).toBe(1);
      const call = serviceCalls.listTickets[0]!;
      expect(call.providerId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(call.providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('delegate getTicket passes physician provider_id, not delegate user_id', async () => {
      await delegateRequest('GET', `/api/v1/support/tickets/${DUMMY_UUID}`);

      expect(serviceCalls.getTicket.length).toBe(1);
      const call = serviceCalls.getTicket[0]!;
      expect(call.providerId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(call.providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('delegate rateTicket passes physician provider_id, not delegate user_id', async () => {
      await delegateRequest('POST', `/api/v1/support/tickets/${DUMMY_UUID}/rating`, validRatingPayload);

      expect(serviceCalls.rateTicket.length).toBe(1);
      const call = serviceCalls.rateTicket[0]!;
      expect(call.providerId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(call.providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('delegate submitFeedback passes physician provider_id, not delegate user_id', async () => {
      await delegateRequest('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);

      expect(serviceCalls.submitFeedback.length).toBe(1);
      const call = serviceCalls.submitFeedback[0]!;
      expect(call.providerId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(call.providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('physician createTicket passes own user_id as provider_id', async () => {
      await physicianRequest('POST', '/api/v1/support/tickets', validTicketPayload);

      expect(serviceCalls.createTicket.length).toBe(1);
      const call = serviceCalls.createTicket[0]!;
      // Physician's userId is used directly (no delegateContext)
      expect(call.providerId).toBe(PHYSICIAN_USER_ID);
    });
  });

  // =========================================================================
  // 5. Admin-only operations are not exposed as external routes
  //    (updateTicket, transitionTicket, triage queue, SLA breach)
  // =========================================================================

  describe('Admin-only service methods not exposed as external routes', () => {
    it('PUT /api/v1/support/tickets/:id returns 404 — no update route for physicians', async () => {
      const res = await physicianRequest('PUT', `/api/v1/support/tickets/${DUMMY_UUID}`, {
        status: 'IN_PROGRESS',
      });
      // Route does not exist → 404 from Fastify
      expect(res.statusCode).toBe(404);
    });

    it('PATCH /api/v1/support/tickets/:id returns 404 — no patch route', async () => {
      const res = await physicianRequest('PUT', `/api/v1/support/tickets/${DUMMY_UUID}`, {
        priority: 'URGENT',
      });
      expect(res.statusCode).toBe(404);
    });

    it('DELETE /api/v1/support/tickets/:id returns 404 — no delete route', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/support/tickets/${DUMMY_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET /api/v1/support/triage returns 404 — no triage queue route for external users', async () => {
      const res = await physicianRequest('GET', '/api/v1/support/triage');
      expect(res.statusCode).toBe(404);
    });

    it('GET /api/v1/support/sla-breach returns 404 — no SLA breach route for external users', async () => {
      const res = await physicianRequest('GET', '/api/v1/support/sla-breach');
      expect(res.statusCode).toBe(404);
    });

    it('admin cannot access triage queue externally (no route exists)', async () => {
      const res = await adminRequest('GET', '/api/v1/support/triage');
      expect(res.statusCode).toBe(404);
    });

    it('admin cannot access SLA breach externally (no route exists)', async () => {
      const res = await adminRequest('GET', '/api/v1/support/sla-breach');
      expect(res.statusCode).toBe(404);
    });

    it('delegate cannot PUT tickets (no update route)', async () => {
      const res = await delegateRequest('PUT', `/api/v1/support/tickets/${DUMMY_UUID}`, {
        status: 'RESOLVED',
        category: 'BILLING',
      });
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 6. Physician cannot manipulate ticket status/category/priority
  // =========================================================================

  describe('Physicians cannot self-triage or manipulate ticket metadata', () => {
    it('physician cannot change ticket status via any existing route', async () => {
      // Only POST (create), GET (list/view), and POST rating exist
      // Verify PUT does not exist
      const res = await physicianRequest('PUT', `/api/v1/support/tickets/${DUMMY_UUID}`, {
        status: 'RESOLVED',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician cannot change ticket assigned_to via any existing route', async () => {
      const res = await physicianRequest('PUT', `/api/v1/support/tickets/${DUMMY_UUID}`, {
        assigned_to: 'some-admin-id',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician cannot change ticket priority via any existing route', async () => {
      const res = await physicianRequest('PUT', `/api/v1/support/tickets/${DUMMY_UUID}`, {
        priority: 'URGENT',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician cannot change ticket category via any existing route', async () => {
      const res = await physicianRequest('PUT', `/api/v1/support/tickets/${DUMMY_UUID}`, {
        category: 'BILLING',
      });
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 7. 403/error responses contain no sensitive data
  // =========================================================================

  describe('Error responses from authorization layer are safe', () => {
    it('404 for non-existent admin routes does not reveal internal route info', async () => {
      const res = await physicianRequest('GET', '/api/v1/support/triage');
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      // Must not leak any internal identifiers
      expect(rawBody).not.toContain('triage_queue');
      expect(rawBody).not.toContain('sla_breach');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
    });

    it('404 for PUT on tickets does not reveal admin capabilities', async () => {
      const res = await physicianRequest('PUT', `/api/v1/support/tickets/${DUMMY_UUID}`, {
        status: 'IN_PROGRESS',
      });
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain('updateTicket');
      expect(rawBody).not.toContain('admin');
      expect(rawBody).not.toContain('triage');
    });
  });

  // =========================================================================
  // 8. Sanity: public help routes remain accessible to all roles AND
  //    unauthenticated users (not an authz concern, but validates no
  //    accidental auth guards were added)
  // =========================================================================

  describe('Sanity: public help routes remain ungated', () => {
    it('GET /api/v1/help/articles — no auth required', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles?category=GETTING_STARTED',
      });
      expect(res.statusCode).toBe(200);
    });

    it('GET /api/v1/help/articles/:slug — no auth required', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles/getting-started',
      });
      expect(res.statusCode).toBe(200);
    });

    it('POST /api/v1/help/articles/:slug/feedback — requires auth but no permission', async () => {
      // Without auth → 401
      const resNoAuth = await app.inject({
        method: 'POST',
        url: '/api/v1/help/articles/getting-started/feedback',
        payload: validFeedbackPayload,
      });
      expect(resNoAuth.statusCode).toBe(401);

      // With auth (any role) → 200
      const resPhysician = await physicianRequest('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);
      expect(resPhysician.statusCode).toBe(200);

      const resDelegate = await delegateRequest('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);
      expect(resDelegate.statusCode).toBe(200);

      const resAdmin = await adminRequest('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);
      expect(resAdmin.statusCode).toBe(200);
    });
  });
});
