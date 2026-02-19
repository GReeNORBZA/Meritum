// ============================================================================
// Domain 13: Support System — Cross-Physician Tenant Isolation (Security)
// MOST CRITICAL security test for the support domain.
//
// Verifies:
//   1. Physician A cannot see/access Physician B's support tickets (list, get, rate).
//   2. Cross-physician access always returns 404 (never 403) — do not confirm existence.
//   3. Article feedback is per-physician and isolated.
//   4. Help articles are intentionally public (no tenant scoping needed).
//   5. Delegate sees their linked physician's tickets, not another physician's.
//   6. Screenshot paths are never exposed in responses.
//
// Setup: Two physicians (P1, P2) each with tickets. One delegate linked to P1.
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
// Fixed test identities — TWO physicians + ONE delegate linked to P1
// ---------------------------------------------------------------------------

// Physician A (P1)
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const P1_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';
const P1_PROVIDER_ID = 'pppp0000-0000-0000-0000-000000000001';

// Physician B (P2)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const P2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';
const P2_PROVIDER_ID = 'pppp0000-0000-0000-0000-000000000002';

// Delegate linked to Physician A
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = 'cccc0000-0000-0000-0000-000000000003';
const DELEGATE_SESSION_ID = 'dddd0000-0000-0000-0000-000000000003';

// ---------------------------------------------------------------------------
// Fixed ticket IDs — each physician owns two tickets
// ---------------------------------------------------------------------------

const P1_TICKET_1 = '11111111-0000-0000-0000-000000000001';
const P1_TICKET_2 = '11111111-0000-0000-0000-000000000002';
const P2_TICKET_1 = '22222222-0000-0000-0000-000000000001';
const P2_TICKET_2 = '22222222-0000-0000-0000-000000000002';

// Non-existent ticket
const NONEXISTENT_TICKET = '99999999-0000-0000-0000-000000000099';

const FIXED_DATE = new Date('2026-01-01T00:00:00.000Z');

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

interface MockTicket {
  ticketId: string;
  providerId: string;
  subject: string;
  description: string;
  status: string;
  priority: string;
  category: string | null;
  contextUrl: string | null;
  contextMetadata: Record<string, unknown> | null;
  assignedTo: string | null;
  resolutionNotes: string | null;
  satisfactionRating: number | null;
  satisfactionComment: string | null;
  screenshotPath: string | null;
  resolvedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

interface MockFeedback {
  articleSlug: string;
  providerId: string;
  isHelpful: boolean;
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];
let tickets: MockTicket[] = [];
let feedbackStore: MockFeedback[] = [];

// ---------------------------------------------------------------------------
// Track service calls for verification
// ---------------------------------------------------------------------------

const serviceCalls: {
  createTicket: Array<{ providerId: string; data: any }>;
  listTickets: Array<{ providerId: string }>;
  getTicket: Array<{ providerId: string; ticketId: string }>;
  rateTicket: Array<{ providerId: string; ticketId: string }>;
  submitFeedback: Array<{ slug: string; providerId: string; isHelpful: boolean }>;
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
// Stub service deps — provider-scoped ticket operations
// ---------------------------------------------------------------------------

function createStubTicketDeps(): TicketRoutesDeps {
  return {
    supportTicketService: {
      createTicket: vi.fn(async (providerId: string, data: any) => {
        serviceCalls.createTicket.push({ providerId, data });
        const newTicket: MockTicket = {
          ticketId: randomBytes(16).toString('hex'),
          providerId,
          subject: data.subject,
          description: data.description,
          status: 'OPEN',
          priority: 'MEDIUM',
          category: null,
          contextUrl: data.contextUrl ?? null,
          contextMetadata: data.contextMetadata ?? null,
          assignedTo: null,
          resolutionNotes: null,
          satisfactionRating: null,
          satisfactionComment: null,
          screenshotPath: null,
          resolvedAt: null,
          createdAt: FIXED_DATE,
          updatedAt: FIXED_DATE,
        };
        tickets.push(newTicket);
        // Return without screenshotPath (service strips it)
        const { screenshotPath: _, ...rest } = newTicket;
        return rest;
      }),

      listTickets: vi.fn(async (providerId: string) => {
        serviceCalls.listTickets.push({ providerId });
        // CRITICAL: Only return tickets belonging to THIS provider
        const providerTickets = tickets
          .filter((t) => t.providerId === providerId)
          .map(({ screenshotPath: _, ...rest }) => rest);
        return {
          data: providerTickets,
          pagination: {
            total: providerTickets.length,
            page: 1,
            pageSize: 20,
            hasMore: false,
          },
        };
      }),

      getTicket: vi.fn(async (providerId: string, ticketId: string) => {
        serviceCalls.getTicket.push({ providerId, ticketId });
        // CRITICAL: Only return if ticket belongs to THIS provider
        const ticket = tickets.find(
          (t) => t.ticketId === ticketId && t.providerId === providerId,
        );
        if (!ticket) return null;
        const { screenshotPath: _, ...rest } = ticket;
        return rest;
      }),

      rateTicket: vi.fn(async (providerId: string, ticketId: string, rating: number, comment?: string) => {
        serviceCalls.rateTicket.push({ providerId, ticketId });
        // CRITICAL: Only rate if ticket belongs to THIS provider
        const ticket = tickets.find(
          (t) => t.ticketId === ticketId && t.providerId === providerId,
        );
        if (!ticket) return null;
        ticket.satisfactionRating = rating;
        ticket.satisfactionComment = comment ?? null;
        const { screenshotPath: _, ...rest } = ticket;
        return rest;
      }),

      transitionTicket: vi.fn(async () => null),
      checkSlaBreach: vi.fn(async () => []),
    } as any,
  };
}

function createStubHelpDeps(): HelpRoutesDeps {
  return {
    helpCentreService: {
      searchArticles: vi.fn(async () => []),
      listByCategory: vi.fn(async () => []),
      getArticle: vi.fn(async (_providerId: string, slug: string) => ({
        articleId: '11111111-0000-0000-0000-000000000099',
        slug,
        title: 'Test Article',
        content: 'Test content for help article.',
        category: 'GETTING_STARTED',
        status: 'PUBLISHED',
        helpfulCount: 0,
        notHelpfulCount: 0,
        createdAt: FIXED_DATE,
        updatedAt: FIXED_DATE,
      })),
      submitFeedback: vi.fn(async (slug: string, providerId: string, isHelpful: boolean) => {
        serviceCalls.submitFeedback.push({ slug, providerId, isHelpful });
        // Store feedback per-provider
        const existing = feedbackStore.find(
          (f) => f.articleSlug === slug && f.providerId === providerId,
        );
        if (existing) {
          existing.isHelpful = isHelpful;
        } else {
          feedbackStore.push({ articleSlug: slug, providerId, isHelpful });
        }
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

function asPhysician1(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asPhysician2(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asDelegate(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  sessions = [];
  users = [];

  // Physician A
  users.push({
    userId: P1_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: P1_SESSION_ID,
    userId: P1_USER_ID,
    tokenHash: P1_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Physician B
  users.push({
    userId: P2_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: P2_SESSION_ID,
    userId: P2_USER_ID,
    tokenHash: P2_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate linked to Physician A
  users.push({
    userId: DELEGATE_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_USER_ID,
      physicianProviderId: P1_PROVIDER_ID,
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
}

function seedTickets() {
  tickets = [];

  // Physician A's tickets
  tickets.push({
    ticketId: P1_TICKET_1,
    providerId: P1_USER_ID,
    subject: 'P1 billing issue',
    description: 'Cannot submit claims for patient.',
    status: 'RESOLVED',
    priority: 'MEDIUM',
    category: 'BILLING',
    contextUrl: null,
    contextMetadata: null,
    assignedTo: null,
    resolutionNotes: 'Fixed billing codes.',
    satisfactionRating: null,
    satisfactionComment: null,
    screenshotPath: `support-tickets/${P1_TICKET_1}/screenshot.png`,
    resolvedAt: FIXED_DATE,
    createdAt: FIXED_DATE,
    updatedAt: FIXED_DATE,
  });
  tickets.push({
    ticketId: P1_TICKET_2,
    providerId: P1_USER_ID,
    subject: 'P1 login problem',
    description: 'MFA not working on mobile.',
    status: 'OPEN',
    priority: 'HIGH',
    category: 'ACCOUNT',
    contextUrl: null,
    contextMetadata: null,
    assignedTo: null,
    resolutionNotes: null,
    satisfactionRating: null,
    satisfactionComment: null,
    screenshotPath: null,
    resolvedAt: null,
    createdAt: FIXED_DATE,
    updatedAt: FIXED_DATE,
  });

  // Physician B's tickets
  tickets.push({
    ticketId: P2_TICKET_1,
    providerId: P2_USER_ID,
    subject: 'P2 claim rejection',
    description: 'Patient claim was rejected unexpectedly.',
    status: 'RESOLVED',
    priority: 'URGENT',
    category: 'CLAIMS',
    contextUrl: null,
    contextMetadata: null,
    assignedTo: null,
    resolutionNotes: 'Corrected diagnostic code.',
    satisfactionRating: null,
    satisfactionComment: null,
    screenshotPath: `support-tickets/${P2_TICKET_1}/screenshot.jpeg`,
    resolvedAt: FIXED_DATE,
    createdAt: FIXED_DATE,
    updatedAt: FIXED_DATE,
  });
  tickets.push({
    ticketId: P2_TICKET_2,
    providerId: P2_USER_ID,
    subject: 'P2 onboarding help',
    description: 'Need help setting up WCB.',
    status: 'OPEN',
    priority: 'LOW',
    category: 'ONBOARDING',
    contextUrl: null,
    contextMetadata: null,
    assignedTo: null,
    resolutionNotes: null,
    satisfactionRating: null,
    satisfactionComment: null,
    screenshotPath: null,
    resolvedAt: null,
    createdAt: FIXED_DATE,
    updatedAt: FIXED_DATE,
  });
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

const validTicketPayload = {
  subject: 'Test support request',
  description: 'I need help with my account.',
};

const validRatingPayload = {
  rating: 5,
  comment: 'Issue resolved quickly.',
};

const validFeedbackPayload = {
  is_helpful: true,
};

// ===========================================================================
// Test Suite
// ===========================================================================

describe('Support System Cross-Physician Tenant Isolation (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
    seedTickets();
    feedbackStore = [];
    resetServiceCalls();
  });

  // =========================================================================
  // 1. TICKET LIST ISOLATION
  // =========================================================================

  describe('Ticket list isolation — each physician sees ONLY their own tickets', () => {
    it('Physician A lists tickets and sees only their own (2 tickets)', async () => {
      const res = await asPhysician1('GET', '/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(2);
      body.data.forEach((ticket: any) => {
        // Verify every ticket belongs to P1 (userId used as providerId for physicians)
        expect(ticket.providerId).toBe(P1_USER_ID);
      });

      // Verify P2's ticket IDs are NOT present
      const ticketIds = body.data.map((t: any) => t.ticketId);
      expect(ticketIds).not.toContain(P2_TICKET_1);
      expect(ticketIds).not.toContain(P2_TICKET_2);
    });

    it('Physician B lists tickets and sees only their own (2 tickets)', async () => {
      const res = await asPhysician2('GET', '/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(2);
      body.data.forEach((ticket: any) => {
        expect(ticket.providerId).toBe(P2_USER_ID);
      });

      // Verify P1's ticket IDs are NOT present
      const ticketIds = body.data.map((t: any) => t.ticketId);
      expect(ticketIds).not.toContain(P1_TICKET_1);
      expect(ticketIds).not.toContain(P1_TICKET_2);
    });

    it('service receives correct providerId for P1 list', async () => {
      await asPhysician1('GET', '/api/v1/support/tickets');
      expect(serviceCalls.listTickets.length).toBe(1);
      expect(serviceCalls.listTickets[0]!.providerId).toBe(P1_USER_ID);
    });

    it('service receives correct providerId for P2 list', async () => {
      await asPhysician2('GET', '/api/v1/support/tickets');
      expect(serviceCalls.listTickets.length).toBe(1);
      expect(serviceCalls.listTickets[0]!.providerId).toBe(P2_USER_ID);
    });
  });

  // =========================================================================
  // 2. TICKET GET-BY-ID ISOLATION — cross-physician returns 404
  // =========================================================================

  describe('Ticket get-by-ID isolation — cross-physician access returns 404', () => {
    it('Physician A can view their own ticket', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_1}`);
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body.data.ticketId).toBe(P1_TICKET_1);
      expect(body.data.providerId).toBe(P1_USER_ID);
    });

    it('Physician A cannot access Physician B ticket 1 — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_1}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('NOT_FOUND');
      // Must NOT return 403 (would confirm resource exists)
      expect(res.statusCode).not.toBe(403);
    });

    it('Physician A cannot access Physician B ticket 2 — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_2}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('Physician B cannot access Physician A ticket 1 — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/support/tickets/${P1_TICKET_1}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('Physician B cannot access Physician A ticket 2 — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/support/tickets/${P1_TICKET_2}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('non-existent ticket returns 404 (same shape as cross-physician)', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${NONEXISTENT_TICKET}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');
    });

    it('cross-physician 404 response is identical to non-existent ticket 404', async () => {
      // Cross-physician access
      const crossRes = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_1}`);
      // Non-existent ticket
      const missingRes = await asPhysician1('GET', `/api/v1/support/tickets/${NONEXISTENT_TICKET}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      // Error shape must be identical — attacker cannot distinguish
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });
  });

  // =========================================================================
  // 3. TICKET RATING ISOLATION — cross-physician returns 404
  // =========================================================================

  describe('Ticket rating isolation — cross-physician rating returns 404', () => {
    it('Physician A can rate their own resolved ticket', async () => {
      const res = await asPhysician1('POST', `/api/v1/support/tickets/${P1_TICKET_1}/rating`, validRatingPayload);
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body.data.ticketId).toBe(P1_TICKET_1);
    });

    it('Physician A cannot rate Physician B resolved ticket — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/support/tickets/${P2_TICKET_1}/rating`, validRatingPayload);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('NOT_FOUND');
      expect(res.statusCode).not.toBe(403);
    });

    it('Physician B cannot rate Physician A resolved ticket — returns 404', async () => {
      const res = await asPhysician2('POST', `/api/v1/support/tickets/${P1_TICKET_1}/rating`, validRatingPayload);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('rating non-existent ticket returns 404 (same as cross-physician)', async () => {
      const res = await asPhysician1('POST', `/api/v1/support/tickets/${NONEXISTENT_TICKET}/rating`, validRatingPayload);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('cross-physician rating does not modify the target ticket', async () => {
      // Physician A tries to rate Physician B's ticket
      await asPhysician1('POST', `/api/v1/support/tickets/${P2_TICKET_1}/rating`, validRatingPayload);

      // Verify P2's ticket was NOT modified
      const p2Ticket = tickets.find((t) => t.ticketId === P2_TICKET_1);
      expect(p2Ticket).toBeDefined();
      expect(p2Ticket!.satisfactionRating).toBeNull();
      expect(p2Ticket!.satisfactionComment).toBeNull();
    });
  });

  // =========================================================================
  // 4. TICKET CREATION ISOLATION — tickets are scoped to creating physician
  // =========================================================================

  describe('Ticket creation isolation — tickets scoped to creating physician', () => {
    it('Physician A creates ticket — ticket is owned by P1', async () => {
      const res = await asPhysician1('POST', '/api/v1/support/tickets', validTicketPayload);
      expect(res.statusCode).toBe(201);

      expect(serviceCalls.createTicket.length).toBe(1);
      expect(serviceCalls.createTicket[0]!.providerId).toBe(P1_USER_ID);
    });

    it('Physician B creates ticket — ticket is owned by P2', async () => {
      const res = await asPhysician2('POST', '/api/v1/support/tickets', validTicketPayload);
      expect(res.statusCode).toBe(201);

      expect(serviceCalls.createTicket.length).toBe(1);
      expect(serviceCalls.createTicket[0]!.providerId).toBe(P2_USER_ID);
    });

    it('after P1 and P2 both create tickets, each sees only their own on list', async () => {
      await asPhysician1('POST', '/api/v1/support/tickets', { subject: 'P1 new', description: 'test' });
      await asPhysician2('POST', '/api/v1/support/tickets', { subject: 'P2 new', description: 'test' });

      const res1 = await asPhysician1('GET', '/api/v1/support/tickets');
      const body1 = JSON.parse(res1.body);
      // P1 had 2 tickets + 1 new = 3
      expect(body1.data.length).toBe(3);
      body1.data.forEach((t: any) => {
        expect(t.providerId).toBe(P1_USER_ID);
      });

      const res2 = await asPhysician2('GET', '/api/v1/support/tickets');
      const body2 = JSON.parse(res2.body);
      // P2 had 2 tickets + 1 new = 3
      expect(body2.data.length).toBe(3);
      body2.data.forEach((t: any) => {
        expect(t.providerId).toBe(P2_USER_ID);
      });
    });
  });

  // =========================================================================
  // 5. SCREENSHOT PATH ISOLATION — never exposed in responses
  // =========================================================================

  describe('Screenshot path isolation — paths never exposed in any response', () => {
    it('ticket list responses do not contain screenshotPath', async () => {
      const res = await asPhysician1('GET', '/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('screenshotPath');
      expect(rawBody).not.toContain('screenshot_path');
      expect(rawBody).not.toContain('support-tickets/');
      expect(rawBody).not.toContain('.png');
    });

    it('ticket detail responses do not contain screenshotPath', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_1}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('screenshotPath');
      expect(rawBody).not.toContain('screenshot_path');
      expect(rawBody).not.toContain('support-tickets/');
    });

    it('ticket rating responses do not contain screenshotPath', async () => {
      const res = await asPhysician1('POST', `/api/v1/support/tickets/${P1_TICKET_1}/rating`, validRatingPayload);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('screenshotPath');
      expect(rawBody).not.toContain('screenshot_path');
    });

    it('ticket creation responses do not contain screenshotPath', async () => {
      const res = await asPhysician1('POST', '/api/v1/support/tickets', validTicketPayload);
      expect(res.statusCode).toBe(201);

      const rawBody = res.body;
      expect(rawBody).not.toContain('screenshotPath');
      expect(rawBody).not.toContain('screenshot_path');
    });
  });

  // =========================================================================
  // 6. ARTICLE FEEDBACK ISOLATION — per-physician, independent
  // =========================================================================

  describe('Article feedback isolation — per-physician, independent submissions', () => {
    it('Physician A submits feedback — recorded with P1 providerId', async () => {
      const res = await asPhysician1('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);
      expect(res.statusCode).toBe(200);

      expect(serviceCalls.submitFeedback.length).toBe(1);
      expect(serviceCalls.submitFeedback[0]!.providerId).toBe(P1_USER_ID);
      expect(serviceCalls.submitFeedback[0]!.slug).toBe('getting-started');
    });

    it('Physician B submits feedback — recorded with P2 providerId', async () => {
      const res = await asPhysician2('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);
      expect(res.statusCode).toBe(200);

      expect(serviceCalls.submitFeedback.length).toBe(1);
      expect(serviceCalls.submitFeedback[0]!.providerId).toBe(P2_USER_ID);
    });

    it('both physicians can submit feedback on the same article independently', async () => {
      // P1 says helpful
      await asPhysician1('POST', '/api/v1/help/articles/getting-started/feedback', { is_helpful: true });
      // P2 says not helpful
      await asPhysician2('POST', '/api/v1/help/articles/getting-started/feedback', { is_helpful: false });

      expect(serviceCalls.submitFeedback.length).toBe(2);

      // Verify each was called with the correct providerId
      const p1Call = serviceCalls.submitFeedback.find((c) => c.providerId === P1_USER_ID);
      const p2Call = serviceCalls.submitFeedback.find((c) => c.providerId === P2_USER_ID);
      expect(p1Call).toBeDefined();
      expect(p2Call).toBeDefined();
      expect(p1Call!.isHelpful).toBe(true);
      expect(p2Call!.isHelpful).toBe(false);
    });

    it('P1 feedback does not overwrite P2 feedback on same article', async () => {
      // P2 submits first
      await asPhysician2('POST', '/api/v1/help/articles/getting-started/feedback', { is_helpful: false });
      // P1 submits second
      await asPhysician1('POST', '/api/v1/help/articles/getting-started/feedback', { is_helpful: true });

      // Both feedback records exist independently
      const p1Feedback = feedbackStore.find(
        (f) => f.providerId === P1_USER_ID && f.articleSlug === 'getting-started',
      );
      const p2Feedback = feedbackStore.find(
        (f) => f.providerId === P2_USER_ID && f.articleSlug === 'getting-started',
      );

      expect(p1Feedback).toBeDefined();
      expect(p2Feedback).toBeDefined();
      expect(p1Feedback!.isHelpful).toBe(true);
      expect(p2Feedback!.isHelpful).toBe(false);
    });
  });

  // =========================================================================
  // 7. DELEGATE CROSS-PHYSICIAN ISOLATION
  // =========================================================================

  describe('Delegate cross-physician isolation', () => {
    it('delegate of P1 lists tickets — sees P1 tickets (uses physician provider_id)', async () => {
      const res = await asDelegate('GET', '/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);

      // Service should have been called with P1's provider_id (from delegate context)
      expect(serviceCalls.listTickets.length).toBe(1);
      expect(serviceCalls.listTickets[0]!.providerId).toBe(P1_PROVIDER_ID);
    });

    it('delegate of P1 can view P1 ticket', async () => {
      // We need to add a ticket owned by P1_PROVIDER_ID for delegate context
      tickets.push({
        ticketId: 'dddd0000-0000-0000-0000-000000000001',
        providerId: P1_PROVIDER_ID,
        subject: 'Delegate-visible ticket',
        description: 'Ticket owned by physician through provider context.',
        status: 'OPEN',
        priority: 'MEDIUM',
        category: null,
        contextUrl: null,
        contextMetadata: null,
        assignedTo: null,
        resolutionNotes: null,
        satisfactionRating: null,
        satisfactionComment: null,
        screenshotPath: null,
        resolvedAt: null,
        createdAt: FIXED_DATE,
        updatedAt: FIXED_DATE,
      });

      const res = await asDelegate('GET', '/api/v1/support/tickets/dddd0000-0000-0000-0000-000000000001');
      expect(res.statusCode).toBe(200);

      expect(serviceCalls.getTicket.length).toBe(1);
      expect(serviceCalls.getTicket[0]!.providerId).toBe(P1_PROVIDER_ID);
    });

    it('delegate of P1 cannot access Physician B tickets — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/support/tickets/${P2_TICKET_1}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);

      // Service was called with P1's provider_id, so P2's ticket is not found
      expect(serviceCalls.getTicket.length).toBe(1);
      expect(serviceCalls.getTicket[0]!.providerId).toBe(P1_PROVIDER_ID);
    });

    it('delegate of P1 cannot rate Physician B ticket — returns 404', async () => {
      const res = await asDelegate('POST', `/api/v1/support/tickets/${P2_TICKET_1}/rating`, validRatingPayload);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('delegate creates ticket — scoped to linked physician (P1), not delegate user_id', async () => {
      const res = await asDelegate('POST', '/api/v1/support/tickets', validTicketPayload);
      expect(res.statusCode).toBe(201);

      expect(serviceCalls.createTicket.length).toBe(1);
      expect(serviceCalls.createTicket[0]!.providerId).toBe(P1_PROVIDER_ID);
      expect(serviceCalls.createTicket[0]!.providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('delegate feedback on article uses physician provider_id, not delegate user_id', async () => {
      const res = await asDelegate('POST', '/api/v1/help/articles/getting-started/feedback', validFeedbackPayload);
      expect(res.statusCode).toBe(200);

      expect(serviceCalls.submitFeedback.length).toBe(1);
      expect(serviceCalls.submitFeedback[0]!.providerId).toBe(P1_PROVIDER_ID);
      expect(serviceCalls.submitFeedback[0]!.providerId).not.toBe(DELEGATE_USER_ID);
    });
  });

  // =========================================================================
  // 8. HELP ARTICLES ARE PUBLIC — intentionally NOT tenant-scoped
  // =========================================================================

  describe('Help articles are public — no tenant scoping (intentional)', () => {
    it('GET /api/v1/help/articles accessible without auth', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles?category=GETTING_STARTED',
      });
      expect(res.statusCode).toBe(200);
    });

    it('GET /api/v1/help/articles/:slug accessible without auth', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/help/articles/getting-started',
      });
      expect(res.statusCode).toBe(200);
    });

    it('articles return same content for both physicians (shared knowledge base)', async () => {
      const res1 = await asPhysician1('GET', '/api/v1/help/articles/getting-started');
      const res2 = await asPhysician2('GET', '/api/v1/help/articles/getting-started');

      expect(res1.statusCode).toBe(200);
      expect(res2.statusCode).toBe(200);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('article responses do not contain any physician-specific data', async () => {
      const res = await asPhysician1('GET', '/api/v1/help/articles/getting-started');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_USER_ID);
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('providerId');
      expect(rawBody).not.toContain('provider_id');
    });
  });

  // =========================================================================
  // 9. CROSS-PHYSICIAN 404 RESPONSE SAFETY
  // =========================================================================

  describe('Cross-physician 404 responses do not leak ticket details', () => {
    it('404 on cross-physician GET does not contain other physician ticket subject', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_1}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain('P2 claim rejection');
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_TICKET_1);
    });

    it('404 on cross-physician rating does not contain other physician ticket data', async () => {
      const res = await asPhysician1('POST', `/api/v1/support/tickets/${P2_TICKET_1}/rating`, validRatingPayload);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain('P2 claim rejection');
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain('URGENT');
      expect(rawBody).not.toContain('Corrected diagnostic code');
    });

    it('404 error shape has no data property', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_1}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(Object.keys(body)).toEqual(['error']);
    });

    it('404 error message is generic — does not mention tickets or resource type', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_1}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Resource not found');
      // Must not say "ticket not found" — would confirm resource type
    });
  });

  // =========================================================================
  // 10. BIDIRECTIONAL ISOLATION — ensure isolation works in both directions
  // =========================================================================

  describe('Bidirectional isolation — verify in both directions', () => {
    it('P1 → P2: all ticket endpoints return 404 for P2 resources', async () => {
      // GET ticket
      const getRes = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_1}`);
      expect(getRes.statusCode).toBe(404);

      // POST rating
      const rateRes = await asPhysician1('POST', `/api/v1/support/tickets/${P2_TICKET_1}/rating`, validRatingPayload);
      expect(rateRes.statusCode).toBe(404);
    });

    it('P2 → P1: all ticket endpoints return 404 for P1 resources', async () => {
      // GET ticket
      const getRes = await asPhysician2('GET', `/api/v1/support/tickets/${P1_TICKET_1}`);
      expect(getRes.statusCode).toBe(404);

      // POST rating
      const rateRes = await asPhysician2('POST', `/api/v1/support/tickets/${P1_TICKET_1}/rating`, validRatingPayload);
      expect(rateRes.statusCode).toBe(404);
    });

    it('P1 list never contains P2 ticket IDs and vice versa', async () => {
      const res1 = await asPhysician1('GET', '/api/v1/support/tickets');
      const res2 = await asPhysician2('GET', '/api/v1/support/tickets');

      const p1Ids = JSON.parse(res1.body).data.map((t: any) => t.ticketId);
      const p2Ids = JSON.parse(res2.body).data.map((t: any) => t.ticketId);

      // No overlap between the two sets
      const overlap = p1Ids.filter((id: string) => p2Ids.includes(id));
      expect(overlap).toHaveLength(0);
    });
  });
});
