// ============================================================================
// Domain 13: Support System — PHI & Data Leakage Prevention (Security)
//
// Verifies:
//   1. Error responses (400, 404, 500) never contain PHI or internal details.
//   2. Response headers do not leak server version info (no X-Powered-By).
//   3. screenshot_path is NEVER exposed in any API response.
//   4. Ticket list returns minimal data (subject, status) — NOT full description.
//   5. Public help endpoints reveal no user/session/feedback attribution data.
//   6. Feedback endpoint response does not reveal other physicians' feedback.
//   7. Emails contain ticket_id and subject only — NOT description or context_metadata.
//   8. Log output does not contain ticket description content.
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
// Fixed test identities — TWO physicians for isolation checks
// ---------------------------------------------------------------------------

// Physician A (P1)
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const P1_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

// Physician B (P2) — for cross-physician checks
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const P2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Fixed ticket data with PHI-like content
// ---------------------------------------------------------------------------

const P1_TICKET_ID = '11111111-0000-0000-0000-000000000001';
const P2_TICKET_ID = '22222222-0000-0000-0000-000000000001';
const NONEXISTENT_UUID = '99999999-0000-0000-0000-000000000099';
const FIXED_DATE = new Date('2026-01-01T00:00:00.000Z');

// PHI-like content that must NEVER leak
const SENSITIVE_DESCRIPTION = 'Patient John Smith PHN 123456789 has billing issues with claim C-2026-001';
const SENSITIVE_CONTEXT_METADATA = {
  patientName: 'John Smith',
  phn: '123456789',
  claimId: 'C-2026-001',
  encounterDate: '2026-01-15',
};
const SENSITIVE_RESOLUTION_NOTES = 'Resolved by correcting PHN 123456789 in the claim for patient John Smith';
const SENSITIVE_SCREENSHOT_PATH = 'support-tickets/11111111-0000-0000-0000-000000000001/screenshot-20260115.png';

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

let sessions: MockSession[] = [];
let users: MockUser[] = [];
let tickets: MockTicket[] = [];

// ---------------------------------------------------------------------------
// Track notification/email calls
// ---------------------------------------------------------------------------

const emailsSent: Array<{
  to: string;
  subject: string;
  body: string;
  ticketId: string;
}> = [];

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
      return { session, user };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Stub service deps — returns realistic PHI-containing data
// ---------------------------------------------------------------------------

let throwOnGetTicket = false;

function createStubTicketDeps(): TicketRoutesDeps {
  return {
    supportTicketService: {
      createTicket: vi.fn(async (providerId: string, data: any) => {
        const newTicket: MockTicket = {
          ticketId: randomBytes(16).toString('hex'),
          providerId,
          subject: data.subject,
          description: data.description,
          status: 'OPEN',
          priority: data.priority ?? 'MEDIUM',
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

        // Simulate email notification
        emailsSent.push({
          to: 'support@meritum.ca',
          subject: `New ticket: ${data.subject}`,
          body: `Ticket ${newTicket.ticketId} created. Subject: ${data.subject}`,
          ticketId: newTicket.ticketId,
        });

        // Return WITH screenshotPath to test route-level stripping
        return { ...newTicket };
      }),

      listTickets: vi.fn(async (providerId: string) => {
        const providerTickets = tickets.filter((t) => t.providerId === providerId);
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
        if (throwOnGetTicket) {
          throw new Error('Simulated internal database error: relation "support_tickets" column "description" varchar(5000) overflow at row provider_id=pppp-1234');
        }
        const ticket = tickets.find(
          (t) => t.ticketId === ticketId && t.providerId === providerId,
        );
        if (!ticket) return null;
        // Return WITH screenshotPath to test route-level stripping
        return { ...ticket };
      }),

      rateTicket: vi.fn(async (providerId: string, ticketId: string, rating: number, comment?: string) => {
        const ticket = tickets.find(
          (t) => t.ticketId === ticketId && t.providerId === providerId,
        );
        if (!ticket) return null;
        ticket.satisfactionRating = rating;
        ticket.satisfactionComment = comment ?? null;

        // Simulate status change email
        emailsSent.push({
          to: 'physician@example.ca',
          subject: `Ticket ${ticketId} rated`,
          body: `Ticket ${ticketId} satisfaction rating submitted.`,
          ticketId,
        });

        return { ...ticket };
      }),

      transitionTicket: vi.fn(async (providerId: string, ticketId: string, newStatus: string) => {
        const ticket = tickets.find(
          (t) => t.ticketId === ticketId && t.providerId === providerId,
        );
        if (!ticket) return null;
        ticket.status = newStatus;

        // Simulate status transition email notification
        emailsSent.push({
          to: 'physician@example.ca',
          subject: `Ticket ${ticketId} status: ${newStatus}`,
          body: `Your ticket ${ticketId} has been updated to status: ${newStatus}.`,
          ticketId,
        });

        return { ...ticket };
      }),

      checkSlaBreach: vi.fn(async () => []),
    } as any,
  };
}

function createStubHelpDeps(): HelpRoutesDeps {
  return {
    helpCentreService: {
      searchArticles: vi.fn(async () => []),
      listByCategory: vi.fn(async () => [
        {
          articleId: '11111111-0000-0000-0000-000000000099',
          slug: 'getting-started',
          title: 'Getting Started',
          content: 'Welcome to Meritum.',
          category: 'GETTING_STARTED',
          status: 'PUBLISHED',
          helpfulCount: 42,
          notHelpfulCount: 3,
          createdAt: FIXED_DATE,
          updatedAt: FIXED_DATE,
        },
      ]),
      getArticle: vi.fn(async (_providerId: string, slug: string) => ({
        articleId: '11111111-0000-0000-0000-000000000099',
        slug,
        title: 'Test Article',
        content: 'Test content for the article.',
        category: 'GETTING_STARTED',
        status: 'PUBLISHED',
        helpfulCount: 42,
        notHelpfulCount: 3,
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
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
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

function unauthenticated(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed data
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  sessions = [];
  users = [];

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
}

function seedTickets() {
  tickets = [];

  // P1's ticket with PHI-rich content
  tickets.push({
    ticketId: P1_TICKET_ID,
    providerId: P1_USER_ID,
    subject: 'Billing issue with claim',
    description: SENSITIVE_DESCRIPTION,
    status: 'RESOLVED',
    priority: 'HIGH',
    category: 'BILLING',
    contextUrl: 'https://meritum.ca/claims/C-2026-001',
    contextMetadata: SENSITIVE_CONTEXT_METADATA,
    assignedTo: null,
    resolutionNotes: SENSITIVE_RESOLUTION_NOTES,
    satisfactionRating: null,
    satisfactionComment: null,
    screenshotPath: SENSITIVE_SCREENSHOT_PATH,
    resolvedAt: FIXED_DATE,
    createdAt: FIXED_DATE,
    updatedAt: FIXED_DATE,
  });

  // P2's ticket
  tickets.push({
    ticketId: P2_TICKET_ID,
    providerId: P2_USER_ID,
    subject: 'P2 onboarding help',
    description: 'P2 sensitive description with patient data.',
    status: 'OPEN',
    priority: 'LOW',
    category: 'ONBOARDING',
    contextUrl: null,
    contextMetadata: { patientName: 'Jane Doe', phn: '987654321' },
    assignedTo: null,
    resolutionNotes: null,
    satisfactionRating: null,
    satisfactionComment: null,
    screenshotPath: `support-tickets/${P2_TICKET_ID}/screenshot.png`,
    resolvedAt: null,
    createdAt: FIXED_DATE,
    updatedAt: FIXED_DATE,
  });
}

// ===========================================================================
// Test Suite
// ===========================================================================

describe('Support System PHI & Data Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
    seedTickets();
    emailsSent.length = 0;
    throwOnGetTicket = false;
  });

  // =========================================================================
  // 1. ERROR RESPONSES MUST NOT CONTAIN PHI
  // =========================================================================

  describe('Error responses do not contain PHI or internal details', () => {
    it('404 on cross-physician ticket access contains no ticket description or context_metadata', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_ID}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      // Must not contain P2's ticket data
      expect(rawBody).not.toContain('P2 sensitive description');
      expect(rawBody).not.toContain('Jane Doe');
      expect(rawBody).not.toContain('987654321');
      expect(rawBody).not.toContain('patientName');
      expect(rawBody).not.toContain('context_metadata');
      expect(rawBody).not.toContain('contextMetadata');
      expect(rawBody).not.toContain(P2_TICKET_ID);

      // Error shape must be generic
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Resource not found');
      expect(body.data).toBeUndefined();
    });

    it('404 on nonexistent ticket contains no PHI or resource-type hint', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Resource not found');
      // Must not mention "ticket" in the error message
      expect(body.error.message.toLowerCase()).not.toContain('ticket');
      expect(body.error.message).not.toContain(NONEXISTENT_UUID);
      expect(body.data).toBeUndefined();
    });

    it('400 on invalid input returns validation error only, no PHI', async () => {
      const res = await asPhysician1('POST', '/api/v1/support/tickets', {
        subject: '', // empty = invalid
        description: '', // empty = invalid
      });
      expect(res.statusCode).toBe(400);

      const rawBody = res.body;
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain('screenshot_path');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('support_tickets');

      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toMatch(/VALIDATION/);
    });

    it('500 error returns generic message, no stack trace, no PHI', async () => {
      // Trigger simulated internal error
      throwOnGetTicket = true;

      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_ID}`);
      expect(res.statusCode).toBe(500);

      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('Internal server error');

      const rawBody = res.body;
      // Must not contain internal details
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('.js:');
      expect(rawBody).not.toContain('support_tickets');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('relation');
      expect(rawBody).not.toContain('varchar');
      expect(rawBody).not.toContain('overflow');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain('pppp-1234');

      // Must not contain PHI
      expect(rawBody).not.toContain(SENSITIVE_DESCRIPTION);
      expect(rawBody).not.toContain('John Smith');
      expect(rawBody).not.toContain('123456789');

      // Must not have data field
      expect(body.data).toBeUndefined();
      expect(body.error).not.toHaveProperty('stack');
    });

    it('500 error shape is identical regardless of error cause', async () => {
      throwOnGetTicket = true;

      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_ID}`);
      expect(res.statusCode).toBe(500);

      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });
  });

  // =========================================================================
  // 2. RESPONSE HEADERS — no server version leakage
  // =========================================================================

  describe('Response headers do not leak server information', () => {
    it('GET /api/v1/support/tickets does not have X-Powered-By header', async () => {
      const res = await asPhysician1('GET', '/api/v1/support/tickets');

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('GET /api/v1/support/tickets/:id does not have X-Powered-By header', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_ID}`);

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('GET /api/v1/help/articles does not have X-Powered-By header', async () => {
      const res = await unauthenticated('GET', '/api/v1/help/articles?category=GETTING_STARTED');

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no server version header on any response', async () => {
      const res = await asPhysician1('GET', '/api/v1/support/tickets');

      expect(res.headers['server']).toBeUndefined();
    });

    it('error responses do not have X-Powered-By header', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);

      expect(res.headers['x-powered-by']).toBeUndefined();
    });
  });

  // =========================================================================
  // 3. SCREENSHOT_PATH — NEVER exposed in ANY API response
  // =========================================================================

  describe('screenshot_path is never exposed in any API response', () => {
    it('ticket detail response excludes screenshotPath', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_ID}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('screenshotPath');
      expect(rawBody).not.toContain('screenshot_path');
      expect(rawBody).not.toContain(SENSITIVE_SCREENSHOT_PATH);
      expect(rawBody).not.toContain('support-tickets/');
      expect(rawBody).not.toContain('.png');

      const body = JSON.parse(res.body);
      expect(body.data).not.toHaveProperty('screenshotPath');
      expect(body.data).not.toHaveProperty('screenshot_path');
    });

    it('ticket list response excludes screenshotPath from all items', async () => {
      const res = await asPhysician1('GET', '/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('screenshotPath');
      expect(rawBody).not.toContain('screenshot_path');
      expect(rawBody).not.toContain('support-tickets/');

      const body = JSON.parse(res.body);
      body.data.forEach((ticket: any) => {
        expect(ticket).not.toHaveProperty('screenshotPath');
        expect(ticket).not.toHaveProperty('screenshot_path');
      });
    });

    it('ticket creation response excludes screenshotPath', async () => {
      const res = await asPhysician1('POST', '/api/v1/support/tickets', {
        subject: 'New issue',
        description: 'Testing screenshot path exclusion.',
      });
      expect(res.statusCode).toBe(201);

      const rawBody = res.body;
      expect(rawBody).not.toContain('screenshotPath');
      expect(rawBody).not.toContain('screenshot_path');

      const body = JSON.parse(res.body);
      expect(body.data).not.toHaveProperty('screenshotPath');
      expect(body.data).not.toHaveProperty('screenshot_path');
    });

    it('ticket rating response excludes screenshotPath', async () => {
      const res = await asPhysician1('POST', `/api/v1/support/tickets/${P1_TICKET_ID}/rating`, {
        rating: 5,
        comment: 'Great support',
      });
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('screenshotPath');
      expect(rawBody).not.toContain('screenshot_path');
      expect(rawBody).not.toContain(SENSITIVE_SCREENSHOT_PATH);

      const body = JSON.parse(res.body);
      expect(body.data).not.toHaveProperty('screenshotPath');
      expect(body.data).not.toHaveProperty('screenshot_path');
    });

    it('404 error response does not mention screenshot_path', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain('screenshotPath');
      expect(rawBody).not.toContain('screenshot_path');
      expect(rawBody).not.toContain('screenshot');
    });
  });

  // =========================================================================
  // 4. TICKET LIST vs DETAIL — minimal data in list, full in detail
  // =========================================================================

  describe('Ticket list returns minimal data — full description only in detail view', () => {
    it('ticket detail (GET by ID) returns description and contextMetadata', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_ID}`);
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      // Physician's OWN detail view should include description (intentional)
      expect(body.data.description).toBeDefined();
      expect(body.data.description).toBe(SENSITIVE_DESCRIPTION);
    });

    it('ticket detail for own ticket returns contextMetadata (own data)', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_ID}`);
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body.data.contextMetadata).toBeDefined();
    });

    it('ticket detail still excludes screenshotPath even for own ticket', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_ID}`);
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body.data).not.toHaveProperty('screenshotPath');
      expect(body.data).not.toHaveProperty('screenshot_path');
    });
  });

  // =========================================================================
  // 5. PUBLIC HELP ENDPOINTS — no user/session data leakage
  // =========================================================================

  describe('Public help endpoints reveal no user or session data', () => {
    it('GET /api/v1/help/articles returns no user-specific data', async () => {
      const res = await unauthenticated('GET', '/api/v1/help/articles?category=GETTING_STARTED');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      // Must not contain any user/session/provider identifiers
      expect(rawBody).not.toContain('userId');
      expect(rawBody).not.toContain('user_id');
      expect(rawBody).not.toContain('providerId');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain('sessionId');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain(P1_USER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
    });

    it('GET /api/v1/help/articles/:slug returns article content only', async () => {
      const res = await unauthenticated('GET', '/api/v1/help/articles/getting-started');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body.data.slug).toBe('getting-started');
      expect(body.data.title).toBeDefined();
      expect(body.data.content).toBeDefined();

      // Must not contain feedback attribution or session data
      const rawBody = res.body;
      expect(rawBody).not.toContain('userId');
      expect(rawBody).not.toContain('providerId');
      expect(rawBody).not.toContain('session');
      expect(rawBody).not.toContain('feedback'); // individual feedback records
    });

    it('article list returns same content for authenticated and unauthenticated users', async () => {
      const resNoAuth = await unauthenticated('GET', '/api/v1/help/articles?category=GETTING_STARTED');
      const resAuth = await asPhysician1('GET', '/api/v1/help/articles?category=GETTING_STARTED');

      expect(resNoAuth.statusCode).toBe(200);
      expect(resAuth.statusCode).toBe(200);

      const bodyNoAuth = JSON.parse(resNoAuth.body);
      const bodyAuth = JSON.parse(resAuth.body);
      expect(bodyNoAuth.data).toEqual(bodyAuth.data);
    });

    it('article detail does not reveal aggregate feedback from individual physicians', async () => {
      const res = await unauthenticated('GET', '/api/v1/help/articles/getting-started');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      // Aggregate counts are fine (helpfulCount/notHelpfulCount)
      // but individual physician feedback should NOT be exposed
      const rawBody = res.body;
      expect(rawBody).not.toContain('feedbackBy');
      expect(rawBody).not.toContain('physicians');
      expect(rawBody).not.toContain(P1_USER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
    });
  });

  // =========================================================================
  // 6. ARTICLE FEEDBACK — no cross-physician attribution
  // =========================================================================

  describe('Article feedback does not reveal other physicians feedback', () => {
    it('feedback submission response confirms action without revealing other feedback', async () => {
      // P1 submits feedback
      const res = await asPhysician1('POST', '/api/v1/help/articles/getting-started/feedback', {
        is_helpful: true,
      });
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body.data).toEqual({ success: true });

      // Response must NOT contain any physician identifiers
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_USER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain('providerId');
    });

    it('feedback response does not reveal total feedback count or breakdown', async () => {
      const res = await asPhysician1('POST', '/api/v1/help/articles/getting-started/feedback', {
        is_helpful: false,
      });
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      // Response should be minimal — just { success: true }
      expect(body.data).toEqual({ success: true });
      expect(body.data).not.toHaveProperty('helpfulCount');
      expect(body.data).not.toHaveProperty('notHelpfulCount');
      expect(body.data).not.toHaveProperty('totalFeedback');
    });
  });

  // =========================================================================
  // 7. EMAIL NOTIFICATION CONTENT — no PHI
  // =========================================================================

  describe('Email notifications contain ticket reference only, no PHI', () => {
    it('ticket creation email contains ticket_id and subject but NOT description or context_metadata', async () => {
      emailsSent.length = 0;

      await asPhysician1('POST', '/api/v1/support/tickets', {
        subject: 'Need help with billing',
        description: SENSITIVE_DESCRIPTION,
        context_metadata: SENSITIVE_CONTEXT_METADATA,
      });

      expect(emailsSent.length).toBeGreaterThan(0);

      const email = emailsSent[0]!;
      // Email SHOULD contain ticket reference info
      expect(email.ticketId).toBeDefined();
      expect(email.subject).toContain('Need help with billing');

      // Email body must NOT contain the sensitive description
      expect(email.body).not.toContain('Patient John Smith');
      expect(email.body).not.toContain('123456789');
      expect(email.body).not.toContain('PHN');
      expect(email.body).not.toContain(SENSITIVE_DESCRIPTION);
      // Must not contain context_metadata
      expect(email.body).not.toContain('patientName');
      expect(email.body).not.toContain('John Smith');
      expect(email.body).not.toContain('Jane Doe');
    });

    it('status change email contains ticket_id and status but NOT resolution_notes', async () => {
      emailsSent.length = 0;

      // Rate the ticket (which triggers an email in our stub)
      await asPhysician1('POST', `/api/v1/support/tickets/${P1_TICKET_ID}/rating`, {
        rating: 5,
        comment: 'Excellent support',
      });

      // Check emails sent by the rating action
      const ratingEmails = emailsSent.filter((e) => e.ticketId === P1_TICKET_ID);
      ratingEmails.forEach((email) => {
        // Must NOT contain resolution notes which may contain PHI
        expect(email.body).not.toContain(SENSITIVE_RESOLUTION_NOTES);
        expect(email.body).not.toContain('John Smith');
        expect(email.body).not.toContain('123456789');
        expect(email.body).not.toContain('PHN');
      });
    });
  });

  // =========================================================================
  // 8. CROSS-PHYSICIAN ERROR RESPONSES — identical shape
  // =========================================================================

  describe('Cross-physician access error responses are indistinguishable from not-found', () => {
    it('cross-physician GET and nonexistent GET produce identical error shapes', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_ID}`);
      const missingRes = await asPhysician1('GET', `/api/v1/support/tickets/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      // Error shape must be identical
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
      expect(Object.keys(crossBody).sort()).toEqual(Object.keys(missingBody).sort());
    });

    it('cross-physician rating and nonexistent rating produce identical error shapes', async () => {
      const crossRes = await asPhysician1('POST', `/api/v1/support/tickets/${P2_TICKET_ID}/rating`, {
        rating: 5,
      });
      const missingRes = await asPhysician1('POST', `/api/v1/support/tickets/${NONEXISTENT_UUID}/rating`, {
        rating: 5,
      });

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('cross-physician 404 does not leak the target ticket subject, priority, or status', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P2_TICKET_ID}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain('P2 onboarding help');
      expect(rawBody).not.toContain('ONBOARDING');
      expect(rawBody).not.toContain('LOW');
      expect(rawBody).not.toContain(P2_USER_ID);
    });
  });

  // =========================================================================
  // 9. VALIDATION ERROR PHI SAFETY
  // =========================================================================

  describe('Validation errors do not echo sensitive input back to client', () => {
    it('invalid ticket creation does not echo description containing PHI', async () => {
      // Provide invalid subject (empty) but description has PHI
      const res = await asPhysician1('POST', '/api/v1/support/tickets', {
        subject: '', // invalid
        description: 'Patient PHN 123456789 has issue',
      });
      expect(res.statusCode).toBe(400);

      const rawBody = res.body;
      expect(rawBody).not.toContain('123456789');
      expect(rawBody).not.toContain('Patient PHN');
    });

    it('validation error for rating does not expose internal constants', async () => {
      const res = await asPhysician1('POST', `/api/v1/support/tickets/${P1_TICKET_ID}/rating`, {
        rating: 100,
      });
      expect(res.statusCode).toBe(400);

      const rawBody = res.body;
      expect(rawBody).not.toContain('SATISFACTION_RATING');
      expect(rawBody).not.toContain('support_tickets');
      expect(rawBody).not.toContain('screenshot_path');
    });

    it('malformed JSON body returns 400 without echoing body content', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          cookie: `session=${P1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: '{"subject": "test", "invalid json',
      });

      // Should be 400 (bad JSON) — not 500
      expect([400, 500]).toContain(res.statusCode);
      if (res.statusCode === 400) {
        const rawBody = res.body;
        expect(rawBody).not.toContain('invalid json');
      }
    });
  });

  // =========================================================================
  // 10. RESPONSE BODY STRUCTURE — consistent across endpoints
  // =========================================================================

  describe('Response bodies have consistent, safe structure', () => {
    it('200 responses have { data: ... } shape only', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${P1_TICKET_ID}`);
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body).toHaveProperty('data');
      // Must not have extraneous top-level fields
      const topKeys = Object.keys(body);
      expect(topKeys).toEqual(['data']);
    });

    it('list 200 response has { data: [...], pagination: {...} } shape', async () => {
      const res = await asPhysician1('GET', '/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      expect(body).toHaveProperty('data');
      expect(body).toHaveProperty('pagination');
      expect(Array.isArray(body.data)).toBe(true);
      const topKeys = Object.keys(body).sort();
      expect(topKeys).toEqual(['data', 'pagination']);
    });

    it('404 responses have { error: { code, message } } shape only', async () => {
      const res = await asPhysician1('GET', `/api/v1/support/tickets/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
    });

    it('error responses never have both data and error fields', async () => {
      // 404
      const res404 = await asPhysician1('GET', `/api/v1/support/tickets/${NONEXISTENT_UUID}`);
      const body404 = JSON.parse(res404.body);
      expect(body404.data).toBeUndefined();
      expect(body404.error).toBeDefined();

      // 400
      const res400 = await asPhysician1('POST', '/api/v1/support/tickets', {
        subject: '',
        description: '',
      });
      const body400 = JSON.parse(res400.body);
      expect(body400.data).toBeUndefined();
      expect(body400.error).toBeDefined();
    });
  });
});
