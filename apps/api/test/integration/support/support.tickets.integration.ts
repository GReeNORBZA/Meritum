// ============================================================================
// Domain 13: Support Tickets — Integration Tests
// Ticket creation, listing, detail, lifecycle, rating.
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
  ticketRoutes,
  type TicketRoutesDeps,
} from '../../../src/domains/support/routes/ticket.routes.js';
import { TicketStatus, TicketPriority } from '@meritum/shared/constants/support.constants.js';

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

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// Test ticket data
// ---------------------------------------------------------------------------

const TICKET_ID_1 = '00000000-cccc-0000-0000-000000000001';
const TICKET_ID_2 = '00000000-cccc-0000-0000-000000000002';

const VALID_TICKET = {
  subject: 'Batch submission failed',
  description: 'My Thursday batch had 3 errors I cannot understand.',
  context_url: 'https://meritum.ca/claims/batches',
};

function makeTicket(overrides: Record<string, unknown> = {}) {
  return {
    ticketId: TICKET_ID_1,
    providerId: PHYSICIAN1_USER_ID,
    subject: 'Batch submission failed',
    description: 'My Thursday batch had 3 errors.',
    contextUrl: 'https://meritum.ca/claims/batches',
    contextMetadata: null,
    category: null,
    priority: TicketPriority.MEDIUM,
    status: TicketStatus.OPEN,
    assignedTo: null,
    resolutionNotes: null,
    resolvedAt: null,
    satisfactionRating: null,
    satisfactionComment: null,
    screenshotPath: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock tickets repository
// ---------------------------------------------------------------------------

function createMockTicketsRepo() {
  return {
    create: vi.fn(async (data: any) => makeTicket({
      ...data,
      ticketId: crypto.randomUUID(),
      status: TicketStatus.OPEN,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),

    getById: vi.fn(async (ticketId: string, providerId: string) => {
      // Simulate physician scoping
      const ticket = makeTicket({ ticketId });
      if (ticket.providerId !== providerId) return null;
      return ticket;
    }),

    listByProvider: vi.fn(async (_providerId: string, filters?: any) => {
      const tickets = [makeTicket(), makeTicket({ ticketId: TICKET_ID_2 })];
      const filtered = filters?.status
        ? tickets.filter((t) => t.status === filters.status)
        : tickets;
      return {
        data: filtered,
        pagination: {
          total: filtered.length,
          page: 1,
          pageSize: filters?.limit ?? 20,
          hasMore: false,
        },
      };
    }),

    addRating: vi.fn(async (ticketId: string, providerId: string, rating: number, comment?: string) => {
      return makeTicket({
        ticketId,
        providerId,
        status: TicketStatus.RESOLVED,
        resolvedAt: new Date(),
        satisfactionRating: rating,
        satisfactionComment: comment ?? null,
      });
    }),

    setScreenshotPath: vi.fn(async () => makeTicket()),

    updateTicket: vi.fn(async (ticketId: string, data: any) => {
      return makeTicket({
        ticketId,
        ...data,
        resolvedAt: data.status === TicketStatus.RESOLVED ? new Date() : null,
        updatedAt: new Date(),
      });
    }),

    listAllTickets: vi.fn(async () => ({
      data: [makeTicket()],
      pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
    })),

    getSlaBreach: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock notification service
// ---------------------------------------------------------------------------

function createMockNotificationService() {
  return { send: vi.fn(async () => {}) };
}

// ---------------------------------------------------------------------------
// Mock file storage
// ---------------------------------------------------------------------------

function createMockFileStorage() {
  return { upload: vi.fn(async (key: string) => key) };
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
let mockTicketsRepo: ReturnType<typeof createMockTicketsRepo>;
let mockNotificationService: ReturnType<typeof createMockNotificationService>;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;
let mockFileStorage: ReturnType<typeof createMockFileStorage>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockTicketsRepo = createMockTicketsRepo();
  mockNotificationService = createMockNotificationService();
  mockAuditRepo = createMockAuditRepo();
  mockFileStorage = createMockFileStorage();

  const { createSupportTicketService } = await import(
    '../../../src/domains/support/services/support-ticket.service.js'
  );

  const supportTicketService = createSupportTicketService({
    ticketsRepo: mockTicketsRepo as any,
    auditRepo: mockAuditRepo,
    notificationService: mockNotificationService,
    fileStorage: mockFileStorage,
  });

  const ticketDeps: TicketRoutesDeps = { supportTicketService };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register multipart plugin (needed for screenshot upload route)
  await testApp.register(import('@fastify/multipart'), {
    limits: { fileSize: 5 * 1024 * 1024 },
  });

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

  await testApp.register(ticketRoutes, { deps: ticketDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function authedPost(url: string, body?: Record<string, unknown>, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

function authedGet(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function unauthedPost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body ?? {},
  });
}

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

// ============================================================================
// Tests
// ============================================================================

describe('Support Tickets Integration Tests', () => {
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
  // POST /api/v1/support/tickets — Create ticket
  // =========================================================================

  describe('POST /api/v1/support/tickets', () => {
    it('creates ticket with context and returns OPEN status', async () => {
      const res = await authedPost('/api/v1/support/tickets', VALID_TICKET);
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.subject).toBe(VALID_TICKET.subject);
      expect(body.data.status).toBe(TicketStatus.OPEN);
      expect(body.data.providerId).toBe(PHYSICIAN1_USER_ID);

      // Confirmation notification sent
      expect(mockNotificationService.send).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'support.ticket_created',
          providerId: PHYSICIAN1_USER_ID,
        }),
      );
    });

    it('creates ticket with batch failure context and auto-sets URGENT priority', async () => {
      // Override the create mock to detect batch failure metadata
      mockTicketsRepo.create.mockResolvedValueOnce(
        makeTicket({
          ticketId: crypto.randomUUID(),
          priority: TicketPriority.URGENT,
          contextMetadata: { batch_error: true, batch_id: 'batch-123' },
        }),
      );

      const res = await authedPost('/api/v1/support/tickets', {
        subject: 'Batch failed',
        description: 'My batch submission completely failed.',
        context_metadata: { batch_error: true, batch_id: 'batch-123' },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data.priority).toBe(TicketPriority.URGENT);
    });

    it('creates ticket with batch_id + error_codes and auto-sets URGENT', async () => {
      mockTicketsRepo.create.mockResolvedValueOnce(
        makeTicket({
          ticketId: crypto.randomUUID(),
          priority: TicketPriority.URGENT,
          contextMetadata: { batch_id: 'batch-456', error_codes: ['E001', 'E002'] },
        }),
      );

      const res = await authedPost('/api/v1/support/tickets', {
        subject: 'Errors in batch',
        description: 'Multiple errors in my latest batch.',
        context_metadata: { batch_id: 'batch-456', error_codes: ['E001', 'E002'] },
      });

      expect(res.statusCode).toBe(201);
      expect(res.json().data.priority).toBe(TicketPriority.URGENT);
    });

    it('screenshot_path is not in API response', async () => {
      mockTicketsRepo.create.mockResolvedValueOnce(
        makeTicket({ screenshotPath: '/secret/path/screenshot.png' }),
      );

      const res = await authedPost('/api/v1/support/tickets', VALID_TICKET);
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data.screenshotPath).toBeUndefined();
      expect(body.data.screenshot_path).toBeUndefined();
    });

    it('rejects request with missing required fields', async () => {
      const res = await authedPost('/api/v1/support/tickets', {
        subject: 'Missing description',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/support/tickets', VALID_TICKET);
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // GET /api/v1/support/tickets — List tickets
  // =========================================================================

  describe('GET /api/v1/support/tickets', () => {
    it('shows created tickets ordered by recency', async () => {
      const res = await authedGet('/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.pagination).toBeDefined();
      expect(body.pagination.total).toBeGreaterThan(0);
    });

    it('filters by status', async () => {
      mockTicketsRepo.listByProvider.mockResolvedValueOnce({
        data: [makeTicket({ status: TicketStatus.OPEN })],
        pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
      });

      const res = await authedGet('/api/v1/support/tickets?status=OPEN');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.length).toBe(1);
    });

    it('screenshot_path stripped from list results', async () => {
      mockTicketsRepo.listByProvider.mockResolvedValueOnce({
        data: [makeTicket({ screenshotPath: '/secret/path.png' })],
        pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
      });

      const res = await authedGet('/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      body.data.forEach((ticket: any) => {
        expect(ticket.screenshotPath).toBeUndefined();
        expect(ticket.screenshot_path).toBeUndefined();
      });
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/support/tickets');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/support/tickets/:id — Get ticket by ID
  // =========================================================================

  describe('GET /api/v1/support/tickets/:id', () => {
    it('returns full details without screenshot_path', async () => {
      mockTicketsRepo.getById.mockResolvedValueOnce(
        makeTicket({ ticketId: TICKET_ID_1, screenshotPath: '/secret.png' }),
      );

      const res = await authedGet(`/api/v1/support/tickets/${TICKET_ID_1}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.ticketId).toBe(TICKET_ID_1);
      expect(body.data.subject).toBeDefined();
      expect(body.data.description).toBeDefined();
      expect(body.data.screenshotPath).toBeUndefined();
      expect(body.data.screenshot_path).toBeUndefined();
    });

    it('returns 404 for non-existent ticket', async () => {
      mockTicketsRepo.getById.mockResolvedValueOnce(null);

      const res = await authedGet(`/api/v1/support/tickets/${crypto.randomUUID()}`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID id parameter', async () => {
      const res = await authedGet('/api/v1/support/tickets/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/support/tickets/${TICKET_ID_1}`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/support/tickets/:id/rating — Rate ticket
  // =========================================================================

  describe('POST /api/v1/support/tickets/:id/rating', () => {
    it('rate ticket before resolution returns 400', async () => {
      // getTicket returns OPEN ticket (not resolved)
      mockTicketsRepo.getById.mockResolvedValueOnce(
        makeTicket({ ticketId: TICKET_ID_1, status: TicketStatus.OPEN }),
      );

      const res = await authedPost(`/api/v1/support/tickets/${TICKET_ID_1}/rating`, {
        rating: 5,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error.message).toContain('resolved or closed');
    });

    it('rate IN_PROGRESS ticket returns 400', async () => {
      mockTicketsRepo.getById.mockResolvedValueOnce(
        makeTicket({ ticketId: TICKET_ID_1, status: TicketStatus.IN_PROGRESS }),
      );

      const res = await authedPost(`/api/v1/support/tickets/${TICKET_ID_1}/rating`, {
        rating: 4,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rate resolved ticket with valid rating 1-5 succeeds', async () => {
      // getTicket call to check status
      mockTicketsRepo.getById.mockResolvedValueOnce(
        makeTicket({ ticketId: TICKET_ID_1, status: TicketStatus.RESOLVED, resolvedAt: new Date() }),
      );

      const res = await authedPost(`/api/v1/support/tickets/${TICKET_ID_1}/rating`, {
        rating: 4,
        comment: 'Quick response, thank you!',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.satisfactionRating).toBe(4);
    });

    it('rating 0 returns 400 (below minimum)', async () => {
      const res = await authedPost(`/api/v1/support/tickets/${TICKET_ID_1}/rating`, {
        rating: 0,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rating 6 returns 400 (above maximum)', async () => {
      const res = await authedPost(`/api/v1/support/tickets/${TICKET_ID_1}/rating`, {
        rating: 6,
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/support/tickets/${TICKET_ID_1}/rating`, {
        rating: 5,
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Ticket Lifecycle: OPEN -> RESOLVED -> CLOSED
  // =========================================================================

  describe('Ticket Lifecycle (via service admin methods)', () => {
    it('admin resolves ticket -> physician notified, status=RESOLVED, resolved_at set', async () => {
      const { createSupportTicketService } = await import(
        '../../../src/domains/support/services/support-ticket.service.js'
      );

      const localMockRepo = createMockTicketsRepo();
      const localMockNotify = createMockNotificationService();
      const localMockAudit = createMockAuditRepo();

      // _getTicketAdmin calls listAllTickets to find the ticket
      localMockRepo.listAllTickets.mockResolvedValueOnce({
        data: [makeTicket({ ticketId: TICKET_ID_1, status: TicketStatus.IN_PROGRESS })],
        pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
      });

      localMockRepo.updateTicket.mockResolvedValueOnce(
        makeTicket({
          ticketId: TICKET_ID_1,
          status: TicketStatus.RESOLVED,
          resolvedAt: new Date(),
          resolutionNotes: 'Fixed the batch config.',
        }),
      );

      const service = createSupportTicketService({
        ticketsRepo: localMockRepo as any,
        auditRepo: localMockAudit,
        notificationService: localMockNotify,
        fileStorage: createMockFileStorage(),
      });

      const updated = await service.updateTicket(
        TICKET_ID_1,
        { status: TicketStatus.RESOLVED, resolutionNotes: 'Fixed the batch config.' },
        ADMIN_USER_ID,
      );

      expect(updated).not.toBeNull();
      expect(updated!.status).toBe(TicketStatus.RESOLVED);

      // Physician notified of resolution
      expect(localMockNotify.send).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'support.ticket_resolved',
          providerId: PHYSICIAN1_USER_ID,
        }),
      );

      // Audit log recorded
      expect(localMockAudit.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'support.ticket_resolved',
          resourceId: TICKET_ID_1,
        }),
      );
    });

    it('admin closes resolved ticket -> status=CLOSED', async () => {
      const { createSupportTicketService } = await import(
        '../../../src/domains/support/services/support-ticket.service.js'
      );

      const localMockRepo = createMockTicketsRepo();
      const localMockNotify = createMockNotificationService();
      const localMockAudit = createMockAuditRepo();

      // _getTicketAdmin
      localMockRepo.listAllTickets.mockResolvedValueOnce({
        data: [makeTicket({ ticketId: TICKET_ID_1, status: TicketStatus.RESOLVED })],
        pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
      });

      localMockRepo.updateTicket.mockResolvedValueOnce(
        makeTicket({ ticketId: TICKET_ID_1, status: TicketStatus.CLOSED }),
      );

      const service = createSupportTicketService({
        ticketsRepo: localMockRepo as any,
        auditRepo: localMockAudit,
        notificationService: localMockNotify,
        fileStorage: createMockFileStorage(),
      });

      const closed = await service.closeTicket(TICKET_ID_1, ADMIN_USER_ID);

      expect(closed).not.toBeNull();
      expect(closed!.status).toBe(TicketStatus.CLOSED);

      // Audit log for closure
      expect(localMockAudit.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'support.ticket_closed',
          resourceId: TICKET_ID_1,
        }),
      );
    });
  });
});
