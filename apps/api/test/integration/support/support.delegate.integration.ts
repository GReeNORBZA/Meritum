// ============================================================================
// Domain 13: Delegate Access — Integration Tests
// Tests delegates creating tickets on behalf of physician, viewing physician's
// tickets, and verifying tickets are linked to physician's provider_id.
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

const PHYSICIAN_PROVIDER_ID = '00000000-1111-0000-0000-000000000001';
const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000002';

// Physician session
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);

// Delegate session
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Test ticket data
// ---------------------------------------------------------------------------

const TICKET_ID_1 = '00000000-cccc-0000-0000-000000000001';

const VALID_TICKET = {
  subject: 'Help with billing code',
  description: 'Need clarification on health service code 03.04A.',
};

function makeTicket(overrides: Record<string, unknown> = {}) {
  return {
    ticketId: TICKET_ID_1,
    providerId: PHYSICIAN_PROVIDER_ID,
    subject: 'Help with billing code',
    description: 'Need clarification on health service code 03.04A.',
    contextUrl: null,
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
      if (providerId !== PHYSICIAN_PROVIDER_ID) return null;
      return makeTicket({ ticketId });
    }),

    listByProvider: vi.fn(async (providerId: string) => {
      if (providerId !== PHYSICIAN_PROVIDER_ID) {
        return {
          data: [],
          pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
        };
      }
      return {
        data: [makeTicket()],
        pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
      };
    }),

    addRating: vi.fn(async () => null),
    setScreenshotPath: vi.fn(async () => makeTicket()),
    updateTicket: vi.fn(async () => makeTicket()),
    listAllTickets: vi.fn(async () => ({
      data: [makeTicket()],
      pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
    })),
    getSlaBreach: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

function createMockNotificationService() {
  return { send: vi.fn(async () => {}) };
}

function createMockFileStorage() {
  return { upload: vi.fn(async (key: string) => key) };
}

function createMockAuditRepo() {
  return { appendAuditLog: vi.fn(async () => {}) };
}

// ---------------------------------------------------------------------------
// Mock session repo — supports both physician and delegate sessions
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      // Physician session
      if (tokenHash === PHYSICIAN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000001',
            userId: PHYSICIAN_PROVIDER_ID,
            tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN_PROVIDER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }

      // Delegate session — has delegateContext pointing to physician
      if (tokenHash === DELEGATE_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000002',
            userId: DELEGATE_USER_ID,
            tokenHash: DELEGATE_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: DELEGATE_USER_ID,
            role: 'delegate',
            subscriptionStatus: 'ACTIVE',
            delegateContext: {
              delegateUserId: DELEGATE_USER_ID,
              physicianProviderId: PHYSICIAN_PROVIDER_ID,
              permissions: ['SUPPORT_VIEW', 'SUPPORT_CREATE'],
              linkageId: 'link-delegate-1',
            },
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

async function buildTestApp(): Promise<FastifyInstance> {
  mockTicketsRepo = createMockTicketsRepo();
  mockNotificationService = createMockNotificationService();

  const { createSupportTicketService } = await import(
    '../../../src/domains/support/services/support-ticket.service.js'
  );

  const supportTicketService = createSupportTicketService({
    ticketsRepo: mockTicketsRepo as any,
    auditRepo: createMockAuditRepo(),
    notificationService: mockNotificationService,
    fileStorage: createMockFileStorage(),
  });

  const ticketDeps: TicketRoutesDeps = { supportTicketService };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(import('@fastify/multipart'), {
    limits: { fileSize: 5 * 1024 * 1024 },
  });

  // Auth plugin with both physician and delegate sessions
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

function delegatePost(url: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${DELEGATE_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body,
  });
}

function delegateGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
  });
}

function physicianGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
  });
}

// ============================================================================
// Tests
// ============================================================================

describe('Support Delegate Access Integration Tests', () => {
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
  // Delegate creates tickets on behalf of physician
  // =========================================================================

  describe('Delegate ticket creation', () => {
    it('delegate can create support ticket on behalf of physician', async () => {
      const res = await delegatePost('/api/v1/support/tickets', VALID_TICKET);
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.subject).toBe(VALID_TICKET.subject);
      expect(body.data.status).toBe(TicketStatus.OPEN);
    });

    it('delegate-created ticket is linked to physician provider_id (not delegate)', async () => {
      const res = await delegatePost('/api/v1/support/tickets', VALID_TICKET);
      expect(res.statusCode).toBe(201);

      // Verify the repo create was called with the physician's provider_id
      expect(mockTicketsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PHYSICIAN_PROVIDER_ID,
        }),
      );

      // The ticket should NOT have the delegate's user ID as provider
      const createArg = mockTicketsRepo.create.mock.calls[0][0];
      expect(createArg.providerId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(createArg.providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('notification is sent to physician (not delegate)', async () => {
      await delegatePost('/api/v1/support/tickets', VALID_TICKET);

      expect(mockNotificationService.send).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'support.ticket_created',
          providerId: PHYSICIAN_PROVIDER_ID,
        }),
      );
    });
  });

  // =========================================================================
  // Delegate views physician's tickets
  // =========================================================================

  describe('Delegate ticket viewing', () => {
    it('delegate can view physician tickets', async () => {
      const res = await delegateGet('/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.length).toBeGreaterThan(0);

      // Verify the repo was called with physician's provider_id
      expect(mockTicketsRepo.listByProvider).toHaveBeenCalledWith(
        PHYSICIAN_PROVIDER_ID,
        expect.any(Object),
      );
    });

    it('delegate sees physician ticket by ID', async () => {
      const res = await delegateGet(`/api/v1/support/tickets/${TICKET_ID_1}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.ticketId).toBe(TICKET_ID_1);
      expect(body.data.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    });

    it('physician also sees the same tickets', async () => {
      const res = await physicianGet('/api/v1/support/tickets');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.length).toBeGreaterThan(0);
    });
  });

  // =========================================================================
  // Verify provider scoping is correct for delegates
  // =========================================================================

  describe('Delegate provider scoping', () => {
    it('all ticket operations use physician provider_id from delegateContext', async () => {
      // Create
      await delegatePost('/api/v1/support/tickets', VALID_TICKET);
      expect(mockTicketsRepo.create.mock.calls[0][0].providerId).toBe(PHYSICIAN_PROVIDER_ID);

      vi.clearAllMocks();

      // List
      await delegateGet('/api/v1/support/tickets');
      expect(mockTicketsRepo.listByProvider).toHaveBeenCalledWith(
        PHYSICIAN_PROVIDER_ID,
        expect.any(Object),
      );

      vi.clearAllMocks();

      // Get by ID
      await delegateGet(`/api/v1/support/tickets/${TICKET_ID_1}`);
      expect(mockTicketsRepo.getById).toHaveBeenCalledWith(
        TICKET_ID_1,
        PHYSICIAN_PROVIDER_ID,
      );
    });
  });
});
