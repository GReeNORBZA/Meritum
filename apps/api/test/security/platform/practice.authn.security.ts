import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
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

import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { practiceRoutes } from '../../../src/domains/platform/practice.routes.js';
import { type PracticeHandlerDeps } from '../../../src/domains/platform/practice.handlers.js';
import {
  type PracticeServiceDeps,
  type PracticeUserRepo,
  type PracticeSubscriptionRepo,
  type PracticeStripeClient,
  type PracticeAuditLogger,
  type PracticeNotifier,
} from '../../../src/domains/platform/practice.service.js';
import { type PracticeRepository } from '../../../src/domains/platform/practice.repository.js';
import { type PracticeMembershipRepository } from '../../../src/domains/platform/practice-membership.repository.js';
import { type PracticeInvitationRepository } from '../../../src/domains/platform/practice-invitation.repository.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// Expired session
const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_SESSION_TOKEN_HASH = hashToken(EXPIRED_SESSION_TOKEN);

// Fixed IDs
const PRACTICE_ID = '00000000-3333-0000-0000-000000000001';
const MEMBER_USER_ID = '00000000-1111-0000-0000-000000000004';
const RAW_TOKEN = randomBytes(32).toString('hex');

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockPractices: Array<Record<string, any>>;
let mockMemberships: Array<Record<string, any>>;
let mockInvitations: Array<Record<string, any>>;

// ---------------------------------------------------------------------------
// Mock Repos (minimal for authn tests)
// ---------------------------------------------------------------------------

function createMockUserRepo(): PracticeUserRepo {
  return {
    findUserById: vi.fn(async () => undefined),
    findUserByEmail: vi.fn(async () => undefined),
    updateUserRole: vi.fn(async () => {}),
  };
}

function createMockSubscriptionRepo(): PracticeSubscriptionRepo {
  return {
    findActiveEarlyBirdByProviderId: vi.fn(async () => null),
    findActiveSubscriptionByProviderId: vi.fn(async () => null),
    createSubscription: vi.fn(async () => ({ subscriptionId: crypto.randomUUID() })),
  };
}

function createMockStripe(): PracticeStripeClient {
  return {
    customers: {
      create: vi.fn(async () => ({ id: 'cus_test' })),
    },
    subscriptions: {
      cancel: vi.fn(async () => ({ id: 'sub_cancelled', status: 'canceled' })),
      update: vi.fn(async () => ({ id: 'sub_updated', quantity: 1 })),
      create: vi.fn(async () => ({ id: 'sub_new', status: 'active' })),
    },
  };
}

function createMockPracticeRepo(): PracticeRepository {
  return {
    createPractice: vi.fn(async () => ({})),
    findPracticeById: vi.fn(async () => null),
    findPracticeByAdminUserId: vi.fn(async () => null),
    updatePractice: vi.fn(async () => ({})),
    updatePracticeStatus: vi.fn(async () => {}),
    updatePracticeStripeIds: vi.fn(async () => {}),
    getActiveHeadcount: vi.fn(async () => 0),
    getConsolidatedSeatCount: vi.fn(async () => 0),
    findActivePractices: vi.fn(async () => []),
  } as unknown as PracticeRepository;
}

function createMockMembershipRepo(): PracticeMembershipRepository {
  return {
    createMembership: vi.fn(async () => ({})),
    findActiveMembershipByPhysicianId: vi.fn(async () => null),
    findActiveMembershipsByPracticeId: vi.fn(async () => []),
    findMembershipByPracticeAndPhysician: vi.fn(async () => null),
    setRemovalScheduled: vi.fn(async () => {}),
    deactivateMembership: vi.fn(async () => {}),
    findPendingRemovals: vi.fn(async () => []),
    deactivateAllMemberships: vi.fn(async () => {}),
    updateBillingMode: vi.fn(async () => {}),
    findMembershipsByBillingMode: vi.fn(async () => []),
    countActiveMembersByBillingMode: vi.fn(async () => 0),
  } as unknown as PracticeMembershipRepository;
}

function createMockInvitationRepo(): PracticeInvitationRepository {
  return {
    createInvitation: vi.fn(async () => ({})),
    findInvitationByTokenHash: vi.fn(async () => null),
    findPendingInvitationByEmail: vi.fn(async () => null),
    findPendingInvitationsByPracticeId: vi.fn(async () => []),
    updateInvitationStatus: vi.fn(async () => {}),
    expireInvitations: vi.fn(async () => 0),
    findInvitationsByEmail: vi.fn(async () => []),
  } as unknown as PracticeInvitationRepository;
}

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === ADMIN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: ADMIN_SESSION_ID,
            userId: ADMIN_USER_ID,
            tokenHash: ADMIN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: ADMIN_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      // Expired session token returns undefined (simulates revoked/expired)
      // Tampered tokens also return undefined (no matching session)
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const serviceDeps: PracticeServiceDeps = {
    practiceRepo: createMockPracticeRepo(),
    membershipRepo: createMockMembershipRepo(),
    invitationRepo: createMockInvitationRepo(),
    userRepo: createMockUserRepo(),
    subscriptionRepo: createMockSubscriptionRepo(),
    stripe: createMockStripe(),
    notifier: {
      sendInvitationEmail: vi.fn(async () => {}),
      sendRemovalNotification: vi.fn(async () => {}),
      sendHeadcountWarning: vi.fn(async () => {}),
      sendDissolutionNotification: vi.fn(async () => {}),
    },
    auditLogger: { log: vi.fn(async () => {}) },
  };

  const handlerDeps: PracticeHandlerDeps = {
    serviceDeps,
    practiceRepo: serviceDeps.practiceRepo,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: createMockSessionRepo(),
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: {
          code: (error as any).code ?? 'ERROR',
          message: error.message,
        },
      });
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
    request.log.error(error);
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(practiceRoutes, { deps: handlerDeps });
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
// Routes to test — all 8 practice endpoints
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const PRACTICE_ROUTES: RouteSpec[] = [
  {
    method: 'POST',
    url: '/api/v1/practices',
    payload: { name: 'Test Clinic', billing_frequency: 'MONTHLY' },
    description: 'Create practice',
  },
  {
    method: 'GET',
    url: `/api/v1/practices/${PRACTICE_ID}`,
    description: 'Get practice details',
  },
  {
    method: 'PATCH',
    url: `/api/v1/practices/${PRACTICE_ID}`,
    payload: { name: 'Updated Name' },
    description: 'Update practice',
  },
  {
    method: 'GET',
    url: `/api/v1/practices/${PRACTICE_ID}/seats`,
    description: 'Get practice seats',
  },
  {
    method: 'POST',
    url: `/api/v1/practices/${PRACTICE_ID}/invitations`,
    payload: { email: 'new@clinic.ca' },
    description: 'Send invitation',
  },
  {
    method: 'POST',
    url: `/api/v1/practice-invitations/${RAW_TOKEN}/accept`,
    payload: {},
    description: 'Accept invitation',
  },
  {
    method: 'DELETE',
    url: `/api/v1/practices/${PRACTICE_ID}/seats/${MEMBER_USER_ID}`,
    description: 'Remove physician',
  },
  {
    method: 'GET',
    url: `/api/v1/practices/${PRACTICE_ID}/invoices`,
    description: 'Get practice invoices',
  },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('D16-040: Practice Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // No Cookie — each practice route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of PRACTICE_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 without session cookie (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          ...(route.payload
            ? { payload: route.payload, headers: { 'content-type': 'application/json' } }
            : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        // No practice data leakage
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Expired Cookie — each practice route returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of PRACTICE_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 with expired session (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: {
            cookie: `session=${EXPIRED_SESSION_TOKEN}`,
            ...(route.payload ? { 'content-type': 'application/json' } : {}),
          },
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
  // Tampered Cookie — each practice route returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of PRACTICE_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 with tampered cookie (${route.description})`, async () => {
        const tamperedToken = createTamperedCookie();
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: {
            cookie: `session=${tamperedToken}`,
            ...(route.payload ? { 'content-type': 'application/json' } : {}),
          },
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
  // 401 responses must not contain any practice data
  // =========================================================================

  describe('401 responses contain no practice data or internal details', () => {
    it('401 response does not contain practice names or IDs', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/practices/${PRACTICE_ID}`,
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('Test Clinic');
      expect(rawBody).not.toContain(PRACTICE_ID);
      expect(rawBody).not.toContain('practiceName');
    });

    it('401 response does not contain stack traces or internals', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/practices/${PRACTICE_ID}/seats`,
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/practices',
        headers: { 'content-type': 'application/json' },
        payload: { name: 'My Clinic', billing_frequency: 'MONTHLY' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });
  });

  // =========================================================================
  // Sanity: valid session is accepted (confirms test setup works)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('POST /api/v1/practices returns non-401 with valid physician session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/practices',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { name: 'Test Clinic', billing_frequency: 'MONTHLY' },
      });

      expect(res.statusCode).not.toBe(401);
    });
  });
});
