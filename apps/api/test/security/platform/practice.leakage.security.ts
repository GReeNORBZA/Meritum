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
} from '../../../src/domains/platform/practice.service.js';
import { type PracticeRepository } from '../../../src/domains/platform/practice.repository.js';
import { type PracticeMembershipRepository } from '../../../src/domains/platform/practice-membership.repository.js';
import { type PracticeInvitationRepository } from '../../../src/domains/platform/practice-invitation.repository.js';

const BillingMode = {
  PRACTICE_CONSOLIDATED: 'PRACTICE_CONSOLIDATED',
  INDIVIDUAL_EARLY_BIRD: 'INDIVIDUAL_EARLY_BIRD',
} as const;

const PracticeStatus = {
  ACTIVE: 'ACTIVE',
  SUSPENDED: 'SUSPENDED',
  CANCELLED: 'CANCELLED',
} as const;

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

// PRACTICE_ADMIN of Practice A
const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// Regular PHYSICIAN (not an admin of any practice)
const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000002';

// DELEGATE user
const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000050';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '00000000-2222-0000-0000-000000000050';

// Fixed IDs
const PRACTICE_ID = '00000000-3333-0000-0000-000000000001';
const NON_EXISTENT_PRACTICE_ID = '00000000-3333-0000-0000-000000000099';
const MEMBER_USER_ID = '00000000-1111-0000-0000-000000000004';
const MEMBERSHIP_ADMIN_ID = '00000000-4444-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockPractices: Array<Record<string, any>>;
let mockMemberships: Array<Record<string, any>>;

// ---------------------------------------------------------------------------
// Mock Repos
// ---------------------------------------------------------------------------

function createMockUserRepo(): PracticeUserRepo {
  return {
    findUserById: vi.fn(async (userId: string) => {
      const users: Record<string, any> = {
        [ADMIN_USER_ID]: { userId: ADMIN_USER_ID, email: 'admin@clinic.ca', fullName: 'Dr. Admin', role: 'PHYSICIAN' },
        [PHYSICIAN_USER_ID]: { userId: PHYSICIAN_USER_ID, email: 'physician@clinic.ca', fullName: 'Dr. Physician', role: 'PHYSICIAN' },
        [DELEGATE_USER_ID]: { userId: DELEGATE_USER_ID, email: 'delegate@clinic.ca', fullName: 'Delegate User', role: 'DELEGATE' },
      };
      return users[userId];
    }),
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
    customers: { create: vi.fn(async () => ({ id: 'cus_test' })) },
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
    findPracticeById: vi.fn(async (practiceId: string) => {
      return mockPractices.find((p) => p.practiceId === practiceId) ?? null;
    }),
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
      const sessions: Record<string, any> = {
        [ADMIN_SESSION_TOKEN_HASH]: {
          session: { sessionId: ADMIN_SESSION_ID, userId: ADMIN_USER_ID, tokenHash: ADMIN_SESSION_TOKEN_HASH, createdAt: new Date(), lastActiveAt: new Date(), revoked: false },
          user: { userId: ADMIN_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'ACTIVE' },
        },
        [PHYSICIAN_SESSION_TOKEN_HASH]: {
          session: { sessionId: PHYSICIAN_SESSION_ID, userId: PHYSICIAN_USER_ID, tokenHash: PHYSICIAN_SESSION_TOKEN_HASH, createdAt: new Date(), lastActiveAt: new Date(), revoked: false },
          user: { userId: PHYSICIAN_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'ACTIVE' },
        },
        [DELEGATE_SESSION_TOKEN_HASH]: {
          session: { sessionId: DELEGATE_SESSION_ID, userId: DELEGATE_USER_ID, tokenHash: DELEGATE_SESSION_TOKEN_HASH, createdAt: new Date(), lastActiveAt: new Date(), revoked: false },
          user: { userId: DELEGATE_USER_ID, role: 'DELEGATE', subscriptionStatus: 'ACTIVE' },
        },
      };
      return sessions[tokenHash] ?? undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function seedPracticeA() {
  mockPractices.push({
    practiceId: PRACTICE_ID,
    name: 'Test Clinic A',
    adminUserId: ADMIN_USER_ID,
    stripeCustomerId: 'cus_practice_a_secret',
    stripeSubscriptionId: 'sub_practice_a_secret',
    billingFrequency: 'MONTHLY',
    status: PracticeStatus.ACTIVE,
    currentPeriodStart: new Date(),
    currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  mockMemberships.push({
    membershipId: MEMBERSHIP_ADMIN_ID,
    practiceId: PRACTICE_ID,
    physicianUserId: ADMIN_USER_ID,
    billingMode: BillingMode.PRACTICE_CONSOLIDATED,
    joinedAt: new Date(),
    removedAt: null,
    removalEffectiveAt: null,
    isActive: true,
    createdAt: new Date(),
  });
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let serviceDeps: PracticeServiceDeps;

async function buildTestApp(): Promise<FastifyInstance> {
  serviceDeps = {
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
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
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
// Request helpers
// ---------------------------------------------------------------------------

function authedGet(url: string, token = ADMIN_SESSION_TOKEN) {
  return app.inject({ method: 'GET', url, headers: { cookie: `session=${token}` } });
}

function authedPost(url: string, body: Record<string, unknown>, token = ADMIN_SESSION_TOKEN) {
  return app.inject({
    method: 'POST', url,
    headers: { cookie: `session=${token}`, 'content-type': 'application/json' },
    payload: body,
  });
}

function authedPatch(url: string, body: Record<string, unknown>, token = ADMIN_SESSION_TOKEN) {
  return app.inject({
    method: 'PATCH', url,
    headers: { cookie: `session=${token}`, 'content-type': 'application/json' },
    payload: body,
  });
}

function authedDelete(url: string, token = ADMIN_SESSION_TOKEN) {
  return app.inject({ method: 'DELETE', url, headers: { cookie: `session=${token}` } });
}

function unauthGet(url: string) {
  return app.inject({ method: 'GET', url });
}

function unauthPost(url: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'POST', url,
    headers: { 'content-type': 'application/json' },
    payload: body,
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('D16-044: Practice Error Response Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    mockPractices = [];
    mockMemberships = [];
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockPractices = [];
    mockMemberships = [];
    vi.clearAllMocks();
  });

  // =========================================================================
  // 401 responses do not leak practice data
  // =========================================================================

  describe('401 responses do not leak practice or member details', () => {
    it('401 on GET /practices/:id does not reveal practice name', async () => {
      seedPracticeA();
      const res = await unauthGet(`/api/v1/practices/${PRACTICE_ID}`);
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('Test Clinic A');
      expect(res.body).not.toContain('admin@clinic.ca');
      expect(res.body).not.toContain(ADMIN_USER_ID);
    });

    it('401 on GET /practices/:id/seats does not reveal member info', async () => {
      seedPracticeA();
      const res = await unauthGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('Dr. Admin');
      expect(res.body).not.toContain('admin@clinic.ca');
      expect(res.body).not.toContain('physicianName');
    });

    it('401 on GET /practices/:id/invoices does not reveal billing data', async () => {
      seedPracticeA();
      const res = await unauthGet(`/api/v1/practices/${PRACTICE_ID}/invoices`);
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('totalAmount');
      expect(res.body).not.toContain('perSeatRate');
      expect(res.body).not.toContain('billingFrequency');
    });

    it('401 on POST /practices does not reveal any practice data', async () => {
      const res = await unauthPost('/api/v1/practices', {
        name: 'Test Clinic',
        billing_frequency: 'MONTHLY',
      });
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('Test Clinic');
      expect(res.body).not.toContain('practiceId');
    });
  });

  // =========================================================================
  // 403 responses do not leak practice existence or details
  // =========================================================================

  describe('403 responses do not leak practice existence or details', () => {
    it('403 from non-admin physician does not reveal practice name', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      expect(res.body).not.toContain('Test Clinic A');
      expect(res.body).not.toContain('cus_practice_a_secret');
      expect(res.body).not.toContain('sub_practice_a_secret');
    });

    it('403 from delegate does not reveal practice exists', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      expect(res.body).not.toContain('Test Clinic');
      expect(res.body).not.toContain(PRACTICE_ID);
    });

    it('403 from delegate on POST /practices does not reveal any data', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'Clinic',
        billing_frequency: 'MONTHLY',
      }, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.data).toBeUndefined();
      expect(body.error).toBeDefined();
    });

    it('403 response has only error field, no data field', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
    });
  });

  // =========================================================================
  // 404 responses are consistent regardless of resource existence
  // =========================================================================

  describe('404 responses do not reveal resource existence', () => {
    it('404 for non-existent practice uses generic message', async () => {
      // Admin session but practice does not exist
      const res = await authedGet(`/api/v1/practices/${NON_EXISTENT_PRACTICE_ID}`);
      expect(res.statusCode).toBe(404);
      const body = res.json();
      expect(body.error.code).toBe('NOT_FOUND');
      // Must not echo back the practice ID
      expect(body.error.message).not.toContain(NON_EXISTENT_PRACTICE_ID);
    });

    it('404 for non-existent practice does not reveal other practice names', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${NON_EXISTENT_PRACTICE_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain('Test Clinic A');
    });

    it('404 on seats endpoint for non-existent practice uses generic message', async () => {
      const res = await authedGet(`/api/v1/practices/${NON_EXISTENT_PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(404);
      const body = res.json();
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).not.toContain(NON_EXISTENT_PRACTICE_ID);
    });

    it('404 on invoices endpoint for non-existent practice uses generic message', async () => {
      const res = await authedGet(`/api/v1/practices/${NON_EXISTENT_PRACTICE_ID}/invoices`);
      expect(res.statusCode).toBe(404);
      const body = res.json();
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).not.toContain(NON_EXISTENT_PRACTICE_ID);
    });
  });

  // =========================================================================
  // 500 error responses are sanitised
  // =========================================================================

  describe('500 error responses are sanitised', () => {
    it('500 errors do not expose stack traces', async () => {
      const errorApp = Fastify({ logger: false });
      errorApp.setValidatorCompiler(validatorCompiler);
      errorApp.setSerializerCompiler(serializerCompiler);

      errorApp.get('/test/error', async () => {
        throw new Error('ECONNREFUSED: connect to db-host:5432 postgresql://user:pass@host/meritum');
      });

      errorApp.setErrorHandler((_error, _request, reply) => {
        return reply.code(500).send({
          error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
      });

      await errorApp.ready();

      const res = await errorApp.inject({ method: 'GET', url: '/test/error' });
      expect(res.statusCode).toBe(500);

      const rawBody = res.body;
      expect(rawBody).not.toContain('ECONNREFUSED');
      expect(rawBody).not.toContain('postgresql://');
      expect(rawBody).not.toContain('db-host');
      expect(rawBody).not.toContain('password');
      expect(rawBody).not.toContain(':5432');
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');

      const body = JSON.parse(rawBody);
      expect(body.error.message).toBe('Internal server error');
      expect(body.error).not.toHaveProperty('stack');

      await errorApp.close();
    });

    it('500 errors do not expose Stripe secrets', async () => {
      const errorApp = Fastify({ logger: false });
      errorApp.setValidatorCompiler(validatorCompiler);
      errorApp.setSerializerCompiler(serializerCompiler);

      errorApp.get('/test/stripe-error', async () => {
        throw new Error('Stripe API error: sk_live_secret_key_12345 whsec_practice_webhook_secret');
      });

      errorApp.setErrorHandler((_error, _request, reply) => {
        return reply.code(500).send({
          error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
      });

      await errorApp.ready();

      const res = await errorApp.inject({ method: 'GET', url: '/test/stripe-error' });
      expect(res.statusCode).toBe(500);

      expect(res.body).not.toContain('sk_live');
      expect(res.body).not.toContain('whsec_');
      expect(res.body).not.toContain('secret_key');

      await errorApp.close();
    });
  });

  // =========================================================================
  // Error response format is consistent across all error status codes
  // =========================================================================

  describe('Error response format is consistent', () => {
    it('401 response has consistent { error: { code, message } } shape', async () => {
      const res = await unauthGet(`/api/v1/practices/${PRACTICE_ID}`);
      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('403 response has consistent { error: { code, message } } shape', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('404 response has consistent { error: { code, message } } shape', async () => {
      const res = await authedGet(`/api/v1/practices/${NON_EXISTENT_PRACTICE_ID}`);
      expect(res.statusCode).toBe(404);
      const body = res.json();
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });
  });

  // =========================================================================
  // No server version headers
  // =========================================================================

  describe('Response headers do not reveal server technology', () => {
    it('no X-Powered-By header on practice endpoints', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header on unauthenticated practice requests', async () => {
      const res = await unauthGet(`/api/v1/practices/${PRACTICE_ID}`);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing Fastify or Node version', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`);
      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/node/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });

    it('no Server header on 401 responses', async () => {
      const res = await unauthGet(`/api/v1/practices/${PRACTICE_ID}`);
      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/node/i);
      }
    });

    it('no Server header on 403 responses', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, PHYSICIAN_SESSION_TOKEN);
      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/node/i);
      }
    });

    it('no Server header on 404 responses', async () => {
      const res = await authedGet(`/api/v1/practices/${NON_EXISTENT_PRACTICE_ID}`);
      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/node/i);
      }
    });
  });

  // =========================================================================
  // No Stripe IDs in practice error responses
  // =========================================================================

  describe('No Stripe IDs leak in practice error responses', () => {
    it('403 from non-admin does not reveal Stripe customer or subscription IDs', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      expect(res.body).not.toContain('cus_');
      expect(res.body).not.toContain('sub_');
      expect(res.body).not.toContain('stripeCustomerId');
      expect(res.body).not.toContain('stripeSubscriptionId');
    });

    it('401 from unauthenticated does not reveal Stripe IDs', async () => {
      seedPracticeA();
      const res = await unauthGet(`/api/v1/practices/${PRACTICE_ID}`);
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('cus_');
      expect(res.body).not.toContain('stripeCustomerId');
    });
  });

  // =========================================================================
  // No internal error details in practice responses
  // =========================================================================

  describe('No internal error details in any practice error response', () => {
    it('error responses do not contain drizzle or postgres references', async () => {
      const res = await unauthGet(`/api/v1/practices/${PRACTICE_ID}`);
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('drizzle');
      expect(res.body).not.toContain('postgres');
      expect(res.body).not.toContain('pg_');
    });

    it('error responses do not contain file paths', async () => {
      const res = await unauthGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('.ts:');
      expect(res.body).not.toContain('.js:');
      expect(res.body).not.toContain('node_modules');
      expect(res.body).not.toContain('/src/');
    });

    it('403 responses do not contain file paths or internals', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      expect(res.body).not.toContain('.ts:');
      expect(res.body).not.toContain('.js:');
      expect(res.body).not.toContain('node_modules');
      expect(res.body).not.toContain('/src/');
      expect(res.body).not.toContain('drizzle');
      expect(res.body).not.toContain('postgres');
    });
  });
});
