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

const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000002';

const PRACTICE_ID = '00000000-3333-0000-0000-000000000001';
const MEMBER_USER_ID = '00000000-1111-0000-0000-000000000004';

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
    createPractice: vi.fn(async (data: any) => {
      const practice = {
        practiceId: PRACTICE_ID,
        name: data.name,
        adminUserId: data.adminUserId,
        stripeCustomerId: null,
        stripeSubscriptionId: null,
        billingFrequency: data.billingFrequency,
        status: 'ACTIVE',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockPractices.push(practice);
      return practice;
    }),
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
    createMembership: vi.fn(async (data: any) => {
      const m = { membershipId: crypto.randomUUID(), ...data, isActive: true, createdAt: new Date() };
      mockMemberships.push(m);
      return m;
    }),
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
          session: { sessionId: ADMIN_SESSION_ID, userId: ADMIN_USER_ID, tokenHash: ADMIN_SESSION_TOKEN_HASH, createdAt: new Date(), lastActiveAt: new Date(), revoked: false },
          user: { userId: ADMIN_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'ACTIVE' },
        };
      }
      if (tokenHash === PHYSICIAN_SESSION_TOKEN_HASH) {
        return {
          session: { sessionId: PHYSICIAN_SESSION_ID, userId: PHYSICIAN_USER_ID, tokenHash: PHYSICIAN_SESSION_TOKEN_HASH, createdAt: new Date(), lastActiveAt: new Date(), revoked: false },
          user: { userId: PHYSICIAN_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'ACTIVE' },
        };
      }
      return undefined;
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
    stripeCustomerId: 'cus_a',
    stripeSubscriptionId: 'sub_a',
    billingFrequency: 'MONTHLY',
    status: 'ACTIVE',
    currentPeriodStart: new Date(),
    currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  mockMemberships.push({
    membershipId: '00000000-4444-0000-0000-000000000001',
    practiceId: PRACTICE_ID,
    physicianUserId: ADMIN_USER_ID,
    billingMode: 'PRACTICE_CONSOLIDATED',
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

function authedPost(url: string, body: Record<string, unknown>, token = PHYSICIAN_SESSION_TOKEN) {
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

function authedGet(url: string, token = ADMIN_SESSION_TOKEN) {
  return app.inject({ method: 'GET', url, headers: { cookie: `session=${token}` } });
}

function authedDelete(url: string, token = ADMIN_SESSION_TOKEN) {
  return app.inject({ method: 'DELETE', url, headers: { cookie: `session=${token}` } });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('D16-043: Practice Input Validation & Injection Prevention (Security)', () => {
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
  // SQL Injection in practice name
  // =========================================================================

  describe('SQL Injection Prevention -- practice name', () => {
    const SQL_PAYLOADS = [
      "' OR 1=1--",
      "'; DROP TABLE practices; --",
      "1' OR '1'='1",
      "' UNION SELECT * FROM users --",
      "Robert'); DROP TABLE practices;--",
    ];

    for (const payload of SQL_PAYLOADS) {
      it(`safely handles name="${payload}" (stored via parameterized queries)`, async () => {
        const res = await authedPost('/api/v1/practices', {
          name: payload,
          billing_frequency: 'MONTHLY',
        });

        // Should not crash (500) or return data from another table
        // May be 201 (stored safely via parameterized queries) or 400
        expect(res.statusCode).not.toBe(500);
        expect([200, 201, 400, 404, 422]).toContain(res.statusCode);
      });
    }
  });

  // =========================================================================
  // SQL Injection in invitation email
  // =========================================================================

  describe('SQL Injection Prevention -- invitation email', () => {
    const SQL_PAYLOADS = [
      "admin@clinic.ca' OR 1=1--",
      "'; DROP TABLE invitations; --",
      "' UNION SELECT * FROM users --@test.ca",
    ];

    for (const payload of SQL_PAYLOADS) {
      it(`rejects email="${payload}" with 400`, async () => {
        seedPracticeA();

        const res = await authedPost(
          `/api/v1/practices/${PRACTICE_ID}/invitations`,
          { email: payload },
          ADMIN_SESSION_TOKEN,
        );

        // Invalid email format should be rejected by Zod schema
        expect(res.statusCode).toBe(400);
        const body = res.json();
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // XSS Payloads in practice name
  // =========================================================================

  describe('XSS Prevention -- practice name', () => {
    const XSS_PAYLOADS = [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '<svg onload=alert(1)>',
      '"><script>document.location="http://evil.com"</script>',
    ];

    for (const payload of XSS_PAYLOADS) {
      it(`safely handles name="${payload}" (API returns JSON, not HTML)`, async () => {
        const res = await authedPost('/api/v1/practices', {
          name: payload,
          billing_frequency: 'MONTHLY',
        });

        // Should not crash; stored safely via parameterized queries.
        // XSS is irrelevant at API layer since response is JSON.
        expect(res.statusCode).not.toBe(500);
        expect([200, 201, 400, 404, 422]).toContain(res.statusCode);
      });
    }
  });

  // =========================================================================
  // Name exceeding 200 chars
  // =========================================================================

  describe('String Length Validation', () => {
    it('rejects practice name exceeding 200 characters', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'A'.repeat(201),
        billing_frequency: 'MONTHLY',
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts practice name at 200 characters', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'A'.repeat(200),
        billing_frequency: 'MONTHLY',
      });

      // Should not be 400 (validation pass)
      expect(res.statusCode).not.toBe(400);
    });

    it('rejects empty practice name', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: '',
        billing_frequency: 'MONTHLY',
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Invalid email format
  // =========================================================================

  describe('Email Validation', () => {
    it('rejects invitation with invalid email format', async () => {
      seedPracticeA();

      const res = await authedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: 'not-an-email' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(400);
    });

    it('rejects invitation with empty email', async () => {
      seedPracticeA();

      const res = await authedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: '' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Non-UUID path parameters
  // =========================================================================

  describe('UUID Parameter Validation', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      '../../../etc/passwd',
      '<script>alert(1)</script>',
      "'; DROP TABLE practices; --",
      'null',
      'undefined',
      '00000000-0000-0000-0000-00000000000g',
    ];

    describe('GET /practices/:id rejects non-UUID', () => {
      for (const invalidId of INVALID_UUIDS) {
        it(`rejects id="${invalidId}"`, async () => {
          const res = await authedGet(
            `/api/v1/practices/${encodeURIComponent(invalidId)}`,
          );

          expect(res.statusCode).toBe(400);
          const body = res.json();
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('PATCH /practices/:id rejects non-UUID', () => {
      for (const invalidId of INVALID_UUIDS) {
        it(`rejects id="${invalidId}"`, async () => {
          const res = await authedPatch(
            `/api/v1/practices/${encodeURIComponent(invalidId)}`,
            { name: 'Test' },
          );

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('DELETE /practices/:id/seats/:userId rejects non-UUID practiceId', () => {
      for (const invalidId of INVALID_UUIDS) {
        it(`rejects practiceId="${invalidId}"`, async () => {
          const res = await authedDelete(
            `/api/v1/practices/${encodeURIComponent(invalidId)}/seats/${MEMBER_USER_ID}`,
          );

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('DELETE /practices/:id/seats/:userId rejects non-UUID userId', () => {
      for (const invalidId of INVALID_UUIDS) {
        it(`rejects userId="${invalidId}"`, async () => {
          seedPracticeA();
          const res = await authedDelete(
            `/api/v1/practices/${PRACTICE_ID}/seats/${encodeURIComponent(invalidId)}`,
          );

          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // Type coercion attacks on billing_frequency
  // =========================================================================

  describe('Type Coercion Prevention -- billing_frequency', () => {
    it('rejects number for billing_frequency', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'Test Clinic',
        billing_frequency: 12345,
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects array for billing_frequency', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'Test Clinic',
        billing_frequency: ['MONTHLY', 'ANNUAL'],
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid billing_frequency value', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'Test Clinic',
        billing_frequency: 'WEEKLY',
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects null billing_frequency', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'Test Clinic',
        billing_frequency: null,
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects missing billing_frequency', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'Test Clinic',
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts MONTHLY billing_frequency', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'Test Clinic',
        billing_frequency: 'MONTHLY',
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts ANNUAL billing_frequency', async () => {
      const res = await authedPost('/api/v1/practices', {
        name: 'Test Clinic',
        billing_frequency: 'ANNUAL',
      });

      expect(res.statusCode).not.toBe(400);
    });
  });
});
