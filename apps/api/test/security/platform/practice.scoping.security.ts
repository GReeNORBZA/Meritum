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

const BillingMode = {
  PRACTICE_CONSOLIDATED: 'PRACTICE_CONSOLIDATED',
  INDIVIDUAL_EARLY_BIRD: 'INDIVIDUAL_EARLY_BIRD',
} as const;

const PracticeStatus = {
  ACTIVE: 'ACTIVE',
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

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

const MEMBER_USER_ID = '00000000-1111-0000-0000-000000000004';

const PRACTICE_ID = '00000000-3333-0000-0000-000000000001';
const MEMBERSHIP_ADMIN_ID = '00000000-4444-0000-0000-000000000001';
const MEMBERSHIP_MEMBER_ID = '00000000-4444-0000-0000-000000000002';

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
        [MEMBER_USER_ID]: { userId: MEMBER_USER_ID, email: 'member@clinic.ca', fullName: 'Dr. Member', role: 'PHYSICIAN' },
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
    getActiveHeadcount: vi.fn(async (practiceId: string) => {
      return mockMemberships.filter((m) => m.practiceId === practiceId && m.isActive).length;
    }),
    getConsolidatedSeatCount: vi.fn(async (practiceId: string) => {
      return mockMemberships.filter(
        (m) => m.practiceId === practiceId && m.isActive && m.billingMode === BillingMode.PRACTICE_CONSOLIDATED,
      ).length;
    }),
    findActivePractices: vi.fn(async () => []),
  } as unknown as PracticeRepository;
}

function createMockMembershipRepo(): PracticeMembershipRepository {
  return {
    createMembership: vi.fn(async () => ({})),
    findActiveMembershipByPhysicianId: vi.fn(async () => null),
    findActiveMembershipsByPracticeId: vi.fn(async (practiceId: string) => {
      return mockMemberships.filter((m) => m.practiceId === practiceId && m.isActive);
    }),
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
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function seedPracticeWithMembers() {
  mockPractices.push({
    practiceId: PRACTICE_ID,
    name: 'Test Clinic A',
    adminUserId: ADMIN_USER_ID,
    stripeCustomerId: 'cus_a',
    stripeSubscriptionId: 'sub_a',
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

  mockMemberships.push({
    membershipId: MEMBERSHIP_MEMBER_ID,
    practiceId: PRACTICE_ID,
    physicianUserId: MEMBER_USER_ID,
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

function authedGet(url: string, token = ADMIN_SESSION_TOKEN) {
  return app.inject({ method: 'GET', url, headers: { cookie: `session=${token}` } });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('D16-042: Practice Data Scoping (Security) -- CRITICAL', () => {
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
  // Seats endpoint: ONLY 4 allowed keys per seat
  // =========================================================================

  describe('GET /practices/:id/seats returns ONLY {physicianName, email, joinedAt, billingMode}', () => {
    const ALLOWED_SEAT_KEYS = ['physicianName', 'email', 'joinedAt', 'billingMode'];

    it('each seat object has exactly 4 allowed keys', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.length).toBeGreaterThan(0);

      for (const seat of body.data) {
        const keys = Object.keys(seat);
        expect(keys.sort()).toEqual(ALLOWED_SEAT_KEYS.sort());
      }
    });

    it('seat objects have no extra keys beyond the 4 allowed', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(200);
      const body = res.json();

      for (const seat of body.data) {
        const keys = Object.keys(seat);
        expect(keys.length).toBe(4);
        for (const key of keys) {
          expect(ALLOWED_SEAT_KEYS).toContain(key);
        }
      }
    });
  });

  // =========================================================================
  // No claim data in seats response
  // =========================================================================

  describe('No claim data in any practice admin response', () => {
    it('seats response does NOT contain claim-related fields', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      const claimFields = [
        'claimId', 'claimCount', 'rejectionRate', 'submissionCount',
        'healthServiceCode', 'diagnosticCode', 'claim_id',
      ];
      for (const field of claimFields) {
        expect(bodyStr).not.toContain(field);
      }
    });
  });

  // =========================================================================
  // No billing volume data in seats response
  // =========================================================================

  describe('No billing volume data in seats response', () => {
    it('seats response does NOT contain billing volume fields', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      const billingFields = ['billingVolume', 'revenue', 'totalBilled', 'amountCad'];
      for (const field of billingFields) {
        expect(bodyStr).not.toContain(field);
      }
    });
  });

  // =========================================================================
  // No patient data in seats response
  // =========================================================================

  describe('No patient data in seats response', () => {
    it('seats response does NOT contain patient data fields', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      const patientFields = ['patientId', 'phn', 'firstName', 'lastName', 'dateOfBirth'];
      for (const field of patientFields) {
        expect(bodyStr).not.toContain(field);
      }
    });
  });

  // =========================================================================
  // No analytics/AI data in seats response
  // =========================================================================

  describe('No analytics or AI data in seats response', () => {
    it('seats response does NOT contain analytics or AI fields', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      const analyticsFields = [
        'analytics', 'analyticsCache', 'analytics_cache',
        'generatedReports', 'generated_reports',
        'aiSuggestion', 'ai_suggestion_events', 'aiSuggestionEvents',
      ];
      for (const field of analyticsFields) {
        expect(bodyStr).not.toContain(field);
      }
    });
  });

  // =========================================================================
  // No individual payment history in seats response
  // =========================================================================

  describe('No individual payment history in seats response', () => {
    it('seats response does NOT contain payment history fields', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      const paymentFields = ['paymentId', 'payment_history', 'stripeInvoiceId', 'paidAt'];
      for (const field of paymentFields) {
        expect(bodyStr).not.toContain(field);
      }
    });
  });

  // =========================================================================
  // Invoice endpoint returns practice-level data, not individual records
  // =========================================================================

  describe('GET /practices/:id/invoices returns practice-level data only', () => {
    it('invoice response includes practice-level fields', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/invoices`);
      expect(res.statusCode).toBe(200);
      const body = res.json();

      expect(body.data).toHaveProperty('totalAmount');
      expect(body.data).toHaveProperty('perSeatRate');
      expect(body.data).toHaveProperty('consolidatedSeatCount');
      expect(body.data).toHaveProperty('billingFrequency');
    });

    it('invoice response is NOT an array of individual records', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/invoices`);
      expect(res.statusCode).toBe(200);
      const body = res.json();

      expect(Array.isArray(body.data)).toBe(false);
    });

    it('invoice response does NOT contain individual physician payment records', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/invoices`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      expect(bodyStr).not.toContain('paymentId');
      expect(bodyStr).not.toContain('stripeInvoiceId');
      expect(bodyStr).not.toContain('paidAt');
    });

    it('invoice response does NOT contain PHI fields', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/invoices`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      const phiFields = ['patientId', 'phn', 'claimId', 'healthServiceCode'];
      for (const field of phiFields) {
        expect(bodyStr).not.toContain(field);
      }
    });
  });

  // =========================================================================
  // Practice admin endpoints NEVER join with sensitive tables
  // =========================================================================

  describe('Practice admin endpoints never expose data from sensitive tables', () => {
    const SENSITIVE_TABLE_INDICATORS = [
      'claims', 'patients', 'analytics_cache', 'generated_reports',
      'ai_suggestion_events', 'payment_history',
    ];

    it('GET /practices/:id response contains no sensitive table field names', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      for (const table of SENSITIVE_TABLE_INDICATORS) {
        expect(bodyStr).not.toContain(table);
      }
    });

    it('GET /practices/:id/seats response contains no sensitive table field names', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      for (const table of SENSITIVE_TABLE_INDICATORS) {
        expect(bodyStr).not.toContain(table);
      }
    });

    it('GET /practices/:id/invoices response contains no sensitive table field names', async () => {
      seedPracticeWithMembers();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/invoices`);
      expect(res.statusCode).toBe(200);
      const bodyStr = JSON.stringify(res.json());

      for (const table of SENSITIVE_TABLE_INDICATORS) {
        expect(bodyStr).not.toContain(table);
      }
    });
  });
});
