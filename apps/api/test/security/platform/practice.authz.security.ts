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
  SUSPENDED: 'SUSPENDED',
  CANCELLED: 'CANCELLED',
} as const;

const Role = {
  PHYSICIAN: 'PHYSICIAN',
  DELEGATE: 'DELEGATE',
  ADMIN: 'ADMIN',
  PRACTICE_ADMIN: 'PRACTICE_ADMIN',
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

// PRACTICE_ADMIN physician (admin of Practice A)
const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// Regular PHYSICIAN (not a practice admin)
const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000002';

// Another PRACTICE_ADMIN for cross-practice isolation tests (admin of Practice B)
const OTHER_ADMIN_USER_ID = '00000000-1111-0000-0000-000000000003';
const OTHER_ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const OTHER_ADMIN_SESSION_TOKEN_HASH = hashToken(OTHER_ADMIN_SESSION_TOKEN);
const OTHER_ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000003';

// DELEGATE user (non-physician role)
const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000050';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '00000000-2222-0000-0000-000000000050';

// Member physician
const MEMBER_USER_ID = '00000000-1111-0000-0000-000000000004';

// Fixed IDs
const PRACTICE_ID = '00000000-3333-0000-0000-000000000001';
const OTHER_PRACTICE_ID = '00000000-3333-0000-0000-000000000002';
const MEMBERSHIP_ADMIN_ID = '00000000-4444-0000-0000-000000000001';
const MEMBERSHIP_MEMBER_ID = '00000000-4444-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockPractices: Array<Record<string, any>>;
let mockMemberships: Array<Record<string, any>>;
let mockInvitations: Array<Record<string, any>>;

// ---------------------------------------------------------------------------
// Mock Repos
// ---------------------------------------------------------------------------

function createMockUserRepo(): PracticeUserRepo {
  return {
    findUserById: vi.fn(async (userId: string) => {
      const users: Record<string, any> = {
        [ADMIN_USER_ID]: { userId: ADMIN_USER_ID, email: 'admin@clinic.ca', fullName: 'Dr. Admin', role: Role.PHYSICIAN },
        [PHYSICIAN_USER_ID]: { userId: PHYSICIAN_USER_ID, email: 'physician@clinic.ca', fullName: 'Dr. Physician', role: Role.PHYSICIAN },
        [OTHER_ADMIN_USER_ID]: { userId: OTHER_ADMIN_USER_ID, email: 'other-admin@clinic.ca', fullName: 'Dr. Other Admin', role: Role.PHYSICIAN },
        [MEMBER_USER_ID]: { userId: MEMBER_USER_ID, email: 'member@clinic.ca', fullName: 'Dr. Member', role: Role.PHYSICIAN },
        [DELEGATE_USER_ID]: { userId: DELEGATE_USER_ID, email: 'delegate@clinic.ca', fullName: 'Delegate User', role: Role.DELEGATE },
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
        status: data.status ?? PracticeStatus.ACTIVE,
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
    findPracticeByAdminUserId: vi.fn(async (adminUserId: string) => {
      return mockPractices.find((p) => p.adminUserId === adminUserId && p.status === 'ACTIVE') ?? null;
    }),
    updatePractice: vi.fn(async (practiceId: string, data: any) => {
      const practice = mockPractices.find((p) => p.practiceId === practiceId);
      if (!practice) return practice;
      Object.assign(practice, data, { updatedAt: new Date() });
      return practice;
    }),
    updatePracticeStatus: vi.fn(async () => {}),
    updatePracticeStripeIds: vi.fn(async () => {}),
    getActiveHeadcount: vi.fn(async (practiceId: string) => {
      return mockMemberships.filter((m) => m.practiceId === practiceId && m.isActive).length;
    }),
    getConsolidatedSeatCount: vi.fn(async () => 0),
    findActivePractices: vi.fn(async () => []),
  } as unknown as PracticeRepository;
}

function createMockMembershipRepo(): PracticeMembershipRepository {
  return {
    createMembership: vi.fn(async (data: any) => {
      const membership = {
        membershipId: crypto.randomUUID(),
        practiceId: data.practiceId,
        physicianUserId: data.physicianUserId,
        billingMode: data.billingMode ?? BillingMode.PRACTICE_CONSOLIDATED,
        joinedAt: data.joinedAt ?? new Date(),
        removedAt: null,
        removalEffectiveAt: null,
        isActive: true,
        createdAt: new Date(),
      };
      mockMemberships.push(membership);
      return membership;
    }),
    findActiveMembershipByPhysicianId: vi.fn(async (physicianUserId: string) => {
      return mockMemberships.find((m) => m.physicianUserId === physicianUserId && m.isActive) ?? null;
    }),
    findActiveMembershipsByPracticeId: vi.fn(async (practiceId: string) => {
      return mockMemberships.filter((m) => m.practiceId === practiceId && m.isActive);
    }),
    findMembershipByPracticeAndPhysician: vi.fn(async (practiceId: string, physicianUserId: string) => {
      return mockMemberships.find((m) => m.practiceId === practiceId && m.physicianUserId === physicianUserId && m.isActive) ?? null;
    }),
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
        [OTHER_ADMIN_SESSION_TOKEN_HASH]: {
          session: { sessionId: OTHER_ADMIN_SESSION_ID, userId: OTHER_ADMIN_USER_ID, tokenHash: OTHER_ADMIN_SESSION_TOKEN_HASH, createdAt: new Date(), lastActiveAt: new Date(), revoked: false },
          user: { userId: OTHER_ADMIN_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'ACTIVE' },
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
  const practice = {
    practiceId: PRACTICE_ID,
    name: 'Test Clinic A',
    adminUserId: ADMIN_USER_ID,
    stripeCustomerId: 'cus_practice_a',
    stripeSubscriptionId: 'sub_practice_a',
    billingFrequency: 'MONTHLY',
    status: PracticeStatus.ACTIVE,
    currentPeriodStart: new Date(),
    currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  mockPractices.push(practice);

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

  return practice;
}

function seedPracticeB() {
  const practice = {
    practiceId: OTHER_PRACTICE_ID,
    name: 'Test Clinic B',
    adminUserId: OTHER_ADMIN_USER_ID,
    stripeCustomerId: 'cus_practice_b',
    stripeSubscriptionId: 'sub_practice_b',
    billingFrequency: 'MONTHLY',
    status: PracticeStatus.ACTIVE,
    currentPeriodStart: new Date(),
    currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  mockPractices.push(practice);

  mockMemberships.push({
    membershipId: crypto.randomUUID(),
    practiceId: OTHER_PRACTICE_ID,
    physicianUserId: OTHER_ADMIN_USER_ID,
    billingMode: BillingMode.PRACTICE_CONSOLIDATED,
    joinedAt: new Date(),
    removedAt: null,
    removalEffectiveAt: null,
    isActive: true,
    createdAt: new Date(),
  });

  return practice;
}

function seedMember() {
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
        error: {
          code: (error as any).code ?? 'ERROR',
          message: error.message,
        },
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

function authedGet(url: string, token: string) {
  return app.inject({ method: 'GET', url, headers: { cookie: `session=${token}` } });
}

function authedPost(url: string, body: Record<string, unknown>, token: string) {
  return app.inject({
    method: 'POST', url,
    headers: { cookie: `session=${token}`, 'content-type': 'application/json' },
    payload: body,
  });
}

function authedPatch(url: string, body: Record<string, unknown>, token: string) {
  return app.inject({
    method: 'PATCH', url,
    headers: { cookie: `session=${token}`, 'content-type': 'application/json' },
    payload: body,
  });
}

function authedDelete(url: string, token: string) {
  return app.inject({ method: 'DELETE', url, headers: { cookie: `session=${token}` } });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('D16-041: Practice Authorization & Role Enforcement (Security)', () => {
  beforeAll(async () => {
    mockPractices = [];
    mockMemberships = [];
    mockInvitations = [];
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockPractices = [];
    mockMemberships = [];
    mockInvitations = [];
    vi.clearAllMocks();
  });

  // =========================================================================
  // PRACTICE_ADMIN role enforcement: non-admin physician gets 403
  // =========================================================================

  describe('Non-admin physician gets 403 on practice-admin endpoints', () => {
    it('GET /practices/:id -- non-admin physician gets 403', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.data).toBeUndefined();
    });

    it('PATCH /practices/:id -- non-admin physician gets 403', async () => {
      seedPracticeA();
      const res = await authedPatch(`/api/v1/practices/${PRACTICE_ID}`, { name: 'Hacked' }, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.data).toBeUndefined();
    });

    it('GET /practices/:id/seats -- non-admin physician gets 403', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.data).toBeUndefined();
    });

    it('POST /practices/:id/invitations -- non-admin physician gets 403', async () => {
      seedPracticeA();
      const res = await authedPost(`/api/v1/practices/${PRACTICE_ID}/invitations`, { email: 'new@test.ca' }, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.data).toBeUndefined();
    });

    it('DELETE /practices/:id/seats/:userId -- non-admin physician gets 403', async () => {
      seedPracticeA();
      seedMember();
      const res = await authedDelete(`/api/v1/practices/${PRACTICE_ID}/seats/${MEMBER_USER_ID}`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.data).toBeUndefined();
    });

    it('GET /practices/:id/invoices -- non-admin physician gets 403', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/invoices`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // Cross-practice isolation: admin of A cannot access B
  // =========================================================================

  describe('Cross-practice isolation: admin of A cannot access B', () => {
    it('GET /practices/:id -- admin A gets 403 on practice B', async () => {
      seedPracticeA();
      seedPracticeB();
      const res = await authedGet(`/api/v1/practices/${OTHER_PRACTICE_ID}`, ADMIN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('PATCH /practices/:id -- admin A gets 403 on practice B', async () => {
      seedPracticeA();
      seedPracticeB();
      const res = await authedPatch(`/api/v1/practices/${OTHER_PRACTICE_ID}`, { name: 'Hacked' }, ADMIN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('GET /practices/:id/seats -- admin A gets 403 on practice B', async () => {
      seedPracticeA();
      seedPracticeB();
      const res = await authedGet(`/api/v1/practices/${OTHER_PRACTICE_ID}/seats`, ADMIN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('POST /practices/:id/invitations -- admin A gets 403 on practice B', async () => {
      seedPracticeA();
      seedPracticeB();
      const res = await authedPost(`/api/v1/practices/${OTHER_PRACTICE_ID}/invitations`, { email: 'x@test.ca' }, ADMIN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('DELETE /practices/:id/seats/:userId -- admin A gets 403 on practice B', async () => {
      seedPracticeA();
      seedPracticeB();
      const res = await authedDelete(`/api/v1/practices/${OTHER_PRACTICE_ID}/seats/${OTHER_ADMIN_USER_ID}`, ADMIN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('GET /practices/:id/invoices -- admin A gets 403 on practice B', async () => {
      seedPracticeA();
      seedPracticeB();
      const res = await authedGet(`/api/v1/practices/${OTHER_PRACTICE_ID}/invoices`, ADMIN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // DELEGATE role gets 403 on all practice endpoints
  // =========================================================================

  describe('DELEGATE role gets 403 on all practice endpoints', () => {
    it('POST /practices -- delegate gets 403', async () => {
      const res = await authedPost('/api/v1/practices', { name: 'Test', billing_frequency: 'MONTHLY' }, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.data).toBeUndefined();
    });

    it('GET /practices/:id -- delegate gets 403', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('PATCH /practices/:id -- delegate gets 403', async () => {
      seedPracticeA();
      const res = await authedPatch(`/api/v1/practices/${PRACTICE_ID}`, { name: 'Hacked' }, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('GET /practices/:id/seats -- delegate gets 403', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/seats`, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('POST /practices/:id/invitations -- delegate gets 403', async () => {
      seedPracticeA();
      const res = await authedPost(`/api/v1/practices/${PRACTICE_ID}/invitations`, { email: 'test@test.ca' }, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('POST /practice-invitations/:token/accept -- delegate gets 403', async () => {
      const res = await authedPost('/api/v1/practice-invitations/sometoken/accept', {}, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.data).toBeUndefined();
    });

    it('DELETE /practices/:id/seats/:userId -- delegate gets 403', async () => {
      seedPracticeA();
      seedMember();
      const res = await authedDelete(`/api/v1/practices/${PRACTICE_ID}/seats/${MEMBER_USER_ID}`, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('GET /practices/:id/invoices -- delegate gets 403', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}/invoices`, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Only PHYSICIAN can create a practice
  // =========================================================================

  describe('Only PHYSICIAN can create a practice', () => {
    it('DELEGATE cannot create a practice (403)', async () => {
      const res = await authedPost('/api/v1/practices', { name: 'Clinic', billing_frequency: 'MONTHLY' }, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('PHYSICIAN can create a practice (non-403)', async () => {
      const res = await authedPost('/api/v1/practices', { name: 'My Clinic', billing_frequency: 'MONTHLY' }, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 403 responses do not leak practice existence or details
  // =========================================================================

  describe('403 responses do not leak practice existence or details', () => {
    it('403 from non-admin does not reveal practice name', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('Test Clinic A');
      expect(rawBody).not.toContain('admin@clinic.ca');
    });

    it('403 from cross-practice admin does not reveal other practice name', async () => {
      seedPracticeA();
      seedPracticeB();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, OTHER_ADMIN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('Test Clinic A');
    });

    it('403 response has consistent error shape', async () => {
      seedPracticeA();
      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, PHYSICIAN_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
    });
  });
});
