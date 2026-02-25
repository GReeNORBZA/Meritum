import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (before any imports that read env vars)
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
// Use string literals to avoid potential module resolution issues with recently-added exports
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

// PRACTICE_ADMIN physician
const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// Regular PHYSICIAN (not a practice admin)
const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000002';

// Another PRACTICE_ADMIN for cross-practice isolation tests
const OTHER_ADMIN_USER_ID = '00000000-1111-0000-0000-000000000003';
const OTHER_ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const OTHER_ADMIN_SESSION_TOKEN_HASH = hashToken(OTHER_ADMIN_SESSION_TOKEN);
const OTHER_ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000003';

// DELEGATE user (non-physician role)
const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000050';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '00000000-2222-0000-0000-000000000050';

// Member physician (invited/accepted onto practice A)
const MEMBER_USER_ID = '00000000-1111-0000-0000-000000000004';
const MEMBER_SESSION_TOKEN = randomBytes(32).toString('hex');
const MEMBER_SESSION_TOKEN_HASH = hashToken(MEMBER_SESSION_TOKEN);
const MEMBER_SESSION_ID = '00000000-2222-0000-0000-000000000004';

// Fixed IDs
const PRACTICE_ID = '00000000-3333-0000-0000-000000000001';
const OTHER_PRACTICE_ID = '00000000-3333-0000-0000-000000000002';
const MEMBERSHIP_ADMIN_ID = '00000000-4444-0000-0000-000000000001';
const MEMBERSHIP_MEMBER_ID = '00000000-4444-0000-0000-000000000002';
const INVITATION_ID = '00000000-5555-0000-0000-000000000001';
const STRIPE_CUSTOMER_ID = 'cus_practice_test';

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockPractices: Array<Record<string, any>>;
let mockMemberships: Array<Record<string, any>>;
let mockInvitations: Array<Record<string, any>>;

// ---------------------------------------------------------------------------
// Mock User Repo
// ---------------------------------------------------------------------------

function createMockUserRepo(): PracticeUserRepo {
  return {
    findUserById: vi.fn(async (userId: string) => {
      const users: Record<string, { userId: string; email: string; fullName: string; role: string }> = {
        [ADMIN_USER_ID]: { userId: ADMIN_USER_ID, email: 'admin@clinic.ca', fullName: 'Dr. Admin', role: Role.PHYSICIAN },
        [PHYSICIAN_USER_ID]: { userId: PHYSICIAN_USER_ID, email: 'physician@clinic.ca', fullName: 'Dr. Physician', role: Role.PHYSICIAN },
        [OTHER_ADMIN_USER_ID]: { userId: OTHER_ADMIN_USER_ID, email: 'other-admin@clinic.ca', fullName: 'Dr. Other Admin', role: Role.PHYSICIAN },
        [MEMBER_USER_ID]: { userId: MEMBER_USER_ID, email: 'member@clinic.ca', fullName: 'Dr. Member', role: Role.PHYSICIAN },
        [DELEGATE_USER_ID]: { userId: DELEGATE_USER_ID, email: 'delegate@clinic.ca', fullName: 'Delegate User', role: Role.DELEGATE },
      };
      return users[userId];
    }),
    findUserByEmail: vi.fn(async (email: string) => {
      const byEmail: Record<string, { userId: string; email: string; fullName: string; role: string }> = {
        'admin@clinic.ca': { userId: ADMIN_USER_ID, email: 'admin@clinic.ca', fullName: 'Dr. Admin', role: Role.PHYSICIAN },
        'physician@clinic.ca': { userId: PHYSICIAN_USER_ID, email: 'physician@clinic.ca', fullName: 'Dr. Physician', role: Role.PHYSICIAN },
        'other-admin@clinic.ca': { userId: OTHER_ADMIN_USER_ID, email: 'other-admin@clinic.ca', fullName: 'Dr. Other Admin', role: Role.PHYSICIAN },
        'member@clinic.ca': { userId: MEMBER_USER_ID, email: 'member@clinic.ca', fullName: 'Dr. Member', role: Role.PHYSICIAN },
      };
      return byEmail[email.toLowerCase()];
    }),
    updateUserRole: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock Subscription Repo
// ---------------------------------------------------------------------------

function createMockSubscriptionRepo(): PracticeSubscriptionRepo {
  return {
    findActiveEarlyBirdByProviderId: vi.fn(async () => null),
    findActiveSubscriptionByProviderId: vi.fn(async () => null),
    createSubscription: vi.fn(async (data: any) => ({ subscriptionId: crypto.randomUUID() })),
  };
}

// ---------------------------------------------------------------------------
// Mock Stripe Client
// ---------------------------------------------------------------------------

function createMockStripe(): PracticeStripeClient {
  return {
    customers: {
      create: vi.fn(async () => ({ id: STRIPE_CUSTOMER_ID })),
    },
    subscriptions: {
      cancel: vi.fn(async () => ({ id: 'sub_cancelled', status: 'canceled' })),
      update: vi.fn(async () => ({ id: 'sub_updated', quantity: 1 })),
      create: vi.fn(async () => ({ id: 'sub_new', status: 'active' })),
    },
  };
}

// ---------------------------------------------------------------------------
// Mock Practice Repo
// ---------------------------------------------------------------------------

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
        currentPeriodStart: data.currentPeriodStart ?? new Date(),
        currentPeriodEnd: data.currentPeriodEnd ?? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
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
      return mockPractices.find(
        (p) => p.adminUserId === adminUserId && p.status === 'ACTIVE',
      ) ?? null;
    }),

    updatePractice: vi.fn(async (practiceId: string, data: any) => {
      const practice = mockPractices.find((p) => p.practiceId === practiceId);
      if (!practice) return practice;
      Object.assign(practice, data, { updatedAt: new Date() });
      return practice;
    }),

    updatePracticeStatus: vi.fn(async (practiceId: string, status: string) => {
      const practice = mockPractices.find((p) => p.practiceId === practiceId);
      if (practice) practice.status = status;
    }),

    updatePracticeStripeIds: vi.fn(async () => {}),

    getActiveHeadcount: vi.fn(async (practiceId: string) => {
      return mockMemberships.filter(
        (m) => m.practiceId === practiceId && m.isActive,
      ).length;
    }),

    getConsolidatedSeatCount: vi.fn(async (practiceId: string) => {
      return mockMemberships.filter(
        (m) =>
          m.practiceId === practiceId &&
          m.isActive &&
          m.billingMode === BillingMode.PRACTICE_CONSOLIDATED,
      ).length;
    }),

    findActivePractices: vi.fn(async () => {
      return mockPractices.filter((p) => p.status === 'ACTIVE');
    }),
  } as unknown as PracticeRepository;
}

// ---------------------------------------------------------------------------
// Mock Membership Repo
// ---------------------------------------------------------------------------

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
      return mockMemberships.find(
        (m) => m.physicianUserId === physicianUserId && m.isActive,
      ) ?? null;
    }),

    findActiveMembershipsByPracticeId: vi.fn(async (practiceId: string) => {
      return mockMemberships.filter(
        (m) => m.practiceId === practiceId && m.isActive,
      );
    }),

    findMembershipByPracticeAndPhysician: vi.fn(
      async (practiceId: string, physicianUserId: string) => {
        return mockMemberships.find(
          (m) =>
            m.practiceId === practiceId &&
            m.physicianUserId === physicianUserId &&
            m.isActive,
        ) ?? null;
      },
    ),

    setRemovalScheduled: vi.fn(
      async (membershipId: string, removedAt: Date, removalEffectiveAt: Date) => {
        const membership = mockMemberships.find((m) => m.membershipId === membershipId);
        if (membership) {
          membership.removedAt = removedAt;
          membership.removalEffectiveAt = removalEffectiveAt;
        }
      },
    ),

    deactivateMembership: vi.fn(async (membershipId: string) => {
      const membership = mockMemberships.find((m) => m.membershipId === membershipId);
      if (membership) membership.isActive = false;
    }),

    findPendingRemovals: vi.fn(async () => []),

    deactivateAllMemberships: vi.fn(async (practiceId: string) => {
      for (const m of mockMemberships) {
        if (m.practiceId === practiceId) m.isActive = false;
      }
    }),

    updateBillingMode: vi.fn(async () => {}),

    findMembershipsByBillingMode: vi.fn(async (practiceId: string, billingMode: string) => {
      return mockMemberships.filter(
        (m) => m.practiceId === practiceId && m.billingMode === billingMode && m.isActive,
      );
    }),

    countActiveMembersByBillingMode: vi.fn(async (practiceId: string, billingMode: string) => {
      return mockMemberships.filter(
        (m) => m.practiceId === practiceId && m.billingMode === billingMode && m.isActive,
      ).length;
    }),
  } as unknown as PracticeMembershipRepository;
}

// ---------------------------------------------------------------------------
// Mock Invitation Repo
// ---------------------------------------------------------------------------

function createMockInvitationRepo(): PracticeInvitationRepository {
  return {
    createInvitation: vi.fn(async (data: any) => {
      const invitation = {
        invitationId: crypto.randomUUID(),
        practiceId: data.practiceId,
        invitedEmail: data.invitedEmail,
        invitedByUserId: data.invitedByUserId,
        status: data.status ?? 'PENDING',
        tokenHash: data.tokenHash,
        expiresAt: data.expiresAt,
        createdAt: new Date(),
      };
      mockInvitations.push(invitation);
      return invitation;
    }),

    findInvitationByTokenHash: vi.fn(async (tokenHash: string) => {
      return mockInvitations.find((inv) => inv.tokenHash === tokenHash) ?? null;
    }),

    findPendingInvitationByEmail: vi.fn(async (email: string, practiceId: string) => {
      return mockInvitations.find(
        (inv) =>
          inv.invitedEmail === email.toLowerCase() &&
          inv.practiceId === practiceId &&
          inv.status === 'PENDING',
      ) ?? null;
    }),

    findPendingInvitationsByPracticeId: vi.fn(async (practiceId: string) => {
      return mockInvitations.filter(
        (inv) => inv.practiceId === practiceId && inv.status === 'PENDING',
      );
    }),

    updateInvitationStatus: vi.fn(async (invitationId: string, status: string) => {
      const inv = mockInvitations.find((i) => i.invitationId === invitationId);
      if (inv) inv.status = status;
    }),

    expireInvitations: vi.fn(async () => 0),

    findInvitationsByEmail: vi.fn(async (email: string) => {
      return mockInvitations.filter((inv) => inv.invitedEmail === email.toLowerCase());
    }),
  } as unknown as PracticeInvitationRepository;
}

// ---------------------------------------------------------------------------
// Mock Session Repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const sessions: Record<string, any> = {
        [ADMIN_SESSION_TOKEN_HASH]: {
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
        },
        [PHYSICIAN_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: PHYSICIAN_SESSION_ID,
            userId: PHYSICIAN_USER_ID,
            tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        },
        [OTHER_ADMIN_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: OTHER_ADMIN_SESSION_ID,
            userId: OTHER_ADMIN_USER_ID,
            tokenHash: OTHER_ADMIN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: OTHER_ADMIN_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        },
        [DELEGATE_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: DELEGATE_SESSION_ID,
            userId: DELEGATE_USER_ID,
            tokenHash: DELEGATE_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: DELEGATE_USER_ID,
            role: 'DELEGATE',
            subscriptionStatus: 'ACTIVE',
          },
        },
        [MEMBER_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: MEMBER_SESSION_ID,
            userId: MEMBER_USER_ID,
            tokenHash: MEMBER_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: MEMBER_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        },
      };
      return sessions[tokenHash] ?? undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Helper: seed a practice with admin membership
// ---------------------------------------------------------------------------

function seedPracticeA() {
  const practice = {
    practiceId: PRACTICE_ID,
    name: 'Test Clinic A',
    adminUserId: ADMIN_USER_ID,
    stripeCustomerId: STRIPE_CUSTOMER_ID,
    stripeSubscriptionId: 'sub_practice_a',
    billingFrequency: 'MONTHLY',
    status: PracticeStatus.ACTIVE,
    currentPeriodStart: new Date(),
    currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  mockPractices.push(practice);

  const adminMembership = {
    membershipId: MEMBERSHIP_ADMIN_ID,
    practiceId: PRACTICE_ID,
    physicianUserId: ADMIN_USER_ID,
    billingMode: BillingMode.PRACTICE_CONSOLIDATED,
    joinedAt: new Date(),
    removedAt: null,
    removalEffectiveAt: null,
    isActive: true,
    createdAt: new Date(),
  };
  mockMemberships.push(adminMembership);

  return { practice, adminMembership };
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
  const membership = {
    membershipId: MEMBERSHIP_MEMBER_ID,
    practiceId: PRACTICE_ID,
    physicianUserId: MEMBER_USER_ID,
    billingMode: BillingMode.PRACTICE_CONSOLIDATED,
    joinedAt: new Date(),
    removedAt: null,
    removalEffectiveAt: null,
    isActive: true,
    createdAt: new Date(),
  };
  mockMemberships.push(membership);
  return membership;
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockPracticeRepo: ReturnType<typeof createMockPracticeRepo>;
let mockMembershipRepo: ReturnType<typeof createMockMembershipRepo>;
let mockInvitationRepo: ReturnType<typeof createMockInvitationRepo>;
let mockUserRepo: ReturnType<typeof createMockUserRepo>;
let mockSubscriptionRepo: ReturnType<typeof createMockSubscriptionRepo>;
let mockStripe: ReturnType<typeof createMockStripe>;
let mockAuditLogger: PracticeAuditLogger;
let mockNotifier: PracticeNotifier;
let mockEvents: { emit: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  mockPracticeRepo = createMockPracticeRepo();
  mockMembershipRepo = createMockMembershipRepo();
  mockInvitationRepo = createMockInvitationRepo();
  mockUserRepo = createMockUserRepo();
  mockSubscriptionRepo = createMockSubscriptionRepo();
  mockStripe = createMockStripe();
  mockAuditLogger = { log: vi.fn(async () => {}) };
  mockNotifier = {
    sendInvitationEmail: vi.fn(async () => {}),
    sendRemovalNotification: vi.fn(async () => {}),
    sendHeadcountWarning: vi.fn(async () => {}),
    sendDissolutionNotification: vi.fn(async () => {}),
  };
  mockEvents = { emit: vi.fn() };

  const serviceDeps: PracticeServiceDeps = {
    practiceRepo: mockPracticeRepo,
    membershipRepo: mockMembershipRepo,
    invitationRepo: mockInvitationRepo,
    userRepo: mockUserRepo,
    subscriptionRepo: mockSubscriptionRepo,
    stripe: mockStripe,
    notifier: mockNotifier,
    auditLogger: mockAuditLogger,
  };

  const handlerDeps: PracticeHandlerDeps = {
    serviceDeps,
    practiceRepo: mockPracticeRepo,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register auth plugin
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: createMockSessionRepo(),
      auditRepo: { appendAuditLog: vi.fn() },
      events: mockEvents,
    },
  });

  // Error handler (matching existing integration test pattern)
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
    console.error('UNHANDLED ERROR:', error.message, error.stack);
    request.log.error(error);
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  // Register practice routes
  await testApp.register(practiceRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function authedGet(url: string, token = ADMIN_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function authedPost(url: string, body?: Record<string, unknown>, token = ADMIN_SESSION_TOKEN) {
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

function authedPatch(url: string, body: Record<string, unknown>, token = ADMIN_SESSION_TOKEN) {
  return app.inject({
    method: 'PATCH',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body,
  });
}

function authedDelete(url: string, token = ADMIN_SESSION_TOKEN) {
  return app.inject({
    method: 'DELETE',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

function unauthedPost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body ?? {},
  });
}

function unauthedPatch(url: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'PATCH',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body,
  });
}

function unauthedDelete(url: string) {
  return app.inject({ method: 'DELETE', url });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Practice Routes Integration Tests', () => {
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
  // POST /api/v1/practices
  // =========================================================================

  describe('POST /api/v1/practices', () => {
    it('creates a practice and returns 201 with practice data', async () => {
      const res = await authedPost(
        '/api/v1/practices',
        { name: 'My Clinic', billing_frequency: 'MONTHLY' },
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.name).toBe('My Clinic');
      expect(body.data.adminUserId).toBe(PHYSICIAN_USER_ID);
    });

    it('assigns PRACTICE_ADMIN role to the creating physician', async () => {
      await authedPost(
        '/api/v1/practices',
        { name: 'My Clinic', billing_frequency: 'MONTHLY' },
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(mockUserRepo.updateUserRole).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
        Role.PRACTICE_ADMIN,
      );
    });

    it('creates a membership for the admin', async () => {
      await authedPost(
        '/api/v1/practices',
        { name: 'My Clinic', billing_frequency: 'MONTHLY' },
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(mockMembershipRepo.createMembership).toHaveBeenCalledTimes(1);
      const call = (mockMembershipRepo.createMembership as any).mock.calls[0][0];
      expect(call.physicianUserId).toBe(PHYSICIAN_USER_ID);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/practices', {
        name: 'My Clinic',
        billing_frequency: 'MONTHLY',
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for non-PHYSICIAN role', async () => {
      const res = await authedPost(
        '/api/v1/practices',
        { name: 'My Clinic', billing_frequency: 'MONTHLY' },
        DELEGATE_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('returns 422 if user already admins a practice', async () => {
      // Seed a practice where ADMIN_USER_ID is already admin
      seedPracticeA();

      const res = await authedPost(
        '/api/v1/practices',
        { name: 'Another Clinic', billing_frequency: 'MONTHLY' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });

    it('returns 422 if user is on another practice', async () => {
      // Seed a practice and a membership for PHYSICIAN
      seedPracticeA();
      mockMemberships.push({
        membershipId: crypto.randomUUID(),
        practiceId: PRACTICE_ID,
        physicianUserId: PHYSICIAN_USER_ID,
        billingMode: BillingMode.PRACTICE_CONSOLIDATED,
        joinedAt: new Date(),
        removedAt: null,
        removalEffectiveAt: null,
        isActive: true,
        createdAt: new Date(),
      });

      const res = await authedPost(
        '/api/v1/practices',
        { name: 'New Clinic', billing_frequency: 'MONTHLY' },
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });

    it('returns 400 for missing name', async () => {
      const res = await authedPost(
        '/api/v1/practices',
        { billing_frequency: 'MONTHLY' },
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for invalid billing_frequency', async () => {
      const res = await authedPost(
        '/api/v1/practices',
        { name: 'My Clinic', billing_frequency: 'WEEKLY' },
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for name exceeding 200 characters', async () => {
      const res = await authedPost(
        '/api/v1/practices',
        { name: 'A'.repeat(201), billing_frequency: 'MONTHLY' },
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // GET /api/v1/practices/:id
  // =========================================================================

  describe('GET /api/v1/practices/:id', () => {
    it('returns practice details for PRACTICE_ADMIN', async () => {
      seedPracticeA();

      const res = await authedGet(`/api/v1/practices/${PRACTICE_ID}`, ADMIN_SESSION_TOKEN);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.practiceId).toBe(PRACTICE_ID);
      expect(body.data.name).toBe('Test Clinic A');
    });

    it('returns 401 without authentication', async () => {
      seedPracticeA();

      const res = await unauthedGet(`/api/v1/practices/${PRACTICE_ID}`);

      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for non-admin physician', async () => {
      seedPracticeA();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}`,
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('returns 403 for admin of different practice', async () => {
      seedPracticeA();
      seedPracticeB();

      // OTHER_ADMIN trying to access PRACTICE_ID (admin of PRACTICE B)
      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}`,
        OTHER_ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('returns 404 for non-existent practice', async () => {
      const fakeId = '99999999-0000-0000-0000-000000000099';
      const res = await authedGet(`/api/v1/practices/${fakeId}`, ADMIN_SESSION_TOKEN);

      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // PATCH /api/v1/practices/:id
  // =========================================================================

  describe('PATCH /api/v1/practices/:id', () => {
    it('updates practice name', async () => {
      seedPracticeA();

      const res = await authedPatch(
        `/api/v1/practices/${PRACTICE_ID}`,
        { name: 'Updated Clinic Name' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.name).toBe('Updated Clinic Name');
    });

    it('updates billing frequency', async () => {
      seedPracticeA();

      const res = await authedPatch(
        `/api/v1/practices/${PRACTICE_ID}`,
        { billing_frequency: 'ANNUAL' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.billing_frequency).toBe('ANNUAL');
    });

    it('returns 401 without authentication', async () => {
      seedPracticeA();

      const res = await unauthedPatch(`/api/v1/practices/${PRACTICE_ID}`, {
        name: 'Updated',
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for non-admin', async () => {
      seedPracticeA();

      const res = await authedPatch(
        `/api/v1/practices/${PRACTICE_ID}`,
        { name: 'Unauthorized Update' },
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('returns 400 for invalid name', async () => {
      seedPracticeA();

      const res = await authedPatch(
        `/api/v1/practices/${PRACTICE_ID}`,
        { name: '' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // GET /api/v1/practices/:id/seats
  // =========================================================================

  describe('GET /api/v1/practices/:id/seats', () => {
    it('returns list of seats with physicianName, email, joinedAt, billingMode', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/seats`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.length).toBeGreaterThan(0);

      for (const seat of body.data) {
        expect(seat).toHaveProperty('physicianName');
        expect(seat).toHaveProperty('email');
        expect(seat).toHaveProperty('joinedAt');
        expect(seat).toHaveProperty('billingMode');
      }
    });

    it('response contains ONLY physicianName, email, joinedAt, billingMode per seat', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/seats`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      const ALLOWED_KEYS = ['physicianName', 'email', 'joinedAt', 'billingMode'];

      for (const seat of body.data) {
        const keys = Object.keys(seat);
        expect(keys.sort()).toEqual(ALLOWED_KEYS.sort());
      }
    });

    it('response does NOT contain any claim data fields', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/seats`,
        ADMIN_SESSION_TOKEN,
      );

      const bodyStr = JSON.stringify(res.json());
      const claimFields = ['claimId', 'claimCount', 'rejectionRate', 'submissionCount', 'healthServiceCode'];
      for (const field of claimFields) {
        expect(bodyStr).not.toContain(field);
      }
    });

    it('response does NOT contain any billing volume fields', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/seats`,
        ADMIN_SESSION_TOKEN,
      );

      const bodyStr = JSON.stringify(res.json());
      const billingFields = ['billingVolume', 'revenue', 'totalBilled', 'amountCad'];
      for (const field of billingFields) {
        expect(bodyStr).not.toContain(field);
      }
    });

    it('response does NOT contain any patient data fields', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/seats`,
        ADMIN_SESSION_TOKEN,
      );

      const bodyStr = JSON.stringify(res.json());
      const patientFields = ['patientId', 'phn', 'firstName', 'lastName', 'dateOfBirth'];
      for (const field of patientFields) {
        expect(bodyStr).not.toContain(field);
      }
    });

    it('includes both PRACTICE_CONSOLIDATED and INDIVIDUAL_EARLY_BIRD members', async () => {
      seedPracticeA();

      // Add an early bird member
      mockMemberships.push({
        membershipId: crypto.randomUUID(),
        practiceId: PRACTICE_ID,
        physicianUserId: MEMBER_USER_ID,
        billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
        joinedAt: new Date(),
        removedAt: null,
        removalEffectiveAt: null,
        isActive: true,
        createdAt: new Date(),
      });

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/seats`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      const modes = body.data.map((s: any) => s.billingMode);
      expect(modes).toContain(BillingMode.PRACTICE_CONSOLIDATED);
      expect(modes).toContain(BillingMode.INDIVIDUAL_EARLY_BIRD);
    });

    it('excludes inactive members', async () => {
      seedPracticeA();

      // Add an inactive member
      mockMemberships.push({
        membershipId: crypto.randomUUID(),
        practiceId: PRACTICE_ID,
        physicianUserId: MEMBER_USER_ID,
        billingMode: BillingMode.PRACTICE_CONSOLIDATED,
        joinedAt: new Date(),
        removedAt: new Date(),
        removalEffectiveAt: new Date(),
        isActive: false,
        createdAt: new Date(),
      });

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/seats`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      // Should only have admin membership, not the inactive member
      expect(body.data.length).toBe(1);
    });

    it('returns 401 without authentication', async () => {
      seedPracticeA();

      const res = await unauthedGet(`/api/v1/practices/${PRACTICE_ID}/seats`);

      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for non-admin', async () => {
      seedPracticeA();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/seats`,
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // POST /api/v1/practices/:id/invitations
  // =========================================================================

  describe('POST /api/v1/practices/:id/invitations', () => {
    it('creates invitation and returns 201', async () => {
      seedPracticeA();

      const res = await authedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: 'new-doc@clinic.ca' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.invitedEmail).toBe('new-doc@clinic.ca');
      expect(body.data.status).toBe('PENDING');
    });

    it('does NOT return raw token in response', async () => {
      seedPracticeA();

      const res = await authedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: 'new-doc@clinic.ca' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(201);
      const body = res.json();
      const bodyStr = JSON.stringify(body);

      // The response should NOT contain a raw token — only tokenHash is stored
      expect(body.data.token).toBeUndefined();
      expect(body.data.rawToken).toBeUndefined();
      // The tokenHash should be present (it's stored in the DB record returned)
      // but NO field named "token" with a raw value
      expect(bodyStr).not.toMatch(/"token"\s*:\s*"[a-f0-9]{64}"/);
    });

    it('returns 401 without authentication', async () => {
      seedPracticeA();

      const res = await unauthedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: 'new-doc@clinic.ca' },
      );

      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for non-admin', async () => {
      seedPracticeA();

      const res = await authedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: 'new-doc@clinic.ca' },
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('returns 422 for email already on practice', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: 'member@clinic.ca' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });

    it('returns 422 for email on another practice', async () => {
      seedPracticeA();
      seedPracticeB();

      // OTHER_ADMIN is on practice B — we try to invite them from practice A
      const res = await authedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: 'other-admin@clinic.ca' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });

    it('returns 422 for duplicate pending invitation', async () => {
      seedPracticeA();

      // First invitation
      mockInvitations.push({
        invitationId: INVITATION_ID,
        practiceId: PRACTICE_ID,
        invitedEmail: 'new-doc@clinic.ca',
        invitedByUserId: ADMIN_USER_ID,
        status: 'PENDING',
        tokenHash: 'some-hash',
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        createdAt: new Date(),
      });

      const res = await authedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: 'new-doc@clinic.ca' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });

    it('returns 400 for invalid email format', async () => {
      seedPracticeA();

      const res = await authedPost(
        `/api/v1/practices/${PRACTICE_ID}/invitations`,
        { email: 'not-an-email' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // POST /api/v1/practice-invitations/:token/accept
  // =========================================================================

  describe('POST /api/v1/practice-invitations/:token/accept', () => {
    const RAW_TOKEN = randomBytes(32).toString('hex');
    const TOKEN_HASH = hashToken(RAW_TOKEN);

    function seedPendingInvitation(overrides?: Record<string, any>) {
      const invitation = {
        invitationId: INVITATION_ID,
        practiceId: PRACTICE_ID,
        invitedEmail: 'member@clinic.ca',
        invitedByUserId: ADMIN_USER_ID,
        status: 'PENDING',
        tokenHash: TOKEN_HASH,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        createdAt: new Date(),
        ...overrides,
      };
      mockInvitations.push(invitation);
      return invitation;
    }

    it('accepts invitation and creates membership', async () => {
      seedPracticeA();
      seedPendingInvitation();

      const res = await authedPost(
        `/api/v1/practice-invitations/${RAW_TOKEN}/accept`,
        {},
        MEMBER_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.practiceId).toBe(PRACTICE_ID);
      expect(body.data.physicianUserId).toBe(MEMBER_USER_ID);
    });

    it('sets billing_mode to INDIVIDUAL_EARLY_BIRD for early bird physician', async () => {
      seedPracticeA();
      seedPendingInvitation();

      // Mock: physician has an early bird subscription
      (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValueOnce({
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
      });

      const res = await authedPost(
        `/api/v1/practice-invitations/${RAW_TOKEN}/accept`,
        {},
        MEMBER_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.billingMode).toBe(BillingMode.INDIVIDUAL_EARLY_BIRD);
    });

    it('sets billing_mode to PRACTICE_CONSOLIDATED for non-early-bird physician', async () => {
      seedPracticeA();
      seedPendingInvitation();

      // Default mock returns null (no early bird)
      const res = await authedPost(
        `/api/v1/practice-invitations/${RAW_TOKEN}/accept`,
        {},
        MEMBER_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.billingMode).toBe(BillingMode.PRACTICE_CONSOLIDATED);
    });

    it('returns 401 without authentication', async () => {
      seedPracticeA();
      seedPendingInvitation();

      const res = await unauthedPost(
        `/api/v1/practice-invitations/${RAW_TOKEN}/accept`,
      );

      expect(res.statusCode).toBe(401);
    });

    it('returns 404 for invalid token', async () => {
      seedPracticeA();

      const res = await authedPost(
        '/api/v1/practice-invitations/invalid-token-value/accept',
        {},
        MEMBER_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(404);
    });

    it('returns 422 for expired invitation', async () => {
      seedPracticeA();
      seedPendingInvitation({
        expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000), // expired yesterday
      });

      const res = await authedPost(
        `/api/v1/practice-invitations/${RAW_TOKEN}/accept`,
        {},
        MEMBER_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });

    it('returns 422 for already accepted invitation', async () => {
      seedPracticeA();
      seedPendingInvitation({ status: 'ACCEPTED' });

      const res = await authedPost(
        `/api/v1/practice-invitations/${RAW_TOKEN}/accept`,
        {},
        MEMBER_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });

    it('returns 403 for email mismatch', async () => {
      seedPracticeA();
      seedPendingInvitation({ invitedEmail: 'someone-else@clinic.ca' });

      const res = await authedPost(
        `/api/v1/practice-invitations/${RAW_TOKEN}/accept`,
        {},
        MEMBER_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('returns 422 for physician already on another practice', async () => {
      seedPracticeA();
      seedPracticeB();
      seedPendingInvitation();

      // MEMBER is already on practice B
      mockMemberships.push({
        membershipId: crypto.randomUUID(),
        practiceId: OTHER_PRACTICE_ID,
        physicianUserId: MEMBER_USER_ID,
        billingMode: BillingMode.PRACTICE_CONSOLIDATED,
        joinedAt: new Date(),
        removedAt: null,
        removalEffectiveAt: null,
        isActive: true,
        createdAt: new Date(),
      });

      const res = await authedPost(
        `/api/v1/practice-invitations/${RAW_TOKEN}/accept`,
        {},
        MEMBER_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });
  });

  // =========================================================================
  // DELETE /api/v1/practices/:id/seats/:userId
  // =========================================================================

  describe('DELETE /api/v1/practices/:id/seats/:userId', () => {
    it('schedules removal and returns 204', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedDelete(
        `/api/v1/practices/${PRACTICE_ID}/seats/${MEMBER_USER_ID}`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(204);
    });

    it('returns 401 without authentication', async () => {
      seedPracticeA();
      seedMember();

      const res = await unauthedDelete(
        `/api/v1/practices/${PRACTICE_ID}/seats/${MEMBER_USER_ID}`,
      );

      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for non-admin', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedDelete(
        `/api/v1/practices/${PRACTICE_ID}/seats/${MEMBER_USER_ID}`,
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('returns 422 for trying to remove admin', async () => {
      seedPracticeA();

      const res = await authedDelete(
        `/api/v1/practices/${PRACTICE_ID}/seats/${ADMIN_USER_ID}`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });

    it('returns 404 for non-existent membership', async () => {
      seedPracticeA();

      const nonMemberId = '99999999-0000-0000-0000-000000000099';
      const res = await authedDelete(
        `/api/v1/practices/${PRACTICE_ID}/seats/${nonMemberId}`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(404);
    });

    it('returns 422 for already scheduled removal', async () => {
      seedPracticeA();

      // Add a member with removal already scheduled
      mockMemberships.push({
        membershipId: MEMBERSHIP_MEMBER_ID,
        practiceId: PRACTICE_ID,
        physicianUserId: MEMBER_USER_ID,
        billingMode: BillingMode.PRACTICE_CONSOLIDATED,
        joinedAt: new Date(),
        removedAt: null,
        removalEffectiveAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        isActive: true,
        createdAt: new Date(),
      });

      const res = await authedDelete(
        `/api/v1/practices/${PRACTICE_ID}/seats/${MEMBER_USER_ID}`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
    });
  });

  // =========================================================================
  // GET /api/v1/practices/:id/invoices
  // =========================================================================

  describe('GET /api/v1/practices/:id/invoices', () => {
    it('returns consolidated invoice data', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/invoices`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
    });

    it('includes totalAmount, perSeatRate, consolidatedSeatCount, billingFrequency', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/invoices`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('totalAmount');
      expect(body.data).toHaveProperty('perSeatRate');
      expect(body.data).toHaveProperty('consolidatedSeatCount');
      expect(body.data).toHaveProperty('billingFrequency');
    });

    it('does NOT return individual physician payment records', async () => {
      seedPracticeA();
      seedMember();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/invoices`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      const bodyStr = JSON.stringify(body);

      // Should not contain individual payment fields
      expect(bodyStr).not.toContain('paymentId');
      expect(bodyStr).not.toContain('stripeInvoiceId');
      expect(bodyStr).not.toContain('paidAt');
      // Invoice data should NOT be an array of individual records
      expect(Array.isArray(body.data)).toBe(false);
    });

    it('returns 401 without authentication', async () => {
      seedPracticeA();

      const res = await unauthedGet(`/api/v1/practices/${PRACTICE_ID}/invoices`);

      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for non-admin', async () => {
      seedPracticeA();

      const res = await authedGet(
        `/api/v1/practices/${PRACTICE_ID}/invoices`,
        PHYSICIAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Cross-practice isolation
  // =========================================================================

  describe('Cross-practice isolation', () => {
    it('admin of practice A gets 403 on practice B GET endpoint', async () => {
      seedPracticeA();
      seedPracticeB();

      const res = await authedGet(
        `/api/v1/practices/${OTHER_PRACTICE_ID}`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('admin of practice A gets 403 on practice B seats endpoint', async () => {
      seedPracticeA();
      seedPracticeB();

      const res = await authedGet(
        `/api/v1/practices/${OTHER_PRACTICE_ID}/seats`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('admin of practice A gets 403 on practice B invitations endpoint', async () => {
      seedPracticeA();
      seedPracticeB();

      const res = await authedPost(
        `/api/v1/practices/${OTHER_PRACTICE_ID}/invitations`,
        { email: 'someone@clinic.ca' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('admin of practice A gets 403 on practice B invoices endpoint', async () => {
      seedPracticeA();
      seedPracticeB();

      const res = await authedGet(
        `/api/v1/practices/${OTHER_PRACTICE_ID}/invoices`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('admin of practice A gets 403 on practice B PATCH endpoint', async () => {
      seedPracticeA();
      seedPracticeB();

      const res = await authedPatch(
        `/api/v1/practices/${OTHER_PRACTICE_ID}`,
        { name: 'Hacked Name' },
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });

    it('admin of practice A gets 403 on practice B DELETE seat endpoint', async () => {
      seedPracticeA();
      seedPracticeB();

      const res = await authedDelete(
        `/api/v1/practices/${OTHER_PRACTICE_ID}/seats/${OTHER_ADMIN_USER_ID}`,
        ADMIN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(403);
    });
  });
});
