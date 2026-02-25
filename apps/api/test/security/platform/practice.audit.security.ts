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
  createPractice,
  invitePhysician,
  acceptInvitation,
  removePhysician,
  handleEndOfMonthRemovals,
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

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

const MEMBER_USER_ID = '00000000-1111-0000-0000-000000000004';

const PRACTICE_ID = '00000000-3333-0000-0000-000000000001';
const MEMBERSHIP_ADMIN_ID = '00000000-4444-0000-0000-000000000001';
const MEMBERSHIP_MEMBER_ID = '00000000-4444-0000-0000-000000000002';
const INVITATION_ID = '00000000-5555-0000-0000-000000000001';
const INVITATION_TOKEN = randomBytes(32).toString('hex');
const INVITATION_TOKEN_HASH = hashToken(INVITATION_TOKEN);

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
        [ADMIN_USER_ID]: { userId: ADMIN_USER_ID, email: 'admin@clinic.ca', fullName: 'Dr. Admin', role: 'PHYSICIAN' },
        [MEMBER_USER_ID]: { userId: MEMBER_USER_ID, email: 'member@clinic.ca', fullName: 'Dr. Member', role: 'PHYSICIAN' },
      };
      return users[userId];
    }),
    findUserByEmail: vi.fn(async (email: string) => {
      if (email === 'member@clinic.ca') {
        return { userId: MEMBER_USER_ID, email: 'member@clinic.ca', fullName: 'Dr. Member', role: 'PHYSICIAN' };
      }
      return undefined;
    }),
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
    createMembership: vi.fn(async (data: any) => {
      const membership = {
        membershipId: MEMBERSHIP_MEMBER_ID,
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
    createInvitation: vi.fn(async (data: any) => ({
      invitationId: INVITATION_ID,
      practiceId: data.practiceId,
      invitedEmail: data.invitedEmail,
      invitedByUserId: data.invitedByUserId,
      status: data.status,
      tokenHash: data.tokenHash,
      expiresAt: data.expiresAt,
      createdAt: new Date(),
    })),
    findInvitationByTokenHash: vi.fn(async (tokenHash: string) => {
      return mockInvitations.find((inv) => inv.tokenHash === tokenHash) ?? null;
    }),
    findPendingInvitationByEmail: vi.fn(async () => null),
    findPendingInvitationsByPracticeId: vi.fn(async () => []),
    updateInvitationStatus: vi.fn(async () => {}),
    expireInvitations: vi.fn(async () => 0),
    findInvitationsByEmail: vi.fn(async () => []),
  } as unknown as PracticeInvitationRepository;
}

function createMockAuditLogger(): PracticeAuditLogger & { log: ReturnType<typeof vi.fn> } {
  return {
    log: vi.fn(async () => {}),
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

function seedPendingInvitation() {
  mockInvitations.push({
    invitationId: INVITATION_ID,
    practiceId: PRACTICE_ID,
    invitedEmail: 'member@clinic.ca',
    invitedByUserId: ADMIN_USER_ID,
    status: 'PENDING',
    tokenHash: INVITATION_TOKEN_HASH,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
  });
}

// ---------------------------------------------------------------------------
// Build service deps with configurable audit logger
// ---------------------------------------------------------------------------

function buildServiceDeps(overrides?: {
  auditLogger?: PracticeAuditLogger;
  practiceRepo?: PracticeRepository;
  membershipRepo?: PracticeMembershipRepository;
  invitationRepo?: PracticeInvitationRepository;
}): PracticeServiceDeps {
  return {
    practiceRepo: overrides?.practiceRepo ?? createMockPracticeRepo(),
    membershipRepo: overrides?.membershipRepo ?? createMockMembershipRepo(),
    invitationRepo: overrides?.invitationRepo ?? createMockInvitationRepo(),
    userRepo: createMockUserRepo(),
    subscriptionRepo: createMockSubscriptionRepo(),
    stripe: createMockStripe(),
    notifier: {
      sendInvitationEmail: vi.fn(async () => {}),
      sendRemovalNotification: vi.fn(async () => {}),
      sendHeadcountWarning: vi.fn(async () => {}),
      sendDissolutionNotification: vi.fn(async () => {}),
    },
    auditLogger: overrides?.auditLogger ?? createMockAuditLogger(),
  };
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('D16-045: Practice Audit Trail Verification (Security)', () => {
  beforeEach(() => {
    mockPractices = [];
    mockMemberships = [];
    mockInvitations = [];
    vi.clearAllMocks();
  });

  // =========================================================================
  // Practice creation produces audit record
  // =========================================================================

  describe('Practice creation produces audit record', () => {
    it('createPractice logs practice.created with correct action and resourceType', async () => {
      const auditLogger = createMockAuditLogger();
      const deps = buildServiceDeps({ auditLogger });

      await createPractice(deps, ADMIN_USER_ID, 'My Clinic', 'MONTHLY');

      expect(auditLogger.log).toHaveBeenCalledTimes(1);
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'practice.created',
          resourceType: 'practice',
          resourceId: PRACTICE_ID,
          actorType: 'physician',
        }),
      );
    });

    it('practice.created audit record contains adminUserId and practiceName', async () => {
      const auditLogger = createMockAuditLogger();
      const deps = buildServiceDeps({ auditLogger });

      await createPractice(deps, ADMIN_USER_ID, 'My Clinic', 'MONTHLY');

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({
            adminUserId: ADMIN_USER_ID,
            practiceName: 'My Clinic',
          }),
        }),
      );
    });

    it('practice.created audit record does NOT contain Stripe secrets', async () => {
      const auditLogger = createMockAuditLogger();
      const deps = buildServiceDeps({ auditLogger });

      await createPractice(deps, ADMIN_USER_ID, 'My Clinic', 'MONTHLY');

      expect(auditLogger.log).toHaveBeenCalled();
      const logEntry = JSON.stringify(auditLogger.log.mock.calls[0][0]);
      expect(logEntry).not.toContain('sk_live');
      expect(logEntry).not.toContain('sk_test');
      expect(logEntry).not.toContain('whsec_');
    });
  });

  // =========================================================================
  // Invitation sent produces audit record
  // =========================================================================

  describe('Invitation sent produces audit record', () => {
    it('invitePhysician logs practice.invitation_sent', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const invitationRepo = createMockInvitationRepo();

      seedPracticeA();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        invitationRepo,
      });

      await invitePhysician(deps, PRACTICE_ID, 'newdoc@clinic.ca', ADMIN_USER_ID);

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'practice.invitation_sent',
          resourceType: 'practice_invitation',
          resourceId: INVITATION_ID,
          actorType: 'physician',
        }),
      );
    });

    it('invitation audit record contains practiceId and invitedEmail', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const invitationRepo = createMockInvitationRepo();

      seedPracticeA();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        invitationRepo,
      });

      await invitePhysician(deps, PRACTICE_ID, 'newdoc@clinic.ca', ADMIN_USER_ID);

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({
            practiceId: PRACTICE_ID,
            invitedEmail: 'newdoc@clinic.ca',
            invitedByUserId: ADMIN_USER_ID,
          }),
        }),
      );
    });

    it('invitation audit record does NOT contain the raw invitation token', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const invitationRepo = createMockInvitationRepo();

      seedPracticeA();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        invitationRepo,
      });

      await invitePhysician(deps, PRACTICE_ID, 'newdoc@clinic.ca', ADMIN_USER_ID);

      expect(auditLogger.log).toHaveBeenCalled();
      const logEntry = JSON.stringify(auditLogger.log.mock.calls[0][0]);
      // The raw token should never appear in audit logs — only the hash is stored
      expect(logEntry).not.toContain('rawToken');
      expect(logEntry).not.toContain('tokenHash');
    });
  });

  // =========================================================================
  // Invitation accepted produces audit record
  // =========================================================================

  describe('Invitation accepted produces audit record', () => {
    it('acceptInvitation logs practice.invitation_accepted', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();
      const invitationRepo = createMockInvitationRepo();

      seedPracticeA();
      seedPendingInvitation();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
        invitationRepo,
      });

      await acceptInvitation(deps, INVITATION_TOKEN, MEMBER_USER_ID);

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'practice.invitation_accepted',
          resourceType: 'practice_membership',
          resourceId: MEMBERSHIP_MEMBER_ID,
          actorType: 'physician',
        }),
      );
    });

    it('acceptance audit record contains practiceId, physicianUserId, billingMode', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();
      const invitationRepo = createMockInvitationRepo();

      seedPracticeA();
      seedPendingInvitation();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
        invitationRepo,
      });

      await acceptInvitation(deps, INVITATION_TOKEN, MEMBER_USER_ID);

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({
            practiceId: PRACTICE_ID,
            physicianUserId: MEMBER_USER_ID,
            billingMode: BillingMode.PRACTICE_CONSOLIDATED,
            invitationId: INVITATION_ID,
          }),
        }),
      );
    });
  });

  // =========================================================================
  // Physician removal produces audit record
  // =========================================================================

  describe('Physician removal produces audit record', () => {
    it('removePhysician logs practice.physician_removed', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();

      seedPracticeA();
      seedMember();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
      });

      await removePhysician(deps, PRACTICE_ID, MEMBER_USER_ID, ADMIN_USER_ID);

      // May have 1 or 2 audit calls (removal + optional headcount warning)
      const removalCall = auditLogger.log.mock.calls.find(
        (call: any) => call[0].action === 'practice.physician_removed',
      );
      expect(removalCall).toBeDefined();

      expect(removalCall![0]).toMatchObject({
        action: 'practice.physician_removed',
        resourceType: 'practice_membership',
        resourceId: MEMBERSHIP_MEMBER_ID,
        actorType: 'physician',
      });
    });

    it('removal audit record contains practiceId, physicianUserId, removedByUserId', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();

      seedPracticeA();
      seedMember();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
      });

      await removePhysician(deps, PRACTICE_ID, MEMBER_USER_ID, ADMIN_USER_ID);

      const removalCall = auditLogger.log.mock.calls.find(
        (call: any) => call[0].action === 'practice.physician_removed',
      );
      expect(removalCall).toBeDefined();

      expect(removalCall![0].metadata).toMatchObject({
        practiceId: PRACTICE_ID,
        physicianUserId: MEMBER_USER_ID,
        removedByUserId: ADMIN_USER_ID,
      });
      // removalEffectiveAt should be a date string
      expect(removalCall![0].metadata.removalEffectiveAt).toBeDefined();
    });

    it('removal audit record does NOT contain patient data or PHI', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();

      seedPracticeA();
      seedMember();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
      });

      await removePhysician(deps, PRACTICE_ID, MEMBER_USER_ID, ADMIN_USER_ID);

      for (const call of auditLogger.log.mock.calls) {
        const logEntry = JSON.stringify(call[0]);
        expect(logEntry).not.toContain('patientId');
        expect(logEntry).not.toContain('phn');
        expect(logEntry).not.toContain('claimId');
        expect(logEntry).not.toContain('healthServiceCode');
        expect(logEntry).not.toContain('diagnosticCode');
      }
    });
  });

  // =========================================================================
  // Low headcount warning produces audit record
  // =========================================================================

  describe('Low headcount warning produces audit record', () => {
    it('removePhysician logs practice.headcount_warning when below minimum', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();

      seedPracticeA();
      seedMember();

      // Override getActiveHeadcount to return a low number (below minimum of 5)
      (practiceRepo.getActiveHeadcount as any).mockResolvedValue(2);

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
      });

      await removePhysician(deps, PRACTICE_ID, MEMBER_USER_ID, ADMIN_USER_ID);

      const warningCall = auditLogger.log.mock.calls.find(
        (call: any) => call[0].action === 'practice.headcount_warning',
      );
      expect(warningCall).toBeDefined();

      expect(warningCall![0]).toMatchObject({
        action: 'practice.headcount_warning',
        resourceType: 'practice',
        resourceId: PRACTICE_ID,
        actorType: 'system',
      });

      // Should include headcount details
      expect(warningCall![0].metadata).toHaveProperty('currentHeadcount');
      expect(warningCall![0].metadata).toHaveProperty('projectedHeadcount');
      expect(warningCall![0].metadata).toHaveProperty('minimumRequired');
    });
  });

  // =========================================================================
  // Practice dissolution produces audit record
  // =========================================================================

  describe('Practice dissolution produces audit record', () => {
    it('handleEndOfMonthRemovals logs practice.dissolved when headcount drops below minimum', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();

      seedPracticeA();
      seedMember();

      // Set up a pending removal that has passed its effective date
      const pastRemoval = {
        membershipId: MEMBERSHIP_MEMBER_ID,
        practiceId: PRACTICE_ID,
        physicianUserId: MEMBER_USER_ID,
        billingMode: BillingMode.PRACTICE_CONSOLIDATED,
        joinedAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000),
        removedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        removalEffectiveAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
        isActive: true,
        createdAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000),
      };

      // Mock findPendingRemovals to return our removal
      (membershipRepo.findPendingRemovals as any).mockResolvedValue([pastRemoval]);

      // After deactivation, headcount drops below minimum (return 1, which is below 5)
      (practiceRepo.getActiveHeadcount as any).mockResolvedValue(1);

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
      });

      const result = await handleEndOfMonthRemovals(deps);

      expect(result.dissolvedPractices).toContain(PRACTICE_ID);

      const dissolvedCall = auditLogger.log.mock.calls.find(
        (call: any) => call[0].action === 'practice.dissolved',
      );
      expect(dissolvedCall).toBeDefined();

      expect(dissolvedCall![0]).toMatchObject({
        action: 'practice.dissolved',
        resourceType: 'practice',
        resourceId: PRACTICE_ID,
        actorType: 'system',
      });

      expect(dissolvedCall![0].metadata).toMatchObject({
        reason: 'BELOW_MINIMUM_HEADCOUNT',
      });
      expect(dissolvedCall![0].metadata).toHaveProperty('remainingMemberCount');
      expect(dissolvedCall![0].metadata).toHaveProperty('minimumRequired');
    });
  });

  // =========================================================================
  // Audit entries do not contain Stripe secrets or PHI
  // =========================================================================

  describe('Audit entries do not contain secrets or PHI', () => {
    it('practice creation audit does not contain Stripe API keys', async () => {
      const auditLogger = createMockAuditLogger();
      const deps = buildServiceDeps({ auditLogger });

      await createPractice(deps, ADMIN_USER_ID, 'My Clinic', 'MONTHLY');

      for (const call of auditLogger.log.mock.calls) {
        const logEntry = JSON.stringify(call[0]);
        expect(logEntry).not.toContain('sk_live');
        expect(logEntry).not.toContain('sk_test');
        expect(logEntry).not.toContain('whsec_');
      }
    });

    it('invitation audit does not contain raw invitation token', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const invitationRepo = createMockInvitationRepo();

      seedPracticeA();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        invitationRepo,
      });

      await invitePhysician(deps, PRACTICE_ID, 'newdoc@clinic.ca', ADMIN_USER_ID);

      for (const call of auditLogger.log.mock.calls) {
        const logEntry = JSON.stringify(call[0]);
        // The raw token is a 64-character hex string; it should never be in audit logs
        expect(logEntry).not.toContain('rawToken');
      }
    });

    it('removal audit does not contain patient PHI', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();

      seedPracticeA();
      seedMember();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
      });

      await removePhysician(deps, PRACTICE_ID, MEMBER_USER_ID, ADMIN_USER_ID);

      const phiFields = ['patientId', 'phn', 'claimId', 'healthServiceCode', 'diagnosticCode', 'dateOfBirth'];
      for (const call of auditLogger.log.mock.calls) {
        const logEntry = JSON.stringify(call[0]);
        for (const field of phiFields) {
          expect(logEntry).not.toContain(field);
        }
      }
    });

    it('dissolution audit does not contain patient PHI or Stripe secrets', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();

      seedPracticeA();
      seedMember();

      const pastRemoval = {
        membershipId: MEMBERSHIP_MEMBER_ID,
        practiceId: PRACTICE_ID,
        physicianUserId: MEMBER_USER_ID,
        billingMode: BillingMode.PRACTICE_CONSOLIDATED,
        joinedAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000),
        removedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        removalEffectiveAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
        isActive: true,
        createdAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000),
      };

      (membershipRepo.findPendingRemovals as any).mockResolvedValue([pastRemoval]);
      (practiceRepo.getActiveHeadcount as any).mockResolvedValue(1);

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
      });

      await handleEndOfMonthRemovals(deps);

      const phiFields = ['patientId', 'phn', 'claimId', 'healthServiceCode'];
      for (const call of auditLogger.log.mock.calls) {
        const logEntry = JSON.stringify(call[0]);
        for (const field of phiFields) {
          expect(logEntry).not.toContain(field);
        }
        expect(logEntry).not.toContain('sk_live');
        expect(logEntry).not.toContain('sk_test');
        expect(logEntry).not.toContain('whsec_');
      }
    });
  });

  // =========================================================================
  // All auditable actions produce exactly one audit record each
  // =========================================================================

  describe('Audit record count sanity checks', () => {
    it('createPractice produces exactly 1 audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const deps = buildServiceDeps({ auditLogger });

      await createPractice(deps, ADMIN_USER_ID, 'My Clinic', 'MONTHLY');

      expect(auditLogger.log).toHaveBeenCalledTimes(1);
    });

    it('invitePhysician produces exactly 1 audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const invitationRepo = createMockInvitationRepo();

      seedPracticeA();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        invitationRepo,
      });

      await invitePhysician(deps, PRACTICE_ID, 'newdoc@clinic.ca', ADMIN_USER_ID);

      expect(auditLogger.log).toHaveBeenCalledTimes(1);
    });

    it('acceptInvitation produces exactly 1 audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();
      const invitationRepo = createMockInvitationRepo();

      seedPracticeA();
      seedPendingInvitation();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
        invitationRepo,
      });

      await acceptInvitation(deps, INVITATION_TOKEN, MEMBER_USER_ID);

      expect(auditLogger.log).toHaveBeenCalledTimes(1);
    });

    it('removePhysician produces at least 1 audit record (removal)', async () => {
      const auditLogger = createMockAuditLogger();
      const practiceRepo = createMockPracticeRepo();
      const membershipRepo = createMockMembershipRepo();

      seedPracticeA();
      seedMember();

      const deps = buildServiceDeps({
        auditLogger,
        practiceRepo,
        membershipRepo,
      });

      await removePhysician(deps, PRACTICE_ID, MEMBER_USER_ID, ADMIN_USER_ID);

      // At least 1 (removal), possibly 2 (+ headcount warning)
      expect(auditLogger.log.mock.calls.length).toBeGreaterThanOrEqual(1);

      // Ensure the removal audit is always present
      const removalCalls = auditLogger.log.mock.calls.filter(
        (call: any) => call[0].action === 'practice.physician_removed',
      );
      expect(removalCalls.length).toBe(1);
    });
  });
});
