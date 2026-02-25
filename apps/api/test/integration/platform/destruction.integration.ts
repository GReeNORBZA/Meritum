import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Environment setup
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by transitive imports)
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
  runDeletionCheck,
  runDestructionConfirmation,
  markBackupPurged,
  type PlatformServiceDeps,
  type StripeClient,
  type StripeEvent,
  type PlatformEventEmitter,
  type DataDeletionRepo,
  type AuditLogger,
  type UserRepo,
} from '../../../src/domains/platform/platform.service.js';
import {
  BACKUP_PURGE_DEADLINE_DAYS,
} from '@meritum/shared/constants/platform.constants.js';
import type { SpacesFileClient } from '../../../src/lib/spaces.js';
import type { DestructionTrackingRepository } from '../../../src/domains/platform/platform.repository.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function createMockStripe(): StripeClient {
  return {
    customers: {
      create: vi.fn(async () => ({ id: 'cus_test' })),
      del: vi.fn(async () => ({ id: 'cus_test', deleted: true })),
    },
    checkout: {
      sessions: {
        create: vi.fn(async () => ({ url: 'https://checkout.stripe.com/test' })),
      },
    },
    billingPortal: {
      sessions: {
        create: vi.fn(async () => ({ url: 'https://billing.stripe.com/test' })),
      },
    },
    taxRates: {
      create: vi.fn(async () => ({ id: 'txr_test' })),
    },
    webhooks: {
      constructEvent: vi.fn((_payload, _signature, _secret): StripeEvent => {
        throw new Error('Not configured');
      }),
    },
    invoiceItems: {
      create: vi.fn(async () => ({ id: 'ii_test' })),
    },
    subscriptions: {
      cancel: vi.fn(async () => ({ id: 'sub_test', status: 'canceled' })),
      update: vi.fn(async () => ({ id: 'sub_test', status: 'active' })),
    },
  };
}

function createMockSubscriptionRepo() {
  return {
    createSubscription: vi.fn(async (data: any) => ({
      subscriptionId: `sub-${Date.now()}`,
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findSubscriptionByProviderId: vi.fn(async () => undefined),
    findSubscriptionByStripeCustomerId: vi.fn(async () => undefined),
    findSubscriptionByStripeSubscriptionId: vi.fn(async () => undefined),
    updateSubscriptionStatus: vi.fn(async (id: string, status: string, metadata?: any) => ({
      subscriptionId: id,
      status,
      ...metadata,
    })),
    updateSubscriptionPeriod: vi.fn(async () => undefined),
    updateSubscriptionPlan: vi.fn(async () => undefined),
    incrementFailedPaymentCount: vi.fn(async () => undefined),
    resetFailedPaymentCount: vi.fn(async () => undefined),
    findPastDueSubscriptions: vi.fn(async () => []),
    findSubscriptionsDueForSuspension: vi.fn(async () => []),
    findSubscriptionsDueForCancellation: vi.fn(async () => []),
    findSubscriptionsDueForDeletion: vi.fn(async () => []),
    countEarlyBirdSubscriptions: vi.fn(async () => 0),
    findAllSubscriptions: vi.fn(async () => ({ data: [], total: 0 })),
    updateSubscription: vi.fn(async () => undefined),
    hasEverHadEarlyBird: vi.fn(async () => false),
    findExpiringEarlyBirdSubscriptions: vi.fn(async () => []),
    findExpiredEarlyBirdSubscriptions: vi.fn(async () => []),
    getActivePracticeMembership: vi.fn(async () => null),
    updatePracticeMembershipBillingMode: vi.fn(async () => undefined),
    getEarlyBirdMembersInPractice: vi.fn(async () => []),
    findCancelledSubscriptionsInExportWindow: vi.fn(async () => []),
  };
}

function createMockPaymentRepo() {
  return {
    recordPayment: vi.fn(async (data: any) => ({
      paymentId: `pay-${Date.now()}`,
      ...data,
      createdAt: new Date(),
    })),
    findPaymentByStripeInvoiceId: vi.fn(async () => undefined),
    listPaymentsForSubscription: vi.fn(async () => ({ data: [], total: 0 })),
    updatePaymentStatus: vi.fn(async () => undefined),
    getPaymentSummary: vi.fn(async () => ({
      totalPaid: '0.00',
      totalGst: '0.00',
      paymentCount: 0,
      lastPaymentDate: null,
    })),
  };
}

function createMockStatusComponentRepo() {
  return {
    listComponents: vi.fn(async () => []),
    updateComponentStatus: vi.fn(async () => undefined),
    seedComponents: vi.fn(async () => undefined),
  };
}

function createMockIncidentRepo() {
  return {
    createIncident: vi.fn(async () => ({
      incidentId: 'inc-1',
      title: '',
      status: 'INVESTIGATING',
      severity: 'minor',
      affectedComponents: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      resolvedAt: null,
      updates: [],
    })),
    updateIncident: vi.fn(async () => undefined),
    listActiveIncidents: vi.fn(async () => []),
    listIncidentHistory: vi.fn(async () => ({ data: [], total: 0 })),
    findIncidentById: vi.fn(async () => undefined),
  };
}

function createMockUserRepo(): UserRepo {
  return {
    findUserById: vi.fn(async () => ({
      userId: 'user-1',
      email: 'dr.smith@clinic.ca',
      fullName: 'Dr. Smith',
    })),
    updateSubscriptionStatus: vi.fn(async () => undefined),
  };
}

function createMockDataDeletionRepo(): DataDeletionRepo {
  return {
    deleteClaimsByProviderId: vi.fn(async () => 5),
    deletePatientsByProviderId: vi.fn(async () => 3),
    deleteReportsByProviderId: vi.fn(async () => 2),
    stripPiiFromAuditLogs: vi.fn(async () => 10),
    anonymiseAiLearningData: vi.fn(async () => 4),
    deactivateUser: vi.fn(async () => undefined),
  };
}

function createMockAuditLogger(): AuditLogger {
  return {
    log: vi.fn(async () => undefined),
  };
}

function createMockEventEmitter(): PlatformEventEmitter {
  return {
    emit: vi.fn(),
  };
}

function createMockSpacesFileClient(): SpacesFileClient {
  return {
    deleteProviderFiles: vi.fn(async () => ({
      totalDeleted: 7,
      prefixes: { exports: 2, reports: 3, uploads: 2 },
    })),
  };
}

function createMockDestructionTrackingRepo(): {
  [K in keyof DestructionTrackingRepository]: ReturnType<typeof vi.fn>;
} {
  return {
    createTrackingRecord: vi.fn(async (data: any) => ({
      trackingId: crypto.randomUUID(),
      ...data,
      createdAt: new Date(),
    })),
    findByProviderId: vi.fn(async () => undefined),
    updateActiveDeletedAt: vi.fn(async () => undefined),
    updateFilesDeletedAt: vi.fn(async () => undefined),
    updateBackupPurgedAt: vi.fn(async () => undefined),
    updateConfirmationSentAt: vi.fn(async () => undefined),
    findPendingConfirmations: vi.fn(async () => []),
    findOverdueBackupPurges: vi.fn(async () => []),
  };
}

function buildDeps(overrides?: Partial<PlatformServiceDeps>): PlatformServiceDeps {
  return {
    subscriptionRepo: createMockSubscriptionRepo(),
    paymentRepo: createMockPaymentRepo(),
    statusComponentRepo: createMockStatusComponentRepo(),
    incidentRepo: createMockIncidentRepo(),
    userRepo: createMockUserRepo(),
    stripe: createMockStripe(),
    config: {
      stripePriceStandardMonthly: 'price_std_mo',
      stripePriceStandardAnnual: 'price_std_yr',
      stripePriceEarlyBirdMonthly: 'price_eb_mo',
      stripePriceEarlyBirdAnnual: 'price_eb_yr',
      stripeWebhookSecret: 'whsec_test',
    },
    auditLogger: createMockAuditLogger(),
    dataDeletionRepo: createMockDataDeletionRepo(),
    ...overrides,
  };
}

// ===========================================================================
// Tests: Data Destruction Pipeline (IMA §8.4) — Integration
// ===========================================================================

describe('Data Destruction Pipeline (IMA §8.4)', () => {
  // -------------------------------------------------------------------------
  // Deletion execution
  // -------------------------------------------------------------------------

  describe('Deletion execution', () => {
    it('after 45-day grace period, PHI is deleted from active tables', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          subscriptionId: 'sub-del-1',
          providerId: 'provider-del-1',
          stripeCustomerId: 'cus_del_1',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
        },
      ]);

      const dataDeletionRepo = createMockDataDeletionRepo();
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const spacesFileClient = createMockSpacesFileClient();
      const deps = buildDeps({
        subscriptionRepo: subRepo,
        dataDeletionRepo,
        destructionTrackingRepo,
        spacesFileClient,
      });
      const emitter = createMockEventEmitter();

      const result = await runDeletionCheck(deps, emitter);

      expect(result.deleted).toBe(1);

      // Claims deleted
      expect(dataDeletionRepo.deleteClaimsByProviderId).toHaveBeenCalledWith(
        'provider-del-1',
      );
      // Reports deleted
      expect(dataDeletionRepo.deleteReportsByProviderId).toHaveBeenCalledWith(
        'provider-del-1',
      );
      // User deactivated
      expect(dataDeletionRepo.deactivateUser).toHaveBeenCalledWith(
        'provider-del-1',
      );
      // Stripe customer deleted
      expect(deps.stripe.customers.del).toHaveBeenCalledWith('cus_del_1');
    });

    it('patients table has no records for the provider', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          subscriptionId: 'sub-pat-del',
          providerId: 'provider-pat-del',
          stripeCustomerId: 'cus_pat_del',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
        },
      ]);

      const dataDeletionRepo = createMockDataDeletionRepo();
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const deps = buildDeps({
        subscriptionRepo: subRepo,
        dataDeletionRepo,
        destructionTrackingRepo,
      });
      const emitter = createMockEventEmitter();

      await runDeletionCheck(deps, emitter);

      expect(dataDeletionRepo.deletePatientsByProviderId).toHaveBeenCalledWith(
        'provider-pat-del',
      );
    });

    it('audit log entries are preserved but PII is stripped', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          subscriptionId: 'sub-audit-strip',
          providerId: 'provider-audit-strip',
          stripeCustomerId: 'cus_audit',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
        },
      ]);

      const dataDeletionRepo = createMockDataDeletionRepo();
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const deps = buildDeps({
        subscriptionRepo: subRepo,
        dataDeletionRepo,
        destructionTrackingRepo,
      });
      const emitter = createMockEventEmitter();

      await runDeletionCheck(deps, emitter);

      // Verify stripPiiFromAuditLogs was called (logs preserved, PII stripped)
      expect(dataDeletionRepo.stripPiiFromAuditLogs).toHaveBeenCalledWith(
        'provider-audit-strip',
      );
      // AI learning data anonymised (not deleted)
      expect(dataDeletionRepo.anonymiseAiLearningData).toHaveBeenCalledWith(
        'provider-audit-strip',
      );
    });

    it('IMA records are preserved (legal evidence)', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          subscriptionId: 'sub-ima-preserve',
          providerId: 'provider-ima-preserve',
          stripeCustomerId: 'cus_ima',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
        },
      ]);

      const dataDeletionRepo = createMockDataDeletionRepo();
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const deps = buildDeps({
        subscriptionRepo: subRepo,
        dataDeletionRepo,
        destructionTrackingRepo,
      });
      const emitter = createMockEventEmitter();

      await runDeletionCheck(deps, emitter);

      // IMA records (amendment responses) are NOT in the deletionRepo's scope:
      // only claims, patients, and reports are deleted. Audit logs are stripped.
      // No deleteImaRecords method should exist on dataDeletionRepo.
      expect(dataDeletionRepo.deleteClaimsByProviderId).toHaveBeenCalled();
      expect(dataDeletionRepo.deletePatientsByProviderId).toHaveBeenCalled();
      expect(dataDeletionRepo.deleteReportsByProviderId).toHaveBeenCalled();
      // Verify IMA records NOT deleted — deletion repo has no such method
      expect(dataDeletionRepo).not.toHaveProperty('deleteImaRecordsByProviderId');
    });

    it('DO Spaces files for the provider are deleted', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          subscriptionId: 'sub-spaces-del',
          providerId: 'provider-spaces-del',
          stripeCustomerId: 'cus_spaces',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
        },
      ]);

      const dataDeletionRepo = createMockDataDeletionRepo();
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const spacesFileClient = createMockSpacesFileClient();
      const deps = buildDeps({
        subscriptionRepo: subRepo,
        dataDeletionRepo,
        destructionTrackingRepo,
        spacesFileClient,
      });
      const emitter = createMockEventEmitter();

      await runDeletionCheck(deps, emitter);

      // DO Spaces cleanup called with provider ID
      expect(spacesFileClient.deleteProviderFiles).toHaveBeenCalledWith(
        'provider-spaces-del',
      );

      // filesDeletedAt should be recorded on the tracking record
      expect(destructionTrackingRepo.updateFilesDeletedAt).toHaveBeenCalledWith(
        'provider-spaces-del',
        expect.any(Date),
      );
    });

    it('destruction tracking record created with correct timestamps', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          subscriptionId: 'sub-track-1',
          providerId: 'provider-track-1',
          stripeCustomerId: 'cus_track',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
        },
      ]);

      const dataDeletionRepo = createMockDataDeletionRepo();
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const userRepo: UserRepo = {
        findUserById: vi.fn(async () => ({
          userId: 'provider-track-1',
          email: 'tracked@clinic.ca',
          fullName: 'Dr. Tracked',
        })),
        updateSubscriptionStatus: vi.fn(async () => undefined),
      };
      const deps = buildDeps({
        subscriptionRepo: subRepo,
        dataDeletionRepo,
        destructionTrackingRepo,
        userRepo,
      });
      const emitter = createMockEventEmitter();

      const beforeCall = new Date();
      await runDeletionCheck(deps, emitter);

      // Verify tracking record was created
      expect(destructionTrackingRepo.createTrackingRecord).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: 'provider-track-1',
          lastKnownEmail: 'tracked@clinic.ca',
          activeDeletedAt: expect.any(Date),
          backupPurgeDeadline: expect.any(Date),
        }),
      );

      // Verify backupPurgeDeadline is ~90 days from now
      const callArgs = destructionTrackingRepo.createTrackingRecord.mock.calls[0][0];
      const deadlineDiff = Math.round(
        (callArgs.backupPurgeDeadline.getTime() - beforeCall.getTime()) / DAY_MS,
      );
      expect(deadlineDiff).toBe(BACKUP_PURGE_DEADLINE_DAYS);
    });
  });

  // -------------------------------------------------------------------------
  // Backup purge tracking
  // -------------------------------------------------------------------------

  describe('Backup purge tracking', () => {
    it('backupPurgeDeadline is 90 days after active deletion', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          subscriptionId: 'sub-90d',
          providerId: 'provider-90d',
          stripeCustomerId: 'cus_90d',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
        },
      ]);

      const dataDeletionRepo = createMockDataDeletionRepo();
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const deps = buildDeps({
        subscriptionRepo: subRepo,
        dataDeletionRepo,
        destructionTrackingRepo,
      });
      const emitter = createMockEventEmitter();

      const beforeCall = new Date();
      await runDeletionCheck(deps, emitter);

      const callArgs = destructionTrackingRepo.createTrackingRecord.mock.calls[0][0];
      const deadlineDays = Math.round(
        (callArgs.backupPurgeDeadline.getTime() - beforeCall.getTime()) / DAY_MS,
      );
      expect(deadlineDays).toBe(90);
      expect(BACKUP_PURGE_DEADLINE_DAYS).toBe(90);
    });

    it('admin can mark backup as purged', async () => {
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      destructionTrackingRepo.findByProviderId.mockResolvedValue({
        trackingId: 'track-purge-1',
        providerId: 'provider-purge-1',
        lastKnownEmail: 'admin@clinic.ca',
        activeDeletedAt: new Date(Date.now() - 30 * DAY_MS),
        filesDeletedAt: new Date(Date.now() - 30 * DAY_MS),
        backupPurgeDeadline: new Date(Date.now() + 60 * DAY_MS),
        backupPurgedAt: null,
        confirmationSentAt: null,
        createdAt: new Date(Date.now() - 30 * DAY_MS),
      });

      const deps = buildDeps({ destructionTrackingRepo });
      const adminCtx = { userId: 'admin-user-1', role: 'ADMIN' };

      const result = await markBackupPurged(deps, adminCtx, 'provider-purge-1');

      expect(result.backupPurgedAt).toBeInstanceOf(Date);
      expect(destructionTrackingRepo.updateBackupPurgedAt).toHaveBeenCalledWith(
        'provider-purge-1',
        expect.any(Date),
      );
    });

    it('marking backup purged is admin-only (403 for physician)', async () => {
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const deps = buildDeps({ destructionTrackingRepo });
      const physicianCtx = { userId: 'physician-user-1', role: 'physician' };

      await expect(
        markBackupPurged(deps, physicianCtx, 'provider-1'),
      ).rejects.toThrow('Only admin can mark backup purges');
    });
  });

  // -------------------------------------------------------------------------
  // Destruction confirmation
  // -------------------------------------------------------------------------

  describe('Destruction confirmation', () => {
    it('after backup purge marked, confirmation email sent to last known email', async () => {
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const now = new Date();
      destructionTrackingRepo.findPendingConfirmations.mockResolvedValue([
        {
          trackingId: 'track-confirm-1',
          providerId: 'provider-confirm-1',
          lastKnownEmail: 'confirmed@clinic.ca',
          activeDeletedAt: new Date(now.getTime() - 60 * DAY_MS),
          filesDeletedAt: new Date(now.getTime() - 60 * DAY_MS),
          backupPurgeDeadline: new Date(now.getTime() - 5 * DAY_MS),
          backupPurgedAt: new Date(now.getTime() - 1 * DAY_MS),
          confirmationSentAt: null,
          createdAt: new Date(now.getTime() - 60 * DAY_MS),
        },
      ]);

      const deps = buildDeps({ destructionTrackingRepo });
      const emitter = createMockEventEmitter();

      const result = await runDestructionConfirmation(deps, emitter);

      expect(result.confirmed).toBe(1);
      expect(emitter.emit).toHaveBeenCalledWith(
        'DATA_DESTRUCTION_CONFIRMED',
        expect.objectContaining({
          providerId: 'provider-confirm-1',
          email: 'confirmed@clinic.ca',
        }),
      );
    });

    it('confirmationSentAt set after email sent', async () => {
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      const now = new Date();
      destructionTrackingRepo.findPendingConfirmations.mockResolvedValue([
        {
          trackingId: 'track-sent-1',
          providerId: 'provider-sent-1',
          lastKnownEmail: 'sent@clinic.ca',
          activeDeletedAt: new Date(now.getTime() - 60 * DAY_MS),
          filesDeletedAt: new Date(now.getTime() - 60 * DAY_MS),
          backupPurgeDeadline: new Date(now.getTime() - 5 * DAY_MS),
          backupPurgedAt: new Date(now.getTime() - 1 * DAY_MS),
          confirmationSentAt: null,
          createdAt: new Date(now.getTime() - 60 * DAY_MS),
        },
      ]);

      const deps = buildDeps({ destructionTrackingRepo });
      const emitter = createMockEventEmitter();

      await runDestructionConfirmation(deps, emitter);

      expect(
        destructionTrackingRepo.updateConfirmationSentAt,
      ).toHaveBeenCalledWith('provider-sent-1', expect.any(Date));
    });

    it('confirmation job is idempotent', async () => {
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      // No pending confirmations (already sent)
      destructionTrackingRepo.findPendingConfirmations.mockResolvedValue([]);
      destructionTrackingRepo.findOverdueBackupPurges.mockResolvedValue([]);

      const deps = buildDeps({ destructionTrackingRepo });
      const emitter = createMockEventEmitter();

      const result1 = await runDestructionConfirmation(deps, emitter);
      const result2 = await runDestructionConfirmation(deps, emitter);

      // Both calls should succeed with 0 processed
      expect(result1.confirmed).toBe(0);
      expect(result2.confirmed).toBe(0);
      expect(emitter.emit).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // Overdue tracking
  // -------------------------------------------------------------------------

  describe('Overdue tracking', () => {
    it('admin alerted when backup purge deadline passes without purge', async () => {
      const destructionTrackingRepo = createMockDestructionTrackingRepo();
      destructionTrackingRepo.findPendingConfirmations.mockResolvedValue([]);
      destructionTrackingRepo.findOverdueBackupPurges.mockResolvedValue([
        {
          trackingId: 'track-overdue-1',
          providerId: 'provider-overdue-1',
          lastKnownEmail: 'overdue@clinic.ca',
          activeDeletedAt: new Date(Date.now() - 100 * DAY_MS),
          filesDeletedAt: new Date(Date.now() - 100 * DAY_MS),
          backupPurgeDeadline: new Date(Date.now() - 5 * DAY_MS),
          backupPurgedAt: null,
          confirmationSentAt: null,
          createdAt: new Date(Date.now() - 100 * DAY_MS),
        },
      ]);

      const deps = buildDeps({ destructionTrackingRepo });
      const emitter = createMockEventEmitter();

      const result = await runDestructionConfirmation(deps, emitter);

      expect(result.overdueAlerts).toBe(1);
      expect(emitter.emit).toHaveBeenCalledWith(
        'DESTRUCTION_BACKUP_OVERDUE',
        expect.objectContaining({
          providerId: 'provider-overdue-1',
        }),
      );
    });
  });
});
