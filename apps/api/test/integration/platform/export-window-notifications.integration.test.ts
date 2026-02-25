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
  handleSubscriptionDeleted,
  runCancellationCheck,
  runDeletionCheck,
  runExportWindowReminders,
  type PlatformServiceDeps,
  type StripeClient,
  type StripeEvent,
  type PlatformEventEmitter,
  type DataDeletionRepo,
  type AuditLogger,
  type UserRepo,
} from '../../../src/domains/platform/platform.service.js';
import {
  DELETION_GRACE_PERIOD_DAYS,
} from '@meritum/shared/constants/platform.constants.js';

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
      email: 'test@test.com',
      fullName: 'Test User',
    })),
    updateSubscriptionStatus: vi.fn(async () => undefined),
  };
}

function createMockDataDeletionRepo(): DataDeletionRepo {
  return {
    deleteClaimsByProviderId: vi.fn(async () => 0),
    deletePatientsByProviderId: vi.fn(async () => 0),
    deleteReportsByProviderId: vi.fn(async () => 0),
    stripPiiFromAuditLogs: vi.fn(async () => 0),
    anonymiseAiLearningData: vi.fn(async () => 0),
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
// Tests: IMA-012 Export Window Notifications (Integration)
// ===========================================================================

describe('IMA-012 Export Window Notifications — Integration', () => {
  // -------------------------------------------------------------------------
  // EXPORT_WINDOW_STARTED on cancellation
  // -------------------------------------------------------------------------

  describe('cancellation emits EXPORT_WINDOW_STARTED', () => {
    it('runCancellationCheck emits EXPORT_WINDOW_STARTED notification', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForCancellation.mockResolvedValue([
        {
          subscriptionId: 'sub-cancel-1',
          providerId: 'user-cancel-1',
          stripeSubscriptionId: 'sub_stripe_cancel',
          stripeCustomerId: 'cus_cancel',
          status: 'SUSPENDED',
          suspendedAt: new Date(Date.now() - 17 * DAY_MS),
          failedPaymentCount: 3,
        },
      ]);

      const deps = buildDeps({ subscriptionRepo: subRepo });
      const emitter = createMockEventEmitter();

      await runCancellationCheck(deps, emitter);

      // Should emit both SUBSCRIPTION_CANCELLED and EXPORT_WINDOW_STARTED
      expect(emitter.emit).toHaveBeenCalledWith(
        'SUBSCRIPTION_CANCELLED',
        expect.objectContaining({
          subscriptionId: 'sub-cancel-1',
          providerId: 'user-cancel-1',
        }),
      );
      expect(emitter.emit).toHaveBeenCalledWith(
        'EXPORT_WINDOW_STARTED',
        expect.objectContaining({
          subscriptionId: 'sub-cancel-1',
          providerId: 'user-cancel-1',
          exportWindowDays: DELETION_GRACE_PERIOD_DAYS,
        }),
      );
    });

    it('handleSubscriptionDeleted emits EXPORT_WINDOW_STARTED on Stripe subscription.deleted', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValue({
        subscriptionId: 'sub-deleted-1',
        providerId: 'user-deleted-1',
        stripeSubscriptionId: 'sub_stripe_del',
        stripeCustomerId: 'cus_del',
        status: 'ACTIVE',
      });

      const deps = buildDeps({ subscriptionRepo: subRepo });
      const emitter = createMockEventEmitter();

      const event: StripeEvent = {
        id: 'evt_del',
        type: 'customer.subscription.deleted',
        data: {
          object: { id: 'sub_stripe_del' },
        },
      };

      await handleSubscriptionDeleted(deps, event, emitter);

      expect(emitter.emit).toHaveBeenCalledWith(
        'EXPORT_WINDOW_STARTED',
        expect.objectContaining({
          subscriptionId: 'sub-deleted-1',
          providerId: 'user-deleted-1',
          exportWindowDays: DELETION_GRACE_PERIOD_DAYS,
        }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // EXPORT_WINDOW_REMINDER at 15 days remaining
  // -------------------------------------------------------------------------

  describe('export window reminders', () => {
    it('export window reminder emitted at 15 days remaining', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findCancelledSubscriptionsInExportWindow.mockResolvedValue([
        {
          subscriptionId: 'sub-remind-15',
          providerId: 'user-remind-15',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 15 * DAY_MS),
        },
      ]);

      const deps = buildDeps({ subscriptionRepo: subRepo });
      const emitter = createMockEventEmitter();

      const result = await runExportWindowReminders(deps, emitter);

      expect(result.reminded).toBe(1);
      expect(emitter.emit).toHaveBeenCalledWith(
        'EXPORT_WINDOW_REMINDER',
        expect.objectContaining({
          subscriptionId: 'sub-remind-15',
          providerId: 'user-remind-15',
          daysRemaining: 15,
        }),
      );
    });

    it('export window closing emitted at 7 days remaining', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findCancelledSubscriptionsInExportWindow.mockResolvedValue([
        {
          subscriptionId: 'sub-closing-7',
          providerId: 'user-closing-7',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 7 * DAY_MS),
        },
      ]);

      const deps = buildDeps({ subscriptionRepo: subRepo });
      const emitter = createMockEventEmitter();

      const result = await runExportWindowReminders(deps, emitter);

      expect(result.reminded).toBe(1);
      expect(emitter.emit).toHaveBeenCalledWith(
        'EXPORT_WINDOW_CLOSING',
        expect.objectContaining({
          subscriptionId: 'sub-closing-7',
          providerId: 'user-closing-7',
          daysRemaining: 7,
        }),
      );
    });

    it('export window closing emitted at 1 day remaining (final warning)', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findCancelledSubscriptionsInExportWindow.mockResolvedValue([
        {
          subscriptionId: 'sub-final-1',
          providerId: 'user-final-1',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 1 * DAY_MS),
        },
      ]);

      const deps = buildDeps({ subscriptionRepo: subRepo });
      const emitter = createMockEventEmitter();

      const result = await runExportWindowReminders(deps, emitter);

      expect(result.reminded).toBe(1);
      expect(emitter.emit).toHaveBeenCalledWith(
        'EXPORT_WINDOW_CLOSING',
        expect.objectContaining({
          subscriptionId: 'sub-final-1',
          providerId: 'user-final-1',
          daysRemaining: 1,
        }),
      );
    });

    it('no reminders emitted for non-checkpoint days', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findCancelledSubscriptionsInExportWindow.mockResolvedValue([
        {
          subscriptionId: 'sub-no-remind',
          providerId: 'user-no-remind',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 20 * DAY_MS),
        },
      ]);

      const deps = buildDeps({ subscriptionRepo: subRepo });
      const emitter = createMockEventEmitter();

      const result = await runExportWindowReminders(deps, emitter);

      expect(result.reminded).toBe(0);
      expect(emitter.emit).not.toHaveBeenCalled();
    });

    it('handles multiple subscriptions at different reminder stages', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findCancelledSubscriptionsInExportWindow.mockResolvedValue([
        {
          subscriptionId: 'sub-multi-15',
          providerId: 'user-multi-15',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 15 * DAY_MS),
        },
        {
          subscriptionId: 'sub-multi-7',
          providerId: 'user-multi-7',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 7 * DAY_MS),
        },
        {
          subscriptionId: 'sub-multi-30',
          providerId: 'user-multi-30',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 30 * DAY_MS),
        },
      ]);

      const deps = buildDeps({ subscriptionRepo: subRepo });
      const emitter = createMockEventEmitter();

      const result = await runExportWindowReminders(deps, emitter);

      // 15-day and 7-day should be reminded, 30-day should not
      expect(result.reminded).toBe(2);
      expect(emitter.emit).toHaveBeenCalledWith(
        'EXPORT_WINDOW_REMINDER',
        expect.objectContaining({ subscriptionId: 'sub-multi-15' }),
      );
      expect(emitter.emit).toHaveBeenCalledWith(
        'EXPORT_WINDOW_CLOSING',
        expect.objectContaining({ subscriptionId: 'sub-multi-7' }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // EXPORT_WINDOW_CLOSED when deletion begins
  // -------------------------------------------------------------------------

  describe('EXPORT_WINDOW_CLOSED on deletion', () => {
    it('EXPORT_WINDOW_CLOSED emitted when deletion begins', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          subscriptionId: 'sub-delete-1',
          providerId: 'user-delete-1',
          stripeCustomerId: 'cus_delete',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
        },
      ]);

      const dataDeletionRepo = createMockDataDeletionRepo();
      const deps = buildDeps({ subscriptionRepo: subRepo, dataDeletionRepo });
      const emitter = createMockEventEmitter();

      await runDeletionCheck(deps, emitter);

      expect(emitter.emit).toHaveBeenCalledWith(
        'EXPORT_WINDOW_CLOSED',
        expect.objectContaining({
          subscriptionId: 'sub-delete-1',
          providerId: 'user-delete-1',
        }),
      );
    });

    it('EXPORT_WINDOW_CLOSED emitted before ACCOUNT_DATA_DELETED', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          subscriptionId: 'sub-order-1',
          providerId: 'user-order-1',
          stripeCustomerId: 'cus_order',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
        },
      ]);

      const dataDeletionRepo = createMockDataDeletionRepo();
      const deps = buildDeps({ subscriptionRepo: subRepo, dataDeletionRepo });
      const emitter = createMockEventEmitter();

      await runDeletionCheck(deps, emitter);

      const emitCalls = (emitter.emit as ReturnType<typeof vi.fn>).mock.calls;
      const closedIdx = emitCalls.findIndex(
        (c: any) => c[0] === 'EXPORT_WINDOW_CLOSED',
      );
      const deletedIdx = emitCalls.findIndex(
        (c: any) => c[0] === 'ACCOUNT_DATA_DELETED',
      );

      expect(closedIdx).toBeGreaterThanOrEqual(0);
      expect(deletedIdx).toBeGreaterThanOrEqual(0);
      expect(closedIdx).toBeLessThan(deletedIdx);
    });
  });

  // -------------------------------------------------------------------------
  // 45-day export window (not 30)
  // -------------------------------------------------------------------------

  describe('export window uses 45-day period', () => {
    it('export window uses 45-day period, not 30', async () => {
      expect(DELETION_GRACE_PERIOD_DAYS).toBe(45);
    });

    it('cancellation sets deletion_scheduled_at to ~45 days from now', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForCancellation.mockResolvedValue([
        {
          subscriptionId: 'sub-45d',
          providerId: 'user-45d',
          stripeSubscriptionId: 'sub_stripe_45',
          stripeCustomerId: 'cus_45',
          status: 'SUSPENDED',
          suspendedAt: new Date(Date.now() - 17 * DAY_MS),
          failedPaymentCount: 3,
        },
      ]);

      const deps = buildDeps({ subscriptionRepo: subRepo });
      const emitter = createMockEventEmitter();

      const beforeCall = new Date();
      await runCancellationCheck(deps, emitter);

      // Verify updateSubscriptionStatus was called with deletion_scheduled_at ~45 days from now
      const updateCall = (subRepo.updateSubscriptionStatus as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(updateCall).toBeDefined();
      const metadata = updateCall[2];
      expect(metadata).toBeDefined();
      expect(metadata.deletion_scheduled_at).toBeInstanceOf(Date);

      const daysDiff = Math.round(
        (metadata.deletion_scheduled_at.getTime() - beforeCall.getTime()) /
          DAY_MS,
      );
      expect(daysDiff).toBe(45);
    });

    it('EXPORT_WINDOW_STARTED includes exportWindowDays = 45', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionsDueForCancellation.mockResolvedValue([
        {
          subscriptionId: 'sub-wd',
          providerId: 'user-wd',
          stripeSubscriptionId: 'sub_stripe_wd',
          stripeCustomerId: 'cus_wd',
          status: 'SUSPENDED',
          suspendedAt: new Date(Date.now() - 17 * DAY_MS),
          failedPaymentCount: 3,
        },
      ]);

      const deps = buildDeps({ subscriptionRepo: subRepo });
      const emitter = createMockEventEmitter();

      await runCancellationCheck(deps, emitter);

      expect(emitter.emit).toHaveBeenCalledWith(
        'EXPORT_WINDOW_STARTED',
        expect.objectContaining({
          exportWindowDays: 45,
        }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // Audit logging for export window events
  // -------------------------------------------------------------------------

  describe('audit logging', () => {
    it('export window reminder creates audit log entry', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findCancelledSubscriptionsInExportWindow.mockResolvedValue([
        {
          subscriptionId: 'sub-audit-15',
          providerId: 'user-audit-15',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 15 * DAY_MS),
        },
      ]);

      const auditLogger = createMockAuditLogger();
      const deps = buildDeps({ subscriptionRepo: subRepo, auditLogger });
      const emitter = createMockEventEmitter();

      await runExportWindowReminders(deps, emitter);

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'EXPORT_WINDOW_REMINDER',
          resourceType: 'subscription',
          resourceId: 'sub-audit-15',
          actorType: 'system',
        }),
      );
    });

    it('export window closing creates audit log entry', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findCancelledSubscriptionsInExportWindow.mockResolvedValue([
        {
          subscriptionId: 'sub-audit-7',
          providerId: 'user-audit-7',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 7 * DAY_MS),
        },
      ]);

      const auditLogger = createMockAuditLogger();
      const deps = buildDeps({ subscriptionRepo: subRepo, auditLogger });
      const emitter = createMockEventEmitter();

      await runExportWindowReminders(deps, emitter);

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'EXPORT_WINDOW_CLOSING',
          resourceType: 'subscription',
          resourceId: 'sub-audit-7',
        }),
      );
    });

    it('final warning creates distinct audit action', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findCancelledSubscriptionsInExportWindow.mockResolvedValue([
        {
          subscriptionId: 'sub-audit-1',
          providerId: 'user-audit-1',
          status: 'CANCELLED',
          deletionScheduledAt: new Date(Date.now() + 1 * DAY_MS),
        },
      ]);

      const auditLogger = createMockAuditLogger();
      const deps = buildDeps({ subscriptionRepo: subRepo, auditLogger });
      const emitter = createMockEventEmitter();

      await runExportWindowReminders(deps, emitter);

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'EXPORT_WINDOW_CLOSING_FINAL',
          resourceType: 'subscription',
          resourceId: 'sub-audit-1',
        }),
      );
    });
  });
});
