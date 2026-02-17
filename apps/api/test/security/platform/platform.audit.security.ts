import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

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
import { stripeWebhookPluginFp } from '../../../src/plugins/stripe-webhook.plugin.js';
import { platformRoutes } from '../../../src/domains/platform/platform.routes.js';
import { type PlatformHandlerDeps } from '../../../src/domains/platform/platform.handlers.js';
import {
  type PlatformServiceDeps,
  type StripeClient,
  type AuditLogger,
  runDunningCheck,
  runCancellationCheck,
  runDeletionCheck,
  createCheckoutSession,
  handleCheckoutCompleted,
  handleInvoicePaid,
  handleInvoicePaymentFailed,
  handleSubscriptionUpdated,
  handleSubscriptionDeleted,
  createIncident,
  updateIncident,
  updateComponentStatus,
} from '../../../src/domains/platform/platform.service.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000099';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// Subscription + payment test data
// ---------------------------------------------------------------------------

const SUBSCRIPTION_ID = '00000000-3333-0000-0000-000000000001';
const STRIPE_CUSTOMER_ID = 'cus_test_audit_001';
const STRIPE_SUBSCRIPTION_ID = 'sub_test_audit_001';
const STRIPE_INVOICE_ID = 'inv_test_audit_001';
const COMPONENT_ID = '00000000-4444-0000-0000-000000000001';
const INCIDENT_ID = '00000000-5555-0000-0000-000000000001';

const activeSubscription = {
  subscriptionId: SUBSCRIPTION_ID,
  providerId: PHYSICIAN_USER_ID,
  stripeCustomerId: STRIPE_CUSTOMER_ID,
  stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
  plan: 'STANDARD_MONTHLY',
  status: 'ACTIVE',
  currentPeriodStart: new Date('2026-01-01'),
  currentPeriodEnd: new Date('2026-02-01'),
  failedPaymentCount: 0,
  suspendedAt: null,
  cancelledAt: null,
  deletionScheduledAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01'),
};

// ---------------------------------------------------------------------------
// Mock Stripe client
// ---------------------------------------------------------------------------

function createMockStripe(): StripeClient {
  return {
    customers: {
      create: vi.fn(async () => ({ id: 'cus_test_new' })),
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
      constructEvent: vi.fn((payload, signature, _secret) => {
        if (signature === 'invalid_signature') {
          throw new Error('Invalid signature');
        }
        return JSON.parse(payload);
      }),
    },
    invoiceItems: {
      create: vi.fn(async () => ({ id: 'ii_test' })),
    },
    subscriptions: {
      cancel: vi.fn(async () => ({ id: 'sub_test', status: 'canceled' })),
    },
  };
}

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSubscriptionRepo() {
  return {
    createSubscription: vi.fn(async () => ({})),
    findSubscriptionByProviderId: vi.fn(async () => undefined),
    findSubscriptionByStripeCustomerId: vi.fn(async () => undefined),
    findSubscriptionByStripeSubscriptionId: vi.fn(async () => undefined),
    updateSubscriptionStatus: vi.fn(async () => undefined),
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
  };
}

function createMockPaymentRepo() {
  return {
    recordPayment: vi.fn(async () => ({})),
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
    updateComponentStatus: vi.fn(async (id: string, status: string) => ({
      componentId: id,
      name: 'WEB_APP',
      displayName: 'Web Application',
      status,
    })),
    seedComponents: vi.fn(async () => {}),
  };
}

function createMockIncidentRepo() {
  return {
    createIncident: vi.fn(async (data: any) => ({
      incidentId: INCIDENT_ID,
      title: data.title,
      status: 'INVESTIGATING',
      severity: data.severity,
      affectedComponents: data.affectedComponents,
      createdAt: new Date(),
      updatedAt: new Date(),
      resolvedAt: null,
      updates: [
        {
          updateId: randomUUID(),
          status: 'INVESTIGATING',
          message: data.initialMessage,
          createdAt: new Date(),
        },
      ],
    })),
    updateIncident: vi.fn(async (id: string, status: string, message: string) => ({
      incidentId: id,
      title: 'Test Incident',
      status,
      severity: 'major',
      affectedComponents: [COMPONENT_ID],
      createdAt: new Date(),
      updatedAt: new Date(),
      resolvedAt: status === 'RESOLVED' ? new Date() : null,
      updates: [
        {
          updateId: randomUUID(),
          status,
          message,
          createdAt: new Date(),
        },
      ],
    })),
    listActiveIncidents: vi.fn(async () => []),
    listIncidentHistory: vi.fn(async () => ({ data: [], total: 0 })),
    findIncidentById: vi.fn(async () => undefined),
  };
}

function createMockUserRepo() {
  return {
    findUserById: vi.fn(async () => ({
      userId: PHYSICIAN_USER_ID,
      email: 'doc@example.com',
      fullName: 'Dr. Test',
    })),
    updateSubscriptionStatus: vi.fn(async () => {}),
  };
}

function createMockAuditLogger(): AuditLogger & { log: ReturnType<typeof vi.fn> } {
  return {
    log: vi.fn(async () => {}),
  };
}

function createMockDataDeletionRepo() {
  return {
    deleteClaimsByProviderId: vi.fn(async () => 5),
    deletePatientsByProviderId: vi.fn(async () => 3),
    deleteReportsByProviderId: vi.fn(async () => 2),
    stripPiiFromAuditLogs: vi.fn(async () => 10),
    anonymiseAiLearningData: vi.fn(async () => 8),
    deactivateUser: vi.fn(async () => {}),
  };
}

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN_SESSION_TOKEN_HASH) {
        return {
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
        };
      }
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
            role: 'ADMIN',
            subscriptionStatus: 'ACTIVE',
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
// Build service deps with configurable mocks
// ---------------------------------------------------------------------------

function buildServiceDeps(overrides?: {
  subscriptionRepo?: ReturnType<typeof createMockSubscriptionRepo>;
  paymentRepo?: ReturnType<typeof createMockPaymentRepo>;
  statusComponentRepo?: ReturnType<typeof createMockStatusComponentRepo>;
  incidentRepo?: ReturnType<typeof createMockIncidentRepo>;
  userRepo?: ReturnType<typeof createMockUserRepo>;
  stripe?: StripeClient;
  auditLogger?: AuditLogger;
  dataDeletionRepo?: ReturnType<typeof createMockDataDeletionRepo>;
}): PlatformServiceDeps {
  return {
    subscriptionRepo: (overrides?.subscriptionRepo ?? createMockSubscriptionRepo()) as any,
    paymentRepo: (overrides?.paymentRepo ?? createMockPaymentRepo()) as any,
    statusComponentRepo: (overrides?.statusComponentRepo ?? createMockStatusComponentRepo()) as any,
    incidentRepo: (overrides?.incidentRepo ?? createMockIncidentRepo()) as any,
    userRepo: overrides?.userRepo ?? createMockUserRepo(),
    stripe: overrides?.stripe ?? createMockStripe(),
    config: {
      stripePriceStandardMonthly: 'price_monthly_test',
      stripePriceStandardAnnual: 'price_annual_test',
      stripePriceEarlyBirdMonthly: 'price_earlybird_test',
      stripeWebhookSecret: 'whsec_test_secret',
    },
    auditLogger: overrides?.auditLogger,
    dataDeletionRepo: overrides?.dataDeletionRepo,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder (for route-level tests)
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockStripe = createMockStripe();
  const mockEvents = { emit: vi.fn() };

  const serviceDeps = buildServiceDeps({ stripe: mockStripe });

  const handlerDeps: PlatformHandlerDeps = {
    serviceDeps,
    eventEmitter: mockEvents,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: createMockSessionRepo(),
      auditRepo: { appendAuditLog: vi.fn() },
      events: mockEvents,
    },
  });

  await testApp.register(stripeWebhookPluginFp, {
    webhookPath: '/api/v1/webhooks/stripe',
    stripe: mockStripe,
    webhookSecret: 'whsec_test_secret',
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

  await testApp.register(platformRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ===========================================================================
// TEST SUITE: Audit Trail Completeness for Billing & Subscription Events
// ===========================================================================

describe('Platform Audit Trail (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // Subscription Events — Audit Records
  // =========================================================================

  describe('Subscription Events', () => {
    it('checkout.session.completed produces subscription.created audit via event emitter', async () => {
      const mockEvents = { emit: vi.fn() };
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValue(undefined);
      subRepo.createSubscription.mockResolvedValue({});

      const deps = buildServiceDeps({ subscriptionRepo: subRepo });

      const event = {
        id: 'evt_checkout_001',
        type: 'checkout.session.completed',
        data: {
          object: {
            metadata: {
              meritum_user_id: PHYSICIAN_USER_ID,
              plan: 'STANDARD_MONTHLY',
            },
            customer: STRIPE_CUSTOMER_ID,
            subscription: STRIPE_SUBSCRIPTION_ID,
          },
        },
      };

      await handleCheckoutCompleted(deps, event, mockEvents);

      // Subscription was created
      expect(subRepo.createSubscription).toHaveBeenCalledTimes(1);

      // Event emitter captured the creation for audit trail
      expect(mockEvents.emit).toHaveBeenCalledWith(
        'SUBSCRIPTION_CREATED',
        expect.objectContaining({
          userId: PHYSICIAN_USER_ID,
          plan: 'STANDARD_MONTHLY',
          stripeCustomerId: STRIPE_CUSTOMER_ID,
          stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
        }),
      );
    });

    it('customer.subscription.updated produces status change when status differs', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValue({
        ...activeSubscription,
        status: 'ACTIVE',
      });

      const deps = buildServiceDeps({ subscriptionRepo: subRepo });

      const event = {
        id: 'evt_sub_updated_001',
        type: 'customer.subscription.updated',
        data: {
          object: {
            id: STRIPE_SUBSCRIPTION_ID,
            status: 'past_due',
            current_period_start: Math.floor(Date.now() / 1000),
            current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400,
          },
        },
      };

      await handleSubscriptionUpdated(deps, event);

      // Status was updated from ACTIVE → PAST_DUE
      expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        'PAST_DUE',
      );
    });

    it('customer.subscription.updated produces plan change when plan differs', async () => {
      const subRepo = createMockSubscriptionRepo();
      subRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValue({
        ...activeSubscription,
        plan: 'STANDARD_MONTHLY',
      });

      const deps = buildServiceDeps({ subscriptionRepo: subRepo });

      const event = {
        id: 'evt_sub_plan_001',
        type: 'customer.subscription.updated',
        data: {
          object: {
            id: STRIPE_SUBSCRIPTION_ID,
            status: 'active',
            current_period_start: Math.floor(Date.now() / 1000),
            current_period_end: Math.floor(Date.now() / 1000) + 365 * 86400,
            items: {
              data: [
                { price: { id: 'price_annual_test' } },
              ],
            },
          },
        },
      };

      await handleSubscriptionUpdated(deps, event);

      // Plan was updated from STANDARD_MONTHLY → STANDARD_ANNUAL
      expect(subRepo.updateSubscriptionPlan).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        'STANDARD_ANNUAL',
      );
    });
  });

  // =========================================================================
  // Payment Events — Audit Records
  // =========================================================================

  describe('Payment Events', () => {
    it('invoice.paid records payment and emits PAYMENT_SUCCEEDED', async () => {
      const mockEvents = { emit: vi.fn() };
      const subRepo = createMockSubscriptionRepo();
      const paymentRepo = createMockPaymentRepo();

      subRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValue({
        ...activeSubscription,
      });
      paymentRepo.findPaymentByStripeInvoiceId.mockResolvedValue(undefined);

      const deps = buildServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

      const event = {
        id: 'evt_inv_paid_001',
        type: 'invoice.paid',
        data: {
          object: {
            id: STRIPE_INVOICE_ID,
            subscription: STRIPE_SUBSCRIPTION_ID,
            amount_paid: 29295, // $292.95 CAD (279 + GST)
            tax: 1395,
            total: 29295,
          },
        },
      };

      await handleInvoicePaid(deps, event, mockEvents);

      // Payment recorded
      expect(paymentRepo.recordPayment).toHaveBeenCalledWith(
        expect.objectContaining({
          subscriptionId: SUBSCRIPTION_ID,
          stripeInvoiceId: STRIPE_INVOICE_ID,
          totalCad: '292.95',
          status: 'PAID',
        }),
      );

      // Audit event emitted
      expect(mockEvents.emit).toHaveBeenCalledWith(
        'PAYMENT_SUCCEEDED',
        expect.objectContaining({
          subscriptionId: SUBSCRIPTION_ID,
          stripeInvoiceId: STRIPE_INVOICE_ID,
          amountCad: '292.95',
        }),
      );
    });

    it('invoice.payment_failed records failed payment and emits PAYMENT_FAILED', async () => {
      const mockEvents = { emit: vi.fn() };
      const subRepo = createMockSubscriptionRepo();
      const paymentRepo = createMockPaymentRepo();

      subRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValue({
        ...activeSubscription,
      });
      paymentRepo.findPaymentByStripeInvoiceId.mockResolvedValue(undefined);

      const deps = buildServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

      const event = {
        id: 'evt_inv_failed_001',
        type: 'invoice.payment_failed',
        data: {
          object: {
            id: STRIPE_INVOICE_ID,
            subscription: STRIPE_SUBSCRIPTION_ID,
            amount_due: 29295,
            tax: 1395,
            total: 29295,
          },
        },
      };

      await handleInvoicePaymentFailed(deps, event, mockEvents);

      // Failed payment recorded
      expect(paymentRepo.recordPayment).toHaveBeenCalledWith(
        expect.objectContaining({
          subscriptionId: SUBSCRIPTION_ID,
          stripeInvoiceId: STRIPE_INVOICE_ID,
          status: 'FAILED',
        }),
      );

      // Failed payment count incremented
      expect(subRepo.incrementFailedPaymentCount).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
      );

      // Audit event emitted
      expect(mockEvents.emit).toHaveBeenCalledWith(
        'PAYMENT_FAILED',
        expect.objectContaining({
          subscriptionId: SUBSCRIPTION_ID,
          stripeInvoiceId: STRIPE_INVOICE_ID,
        }),
      );
    });
  });

  // =========================================================================
  // Dunning Events — Audit Records
  // =========================================================================

  describe('Dunning Events', () => {
    it('account suspension (Day 14) produces DUNNING_SUSPENSION audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const mockEvents = { emit: vi.fn() };
      const subRepo = createMockSubscriptionRepo();

      // Simulate subscription due for suspension
      subRepo.findSubscriptionsDueForSuspension.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'PAST_DUE',
          failedPaymentCount: 3,
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        auditLogger,
      });

      await runDunningCheck(deps, mockEvents);

      // Audit log: DUNNING_SUSPENSION
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'DUNNING_SUSPENSION',
          resourceType: 'subscription',
          resourceId: SUBSCRIPTION_ID,
          actorType: 'system',
          metadata: expect.objectContaining({
            providerId: PHYSICIAN_USER_ID,
            failedPaymentCount: 3,
            step: 'DAY_14_SUSPEND',
          }),
        }),
      );

      // ACCOUNT_SUSPENDED event emitted with reason
      expect(mockEvents.emit).toHaveBeenCalledWith(
        'ACCOUNT_SUSPENDED',
        expect.objectContaining({
          subscriptionId: SUBSCRIPTION_ID,
          providerId: PHYSICIAN_USER_ID,
        }),
      );
    });

    it('Day 7 dunning warning produces DUNNING_WARNING audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const mockEvents = { emit: vi.fn() };
      const subRepo = createMockSubscriptionRepo();

      // No suspensions pending
      subRepo.findSubscriptionsDueForSuspension.mockResolvedValue([]);

      // One PAST_DUE subscription 8 days old
      const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
      subRepo.findPastDueSubscriptions.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'PAST_DUE',
          failedPaymentCount: 2,
          updatedAt: eightDaysAgo,
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        auditLogger,
      });

      await runDunningCheck(deps, mockEvents);

      // Audit log: DUNNING_WARNING
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'DUNNING_WARNING',
          resourceType: 'subscription',
          resourceId: SUBSCRIPTION_ID,
          actorType: 'system',
          metadata: expect.objectContaining({
            step: 'DAY_7_WARNING',
          }),
        }),
      );

      // Suspension warning event emitted
      expect(mockEvents.emit).toHaveBeenCalledWith(
        'PAYMENT_SUSPENSION_WARNING',
        expect.objectContaining({
          subscriptionId: SUBSCRIPTION_ID,
          providerId: PHYSICIAN_USER_ID,
        }),
      );
    });

    it('Day 3 retry notification produces DUNNING_RETRY_NOTIFICATION audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const mockEvents = { emit: vi.fn() };
      const subRepo = createMockSubscriptionRepo();

      subRepo.findSubscriptionsDueForSuspension.mockResolvedValue([]);

      // One PAST_DUE subscription 4 days old
      const fourDaysAgo = new Date(Date.now() - 4 * 24 * 60 * 60 * 1000);
      subRepo.findPastDueSubscriptions.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'PAST_DUE',
          failedPaymentCount: 1,
          updatedAt: fourDaysAgo,
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        auditLogger,
      });

      await runDunningCheck(deps, mockEvents);

      // Audit log: DUNNING_RETRY_NOTIFICATION
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'DUNNING_RETRY_NOTIFICATION',
          resourceType: 'subscription',
          resourceId: SUBSCRIPTION_ID,
          actorType: 'system',
          metadata: expect.objectContaining({
            step: 'DAY_3_RETRY_FAILED',
          }),
        }),
      );
    });

    it('account cancellation (Day 30) produces DUNNING_CANCELLATION audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const mockEvents = { emit: vi.fn() };
      const subRepo = createMockSubscriptionRepo();

      const sixteenDaysAgo = new Date(Date.now() - 16 * 24 * 60 * 60 * 1000);
      subRepo.findSubscriptionsDueForCancellation.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'SUSPENDED',
          suspendedAt: sixteenDaysAgo,
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        auditLogger,
      });

      await runCancellationCheck(deps, mockEvents);

      // Audit log: DUNNING_CANCELLATION
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'DUNNING_CANCELLATION',
          resourceType: 'subscription',
          resourceId: SUBSCRIPTION_ID,
          actorType: 'system',
          metadata: expect.objectContaining({
            providerId: PHYSICIAN_USER_ID,
            stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
            deletionScheduledAt: expect.any(String),
          }),
        }),
      );

      // SUBSCRIPTION_CANCELLED event emitted
      expect(mockEvents.emit).toHaveBeenCalledWith(
        'SUBSCRIPTION_CANCELLED',
        expect.objectContaining({
          subscriptionId: SUBSCRIPTION_ID,
          providerId: PHYSICIAN_USER_ID,
          cancelledAt: expect.any(String),
          deletionScheduledAt: expect.any(String),
        }),
      );
    });
  });

  // =========================================================================
  // Deletion Events — Audit Records
  // =========================================================================

  describe('Deletion Events', () => {
    it('account data deletion produces ACCOUNT_DATA_DELETED audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const mockEvents = { emit: vi.fn() };
      const subRepo = createMockSubscriptionRepo();
      const dataDeletionRepo = createMockDataDeletionRepo();

      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'CANCELLED',
          cancelledAt: new Date('2026-01-01'),
          deletionScheduledAt: new Date('2026-01-31'),
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        auditLogger,
        dataDeletionRepo,
      });

      await runDeletionCheck(deps, mockEvents);

      // All PHI deletion methods called
      expect(dataDeletionRepo.deleteClaimsByProviderId).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
      );
      expect(dataDeletionRepo.deletePatientsByProviderId).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
      );
      expect(dataDeletionRepo.deleteReportsByProviderId).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
      );
      expect(dataDeletionRepo.stripPiiFromAuditLogs).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
      );
      expect(dataDeletionRepo.anonymiseAiLearningData).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
      );
      expect(dataDeletionRepo.deactivateUser).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
      );

      // Audit log: ACCOUNT_DATA_DELETED
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'ACCOUNT_DATA_DELETED',
          resourceType: 'subscription',
          resourceId: SUBSCRIPTION_ID,
          actorType: 'system',
          metadata: expect.objectContaining({
            providerId: PHYSICIAN_USER_ID,
            stripeCustomerId: STRIPE_CUSTOMER_ID,
          }),
        }),
      );

      // ACCOUNT_DATA_DELETED event emitted
      expect(mockEvents.emit).toHaveBeenCalledWith(
        'ACCOUNT_DATA_DELETED',
        expect.objectContaining({
          subscriptionId: SUBSCRIPTION_ID,
          providerId: PHYSICIAN_USER_ID,
          deletedAt: expect.any(String),
        }),
      );
    });

    it('deletion scheduled via subscription.deleted webhook sets deletion_scheduled_at', async () => {
      const mockEvents = { emit: vi.fn() };
      const subRepo = createMockSubscriptionRepo();

      subRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValue({
        ...activeSubscription,
        status: 'SUSPENDED',
      });

      const deps = buildServiceDeps({ subscriptionRepo: subRepo });

      const event = {
        id: 'evt_sub_deleted_001',
        type: 'customer.subscription.deleted',
        data: {
          object: {
            id: STRIPE_SUBSCRIPTION_ID,
          },
        },
      };

      await handleSubscriptionDeleted(deps, event, mockEvents);

      // Status updated to CANCELLED with deletion date
      expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        'CANCELLED',
        expect.objectContaining({
          cancelled_at: expect.any(Date),
          deletion_scheduled_at: expect.any(Date),
        }),
      );

      // SUBSCRIPTION_CANCELLED event with deletion date
      expect(mockEvents.emit).toHaveBeenCalledWith(
        'SUBSCRIPTION_CANCELLED',
        expect.objectContaining({
          subscriptionId: SUBSCRIPTION_ID,
          providerId: PHYSICIAN_USER_ID,
          cancelledAt: expect.any(String),
          deletionScheduledAt: expect.any(String),
        }),
      );
    });
  });

  // =========================================================================
  // Incident Events — Audit Records
  // =========================================================================

  describe('Incident Events', () => {
    it('incident creation produces incident.created audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const mockEvents = { emit: vi.fn() };
      const incidentRepo = createMockIncidentRepo();

      const deps = buildServiceDeps({
        incidentRepo,
        auditLogger,
      });

      await createIncident(
        deps,
        ADMIN_USER_ID,
        {
          title: 'H-Link service degradation',
          severity: 'major',
          affected_components: [COMPONENT_ID],
          message: 'Investigating slowness in H-Link submission pipeline',
        },
        mockEvents,
      );

      // Audit log: incident.created
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'incident.created',
          resourceType: 'incident',
          resourceId: INCIDENT_ID,
          actorType: 'admin',
          metadata: expect.objectContaining({
            adminUserId: ADMIN_USER_ID,
            title: 'H-Link service degradation',
            severity: 'major',
            affectedComponents: [COMPONENT_ID],
          }),
        }),
      );
    });

    it('incident update produces incident.updated audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const mockEvents = { emit: vi.fn() };
      const incidentRepo = createMockIncidentRepo();

      const deps = buildServiceDeps({
        incidentRepo,
        auditLogger,
      });

      await updateIncident(
        deps,
        ADMIN_USER_ID,
        INCIDENT_ID,
        'IDENTIFIED',
        'Root cause identified: database connection pool exhaustion',
        mockEvents,
      );

      // Audit log: incident.updated
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'incident.updated',
          resourceType: 'incident',
          resourceId: INCIDENT_ID,
          actorType: 'admin',
          metadata: expect.objectContaining({
            adminUserId: ADMIN_USER_ID,
            newStatus: 'IDENTIFIED',
            message: 'Root cause identified: database connection pool exhaustion',
          }),
        }),
      );
    });

    it('incident resolution produces audit record and restores component status', async () => {
      const auditLogger = createMockAuditLogger();
      const mockEvents = { emit: vi.fn() };
      const incidentRepo = createMockIncidentRepo();
      const statusComponentRepo = createMockStatusComponentRepo();

      const deps = buildServiceDeps({
        incidentRepo,
        statusComponentRepo,
        auditLogger,
      });

      await updateIncident(
        deps,
        ADMIN_USER_ID,
        INCIDENT_ID,
        'RESOLVED',
        'Issue resolved, all systems operational',
        mockEvents,
      );

      // Audit log for resolution
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'incident.updated',
          resourceType: 'incident',
          resourceId: INCIDENT_ID,
          actorType: 'admin',
          metadata: expect.objectContaining({
            newStatus: 'RESOLVED',
          }),
        }),
      );

      // Component statuses restored to OPERATIONAL
      expect(statusComponentRepo.updateComponentStatus).toHaveBeenCalledWith(
        COMPONENT_ID,
        'OPERATIONAL',
      );

      // INCIDENT_UPDATED event emitted
      expect(mockEvents.emit).toHaveBeenCalledWith(
        'INCIDENT_UPDATED',
        expect.objectContaining({
          incidentId: INCIDENT_ID,
          status: 'RESOLVED',
          resolvedAt: expect.any(String),
        }),
      );
    });

    it('component status change produces component.status_updated audit record', async () => {
      const auditLogger = createMockAuditLogger();
      const statusComponentRepo = createMockStatusComponentRepo();

      const deps = buildServiceDeps({
        statusComponentRepo,
        auditLogger,
      });

      await updateComponentStatus(
        deps,
        ADMIN_USER_ID,
        COMPONENT_ID,
        'DEGRADED',
      );

      // Audit log: component.status_updated
      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'component.status_updated',
          resourceType: 'component',
          resourceId: COMPONENT_ID,
          actorType: 'admin',
          metadata: expect.objectContaining({
            adminUserId: ADMIN_USER_ID,
            newStatus: 'DEGRADED',
          }),
        }),
      );
    });
  });

  // =========================================================================
  // Audit Log Integrity — Immutability of Financial Records
  // =========================================================================

  describe('Audit Log Integrity', () => {
    it('no UPDATE endpoint exists for payment_history', async () => {
      // Attempt PUT on payment history endpoint — should return 404 (no such route)
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/subscriptions/payments/${randomUUID()}`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { status: 'REFUNDED' },
      });

      // 404 means no route matched — payment history has no update endpoint
      expect(res.statusCode).toBe(404);
    });

    it('no PATCH endpoint exists for payment_history', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/subscriptions/payments/${randomUUID()}`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { status: 'REFUNDED' },
      });

      expect(res.statusCode).toBe(404);
    });

    it('no DELETE endpoint exists for payment_history', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/subscriptions/payments/${randomUUID()}`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      // 404 means no route matched — payment history cannot be deleted
      expect(res.statusCode).toBe(404);
    });

    it('no DELETE endpoint exists for individual payment records', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
    });

    it('admin cannot delete payment records either', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/payments/${randomUUID()}`,
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // Audit Entries — No Sensitive Data Leakage
  // =========================================================================

  describe('Audit Entries Do Not Contain Secrets', () => {
    const STRIPE_SECRET_KEY = 'sk_live_test_secret_key_1234567890';
    const STRIPE_WEBHOOK_SECRET = 'whsec_test_secret';

    it('dunning audit entries do not contain Stripe API keys', async () => {
      const auditLogger = createMockAuditLogger();
      const subRepo = createMockSubscriptionRepo();

      subRepo.findSubscriptionsDueForSuspension.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'PAST_DUE',
          failedPaymentCount: 3,
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        auditLogger,
      });
      // Override config to include a realistic Stripe key (to verify it doesn't leak)
      (deps.config as any).stripeSecretKey = STRIPE_SECRET_KEY;

      await runDunningCheck(deps, { emit: vi.fn() });

      // Verify audit log was called
      expect(auditLogger.log).toHaveBeenCalled();

      // Verify no audit entry contains the Stripe secret key
      for (const call of auditLogger.log.mock.calls) {
        const logEntry = JSON.stringify(call[0]);
        expect(logEntry).not.toContain(STRIPE_SECRET_KEY);
        expect(logEntry).not.toContain('sk_live');
        expect(logEntry).not.toContain(STRIPE_WEBHOOK_SECRET);
      }
    });

    it('cancellation audit entries do not contain Stripe API keys', async () => {
      const auditLogger = createMockAuditLogger();
      const subRepo = createMockSubscriptionRepo();

      subRepo.findSubscriptionsDueForCancellation.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'SUSPENDED',
          suspendedAt: new Date(Date.now() - 16 * 24 * 60 * 60 * 1000),
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        auditLogger,
      });

      await runCancellationCheck(deps, { emit: vi.fn() });

      expect(auditLogger.log).toHaveBeenCalled();

      for (const call of auditLogger.log.mock.calls) {
        const logEntry = JSON.stringify(call[0]);
        expect(logEntry).not.toContain('sk_live');
        expect(logEntry).not.toContain('sk_test');
        expect(logEntry).not.toContain('whsec_');
      }
    });

    it('deletion audit entries do not contain Stripe API keys or webhook secrets', async () => {
      const auditLogger = createMockAuditLogger();
      const subRepo = createMockSubscriptionRepo();
      const dataDeletionRepo = createMockDataDeletionRepo();

      subRepo.findSubscriptionsDueForDeletion.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'CANCELLED',
          cancelledAt: new Date('2026-01-01'),
          deletionScheduledAt: new Date('2026-01-31'),
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        auditLogger,
        dataDeletionRepo,
      });

      await runDeletionCheck(deps, { emit: vi.fn() });

      expect(auditLogger.log).toHaveBeenCalled();

      for (const call of auditLogger.log.mock.calls) {
        const logEntry = JSON.stringify(call[0]);
        expect(logEntry).not.toContain('sk_live');
        expect(logEntry).not.toContain('sk_test');
        expect(logEntry).not.toContain('whsec_');
      }
    });

    it('incident audit entries do not contain Stripe credentials', async () => {
      const auditLogger = createMockAuditLogger();
      const incidentRepo = createMockIncidentRepo();

      const deps = buildServiceDeps({
        incidentRepo,
        auditLogger,
      });

      await createIncident(deps, ADMIN_USER_ID, {
        title: 'Payment processing outage',
        severity: 'critical',
        affected_components: [COMPONENT_ID],
        message: 'Stripe integration down',
      });

      expect(auditLogger.log).toHaveBeenCalled();

      for (const call of auditLogger.log.mock.calls) {
        const logEntry = JSON.stringify(call[0]);
        expect(logEntry).not.toContain('sk_live');
        expect(logEntry).not.toContain('sk_test');
        expect(logEntry).not.toContain('whsec_');
      }
    });
  });

  // =========================================================================
  // Audit Record Completeness — All State Changes Tracked
  // =========================================================================

  describe('Audit Record Completeness', () => {
    it('suspension updates user subscription_status', async () => {
      const auditLogger = createMockAuditLogger();
      const subRepo = createMockSubscriptionRepo();
      const userRepo = createMockUserRepo();

      subRepo.findSubscriptionsDueForSuspension.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'PAST_DUE',
          failedPaymentCount: 3,
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        userRepo,
        auditLogger,
      });

      await runDunningCheck(deps, { emit: vi.fn() });

      // User status updated to SUSPENDED
      expect(userRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
        'SUSPENDED',
      );
    });

    it('cancellation updates user subscription_status', async () => {
      const auditLogger = createMockAuditLogger();
      const subRepo = createMockSubscriptionRepo();
      const userRepo = createMockUserRepo();

      subRepo.findSubscriptionsDueForCancellation.mockResolvedValue([
        {
          ...activeSubscription,
          status: 'SUSPENDED',
          suspendedAt: new Date(Date.now() - 16 * 24 * 60 * 60 * 1000),
        },
      ]);

      const deps = buildServiceDeps({
        subscriptionRepo: subRepo,
        userRepo,
        auditLogger,
      });

      await runCancellationCheck(deps, { emit: vi.fn() });

      // User status updated to CANCELLED
      expect(userRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
        'CANCELLED',
      );
    });

    it('payment success transitions PAST_DUE back to ACTIVE', async () => {
      const subRepo = createMockSubscriptionRepo();
      const paymentRepo = createMockPaymentRepo();

      subRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValue({
        ...activeSubscription,
        status: 'PAST_DUE',
        failedPaymentCount: 2,
      });
      paymentRepo.findPaymentByStripeInvoiceId.mockResolvedValue(undefined);

      const deps = buildServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

      const event = {
        id: 'evt_inv_paid_recovery',
        type: 'invoice.paid',
        data: {
          object: {
            id: 'inv_recovery_001',
            subscription: STRIPE_SUBSCRIPTION_ID,
            amount_paid: 29295,
            tax: 1395,
          },
        },
      };

      await handleInvoicePaid(deps, event, { emit: vi.fn() });

      // Status transitioned back to ACTIVE
      expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        'ACTIVE',
        expect.objectContaining({ suspended_at: null }),
      );

      // Failed payment count reset
      expect(subRepo.resetFailedPaymentCount).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
      );
    });

    it('payment failure transitions ACTIVE to PAST_DUE', async () => {
      const subRepo = createMockSubscriptionRepo();
      const paymentRepo = createMockPaymentRepo();

      subRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValue({
        ...activeSubscription,
        status: 'ACTIVE',
        failedPaymentCount: 0,
      });
      paymentRepo.findPaymentByStripeInvoiceId.mockResolvedValue(undefined);

      const deps = buildServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

      const event = {
        id: 'evt_inv_failed_transition',
        type: 'invoice.payment_failed',
        data: {
          object: {
            id: 'inv_fail_001',
            subscription: STRIPE_SUBSCRIPTION_ID,
            amount_due: 29295,
            tax: 1395,
          },
        },
      };

      await handleInvoicePaymentFailed(deps, event, { emit: vi.fn() });

      // Status updated to PAST_DUE
      expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        'PAST_DUE',
      );
    });
  });
});
