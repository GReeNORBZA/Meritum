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
import { stripeWebhookPluginFp } from '../../../src/plugins/stripe-webhook.plugin.js';
import { platformRoutes } from '../../../src/domains/platform/platform.routes.js';
import { type PlatformHandlerDeps } from '../../../src/domains/platform/platform.handlers.js';
import {
  type PlatformServiceDeps,
  type StripeClient,
} from '../../../src/domains/platform/platform.service.js';
import {
  type FullHiExportDeps,
} from '../../../src/domains/platform/export.service.js';
import { type CompleteHealthInformation } from '../../../src/domains/platform/export.repository.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities — two isolated physicians + delegate
// ---------------------------------------------------------------------------

// Physician 1 — "our" physician
const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);

// Physician 2 — "other" physician (attacker perspective)
const PHYSICIAN2_USER_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_SESSION_TOKEN_HASH = hashToken(PHYSICIAN2_SESSION_TOKEN);

// Delegate without DATA_EXPORT permission
const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000003';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);

// Expired session
const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');

// ---------------------------------------------------------------------------
// Per-physician HI data — physician1 has unique data, physician2 has different data
// ---------------------------------------------------------------------------

const PHYSICIAN1_PATIENT_ID = '00000000-aaaa-0000-0000-000000000001';
const PHYSICIAN2_PATIENT_ID = '00000000-aaaa-0000-0000-000000000002';

function createPhysician1Hi(): CompleteHealthInformation {
  return {
    patients: [
      { patientId: PHYSICIAN1_PATIENT_ID, firstName: 'Alice', lastName: 'Martin', dob: '1988-03-10', phn: '111222333' },
    ],
    claims: [
      { claimId: crypto.randomUUID(), serviceDate: '2026-01-15', code: '03.03A', amount: '75.00', status: 'PAID' },
    ],
    claimAuditHistory: [],
    shifts: [],
    claimExports: [],
    ahcipClaimDetails: [],
    ahcipBatches: [],
    wcbClaimDetails: [],
    wcbBatches: [],
    wcbRemittanceImports: [],
    provider: { providerId: PHYSICIAN1_USER_ID, firstName: 'Dr', lastName: 'One', email: 'dr1@test.ca' },
    businessArrangements: [],
    practiceLocations: [],
    wcbConfigurations: [],
    delegateRelationships: [],
    submissionPreferences: [],
    hlinkConfigurations: [],
    pcpcmEnrolments: [],
    pcpcmPayments: [],
    pcpcmPanelEstimates: [],
    analyticsCache: [],
    generatedReports: [],
    reportSubscriptions: [],
    aiProviderLearning: [],
    aiSuggestionEvents: [],
    edShifts: [],
    favouriteCodes: [],
    subscription: { subscriptionId: crypto.randomUUID(), status: 'ACTIVE', plan: 'STANDARD_MONTHLY' },
    imaAmendmentResponses: [],
    auditLog: [],
  };
}

function createPhysician2Hi(): CompleteHealthInformation {
  return {
    patients: [
      { patientId: PHYSICIAN2_PATIENT_ID, firstName: 'Bob', lastName: 'Wilson', dob: '1975-11-20', phn: '444555666' },
      { patientId: crypto.randomUUID(), firstName: 'Carol', lastName: 'Davis', dob: '1992-07-04', phn: '777888999' },
    ],
    claims: [
      { claimId: crypto.randomUUID(), serviceDate: '2026-02-01', code: '08.19A', amount: '120.00', status: 'SUBMITTED' },
      { claimId: crypto.randomUUID(), serviceDate: '2026-02-05', code: '03.04A', amount: '35.00', status: 'PAID' },
    ],
    claimAuditHistory: [],
    shifts: [],
    claimExports: [],
    ahcipClaimDetails: [],
    ahcipBatches: [],
    wcbClaimDetails: [],
    wcbBatches: [],
    wcbRemittanceImports: [],
    provider: { providerId: PHYSICIAN2_USER_ID, firstName: 'Dr', lastName: 'Two', email: 'dr2@test.ca' },
    businessArrangements: [],
    practiceLocations: [],
    wcbConfigurations: [],
    delegateRelationships: [],
    submissionPreferences: [],
    hlinkConfigurations: [],
    pcpcmEnrolments: [],
    pcpcmPayments: [],
    pcpcmPanelEstimates: [],
    analyticsCache: [],
    generatedReports: [],
    reportSubscriptions: [],
    aiProviderLearning: [],
    aiSuggestionEvents: [],
    edShifts: [],
    favouriteCodes: [],
    subscription: { subscriptionId: crypto.randomUUID(), status: 'ACTIVE', plan: 'STANDARD_ANNUAL' },
    imaAmendmentResponses: [],
    auditLog: [],
  };
}

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000001',
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      if (tokenHash === PHYSICIAN2_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000002',
            userId: PHYSICIAN2_USER_ID,
            tokenHash: PHYSICIAN2_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN2_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      if (tokenHash === DELEGATE_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000003',
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
            delegateContext: {
              delegateUserId: DELEGATE_USER_ID,
              physicianProviderId: PHYSICIAN1_USER_ID,
              permissions: ['CLAIM_VIEW'], // No DATA_EXPORT
            },
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
// Mock export deps — scoped per physician
// ---------------------------------------------------------------------------

let auditLogs: Array<Record<string, unknown>>;
let emittedEvents: Array<{ event: string; data: Record<string, unknown> }>;
let mockExportRepo: { getCompleteHealthInformation: ReturnType<typeof vi.fn> };

function createMockExportDeps(): FullHiExportDeps {
  auditLogs = [];
  emittedEvents = [];
  mockExportRepo = {
    getCompleteHealthInformation: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN1_USER_ID) return createPhysician1Hi();
      if (providerId === PHYSICIAN2_USER_ID) return createPhysician2Hi();
      return {
        patients: [],
        claims: [],
        claimAuditHistory: [],
        shifts: [],
        claimExports: [],
        ahcipClaimDetails: [],
        ahcipBatches: [],
        wcbClaimDetails: [],
        wcbBatches: [],
        wcbRemittanceImports: [],
        provider: null,
        businessArrangements: [],
        practiceLocations: [],
        wcbConfigurations: [],
        delegateRelationships: [],
        submissionPreferences: [],
        hlinkConfigurations: [],
        pcpcmEnrolments: [],
        pcpcmPayments: [],
        pcpcmPanelEstimates: [],
        analyticsCache: [],
        generatedReports: [],
        reportSubscriptions: [],
        aiProviderLearning: [],
        aiSuggestionEvents: [],
        edShifts: [],
        favouriteCodes: [],
        subscription: null,
        imaAmendmentResponses: [],
        auditLog: [],
      };
    }),
  };

  return {
    exportRepo: mockExportRepo as any,
    reportRepo: {
      createReport: vi.fn(async (data: any) => ({
        reportId: crypto.randomUUID(),
        ...data,
      })),
    },
    objectStorage: {
      uploadBuffer: vi.fn(async () => {}),
      getPresignedUrl: vi.fn(async (key: string) => {
        return `https://meritum-files.tor1.digitaloceanspaces.com/${key}?sig=mock`;
      }),
    },
    auditLogger: {
      log: vi.fn(async (entry: Record<string, unknown>) => {
        auditLogs.push(entry);
      }),
    },
    eventEmitter: {
      emit: vi.fn((event: string, data: Record<string, unknown>) => {
        emittedEvents.push({ event, data });
      }),
    },
  };
}

// ---------------------------------------------------------------------------
// Mock Stripe + service repos
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
      constructEvent: vi.fn((payload, signature) => {
        if (signature === 'invalid_signature') throw new Error('Invalid signature');
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

function createMinimalServiceDeps(): PlatformServiceDeps {
  return {
    subscriptionRepo: {
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
    } as any,
    paymentRepo: {
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
    } as any,
    statusComponentRepo: {
      listComponents: vi.fn(async () => []),
      updateComponentStatus: vi.fn(async () => undefined),
      seedComponents: vi.fn(async () => {}),
    } as any,
    incidentRepo: {
      createIncident: vi.fn(async () => ({})),
      updateIncident: vi.fn(async () => undefined),
      listActiveIncidents: vi.fn(async () => []),
      listIncidentHistory: vi.fn(async () => ({ data: [], total: 0 })),
      findIncidentById: vi.fn(async () => undefined),
    } as any,
    userRepo: {
      findUserById: vi.fn(async () => undefined),
      updateSubscriptionStatus: vi.fn(async () => {}),
    },
    stripe: createMockStripe(),
    config: {
      stripePriceStandardMonthly: 'price_monthly_test',
      stripePriceStandardAnnual: 'price_annual_test',
      stripePriceEarlyBirdMonthly: 'price_earlybird_test',
      stripeWebhookSecret: 'whsec_test_secret',
    },
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockExportDeps: FullHiExportDeps;

async function buildTestApp(): Promise<FastifyInstance> {
  const serviceDeps = createMinimalServiceDeps();
  mockExportDeps = createMockExportDeps();

  const handlerDeps: PlatformHandlerDeps = {
    serviceDeps,
    eventEmitter: { emit: vi.fn() },
    exportDeps: mockExportDeps,
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

  await testApp.register(stripeWebhookPluginFp, {
    webhookPath: '/api/v1/webhooks/stripe',
    stripe: serviceDeps.stripe,
    webhookSecret: 'whsec_test_secret',
  });

  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: {
            code: (error as any).code,
            message: error.message,
          },
        });
      }
    }
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
        },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(platformRoutes, { deps: handlerDeps });
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
// Test Suite
// ---------------------------------------------------------------------------

describe('Export Security Tests (IMA §8.3)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Clear tracking arrays — the mock functions on the original deps are
    // cleared by vi.clearAllMocks(), but we need to re-add implementations
    // since clearAllMocks strips them.
    auditLogs = [];
    emittedEvents = [];

    // Re-add implementations to the cleared mocks
    mockExportRepo.getCompleteHealthInformation.mockImplementation(async (providerId: string) => {
      if (providerId === PHYSICIAN1_USER_ID) return createPhysician1Hi();
      if (providerId === PHYSICIAN2_USER_ID) return createPhysician2Hi();
      return {
        patients: [], claims: [], claimAuditHistory: [], shifts: [], claimExports: [],
        ahcipClaimDetails: [], ahcipBatches: [], wcbClaimDetails: [], wcbBatches: [],
        wcbRemittanceImports: [], provider: null, businessArrangements: [],
        practiceLocations: [], wcbConfigurations: [], delegateRelationships: [],
        submissionPreferences: [], hlinkConfigurations: [], pcpcmEnrolments: [],
        pcpcmPayments: [], pcpcmPanelEstimates: [], analyticsCache: [],
        generatedReports: [], reportSubscriptions: [], aiProviderLearning: [],
        aiSuggestionEvents: [], edShifts: [], favouriteCodes: [], subscription: null,
        imaAmendmentResponses: [], auditLog: [],
      };
    });
    (mockExportDeps.reportRepo.createReport as ReturnType<typeof vi.fn>).mockImplementation(
      async (data: any) => ({ reportId: crypto.randomUUID(), ...data }),
    );
    (mockExportDeps.objectStorage.getPresignedUrl as ReturnType<typeof vi.fn>).mockImplementation(
      async (key: string) => `https://meritum-files.tor1.digitaloceanspaces.com/${key}?sig=mock`,
    );
    (mockExportDeps.auditLogger!.log as ReturnType<typeof vi.fn>).mockImplementation(
      async (entry: Record<string, unknown>) => { auditLogs.push(entry); },
    );
    (mockExportDeps.eventEmitter!.emit as ReturnType<typeof vi.fn>).mockImplementation(
      (event: string, data: Record<string, unknown>) => { emittedEvents.push({ event, data }); },
    );
  });

  // =========================================================================
  // Category 1: Authentication Enforcement (authn)
  // =========================================================================

  describe('Authentication Enforcement', () => {
    it('POST /api/v1/platform/export/full returns 401 without session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: { 'content-type': 'application/json' },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/platform/export/full returns 401 with expired session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${EXPIRED_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/platform/export/full returns 401 with tampered cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${createTamperedCookie()}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('POST /api/v1/platform/export/full returns 401 with empty cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: 'session=',
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // Category 2: Authorization & Permissions (authz)
  // =========================================================================

  describe('Authorization & Permissions', () => {
    it('delegate without DATA_EXPORT permission gets 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('physician (has all permissions) can request export', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(202);
      expect(res.json().data).toBeDefined();
    });
  });

  // =========================================================================
  // Category 3: Physician Tenant Isolation (scoping)
  // =========================================================================

  describe('Physician Tenant Isolation', () => {
    it('export contains ONLY the authenticated physician data', async () => {
      // Physician1 requests export
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(202);

      // Verify exportRepo was called with physician1's ID
      expect(mockExportRepo.getCompleteHealthInformation).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
      );
      expect(mockExportRepo.getCompleteHealthInformation).not.toHaveBeenCalledWith(
        PHYSICIAN2_USER_ID,
      );
    });

    it('physician1 export contains zero records from physician2', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'json' },
      });

      expect(res.statusCode).toBe(202);

      // Verify the response body does not contain physician2's data
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN2_PATIENT_ID);
      expect(rawBody).not.toContain('Bob');
      expect(rawBody).not.toContain('Wilson');
      expect(rawBody).not.toContain('444555666');
      expect(rawBody).not.toContain('dr2@test.ca');
    });

    it('physician2 export contains zero records from physician1', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN2_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'json' },
      });

      expect(res.statusCode).toBe(202);

      // Verify exportRepo was called with physician2's ID
      expect(mockExportRepo.getCompleteHealthInformation).toHaveBeenCalledWith(
        PHYSICIAN2_USER_ID,
      );

      // Verify the response does not contain physician1's data
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN1_PATIENT_ID);
      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain('Martin');
      expect(rawBody).not.toContain('111222333');
      expect(rawBody).not.toContain('dr1@test.ca');
    });

    it('handler extracts providerId from auth context, not from request body', async () => {
      // Even if an attacker provides a different providerId in the request body,
      // the handler uses authContext.userId
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv', providerId: PHYSICIAN2_USER_ID },
      });

      expect(res.statusCode).toBe(202);

      // Verify the exportRepo was called with physician1's ID (from auth context),
      // NOT physician2's ID (from the request body)
      expect(mockExportRepo.getCompleteHealthInformation).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
      );
      expect(mockExportRepo.getCompleteHealthInformation).not.toHaveBeenCalledWith(
        PHYSICIAN2_USER_ID,
      );
    });
  });

  // =========================================================================
  // Category 4: Input Validation & Injection Prevention (input)
  // =========================================================================

  describe('Input Validation & Injection Prevention', () => {
    it('rejects invalid format parameter', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'xml' },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBeDefined();
      expect(res.json().data).toBeUndefined();
    });

    it('rejects SQL injection in format field', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: "'; DROP TABLE users; --" },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects XSS payload in format field', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: '<script>alert("xss")</script>' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects wrong type for format field (number instead of string)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 12345 },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts valid format "csv"', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(202);
    });

    it('accepts valid format "json"', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'json' },
      });

      expect(res.statusCode).toBe(202);
    });

    it('accepts empty body (defaults to csv)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: {},
      });

      expect(res.statusCode).toBe(202);
    });
  });

  // =========================================================================
  // Category 5: PHI & Data Leakage Prevention (leakage)
  // =========================================================================

  describe('PHI & Data Leakage Prevention', () => {
    it('error responses contain no PHI', async () => {
      // Trigger a validation error by providing an invalid format
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'invalid' },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;

      // Must not contain any PHI
      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain('Martin');
      expect(rawBody).not.toContain('111222333');
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain('dr1@test.ca');
    });

    it('401 responses contain no PHI or internal details', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: { 'content-type': 'application/json' },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;

      // Must not contain PHI, stack traces, or internal details
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain('111222333');
    });

    it('403 responses contain no PHI', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(403);
      const rawBody = res.body;

      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain('111222333');
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
    });

    it('successful response does not contain raw PHI in HTTP body', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(res.statusCode).toBe(202);
      const rawBody = res.body;

      // Response should only contain reportId, downloadUrl, expiresAt
      // It should NOT contain patient names or PHNs inline
      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain('Martin');
      expect(rawBody).not.toContain('111222333');
    });

    it('audit log entries do not contain PHI', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      const logStr = JSON.stringify(auditLogs);
      expect(logStr).not.toContain('Alice');
      expect(logStr).not.toContain('Martin');
      expect(logStr).not.toContain('111222333');
      expect(logStr).not.toContain('dr1@test.ca');
    });
  });

  // =========================================================================
  // Category 6: Audit Trail Verification (audit)
  // =========================================================================

  describe('Audit Trail Verification', () => {
    it('export request produces audit record', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      const requestLog = auditLogs.find(
        (l) => l.action === 'export.full_hi_requested',
      );
      expect(requestLog).toBeDefined();
      expect(requestLog!.resourceType).toBe('export');
      expect(requestLog!.actorType).toBe('physician');
      expect((requestLog!.metadata as any)?.providerId).toBe(PHYSICIAN1_USER_ID);
      expect((requestLog!.metadata as any)?.format).toBe('csv');
    });

    it('export completion produces audit record', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      const readyLog = auditLogs.find(
        (l) => l.action === 'export.full_hi_ready',
      );
      expect(readyLog).toBeDefined();
      expect(readyLog!.resourceType).toBe('export');
      expect(readyLog!.actorType).toBe('physician');
    });

    it('both audit events recorded for single export request', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      expect(auditLogs).toHaveLength(2);
      const actions = auditLogs.map((l) => l.action);
      expect(actions).toContain('export.full_hi_requested');
      expect(actions).toContain('export.full_hi_ready');
    });

    it('failed export request (403) does not produce completion audit record', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/platform/export/full',
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { format: 'csv' },
      });

      // No audit records should exist for the export service (delegate blocked at auth level)
      const exportAuditLogs = auditLogs.filter(
        (l) =>
          l.action === 'export.full_hi_requested' ||
          l.action === 'export.full_hi_ready',
      );
      expect(exportAuditLogs).toHaveLength(0);
    });
  });
});
