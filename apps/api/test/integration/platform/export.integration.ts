import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';
import * as AdmZip from 'adm-zip';

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
  type ExportAuthContext,
} from '../../../src/domains/platform/export.service.js';
import { type CompleteHealthInformation } from '../../../src/domains/platform/export.repository.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);

const PHYSICIAN2_USER_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_SESSION_TOKEN_HASH = hashToken(PHYSICIAN2_SESSION_TOKEN);

// Delegate without DATA_EXPORT permission
const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000003';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);

// Physician with CANCELLED subscription status
const CANCELLED_USER_ID = '00000000-1111-0000-0000-000000000004';
const CANCELLED_SESSION_TOKEN = randomBytes(32).toString('hex');
const CANCELLED_SESSION_TOKEN_HASH = hashToken(CANCELLED_SESSION_TOKEN);

// Physician with SUSPENDED subscription status
const SUSPENDED_USER_ID = '00000000-1111-0000-0000-000000000005';
const SUSPENDED_SESSION_TOKEN = randomBytes(32).toString('hex');
const SUSPENDED_SESSION_TOKEN_HASH = hashToken(SUSPENDED_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Mock session repo — supports physicians, delegate, and special states
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
      if (tokenHash === CANCELLED_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000004',
            userId: CANCELLED_USER_ID,
            tokenHash: CANCELLED_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: CANCELLED_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'CANCELLED',
          },
        };
      }
      if (tokenHash === SUSPENDED_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000005',
            userId: SUSPENDED_USER_ID,
            tokenHash: SUSPENDED_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: SUSPENDED_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'SUSPENDED',
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
// HI data factories
// ---------------------------------------------------------------------------

function createEmptyHi(): CompleteHealthInformation {
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
}

function createHiWithData(providerId: string): CompleteHealthInformation {
  return {
    ...createEmptyHi(),
    patients: [
      { patientId: crypto.randomUUID(), firstName: 'Jane', lastName: 'Doe', dob: '1990-01-01', phn: '123456789' },
      { patientId: crypto.randomUUID(), firstName: 'John', lastName: 'Smith', dob: '1985-06-15', phn: '987654321' },
    ],
    claims: [
      { claimId: crypto.randomUUID(), serviceDate: '2026-01-01', code: '03.03A', amount: '50.00', status: 'PAID' },
    ],
    provider: { providerId, firstName: 'Dr', lastName: 'Test', email: 'dr@test.ca' },
    subscription: { subscriptionId: crypto.randomUUID(), status: 'ACTIVE', plan: 'STANDARD_MONTHLY' },
  };
}

// ---------------------------------------------------------------------------
// Mock export deps
// ---------------------------------------------------------------------------

let uploadedBuffers: Map<string, Buffer>;
let reportStore: Array<Record<string, unknown>>;
let auditLogs: Array<Record<string, unknown>>;
let emittedEvents: Array<{ event: string; data: Record<string, unknown> }>;
let mockExportRepo: { getCompleteHealthInformation: ReturnType<typeof vi.fn> };

function createMockExportDeps(): FullHiExportDeps {
  uploadedBuffers = new Map();
  reportStore = [];
  auditLogs = [];
  emittedEvents = [];
  mockExportRepo = {
    getCompleteHealthInformation: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN1_USER_ID) return createHiWithData(PHYSICIAN1_USER_ID);
      if (providerId === PHYSICIAN2_USER_ID) return createHiWithData(PHYSICIAN2_USER_ID);
      return createEmptyHi();
    }),
  };

  return {
    exportRepo: mockExportRepo as any,
    reportRepo: {
      createReport: vi.fn(async (data: any) => {
        const report = { reportId: crypto.randomUUID(), ...data };
        reportStore.push(report);
        return report;
      }),
    },
    objectStorage: {
      uploadBuffer: vi.fn(async (key: string, buffer: Buffer) => {
        uploadedBuffers.set(key, buffer);
      }),
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
// Mock Stripe + service repos (required for platformRoutes registration)
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
            details: (error as any).details,
          },
        });
      }
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

function authedPost(url: string, body?: Record<string, unknown>, token = PHYSICIAN1_SESSION_TOKEN) {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Complete Health Information Export (IMA §8.3)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Clear tracking arrays
    uploadedBuffers = new Map();
    reportStore = [];
    auditLogs = [];
    emittedEvents = [];

    // Re-add implementations cleared by vi.clearAllMocks()
    mockExportRepo.getCompleteHealthInformation.mockImplementation(
      async (providerId: string) => {
        if (providerId === PHYSICIAN1_USER_ID) return createHiWithData(PHYSICIAN1_USER_ID);
        if (providerId === PHYSICIAN2_USER_ID) return createHiWithData(PHYSICIAN2_USER_ID);
        return createEmptyHi();
      },
    );
    (mockExportDeps.reportRepo.createReport as ReturnType<typeof vi.fn>).mockImplementation(
      async (data: any) => {
        const report = { reportId: crypto.randomUUID(), ...data };
        reportStore.push(report);
        return report;
      },
    );
    (mockExportDeps.objectStorage.uploadBuffer as ReturnType<typeof vi.fn>).mockImplementation(
      async (key: string, buffer: Buffer) => { uploadedBuffers.set(key, buffer); },
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
  // Core Integration Tests
  // =========================================================================

  it('physician requests full export → 202 accepted', async () => {
    const res = await authedPost('/api/v1/platform/export/full', { format: 'csv' });

    expect(res.statusCode).toBe(202);
    const body = res.json();
    expect(body.data).toBeDefined();
    expect(body.data.reportId).toBeDefined();
    expect(typeof body.data.reportId).toBe('string');
    expect(body.data.downloadUrl).toBeDefined();
    expect(body.data.downloadUrl).toContain('https://');
    expect(body.data.expiresAt).toBeDefined();
  });

  it('export ZIP contains patients.csv with all patient records', async () => {
    const res = await authedPost('/api/v1/platform/export/full', { format: 'csv' });

    expect(res.statusCode).toBe(202);

    // Verify the upload was made
    expect(uploadedBuffers.size).toBe(1);
    const zipBuffer = [...uploadedBuffers.values()][0];
    const zip = new AdmZip.default(zipBuffer);
    const entryNames = zip.getEntries().map((e) => e.entryName);

    expect(entryNames).toContain('patients.csv');

    const patientsCsv = zip.readAsText('patients.csv');
    // Should contain headers and 2 patient rows
    const lines = patientsCsv.trim().split('\n');
    expect(lines.length).toBe(3); // header + 2 patients
    expect(patientsCsv).toContain('Jane');
    expect(patientsCsv).toContain('John');
  });

  it('export ZIP contains provider.csv', async () => {
    const res = await authedPost('/api/v1/platform/export/full', { format: 'csv' });

    expect(res.statusCode).toBe(202);
    const zipBuffer = [...uploadedBuffers.values()][0];
    const zip = new AdmZip.default(zipBuffer);
    const entryNames = zip.getEntries().map((e) => e.entryName);

    expect(entryNames).toContain('provider.csv');
    const providerCsv = zip.readAsText('provider.csv');
    expect(providerCsv).toContain('Dr');
    expect(providerCsv).toContain('Test');
  });

  it('export ZIP contains manifest.json with entity counts', async () => {
    const res = await authedPost('/api/v1/platform/export/full', { format: 'csv' });

    expect(res.statusCode).toBe(202);
    const zipBuffer = [...uploadedBuffers.values()][0];
    const zip = new AdmZip.default(zipBuffer);

    const manifestEntry = zip.getEntry('manifest.json');
    expect(manifestEntry).toBeDefined();

    const manifest = JSON.parse(zip.readAsText('manifest.json'));
    expect(manifest.export_date).toBeDefined();
    expect(manifest.provider_id).toBe(PHYSICIAN1_USER_ID);
    expect(manifest.format).toBe('csv');
    expect(manifest.schema_version).toBe('1.0.0');
    expect(manifest.entity_counts).toBeDefined();
    expect(manifest.entity_counts.patients).toBe(2);
    expect(manifest.entity_counts.claims).toBe(1);
    expect(manifest.entity_counts.provider).toBe(1);
    expect(manifest.entity_counts.subscription).toBe(1);
  });

  it('download URL is time-limited (72h)', async () => {
    const res = await authedPost('/api/v1/platform/export/full', { format: 'csv' });

    expect(res.statusCode).toBe(202);
    const body = res.json();
    const expiresAt = new Date(body.data.expiresAt);
    const now = Date.now();
    const diffHours = (expiresAt.getTime() - now) / (1000 * 60 * 60);
    expect(diffHours).toBeGreaterThan(71);
    expect(diffHours).toBeLessThan(73);
  });

  it('FULL_HI_EXPORT_READY notification sent', async () => {
    const res = await authedPost('/api/v1/platform/export/full', { format: 'csv' });

    expect(res.statusCode).toBe(202);
    const body = res.json();

    const event = emittedEvents.find((e) => e.event === 'FULL_HI_EXPORT_READY');
    expect(event).toBeDefined();
    expect(event!.data.reportId).toBe(body.data.reportId);
    expect(event!.data.providerId).toBe(PHYSICIAN1_USER_ID);
    expect(event!.data.format).toBe('csv');
    expect(event!.data.downloadUrl).toBeDefined();
    expect(event!.data.expiresAt).toBeDefined();
  });

  it('export accessible in CANCELLED subscription state', async () => {
    const res = await authedPost(
      '/api/v1/platform/export/full',
      { format: 'csv' },
      CANCELLED_SESSION_TOKEN,
    );

    // Should not be 401, 402, or 403 — DATA_EXPORT is available to CANCELLED users
    expect(res.statusCode).toBe(202);
    const body = res.json();
    expect(body.data.reportId).toBeDefined();
    expect(body.data.downloadUrl).toBeDefined();
  });

  it('export accessible in SUSPENDED subscription state', async () => {
    const res = await authedPost(
      '/api/v1/platform/export/full',
      { format: 'csv' },
      SUSPENDED_SESSION_TOKEN,
    );

    // DATA_EXPORT should still be accessible to SUSPENDED users per IMA
    expect(res.statusCode).toBe(202);
    const body = res.json();
    expect(body.data.reportId).toBeDefined();
    expect(body.data.downloadUrl).toBeDefined();
  });

  it('delegate without DATA_EXPORT permission cannot export (403)', async () => {
    const res = await authedPost(
      '/api/v1/platform/export/full',
      { format: 'csv' },
      DELEGATE_SESSION_TOKEN,
    );

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.error).toBeDefined();
    expect(body.error.code).toBe('FORBIDDEN');
    expect(body.data).toBeUndefined();
  });
});
