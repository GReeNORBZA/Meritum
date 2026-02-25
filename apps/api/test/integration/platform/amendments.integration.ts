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

import {
  authPluginFp,
  type AmendmentGateDeps,
} from '../../../src/plugins/auth.plugin.js';
import { platformRoutes } from '../../../src/domains/platform/platform.routes.js';
import {
  type PlatformHandlerDeps,
} from '../../../src/domains/platform/platform.handlers.js';
import {
  type PlatformServiceDeps,
  type StripeClient,
  type UserRepo,
  type AuditLogger,
  type ActiveProviderRepo,
  runAmendmentReminders,
} from '../../../src/domains/platform/platform.service.js';
import {
  type AmendmentRepository,
} from '../../../src/domains/platform/platform.repository.js';
import { ConflictError } from '../../../src/lib/errors.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000bb0001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000bb0001';

const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000bb0002';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);
const PHYSICIAN1_SESSION_ID = '00000000-2222-0000-0000-000000bb0002';

const PHYSICIAN2_USER_ID = '00000000-1111-0000-0000-000000bb0003';
const PHYSICIAN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_SESSION_TOKEN_HASH = hashToken(PHYSICIAN2_SESSION_TOKEN);
const PHYSICIAN2_SESSION_ID = '00000000-2222-0000-0000-000000bb0003';

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockAmendments: Array<Record<string, any>>;
let mockAmendmentResponses: Array<Record<string, any>>;

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
            role: 'ADMIN',
            subscriptionStatus: 'ACTIVE',
          },
        },
        [PHYSICIAN1_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: PHYSICIAN1_SESSION_ID,
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
            providerId: PHYSICIAN1_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        },
        [PHYSICIAN2_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: PHYSICIAN2_SESSION_ID,
            userId: PHYSICIAN2_USER_ID,
            tokenHash: PHYSICIAN2_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN2_USER_ID,
            providerId: PHYSICIAN2_USER_ID,
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
// Mock Amendment Repo
// ---------------------------------------------------------------------------

function createMockAmendmentRepo(): AmendmentRepository {
  return {
    createAmendment: vi.fn(async (data: any) => {
      const amendment = {
        amendmentId: crypto.randomUUID(),
        amendmentType: data.amendmentType,
        title: data.title,
        description: data.description,
        documentHash: createHash('sha256').update(data.documentText ?? '').digest('hex'),
        noticeDate: new Date(),
        effectiveDate: data.effectiveDate,
        createdBy: data.createdBy,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockAmendments.push(amendment);
      return amendment;
    }),

    findAmendmentById: vi.fn(async (amendmentId: string) => {
      const amendment = mockAmendments.find((a) => a.amendmentId === amendmentId);
      if (!amendment) return undefined;

      const responses = mockAmendmentResponses.filter(
        (r) => r.amendmentId === amendmentId,
      );
      return {
        ...amendment,
        responseCounts: {
          total: responses.length,
          acknowledged: responses.filter((r) => r.responseType === 'ACKNOWLEDGED').length,
          accepted: responses.filter((r) => r.responseType === 'ACCEPTED').length,
          rejected: responses.filter((r) => r.responseType === 'REJECTED').length,
        },
      };
    }),

    listAmendments: vi.fn(async (filters: any) => {
      const offset = ((filters.page ?? 1) - 1) * (filters.pageSize ?? 50);
      const now = new Date();

      const withStatus = mockAmendments.map((row) => ({
        ...row,
        derivedStatus: now < row.effectiveDate ? 'PENDING' : 'ACTIVE',
      }));

      const filtered = filters.status
        ? withStatus.filter((r) => r.derivedStatus === filters.status)
        : withStatus;

      return {
        data: filtered.slice(offset, offset + (filters.pageSize ?? 50)),
        total: filtered.length,
      };
    }),

    findPendingAmendmentsForProvider: vi.fn(async (providerId: string) => {
      const now = new Date();
      const pastEffective = mockAmendments.filter(
        (a) => a.effectiveDate <= now,
      );

      const respondedIds = new Set(
        mockAmendmentResponses
          .filter((r) => r.providerId === providerId)
          .map((r) => r.amendmentId),
      );

      return pastEffective.filter((a) => !respondedIds.has(a.amendmentId));
    }),

    createAmendmentResponse: vi.fn(async (data: any) => {
      // Check for duplicate — mirror the real repository behavior
      const existing = mockAmendmentResponses.find(
        (r) => r.amendmentId === data.amendmentId && r.providerId === data.providerId,
      );
      if (existing) {
        throw new ConflictError('Provider has already responded to this amendment');
      }

      const response = {
        responseId: crypto.randomUUID(),
        amendmentId: data.amendmentId,
        providerId: data.providerId,
        responseType: data.responseType,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        respondedAt: new Date(),
        createdAt: new Date(),
      };
      mockAmendmentResponses.push(response);
      return response;
    }),

    getAmendmentResponse: vi.fn(async (amendmentId: string, providerId: string) => {
      return mockAmendmentResponses.find(
        (r) => r.amendmentId === amendmentId && r.providerId === providerId,
      );
    }),

    countUnrespondedAmendments: vi.fn(async (providerId: string) => {
      const now = new Date();
      const pastEffective = mockAmendments.filter(
        (a) => a.effectiveDate <= now,
      );
      const respondedIds = new Set(
        mockAmendmentResponses
          .filter((r) => r.providerId === providerId)
          .map((r) => r.amendmentId),
      );
      return pastEffective.filter((a) => !respondedIds.has(a.amendmentId)).length;
    }),
  } as unknown as AmendmentRepository;
}

// ---------------------------------------------------------------------------
// Mock minimal platform deps
// ---------------------------------------------------------------------------

function createMockPlatformServiceDeps(
  amendmentRepo: AmendmentRepository,
): PlatformServiceDeps {
  return {
    subscriptionRepo: {} as any,
    paymentRepo: {} as any,
    statusComponentRepo: {} as any,
    incidentRepo: {} as any,
    amendmentRepo,
    activeProviderRepo: {
      findActiveProviderIds: vi.fn(async () => [
        PHYSICIAN1_USER_ID,
        PHYSICIAN2_USER_ID,
      ]),
    } as ActiveProviderRepo,
    userRepo: {
      findUserById: vi.fn(async () => undefined),
      updateSubscriptionStatus: vi.fn(async () => {}),
    } as UserRepo,
    stripe: {} as any,
    config: {
      stripePriceStandardMonthly: 'price_std_m',
      stripePriceStandardAnnual: 'price_std_a',
      stripePriceEarlyBirdMonthly: 'price_eb_m',
      stripePriceEarlyBirdAnnual: 'price_eb_a',
      stripeWebhookSecret: 'whsec_test',
    },
    auditLogger: {
      log: vi.fn(async () => {}),
    } as AuditLogger,
  };
}

// ---------------------------------------------------------------------------
// Amendment gate deps
// ---------------------------------------------------------------------------

function createMockAmendmentGateDeps(
  serviceDeps: PlatformServiceDeps,
): AmendmentGateDeps {
  return {
    getBlockingAmendments: async (providerId: string) => {
      if (!serviceDeps.amendmentRepo) return [];

      const pending =
        await serviceDeps.amendmentRepo.findPendingAmendmentsForProvider(
          providerId,
        );

      return pending
        .filter((a: any) => a.amendmentType === 'NON_MATERIAL')
        .map((a: any) => ({
          amendmentId: a.amendmentId,
          title: a.title,
          effectiveDate: a.effectiveDate,
        }));
    },
  };
}

// ---------------------------------------------------------------------------
// Seeding helpers
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;

function seedNonMaterialAmendment(
  opts: { effectiveDate?: Date; id?: string } = {},
) {
  const amendment = {
    amendmentId: opts.id ?? crypto.randomUUID(),
    amendmentType: 'NON_MATERIAL',
    title: 'Updated Privacy Policy v2',
    description: 'Minor wording change to privacy policy',
    documentHash: createHash('sha256').update('document text').digest('hex'),
    noticeDate: new Date(),
    effectiveDate: opts.effectiveDate ?? new Date(Date.now() - DAY_MS),
    createdBy: ADMIN_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  mockAmendments.push(amendment);
  return amendment;
}

function seedMaterialAmendment(
  opts: { effectiveDate?: Date; id?: string } = {},
) {
  const amendment = {
    amendmentId: opts.id ?? crypto.randomUUID(),
    amendmentType: 'MATERIAL',
    title: 'Updated Fee Schedule',
    description: 'Changes to billing rates',
    documentHash: createHash('sha256').update('material text').digest('hex'),
    noticeDate: new Date(),
    effectiveDate: opts.effectiveDate ?? new Date(Date.now() - DAY_MS),
    createdBy: ADMIN_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  mockAmendments.push(amendment);
  return amendment;
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let amendmentRepo: AmendmentRepository;
let serviceDeps: PlatformServiceDeps;
let eventEmitter: { emit: ReturnType<typeof vi.fn> };

describe('IMA Amendment Lifecycle', () => {
  beforeAll(async () => {
    mockAmendments = [];
    mockAmendmentResponses = [];

    amendmentRepo = createMockAmendmentRepo();
    serviceDeps = createMockPlatformServiceDeps(amendmentRepo);
    const amendmentGateDeps = createMockAmendmentGateDeps(serviceDeps);
    eventEmitter = { emit: vi.fn() };

    app = Fastify();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    // Register auth plugin with amendment gate
    await app.register(authPluginFp, {
      sessionDeps: {
        sessionRepo: createMockSessionRepo(),
        auditRepo: { appendAuditLog: vi.fn(async () => {}) },
        events: { emit: vi.fn() },
      } as any,
      amendmentGateDeps,
    });

    // Mock Stripe webhook verifier (required by platformRoutes)
    app.decorate('verifyStripeWebhook', async () => {});
    app.decorateRequest('stripeRawBody', undefined);

    // Register platform routes with event emitter
    const handlerDeps: PlatformHandlerDeps = {
      serviceDeps,
      eventEmitter: eventEmitter as any,
    };
    await app.register(platformRoutes, { deps: handlerDeps });

    // Dummy PHI endpoint to test the gate middleware
    app.get('/api/v1/claims', {
      preHandler: [app.authenticate, app.checkAmendmentGate],
      handler: async (_request, reply) => {
        return reply.code(200).send({ data: [{ claimId: 'test-claim' }] });
      },
    });

    // Dummy patients endpoint (another PHI endpoint)
    app.get('/api/v1/patients', {
      preHandler: [app.authenticate, app.checkAmendmentGate],
      handler: async (_request, reply) => {
        return reply.code(200).send({ data: [{ patientId: 'test-patient' }] });
      },
    });

    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockAmendments = [];
    mockAmendmentResponses = [];
    vi.clearAllMocks();
  });

  // =========================================================================
  // Admin creates non-material amendment
  // =========================================================================

  describe('Admin creates non-material amendment', () => {
    it('creates amendment and returns 201', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/amendments',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: {
          amendment_type: 'NON_MATERIAL',
          title: 'Updated Privacy Policy',
          description: 'Minor wording change',
          document_text: 'Full document text here...',
          effective_date: new Date(Date.now() + 30 * DAY_MS).toISOString(),
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.amendmentType).toBe('NON_MATERIAL');
      expect(body.data.title).toBe('Updated Privacy Policy');
      expect(body.data.documentHash).toBeDefined();
    });

    it('all active physicians receive IMA_AMENDMENT_NOTICE notification', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/platform/amendments',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: {
          amendment_type: 'NON_MATERIAL',
          title: 'Privacy Notice Update',
          description: 'Updated privacy text',
          document_text: 'Document text...',
          effective_date: new Date(Date.now() + 30 * DAY_MS).toISOString(),
        },
      });

      // Verify event emitter was called with IMA_AMENDMENT_NOTICE
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'IMA_AMENDMENT_NOTICE',
        expect.objectContaining({
          amendmentType: 'NON_MATERIAL',
          title: 'Privacy Notice Update',
          recipientProviderIds: expect.arrayContaining([
            PHYSICIAN1_USER_ID,
            PHYSICIAN2_USER_ID,
          ]),
        }),
      );
    });

    it('amendment appears in admin list', async () => {
      // Create amendment via API
      await app.inject({
        method: 'POST',
        url: '/api/v1/platform/amendments',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: {
          amendment_type: 'NON_MATERIAL',
          title: 'Listed Amendment',
          description: 'Should appear in admin list',
          document_text: 'Text...',
          effective_date: new Date(Date.now() + 30 * DAY_MS).toISOString(),
        },
      });

      const listRes = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/amendments',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(listRes.statusCode).toBe(200);
      const body = JSON.parse(listRes.body);
      expect(body.data.length).toBe(1);
      expect(body.data[0].title).toBe('Listed Amendment');
      expect(body.pagination).toBeDefined();
    });
  });

  // =========================================================================
  // Physician acknowledges non-material amendment
  // =========================================================================

  describe('Physician acknowledges non-material amendment', () => {
    it('before effective_date: PHI endpoints work normally', async () => {
      // Create a NON_MATERIAL amendment with effective_date in the future
      seedNonMaterialAmendment({
        effectiveDate: new Date(Date.now() + 7 * DAY_MS),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('after effective_date: PHI endpoints return 403 IMA_AMENDMENT_REQUIRED', async () => {
      // Create amendment with effective_date in the past (already active)
      seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('IMA_AMENDMENT_REQUIRED');
      expect(body.error.details.amendmentIds).toHaveLength(1);
    });

    it('physician acknowledges: returns 200', async () => {
      const amendment = seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.acknowledged).toBe(true);
    });

    it('after acknowledgement: PHI endpoints work again', async () => {
      const amendment = seedNonMaterialAmendment();

      // Acknowledge the amendment
      await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      // PHI endpoint should be accessible again
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('double acknowledgement returns 409', async () => {
      const amendment = seedNonMaterialAmendment();

      // First acknowledgement
      const res1 = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });
      expect(res1.statusCode).toBe(200);

      // Second acknowledgement — should conflict
      const res2 = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });
      expect(res2.statusCode).toBe(409);
    });
  });

  // =========================================================================
  // Admin creates material amendment
  // =========================================================================

  describe('Admin creates material amendment', () => {
    it('creates amendment and returns 201', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/amendments',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: {
          amendment_type: 'MATERIAL',
          title: 'Updated Fee Schedule',
          description: 'Changes to billing rates',
          document_text: 'Full fee schedule text...',
          effective_date: new Date(Date.now() + 60 * DAY_MS).toISOString(),
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.amendmentType).toBe('MATERIAL');
      expect(body.data.title).toBe('Updated Fee Schedule');
    });

    it('after effective_date: PHI endpoints still work (material does not block)', async () => {
      // Create MATERIAL amendment with effective_date in the past
      seedMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      // MATERIAL amendments do NOT block — silence = existing terms continue
      expect(res.statusCode).toBe(200);
    });

    it('physician accepts: returns 200', async () => {
      const amendment = seedMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/respond`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
        payload: { response_type: 'ACCEPTED' },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.responded).toBe(true);
      expect(body.data.responseType).toBe('ACCEPTED');
    });

    it('physician rejects: returns 200', async () => {
      const amendment = seedMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/respond`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
        payload: { response_type: 'REJECTED' },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.responded).toBe(true);
      expect(body.data.responseType).toBe('REJECTED');
    });

    it('physician who did not respond: existing terms continue (no blocking)', async () => {
      // Create MATERIAL amendment past effective_date
      seedMaterialAmendment();

      // Physician2 has NOT responded — PHI endpoints still work
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('double response to material amendment returns 409', async () => {
      const amendment = seedMaterialAmendment();

      // First response
      const res1 = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/respond`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
        payload: { response_type: 'ACCEPTED' },
      });
      expect(res1.statusCode).toBe(200);

      // Second response — should conflict
      const res2 = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/respond`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
        payload: { response_type: 'REJECTED' },
      });
      expect(res2.statusCode).toBe(409);
    });
  });

  // =========================================================================
  // Amendment reminders
  // =========================================================================

  describe('Amendment reminders', () => {
    it('reminder sent at 30 days before deadline for material amendments', async () => {
      const reminderEmitter = { emit: vi.fn() };

      // Create MATERIAL amendment with effective_date 30 days out
      seedMaterialAmendment({
        effectiveDate: new Date(Date.now() + 30 * DAY_MS),
      });

      await runAmendmentReminders(serviceDeps, reminderEmitter as any);

      // Verify IMA_AMENDMENT_REMINDER emitted for both physicians
      expect(reminderEmitter.emit).toHaveBeenCalledWith(
        'IMA_AMENDMENT_REMINDER',
        expect.objectContaining({
          daysUntilEffective: 30,
          providerId: PHYSICIAN1_USER_ID,
        }),
      );
      expect(reminderEmitter.emit).toHaveBeenCalledWith(
        'IMA_AMENDMENT_REMINDER',
        expect.objectContaining({
          daysUntilEffective: 30,
          providerId: PHYSICIAN2_USER_ID,
        }),
      );
    });

    it('reminder sent at 7 days before deadline', async () => {
      const reminderEmitter = { emit: vi.fn() };

      // Create MATERIAL amendment with effective_date 7 days out
      seedMaterialAmendment({
        effectiveDate: new Date(Date.now() + 7 * DAY_MS),
      });

      await runAmendmentReminders(serviceDeps, reminderEmitter as any);

      expect(reminderEmitter.emit).toHaveBeenCalledWith(
        'IMA_AMENDMENT_REMINDER',
        expect.objectContaining({
          daysUntilEffective: 7,
          providerId: PHYSICIAN1_USER_ID,
        }),
      );
    });

    it('no reminder sent for NON_MATERIAL amendments', async () => {
      const reminderEmitter = { emit: vi.fn() };

      seedNonMaterialAmendment({
        effectiveDate: new Date(Date.now() + 30 * DAY_MS),
      });

      await runAmendmentReminders(serviceDeps, reminderEmitter as any);

      expect(reminderEmitter.emit).not.toHaveBeenCalled();
    });

    it('no reminder sent for providers who already responded', async () => {
      const reminderEmitter = { emit: vi.fn() };

      const amendment = seedMaterialAmendment({
        effectiveDate: new Date(Date.now() + 7 * DAY_MS),
      });

      // Physician1 already responded
      mockAmendmentResponses.push({
        responseId: crypto.randomUUID(),
        amendmentId: amendment.amendmentId,
        providerId: PHYSICIAN1_USER_ID,
        responseType: 'ACCEPTED',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
        respondedAt: new Date(),
        createdAt: new Date(),
      });

      await runAmendmentReminders(serviceDeps, reminderEmitter as any);

      // Only physician2 should get reminder (physician1 already responded)
      const reminderCalls = reminderEmitter.emit.mock.calls.filter(
        (call: any[]) => call[0] === 'IMA_AMENDMENT_REMINDER',
      );
      expect(reminderCalls.length).toBe(1);
      expect(reminderCalls[0][1].providerId).toBe(PHYSICIAN2_USER_ID);
    });
  });

  // =========================================================================
  // Multi-physician isolation
  // =========================================================================

  describe('Multi-physician isolation', () => {
    it('physician1 acknowledgement does not affect physician2 gate status', async () => {
      const amendment = seedNonMaterialAmendment();

      // Physician1 acknowledges
      await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      // Physician1 should have PHI access
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });
      expect(res1.statusCode).toBe(200);

      // Physician2 should still be blocked (has NOT acknowledged)
      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });
      expect(res2.statusCode).toBe(403);
      const body2 = JSON.parse(res2.body);
      expect(body2.error.code).toBe('IMA_AMENDMENT_REQUIRED');
    });

    it('each physician must acknowledge independently', async () => {
      const amendment = seedNonMaterialAmendment();

      // Both physicians blocked initially
      const res1before = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });
      expect(res1before.statusCode).toBe(403);

      const res2before = await app.inject({
        method: 'GET',
        url: '/api/v1/patients',
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });
      expect(res2before.statusCode).toBe(403);

      // Physician1 acknowledges
      await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      // Physician2 acknowledges
      await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });

      // Both should now have access
      const res1after = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });
      expect(res1after.statusCode).toBe(200);

      const res2after = await app.inject({
        method: 'GET',
        url: '/api/v1/patients',
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });
      expect(res2after.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // Error response safety
  // =========================================================================

  describe('Error response safety', () => {
    it('error responses do not leak internal details', async () => {
      // Non-existent amendment
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/amendments/00000000-0000-0000-0000-000000000099/acknowledge',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|stack/i);
    });

    it('403 gate error does not expose amendment content', async () => {
      seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      // Should contain amendment IDs but NOT full description or document text
      expect(body.error.code).toBe('IMA_AMENDMENT_REQUIRED');
      expect(body.error.details.amendmentIds).toBeDefined();
      expect(JSON.stringify(body)).not.toContain('document text');
      expect(JSON.stringify(body)).not.toContain('description');
    });
  });
});
