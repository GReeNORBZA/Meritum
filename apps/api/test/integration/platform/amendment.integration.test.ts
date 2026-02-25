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
} from '../../../src/domains/platform/platform.service.js';
import {
  type AmendmentRepository,
} from '../../../src/domains/platform/platform.repository.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

// Admin user
const ADMIN_USER_ID = '00000000-1111-0000-0000-000000aa0001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000aa0001';

// Physician user
const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000aa0002';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000aa0002';

// Second physician for isolation tests
const PHYSICIAN2_USER_ID = '00000000-1111-0000-0000-000000aa0003';
const PHYSICIAN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_SESSION_TOKEN_HASH = hashToken(PHYSICIAN2_SESSION_TOKEN);
const PHYSICIAN2_SESSION_ID = '00000000-2222-0000-0000-000000aa0003';

// Fixed amendment IDs
const AMENDMENT_ID = '00000000-aaaa-0000-0000-000000000001';
const MATERIAL_AMENDMENT_ID = '00000000-aaaa-0000-0000-000000000002';

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
            providerId: PHYSICIAN_USER_ID,
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
      // Check for duplicate
      const existing = mockAmendmentResponses.find(
        (r) => r.amendmentId === data.amendmentId && r.providerId === data.providerId,
      );
      if (existing) {
        const err: any = new Error('duplicate');
        err.code = '23505';
        throw err;
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
// Mock minimal platform deps (stubs for non-amendment functionality)
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
        PHYSICIAN_USER_ID,
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
// Amendment gate deps (wraps the service function)
// ---------------------------------------------------------------------------

function createMockAmendmentGateDeps(
  serviceDeps: PlatformServiceDeps,
): AmendmentGateDeps {
  return {
    getBlockingAmendments: async (providerId: string) => {
      // Inline implementation matching the service logic
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
// Test setup
// ---------------------------------------------------------------------------

let app: FastifyInstance;

function seedNonMaterialAmendment(
  opts: { effectiveDate?: Date; id?: string } = {},
) {
  const amendment = {
    amendmentId: opts.id ?? AMENDMENT_ID,
    amendmentType: 'NON_MATERIAL',
    title: 'Updated Privacy Policy v2',
    description: 'Minor wording change to privacy policy',
    documentHash: createHash('sha256').update('document text').digest('hex'),
    noticeDate: new Date(),
    effectiveDate: opts.effectiveDate ?? new Date(Date.now() - 24 * 60 * 60 * 1000), // yesterday
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
    amendmentId: opts.id ?? MATERIAL_AMENDMENT_ID,
    amendmentType: 'MATERIAL',
    title: 'Updated Fee Schedule',
    description: 'Changes to billing rates',
    documentHash: createHash('sha256').update('material text').digest('hex'),
    noticeDate: new Date(),
    effectiveDate: opts.effectiveDate ?? new Date(Date.now() - 24 * 60 * 60 * 1000), // yesterday
    createdBy: ADMIN_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  mockAmendments.push(amendment);
  return amendment;
}

describe('Amendment Handlers and Gate Middleware', () => {
  let amendmentRepo: AmendmentRepository;
  let serviceDeps: PlatformServiceDeps;

  beforeAll(async () => {
    mockAmendments = [];
    mockAmendmentResponses = [];

    amendmentRepo = createMockAmendmentRepo();
    serviceDeps = createMockPlatformServiceDeps(amendmentRepo);
    const amendmentGateDeps = createMockAmendmentGateDeps(serviceDeps);

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

    // Mock the Stripe webhook verifier (required by platformRoutes but not relevant here)
    app.decorate('verifyStripeWebhook', async () => {});
    // Also mock stripeRawBody on request
    app.decorateRequest('stripeRawBody', undefined);

    // Register platform routes
    const handlerDeps: PlatformHandlerDeps = {
      serviceDeps,
    };
    await app.register(platformRoutes, { deps: handlerDeps });

    // Register a dummy PHI endpoint to test the gate middleware
    app.get('/api/v1/claims', {
      preHandler: [app.authenticate, app.checkAmendmentGate],
      handler: async (_request, reply) => {
        return reply.code(200).send({ data: [{ claimId: 'test-claim' }] });
      },
    });

    // Register a dummy export endpoint (should NOT be gated)
    app.get('/api/v1/data/export', {
      preHandler: [app.authenticate, app.checkAmendmentGate],
      handler: async (_request, reply) => {
        return reply.code(200).send({ data: { exportUrl: '/download/test' } });
      },
    });

    // Register a dummy logout endpoint (should NOT be gated)
    app.post('/api/v1/auth/logout', {
      preHandler: [app.authenticate, app.checkAmendmentGate],
      handler: async (_request, reply) => {
        return reply.code(200).send({ data: { loggedOut: true } });
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
  // Admin amendment CRUD
  // =========================================================================

  describe('Admin Amendment Management', () => {
    it('POST /api/v1/platform/amendments creates amendment (admin only)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/amendments',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: {
          amendment_type: 'NON_MATERIAL',
          title: 'Updated Privacy Policy',
          description: 'Minor wording change',
          document_text: 'Full document text here...',
          effective_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        },
      });

      if (res.statusCode === 500) {
        console.log('DEBUG 500 body:', res.body);
      }
      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.amendmentType).toBe('NON_MATERIAL');
      expect(body.data.title).toBe('Updated Privacy Policy');
    });

    it('POST /api/v1/platform/amendments returns 403 for non-admin', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/amendments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          amendment_type: 'NON_MATERIAL',
          title: 'Attempted Amendment',
          description: 'Should be denied',
          document_text: 'Text',
          effective_date: new Date().toISOString(),
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('POST /api/v1/platform/amendments returns 401 without auth', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/amendments',
        payload: {
          amendment_type: 'NON_MATERIAL',
          title: 'No Auth',
          description: 'Should fail',
          document_text: 'Text',
          effective_date: new Date().toISOString(),
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('GET /api/v1/platform/amendments lists amendments (admin only)', async () => {
      seedNonMaterialAmendment();
      seedMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/amendments',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(2);
      expect(body.pagination).toBeDefined();
    });

    it('GET /api/v1/platform/amendments returns 403 for physician', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/amendments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });

    it('GET /api/v1/platform/amendments/:id returns amendment detail (admin)', async () => {
      const amendment = seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}`,
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.amendmentId).toBe(amendment.amendmentId);
      expect(body.data.responseCounts).toBeDefined();
    });

    it('GET /api/v1/platform/amendments/:id returns 404 for non-existent', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/amendments/00000000-0000-0000-0000-000000000099',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
    });

    it('GET /api/v1/platform/amendments/:id rejects non-UUID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/amendments/not-a-uuid',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Physician acknowledge/respond
  // =========================================================================

  describe('Physician Amendment Acknowledgement', () => {
    it('POST /amendments/:id/acknowledge records acknowledgement', async () => {
      const amendment = seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.acknowledged).toBe(true);

      // Verify response was recorded
      expect(mockAmendmentResponses.length).toBe(1);
      expect(mockAmendmentResponses[0].responseType).toBe('ACKNOWLEDGED');
      expect(mockAmendmentResponses[0].providerId).toBe(PHYSICIAN_USER_ID);
    });

    it('POST /amendments/:id/acknowledge returns 401 without auth', async () => {
      const amendment = seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
      });

      expect(res.statusCode).toBe(401);
    });

    it('POST /amendments/:id/acknowledge returns 404 for non-existent amendment', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/amendments/00000000-0000-0000-0000-000000000099/acknowledge',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
    });

    it('POST /amendments/:id/respond records ACCEPTED response', async () => {
      const amendment = seedMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/respond`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { response_type: 'ACCEPTED' },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.responded).toBe(true);
      expect(body.data.responseType).toBe('ACCEPTED');
    });

    it('POST /amendments/:id/respond records REJECTED response', async () => {
      const amendment = seedMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/respond`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { response_type: 'REJECTED' },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.responseType).toBe('REJECTED');
    });

    it('POST /amendments/:id/respond rejects invalid response type', async () => {
      const amendment = seedMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/respond`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { response_type: 'INVALID' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('GET /api/v1/account/pending-amendments returns pending amendments', async () => {
      seedNonMaterialAmendment();
      seedMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/pending-amendments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(2);
    });

    it('GET /api/v1/account/pending-amendments returns empty after all acknowledged', async () => {
      const amendment = seedNonMaterialAmendment();

      // Acknowledge it
      mockAmendmentResponses.push({
        responseId: crypto.randomUUID(),
        amendmentId: amendment.amendmentId,
        providerId: PHYSICIAN_USER_ID,
        responseType: 'ACKNOWLEDGED',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
        respondedAt: new Date(),
        createdAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/pending-amendments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(0);
    });
  });

  // =========================================================================
  // Gate middleware
  // =========================================================================

  describe('Amendment Gate Middleware', () => {
    it('gate middleware blocks PHI access when unacknowledged NON_MATERIAL amendment exists', async () => {
      // Create a NON_MATERIAL amendment with effective_date in the past
      seedNonMaterialAmendment();

      // Access a PHI endpoint as a physician who has not acknowledged
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('IMA_AMENDMENT_REQUIRED');
      expect(body.error.details.amendmentIds).toHaveLength(1);
    });

    it('gate middleware does not block when amendment is acknowledged', async () => {
      const amendment = seedNonMaterialAmendment();

      // Acknowledge the amendment
      mockAmendmentResponses.push({
        responseId: crypto.randomUUID(),
        amendmentId: amendment.amendmentId,
        providerId: PHYSICIAN_USER_ID,
        responseType: 'ACKNOWLEDGED',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
        respondedAt: new Date(),
        createdAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('gate middleware does not block when amendment effective_date is in the future', async () => {
      seedNonMaterialAmendment({
        effectiveDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('gate middleware does NOT block MATERIAL amendments (only NON_MATERIAL block)', async () => {
      // Only a MATERIAL amendment exists (unacknowledged)
      seedMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      // MATERIAL amendments do not block — silence = existing terms continue
      expect(res.statusCode).toBe(200);
    });

    it('gate middleware does not block amendment acknowledgement endpoint', async () => {
      // Create blocking amendment
      const amendment = seedNonMaterialAmendment();

      // POST to acknowledge — should NOT be blocked
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('gate middleware does not block amendment respond endpoint', async () => {
      // Create blocking NON_MATERIAL amendment AND a material one
      seedNonMaterialAmendment();
      const material = seedMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${material.amendmentId}/respond`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { response_type: 'ACCEPTED' },
      });

      expect(res.statusCode).toBe(200);
    });

    it('gate middleware does not block data export', async () => {
      seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/data/export',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('gate middleware does not block logout', async () => {
      seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('gate middleware does not block account endpoints', async () => {
      seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/pending-amendments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('gate middleware does not block admin users', async () => {
      seedNonMaterialAmendment();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      // Admin is not a physician — gate does not apply
      expect(res.statusCode).toBe(200);
    });

    it('gate middleware blocks with multiple unacknowledged amendments', async () => {
      const a1 = seedNonMaterialAmendment({ id: '00000000-aaaa-0000-0000-000000000010' });
      const a2 = seedNonMaterialAmendment({ id: '00000000-aaaa-0000-0000-000000000011' });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('IMA_AMENDMENT_REQUIRED');
      expect(body.error.details.amendmentIds).toHaveLength(2);
      expect(body.error.details.amendmentIds).toContain(a1.amendmentId);
      expect(body.error.details.amendmentIds).toContain(a2.amendmentId);
    });
  });

  // =========================================================================
  // IP address and user-agent capture
  // =========================================================================

  describe('Request metadata capture', () => {
    it('acknowledging records ip_address and user_agent from request', async () => {
      const amendment = seedNonMaterialAmendment();

      await app.inject({
        method: 'POST',
        url: `/api/v1/platform/amendments/${amendment.amendmentId}/acknowledge`,
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'user-agent': 'Mozilla/5.0 TestBrowser',
        },
      });

      expect(mockAmendmentResponses.length).toBe(1);
      expect(mockAmendmentResponses[0].userAgent).toBe('Mozilla/5.0 TestBrowser');
      // ip_address should be captured from request, not body
      expect(mockAmendmentResponses[0].ipAddress).toBeDefined();
    });
  });
});
