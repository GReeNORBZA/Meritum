import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
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
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { ahcipRoutes } from '../../../src/domains/ahcip/ahcip.routes.js';
import { type AhcipHandlerDeps } from '../../../src/domains/ahcip/ahcip.handlers.js';
import { AhcipBatchStatus } from '@meritum/shared/constants/ahcip.constants.js';

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

// ---------------------------------------------------------------------------
// Test batch data
// ---------------------------------------------------------------------------

const BATCH_ID_1 = '00000000-bbbb-0000-0000-000000000001';
const BATCH_ID_2 = '00000000-bbbb-0000-0000-000000000002';

function makeMockBatch(overrides: Record<string, unknown> = {}) {
  return {
    ahcipBatchId: BATCH_ID_1,
    physicianId: PHYSICIAN1_USER_ID,
    baNumber: '12345',
    batchWeek: '2026-02-19',
    status: AhcipBatchStatus.GENERATED,
    claimCount: 5,
    totalSubmittedValue: '500.00',
    filePath: null,
    fileHash: null,
    submissionReference: null,
    submittedAt: null,
    responseReceivedAt: null,
    createdAt: new Date(),
    createdBy: PHYSICIAN1_USER_ID,
    ...overrides,
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
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock AHCIP repository
// ---------------------------------------------------------------------------

function createMockAhcipRepo() {
  return {
    createAhcipDetail: vi.fn(async () => ({})),
    findAhcipDetailByClaimId: vi.fn(async () => null),
    updateAhcipDetail: vi.fn(async () => undefined),
    findAhcipClaimWithDetails: vi.fn(async () => null),
    listAhcipClaimsForBatch: vi.fn(async () => []),
    updateAssessmentResult: vi.fn(async () => undefined),
    createAhcipBatch: vi.fn(async () => makeMockBatch()),
    findBatchById: vi.fn(async (batchId: string, physicianId: string) => {
      if (batchId === BATCH_ID_1 && physicianId === PHYSICIAN1_USER_ID) {
        return makeMockBatch();
      }
      if (batchId === BATCH_ID_2 && physicianId === PHYSICIAN2_USER_ID) {
        return makeMockBatch({
          ahcipBatchId: BATCH_ID_2,
          physicianId: PHYSICIAN2_USER_ID,
        });
      }
      return null;
    }),
    updateBatchStatus: vi.fn(async (_id: string, _pid: string, status: string) =>
      makeMockBatch({ status }),
    ),
    listBatches: vi.fn(async () => ({
      data: [makeMockBatch()],
      pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
    })),
    findNextBatchPreview: vi.fn(async () => [
      { baNumber: '12345', claimCount: 3, totalValue: '300.00' },
    ]),
    findBatchesAwaitingResponse: vi.fn(async () => []),
    findClaimsByBatchId: vi.fn(async () => []),
    findBatchByWeek: vi.fn(async () => null),
    linkClaimsToBatch: vi.fn(async () => 0),
  };
}

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

function createMockBatchCycleDeps(repo: ReturnType<typeof createMockAhcipRepo>) {
  return {
    repo,
    feeRefData: {
      getHscDetail: vi.fn(async () => null),
      getModifierFeeImpact: vi.fn(async () => null),
      getAfterHoursPremium: vi.fn(async () => null),
      getCmgpPremium: vi.fn(async () => null),
      getRrnpPremium: vi.fn(async () => null),
      getEdSurcharge: vi.fn(async () => null),
    },
    feeProviderService: {
      isRrnpEligible: vi.fn(async () => false),
    },
    claimStateService: {
      transitionState: vi.fn(async () => true),
    },
    notificationService: {
      emit: vi.fn(async () => {}),
    },
    hlinkTransmission: {
      transmit: vi.fn(async () => ({ submissionReference: 'REF-001' })),
    },
    fileEncryption: {
      encryptAndStore: vi.fn(async () => ({
        filePath: '/tmp/test.enc',
        fileHash: 'abc123',
      })),
    },
    submissionPreferences: {
      getAutoSubmissionMode: vi.fn(async () => 'REQUIRE_APPROVAL' as const),
    },
    validationRunner: {
      validateClaim: vi.fn(async () => ({ passed: true, errors: [] })),
    },
  };
}

function createMockFeeCalculationDeps(repo: ReturnType<typeof createMockAhcipRepo>) {
  return {
    repo,
    feeRefData: {
      getHscDetail: vi.fn(async () => ({
        code: '03.04A',
        description: 'Office visit',
        baseFee: '38.56',
        feeType: 'FIXED',
        isActive: true,
        effectiveFrom: '2025-01-01',
        effectiveTo: null,
        specialtyRestrictions: [],
        facilityRestrictions: [],
        requiresReferral: false,
        requiresDiagnosticCode: false,
        requiresFacility: false,
        isTimeBased: false,
        minTime: null,
        maxTime: null,
        minCalls: null,
        maxCalls: null,
        maxPerDay: null,
        surchargeEligible: false,
        pcpcmBasket: null,
        afterHoursEligible: false,
        premium351Eligible: false,
        combinationGroup: null,
      })),
      getModifierFeeImpact: vi.fn(async () => null),
      getAfterHoursPremium: vi.fn(async () => null),
      getCmgpPremium: vi.fn(async () => null),
      getRrnpPremium: vi.fn(async () => null),
      getEdSurcharge: vi.fn(async () => null),
    },
    feeProviderService: {
      isRrnpEligible: vi.fn(async () => false),
    },
  };
}

function createMockAssessmentDeps(repo: ReturnType<typeof createMockAhcipRepo>) {
  return {
    repo,
    claimStateService: {
      transitionState: vi.fn(async () => true),
    },
    notificationService: {
      emit: vi.fn(async () => {}),
    },
    hlinkRetrieval: {
      retrieveAssessmentFile: vi.fn(async () => Buffer.from('')),
    },
    explanatoryCodeService: {
      resolveExplanatoryCode: vi.fn(async () => null),
    },
    fileEncryption: {
      encryptAndStore: vi.fn(async () => ({
        filePath: '/tmp/test.enc',
        fileHash: 'abc123',
      })),
    },
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockAhcipRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockAhcipRepo();

  const handlerDeps: AhcipHandlerDeps = {
    batchCycleDeps: createMockBatchCycleDeps(mockRepo) as any,
    feeCalculationDeps: createMockFeeCalculationDeps(mockRepo) as any,
    assessmentDeps: createMockAssessmentDeps(mockRepo) as any,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register auth plugin
  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

  // Error handler
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

  // Register AHCIP routes
  await testApp.register(ahcipRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authedGet(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

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

// ===========================================================================
// Tests
// ===========================================================================

describe('AHCIP Batch Management Integration', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // =========================================================================
  // GET /api/v1/ahcip/batches
  // =========================================================================

  describe('GET /api/v1/ahcip/batches', () => {
    it('lists physician batches with default pagination', async () => {
      const res = await authedGet('/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body).toHaveProperty('data');
      expect(body).toHaveProperty('pagination');
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.pagination).toHaveProperty('total');
      expect(body.pagination).toHaveProperty('page');
      expect(body.pagination).toHaveProperty('pageSize');
      expect(body.pagination).toHaveProperty('hasMore');

      expect(mockRepo.listBatches).toHaveBeenCalledWith(PHYSICIAN1_USER_ID, {
        status: undefined,
        dateFrom: undefined,
        dateTo: undefined,
        page: 1,
        pageSize: 20,
      });
    });

    it('applies status filter', async () => {
      const res = await authedGet('/api/v1/ahcip/batches?status=SUBMITTED');
      expect(res.statusCode).toBe(200);

      expect(mockRepo.listBatches).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        expect.objectContaining({ status: 'SUBMITTED' }),
      );
    });

    it('applies date range filter', async () => {
      const res = await authedGet('/api/v1/ahcip/batches?date_from=2026-01-01&date_to=2026-02-28');
      expect(res.statusCode).toBe(200);

      expect(mockRepo.listBatches).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        expect.objectContaining({
          dateFrom: '2026-01-01',
          dateTo: '2026-02-28',
        }),
      );
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('rejects invalid status filter', async () => {
      const res = await authedGet('/api/v1/ahcip/batches?status=INVALID');
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // GET /api/v1/ahcip/batches/next
  // =========================================================================

  describe('GET /api/v1/ahcip/batches/next', () => {
    it('previews next Thursday batch', async () => {
      const res = await authedGet('/api/v1/ahcip/batches/next');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body).toHaveProperty('data');
      expect(body.data).toHaveProperty('batchWeek');
      expect(body.data).toHaveProperty('groups');
      expect(body.data).toHaveProperty('totalClaims');
      expect(body.data).toHaveProperty('totalValue');
      expect(Array.isArray(body.data.groups)).toBe(true);

      expect(mockRepo.findNextBatchPreview).toHaveBeenCalledWith(PHYSICIAN1_USER_ID);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/ahcip/batches/next');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/ahcip/batches/:id
  // =========================================================================

  describe('GET /api/v1/ahcip/batches/:id', () => {
    it('returns batch details for owning physician', async () => {
      const res = await authedGet(`/api/v1/ahcip/batches/${BATCH_ID_1}`);
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body).toHaveProperty('data');
      expect(body.data.ahcipBatchId).toBe(BATCH_ID_1);

      expect(mockRepo.findBatchById).toHaveBeenCalledWith(BATCH_ID_1, PHYSICIAN1_USER_ID);
    });

    it('returns 404 for different physician', async () => {
      const res = await authedGet(`/api/v1/ahcip/batches/${BATCH_ID_2}`);
      expect(res.statusCode).toBe(404);

      expect(res.json()).toHaveProperty('error');
      expect(res.json().error.code).toBe('NOT_FOUND');
    });

    it('returns 404 for non-existent batch', async () => {
      const res = await authedGet('/api/v1/ahcip/batches/00000000-9999-0000-0000-000000000099');
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for invalid UUID', async () => {
      const res = await authedGet('/api/v1/ahcip/batches/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/ahcip/batches/${BATCH_ID_1}`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/ahcip/batches/:id/retry
  // =========================================================================

  describe('POST /api/v1/ahcip/batches/:id/retry', () => {
    it('retries an ERROR batch', async () => {
      // Override mock to return an ERROR batch
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({ status: AhcipBatchStatus.ERROR }),
      );

      const res = await authedPost(`/api/v1/ahcip/batches/${BATCH_ID_1}/retry`);
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body).toHaveProperty('data');
    });

    it('rejects retry for non-ERROR batch (GENERATED)', async () => {
      // Default mock returns GENERATED status
      const res = await authedPost(`/api/v1/ahcip/batches/${BATCH_ID_1}/retry`);
      expect(res.statusCode).toBe(409);

      const body = res.json();
      expect(body.error.code).toBe('CONFLICT');
    });

    it('rejects retry for non-ERROR batch (SUBMITTED)', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({ status: AhcipBatchStatus.SUBMITTED }),
      );

      const res = await authedPost(`/api/v1/ahcip/batches/${BATCH_ID_1}/retry`);
      expect(res.statusCode).toBe(409);
    });

    it('returns 404 for batch owned by different physician', async () => {
      const res = await authedPost(`/api/v1/ahcip/batches/${BATCH_ID_2}/retry`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/ahcip/batches/${BATCH_ID_1}/retry`);
      expect(res.statusCode).toBe(401);
    });

    it('returns 400 for invalid UUID', async () => {
      const res = await authedPost('/api/v1/ahcip/batches/not-a-uuid/retry');
      expect(res.statusCode).toBe(400);
    });
  });
});
