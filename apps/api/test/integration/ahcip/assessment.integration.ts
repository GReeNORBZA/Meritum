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
// Test data
// ---------------------------------------------------------------------------

const BATCH_ID_1 = '00000000-bbbb-0000-0000-000000000001';
const BATCH_ID_2 = '00000000-bbbb-0000-0000-000000000002';
const CLAIM_ID_1 = '00000000-cccc-0000-0000-000000000001';

function makeMockBatch(overrides: Record<string, unknown> = {}) {
  return {
    ahcipBatchId: BATCH_ID_1,
    physicianId: PHYSICIAN1_USER_ID,
    baNumber: '12345',
    batchWeek: '2026-02-19',
    status: AhcipBatchStatus.RESPONSE_RECEIVED,
    claimCount: 5,
    totalSubmittedValue: '500.00',
    filePath: '/tmp/batch.enc',
    fileHash: 'abc123',
    submissionReference: 'REF-001',
    submittedAt: new Date(),
    responseReceivedAt: new Date(),
    createdAt: new Date(),
    createdBy: PHYSICIAN1_USER_ID,
    ...overrides,
  };
}

function makeMockClaimForBatch(overrides: Record<string, unknown> = {}) {
  return {
    claim: {
      claimId: CLAIM_ID_1,
      physicianId: PHYSICIAN1_USER_ID,
      patientId: '00000000-aaaa-0000-0000-000000000001',
      claimType: 'AHCIP',
      state: 'ASSESSED',
      dateOfService: '2026-01-15',
      submittedBatchId: BATCH_ID_1,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      ...((overrides.claim as any) ?? {}),
    },
    detail: {
      ahcipDetailId: '00000000-dddd-0000-0000-000000000001',
      claimId: CLAIM_ID_1,
      healthServiceCode: '03.04A',
      baNumber: '12345',
      submittedFee: '38.56',
      assessedFee: '38.56',
      assessmentExplanatoryCodes: [],
      modifier1: null,
      modifier2: null,
      modifier3: null,
      diagnosticCode: null,
      encounterType: 'FOLLOW_UP',
      calls: 1,
      timeSpent: null,
      shadowBillingFlag: false,
      pcpcmBasketFlag: false,
      afterHoursFlag: false,
      afterHoursType: null,
      ...((overrides.detail as any) ?? {}),
    },
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
      return null;
    }),
    updateBatchStatus: vi.fn(async () => makeMockBatch()),
    listBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    findNextBatchPreview: vi.fn(async () => []),
    findBatchesAwaitingResponse: vi.fn(async (physicianId: string) => {
      if (physicianId === PHYSICIAN1_USER_ID) {
        return [makeMockBatch({ status: AhcipBatchStatus.SUBMITTED })];
      }
      return [];
    }),
    findClaimsByBatchId: vi.fn(async (batchId: string, physicianId: string) => {
      if (batchId === BATCH_ID_1 && physicianId === PHYSICIAN1_USER_ID) {
        return [makeMockClaimForBatch()];
      }
      return [];
    }),
    findBatchByWeek: vi.fn(async () => null),
    linkClaimsToBatch: vi.fn(async () => 0),
  };
}

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

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

  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
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

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

// ===========================================================================
// Tests
// ===========================================================================

describe('AHCIP Assessment Integration', () => {
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
  // GET /api/v1/ahcip/assessments/:batch_id
  // =========================================================================

  describe('GET /api/v1/ahcip/assessments/:batch_id', () => {
    it('returns assessment results for physician batch', async () => {
      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body).toHaveProperty('data');
      expect(body.data).toHaveProperty('batchId', BATCH_ID_1);
      expect(body.data).toHaveProperty('batchStatus');
      expect(body.data).toHaveProperty('totalClaims');
      expect(body.data).toHaveProperty('accepted');
      expect(body.data).toHaveProperty('rejected');
      expect(body.data).toHaveProperty('adjusted');
      expect(body.data).toHaveProperty('claims');
      expect(Array.isArray(body.data.claims)).toBe(true);
    });

    it('returns 404 for batch owned by different physician', async () => {
      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_2}`);
      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
    });

    it('returns 400 for invalid UUID', async () => {
      const res = await authedGet('/api/v1/ahcip/assessments/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);
      expect(res.statusCode).toBe(401);
    });

    it('returns claim-level assessment details', async () => {
      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data.claims.length).toBeGreaterThan(0);
      const claim = body.data.claims[0];
      expect(claim).toHaveProperty('claimId');
      expect(claim).toHaveProperty('healthServiceCode');
      expect(claim).toHaveProperty('dateOfService');
      expect(claim).toHaveProperty('submittedFee');
      expect(claim).toHaveProperty('assessedFee');
      expect(claim).toHaveProperty('state');
    });
  });

  // =========================================================================
  // GET /api/v1/ahcip/assessments/pending
  // =========================================================================

  describe('GET /api/v1/ahcip/assessments/pending', () => {
    it('returns SUBMITTED batches awaiting assessment', async () => {
      const res = await authedGet('/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body).toHaveProperty('data');
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);

      const pending = body.data[0];
      expect(pending).toHaveProperty('batchId');
      expect(pending).toHaveProperty('baNumber');
      expect(pending).toHaveProperty('batchWeek');
      expect(pending).toHaveProperty('claimCount');
      expect(pending).toHaveProperty('totalSubmittedValue');
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(401);
    });

    it('scopes results to authenticated physician', async () => {
      const res = await authedGet('/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(200);

      expect(mockRepo.findBatchesAwaitingResponse).toHaveBeenCalledWith(PHYSICIAN1_USER_ID);
    });
  });
});
