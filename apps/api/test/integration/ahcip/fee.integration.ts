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

const CLAIM_ID_1 = '00000000-cccc-0000-0000-000000000001';
const CLAIM_ID_2 = '00000000-cccc-0000-0000-000000000002';

const VALID_FEE_CALCULATE_BODY = {
  health_service_code: '03.04A',
  functional_centre: 'ABCDE',
  encounter_type: 'FOLLOW_UP' as const,
  date_of_service: '2026-01-15',
  patient_id: '00000000-aaaa-0000-0000-000000000001',
  calls: 1,
};

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
    findAhcipDetailByClaimId: vi.fn(async (claimId: string, physicianId: string) => {
      if (claimId === CLAIM_ID_1 && physicianId === PHYSICIAN1_USER_ID) {
        return {
          ahcipDetailId: '00000000-dddd-0000-0000-000000000001',
          claimId: CLAIM_ID_1,
          healthServiceCode: '03.04A',
          baNumber: '12345',
          submittedFee: '38.56',
          assessedFee: null,
          assessmentExplanatoryCodes: null,
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
          claim: {
            claimId: CLAIM_ID_1,
            physicianId: PHYSICIAN1_USER_ID,
            patientId: '00000000-aaaa-0000-0000-000000000001',
            claimType: 'AHCIP',
            state: 'VALIDATED',
            dateOfService: '2026-01-15',
            createdAt: new Date(),
            updatedAt: new Date(),
            deletedAt: null,
          },
        };
      }
      return null;
    }),
    updateAhcipDetail: vi.fn(async () => undefined),
    findAhcipClaimWithDetails: vi.fn(async () => null),
    listAhcipClaimsForBatch: vi.fn(async () => []),
    updateAssessmentResult: vi.fn(async () => undefined),
    createAhcipBatch: vi.fn(async () => ({})),
    findBatchById: vi.fn(async () => null),
    updateBatchStatus: vi.fn(async () => undefined),
    listBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    findNextBatchPreview: vi.fn(async () => []),
    findBatchesAwaitingResponse: vi.fn(async () => []),
    findClaimsByBatchId: vi.fn(async () => []),
    findBatchByWeek: vi.fn(async () => null),
    linkClaimsToBatch: vi.fn(async () => 0),
  };
}

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

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

describe('AHCIP Fee Calculation Integration', () => {
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
  // POST /api/v1/ahcip/fee-calculate
  // =========================================================================

  describe('POST /api/v1/ahcip/fee-calculate', () => {
    it('returns fee preview for valid input', async () => {
      const res = await authedPost('/api/v1/ahcip/fee-calculate', VALID_FEE_CALCULATE_BODY);
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body).toHaveProperty('data');
      expect(body.data).toHaveProperty('base_fee');
      expect(body.data).toHaveProperty('calls');
      expect(body.data).toHaveProperty('modifier_adjustments');
      expect(body.data).toHaveProperty('premiums');
      expect(body.data).toHaveProperty('total_fee');
      expect(Array.isArray(body.data.modifier_adjustments)).toBe(true);
      expect(Array.isArray(body.data.premiums)).toBe(true);
    });

    it('returns 400 for missing required fields', async () => {
      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        health_service_code: '03.04A',
        // missing functional_centre, encounter_type, date_of_service, patient_id
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for invalid encounter_type', async () => {
      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE_BODY,
        encounter_type: 'INVALID_TYPE',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for invalid date format', async () => {
      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE_BODY,
        date_of_service: 'not-a-date',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for invalid patient_id UUID', async () => {
      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE_BODY,
        patient_id: 'not-a-uuid',
      });
      expect(res.statusCode).toBe(400);
    });

    it('accepts optional modifiers', async () => {
      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE_BODY,
        modifier_1: 'AFHR',
        modifier_2: 'CMGP',
      });
      expect(res.statusCode).toBe(200);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/ahcip/fee-calculate', VALID_FEE_CALCULATE_BODY);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/ahcip/claims/:id/fee-breakdown
  // =========================================================================

  describe('GET /api/v1/ahcip/claims/:id/fee-breakdown', () => {
    it('returns itemised breakdown for physician claim', async () => {
      const res = await authedGet(`/api/v1/ahcip/claims/${CLAIM_ID_1}/fee-breakdown`);
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body).toHaveProperty('data');
      expect(body.data).toHaveProperty('base_fee');
      expect(body.data).toHaveProperty('calls');
      expect(body.data).toHaveProperty('modifier_adjustments');
      expect(body.data).toHaveProperty('premiums');
      expect(body.data).toHaveProperty('total_fee');
    });

    it('returns 404 for claim owned by different physician', async () => {
      const res = await authedGet(
        `/api/v1/ahcip/claims/${CLAIM_ID_1}/fee-breakdown`,
        PHYSICIAN2_SESSION_TOKEN,
      );
      expect(res.statusCode).toBe(404);
    });

    it('returns 404 for non-existent claim', async () => {
      const res = await authedGet(
        '/api/v1/ahcip/claims/00000000-9999-0000-0000-000000000099/fee-breakdown',
      );
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for invalid UUID', async () => {
      const res = await authedGet('/api/v1/ahcip/claims/not-a-uuid/fee-breakdown');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/ahcip/claims/${CLAIM_ID_1}/fee-breakdown`);
      expect(res.statusCode).toBe(401);
    });
  });
});
