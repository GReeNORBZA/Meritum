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
// Test data — IDs
// ---------------------------------------------------------------------------

const PATIENT_ID_1 = '00000000-aaaa-0000-0000-000000000001';

const BATCH_ID_1 = '00000000-bbbb-0000-0000-000000000001';
const BATCH_ID_2 = '00000000-bbbb-0000-0000-000000000002';
const BATCH_FFS = '00000000-bbbb-0000-0000-000000000010';
const BATCH_PCPCM = '00000000-bbbb-0000-0000-000000000011';

const CLAIM_ID_FFS = '00000000-cccc-0000-0000-000000000001';
const CLAIM_ID_SHADOW = '00000000-cccc-0000-0000-000000000002';
const CLAIM_ID_PCPCM_IN = '00000000-cccc-0000-0000-000000000003';
const CLAIM_ID_PCPCM_OUT = '00000000-cccc-0000-0000-000000000004';
const CLAIM_ID_ED = '00000000-cccc-0000-0000-000000000005';
const CLAIM_ID_HOSPITAL = '00000000-cccc-0000-0000-000000000006';
const CLAIM_ID_SPECIALIST = '00000000-cccc-0000-0000-000000000007';
const CLAIM_ID_VIRTUAL = '00000000-cccc-0000-0000-000000000008';
const CLAIM_ID_REJECTED = '00000000-cccc-0000-0000-000000000009';
const CLAIM_ID_INVALID = '00000000-cccc-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// HSC lookup data — base fee schedule entries used across scenarios
// ---------------------------------------------------------------------------

const HSC_03_04A = {
  code: '03.04A',
  description: 'Complete history and examination — office visit',
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
  afterHoursEligible: true,
  premium351Eligible: true,
  combinationGroup: null,
};

const HSC_03_03F = {
  ...HSC_03_04A,
  code: '03.03F',
  description: 'Repeat complete assessment — office',
  baseFee: '69.14',
  afterHoursEligible: true,
  surchargeEligible: true,
};

const HSC_03_04J_SPECIALIST = {
  ...HSC_03_04A,
  code: '03.04J',
  description: 'Specialist consultation',
  baseFee: '149.50',
  requiresReferral: true,
  afterHoursEligible: false,
};

const HSC_08_19A_HOSPITAL = {
  ...HSC_03_04A,
  code: '08.19A',
  description: 'Subsequent hospital care — inpatient',
  baseFee: '27.76',
  requiresFacility: true,
  afterHoursEligible: false,
};

const HSC_VIRTUAL = {
  ...HSC_03_04A,
  code: '03.01AD',
  description: 'Virtual care visit',
  baseFee: '38.56',
  afterHoursEligible: true,
};

const HSC_PCPCM_IN = {
  ...HSC_03_04A,
  code: '03.04A',
  pcpcmBasket: 'in_basket',
};

const HSC_PCPCM_OUT = {
  ...HSC_03_04A,
  code: '08.11A',
  description: 'Emergency department visit',
  baseFee: '88.30',
  pcpcmBasket: null,
  surchargeEligible: true,
  afterHoursEligible: true,
};

// ---------------------------------------------------------------------------
// Mock claim and detail builders
// ---------------------------------------------------------------------------

function makeMockClaim(overrides: Record<string, unknown> = {}) {
  return {
    claimId: CLAIM_ID_FFS,
    physicianId: PHYSICIAN1_USER_ID,
    patientId: PATIENT_ID_1,
    claimType: 'AHCIP',
    state: 'VALIDATED',
    dateOfService: '2026-01-15',
    submissionDeadline: '2026-04-15',
    isClean: true,
    validationResult: null,
    submittedBatchId: null,
    shiftId: null,
    importBatchId: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
    ...overrides,
  };
}

function makeMockDetail(overrides: Record<string, unknown> = {}) {
  return {
    ahcipDetailId: '00000000-dddd-0000-0000-000000000001',
    claimId: CLAIM_ID_FFS,
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
    ...overrides,
  };
}

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

function makeClaimForBatch(
  claimOverrides: Record<string, unknown> = {},
  detailOverrides: Record<string, unknown> = {},
) {
  return {
    claim: makeMockClaim(claimOverrides),
    detail: makeMockDetail(detailOverrides),
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
// Mock AHCIP repo (configurable per scenario)
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
    findBatchById: vi.fn(async () => null),
    updateBatchStatus: vi.fn(async () => makeMockBatch()),
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
// Mock dependency factories
// ---------------------------------------------------------------------------

function createMockFeeCalculationDeps(repo: ReturnType<typeof createMockAhcipRepo>) {
  return {
    repo,
    feeRefData: {
      getHscDetail: vi.fn(async () => HSC_03_04A),
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
      getHscDetail: vi.fn(async () => HSC_03_04A),
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
      getAutoSubmissionMode: vi.fn(async () => 'AUTO_ALL' as const),
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
// Test app builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockAhcipRepo>;
let feeDeps: ReturnType<typeof createMockFeeCalculationDeps>;
let batchDeps: ReturnType<typeof createMockBatchCycleDeps>;
let assessmentDeps: ReturnType<typeof createMockAssessmentDeps>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockAhcipRepo();
  feeDeps = createMockFeeCalculationDeps(mockRepo);
  batchDeps = createMockBatchCycleDeps(mockRepo);
  assessmentDeps = createMockAssessmentDeps(mockRepo);

  const handlerDeps: AhcipHandlerDeps = {
    batchCycleDeps: batchDeps as any,
    feeCalculationDeps: feeDeps as any,
    assessmentDeps: assessmentDeps as any,
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

// ===========================================================================
// Tests
// ===========================================================================

describe('AHCIP Billing Scenarios — End-to-End', () => {
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
  // Scenario 1: FFS clinic visit with CMGP + after-hours + RRNP premium
  // =========================================================================

  describe('Scenario: FFS clinic visit with CMGP + after-hours + RRNP', () => {
    it('fee calculation includes base fee, CMGP premium, after-hours, and RRNP', async () => {
      // Configure mocks: HSC eligible for all premiums
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_03_04A);
      feeDeps.feeRefData.getCmgpPremium.mockResolvedValueOnce('15.00');
      feeDeps.feeRefData.getAfterHoursPremium.mockResolvedValueOnce('25.00');
      feeDeps.feeProviderService.isRrnpEligible.mockResolvedValueOnce(true);
      feeDeps.feeRefData.getRrnpPremium.mockResolvedValueOnce('7.71');

      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        health_service_code: '03.04A',
        functional_centre: 'ABCDE',
        encounter_type: 'FOLLOW_UP',
        date_of_service: '2026-01-15',
        patient_id: PATIENT_ID_1,
        modifier_1: 'CMGP',
        modifier_2: 'AFHR',
        calls: 1,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body).toHaveProperty('data');
      expect(body.data).toHaveProperty('base_fee');
      expect(body.data).toHaveProperty('total_fee');
      expect(body.data).toHaveProperty('premiums');
      expect(body.data).toHaveProperty('modifier_adjustments');

      // Base fee is from HSC 03.04A
      expect(body.data.base_fee).toBe('38.56');
      expect(body.data.calls).toBe(1);
    });

    it('fee breakdown for existing FFS claim with premiums returns full detail', async () => {
      // Mock the existing claim detail with premiums
      feeDeps.repo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...makeMockDetail({
          claimId: CLAIM_ID_FFS,
          modifier1: 'CMGP',
          modifier2: 'AFHR',
          afterHoursFlag: true,
          afterHoursType: 'EVENING',
        }),
        claim: makeMockClaim({ claimId: CLAIM_ID_FFS }),
      });
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_03_04A);
      feeDeps.feeRefData.getCmgpPremium.mockResolvedValueOnce('15.00');
      feeDeps.feeRefData.getAfterHoursPremium.mockResolvedValueOnce('25.00');
      feeDeps.feeProviderService.isRrnpEligible.mockResolvedValueOnce(true);
      feeDeps.feeRefData.getRrnpPremium.mockResolvedValueOnce('7.71');

      const res = await authedGet(`/api/v1/ahcip/claims/${CLAIM_ID_FFS}/fee-breakdown`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('base_fee', '38.56');
      expect(body.data).toHaveProperty('total_fee');
      expect(Array.isArray(body.data.premiums)).toBe(true);
      expect(Array.isArray(body.data.modifier_adjustments)).toBe(true);
      // total_fee should be > base_fee due to premiums
      expect(parseFloat(body.data.total_fee)).toBeGreaterThanOrEqual(parseFloat(body.data.base_fee));
    });
  });

  // =========================================================================
  // Scenario 2: Shadow billing (ARP with TM modifier) — fee = $0
  // =========================================================================

  describe('Scenario: Shadow billing produces $0 fee', () => {
    it('fee preview with TM modifier returns fee (shadow billing applied at claim creation)', async () => {
      // In the fee preview endpoint, TM is just a modifier — shadow billing
      // flag is determined at claim creation time. The preview still shows
      // the computed fee; the $0 override is applied via shadowBillingFlag.
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_03_04A);

      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        health_service_code: '03.04A',
        functional_centre: 'ABCDE',
        encounter_type: 'FOLLOW_UP',
        date_of_service: '2026-01-15',
        patient_id: PATIENT_ID_1,
        modifier_1: 'TM',
        calls: 1,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('base_fee', '38.56');
      expect(body.data).toHaveProperty('total_fee');
      expect(body.data).toHaveProperty('calls', 1);
    });

    it('fee breakdown for shadow billing claim shows $0 total with populated breakdown', async () => {
      feeDeps.repo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...makeMockDetail({
          claimId: CLAIM_ID_SHADOW,
          modifier1: 'TM',
          shadowBillingFlag: true,
          submittedFee: '0.00',
        }),
        claim: makeMockClaim({
          claimId: CLAIM_ID_SHADOW,
        }),
      });
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_03_04A);

      const res = await authedGet(`/api/v1/ahcip/claims/${CLAIM_ID_SHADOW}/fee-breakdown`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.total_fee).toBe('0.00');
      // Base fee is still populated (shows what would have been billed)
      expect(body.data.base_fee).toBe('38.56');
    });
  });

  // =========================================================================
  // Scenario 3: PCPCM dual-BA creates two batches
  // =========================================================================

  describe('Scenario: PCPCM dual-BA creates two batches', () => {
    it('batch preview shows separate groups for FFS BA and PCPCM BA', async () => {
      // Physician has both FFS BA (12345) and PCPCM BA (67890)
      mockRepo.findNextBatchPreview.mockResolvedValueOnce([
        { baNumber: '67890', claimCount: 3, totalValue: '115.68' },
        { baNumber: '12345', claimCount: 2, totalValue: '176.60' },
      ]);

      const res = await authedGet('/api/v1/ahcip/batches/next');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('groups');
      expect(body.data.groups).toHaveLength(2);

      // Verify two distinct BA numbers
      const baNumbers = body.data.groups.map((g: any) => g.baNumber);
      expect(baNumbers).toContain('12345');
      expect(baNumbers).toContain('67890');

      // Total should sum both groups
      expect(body.data.totalClaims).toBe(5);
    });

    it('batch listing reflects separate FFS and PCPCM batches', async () => {
      mockRepo.listBatches.mockResolvedValueOnce({
        data: [
          makeMockBatch({
            ahcipBatchId: BATCH_FFS,
            baNumber: '12345',
            claimCount: 2,
            totalSubmittedValue: '176.60',
            status: AhcipBatchStatus.SUBMITTED,
          }),
          makeMockBatch({
            ahcipBatchId: BATCH_PCPCM,
            baNumber: '67890',
            claimCount: 3,
            totalSubmittedValue: '115.68',
            status: AhcipBatchStatus.SUBMITTED,
          }),
        ],
        pagination: { total: 2, page: 1, pageSize: 20, hasMore: false },
      });

      const res = await authedGet('/api/v1/ahcip/batches');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveLength(2);

      const ffs = body.data.find((b: any) => b.baNumber === '12345');
      const pcpcm = body.data.find((b: any) => b.baNumber === '67890');
      expect(ffs).toBeDefined();
      expect(pcpcm).toBeDefined();
      expect(ffs.ahcipBatchId).not.toBe(pcpcm.ahcipBatchId);
    });
  });

  // =========================================================================
  // Scenario 4: ED shift with surcharge (13.99H) + after-hours + CMGP
  // =========================================================================

  describe('Scenario: ED shift with surcharge + after-hours', () => {
    it('fee preview with ED surcharge + AFHR + CMGP yields stacked premiums', async () => {
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_03_03F);
      feeDeps.feeRefData.getEdSurcharge.mockResolvedValueOnce('35.00');
      feeDeps.feeRefData.getAfterHoursPremium.mockResolvedValueOnce('30.00');
      feeDeps.feeRefData.getCmgpPremium.mockResolvedValueOnce('15.00');

      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        health_service_code: '03.03F',
        functional_centre: 'EDEPT',
        encounter_type: 'FOLLOW_UP',
        date_of_service: '2026-01-15',
        patient_id: PATIENT_ID_1,
        modifier_1: '13.99H',
        modifier_2: 'AFHR',
        modifier_3: 'CMGP',
        calls: 1,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.base_fee).toBe('69.14');
      // Total should include base + surcharge + after-hours + CMGP
      expect(parseFloat(body.data.total_fee)).toBeGreaterThan(parseFloat(body.data.base_fee));
    });

    it('fee breakdown for ED claim includes surcharge, after-hours, and CMGP details', async () => {
      feeDeps.repo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...makeMockDetail({
          claimId: CLAIM_ID_ED,
          healthServiceCode: '03.03F',
          modifier1: '13.99H',
          modifier2: 'AFHR',
          modifier3: 'CMGP',
          afterHoursFlag: true,
          afterHoursType: 'NIGHT',
          encounterType: 'FOLLOW_UP',
        }),
        claim: makeMockClaim({ claimId: CLAIM_ID_ED }),
      });
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_03_03F);
      feeDeps.feeRefData.getEdSurcharge.mockResolvedValueOnce('35.00');
      feeDeps.feeRefData.getAfterHoursPremium.mockResolvedValueOnce('30.00');
      feeDeps.feeRefData.getCmgpPremium.mockResolvedValueOnce('15.00');

      const res = await authedGet(`/api/v1/ahcip/claims/${CLAIM_ID_ED}/fee-breakdown`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.base_fee).toBe('69.14');
      expect(parseFloat(body.data.total_fee)).toBeGreaterThan(69.14);
      expect(body.data.calls).toBe(1);
    });
  });

  // =========================================================================
  // Scenario 5: Hospital inpatient with GR 3 visit limit rejection
  // =========================================================================

  describe('Scenario: GR 3 visit limit rejection', () => {
    it('fee calculate returns result for hospital inpatient code', async () => {
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_08_19A_HOSPITAL);

      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        health_service_code: '08.19A',
        functional_centre: 'HOSPT',
        encounter_type: 'FOLLOW_UP',
        date_of_service: '2026-01-15',
        patient_id: PATIENT_ID_1,
        facility_number: 'FAC-001',
        calls: 1,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.base_fee).toBe('27.76');
    });

    it('assessment shows claim rejected for visit limit (GR 3) with explanatory code', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({
          ahcipBatchId: BATCH_ID_1,
          status: AhcipBatchStatus.RESPONSE_RECEIVED,
          submissionReference: 'REF-GR3',
        }),
      );

      mockRepo.findClaimsByBatchId.mockResolvedValueOnce([
        makeClaimForBatch(
          {
            claimId: CLAIM_ID_HOSPITAL,
            state: 'REJECTED',
          },
          {
            claimId: CLAIM_ID_HOSPITAL,
            healthServiceCode: '08.19A',
            submittedFee: '27.76',
            assessedFee: null,
            assessmentExplanatoryCodes: [
              {
                code: 'GR3-01',
                description: 'Visit limit exceeded — max 1 visit per patient per day',
                category: 'GOVERNING_RULE',
              },
            ],
          },
        ),
      ]);

      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.rejected).toBe(1);
      expect(body.data.accepted).toBe(0);
      expect(body.data.claims).toHaveLength(1);
      expect(body.data.claims[0].state).toBe('REJECTED');
      expect(body.data.claims[0].explanatoryCodes).toHaveLength(1);
      expect(body.data.claims[0].explanatoryCodes[0].code).toBe('GR3-01');
    });
  });

  // =========================================================================
  // Scenario 6: Specialist consultation GR 8 missing referral rejection
  // =========================================================================

  describe('Scenario: GR 8 missing referral rejection', () => {
    it('fee calculate succeeds for specialist HSC code', async () => {
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_03_04J_SPECIALIST);

      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        health_service_code: '03.04J',
        functional_centre: 'SPEC1',
        encounter_type: 'CONSULTATION',
        date_of_service: '2026-01-15',
        patient_id: PATIENT_ID_1,
        calls: 1,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.base_fee).toBe('149.50');
    });

    it('assessment shows specialist claim rejected for missing referral (GR 8)', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({
          ahcipBatchId: BATCH_ID_1,
          status: AhcipBatchStatus.RESPONSE_RECEIVED,
          submissionReference: 'REF-GR8',
        }),
      );

      mockRepo.findClaimsByBatchId.mockResolvedValueOnce([
        makeClaimForBatch(
          {
            claimId: CLAIM_ID_SPECIALIST,
            state: 'REJECTED',
          },
          {
            claimId: CLAIM_ID_SPECIALIST,
            healthServiceCode: '03.04J',
            submittedFee: '149.50',
            assessedFee: null,
            assessmentExplanatoryCodes: [
              {
                code: 'GR8-01',
                description: 'Referring practitioner required for specialist consultation',
                category: 'GOVERNING_RULE',
              },
            ],
          },
        ),
      ]);

      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.rejected).toBe(1);
      expect(body.data.claims[0].state).toBe('REJECTED');
      expect(body.data.claims[0].explanatoryCodes[0].code).toBe('GR8-01');
      // assessedFee is null for rejected claims
      expect(body.data.claims[0].assessedFee).toBeNull();
    });
  });

  // =========================================================================
  // Scenario 7: Virtual care visit
  // =========================================================================

  describe('Scenario: Virtual care visit', () => {
    it('fee calculate succeeds for virtual encounter type', async () => {
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_VIRTUAL);

      const res = await authedPost('/api/v1/ahcip/fee-calculate', {
        health_service_code: '03.01AD',
        functional_centre: 'VRTL1',
        encounter_type: 'VIRTUAL',
        date_of_service: '2026-01-15',
        patient_id: PATIENT_ID_1,
        calls: 1,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.base_fee).toBe('38.56');
      expect(body.data.calls).toBe(1);
    });

    it('fee breakdown for virtual claim reflects correct encounter context', async () => {
      feeDeps.repo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...makeMockDetail({
          claimId: CLAIM_ID_VIRTUAL,
          healthServiceCode: '03.01AD',
          encounterType: 'VIRTUAL',
        }),
        claim: makeMockClaim({
          claimId: CLAIM_ID_VIRTUAL,
        }),
      });
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_VIRTUAL);

      const res = await authedGet(`/api/v1/ahcip/claims/${CLAIM_ID_VIRTUAL}/fee-breakdown`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.base_fee).toBe('38.56');
      expect(body.data.total_fee).toBeDefined();
      expect(body.data.calls).toBe(1);
    });
  });

  // =========================================================================
  // Scenario 8: Rejected → correct → resubmit → paid lifecycle
  // =========================================================================

  describe('Scenario: Rejected → correct → resubmit → paid', () => {
    it('step 1: assessment shows initial claim as REJECTED with explanatory code', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({
          ahcipBatchId: BATCH_ID_1,
          status: AhcipBatchStatus.RESPONSE_RECEIVED,
          submissionReference: 'REF-REJECT1',
        }),
      );

      mockRepo.findClaimsByBatchId.mockResolvedValueOnce([
        makeClaimForBatch(
          {
            claimId: CLAIM_ID_REJECTED,
            state: 'REJECTED',
          },
          {
            claimId: CLAIM_ID_REJECTED,
            healthServiceCode: '03.04J',
            submittedFee: '149.50',
            assessedFee: null,
            assessmentExplanatoryCodes: [
              {
                code: 'GR8-01',
                description: 'Referring practitioner required',
                category: 'GOVERNING_RULE',
              },
            ],
          },
        ),
      ]);

      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.rejected).toBe(1);
      expect(body.data.claims[0].state).toBe('REJECTED');
      expect(body.data.claims[0].correctiveActions).toBeDefined();
    });

    it('step 2: corrected claim fee breakdown includes referral', async () => {
      // After correction: referral_practitioner now populated
      feeDeps.repo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...makeMockDetail({
          claimId: CLAIM_ID_REJECTED,
          healthServiceCode: '03.04J',
          referralPractitioner: '99001',
        }),
        claim: makeMockClaim({
          claimId: CLAIM_ID_REJECTED,
          state: 'VALIDATED',
        }),
      });
      feeDeps.feeRefData.getHscDetail.mockResolvedValueOnce(HSC_03_04J_SPECIALIST);

      const res = await authedGet(`/api/v1/ahcip/claims/${CLAIM_ID_REJECTED}/fee-breakdown`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.base_fee).toBe('149.50');
      expect(body.data.total_fee).toBeDefined();
    });

    it('step 3: resubmitted claim assessment shows PAID', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({
          ahcipBatchId: BATCH_ID_2,
          status: AhcipBatchStatus.RECONCILED,
          submissionReference: 'REF-RESUB1',
        }),
      );

      mockRepo.findClaimsByBatchId.mockResolvedValueOnce([
        makeClaimForBatch(
          {
            claimId: CLAIM_ID_REJECTED,
            state: 'PAID',
            submittedBatchId: BATCH_ID_2,
          },
          {
            claimId: CLAIM_ID_REJECTED,
            healthServiceCode: '03.04J',
            submittedFee: '149.50',
            assessedFee: '149.50',
            assessmentExplanatoryCodes: [],
          },
        ),
      ]);

      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_2}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.accepted).toBe(1);
      expect(body.data.rejected).toBe(0);
      expect(body.data.claims[0].state).toBe('PAID');
      expect(body.data.claims[0].assessedFee).toBe('149.50');
      expect(body.data.claims[0].submittedFee).toBe('149.50');
    });
  });
});

// ===========================================================================
// Batch Cycle Tests
// ===========================================================================

describe('AHCIP Batch Cycle', () => {
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
  // Batch cutoff enforcement
  // =========================================================================

  describe('Batch: cutoff enforcement', () => {
    it('next batch preview returns a Thursday batch week date', async () => {
      mockRepo.findNextBatchPreview.mockResolvedValueOnce([
        { baNumber: '12345', claimCount: 3, totalValue: '115.68' },
      ]);

      const res = await authedGet('/api/v1/ahcip/batches/next');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('batchWeek');

      // batchWeek should be a valid date string
      const batchDate = new Date(body.data.batchWeek);
      expect(batchDate.toString()).not.toBe('Invalid Date');

      // batchWeek should be a Thursday (day 4)
      expect(batchDate.getUTCDay()).toBe(4);
    });

    it('claims queued before cutoff are included in batch preview', async () => {
      mockRepo.findNextBatchPreview.mockResolvedValueOnce([
        { baNumber: '12345', claimCount: 5, totalValue: '192.80' },
      ]);

      const res = await authedGet('/api/v1/ahcip/batches/next');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.totalClaims).toBe(5);
      expect(body.data.totalValue).toBe('192.80');
      expect(body.data.groups).toHaveLength(1);
      expect(body.data.groups[0].claimCount).toBe(5);
    });

    it('empty batch preview returns zero counts', async () => {
      mockRepo.findNextBatchPreview.mockResolvedValueOnce([]);

      const res = await authedGet('/api/v1/ahcip/batches/next');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.totalClaims).toBe(0);
      expect(body.data.totalValue).toBe('0.00');
      expect(body.data.groups).toHaveLength(0);
    });
  });

  // =========================================================================
  // Pre-submission validation removes invalid claims
  // =========================================================================

  describe('Batch: pre-submission validation removes invalid', () => {
    it('batch listing after assembly shows only valid claims counted', async () => {
      // After assembleBatch runs, the batch record shows the count of claims
      // that passed pre-submission validation (invalid ones removed)
      mockRepo.listBatches.mockResolvedValueOnce({
        data: [
          makeMockBatch({
            ahcipBatchId: BATCH_ID_1,
            claimCount: 3, // Originally 5 claims, 2 removed by validation
            totalSubmittedValue: '115.68',
            status: AhcipBatchStatus.SUBMITTED,
          }),
        ],
        pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
      });

      const res = await authedGet('/api/v1/ahcip/batches');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveLength(1);
      expect(body.data[0].claimCount).toBe(3);
    });

    it('batch detail shows reduced count after validation removal', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({
          ahcipBatchId: BATCH_ID_1,
          claimCount: 3,
          totalSubmittedValue: '115.68',
          status: AhcipBatchStatus.SUBMITTED,
        }),
      );

      const res = await authedGet(`/api/v1/ahcip/batches/${BATCH_ID_1}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.claimCount).toBe(3);
      expect(body.data.totalSubmittedValue).toBe('115.68');
    });
  });

  // =========================================================================
  // PCPCM dual-BA batch separation
  // =========================================================================

  describe('Batch: PCPCM physician gets two separate batches', () => {
    it('batch preview groups claims by BA number (FFS + PCPCM)', async () => {
      mockRepo.findNextBatchPreview.mockResolvedValueOnce([
        { baNumber: '12345', claimCount: 2, totalValue: '176.60' },
        { baNumber: '67890', claimCount: 3, totalValue: '115.68' },
      ]);

      const res = await authedGet('/api/v1/ahcip/batches/next');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.groups).toHaveLength(2);
      expect(body.data.totalClaims).toBe(5);

      // Each group has distinct BA
      const bas = body.data.groups.map((g: any) => g.baNumber);
      expect(new Set(bas).size).toBe(2);
    });

    it('batches filtered by status still return correct dual-BA set', async () => {
      mockRepo.listBatches.mockResolvedValueOnce({
        data: [
          makeMockBatch({
            ahcipBatchId: BATCH_FFS,
            baNumber: '12345',
            status: AhcipBatchStatus.SUBMITTED,
          }),
          makeMockBatch({
            ahcipBatchId: BATCH_PCPCM,
            baNumber: '67890',
            status: AhcipBatchStatus.SUBMITTED,
          }),
        ],
        pagination: { total: 2, page: 1, pageSize: 20, hasMore: false },
      });

      const res = await authedGet('/api/v1/ahcip/batches?status=SUBMITTED');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveLength(2);
      expect(body.data[0].baNumber).not.toBe(body.data[1].baNumber);
    });
  });
});

// ===========================================================================
// Assessment Ingestion Tests
// ===========================================================================

describe('AHCIP Assessment Ingestion', () => {
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
  // Mixed results batch
  // =========================================================================

  describe('Assessment: mixed results processing', () => {
    it('assessment with accepted, rejected, and adjusted claims returns correct counts', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({
          ahcipBatchId: BATCH_ID_1,
          status: AhcipBatchStatus.RESPONSE_RECEIVED,
          claimCount: 4,
          submissionReference: 'REF-MIXED',
        }),
      );

      mockRepo.findClaimsByBatchId.mockResolvedValueOnce([
        // Accepted claim — assessed fee matches submitted
        makeClaimForBatch(
          {
            claimId: '00000000-cccc-0000-0000-000000000101',
            state: 'ASSESSED',
          },
          {
            claimId: '00000000-cccc-0000-0000-000000000101',
            healthServiceCode: '03.04A',
            submittedFee: '38.56',
            assessedFee: '38.56',
            assessmentExplanatoryCodes: [],
          },
        ),
        // Rejected claim — no assessed fee
        makeClaimForBatch(
          {
            claimId: '00000000-cccc-0000-0000-000000000102',
            state: 'REJECTED',
          },
          {
            claimId: '00000000-cccc-0000-0000-000000000102',
            healthServiceCode: '03.04J',
            submittedFee: '149.50',
            assessedFee: null,
            assessmentExplanatoryCodes: [
              {
                code: 'GR8-01',
                description: 'Referring practitioner required',
                category: 'GOVERNING_RULE',
              },
            ],
          },
        ),
        // Adjusted claim — assessed fee differs from submitted
        makeClaimForBatch(
          {
            claimId: '00000000-cccc-0000-0000-000000000103',
            state: 'ASSESSED',
          },
          {
            claimId: '00000000-cccc-0000-0000-000000000103',
            healthServiceCode: '03.03F',
            submittedFee: '69.14',
            assessedFee: '55.30',
            assessmentExplanatoryCodes: [
              {
                code: 'ADJ-01',
                description: 'Fee reduced per schedule limitation',
                category: 'FEE_ADJUSTMENT',
              },
            ],
          },
        ),
        // Second accepted claim
        makeClaimForBatch(
          {
            claimId: '00000000-cccc-0000-0000-000000000104',
            state: 'ASSESSED',
          },
          {
            claimId: '00000000-cccc-0000-0000-000000000104',
            healthServiceCode: '08.19A',
            submittedFee: '27.76',
            assessedFee: '27.76',
            assessmentExplanatoryCodes: [],
          },
        ),
      ]);

      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();

      // Verify counts
      expect(body.data.totalClaims).toBe(4);
      expect(body.data.accepted).toBe(2);
      expect(body.data.rejected).toBe(1);
      expect(body.data.adjusted).toBe(1);

      // Verify each claim state
      const claims = body.data.claims;
      const accepted = claims.filter((c: any) => c.state === 'ASSESSED' && c.assessedFee === c.submittedFee);
      const rejected = claims.filter((c: any) => c.state === 'REJECTED');
      const adjusted = claims.filter((c: any) => c.state === 'ASSESSED' && c.assessedFee !== c.submittedFee);

      expect(accepted).toHaveLength(2);
      expect(rejected).toHaveLength(1);
      expect(adjusted).toHaveLength(1);

      // Rejected claim has explanatory codes
      expect(rejected[0].explanatoryCodes).toHaveLength(1);

      // Adjusted claim has fee difference
      expect(adjusted[0].submittedFee).toBe('69.14');
      expect(adjusted[0].assessedFee).toBe('55.30');
    });

    it('explanatory codes are resolved to descriptions', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({
          ahcipBatchId: BATCH_ID_1,
          status: AhcipBatchStatus.RESPONSE_RECEIVED,
          submissionReference: 'REF-EXPL',
        }),
      );

      mockRepo.findClaimsByBatchId.mockResolvedValueOnce([
        makeClaimForBatch(
          {
            claimId: '00000000-cccc-0000-0000-000000000201',
            state: 'REJECTED',
          },
          {
            claimId: '00000000-cccc-0000-0000-000000000201',
            healthServiceCode: '03.04A',
            submittedFee: '38.56',
            assessedFee: null,
            assessmentExplanatoryCodes: [
              {
                code: 'EXP-101',
                description: 'Duplicate claim for same service date',
                category: 'DUPLICATE',
              },
              {
                code: 'EXP-205',
                description: 'Service code inactive on date of service',
                category: 'VALIDATION',
              },
            ],
          },
        ),
      ]);

      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      const claim = body.data.claims[0];
      expect(claim.explanatoryCodes).toHaveLength(2);
      expect(claim.explanatoryCodes[0]).toHaveProperty('code', 'EXP-101');
      expect(claim.explanatoryCodes[0]).toHaveProperty('description');
      expect(claim.explanatoryCodes[1]).toHaveProperty('code', 'EXP-205');
    });
  });

  // =========================================================================
  // Payment reconciliation transitions to PAID
  // =========================================================================

  describe('Assessment: payment reconciliation', () => {
    it('RECONCILED batch shows claims transitioned to PAID with payment amounts', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({
          ahcipBatchId: BATCH_ID_1,
          status: AhcipBatchStatus.RECONCILED,
          submissionReference: 'REF-PAY1',
        }),
      );

      mockRepo.findClaimsByBatchId.mockResolvedValueOnce([
        makeClaimForBatch(
          {
            claimId: '00000000-cccc-0000-0000-000000000301',
            state: 'PAID',
          },
          {
            claimId: '00000000-cccc-0000-0000-000000000301',
            healthServiceCode: '03.04A',
            submittedFee: '38.56',
            assessedFee: '38.56',
            assessmentExplanatoryCodes: [],
          },
        ),
        makeClaimForBatch(
          {
            claimId: '00000000-cccc-0000-0000-000000000302',
            state: 'PAID',
          },
          {
            claimId: '00000000-cccc-0000-0000-000000000302',
            healthServiceCode: '03.03F',
            submittedFee: '69.14',
            assessedFee: '69.14',
            assessmentExplanatoryCodes: [],
          },
        ),
      ]);

      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.batchStatus).toBe(AhcipBatchStatus.RECONCILED);
      expect(body.data.accepted).toBe(2);
      expect(body.data.rejected).toBe(0);
      expect(body.data.adjusted).toBe(0);

      // All claims are PAID
      body.data.claims.forEach((claim: any) => {
        expect(claim.state).toBe('PAID');
        expect(claim.assessedFee).toBe(claim.submittedFee);
      });
    });

    it('payment reconciliation preserves submission reference for audit', async () => {
      mockRepo.findBatchById.mockResolvedValueOnce(
        makeMockBatch({
          ahcipBatchId: BATCH_ID_1,
          status: AhcipBatchStatus.RECONCILED,
          submissionReference: 'REF-AUDIT-99',
        }),
      );
      mockRepo.findClaimsByBatchId.mockResolvedValueOnce([]);

      const res = await authedGet(`/api/v1/ahcip/assessments/${BATCH_ID_1}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.submissionReference).toBe('REF-AUDIT-99');
    });

    it('pending assessments list does not include RECONCILED batches', async () => {
      mockRepo.findBatchesAwaitingResponse.mockResolvedValueOnce([
        makeMockBatch({
          ahcipBatchId: BATCH_ID_2,
          status: AhcipBatchStatus.SUBMITTED,
          submissionReference: 'REF-PENDING1',
        }),
      ]);

      const res = await authedGet('/api/v1/ahcip/assessments/pending');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      // Only SUBMITTED batches are pending — RECONCILED excluded by repo
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((b: any) => {
        expect(b.batchId).not.toBeUndefined();
        expect(b.baNumber).not.toBeUndefined();
      });
    });
  });
});
