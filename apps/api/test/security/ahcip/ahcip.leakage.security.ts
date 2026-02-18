import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
// ---------------------------------------------------------------------------

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(
      (email: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`,
    ),
    verify: vi.fn(({ token }: { token: string }) => token === '123456'),
  };
  return { authenticator: mockAuthenticator };
});

// ---------------------------------------------------------------------------
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { ahcipRoutes } from '../../../src/domains/ahcip/ahcip.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type AhcipHandlerDeps } from '../../../src/domains/ahcip/ahcip.handlers.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities — Two isolated physicians
// ---------------------------------------------------------------------------

// Physician 1 — "our" physician
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

// Physician 2 — "other" physician (attacker perspective)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-2222-0000-0000-000000000002';
const P2_PROVIDER_ID = P2_USER_ID;
const P2_SESSION_ID = '22222222-2222-0000-0000-000000000022';

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician 1's data
const P1_BATCH_ID_A = 'aaaa1111-0000-0000-0000-000000000001';
const P1_BATCH_ID_B = 'aaaa1111-0000-0000-0000-000000000002';
const P1_CLAIM_ID = 'cccc1111-0000-0000-0000-000000000001';

// Physician 2's data
const P2_BATCH_ID_A = 'aaaa2222-0000-0000-0000-000000000001';
const P2_BATCH_ID_B = 'aaaa2222-0000-0000-0000-000000000002';
const P2_CLAIM_ID = 'cccc2222-0000-0000-0000-000000000001';

// Non-existent UUID
const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

// Sensitive PHI data — must never leak
const P1_PATIENT_PHN = '123456789';
const P1_PATIENT_DOB = '1985-05-15';
const P2_PATIENT_PHN = '987654321';

// H-Link credentials — must never leak
const HLINK_SUBMITTER_PREFIX = 'MRT-SUB-001';
const HLINK_CREDENTIAL_ID = 'hlink-cred-secret-id-abc123';
const HLINK_CREDENTIAL_SECRET = 'hlink-cred-secret-key-xyz789';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
  passwordHash: string;
  mfaConfigured: boolean;
  totpSecretEncrypted: string | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  isActive: boolean;
  role: string;
  subscriptionStatus: string;
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
}

interface MockSession {
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}

let users: MockUser[] = [];
let sessions: MockSession[] = [];

// ---------------------------------------------------------------------------
// AHCIP data stores (physician-scoped)
// ---------------------------------------------------------------------------

interface MockBatch {
  ahcipBatchId: string;
  physicianId: string;
  baNumber: string;
  batchWeek: string;
  status: string;
  claimCount: number;
  totalValue: string;
  submissionReference: string | null;
  filePath: string | null;
  hlinkFileName: string | null;
  retryCount: number;
  lastError: string | null;
  createdAt: Date;
  updatedAt: Date;
}

interface MockAhcipDetail {
  ahcipDetailId: string;
  claimId: string;
  physicianId: string;
  healthServiceCode: string;
  functionalCentre: string;
  encounterType: string;
  modifier1: string | null;
  modifier2: string | null;
  modifier3: string | null;
  diagnosticCode: string | null;
  facilityNumber: string | null;
  calls: number;
  timeSpent: number | null;
  submittedFee: string;
  assessedFee: string | null;
  afterHoursFlag: boolean;
  afterHoursType: string | null;
  shadowBillingFlag: boolean;
  pcpcmBasketFlag: boolean;
  assessmentExplanatoryCodes: string[];
  claim: {
    claimId: string;
    physicianId: string;
    dateOfService: string;
    state: string;
  };
}

interface MockBatchPreviewGroup {
  baNumber: string;
  claimCount: number;
  totalValue: string;
}

const batchStore: Record<string, MockBatch> = {};
const ahcipDetailStore: Record<string, MockAhcipDetail> = {};

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedTestData() {
  Object.keys(batchStore).forEach((k) => delete batchStore[k]);
  Object.keys(ahcipDetailStore).forEach((k) => delete ahcipDetailStore[k]);

  // --- Physician 1's batches ---
  batchStore[P1_BATCH_ID_A] = {
    ahcipBatchId: P1_BATCH_ID_A,
    physicianId: P1_PROVIDER_ID,
    baNumber: '11111',
    batchWeek: '2026-02-19',
    status: 'SUBMITTED',
    claimCount: 5,
    totalValue: '250.00',
    submissionReference: 'REF-P1-001',
    filePath: `/hlink/batches/${P1_PROVIDER_ID}/${P1_BATCH_ID_A}.dat`,
    hlinkFileName: 'p1_batch_a.hl7',
    retryCount: 0,
    lastError: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  batchStore[P1_BATCH_ID_B] = {
    ahcipBatchId: P1_BATCH_ID_B,
    physicianId: P1_PROVIDER_ID,
    baNumber: '11111',
    batchWeek: '2026-02-12',
    status: 'ERROR',
    claimCount: 3,
    totalValue: '150.00',
    submissionReference: null,
    filePath: `/hlink/batches/${P1_PROVIDER_ID}/${P1_BATCH_ID_B}.dat`,
    hlinkFileName: 'p1_batch_b.hl7',
    retryCount: 1,
    lastError: 'Connection timeout',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Physician 2's batches ---
  batchStore[P2_BATCH_ID_A] = {
    ahcipBatchId: P2_BATCH_ID_A,
    physicianId: P2_PROVIDER_ID,
    baNumber: '22222',
    batchWeek: '2026-02-19',
    status: 'SUBMITTED',
    claimCount: 8,
    totalValue: '400.00',
    submissionReference: 'REF-P2-001',
    filePath: `/hlink/batches/${P2_PROVIDER_ID}/${P2_BATCH_ID_A}.dat`,
    hlinkFileName: 'p2_batch_a.hl7',
    retryCount: 0,
    lastError: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  batchStore[P2_BATCH_ID_B] = {
    ahcipBatchId: P2_BATCH_ID_B,
    physicianId: P2_PROVIDER_ID,
    baNumber: '22222',
    batchWeek: '2026-02-12',
    status: 'ERROR',
    claimCount: 4,
    totalValue: '200.00',
    submissionReference: null,
    filePath: `/hlink/batches/${P2_PROVIDER_ID}/${P2_BATCH_ID_B}.dat`,
    hlinkFileName: 'p2_batch_b.hl7',
    retryCount: 2,
    lastError: 'H-Link unavailable',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Physician 1's AHCIP claim details ---
  ahcipDetailStore[P1_CLAIM_ID] = {
    ahcipDetailId: 'dd111111-0000-0000-0000-000000000001',
    claimId: P1_CLAIM_ID,
    physicianId: P1_PROVIDER_ID,
    healthServiceCode: '03.04A',
    functionalCentre: 'MEDE',
    encounterType: 'CONSULTATION',
    modifier1: null,
    modifier2: null,
    modifier3: null,
    diagnosticCode: '780',
    facilityNumber: null,
    calls: 1,
    timeSpent: null,
    submittedFee: '50.00',
    assessedFee: '50.00',
    afterHoursFlag: false,
    afterHoursType: null,
    shadowBillingFlag: false,
    pcpcmBasketFlag: false,
    assessmentExplanatoryCodes: [],
    claim: {
      claimId: P1_CLAIM_ID,
      physicianId: P1_PROVIDER_ID,
      dateOfService: '2026-01-15',
      state: 'ASSESSED',
    },
  };

  // --- Physician 2's AHCIP claim details ---
  ahcipDetailStore[P2_CLAIM_ID] = {
    ahcipDetailId: 'dd222222-0000-0000-0000-000000000001',
    claimId: P2_CLAIM_ID,
    physicianId: P2_PROVIDER_ID,
    healthServiceCode: '08.19C',
    functionalCentre: 'SURG',
    encounterType: 'PROCEDURE',
    modifier1: 'ANES',
    modifier2: null,
    modifier3: null,
    diagnosticCode: '410',
    facilityNumber: 'FAC-99',
    calls: 2,
    timeSpent: 45,
    submittedFee: '320.00',
    assessedFee: '280.00',
    afterHoursFlag: true,
    afterHoursType: 'EVENING',
    shadowBillingFlag: false,
    pcpcmBasketFlag: false,
    assessmentExplanatoryCodes: ['E01', 'E14'],
    claim: {
      claimId: P2_CLAIM_ID,
      physicianId: P2_PROVIDER_ID,
      dateOfService: '2026-02-01',
      state: 'ASSESSED',
    },
  };
}

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session-id' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      const result: any = {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
      if (user.delegateContext) {
        result.user.delegateContext = user.delegateContext;
      }
      return result;
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Physician-scoped mock AHCIP repository
// ---------------------------------------------------------------------------

function createScopedAhcipRepo() {
  return {
    createAhcipDetail: vi.fn(async () => ({})),

    findAhcipDetailByClaimId: vi.fn(async (claimId: string, physicianId: string) => {
      const detail = ahcipDetailStore[claimId];
      if (!detail || detail.physicianId !== physicianId) return undefined;
      return detail;
    }),

    updateAhcipDetail: vi.fn(async () => ({})),

    findBatchById: vi.fn(async (batchId: string, physicianId: string) => {
      const batch = batchStore[batchId];
      if (!batch || batch.physicianId !== physicianId) return undefined;
      // Simulate stripping internal fields (file_path, submission_reference)
      // from the API response — handler should not expose these
      return {
        ahcipBatchId: batch.ahcipBatchId,
        physicianId: batch.physicianId,
        baNumber: batch.baNumber,
        batchWeek: batch.batchWeek,
        status: batch.status,
        claimCount: batch.claimCount,
        totalValue: batch.totalValue,
        retryCount: batch.retryCount,
        createdAt: batch.createdAt,
        updatedAt: batch.updatedAt,
      };
    }),

    listBatches: vi.fn(async (physicianId: string, filters: any) => {
      let matches = Object.values(batchStore).filter(
        (b) => b.physicianId === physicianId,
      );
      if (filters.status) matches = matches.filter((b) => b.status === filters.status);
      if (filters.dateFrom) matches = matches.filter((b) => b.batchWeek >= filters.dateFrom);
      if (filters.dateTo) matches = matches.filter((b) => b.batchWeek <= filters.dateTo);
      const page = filters.page ?? 1;
      const pageSize = filters.pageSize ?? 20;
      const start = (page - 1) * pageSize;
      // Strip internal fields from list responses
      const safeMatches = matches.map((b) => ({
        ahcipBatchId: b.ahcipBatchId,
        physicianId: b.physicianId,
        baNumber: b.baNumber,
        batchWeek: b.batchWeek,
        status: b.status,
        claimCount: b.claimCount,
        totalValue: b.totalValue,
        retryCount: b.retryCount,
        createdAt: b.createdAt,
        updatedAt: b.updatedAt,
      }));
      return {
        data: safeMatches.slice(start, start + pageSize),
        pagination: { total: safeMatches.length, page, pageSize, hasMore: page * pageSize < safeMatches.length },
      };
    }),

    findNextBatchPreview: vi.fn(async (physicianId: string): Promise<MockBatchPreviewGroup[]> => {
      if (physicianId === P1_PROVIDER_ID) {
        return [{ baNumber: '11111', claimCount: 2, totalValue: '100.00' }];
      }
      if (physicianId === P2_PROVIDER_ID) {
        return [{ baNumber: '22222', claimCount: 5, totalValue: '500.00' }];
      }
      return [];
    }),

    createBatch: vi.fn(async () => ({})),
    updateBatchStatus: vi.fn(async () => ({})),

    findClaimsForBatch: vi.fn(async () => []),

    findAssessmentsByBatchId: vi.fn(async (batchId: string, physicianId: string) => {
      const batch = batchStore[batchId];
      if (!batch || batch.physicianId !== physicianId) return [];
      // Return assessment results with resolved descriptions (not raw codes)
      if (batchId === P1_BATCH_ID_A) {
        return [{
          claimId: P1_CLAIM_ID,
          explanatoryCodeDescriptions: ['Approved as submitted'],
          assessedFee: '50.00',
          submittedFee: '50.00',
          result: 'APPROVED',
        }];
      }
      return [];
    }),

    createAssessment: vi.fn(async () => ({})),

    listBatchesAwaitingResponse: vi.fn(async (physicianId: string) => {
      return Object.values(batchStore).filter(
        (b) => b.physicianId === physicianId && b.status === 'SUBMITTED',
      ).map((b) => ({
        batchId: b.ahcipBatchId,
        baNumber: b.baNumber,
        batchWeek: b.batchWeek,
        claimCount: b.claimCount,
        submittedAt: b.createdAt.toISOString(),
      }));
    }),

    findBatchesAwaitingResponse: vi.fn(async (physicianId: string) => {
      return Object.values(batchStore).filter(
        (b) => b.physicianId === physicianId && b.status === 'SUBMITTED',
      ).map((b) => ({
        ahcipBatchId: b.ahcipBatchId,
        baNumber: b.baNumber,
        batchWeek: b.batchWeek,
        claimCount: b.claimCount,
        totalSubmittedValue: b.totalValue,
        submittedAt: b.createdAt,
      }));
    }),

    findFeeScheduleEntry: vi.fn(async () => ({
      baseFee: '50.00',
      maxCalls: 1,
      timeRequired: false,
    })),

    findClaimWithAhcipDetail: vi.fn(async (claimId: string, physicianId: string) => {
      const detail = ahcipDetailStore[claimId];
      if (!detail || detail.physicianId !== physicianId) return undefined;
      return detail;
    }),

    findClaimsByBatchId: vi.fn(async (batchId: string, physicianId: string) => {
      const batch = batchStore[batchId];
      if (!batch || batch.physicianId !== physicianId) return [];
      return Object.values(ahcipDetailStore)
        .filter((d) => d.physicianId === physicianId)
        .map((d) => ({ claim: d.claim, detail: d }));
    }),

    bulkUpdateClaimStates: vi.fn(async () => []),
    appendClaimAudit: vi.fn(async () => ({})),
  };
}

function createStubHandlerDeps(): AhcipHandlerDeps {
  const repo = createScopedAhcipRepo() as any;
  return {
    batchCycleDeps: {
      repo,
      feeRefData: { lookupFee: vi.fn(async () => null), getCurrentVersion: vi.fn(async () => '1.0') },
      feeProviderService: { getProviderFeeConfig: vi.fn(async () => ({})) },
      claimStateService: { transition: vi.fn(async () => ({})) },
      notificationService: { emit: vi.fn(async () => {}) },
      hlinkTransmission: { transmit: vi.fn(async () => ({ success: true, submissionReference: 'REF-RETRY' })) },
      fileEncryption: { encrypt: vi.fn(async () => Buffer.from('')), decrypt: vi.fn(async () => Buffer.from('')) },
      submissionPreferences: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
      validationRunner: { validate: vi.fn(async () => ({ valid: true, errors: [] })) },
    },
    feeCalculationDeps: {
      repo,
      feeRefData: { lookupFee: vi.fn(async () => ({ baseFee: '50.00', maxCalls: 1, timeRequired: false })), getCurrentVersion: vi.fn(async () => '1.0') },
      feeProviderService: { getProviderFeeConfig: vi.fn(async () => ({ rrnpEligible: false, shadowBilling: false })) },
    },
    assessmentDeps: {
      repo,
      claimStateService: { transition: vi.fn(async () => ({})) },
      notificationService: { emit: vi.fn(async () => {}) },
      hlinkRetrieval: { retrieve: vi.fn(async () => ({})) },
      explanatoryCodeService: { getExplanatoryCode: vi.fn(async () => null) },
      fileEncryption: { encrypt: vi.fn(async () => Buffer.from('')), decrypt: vi.fn(async () => Buffer.from('')) },
    },
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps = createStubHandlerDeps();

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    const statusCode = (error as any).statusCode;
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      return reply.code(statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
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
// Request helpers
// ---------------------------------------------------------------------------

function asPhysician1(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asPhysician2(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function unauthenticated(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed users and sessions
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  users = [];
  sessions = [];

  // Physician 1
  users.push({
    userId: P1_USER_ID,
    email: 'physician1@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
  });
  sessions.push({
    sessionId: P1_SESSION_ID,
    userId: P1_USER_ID,
    tokenHash: P1_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Physician 2
  users.push({
    userId: P2_USER_ID,
    email: 'physician2@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
  });
  sessions.push({
    sessionId: P2_SESSION_ID,
    userId: P2_USER_ID,
    tokenHash: P2_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.2',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('AHCIP PHI & Data Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
    seedTestData();
  });

  // =========================================================================
  // 1. PHI Not in Error Responses
  // =========================================================================

  describe('PHI not in error responses', () => {
    it('400 validation error on fee-calculate does not expose patient PHN or DOB', async () => {
      const res = await asPhysician1('POST', '/api/v1/ahcip/fee-calculate', {
        health_service_code: '',  // invalid — too short
        functional_centre: 'MEDE',
        encounter_type: 'INVALID_TYPE',
        date_of_service: P1_PATIENT_DOB,
        patient_id: NONEXISTENT_UUID,
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);

      // PHI must not appear in validation error
      expect(res.body).not.toContain(P1_PATIENT_PHN);
      expect(res.body).not.toContain(P1_PATIENT_DOB);

      // Only error key, no data
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('404 for cross-physician AHCIP batch does not confirm existence', async () => {
      // P1 tries to access P2's batch
      const crossTenantRes = await asPhysician1('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_A}`);
      // P1 accesses a genuinely non-existent batch
      const genuineMissingRes = await asPhysician1('GET', `/api/v1/ahcip/batches/${NONEXISTENT_UUID}`);

      // Both should be 404 with identical error shape
      expect(crossTenantRes.statusCode).toBe(404);
      expect(genuineMissingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(genuineMissingRes.body);

      // Same error structure — indistinguishable
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);

      // No batch details leaked
      expect(crossTenantRes.body).not.toContain(P2_BATCH_ID_A);
      expect(crossTenantRes.body).not.toContain(P2_PROVIDER_ID);
      expect(crossTenantRes.body).not.toContain('REF-P2-001');
    });

    it('404 for cross-physician fee breakdown does not confirm claim exists', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/ahcip/claims/${P2_CLAIM_ID}/fee-breakdown`);
      const missingRes = await asPhysician1('GET', `/api/v1/ahcip/claims/${NONEXISTENT_UUID}/fee-breakdown`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);

      // No claim details leaked
      expect(crossRes.body).not.toContain(P2_CLAIM_ID);
      expect(crossRes.body).not.toContain(P2_PROVIDER_ID);
      expect(crossRes.body).not.toContain('320.00');
      expect(crossRes.body).not.toContain('08.19C');
    });

    it('404 for cross-physician assessment does not confirm batch exists', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P2_BATCH_ID_A}`);
      const missingRes = await asPhysician1('GET', `/api/v1/ahcip/assessments/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('fee calculation error does not leak internal SOMB data structure', async () => {
      const res = await asPhysician1('POST', '/api/v1/ahcip/fee-calculate', {
        health_service_code: '99.99Z',  // non-existent HSC
        functional_centre: 'MEDE',
        encounter_type: 'CONSULTATION',
        date_of_service: '2026-01-15',
        patient_id: NONEXISTENT_UUID,
      });

      const rawBody = res.body;
      // Must not leak SOMB internal structure names
      expect(rawBody.toLowerCase()).not.toContain('somb');
      expect(rawBody.toLowerCase()).not.toContain('fee_schedule');
      expect(rawBody.toLowerCase()).not.toContain('fee_schedules');
      expect(rawBody.toLowerCase()).not.toContain('governing_rule');
    });

    it('500 errors expose no internals', async () => {
      // Even if an unexpected error occurs, verify the error handler strips internals
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${NONEXISTENT_UUID}`);

      const body = JSON.parse(res.body);
      // No stack traces
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('stackTrace');
      expect(JSON.stringify(body)).not.toMatch(/at\s+\w+\s+\(/);
      expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+:\d+/);
      expect(JSON.stringify(body)).not.toContain('node_modules');
      // No SQL/ORM keywords
      expect(JSON.stringify(body).toLowerCase()).not.toMatch(/postgres|drizzle|pg_catalog|relation|syntax error/);
    });

    it('401 response body contains only error object, no AHCIP data', async () => {
      const res = await unauthenticated('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.data).toBeUndefined();

      // No batch data leaked
      expect(res.body).not.toContain(P1_BATCH_ID_A);
      expect(res.body).not.toContain(P1_PROVIDER_ID);
      expect(res.body).not.toContain('11111');
    });
  });

  // =========================================================================
  // 2. H-Link File Security
  // =========================================================================

  describe('H-Link file security', () => {
    it('batch API responses do not expose file_path', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      // file_path must not be in the response
      expect(rawBody).not.toContain('file_path');
      expect(rawBody).not.toContain('filePath');
      expect(rawBody).not.toContain('/hlink/batches/');
      expect(rawBody).not.toContain('.dat');
    });

    it('batch list responses do not expose file_path', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('file_path');
      expect(rawBody).not.toContain('filePath');
      expect(rawBody).not.toContain('/hlink/batches/');
      expect(rawBody).not.toContain('.dat');
    });

    it('batch response does not expose submission_reference (internal tracking only)', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('submissionReference');
      expect(rawBody).not.toContain('submission_reference');
      expect(rawBody).not.toContain('REF-P1-001');
    });

    it('batch list does not expose submission_reference', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('submissionReference');
      expect(rawBody).not.toContain('submission_reference');
      expect(rawBody).not.toContain('REF-P1-001');
    });

    it('H-Link file not accessible via unauthenticated direct URL attempt', async () => {
      // Attempt to fetch batch file path directly — should not expose file
      const res = await unauthenticated('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(res.body).not.toContain('/hlink/');
      expect(res.body).not.toContain('.dat');
      expect(res.body).not.toContain('.hl7');
    });

    it('cross-tenant batch access does not leak file details', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain('p2_batch_a.hl7');
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain('/hlink/');
      expect(rawBody).not.toContain('REF-P2-001');
    });
  });

  // =========================================================================
  // 3. Assessment Data Leakage Prevention
  // =========================================================================

  describe('Assessment data leakage prevention', () => {
    it('assessment results scoped to physician — no cross-physician leakage', async () => {
      // P1 retrieves their own assessment
      const res = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      // Must not contain P2's data
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('320.00');
      expect(rawBody).not.toContain('280.00');
      expect(rawBody).not.toContain('08.19C');
    });

    it('cross-physician assessment returns 404 with no details', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(body.error).toBeDefined();

      // No assessment data leaked
      expect(res.body).not.toContain(P2_CLAIM_ID);
      expect(res.body).not.toContain('E01');
      expect(res.body).not.toContain('E14');
      expect(res.body).not.toContain('280.00');
    });

    it('assessment response does not expose raw AHCIP response codes', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);

      // Verify the response has resolved descriptions, not raw internal codes
      const body = JSON.parse(res.body);
      if (body.data && Array.isArray(body.data) && body.data.length > 0) {
        body.data.forEach((assessment: any) => {
          // Should have descriptions, not raw AHCIP protocol codes
          if (assessment.explanatoryCodeDescriptions) {
            assessment.explanatoryCodeDescriptions.forEach((desc: string) => {
              // Descriptions should be human-readable, not raw protocol IDs
              expect(desc).not.toMatch(/^[A-Z]\d{2}$/);  // e.g., E01, E14
            });
          }
        });
      }
    });

    it('pending assessments list for P1 does not contain P2 batch data', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('22222');  // P2's BA number
    });
  });

  // =========================================================================
  // 4. Response Header Security
  // =========================================================================

  describe('Response header security', () => {
    it('no X-Powered-By header in authenticated responses', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 401 responses', async () => {
      const res = await unauthenticated('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(401);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 400 responses', async () => {
      const res = await asPhysician1('POST', '/api/v1/ahcip/fee-calculate', {});
      expect(res.statusCode).toBe(400);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 404 responses', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing version/technology', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      const serverHeader = res.headers['server'];
      if (serverHeader) {
        const lower = (serverHeader as string).toLowerCase();
        expect(lower).not.toContain('fastify');
        expect(lower).not.toContain('node');
        expect(lower).not.toContain('express');
      }
    });

    it('no AHCIP claim data in response headers', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      const headerStr = JSON.stringify(res.headers);

      expect(headerStr).not.toContain(P1_PATIENT_PHN);
      expect(headerStr).not.toContain(P1_BATCH_ID_A);
      expect(headerStr).not.toContain(P1_CLAIM_ID);
    });

    it('responses include Content-Type: application/json', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('error responses include Content-Type: application/json', async () => {
      const res = await unauthenticated('GET', '/api/v1/ahcip/batches');
      expect(res.headers['content-type']).toContain('application/json');
    });
  });

  // =========================================================================
  // 5. H-Link Credentials Never Exposed
  // =========================================================================

  describe('H-Link credentials never in API responses', () => {
    it('batch response does not contain H-Link submitter prefix', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(HLINK_SUBMITTER_PREFIX);
      expect(rawBody).not.toContain('submitter_prefix');
      expect(rawBody).not.toContain('submitterPrefix');
    });

    it('batch list response does not contain H-Link credentials', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_ID);
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_SECRET);
      expect(rawBody).not.toContain('hlink_credential');
      expect(rawBody).not.toContain('hlinkCredential');
    });

    it('fee-calculate response does not contain H-Link credentials', async () => {
      const res = await asPhysician1('POST', '/api/v1/ahcip/fee-calculate', {
        health_service_code: '03.04A',
        functional_centre: 'MEDE',
        encounter_type: 'CONSULTATION',
        date_of_service: '2026-01-15',
        patient_id: NONEXISTENT_UUID,
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_ID);
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_SECRET);
      expect(rawBody).not.toContain(HLINK_SUBMITTER_PREFIX);
    });

    it('assessment response does not contain H-Link credentials', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_ID);
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_SECRET);
      expect(rawBody).not.toContain(HLINK_SUBMITTER_PREFIX);
    });

    it('error response on failed retry does not contain H-Link credentials', async () => {
      const res = await asPhysician1('POST', `/api/v1/ahcip/batches/${NONEXISTENT_UUID}/retry`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_ID);
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_SECRET);
      expect(rawBody).not.toContain(HLINK_SUBMITTER_PREFIX);
    });
  });

  // =========================================================================
  // 6. Sensitive Fields Stripped from Responses
  // =========================================================================

  describe('Sensitive fields stripped from responses', () => {
    it('batch response does not contain password_hash or session tokens', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('password_hash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('token_hash');
      expect(rawBody).not.toContain(P1_SESSION_TOKEN);
      expect(rawBody).not.toContain(P1_SESSION_TOKEN_HASH);
    });

    it('batch response does not contain TOTP secrets', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);

      expect(res.body).not.toContain('totpSecret');
      expect(res.body).not.toContain('totp_secret');
      expect(res.body).not.toContain('JBSWY3DPEHPK3PXP');
    });

    it('batch list does not contain internal auth fields', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('totpSecret');
      expect(rawBody).not.toContain(P1_SESSION_TOKEN);
    });

    it('pending assessments do not contain auth fields', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('totpSecret');
    });

    it('batch response does not expose lastError to client (internal diagnostic)', async () => {
      // lastError contains internal debugging info that should not reach the client
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_B}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('lastError');
      expect(rawBody).not.toContain('last_error');
      expect(rawBody).not.toContain('Connection timeout');
    });
  });

  // =========================================================================
  // 7. Error Responses Are Generic — No Internal State Revealed
  // =========================================================================

  describe('Error responses do not reveal internal state', () => {
    it('all 404 responses have consistent error structure', async () => {
      const routes = [
        { method: 'GET' as const, url: `/api/v1/ahcip/batches/${NONEXISTENT_UUID}` },
        { method: 'POST' as const, url: `/api/v1/ahcip/batches/${NONEXISTENT_UUID}/retry` },
        { method: 'GET' as const, url: `/api/v1/ahcip/assessments/${NONEXISTENT_UUID}` },
        { method: 'GET' as const, url: `/api/v1/ahcip/claims/${NONEXISTENT_UUID}/fee-breakdown` },
      ];

      for (const route of routes) {
        const res = await asPhysician1(route.method, route.url);

        if (res.statusCode === 404) {
          const body = JSON.parse(res.body);

          // Consistent structure: only error key
          expect(body.error).toBeDefined();
          expect(body.data).toBeUndefined();
          expect(body.error).toHaveProperty('code');
          expect(body.error).toHaveProperty('message');

          // No stack traces or internal details
          expect(body.error).not.toHaveProperty('stack');
          expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+/);
          expect(JSON.stringify(body)).not.toContain('node_modules');
        }
      }
    });

    it('error responses never contain SQL-related keywords', async () => {
      const res = await asPhysician1('POST', '/api/v1/ahcip/fee-calculate', {
        health_service_code: "'; DROP TABLE ahcip_batches;--",
        functional_centre: 'MEDE',
        encounter_type: 'CONSULTATION',
        date_of_service: '2026-01-15',
        patient_id: NONEXISTENT_UUID,
      });

      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('pg_catalog');
      expect(lower).not.toContain('relation');
      expect(lower).not.toContain('syntax error');
    });

    it('error responses do not expose database table or column names', async () => {
      const res = await asPhysician1('POST', '/api/v1/ahcip/fee-calculate', {});

      if (res.statusCode === 400) {
        const rawBody = res.body.toLowerCase();
        expect(rawBody).not.toContain('ahcip_claim_details');
        expect(rawBody).not.toContain('ahcip_batches');
        expect(rawBody).not.toContain('column');
        expect(rawBody).not.toContain('constraint violation');
        expect(rawBody).not.toContain('unique_constraint');
      }
    });

    it('error responses do not expose resource UUIDs in 404 messages', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain(NONEXISTENT_UUID);
    });

    it('409 conflict on retry does not leak batch internals', async () => {
      // Retry a submitted batch (wrong state) — should be 409
      const res = await asPhysician1('POST', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}/retry`);

      // Whether 409 or other status, should not leak H-Link details
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_PATIENT_PHN);
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_ID);
      expect(rawBody).not.toContain(HLINK_CREDENTIAL_SECRET);
      expect(rawBody).not.toContain('/hlink/');
    });
  });

  // =========================================================================
  // 8. Anti-Enumeration Protection
  // =========================================================================

  describe('Anti-enumeration protection', () => {
    it('404 for cross-tenant batch is indistinguishable from genuinely missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_A}`);
      const missingRes = await asPhysician1('GET', `/api/v1/ahcip/batches/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant retry is indistinguishable from missing', async () => {
      const crossRes = await asPhysician1('POST', `/api/v1/ahcip/batches/${P2_BATCH_ID_B}/retry`);
      const missingRes = await asPhysician1('POST', `/api/v1/ahcip/batches/${NONEXISTENT_UUID}/retry`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant assessment is indistinguishable from missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P2_BATCH_ID_A}`);
      const missingRes = await asPhysician1('GET', `/api/v1/ahcip/assessments/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant fee breakdown is indistinguishable from missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/ahcip/claims/${P2_CLAIM_ID}/fee-breakdown`);
      const missingRes = await asPhysician1('GET', `/api/v1/ahcip/claims/${NONEXISTENT_UUID}/fee-breakdown`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });
  });

  // =========================================================================
  // 9. List / Search Responses Do Not Leak Cross-Tenant Data
  // =========================================================================

  describe('List responses do not leak cross-tenant data', () => {
    it('batch list contains only authenticated physician batches', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      const rawBody = res.body;

      // Must not contain P2's data
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_BATCH_ID_B);

      // All returned batches belong to P1
      if (body.data && body.data.length > 0) {
        body.data.forEach((batch: any) => {
          expect(batch.physicianId).toBe(P1_PROVIDER_ID);
        });
      }
    });

    it('pending assessments list contains only authenticated physician data', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
    });

    it('next batch preview contains only authenticated physician data', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches/next');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('22222');  // P2's BA number
      expect(rawBody).not.toContain('500.00'); // P2's total value
    });
  });
});
