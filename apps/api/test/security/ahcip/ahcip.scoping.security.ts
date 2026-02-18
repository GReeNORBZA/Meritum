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
// Fixed test identities — Two isolated physicians + delegate
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

// Delegate linked to Physician 1 only (with CLAIM_VIEW + CLAIM_SUBMIT)
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '33333333-3333-0000-0000-000000000003';
const DELEGATE_SESSION_ID = '33333333-3333-0000-0000-000000000033';

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician 1's AHCIP batches
const P1_BATCH_ID_A = 'aaaa1111-0000-0000-0000-000000000001';
const P1_BATCH_ID_B = 'aaaa1111-0000-0000-0000-000000000002';

// Physician 2's AHCIP batches
const P2_BATCH_ID_A = 'aaaa2222-0000-0000-0000-000000000001';
const P2_BATCH_ID_B = 'aaaa2222-0000-0000-0000-000000000002';

// Physician 1's claims with AHCIP details
const P1_CLAIM_ID = 'cccc1111-0000-0000-0000-000000000001';

// Physician 2's claims with AHCIP details
const P2_CLAIM_ID = 'cccc2222-0000-0000-0000-000000000001';

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
    assessmentExplanatoryCodes: ['E01'],
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
      return batch;
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
      return {
        data: matches.slice(start, start + pageSize),
        pagination: { total: matches.length, page, pageSize, hasMore: page * pageSize < matches.length },
      };
    }),

    findNextBatchPreview: vi.fn(async (physicianId: string): Promise<MockBatchPreviewGroup[]> => {
      // Return queued claim groups for this physician only
      if (physicianId === P1_PROVIDER_ID) {
        return [
          { baNumber: '11111', claimCount: 2, totalValue: '100.00' },
        ];
      }
      if (physicianId === P2_PROVIDER_ID) {
        return [
          { baNumber: '22222', claimCount: 5, totalValue: '500.00' },
        ];
      }
      return [];
    }),

    createBatch: vi.fn(async () => ({})),
    updateBatchStatus: vi.fn(async () => ({})),

    findClaimsForBatch: vi.fn(async () => []),

    findAssessmentsByBatchId: vi.fn(async (batchId: string, physicianId: string) => {
      const batch = batchStore[batchId];
      if (!batch || batch.physicianId !== physicianId) return [];
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
        submissionReference: b.submissionReference,
      }));
    }),

    findFeeScheduleEntry: vi.fn(async () => ({
      baseFee: '50.00',
      maxCalls: 1,
      timeRequired: false,
    })),

    findClaimWithAhcipDetail: vi.fn(async () => undefined),

    findClaimsByBatchId: vi.fn(async (batchId: string, physicianId: string) => {
      const batch = batchStore[batchId];
      if (!batch || batch.physicianId !== physicianId) return [];
      // Return linked claims for this batch's physician
      return Object.values(ahcipDetailStore)
        .filter((d) => d.physicianId === physicianId)
        .map((d) => ({
          claim: d.claim,
          detail: d,
        }));
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
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
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

function asDelegate(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
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

  // Delegate linked to Physician 1 (with CLAIM_VIEW + CLAIM_SUBMIT)
  users.push({
    userId: DELEGATE_USER_ID,
    email: 'delegate@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_USER_ID,
      physicianProviderId: P1_PROVIDER_ID,
      permissions: ['CLAIM_VIEW', 'CLAIM_SUBMIT'],
      linkageId: '44444444-4444-0000-0000-000000000044',
    },
  });
  sessions.push({
    sessionId: DELEGATE_SESSION_ID,
    userId: DELEGATE_USER_ID,
    tokenHash: DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.3',
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

describe('AHCIP Physician Tenant Isolation — MOST CRITICAL (Security)', () => {
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
  // 1. Batch Isolation — LIST
  // =========================================================================

  describe('Batch isolation — LIST', () => {
    it('physician1 listing batches returns only physician1 batches', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((batch: any) => {
        expect(batch.physicianId).toBe(P1_PROVIDER_ID);
      });
    });

    it('physician2 listing batches returns only physician2 batches', async () => {
      const res = await asPhysician2('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((batch: any) => {
        expect(batch.physicianId).toBe(P2_PROVIDER_ID);
      });
    });

    it('physician1 batch list never contains physician2 batch IDs', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });

    it('physician2 batch list never contains physician1 batch IDs', async () => {
      const res = await asPhysician2('GET', '/api/v1/ahcip/batches');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_BATCH_ID_A);
      expect(rawBody).not.toContain(P1_BATCH_ID_B);
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 2. Batch Isolation — GET by ID
  // =========================================================================

  describe('Batch isolation — GET by ID', () => {
    it('physician1 can retrieve own batch via GET /api/v1/ahcip/batches/:id', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.ahcipBatchId).toBe(P1_BATCH_ID_A);
      expect(body.data.physicianId).toBe(P1_PROVIDER_ID);
    });

    it('physician2 can retrieve own batch via GET /api/v1/ahcip/batches/:id', async () => {
      const res = await asPhysician2('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.ahcipBatchId).toBe(P2_BATCH_ID_A);
      expect(body.data.physicianId).toBe(P2_PROVIDER_ID);
    });

    it('physician1 CANNOT view physician2 batch details — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT view physician1 batch details — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('cross-tenant GET batch response does not leak batch details', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('22222');
      expect(rawBody).not.toContain('REF-P2');
    });
  });

  // =========================================================================
  // 3. Batch Isolation — Retry (POST)
  // =========================================================================

  describe('Batch isolation — Retry', () => {
    it('physician1 CANNOT retry physician2 failed batch — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/ahcip/batches/${P2_BATCH_ID_B}/retry`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT retry physician1 failed batch — returns 404', async () => {
      const res = await asPhysician2('POST', `/api/v1/ahcip/batches/${P1_BATCH_ID_B}/retry`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 batch remains in ERROR status after physician1 retry attempt', async () => {
      await asPhysician1('POST', `/api/v1/ahcip/batches/${P2_BATCH_ID_B}/retry`);
      // Physician 2 checks their own batch — still ERROR
      const res = await asPhysician2('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_B}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe('ERROR');
    });

    it('cross-tenant retry response does not leak batch details', async () => {
      const res = await asPhysician1('POST', `/api/v1/ahcip/batches/${P2_BATCH_ID_B}/retry`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('H-Link unavailable');
    });
  });

  // =========================================================================
  // 4. Assessment Isolation — GET results by batch ID
  // =========================================================================

  describe('Assessment isolation — GET results by batch ID', () => {
    it('physician1 CANNOT view physician2 assessment results — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT view physician1 assessment results — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/ahcip/assessments/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('cross-tenant assessment response does not leak P2 data', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain('08.19C');
    });
  });

  // =========================================================================
  // 5. Assessment Isolation — Pending list
  // =========================================================================

  describe('Assessment isolation — Pending assessments list', () => {
    it('physician1 pending assessments returns only physician1 batches', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((entry: any) => {
        expect(entry.batchId).not.toBe(P2_BATCH_ID_A);
        expect(entry.batchId).not.toBe(P2_BATCH_ID_B);
      });
    });

    it('physician2 pending assessments returns only physician2 batches', async () => {
      const res = await asPhysician2('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((entry: any) => {
        expect(entry.batchId).not.toBe(P1_BATCH_ID_A);
        expect(entry.batchId).not.toBe(P1_BATCH_ID_B);
      });
    });

    it('physician1 pending list response does not contain P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/assessments/pending');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('22222'); // P2's BA number
    });
  });

  // =========================================================================
  // 6. Fee Breakdown Isolation — GET claim fee breakdown
  // =========================================================================

  describe('Fee breakdown isolation — GET claim fee breakdown', () => {
    it('physician1 CANNOT view physician2 fee breakdown — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/claims/${P2_CLAIM_ID}/fee-breakdown`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT view physician1 fee breakdown — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/ahcip/claims/${P1_CLAIM_ID}/fee-breakdown`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('cross-tenant fee breakdown response does not leak claim details', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/claims/${P2_CLAIM_ID}/fee-breakdown`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('320.00');
      expect(rawBody).not.toContain('08.19C');
    });
  });

  // =========================================================================
  // 7. Next Batch Preview Isolation
  // =========================================================================

  describe('Next batch preview isolation', () => {
    it('physician1 next batch preview contains only physician1 queued claims', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches/next');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Preview groups should be for P1's BA only
      if (body.data.groups && body.data.groups.length > 0) {
        body.data.groups.forEach((group: any) => {
          expect(group.baNumber).toBe('11111');
        });
      }
    });

    it('physician2 next batch preview contains only physician2 queued claims', async () => {
      const res = await asPhysician2('GET', '/api/v1/ahcip/batches/next');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      if (body.data.groups && body.data.groups.length > 0) {
        body.data.groups.forEach((group: any) => {
          expect(group.baNumber).toBe('22222');
        });
      }
    });

    it('physician1 next batch preview response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches/next');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('22222'); // P2's BA number
      expect(rawBody).not.toContain('500.00'); // P2's total value
    });

    it('physician2 next batch preview response contains no P1 identifiers', async () => {
      const res = await asPhysician2('GET', '/api/v1/ahcip/batches/next');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
      expect(rawBody).not.toContain('11111'); // P1's BA number
    });
  });

  // =========================================================================
  // 8. Delegate Cross-Context Isolation
  // =========================================================================

  describe('Delegate cross-context isolation', () => {
    it('delegate linked to physician1 can access physician1 batch list', async () => {
      const res = await asDelegate('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((batch: any) => {
        expect(batch.physicianId).toBe(P1_PROVIDER_ID);
      });
    });

    it('delegate linked to physician1 can access physician1 batch by ID', async () => {
      const res = await asDelegate('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.ahcipBatchId).toBe(P1_BATCH_ID_A);
    });

    it('delegate linked to physician1 CANNOT access physician2 batch — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('delegate linked to physician1 CANNOT retry physician2 batch — returns 404', async () => {
      const res = await asDelegate('POST', `/api/v1/ahcip/batches/${P2_BATCH_ID_B}/retry`);
      expect(res.statusCode).toBe(404);
    });

    it('delegate linked to physician1 CANNOT view physician2 assessment results — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/ahcip/assessments/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
    });

    it('delegate linked to physician1 CANNOT view physician2 fee breakdown — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/ahcip/claims/${P2_CLAIM_ID}/fee-breakdown`);
      expect(res.statusCode).toBe(404);
    });

    it('delegate pending assessments list only returns physician1 batches', async () => {
      const res = await asDelegate('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });

    it('delegate next batch preview only returns physician1 data', async () => {
      const res = await asDelegate('GET', '/api/v1/ahcip/batches/next');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('22222');
    });
  });

  // =========================================================================
  // 9. Cross-user access always returns 404 (NOT 403)
  // =========================================================================

  describe('Cross-user access returns 404 not 403 (prevents resource enumeration)', () => {
    it('GET batch by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST retry cross-tenant batch returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/ahcip/batches/${P2_BATCH_ID_B}/retry`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET assessment results cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET fee breakdown cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/claims/${P2_CLAIM_ID}/fee-breakdown`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 10. Non-existent resource IDs return 404 (not 500)
  // =========================================================================

  describe('Non-existent resource IDs return 404', () => {
    const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

    it('GET non-existent batch ID returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('POST retry non-existent batch ID returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/ahcip/batches/${NONEXISTENT_UUID}/retry`);
      expect(res.statusCode).toBe(404);
    });

    it('GET assessment results for non-existent batch returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/assessments/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET fee breakdown for non-existent claim returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/claims/${NONEXISTENT_UUID}/fee-breakdown`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 11. 404 responses reveal no information about the target resource
  // =========================================================================

  describe('404 responses reveal no information about the target resource', () => {
    it('404 for cross-tenant batch does not contain batch details', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('SUBMITTED');
      expect(rawBody).not.toContain('REF-P2-001');
    });

    it('404 for cross-tenant retry does not contain batch error details', async () => {
      const res = await asPhysician1('POST', `/api/v1/ahcip/batches/${P2_BATCH_ID_B}/retry`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
      expect(rawBody).not.toContain('H-Link unavailable');
      expect(rawBody).not.toContain('22222');
    });

    it('404 for cross-tenant assessment does not contain claim or fee details', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/assessments/${P2_BATCH_ID_A}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain('320.00');
      expect(rawBody).not.toContain('280.00');
    });

    it('404 for cross-tenant fee breakdown does not contain fee info', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/claims/${P2_CLAIM_ID}/fee-breakdown`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain('320.00');
      expect(rawBody).not.toContain('PROCEDURE');
    });
  });

  // =========================================================================
  // 12. Bidirectional isolation — verify BOTH directions
  // =========================================================================

  describe('Bidirectional isolation (both physicians tested)', () => {
    it('physician1 batch list contains P1 IDs and not P2 IDs', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      const body = JSON.parse(res.body);
      const ids = body.data.map((b: any) => b.ahcipBatchId);
      expect(ids).toContain(P1_BATCH_ID_A);
      expect(ids).toContain(P1_BATCH_ID_B);
      expect(ids).not.toContain(P2_BATCH_ID_A);
      expect(ids).not.toContain(P2_BATCH_ID_B);
    });

    it('physician2 batch list contains P2 IDs and not P1 IDs', async () => {
      const res = await asPhysician2('GET', '/api/v1/ahcip/batches');
      const body = JSON.parse(res.body);
      const ids = body.data.map((b: any) => b.ahcipBatchId);
      expect(ids).toContain(P2_BATCH_ID_A);
      expect(ids).toContain(P2_BATCH_ID_B);
      expect(ids).not.toContain(P1_BATCH_ID_A);
      expect(ids).not.toContain(P1_BATCH_ID_B);
    });
  });

  // =========================================================================
  // 13. Response body never leaks cross-tenant identifiers
  // =========================================================================

  describe('Response body never leaks cross-tenant identifiers', () => {
    it('physician1 batch GET response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', `/api/v1/ahcip/batches/${P1_BATCH_ID_A}`);
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
    });

    it('physician1 batch list response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
    });

    it('physician1 pending assessments response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
      expect(rawBody).not.toContain(P2_BATCH_ID_B);
    });

    it('physician1 next batch preview response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/ahcip/batches/next');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_BATCH_ID_A);
    });
  });
});
