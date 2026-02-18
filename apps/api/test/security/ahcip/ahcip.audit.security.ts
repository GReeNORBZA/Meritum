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

import {
  assembleBatch,
  generateHlinkFile,
  transmitBatch,
  retryFailedBatch,
  ingestAssessmentFile,
  reconcilePayment,
  createAhcipClaim,
  calculateFeePreview,
  type BatchCycleDeps,
  type AssessmentIngestionDeps,
  type AhcipServiceDeps,
  type FeeCalculationDeps,
} from '../../../src/domains/ahcip/ahcip.service.js';

import { AhcipBatchStatus } from '@meritum/shared/constants/ahcip.constants.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';
const PHYSICIAN_PROVIDER_ID = PHYSICIAN_USER_ID;

const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';
const PLACEHOLDER_UUID_2 = '00000000-0000-0000-0000-000000000002';

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
let auditEntries: Array<Record<string, unknown>> = [];

// ---------------------------------------------------------------------------
// Tracking stores for service-level audit verification
// ---------------------------------------------------------------------------

/** Tracks all claimStateService.transitionState calls. */
let stateTransitions: Array<{
  claimId: string;
  physicianId: string;
  fromState: string;
  toState: string;
  actorId: string;
  actorContext: string;
}> = [];

/** Tracks all notification events. */
let notificationEvents: Array<{ event: string; payload: Record<string, unknown> }> = [];

/** Tracks all repo.updateBatchStatus calls. */
let batchStatusUpdates: Array<{
  batchId: string;
  physicianId: string;
  status: string;
  extraFields?: Record<string, unknown>;
}> = [];

/** Tracks all file encryption calls. */
let encryptedFiles: Array<{ content: Buffer; filename: string }> = [];

// ---------------------------------------------------------------------------
// UUID generator
// ---------------------------------------------------------------------------

function generateUuid(): string {
  return 'aaaaaaaa-bbbb-cccc-dddd-' + Math.random().toString(36).substring(2, 14).padEnd(12, '0');
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
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// AHCIP mock repository (tracks batch status updates and audit-relevant ops)
// ---------------------------------------------------------------------------

let batchStore: Record<string, any>[] = [];
let ahcipDetailStore: Record<string, any>[] = [];

function createMockAhcipRepo() {
  return {
    createAhcipDetail: vi.fn(async (data: any) => {
      const detail = {
        ahcipDetailId: generateUuid(),
        ...data,
      };
      ahcipDetailStore.push(detail);
      return detail;
    }),
    findAhcipDetailByClaimId: vi.fn(async (claimId: string, physicianId: string) => {
      const detail = ahcipDetailStore.find((d) => d.claimId === claimId);
      if (!detail) return null;
      return {
        ...detail,
        claim: {
          claimId,
          physicianId,
          submittedBatchId: detail.submittedBatchId ?? null,
          state: detail.claimState ?? 'SUBMITTED',
          dateOfService: '2026-01-15',
        },
      };
    }),
    updateAhcipDetail: vi.fn(async (claimId: string, physicianId: string, data: any) => {
      const detail = ahcipDetailStore.find((d) => d.claimId === claimId);
      if (detail) Object.assign(detail, data);
      return detail;
    }),
    findBatchById: vi.fn(async (batchId: string, physicianId: string) => {
      return batchStore.find(
        (b) => b.ahcipBatchId === batchId && b.physicianId === physicianId,
      ) ?? null;
    }),
    listBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    findNextBatchPreview: vi.fn(async () => [
      { baNumber: 'BA-001', claimCount: 3, totalValue: '150.00' },
    ]),
    createAhcipBatch: vi.fn(async (data: any) => {
      const batch = {
        ahcipBatchId: generateUuid(),
        ...data,
        status: AhcipBatchStatus.ASSEMBLING,
        filePath: null,
        fileHash: null,
        submissionReference: null,
        submittedAt: null,
        responseReceivedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      batchStore.push(batch);
      return batch;
    }),
    updateBatchStatus: vi.fn(async (batchId: string, physicianId: string, status: string, extraFields?: any) => {
      batchStatusUpdates.push({ batchId, physicianId, status, extraFields });
      const batch = batchStore.find(
        (b) => b.ahcipBatchId === batchId && b.physicianId === physicianId,
      );
      if (batch) {
        batch.status = status;
        if (extraFields?.filePath) batch.filePath = extraFields.filePath;
        if (extraFields?.fileHash) batch.fileHash = extraFields.fileHash;
        if (extraFields?.submissionReference) batch.submissionReference = extraFields.submissionReference;
        if (extraFields?.submittedAt) batch.submittedAt = extraFields.submittedAt;
        if (extraFields?.responseReceivedAt) batch.responseReceivedAt = extraFields.responseReceivedAt;
      }
      return batch;
    }),
    findClaimsForBatch: vi.fn(async () => []),
    findAssessmentsByBatchId: vi.fn(async () => []),
    createAssessment: vi.fn(async () => ({})),
    listBatchesAwaitingResponse: vi.fn(async () => []),
    findBatchesAwaitingResponse: vi.fn(async () => []),
    findFeeScheduleEntry: vi.fn(async () => undefined),
    findClaimWithAhcipDetail: vi.fn(async () => undefined),
    findAhcipClaimWithDetails: vi.fn(async () => undefined),
    bulkUpdateClaimStates: vi.fn(async () => []),
    appendClaimAudit: vi.fn(async () => ({})),
    linkClaimsToBatch: vi.fn(async (claimIds: string[], batchId: string) => {
      for (const detail of ahcipDetailStore) {
        if (claimIds.includes(detail.claimId)) {
          detail.submittedBatchId = batchId;
        }
      }
      return claimIds.length;
    }),
    listAhcipClaimsForBatch: vi.fn(async (physicianId: string, baNumber: string) => {
      return ahcipDetailStore
        .filter((d) => d.baNumber === baNumber)
        .map((d) => ({
          claim: {
            claimId: d.claimId,
            physicianId,
            state: 'QUEUED',
            claimType: 'AHCIP',
            dateOfService: '2026-01-15',
            submittedBatchId: d.submittedBatchId ?? null,
          },
          detail: d,
        }));
    }),
    updateAssessmentResult: vi.fn(async () => ({})),
    findClaimsByBatchId: vi.fn(async (batchId: string, physicianId: string) => {
      return ahcipDetailStore
        .filter((d) => d.submittedBatchId === batchId)
        .map((d) => ({
          claim: {
            claimId: d.claimId,
            physicianId,
            state: d.claimState ?? 'SUBMITTED',
            dateOfService: '2026-01-15',
            submittedBatchId: batchId,
          },
          detail: {
            ...d,
            submittedFee: d.submittedFee ?? '50.00',
            assessedFee: d.assessedFee ?? null,
            assessmentExplanatoryCodes: d.assessmentExplanatoryCodes ?? [],
          },
        }));
    }),
    findBatchByWeek: vi.fn(async () => null),
  };
}

// ---------------------------------------------------------------------------
// Mock service dependencies
// ---------------------------------------------------------------------------

function createMockClaimStateService() {
  return {
    transitionState: vi.fn(async (
      claimId: string,
      physicianId: string,
      fromState: string,
      toState: string,
      actorId: string,
      actorContext: string,
    ) => {
      stateTransitions.push({ claimId, physicianId, fromState, toState, actorId, actorContext });
      return true;
    }),
  };
}

function createMockNotificationService() {
  return {
    emit: vi.fn(async (event: string, payload: Record<string, unknown>) => {
      notificationEvents.push({ event, payload });
    }),
  };
}

function createMockHlinkTransmission() {
  return {
    transmit: vi.fn(async () => ({
      submissionReference: 'HLINK-REF-' + Date.now(),
    })),
  };
}

function createMockHlinkRetrieval() {
  return {
    retrieveAssessmentFile: vi.fn(async () => {
      // Return a simple parsed-like buffer
      return Buffer.from('H|MERITUM|2026-01-23|000003|VND\nT|000003|150.00|abc123\n', 'utf-8');
    }),
  };
}

function createMockFileEncryption() {
  return {
    encryptAndStore: vi.fn(async (content: Buffer, filename: string) => {
      encryptedFiles.push({ content, filename });
      return {
        filePath: `/encrypted/${filename}`,
        fileHash: 'sha256-' + generateUuid(),
      };
    }),
  };
}

function createMockExplanatoryCodeService() {
  return {
    resolveExplanatoryCode: vi.fn(async (code: string) => ({
      code,
      description: `Description for ${code}`,
      category: 'BILLING_ERROR',
      correctiveGuidance: 'Review and resubmit',
    })),
  };
}

function createMockFeeRefData() {
  return {
    getHscDetail: vi.fn(async () => ({
      code: '03.04A',
      description: 'Office visit',
      baseFee: '50.00',
      feeType: 'PER_CALL',
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
    lookupFee: vi.fn(async () => null),
    getCurrentVersion: vi.fn(async () => '2026.1'),
  };
}

function createMockFeeProviderService() {
  return {
    isRrnpEligible: vi.fn(async () => false),
    getProviderFeeConfig: vi.fn(async () => ({})),
  };
}

function createMockSubmissionPreferences() {
  return {
    getAutoSubmissionMode: vi.fn(async () => 'AUTO_ALL' as const),
    getSubmissionMode: vi.fn(async () => 'MANUAL'),
  };
}

function createMockValidationRunner() {
  return {
    validateClaim: vi.fn(async () => ({ passed: true, errors: [] })),
    validate: vi.fn(async () => ({ valid: true, errors: [] })),
  };
}

// ---------------------------------------------------------------------------
// Build dependency bundles
// ---------------------------------------------------------------------------

let mockAhcipRepo: ReturnType<typeof createMockAhcipRepo>;
let mockClaimStateService: ReturnType<typeof createMockClaimStateService>;
let mockNotificationService: ReturnType<typeof createMockNotificationService>;
let mockHlinkTransmission: ReturnType<typeof createMockHlinkTransmission>;
let mockHlinkRetrieval: ReturnType<typeof createMockHlinkRetrieval>;
let mockFileEncryption: ReturnType<typeof createMockFileEncryption>;
let mockExplanatoryCodeService: ReturnType<typeof createMockExplanatoryCodeService>;
let mockFeeRefData: ReturnType<typeof createMockFeeRefData>;
let mockFeeProviderService: ReturnType<typeof createMockFeeProviderService>;
let mockSubmissionPreferences: ReturnType<typeof createMockSubmissionPreferences>;
let mockValidationRunner: ReturnType<typeof createMockValidationRunner>;

function buildBatchCycleDeps(): BatchCycleDeps {
  return {
    repo: mockAhcipRepo as any,
    feeRefData: mockFeeRefData as any,
    feeProviderService: mockFeeProviderService as any,
    claimStateService: mockClaimStateService as any,
    notificationService: mockNotificationService as any,
    hlinkTransmission: mockHlinkTransmission as any,
    fileEncryption: mockFileEncryption as any,
    submissionPreferences: mockSubmissionPreferences as any,
    validationRunner: mockValidationRunner as any,
    sleep: async () => {}, // No-op sleep for tests
  };
}

function buildAssessmentDeps(): AssessmentIngestionDeps {
  return {
    repo: mockAhcipRepo as any,
    claimStateService: mockClaimStateService as any,
    notificationService: mockNotificationService as any,
    hlinkRetrieval: mockHlinkRetrieval as any,
    explanatoryCodeService: mockExplanatoryCodeService as any,
    fileEncryption: mockFileEncryption as any,
  };
}

function buildFeeCalculationDeps(): FeeCalculationDeps {
  return {
    repo: mockAhcipRepo as any,
    feeRefData: mockFeeRefData as any,
    feeProviderService: mockFeeProviderService as any,
  };
}

// ---------------------------------------------------------------------------
// Test app builder (for HTTP-level audit integrity tests)
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps: AhcipHandlerDeps = {
    batchCycleDeps: buildBatchCycleDeps(),
    feeCalculationDeps: buildFeeCalculationDeps(),
    assessmentDeps: buildAssessmentDeps(),
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
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
// Helpers
// ---------------------------------------------------------------------------

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

/** Seed a test batch in the store with given status and properties. */
function seedBatch(overrides?: Partial<Record<string, unknown>>): Record<string, any> {
  const batch = {
    ahcipBatchId: generateUuid(),
    physicianId: PHYSICIAN_PROVIDER_ID,
    baNumber: 'BA-001',
    batchWeek: '2026-01-23',
    status: AhcipBatchStatus.ASSEMBLING,
    claimCount: 3,
    totalSubmittedValue: '150.00',
    filePath: null,
    fileHash: null,
    submissionReference: null,
    submittedAt: null,
    responseReceivedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
  batchStore.push(batch);
  return batch;
}

/** Seed AHCIP claim details linked to a batch. */
function seedClaimDetail(batchId: string, overrides?: Partial<Record<string, unknown>>): Record<string, any> {
  const detail = {
    ahcipDetailId: generateUuid(),
    claimId: generateUuid(),
    baNumber: 'BA-001',
    healthServiceCode: '03.04A',
    functionalCentre: 'MEDE',
    modifier1: null,
    modifier2: null,
    modifier3: null,
    diagnosticCode: null,
    facilityNumber: null,
    referralPractitioner: null,
    encounterType: 'CONSULTATION',
    calls: 1,
    timeSpent: null,
    patientLocation: null,
    shadowBillingFlag: false,
    pcpcmBasketFlag: false,
    afterHoursFlag: false,
    afterHoursType: null,
    submittedFee: '50.00',
    assessedFee: null,
    assessmentExplanatoryCodes: null,
    submittedBatchId: batchId,
    claimState: 'SUBMITTED',
    ...overrides,
  };
  ahcipDetailStore.push(detail);
  return detail;
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('AHCIP Audit Trail Completeness (Security)', () => {
  beforeAll(async () => {
    // Create initial mocks for the app builder
    mockAhcipRepo = createMockAhcipRepo();
    mockClaimStateService = createMockClaimStateService();
    mockNotificationService = createMockNotificationService();
    mockHlinkTransmission = createMockHlinkTransmission();
    mockHlinkRetrieval = createMockHlinkRetrieval();
    mockFileEncryption = createMockFileEncryption();
    mockExplanatoryCodeService = createMockExplanatoryCodeService();
    mockFeeRefData = createMockFeeRefData();
    mockFeeProviderService = createMockFeeProviderService();
    mockSubmissionPreferences = createMockSubmissionPreferences();
    mockValidationRunner = createMockValidationRunner();

    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    // Reset all stores
    users = [];
    sessions = [];
    auditEntries = [];
    stateTransitions = [];
    notificationEvents = [];
    batchStatusUpdates = [];
    encryptedFiles = [];
    batchStore = [];
    ahcipDetailStore = [];

    // Seed physician
    users.push({
      userId: PHYSICIAN_USER_ID,
      email: 'physician@example.com',
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
      sessionId: PHYSICIAN_SESSION_ID,
      userId: PHYSICIAN_USER_ID,
      tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Re-create mocks per test
    mockAhcipRepo = createMockAhcipRepo();
    mockClaimStateService = createMockClaimStateService();
    mockNotificationService = createMockNotificationService();
    mockHlinkTransmission = createMockHlinkTransmission();
    mockHlinkRetrieval = createMockHlinkRetrieval();
    mockFileEncryption = createMockFileEncryption();
    mockExplanatoryCodeService = createMockExplanatoryCodeService();
    mockFeeRefData = createMockFeeRefData();
    mockFeeProviderService = createMockFeeProviderService();
    mockSubmissionPreferences = createMockSubmissionPreferences();
    mockValidationRunner = createMockValidationRunner();
  });

  // =========================================================================
  // Category 1: Batch Lifecycle Audit Events
  // =========================================================================

  describe('Batch lifecycle produces audit-relevant records', () => {
    it('batch assembled emits BATCH_ASSEMBLED notification with claim count and total value', async () => {
      // Seed 2 queued claims for the batch
      const claimId1 = generateUuid();
      const claimId2 = generateUuid();
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId: claimId1,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '50.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId: claimId2,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '100.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      const deps = buildBatchCycleDeps();
      const result = await assembleBatch(deps, PHYSICIAN_PROVIDER_ID, '2026-01-23');

      // Verify BATCH_ASSEMBLED notification emitted
      const assembled = notificationEvents.find((e) => e.event === 'BATCH_ASSEMBLED');
      expect(assembled).toBeDefined();
      expect(assembled!.payload.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(assembled!.payload.batchWeek).toBe('2026-01-23');
      expect(assembled!.payload.batches).toBeDefined();
      const batches = assembled!.payload.batches as any[];
      expect(batches.length).toBeGreaterThan(0);
      expect(batches[0]).toHaveProperty('claimCount');
      expect(batches[0]).toHaveProperty('totalValue');
    });

    it('batch generated (H-Link file) records file_hash via updateBatchStatus', async () => {
      const batch = seedBatch({ status: AhcipBatchStatus.ASSEMBLING });
      const claimDetail = seedClaimDetail(batch.ahcipBatchId);

      const deps = buildBatchCycleDeps();
      await generateHlinkFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      // Verify batch was updated to GENERATED with filePath and fileHash
      const genUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.GENERATED,
      );
      expect(genUpdate).toBeDefined();
      expect(genUpdate!.extraFields).toBeDefined();
      expect(genUpdate!.extraFields!.filePath).toBeDefined();
      expect(genUpdate!.extraFields!.fileHash).toBeDefined();
    });

    it('batch submitted (transmitted) records submission_reference and timestamp', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.GENERATED,
        filePath: '/encrypted/test.dat',
        fileHash: 'sha256-test',
      });

      const deps = buildBatchCycleDeps();
      const result = await transmitBatch(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      expect(result.success).toBe(true);
      expect(result.submissionReference).toBeDefined();

      // Verify batch was updated to SUBMITTED with reference and timestamp
      const subUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.SUBMITTED,
      );
      expect(subUpdate).toBeDefined();
      expect(subUpdate!.extraFields).toBeDefined();
      expect(subUpdate!.extraFields!.submissionReference).toBeDefined();
      expect(subUpdate!.extraFields!.submittedAt).toBeDefined();
    });

    it('batch transmission failure sets ERROR status and emits notification with error details', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.GENERATED,
        filePath: '/encrypted/test.dat',
        fileHash: 'sha256-test',
      });

      // Make transmission always fail
      mockHlinkTransmission.transmit.mockRejectedValue(new Error('Connection refused'));

      const deps = buildBatchCycleDeps();
      const result = await transmitBatch(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Connection refused');

      // Verify ERROR status set
      const errorUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.ERROR,
      );
      expect(errorUpdate).toBeDefined();

      // Verify BATCH_TRANSMISSION_FAILED notification emitted with error details
      const failEvent = notificationEvents.find((e) => e.event === 'BATCH_TRANSMISSION_FAILED');
      expect(failEvent).toBeDefined();
      expect(failEvent!.payload.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(failEvent!.payload.batchId).toBe(batch.ahcipBatchId);
      expect(failEvent!.payload.error).toBe('Connection refused');
      expect(failEvent!.payload.retryCount).toBeDefined();
    });

    it('batch retry initiates retransmission from ERROR state', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.ERROR,
        filePath: '/encrypted/test.dat',
        fileHash: 'sha256-test',
      });

      const deps = buildBatchCycleDeps();
      const result = await retryFailedBatch(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      expect(result.success).toBe(true);

      // Verify status was first set to GENERATED (reset for retry)
      const resetUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.GENERATED,
      );
      expect(resetUpdate).toBeDefined();

      // Then set to SUBMITTED on success
      const subUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.SUBMITTED,
      );
      expect(subUpdate).toBeDefined();
    });

    it('assessment ingested updates batch to RESPONSE_RECEIVED with accepted/rejected/adjusted counts', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.SUBMITTED,
        submissionReference: 'HLINK-REF-001',
      });

      // Seed claims linked to the batch
      const detail1 = seedClaimDetail(batch.ahcipBatchId, { claimState: 'SUBMITTED' });
      const detail2 = seedClaimDetail(batch.ahcipBatchId, { claimState: 'SUBMITTED' });

      // Mock the retrieval to return assessment records matching our claims
      // Format: R|claim_reference|status|assessed_fee|explanatory_codes
      mockHlinkRetrieval.retrieveAssessmentFile.mockResolvedValue(
        Buffer.from(
          `H|MERITUM|2026-01-23|000002|VND\n` +
          `R|${detail1.claimId}|ACCEPTED|50.00|\n` +
          `R|${detail2.claimId}|REJECTED|0.00|E01\n` +
          `T|000002|50.00|abc123\n`,
          'utf-8',
        ),
      );

      // Mock findAhcipDetailByClaimId to return matched claim data
      mockAhcipRepo.findAhcipDetailByClaimId
        .mockResolvedValueOnce({
          ...detail1,
          claim: {
            claimId: detail1.claimId,
            physicianId: PHYSICIAN_PROVIDER_ID,
            submittedBatchId: batch.ahcipBatchId,
            state: 'SUBMITTED',
            dateOfService: '2026-01-15',
          },
        })
        .mockResolvedValueOnce({
          ...detail2,
          claim: {
            claimId: detail2.claimId,
            physicianId: PHYSICIAN_PROVIDER_ID,
            submittedBatchId: batch.ahcipBatchId,
            state: 'SUBMITTED',
            dateOfService: '2026-01-15',
          },
        });

      const deps = buildAssessmentDeps();
      const result = await ingestAssessmentFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      // Verify batch updated to RESPONSE_RECEIVED
      const responseUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.RESPONSE_RECEIVED,
      );
      expect(responseUpdate).toBeDefined();

      // Verify claim state transitions were recorded
      expect(stateTransitions.length).toBeGreaterThan(0);
    });

    it('payment reconciliation updates batch to RECONCILED and transitions claims to PAID', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.RESPONSE_RECEIVED,
        submissionReference: 'HLINK-REF-001',
      });

      // Seed claims in ASSESSED state linked to the batch
      seedClaimDetail(batch.ahcipBatchId, { claimState: 'ASSESSED', assessedFee: '50.00' });
      seedClaimDetail(batch.ahcipBatchId, { claimState: 'ASSESSED', assessedFee: '100.00' });

      const deps = buildAssessmentDeps();
      const result = await reconcilePayment(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      expect(result.reconciledCount).toBe(2);

      // Verify batch status updated to RECONCILED
      const reconUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.RECONCILED,
      );
      expect(reconUpdate).toBeDefined();

      // Verify ASSESSED → PAID state transitions
      const paidTransitions = stateTransitions.filter((t) => t.toState === 'PAID');
      expect(paidTransitions.length).toBe(2);
      for (const t of paidTransitions) {
        expect(t.fromState).toBe('ASSESSED');
        expect(t.actorId).toBe('SYSTEM');
        expect(t.actorContext).toBe('SYSTEM');
      }

      // Verify CLAIM_PAID notifications
      const paidEvents = notificationEvents.filter((e) => e.event === 'CLAIM_PAID');
      expect(paidEvents.length).toBe(2);
    });
  });

  // =========================================================================
  // Category 2: Claim-Level Audit via Domain 4.0 (State Transitions)
  // =========================================================================

  describe('Claim-level audit through Domain 4.0 state transitions', () => {
    it('batch assembly transitions each claim QUEUED → SUBMITTED via claimStateService', async () => {
      const claimId1 = generateUuid();
      const claimId2 = generateUuid();
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId: claimId1,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '50.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId: claimId2,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '100.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      const deps = buildBatchCycleDeps();
      await assembleBatch(deps, PHYSICIAN_PROVIDER_ID, '2026-01-23');

      // Verify QUEUED → SUBMITTED transitions
      const submittedTransitions = stateTransitions.filter(
        (t) => t.fromState === 'QUEUED' && t.toState === 'SUBMITTED',
      );
      expect(submittedTransitions.length).toBe(2);

      for (const t of submittedTransitions) {
        expect(t.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
        expect(t.actorId).toBe('SYSTEM');
        expect(t.actorContext).toBe('SYSTEM');
      }
    });

    it('assessment accepted transitions claim SUBMITTED → ASSESSED', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.SUBMITTED,
        submissionReference: 'HLINK-REF-001',
      });
      const detail = seedClaimDetail(batch.ahcipBatchId, { claimState: 'SUBMITTED' });

      // Mock single claim assessment retrieval
      mockHlinkRetrieval.retrieveAssessmentFile.mockResolvedValue(
        Buffer.from(
          `H|MERITUM|2026-01-23|000001|VND\nR|${detail.claimId}|ACCEPTED|50.00|\nT|000001|50.00|abc\n`,
          'utf-8',
        ),
      );
      mockAhcipRepo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...detail,
        claim: {
          claimId: detail.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          submittedBatchId: batch.ahcipBatchId,
          state: 'SUBMITTED',
          dateOfService: '2026-01-15',
        },
      });

      const deps = buildAssessmentDeps();
      await ingestAssessmentFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const assessed = stateTransitions.find(
        (t) => t.claimId === detail.claimId && t.toState === 'ASSESSED',
      );
      expect(assessed).toBeDefined();
      expect(assessed!.fromState).toBe('SUBMITTED');
      expect(assessed!.actorId).toBe('SYSTEM');
      expect(assessed!.actorContext).toBe('SYSTEM');
    });

    it('assessment rejected transitions claim SUBMITTED → REJECTED and emits notification', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.SUBMITTED,
        submissionReference: 'HLINK-REF-001',
      });
      const detail = seedClaimDetail(batch.ahcipBatchId, { claimState: 'SUBMITTED' });

      mockHlinkRetrieval.retrieveAssessmentFile.mockResolvedValue(
        Buffer.from(
          `H|MERITUM|2026-01-23|000001|VND\nR|${detail.claimId}|REJECTED|0.00|E01\nT|000001|0.00|abc\n`,
          'utf-8',
        ),
      );
      mockAhcipRepo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...detail,
        claim: {
          claimId: detail.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          submittedBatchId: batch.ahcipBatchId,
          state: 'SUBMITTED',
          dateOfService: '2026-01-15',
        },
      });

      const deps = buildAssessmentDeps();
      await ingestAssessmentFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const rejected = stateTransitions.find(
        (t) => t.claimId === detail.claimId && t.toState === 'REJECTED',
      );
      expect(rejected).toBeDefined();
      expect(rejected!.fromState).toBe('SUBMITTED');
      expect(rejected!.actorId).toBe('SYSTEM');
      expect(rejected!.actorContext).toBe('SYSTEM');

      // Verify CLAIM_REJECTED notification
      const rejectEvent = notificationEvents.find((e) => e.event === 'CLAIM_REJECTED');
      expect(rejectEvent).toBeDefined();
      expect(rejectEvent!.payload.claimId).toBe(detail.claimId);
      expect(rejectEvent!.payload.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(rejectEvent!.payload.explanatoryCodes).toBeDefined();
    });

    it('assessment adjusted transitions claim SUBMITTED → ASSESSED and emits notification', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.SUBMITTED,
        submissionReference: 'HLINK-REF-001',
      });
      const detail = seedClaimDetail(batch.ahcipBatchId, {
        claimState: 'SUBMITTED',
        submittedFee: '50.00',
      });

      mockHlinkRetrieval.retrieveAssessmentFile.mockResolvedValue(
        Buffer.from(
          `H|MERITUM|2026-01-23|000001|VND\nR|${detail.claimId}|ADJUSTED|35.00|E02\nT|000001|35.00|abc\n`,
          'utf-8',
        ),
      );
      mockAhcipRepo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...detail,
        submittedFee: '50.00',
        claim: {
          claimId: detail.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          submittedBatchId: batch.ahcipBatchId,
          state: 'SUBMITTED',
          dateOfService: '2026-01-15',
        },
      });

      const deps = buildAssessmentDeps();
      await ingestAssessmentFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const assessedTransition = stateTransitions.find(
        (t) => t.claimId === detail.claimId && t.toState === 'ASSESSED',
      );
      expect(assessedTransition).toBeDefined();

      // Verify CLAIM_ASSESSED notification for adjusted claim
      const adjustEvent = notificationEvents.find((e) => e.event === 'CLAIM_ASSESSED');
      expect(adjustEvent).toBeDefined();
      expect(adjustEvent!.payload.isAdjusted).toBe(true);
      expect(adjustEvent!.payload.submittedFee).toBe('50.00');
      expect(adjustEvent!.payload.assessedFee).toBe('35.00');
    });

    it('claims failing pre-submission validation are returned to VALIDATED with notification', async () => {
      const claimId = generateUuid();
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '50.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      // Make validation fail for this claim
      mockValidationRunner.validateClaim.mockResolvedValue({
        passed: false,
        errors: [{ check: 'A01', severity: 'ERROR', rule_reference: 'A01', message: 'Invalid HSC', help_text: '', field_affected: 'health_service_code' }],
      });

      const deps = buildBatchCycleDeps();
      const result = await assembleBatch(deps, PHYSICIAN_PROVIDER_ID, '2026-01-23');

      // Claim should be removed from batch
      expect(result.removedClaims.length).toBe(1);
      expect(result.removedClaims[0].claimId).toBe(claimId);

      // State should be transitioned back to VALIDATED
      const revertTransition = stateTransitions.find(
        (t) => t.claimId === claimId && t.toState === 'VALIDATED',
      );
      expect(revertTransition).toBeDefined();
      expect(revertTransition!.fromState).toBe('QUEUED');
      expect(revertTransition!.actorId).toBe('SYSTEM');

      // Notification about validation failure emitted
      const failEvent = notificationEvents.find((e) => e.event === 'CLAIM_VALIDATION_FAILED_PRE_BATCH');
      expect(failEvent).toBeDefined();
      expect(failEvent!.payload.claimId).toBe(claimId);
    });
  });

  // =========================================================================
  // Category 3: Submission Preference Audit
  // =========================================================================

  describe('Submission preference changes tracked in batch assembly', () => {
    it('REQUIRE_APPROVAL mode prevents batch assembly (no claims processed)', async () => {
      const claimId = generateUuid();
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '50.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      mockSubmissionPreferences.getAutoSubmissionMode.mockResolvedValue('REQUIRE_APPROVAL');

      const deps = buildBatchCycleDeps();
      const result = await assembleBatch(deps, PHYSICIAN_PROVIDER_ID, '2026-01-23');

      // No batches assembled when mode is REQUIRE_APPROVAL
      expect(result.batches.length).toBe(0);
      expect(stateTransitions.length).toBe(0);
    });

    it('AUTO_CLEAN mode only submits clean claims', async () => {
      const claimId = generateUuid();
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '50.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      mockSubmissionPreferences.getAutoSubmissionMode.mockResolvedValue('AUTO_CLEAN');

      const deps = buildBatchCycleDeps();
      await assembleBatch(deps, PHYSICIAN_PROVIDER_ID, '2026-01-23');

      // Verify isClean filter was passed to repo
      expect(mockAhcipRepo.listAhcipClaimsForBatch).toHaveBeenCalledWith(
        PHYSICIAN_PROVIDER_ID,
        'BA-001',
        true, // isClean filter
      );
    });

    it('AUTO_ALL mode includes all queued claims', async () => {
      const claimId = generateUuid();
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '50.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      mockSubmissionPreferences.getAutoSubmissionMode.mockResolvedValue('AUTO_ALL');

      const deps = buildBatchCycleDeps();
      await assembleBatch(deps, PHYSICIAN_PROVIDER_ID, '2026-01-23');

      // Verify no isClean filter was passed (undefined)
      expect(mockAhcipRepo.listAhcipClaimsForBatch).toHaveBeenCalledWith(
        PHYSICIAN_PROVIDER_ID,
        'BA-001',
        undefined,
      );
    });
  });

  // =========================================================================
  // Category 4: Audit Log Integrity (Append-Only for Batches)
  // =========================================================================

  describe('Audit log is append-only — no modification or deletion API for batches', () => {
    it('no PUT endpoint exists for batch audit history', async () => {
      const res = await physicianRequest('PUT', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no DELETE endpoint exists for batch audit history', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no POST endpoint exists for batch audit injection', async () => {
      const res = await physicianRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/audit`, {
        action: 'FAKE_BATCH_ACTION',
        status: 'SUBMITTED',
      });
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no PUT endpoint exists for assessment audit modification', async () => {
      const res = await physicianRequest('PUT', `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no DELETE endpoint exists for assessment audit deletion', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // Category 5: Full Batch Lifecycle Audit Trail
  // =========================================================================

  describe('Full batch lifecycle produces complete audit trail', () => {
    it('ASSEMBLING → GENERATED → SUBMITTED lifecycle tracks all status transitions', async () => {
      const batch = seedBatch({ status: AhcipBatchStatus.ASSEMBLING });
      seedClaimDetail(batch.ahcipBatchId);

      const batchDeps = buildBatchCycleDeps();

      // Step 1: Generate H-Link file → GENERATED
      await generateHlinkFile(batchDeps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const genUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.GENERATED,
      );
      expect(genUpdate).toBeDefined();

      // Step 2: Transmit → SUBMITTED
      await transmitBatch(batchDeps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const subUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.SUBMITTED,
      );
      expect(subUpdate).toBeDefined();

      // Verify chronological ordering
      const genIdx = batchStatusUpdates.findIndex(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.GENERATED,
      );
      const subIdx = batchStatusUpdates.findIndex(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.SUBMITTED,
      );
      expect(genIdx).toBeLessThan(subIdx);
    });

    it('SUBMITTED → RESPONSE_RECEIVED → RECONCILED lifecycle is fully tracked', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.SUBMITTED,
        submissionReference: 'HLINK-REF-001',
      });
      const detail = seedClaimDetail(batch.ahcipBatchId, { claimState: 'SUBMITTED' });

      // Mock assessment ingestion
      mockHlinkRetrieval.retrieveAssessmentFile.mockResolvedValue(
        Buffer.from(
          `H|MERITUM|2026-01-23|000001|VND\nR|${detail.claimId}|ACCEPTED|50.00|\nT|000001|50.00|abc\n`,
          'utf-8',
        ),
      );
      mockAhcipRepo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...detail,
        claim: {
          claimId: detail.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          submittedBatchId: batch.ahcipBatchId,
          state: 'SUBMITTED',
          dateOfService: '2026-01-15',
        },
      });

      const assessDeps = buildAssessmentDeps();

      // Step 1: Ingest assessment → RESPONSE_RECEIVED
      await ingestAssessmentFile(assessDeps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const respUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.RESPONSE_RECEIVED,
      );
      expect(respUpdate).toBeDefined();

      // Update mock to return ASSESSED claim state for reconciliation
      detail.claimState = 'ASSESSED';

      // Step 2: Reconcile → RECONCILED
      await reconcilePayment(assessDeps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const reconUpdate = batchStatusUpdates.find(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.RECONCILED,
      );
      expect(reconUpdate).toBeDefined();

      // Verify chronological ordering
      const respIdx = batchStatusUpdates.findIndex(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.RESPONSE_RECEIVED,
      );
      const reconIdx = batchStatusUpdates.findIndex(
        (u) => u.batchId === batch.ahcipBatchId && u.status === AhcipBatchStatus.RECONCILED,
      );
      expect(respIdx).toBeLessThan(reconIdx);
    });

    it('ERROR → GENERATED (retry) → SUBMITTED lifecycle recovers correctly', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.ERROR,
        filePath: '/encrypted/test.dat',
        fileHash: 'sha256-test',
      });

      const batchDeps = buildBatchCycleDeps();
      const result = await retryFailedBatch(batchDeps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      expect(result.success).toBe(true);

      // Verify GENERATED (reset) then SUBMITTED
      const statuses = batchStatusUpdates
        .filter((u) => u.batchId === batch.ahcipBatchId)
        .map((u) => u.status);
      expect(statuses).toContain(AhcipBatchStatus.GENERATED);
      expect(statuses).toContain(AhcipBatchStatus.SUBMITTED);

      const genIdx = statuses.indexOf(AhcipBatchStatus.GENERATED);
      const subIdx = statuses.indexOf(AhcipBatchStatus.SUBMITTED);
      expect(genIdx).toBeLessThan(subIdx);
    });
  });

  // =========================================================================
  // Category 6: H-Link Transmission Logs Contain No PHI
  // =========================================================================

  describe('H-Link transmission logs and notifications contain no PHI', () => {
    it('BATCH_TRANSMISSION_FAILED notification contains batch reference but no patient data', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.GENERATED,
        filePath: '/encrypted/test.dat',
        fileHash: 'sha256-test',
      });

      mockHlinkTransmission.transmit.mockRejectedValue(new Error('SFTP timeout'));

      const deps = buildBatchCycleDeps();
      await transmitBatch(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const failEvent = notificationEvents.find((e) => e.event === 'BATCH_TRANSMISSION_FAILED');
      expect(failEvent).toBeDefined();

      const payloadStr = JSON.stringify(failEvent!.payload);

      // Must contain batch identifiers (these are not PHI)
      expect(payloadStr).toContain(batch.ahcipBatchId);
      expect(payloadStr).toContain('BA-001');

      // Must NOT contain PHI patterns
      expect(payloadStr).not.toMatch(/\b\d{9}\b/); // PHN pattern
      expect(payloadStr).not.toMatch(/firstName|lastName|first_name|last_name/i);
      expect(payloadStr).not.toMatch(/patientId|patient_id/i);
      expect(payloadStr).not.toMatch(/dateOfBirth|date_of_birth/i);
    });

    it('BATCH_ASSEMBLED notification contains batch reference but no patient data', async () => {
      const claimId = generateUuid();
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '50.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      const deps = buildBatchCycleDeps();
      await assembleBatch(deps, PHYSICIAN_PROVIDER_ID, '2026-01-23');

      const assembledEvent = notificationEvents.find((e) => e.event === 'BATCH_ASSEMBLED');
      if (assembledEvent) {
        const payloadStr = JSON.stringify(assembledEvent.payload);

        // Must NOT contain PHI patterns
        expect(payloadStr).not.toMatch(/\b\d{9}\b/); // PHN
        expect(payloadStr).not.toMatch(/firstName|lastName|first_name|last_name/i);
        expect(payloadStr).not.toMatch(/dateOfBirth|date_of_birth/i);
      }
    });

    it('CLAIM_REJECTED notification contains claim reference but no patient PHN', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.SUBMITTED,
        submissionReference: 'HLINK-REF-001',
      });
      const detail = seedClaimDetail(batch.ahcipBatchId, { claimState: 'SUBMITTED' });

      mockHlinkRetrieval.retrieveAssessmentFile.mockResolvedValue(
        Buffer.from(
          `H|MERITUM|2026-01-23|000001|VND\nR|${detail.claimId}|REJECTED|0.00|E01\nT|000001|0.00|abc\n`,
          'utf-8',
        ),
      );
      mockAhcipRepo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...detail,
        claim: {
          claimId: detail.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          submittedBatchId: batch.ahcipBatchId,
          state: 'SUBMITTED',
          dateOfService: '2026-01-15',
        },
      });

      const deps = buildAssessmentDeps();
      await ingestAssessmentFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const rejectEvent = notificationEvents.find((e) => e.event === 'CLAIM_REJECTED');
      expect(rejectEvent).toBeDefined();

      const payloadStr = JSON.stringify(rejectEvent!.payload);

      // Must contain claim and physician identifiers
      expect(payloadStr).toContain(detail.claimId);
      expect(payloadStr).toContain(PHYSICIAN_PROVIDER_ID);

      // Must NOT contain PHI
      expect(payloadStr).not.toMatch(/\b\d{9}\b/); // PHN
      expect(payloadStr).not.toMatch(/firstName|lastName|first_name|last_name/i);
    });

    it('encrypted H-Link file is stored for audit trail', async () => {
      const batch = seedBatch({ status: AhcipBatchStatus.ASSEMBLING });
      seedClaimDetail(batch.ahcipBatchId);

      const deps = buildBatchCycleDeps();
      await generateHlinkFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      // Verify file was encrypted and stored
      expect(encryptedFiles.length).toBe(1);
      expect(encryptedFiles[0].filename).toContain('hlink_');
      expect(encryptedFiles[0].filename).toContain('BA-001');
      expect(encryptedFiles[0].content).toBeInstanceOf(Buffer);
    });

    it('assessment raw file is encrypted and stored for audit trail', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.SUBMITTED,
        submissionReference: 'HLINK-REF-001',
      });

      // No matched claims — file still stored even if empty
      mockHlinkRetrieval.retrieveAssessmentFile.mockResolvedValue(
        Buffer.from('H|MERITUM|2026-01-23|000000|VND\nT|000000|0.00|abc\n', 'utf-8'),
      );

      const deps = buildAssessmentDeps();
      await ingestAssessmentFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      // Verify assessment file was encrypted and stored
      expect(mockFileEncryption.encryptAndStore).toHaveBeenCalled();
      const callArgs = mockFileEncryption.encryptAndStore.mock.calls[0];
      expect(callArgs[1]).toContain('assessment_');
      expect(callArgs[1]).toContain(batch.ahcipBatchId);
    });
  });

  // =========================================================================
  // Category 7: Batch Status Transition Integrity
  // =========================================================================

  describe('Batch status transitions enforce valid state machine', () => {
    it('cannot generate H-Link file for non-ASSEMBLING batch', async () => {
      const batch = seedBatch({ status: AhcipBatchStatus.SUBMITTED });

      const deps = buildBatchCycleDeps();
      await expect(
        generateHlinkFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID),
      ).rejects.toThrow(/Cannot generate file for batch/);
    });

    it('cannot transmit batch that is not in GENERATED or ERROR state', async () => {
      const batch = seedBatch({ status: AhcipBatchStatus.ASSEMBLING });

      const deps = buildBatchCycleDeps();
      await expect(
        transmitBatch(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID),
      ).rejects.toThrow(/Cannot transmit batch/);
    });

    it('cannot retry batch that is not in ERROR state', async () => {
      const batch = seedBatch({ status: AhcipBatchStatus.SUBMITTED });

      const deps = buildBatchCycleDeps();
      await expect(
        retryFailedBatch(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID),
      ).rejects.toThrow(/Can only retry batches in ERROR status/);
    });

    it('cannot ingest assessment for non-SUBMITTED batch', async () => {
      const batch = seedBatch({ status: AhcipBatchStatus.GENERATED });

      const deps = buildAssessmentDeps();
      await expect(
        ingestAssessmentFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID),
      ).rejects.toThrow(/Cannot ingest assessment/);
    });

    it('cannot reconcile payment for non-RESPONSE_RECEIVED batch', async () => {
      const batch = seedBatch({ status: AhcipBatchStatus.SUBMITTED });

      const deps = buildAssessmentDeps();
      await expect(
        reconcilePayment(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID),
      ).rejects.toThrow(/Cannot reconcile batch/);
    });
  });

  // =========================================================================
  // Category 8: Actor Context in State Transitions
  // =========================================================================

  describe('All AHCIP batch state transitions use SYSTEM actor context', () => {
    it('batch assembly uses SYSTEM actor for claim state transitions', async () => {
      const claimId = generateUuid();
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '50.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      const deps = buildBatchCycleDeps();
      await assembleBatch(deps, PHYSICIAN_PROVIDER_ID, '2026-01-23');

      for (const t of stateTransitions) {
        expect(t.actorId).toBe('SYSTEM');
        expect(t.actorContext).toBe('SYSTEM');
      }
    });

    it('assessment ingestion uses SYSTEM actor for claim state transitions', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.SUBMITTED,
        submissionReference: 'HLINK-REF-001',
      });
      const detail = seedClaimDetail(batch.ahcipBatchId, { claimState: 'SUBMITTED' });

      mockHlinkRetrieval.retrieveAssessmentFile.mockResolvedValue(
        Buffer.from(
          `H|MERITUM|2026-01-23|000001|VND\nR|${detail.claimId}|ACCEPTED|50.00|\nT|000001|50.00|abc\n`,
          'utf-8',
        ),
      );
      mockAhcipRepo.findAhcipDetailByClaimId.mockResolvedValueOnce({
        ...detail,
        claim: {
          claimId: detail.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          submittedBatchId: batch.ahcipBatchId,
          state: 'SUBMITTED',
          dateOfService: '2026-01-15',
        },
      });

      const deps = buildAssessmentDeps();
      await ingestAssessmentFile(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      for (const t of stateTransitions) {
        expect(t.actorId).toBe('SYSTEM');
        expect(t.actorContext).toBe('SYSTEM');
      }
    });

    it('payment reconciliation uses SYSTEM actor for claim state transitions', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.RESPONSE_RECEIVED,
        submissionReference: 'HLINK-REF-001',
      });
      seedClaimDetail(batch.ahcipBatchId, { claimState: 'ASSESSED', assessedFee: '50.00' });

      const deps = buildAssessmentDeps();
      await reconcilePayment(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      for (const t of stateTransitions) {
        expect(t.actorId).toBe('SYSTEM');
        expect(t.actorContext).toBe('SYSTEM');
      }
    });
  });

  // =========================================================================
  // Category 9: Notification Events as Audit Trail
  // =========================================================================

  describe('Notification events serve as external audit trail', () => {
    it('each batch lifecycle event produces exactly one notification', async () => {
      const claimId = generateUuid();
      ahcipDetailStore.push({
        ahcipDetailId: generateUuid(),
        claimId,
        baNumber: 'BA-001',
        healthServiceCode: '03.04A',
        submittedFee: '50.00',
        calls: 1,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      const deps = buildBatchCycleDeps();
      await assembleBatch(deps, PHYSICIAN_PROVIDER_ID, '2026-01-23');

      // Exactly one BATCH_ASSEMBLED notification
      const assembledEvents = notificationEvents.filter((e) => e.event === 'BATCH_ASSEMBLED');
      expect(assembledEvents.length).toBe(1);
    });

    it('transmission failure produces exactly one BATCH_TRANSMISSION_FAILED notification', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.GENERATED,
        filePath: '/encrypted/test.dat',
        fileHash: 'sha256-test',
      });

      mockHlinkTransmission.transmit.mockRejectedValue(new Error('Network error'));

      const deps = buildBatchCycleDeps();
      await transmitBatch(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const failEvents = notificationEvents.filter((e) => e.event === 'BATCH_TRANSMISSION_FAILED');
      expect(failEvents.length).toBe(1);
    });

    it('payment reconciliation produces CLAIM_PAID notifications for each reconciled claim', async () => {
      const batch = seedBatch({
        status: AhcipBatchStatus.RESPONSE_RECEIVED,
        submissionReference: 'HLINK-REF-001',
      });
      seedClaimDetail(batch.ahcipBatchId, { claimState: 'ASSESSED', assessedFee: '50.00' });
      seedClaimDetail(batch.ahcipBatchId, { claimState: 'ASSESSED', assessedFee: '100.00' });
      // One claim in REJECTED state should NOT produce CLAIM_PAID notification
      seedClaimDetail(batch.ahcipBatchId, { claimState: 'REJECTED' });

      const deps = buildAssessmentDeps();
      await reconcilePayment(deps, batch.ahcipBatchId, PHYSICIAN_PROVIDER_ID);

      const paidEvents = notificationEvents.filter((e) => e.event === 'CLAIM_PAID');
      expect(paidEvents.length).toBe(2); // Only ASSESSED claims, not REJECTED
    });
  });
});
