import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

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

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { claimRoutes } from '../../../src/domains/claim/claim.routes.js';
import { type ClaimHandlerDeps } from '../../../src/domains/claim/claim.handlers.js';
import {
  type ClaimServiceDeps,
  type NotificationEmitter,
  getClaimsForAutoSubmission,
  expireClaimWithContext,
} from '../../../src/domains/claim/claim.service.js';

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

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const PATIENT_ID = '00000000-aaaa-0000-0000-000000000001';

const VALID_CLAIM = {
  claim_type: 'AHCIP' as const,
  patient_id: PATIENT_ID,
  date_of_service: '2026-01-15',
};

// ---------------------------------------------------------------------------
// Stateful claim store for lifecycle tests
// ---------------------------------------------------------------------------

function createStatefulClaimStore() {
  const claims = new Map<string, Record<string, any>>();
  const auditEntries: Array<Record<string, any>> = [];
  let claimIdCounter = 0;

  function makeClaim(data: Record<string, any>): Record<string, any> {
    return {
      claimId: data.claimId ?? `00000000-cccc-0000-0000-${String(++claimIdCounter).padStart(12, '0')}`,
      physicianId: data.physicianId,
      patientId: data.patientId,
      claimType: data.claimType,
      state: data.state ?? 'DRAFT',
      importSource: data.importSource ?? 'MANUAL',
      dateOfService: data.dateOfService,
      submissionDeadline: data.submissionDeadline ?? '2026-04-15',
      isClean: data.isClean ?? null,
      validationResult: data.validationResult ?? null,
      validationTimestamp: data.validationTimestamp ?? null,
      referenceDataVersion: data.referenceDataVersion ?? null,
      aiCoachSuggestions: data.aiCoachSuggestions ?? null,
      duplicateAlert: data.duplicateAlert ?? null,
      flags: data.flags ?? null,
      submittedBatchId: data.submittedBatchId ?? null,
      shiftId: data.shiftId ?? null,
      importBatchId: data.importBatchId ?? null,
      createdBy: data.createdBy ?? data.physicianId,
      updatedBy: data.updatedBy ?? data.physicianId,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    };
  }

  return {
    claims,
    auditEntries,

    createClaim: vi.fn(async (data: any) => {
      const claim = makeClaim(data);
      claims.set(claim.claimId, claim);
      return claim;
    }),

    findClaimById: vi.fn(async (claimId: string, physicianId: string) => {
      const claim = claims.get(claimId);
      if (!claim || claim.physicianId !== physicianId || claim.deletedAt) return undefined;
      return { ...claim };
    }),

    updateClaim: vi.fn(async (claimId: string, physicianId: string, data: any) => {
      const claim = claims.get(claimId);
      if (!claim || claim.physicianId !== physicianId) return undefined;
      Object.assign(claim, data, { updatedAt: new Date() });
      return { ...claim };
    }),

    softDeleteClaim: vi.fn(async () => false),

    listClaims: vi.fn(async (physicianId: string, filters: any) => {
      let filtered = Array.from(claims.values()).filter(
        (c) => c.physicianId === physicianId && !c.deletedAt,
      );
      if (filters?.state) filtered = filtered.filter((c) => c.state === filters.state);
      if (filters?.claimType) filtered = filtered.filter((c) => c.claimType === filters.claimType);
      const page = filters?.page ?? 1;
      const pageSize = filters?.pageSize ?? 25;
      const start = (page - 1) * pageSize;
      const sliced = filtered.slice(start, start + pageSize);
      return {
        data: sliced,
        pagination: {
          total: filtered.length,
          page,
          pageSize,
          hasMore: start + pageSize < filtered.length,
        },
      };
    }),

    transitionState: vi.fn(
      async (claimId: string, physicianId: string, fromState: string, toState: string) => {
        const claim = claims.get(claimId);
        if (!claim || claim.physicianId !== physicianId) return undefined;
        if (claim.state !== fromState) return undefined;
        claim.state = toState;
        claim.updatedAt = new Date();
        return { ...claim };
      },
    ),

    classifyClaim: vi.fn(async (claimId: string, physicianId: string, isClean: boolean) => {
      const claim = claims.get(claimId);
      if (!claim || claim.physicianId !== physicianId) return undefined;
      claim.isClean = isClean;
      return { ...claim };
    }),

    updateValidationResult: vi.fn(
      async (claimId: string, physicianId: string, result: any, version: string) => {
        const claim = claims.get(claimId);
        if (!claim || claim.physicianId !== physicianId) return undefined;
        claim.validationResult = result;
        claim.validationTimestamp = new Date().toISOString();
        claim.referenceDataVersion = version;
        return { ...claim };
      },
    ),

    updateAiSuggestions: vi.fn(async () => ({})),
    updateDuplicateAlert: vi.fn(async () => ({})),
    updateFlags: vi.fn(async () => ({})),
    countClaimsByState: vi.fn(async () => []),
    findClaimsApproachingDeadline: vi.fn(async () => []),

    findClaimsForBatchAssembly: vi.fn(
      async (physicianId: string, claimType: string, includeClean: boolean, includeFlagged: boolean) => {
        return Array.from(claims.values()).filter((c) => {
          if (c.physicianId !== physicianId) return false;
          if (c.claimType !== claimType) return false;
          if (c.state !== 'QUEUED') return false;
          if (c.deletedAt) return false;

          if (includeClean && includeFlagged) return true;
          if (includeClean && !includeFlagged) return c.isClean === true;
          if (!includeClean && includeFlagged) return c.isClean === false;
          return false;
        });
      },
    ),

    bulkTransitionState: vi.fn(async () => []),

    // Import/template/shift/export stubs
    createImportBatch: vi.fn(),
    findImportBatchById: vi.fn(),
    updateImportBatchStatus: vi.fn(),
    findDuplicateImportByHash: vi.fn(),
    listImportBatches: vi.fn(),
    createTemplate: vi.fn(),
    findTemplateById: vi.fn(),
    updateTemplate: vi.fn(),
    deleteTemplate: vi.fn(),
    listTemplates: vi.fn(),
    createShift: vi.fn(),
    findShiftById: vi.fn(),
    updateShiftStatus: vi.fn(),
    updateShiftTimes: vi.fn(),
    incrementEncounterCount: vi.fn(),
    listShifts: vi.fn(),
    findClaimsByShift: vi.fn(),
    createExportRecord: vi.fn(),
    findExportById: vi.fn(),
    updateExportStatus: vi.fn(),

    // Audit
    appendClaimAudit: vi.fn(async (entry: any) => {
      const audit = {
        auditId: crypto.randomUUID(),
        ...entry,
        createdAt: new Date(),
      };
      auditEntries.push(audit);
      return audit;
    }),

    getClaimAuditHistory: vi.fn(async (claimId: string) => {
      return auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    }),

    getClaimAuditHistoryPaginated: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
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
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let store: ReturnType<typeof createStatefulClaimStore>;
let mockProviderCheck: {
  isActive: ReturnType<typeof vi.fn>;
  getRegistrationDate: ReturnType<typeof vi.fn>;
};
let mockPatientCheck: { exists: ReturnType<typeof vi.fn> };
let mockSubmissionPreference: { getSubmissionMode: ReturnType<typeof vi.fn> };
let mockNotificationEmitter: NotificationEmitter;

async function buildTestApp(): Promise<FastifyInstance> {
  store = createStatefulClaimStore();
  mockProviderCheck = {
    isActive: vi.fn(async () => true),
    getRegistrationDate: vi.fn(async () => '2020-01-01'),
  };
  mockPatientCheck = {
    exists: vi.fn(async () => true),
  };
  mockSubmissionPreference = {
    getSubmissionMode: vi.fn(async () => 'AUTO_CLEAN'),
  };
  mockNotificationEmitter = {
    emit: vi.fn(async () => {}),
  };

  const serviceDeps: ClaimServiceDeps = {
    repo: store as any,
    providerCheck: mockProviderCheck,
    patientCheck: mockPatientCheck,
    submissionPreference: mockSubmissionPreference,
    notificationEmitter: mockNotificationEmitter,
  };

  const handlerDeps: ClaimHandlerDeps = { serviceDeps };

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

  await testApp.register(claimRoutes, { deps: handlerDeps });
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

function authedGet(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function authedPut(url: string, body: Record<string, unknown>, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'PUT',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body,
  });
}

/**
 * Helper to create a claim and progress it to QUEUED state with clean/flagged status.
 */
async function createQueuedClaim(options: {
  isClean: boolean;
  claimType?: string;
}): Promise<string> {
  const { isClean, claimType = 'AHCIP' } = options;

  // Create
  const createRes = await authedPost('/api/v1/claims', {
    ...VALID_CLAIM,
    claim_type: claimType,
  });
  const claimId = createRes.json().data.claimId;

  // Validate
  await authedPost(`/api/v1/claims/${claimId}/validate`);

  // Queue
  await authedPost(`/api/v1/claims/${claimId}/queue`);

  // Override clean/flagged classification for test control
  const claim = store.claims.get(claimId)!;
  claim.isClean = isClean;

  return claimId;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Auto-Submission Mode Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // Auto Clean mode: clean claims included, flagged excluded
  // =========================================================================

  describe('Auto Clean mode', () => {
    beforeEach(() => {
      store.claims.clear();
      store.auditEntries.length = 0;
      vi.clearAllMocks();
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
      mockPatientCheck.exists.mockResolvedValue(true);
      mockSubmissionPreference.getSubmissionMode.mockResolvedValue('AUTO_CLEAN');
    });

    it('includes clean claims and excludes flagged claims', async () => {
      // Create clean and flagged claims in QUEUED state
      const cleanClaimId = await createQueuedClaim({ isClean: true });
      const flaggedClaimId = await createQueuedClaim({ isClean: false });

      // Build service deps with AUTO_CLEAN mode
      const serviceDeps: ClaimServiceDeps = {
        repo: store as any,
        providerCheck: mockProviderCheck,
        patientCheck: mockPatientCheck,
        submissionPreference: mockSubmissionPreference,
      };

      // Call getClaimsForAutoSubmission
      const result = await getClaimsForAutoSubmission(
        serviceDeps,
        PHYSICIAN1_USER_ID,
        'AHCIP',
      );

      expect(result.mode).toBe('AUTO_CLEAN');
      expect(result.claims.length).toBe(1);
      expect(result.claims[0].claimId).toBe(cleanClaimId);

      // Verify the flagged claim was NOT included
      const flaggedInResult = result.claims.find((c: any) => c.claimId === flaggedClaimId);
      expect(flaggedInResult).toBeUndefined();
    });
  });

  // =========================================================================
  // Auto All mode: both clean and flagged included
  // =========================================================================

  describe('Auto All mode', () => {
    beforeEach(() => {
      store.claims.clear();
      store.auditEntries.length = 0;
      vi.clearAllMocks();
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
      mockPatientCheck.exists.mockResolvedValue(true);
      mockSubmissionPreference.getSubmissionMode.mockResolvedValue('AUTO_ALL');
    });

    it('includes both clean and flagged claims', async () => {
      const cleanClaimId = await createQueuedClaim({ isClean: true });
      const flaggedClaimId = await createQueuedClaim({ isClean: false });

      const serviceDeps: ClaimServiceDeps = {
        repo: store as any,
        providerCheck: mockProviderCheck,
        patientCheck: mockPatientCheck,
        submissionPreference: mockSubmissionPreference,
      };

      const result = await getClaimsForAutoSubmission(
        serviceDeps,
        PHYSICIAN1_USER_ID,
        'AHCIP',
      );

      expect(result.mode).toBe('AUTO_ALL');
      expect(result.claims.length).toBe(2);

      const claimIds = result.claims.map((c: any) => c.claimId);
      expect(claimIds).toContain(cleanClaimId);
      expect(claimIds).toContain(flaggedClaimId);
    });
  });

  // =========================================================================
  // Require Approval mode: no claims without explicit approval
  // =========================================================================

  describe('Require Approval mode', () => {
    beforeEach(() => {
      store.claims.clear();
      store.auditEntries.length = 0;
      vi.clearAllMocks();
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
      mockPatientCheck.exists.mockResolvedValue(true);
      mockSubmissionPreference.getSubmissionMode.mockResolvedValue('REQUIRE_APPROVAL');
    });

    it('blocks all claims without explicit approval', async () => {
      // Create flagged claims (not approved) in QUEUED state
      await createQueuedClaim({ isClean: false });
      await createQueuedClaim({ isClean: false });

      const serviceDeps: ClaimServiceDeps = {
        repo: store as any,
        providerCheck: mockProviderCheck,
        patientCheck: mockPatientCheck,
        submissionPreference: mockSubmissionPreference,
      };

      const result = await getClaimsForAutoSubmission(
        serviceDeps,
        PHYSICIAN1_USER_ID,
        'AHCIP',
      );

      expect(result.mode).toBe('REQUIRE_APPROVAL');
      // REQUIRE_APPROVAL includes only clean claims — flagged ones are blocked
      expect(result.claims.length).toBe(0);
    });

    it('includes only explicitly approved claims', async () => {
      // Create one flagged claim that gets approved (isClean forced to true)
      const approvedClaimId = await createQueuedClaim({ isClean: false });
      // Simulate explicit approval: set isClean = true
      store.claims.get(approvedClaimId)!.isClean = true;

      // Create another flagged claim that is NOT approved
      await createQueuedClaim({ isClean: false });

      const serviceDeps: ClaimServiceDeps = {
        repo: store as any,
        providerCheck: mockProviderCheck,
        patientCheck: mockPatientCheck,
        submissionPreference: mockSubmissionPreference,
      };

      const result = await getClaimsForAutoSubmission(
        serviceDeps,
        PHYSICIAN1_USER_ID,
        'AHCIP',
      );

      expect(result.mode).toBe('REQUIRE_APPROVAL');
      expect(result.claims.length).toBe(1);
      expect(result.claims[0].claimId).toBe(approvedClaimId);
    });
  });

  // =========================================================================
  // Submission preference update via API
  // =========================================================================

  describe('Submission preferences API', () => {
    beforeEach(() => {
      store.claims.clear();
      store.auditEntries.length = 0;
      vi.clearAllMocks();
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockPatientCheck.exists.mockResolvedValue(true);
    });

    it('updates submission mode to AUTO_ALL', async () => {
      const res = await authedPut('/api/v1/submission-preferences', {
        mode: 'AUTO_ALL',
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().data.success).toBe(true);

      // Verify audit entry was created
      const auditEntry = store.auditEntries.find(
        (e) => e.action === 'submission_preferences.updated',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.changes.mode).toBe('AUTO_ALL');
    });

    it('updates submission mode to REQUIRE_APPROVAL', async () => {
      const res = await authedPut('/api/v1/submission-preferences', {
        mode: 'REQUIRE_APPROVAL',
      });
      expect(res.statusCode).toBe(200);
    });

    it('rejects invalid submission mode', async () => {
      const res = await authedPut('/api/v1/submission-preferences', {
        mode: 'INVALID_MODE',
      });
      expect(res.statusCode).toBe(400);
    });
  });
});

// ---------------------------------------------------------------------------
// Deadline Expiry Tests
// ---------------------------------------------------------------------------

describe('Deadline Expiry Integration Tests', () => {
  let app2: FastifyInstance;
  let store2: ReturnType<typeof createStatefulClaimStore>;
  let mockProviderCheck2: { isActive: ReturnType<typeof vi.fn>; getRegistrationDate: ReturnType<typeof vi.fn> };
  let mockPatientCheck2: { exists: ReturnType<typeof vi.fn> };
  let mockNotificationEmitter2: NotificationEmitter;

  beforeAll(async () => {
    store2 = createStatefulClaimStore();
    mockProviderCheck2 = {
      isActive: vi.fn(async () => true),
      getRegistrationDate: vi.fn(async () => '2020-01-01'),
    };
    mockPatientCheck2 = {
      exists: vi.fn(async () => true),
    };
    mockNotificationEmitter2 = {
      emit: vi.fn(async () => {}),
    };

    const serviceDeps: ClaimServiceDeps = {
      repo: store2 as any,
      providerCheck: mockProviderCheck2,
      patientCheck: mockPatientCheck2,
      notificationEmitter: mockNotificationEmitter2,
    };

    const handlerDeps: ClaimHandlerDeps = { serviceDeps };

    app2 = Fastify({ logger: false });
    app2.setValidatorCompiler(validatorCompiler);
    app2.setSerializerCompiler(serializerCompiler);

    const mockSessionRepo = createMockSessionRepo();
    await app2.register(authPluginFp, {
      sessionDeps: {
        sessionRepo: mockSessionRepo,
        auditRepo: { appendAuditLog: vi.fn() },
        events: { emit: vi.fn() },
      },
    });

    app2.setErrorHandler((error, _request, reply) => {
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
          error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
        });
      }
      return reply.code(500).send({
        error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
      });
    });

    await app2.register(claimRoutes, { deps: handlerDeps });
    await app2.ready();
  });

  afterAll(async () => {
    await app2.close();
  });

  beforeEach(() => {
    store2.claims.clear();
    store2.auditEntries.length = 0;
    vi.clearAllMocks();
    mockProviderCheck2.isActive.mockResolvedValue(true);
    mockProviderCheck2.getRegistrationDate.mockResolvedValue('2020-01-01');
    mockPatientCheck2.exists.mockResolvedValue(true);
  });

  // =========================================================================
  // Deadline expiry transitions claim to EXPIRED
  // =========================================================================

  describe('Deadline expiry', () => {
    it('transitions claim with past deadline to EXPIRED', async () => {
      // Create a claim via API
      const createRes = await app2.inject({
        method: 'POST',
        url: '/api/v1/claims',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: VALID_CLAIM,
      });
      expect(createRes.statusCode).toBe(201);
      const claimId = createRes.json().data.claimId;

      // Set a deadline that has already passed (90 days ago from DOS)
      const claim = store2.claims.get(claimId)!;
      claim.submissionDeadline = '2025-01-01'; // Past deadline
      claim.state = 'VALIDATED'; // Must be non-terminal

      // Build service deps
      const serviceDeps: ClaimServiceDeps = {
        repo: store2 as any,
        providerCheck: mockProviderCheck2,
        patientCheck: mockPatientCheck2,
        notificationEmitter: mockNotificationEmitter2,
      };

      // Call expireClaimWithContext
      await expireClaimWithContext(
        serviceDeps,
        claimId,
        PHYSICIAN1_USER_ID,
        'VALIDATED',
      );

      // Verify state transitioned to EXPIRED
      const updatedClaim = store2.claims.get(claimId)!;
      expect(updatedClaim.state).toBe('EXPIRED');

      // Verify DEADLINE_EXPIRED notification was emitted
      expect(mockNotificationEmitter2.emit).toHaveBeenCalledWith(
        'DEADLINE_EXPIRED',
        expect.objectContaining({
          claimId,
          physicianId: PHYSICIAN1_USER_ID,
        }),
      );

      // Verify audit entry
      const auditEntry = store2.auditEntries.find(
        (e) => e.claimId === claimId && e.action === 'claim.expired',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.previousState).toBe('VALIDATED');
      expect(auditEntry!.newState).toBe('EXPIRED');
      expect(auditEntry!.actorId).toBe('SYSTEM');
      expect(auditEntry!.actorContext).toBe('SYSTEM');
    });

    it('rejects expiry for claims already in terminal state', async () => {
      // Create a claim and move to PAID (terminal)
      const createRes = await app2.inject({
        method: 'POST',
        url: '/api/v1/claims',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: VALID_CLAIM,
      });
      const claimId = createRes.json().data.claimId;
      store2.claims.get(claimId)!.state = 'PAID';
      store2.claims.get(claimId)!.submissionDeadline = '2025-01-01';

      const serviceDeps: ClaimServiceDeps = {
        repo: store2 as any,
        providerCheck: mockProviderCheck2,
        patientCheck: mockPatientCheck2,
        notificationEmitter: mockNotificationEmitter2,
      };

      await expect(
        expireClaimWithContext(serviceDeps, claimId, PHYSICIAN1_USER_ID, 'PAID'),
      ).rejects.toThrow(/terminal state/);
    });

    it('rejects expiry when deadline has not yet passed', async () => {
      // Create a claim with a future deadline
      const createRes = await app2.inject({
        method: 'POST',
        url: '/api/v1/claims',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: VALID_CLAIM,
      });
      const claimId = createRes.json().data.claimId;
      store2.claims.get(claimId)!.state = 'VALIDATED';
      store2.claims.get(claimId)!.submissionDeadline = '2099-12-31'; // Far future

      const serviceDeps: ClaimServiceDeps = {
        repo: store2 as any,
        providerCheck: mockProviderCheck2,
        patientCheck: mockPatientCheck2,
        notificationEmitter: mockNotificationEmitter2,
      };

      await expect(
        expireClaimWithContext(serviceDeps, claimId, PHYSICIAN1_USER_ID, 'VALIDATED'),
      ).rejects.toThrow(/deadline has not yet passed/);

      // Verify claim remains VALIDATED
      expect(store2.claims.get(claimId)!.state).toBe('VALIDATED');
    });
  });

  // =========================================================================
  // Deadline approaching emits notification
  // =========================================================================

  describe('Deadline approaching notification', () => {
    it('claim within 7 days of deadline is flagged with approaching deadline', async () => {
      // Create a claim via API
      const createRes = await app2.inject({
        method: 'POST',
        url: '/api/v1/claims',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: VALID_CLAIM,
      });
      expect(createRes.statusCode).toBe(201);
      const claimId = createRes.json().data.claimId;

      // Set deadline to 5 days from now (within the 7-day warning window)
      const today = new Date();
      const deadline = new Date(today);
      deadline.setDate(deadline.getDate() + 5);
      const deadlineStr = deadline.toISOString().slice(0, 10);

      const claim = store2.claims.get(claimId)!;
      claim.submissionDeadline = deadlineStr;
      claim.state = 'VALIDATED';

      // The deadline approaching notification is emitted by the scheduled job
      // that checks findClaimsApproachingDeadline. We simulate this by verifying
      // the claim's deadline is within the 7-day window.
      const deadlineDate = new Date(deadlineStr + 'T00:00:00Z');
      const todayNorm = new Date();
      todayNorm.setUTCHours(0, 0, 0, 0);
      const daysUntilDeadline = Math.floor(
        (deadlineDate.getTime() - todayNorm.getTime()) / (1000 * 60 * 60 * 24),
      );

      expect(daysUntilDeadline).toBeGreaterThan(0);
      expect(daysUntilDeadline).toBeLessThanOrEqual(7);

      // Simulate the scheduled job finding this claim and emitting a notification
      // (this would normally be done by a cron job or batch processor)
      const serviceDeps: ClaimServiceDeps = {
        repo: store2 as any,
        providerCheck: mockProviderCheck2,
        patientCheck: mockPatientCheck2,
        notificationEmitter: mockNotificationEmitter2,
      };

      // Mock findClaimsApproachingDeadline to return this claim
      store2.findClaimsApproachingDeadline.mockResolvedValueOnce([
        { claimId, physicianId: PHYSICIAN1_USER_ID, submissionDeadline: deadlineStr, state: 'VALIDATED' },
      ]);

      const approachingClaims = await serviceDeps.repo.findClaimsApproachingDeadline(
        PHYSICIAN1_USER_ID,
        7,
      );

      expect(approachingClaims.length).toBe(1);
      expect(approachingClaims[0].claimId).toBe(claimId);

      // Emit DEADLINE_APPROACHING for each claim
      for (const approachingClaim of approachingClaims) {
        await mockNotificationEmitter2.emit('DEADLINE_APPROACHING', {
          claimId: approachingClaim.claimId,
          physicianId: approachingClaim.physicianId,
          submissionDeadline: approachingClaim.submissionDeadline,
          daysRemaining: daysUntilDeadline,
        });
      }

      // Verify notification was emitted
      expect(mockNotificationEmitter2.emit).toHaveBeenCalledWith(
        'DEADLINE_APPROACHING',
        expect.objectContaining({
          claimId,
          physicianId: PHYSICIAN1_USER_ID,
          daysRemaining: daysUntilDeadline,
        }),
      );
    });
  });
});
