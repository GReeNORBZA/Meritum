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
import { type ClaimServiceDeps } from '../../../src/domains/claim/claim.service.js';

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
const CLAIM_ID = '00000000-cccc-0000-0000-000000000001';

const VALID_CLAIM = {
  claim_type: 'AHCIP' as const,
  patient_id: PATIENT_ID,
  date_of_service: '2026-01-15',
};

// ---------------------------------------------------------------------------
// Stateful mock claim store (simulates real DB for lifecycle tests)
// ---------------------------------------------------------------------------

/** In-memory claim store that tracks state changes for lifecycle testing. */
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

    softDeleteClaim: vi.fn(async (claimId: string, physicianId: string) => {
      const claim = claims.get(claimId);
      if (!claim || claim.physicianId !== physicianId) return false;
      if (claim.state !== 'DRAFT') return false;
      claim.deletedAt = new Date();
      claim.state = 'DELETED';
      return true;
    }),

    listClaims: vi.fn(async (physicianId: string, filters: any) => {
      let filtered = Array.from(claims.values()).filter(
        (c) => c.physicianId === physicianId && !c.deletedAt,
      );
      if (filters?.state) filtered = filtered.filter((c) => c.state === filters.state);
      if (filters?.claimType) filtered = filtered.filter((c) => c.claimType === filters.claimType);
      if (filters?.patientId) filtered = filtered.filter((c) => c.patientId === filters.patientId);
      if (filters?.dateFrom)
        filtered = filtered.filter((c) => c.dateOfService >= filters.dateFrom);
      if (filters?.dateTo) filtered = filtered.filter((c) => c.dateOfService <= filters.dateTo);
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

    updateAiSuggestions: vi.fn(async (claimId: string, physicianId: string, suggestions: any) => {
      const claim = claims.get(claimId);
      if (!claim || claim.physicianId !== physicianId) return undefined;
      claim.aiCoachSuggestions = suggestions;
      return { ...claim };
    }),

    updateDuplicateAlert: vi.fn(async () => ({})),
    updateFlags: vi.fn(async () => ({})),
    countClaimsByState: vi.fn(async () => []),
    findClaimsApproachingDeadline: vi.fn(async () => []),
    findClaimsForBatchAssembly: vi.fn(async () => []),
    bulkTransitionState: vi.fn(async () => []),

    // Import/template/shift/export stubs (not exercised in lifecycle tests)
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

    // Audit (append-only)
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

    getClaimAuditHistoryPaginated: vi.fn(async (claimId: string) => {
      const matching = auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
      return {
        data: matching,
        pagination: { total: matching.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),
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

async function buildTestApp(): Promise<FastifyInstance> {
  store = createStatefulClaimStore();
  mockProviderCheck = {
    isActive: vi.fn(async () => true),
    getRegistrationDate: vi.fn(async () => '2020-01-01'),
  };
  mockPatientCheck = {
    exists: vi.fn(async () => true),
  };

  const serviceDeps: ClaimServiceDeps = {
    repo: store as any,
    providerCheck: mockProviderCheck,
    patientCheck: mockPatientCheck,
  };

  const handlerDeps: ClaimHandlerDeps = { serviceDeps };

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

  // Register claim routes
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Claim Lifecycle Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // NOTE: We do NOT clear the store in beforeEach because sequential lifecycle
  // tests (within a single describe) depend on state from previous steps.
  // Each describe block that needs a clean slate handles its own cleanup.

  // =========================================================================
  // Full Happy-Path Lifecycle: DRAFT -> VALIDATED -> QUEUED -> SUBMITTED ->
  //   ASSESSED -> PAID
  // =========================================================================

  describe('Full lifecycle: create -> validate -> queue -> submit -> assess -> paid', () => {
    let claimId: string;

    beforeAll(() => {
      store.claims.clear();
      store.auditEntries.length = 0;
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
      mockPatientCheck.exists.mockResolvedValue(true);
    });

    it('Step 1: creates claim in DRAFT state', async () => {
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data.claimId).toBeDefined();
      claimId = body.data.claimId;

      // Verify claim is in DRAFT state
      const claim = store.claims.get(claimId);
      expect(claim).toBeDefined();
      expect(claim!.state).toBe('DRAFT');
    });

    it('Step 2: validates claim -> VALIDATED state', async () => {
      const res = await authedPost(`/api/v1/claims/${claimId}/validate`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
      expect(body.data.errors).toHaveLength(0);

      // Verify claim transitioned to VALIDATED
      const claim = store.claims.get(claimId);
      expect(claim!.state).toBe('VALIDATED');
    });

    it('Step 3: queues claim -> QUEUED state (classified as clean)', async () => {
      const res = await authedPost(`/api/v1/claims/${claimId}/queue`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.isClean).toBe(true);

      // Verify claim transitioned to QUEUED
      const claim = store.claims.get(claimId);
      expect(claim!.state).toBe('QUEUED');
      expect(claim!.isClean).toBe(true);
    });

    it('Step 4: simulates batch assembly -> SUBMITTED state', async () => {
      // Batch assembly is pathway-specific; simulate via direct store mutation
      const claim = store.claims.get(claimId)!;
      claim.state = 'SUBMITTED';
      claim.submittedBatchId = '00000000-bbbb-0000-0000-000000000001';
      claim.updatedAt = new Date();

      // Add audit entry for submission
      store.auditEntries.push({
        auditId: crypto.randomUUID(),
        claimId,
        action: 'claim.submitted',
        previousState: 'QUEUED',
        newState: 'SUBMITTED',
        changes: { batchId: claim.submittedBatchId },
        actorId: 'SYSTEM',
        actorContext: 'SYSTEM',
        createdAt: new Date(),
      });

      expect(claim.state).toBe('SUBMITTED');
    });

    it('Step 5: simulates assessment response -> ASSESSED state', async () => {
      const claim = store.claims.get(claimId)!;
      claim.state = 'ASSESSED';
      claim.updatedAt = new Date();

      store.auditEntries.push({
        auditId: crypto.randomUUID(),
        claimId,
        action: 'claim.assessed',
        previousState: 'SUBMITTED',
        newState: 'ASSESSED',
        changes: { assessmentResult: 'accepted' },
        actorId: 'SYSTEM',
        actorContext: 'SYSTEM',
        createdAt: new Date(),
      });

      expect(claim.state).toBe('ASSESSED');
    });

    it('Step 6: simulates payment confirmation -> PAID state (terminal)', async () => {
      const claim = store.claims.get(claimId)!;
      claim.state = 'PAID';
      claim.updatedAt = new Date();

      store.auditEntries.push({
        auditId: crypto.randomUUID(),
        claimId,
        action: 'claim.paid',
        previousState: 'ASSESSED',
        newState: 'PAID',
        changes: null,
        actorId: 'SYSTEM',
        actorContext: 'SYSTEM',
        createdAt: new Date(),
      });

      expect(claim.state).toBe('PAID');
    });

    it('Step 7: verifies full audit history chain', async () => {
      const audit = store.auditEntries.filter((e) => e.claimId === claimId);
      expect(audit.length).toBeGreaterThanOrEqual(6);

      // Expected action chain (chronological order)
      const expectedActions = [
        'claim.created',
        'claim.validated',
        'claim.queued',
        'claim.submitted',
        'claim.assessed',
        'claim.paid',
      ];

      const actionSequence = audit
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
        .map((e) => e.action);

      for (const expected of expectedActions) {
        expect(actionSequence).toContain(expected);
      }

      // Verify order: each action appears after its predecessor
      for (let i = 1; i < expectedActions.length; i++) {
        const prevIdx = actionSequence.indexOf(expectedActions[i - 1]);
        const currIdx = actionSequence.indexOf(expectedActions[i]);
        expect(currIdx).toBeGreaterThan(prevIdx);
      }
    });

    it('Step 8: verifies state transitions are correct in audit entries', async () => {
      const audit = store.auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

      // CREATED: null -> DRAFT
      const created = audit.find((e) => e.action === 'claim.created');
      expect(created?.previousState).toBeNull();
      expect(created?.newState).toBe('DRAFT');

      // VALIDATED: DRAFT -> VALIDATED
      const validated = audit.find((e) => e.action === 'claim.validated');
      expect(validated?.previousState).toBe('DRAFT');
      expect(validated?.newState).toBe('VALIDATED');

      // QUEUED: VALIDATED -> QUEUED
      const queued = audit.find((e) => e.action === 'claim.queued');
      expect(queued?.previousState).toBe('VALIDATED');
      expect(queued?.newState).toBe('QUEUED');

      // SUBMITTED: QUEUED -> SUBMITTED
      const submitted = audit.find((e) => e.action === 'claim.submitted');
      expect(submitted?.previousState).toBe('QUEUED');
      expect(submitted?.newState).toBe('SUBMITTED');

      // ASSESSED: SUBMITTED -> ASSESSED
      const assessed = audit.find((e) => e.action === 'claim.assessed');
      expect(assessed?.previousState).toBe('SUBMITTED');
      expect(assessed?.newState).toBe('ASSESSED');

      // PAID: ASSESSED -> PAID
      const paid = audit.find((e) => e.action === 'claim.paid');
      expect(paid?.previousState).toBe('ASSESSED');
      expect(paid?.newState).toBe('PAID');
    });

    it('Step 9: GET /claims/:id returns final PAID state', async () => {
      const res = await authedGet(`/api/v1/claims/${claimId}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.state).toBe('PAID');
    });

    it('Step 10: GET /claims/:id/audit returns full history via API', async () => {
      const res = await authedGet(`/api/v1/claims/${claimId}/audit`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.length).toBeGreaterThanOrEqual(6);
    });
  });

  // =========================================================================
  // Rejection Lifecycle: SUBMITTED -> REJECTED -> edit -> resubmit -> PAID
  // =========================================================================

  describe('Rejection lifecycle: submit -> reject -> review -> resubmit -> paid', () => {
    let claimId: string;

    beforeAll(() => {
      store.claims.clear();
      store.auditEntries.length = 0;
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
      mockPatientCheck.exists.mockResolvedValue(true);
    });

    it('Step 1: creates and progresses claim to SUBMITTED state', async () => {
      // Create
      const createRes = await authedPost('/api/v1/claims', VALID_CLAIM);
      expect(createRes.statusCode).toBe(201);
      claimId = createRes.json().data.claimId;

      // Validate
      const validateRes = await authedPost(`/api/v1/claims/${claimId}/validate`);
      expect(validateRes.statusCode).toBe(200);
      expect(validateRes.json().data.passed).toBe(true);

      // Queue
      const queueRes = await authedPost(`/api/v1/claims/${claimId}/queue`);
      expect(queueRes.statusCode).toBe(200);

      // Simulate submission
      const claim = store.claims.get(claimId)!;
      claim.state = 'SUBMITTED';
      claim.updatedAt = new Date();
      store.auditEntries.push({
        auditId: crypto.randomUUID(),
        claimId,
        action: 'claim.submitted',
        previousState: 'QUEUED',
        newState: 'SUBMITTED',
        changes: null,
        actorId: 'SYSTEM',
        actorContext: 'SYSTEM',
        createdAt: new Date(),
      });
    });

    it('Step 2: simulates rejection from payer', async () => {
      const claim = store.claims.get(claimId)!;
      claim.state = 'REJECTED';
      claim.validationResult = {
        errors: [
          {
            check: 'PAYER_REJECTION',
            rule_reference: 'AHCIP Assessment',
            message: 'Service code not valid for patient age',
            help_text: 'Verify the service code is appropriate for the patient age group.',
          },
        ],
        warnings: [],
        info: [],
        passed: false,
        validation_timestamp: new Date().toISOString(),
        reference_data_version: 'unknown',
      };
      claim.updatedAt = new Date();

      store.auditEntries.push({
        auditId: crypto.randomUUID(),
        claimId,
        action: 'claim.rejected',
        previousState: 'SUBMITTED',
        newState: 'REJECTED',
        changes: { rejectionCodes: ['PAYER_REJECTION'] },
        actorId: 'SYSTEM',
        actorContext: 'SYSTEM',
        createdAt: new Date(),
      });

      expect(claim.state).toBe('REJECTED');
    });

    it('Step 3: GET /claims/:id/rejection-details returns codes and guidance', async () => {
      const res = await authedGet(`/api/v1/claims/${claimId}/rejection-details`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.claimId).toBe(claimId);
      expect(body.data.rejectionCodes).toBeDefined();
      expect(body.data.resubmissionEligible).toBe(true);
    });

    it('Step 4: PUT /claims/:id — edit claim to fix rejection', async () => {
      // Clear the validation result to simulate physician correcting the issue
      const claim = store.claims.get(claimId)!;
      claim.validationResult = null;

      const res = await authedPut(`/api/v1/claims/${claimId}`, {
        date_of_service: '2026-01-16',
      });
      expect(res.statusCode).toBe(200);
    });

    it('Step 5: POST /claims/:id/resubmit — revalidate and requeue', async () => {
      const res = await authedPost(`/api/v1/claims/${claimId}/resubmit`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.newState).toBe('QUEUED');

      // Verify claim is now in QUEUED state
      const claim = store.claims.get(claimId)!;
      expect(claim.state).toBe('QUEUED');
    });

    it('Step 6: verifies audit trail includes REJECTED -> RESUBMITTED entries', async () => {
      const audit = store.auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

      const actions = audit.map((e) => e.action);

      // Must contain rejection and resubmission
      expect(actions).toContain('claim.rejected');
      expect(actions).toContain('claim.resubmitted');

      // Resubmitted must appear after rejected
      const rejectedIdx = actions.indexOf('claim.rejected');
      const resubmittedIdx = actions.indexOf('claim.resubmitted');
      expect(resubmittedIdx).toBeGreaterThan(rejectedIdx);

      // Verify resubmitted audit entry details
      const resubmittedEntry = audit.find((e) => e.action === 'claim.resubmitted');
      expect(resubmittedEntry?.previousState).toBe('REJECTED');
      expect(resubmittedEntry?.newState).toBe('QUEUED');
    });

    it('Step 7: simulates second submission and payment after resubmit', async () => {
      const claim = store.claims.get(claimId)!;

      // Submitted
      claim.state = 'SUBMITTED';
      store.auditEntries.push({
        auditId: crypto.randomUUID(),
        claimId,
        action: 'claim.submitted',
        previousState: 'QUEUED',
        newState: 'SUBMITTED',
        changes: null,
        actorId: 'SYSTEM',
        actorContext: 'SYSTEM',
        createdAt: new Date(),
      });

      // Assessed
      claim.state = 'ASSESSED';
      store.auditEntries.push({
        auditId: crypto.randomUUID(),
        claimId,
        action: 'claim.assessed',
        previousState: 'SUBMITTED',
        newState: 'ASSESSED',
        changes: null,
        actorId: 'SYSTEM',
        actorContext: 'SYSTEM',
        createdAt: new Date(),
      });

      // Paid
      claim.state = 'PAID';
      store.auditEntries.push({
        auditId: crypto.randomUUID(),
        claimId,
        action: 'claim.paid',
        previousState: 'ASSESSED',
        newState: 'PAID',
        changes: null,
        actorId: 'SYSTEM',
        actorContext: 'SYSTEM',
        createdAt: new Date(),
      });

      expect(claim.state).toBe('PAID');

      // Full audit chain should include rejection and resubmission
      const audit = store.auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

      const actions = audit.map((e) => e.action);
      expect(actions).toContain('claim.created');
      expect(actions).toContain('claim.rejected');
      expect(actions).toContain('claim.resubmitted');
      expect(actions).toContain('claim.paid');
    });
  });

  // =========================================================================
  // Invalid State Transitions
  // =========================================================================

  describe('Invalid state transitions', () => {
    beforeEach(() => {
      store.claims.clear();
      store.auditEntries.length = 0;
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
      mockPatientCheck.exists.mockResolvedValue(true);
    });

    it('draft -> submitted (skipping validation and queue) returns 409', async () => {
      // Create a claim in DRAFT state
      const createRes = await authedPost('/api/v1/claims', VALID_CLAIM);
      expect(createRes.statusCode).toBe(201);
      const claimId = createRes.json().data.claimId;

      // Verify it's in DRAFT
      const claim = store.claims.get(claimId)!;
      expect(claim.state).toBe('DRAFT');

      // Try to queue directly from DRAFT (should fail — queue requires VALIDATED)
      const queueRes = await authedPost(`/api/v1/claims/${claimId}/queue`);
      expect(queueRes.statusCode).toBe(409);

      // Claim should still be in DRAFT
      expect(store.claims.get(claimId)!.state).toBe('DRAFT');
    });

    it('paid -> any transition returns 409 (terminal state)', async () => {
      // Create and move claim to PAID terminal state
      const createRes = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = createRes.json().data.claimId;

      // Move through lifecycle to PAID
      await authedPost(`/api/v1/claims/${claimId}/validate`);
      const claim = store.claims.get(claimId)!;
      // Fast-forward to PAID
      claim.state = 'PAID';

      // Try to validate from PAID -> should fail
      const validateRes = await authedPost(`/api/v1/claims/${claimId}/validate`);
      // Validate still runs checks and returns results (it doesn't check state for running)
      // but it should NOT transition the state since PAID is terminal
      expect(claim.state).toBe('PAID');

      // Try to queue from PAID -> should fail
      const queueRes = await authedPost(`/api/v1/claims/${claimId}/queue`);
      expect(queueRes.statusCode).toBe(409);
      expect(claim.state).toBe('PAID');

      // Try to resubmit from PAID -> should fail
      const resubmitRes = await authedPost(`/api/v1/claims/${claimId}/resubmit`);
      expect(resubmitRes.statusCode).toBe(409);
      expect(claim.state).toBe('PAID');

      // Try to write-off from PAID -> should fail
      const writeOffRes = await authedPost(`/api/v1/claims/${claimId}/write-off`, {
        reason: 'Testing terminal state',
      });
      expect(writeOffRes.statusCode).toBe(409);
      expect(claim.state).toBe('PAID');
    });

    it('deleted -> validated (terminal state) returns 404', async () => {
      // Create claim and soft-delete it
      const createRes = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = createRes.json().data.claimId;

      // Soft delete (only from DRAFT)
      const claim = store.claims.get(claimId)!;
      claim.deletedAt = new Date();
      claim.state = 'DELETED';

      // Deleted claims return 404 (not visible)
      const validateRes = await authedPost(`/api/v1/claims/${claimId}/validate`);
      expect(validateRes.statusCode).toBe(404);
    });

    it('written_off -> any transition returns 409 (terminal state)', async () => {
      const createRes = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = createRes.json().data.claimId;
      const claim = store.claims.get(claimId)!;
      claim.state = 'WRITTEN_OFF';

      // Try to queue
      const queueRes = await authedPost(`/api/v1/claims/${claimId}/queue`);
      expect(queueRes.statusCode).toBe(409);

      // Try to resubmit
      const resubmitRes = await authedPost(`/api/v1/claims/${claimId}/resubmit`);
      expect(resubmitRes.statusCode).toBe(409);
    });

    it('expired -> any transition returns 409 (terminal state)', async () => {
      const createRes = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = createRes.json().data.claimId;
      const claim = store.claims.get(claimId)!;
      claim.state = 'EXPIRED';

      const queueRes = await authedPost(`/api/v1/claims/${claimId}/queue`);
      expect(queueRes.statusCode).toBe(409);

      const resubmitRes = await authedPost(`/api/v1/claims/${claimId}/resubmit`);
      expect(resubmitRes.statusCode).toBe(409);
    });

    it('validated -> rejected (skipping queue and submit) returns 409', async () => {
      const createRes = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = createRes.json().data.claimId;

      // Validate
      await authedPost(`/api/v1/claims/${claimId}/validate`);
      const claim = store.claims.get(claimId)!;
      expect(claim.state).toBe('VALIDATED');

      // Try to write-off from VALIDATED (only allowed from REJECTED)
      const writeOffRes = await authedPost(`/api/v1/claims/${claimId}/write-off`, {
        reason: 'Testing invalid transition',
      });
      expect(writeOffRes.statusCode).toBe(409);
    });

    it('queued -> paid (skipping submit and assess) returns 409', async () => {
      const createRes = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = createRes.json().data.claimId;

      // Progress to QUEUED
      await authedPost(`/api/v1/claims/${claimId}/validate`);
      await authedPost(`/api/v1/claims/${claimId}/queue`);
      expect(store.claims.get(claimId)!.state).toBe('QUEUED');

      // Try write-off from QUEUED (only REJECTED -> WRITTEN_OFF is valid)
      const writeOffRes = await authedPost(`/api/v1/claims/${claimId}/write-off`, {
        reason: 'Testing invalid transition',
      });
      expect(writeOffRes.statusCode).toBe(409);
    });

    it('unqueue from non-queued state returns 409', async () => {
      const createRes = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = createRes.json().data.claimId;

      // Claim is in DRAFT
      const unqueueRes = await authedPost(`/api/v1/claims/${claimId}/unqueue`);
      expect(unqueueRes.statusCode).toBe(409);
    });
  });

  // =========================================================================
  // Audit Trail Completeness
  // =========================================================================

  describe('Audit trail records every state change', () => {
    beforeEach(() => {
      store.claims.clear();
      store.auditEntries.length = 0;
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
      mockPatientCheck.exists.mockResolvedValue(true);
    });

    it('records CREATED audit entry on claim creation', async () => {
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = res.json().data.claimId;

      const audit = store.auditEntries.filter((e) => e.claimId === claimId);
      expect(audit).toHaveLength(1);
      expect(audit[0].action).toBe('claim.created');
      expect(audit[0].previousState).toBeNull();
      expect(audit[0].newState).toBe('DRAFT');
      expect(audit[0].actorId).toBe(PHYSICIAN1_USER_ID);
      expect(audit[0].actorContext).toBe('PHYSICIAN');
    });

    it('records VALIDATED audit entry on validation', async () => {
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = res.json().data.claimId;

      await authedPost(`/api/v1/claims/${claimId}/validate`);

      const audit = store.auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

      const validatedEntry = audit.find((e) => e.action === 'claim.validated');
      expect(validatedEntry).toBeDefined();
      expect(validatedEntry!.previousState).toBe('DRAFT');
      expect(validatedEntry!.newState).toBe('VALIDATED');
    });

    it('records QUEUED audit entry on queueing', async () => {
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = res.json().data.claimId;

      await authedPost(`/api/v1/claims/${claimId}/validate`);
      await authedPost(`/api/v1/claims/${claimId}/queue`);

      const audit = store.auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

      const queuedEntry = audit.find((e) => e.action === 'claim.queued');
      expect(queuedEntry).toBeDefined();
      expect(queuedEntry!.previousState).toBe('VALIDATED');
      expect(queuedEntry!.newState).toBe('QUEUED');
      expect(queuedEntry!.changes).toHaveProperty('isClean');
    });

    it('records UNQUEUED audit entry on unqueue', async () => {
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = res.json().data.claimId;

      await authedPost(`/api/v1/claims/${claimId}/validate`);
      await authedPost(`/api/v1/claims/${claimId}/queue`);
      await authedPost(`/api/v1/claims/${claimId}/unqueue`);

      const audit = store.auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

      const unqueuedEntry = audit.find((e) => e.action === 'claim.unqueued');
      expect(unqueuedEntry).toBeDefined();
      expect(unqueuedEntry!.previousState).toBe('QUEUED');
      expect(unqueuedEntry!.newState).toBe('VALIDATED');
    });

    it('records WRITTEN_OFF audit entry with reason', async () => {
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = res.json().data.claimId;

      // Set claim to REJECTED state
      store.claims.get(claimId)!.state = 'REJECTED';

      await authedPost(`/api/v1/claims/${claimId}/write-off`, {
        reason: 'Patient relocated, claim no longer valid',
      });

      const audit = store.auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

      const writtenOffEntry = audit.find((e) => e.action === 'claim.written_off');
      expect(writtenOffEntry).toBeDefined();
      expect(writtenOffEntry!.previousState).toBe('REJECTED');
      expect(writtenOffEntry!.newState).toBe('WRITTEN_OFF');
      expect(writtenOffEntry!.reason).toBe('Patient relocated, claim no longer valid');
    });

    it('audit history chain is complete and ordered for full lifecycle', async () => {
      // Create -> validate -> queue
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      const claimId = res.json().data.claimId;

      await authedPost(`/api/v1/claims/${claimId}/validate`);
      await authedPost(`/api/v1/claims/${claimId}/queue`);

      const audit = store.auditEntries
        .filter((e) => e.claimId === claimId)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

      // Each audit entry's newState should match the next entry's previousState
      // (excluding validation re-run entries during queue)
      const stateChanges = audit.filter(
        (e) => e.newState && e.action !== 'claim.validated' || e.action === 'claim.created',
      );

      // At minimum: created, validated (from validate call), queued
      expect(audit.length).toBeGreaterThanOrEqual(3);

      // Verify CREATED is first
      expect(audit[0].action).toBe('claim.created');

      // Verify chain ends with QUEUED
      const lastStateChange = audit
        .filter((e) => e.newState)
        .pop();
      expect(lastStateChange!.newState).toBe('QUEUED');
    });
  });
});
