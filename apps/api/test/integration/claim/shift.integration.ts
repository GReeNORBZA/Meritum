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

const FACILITY_ID = '00000000-aaaa-0000-0000-000000000001';
const PATIENT_ID_1 = '00000000-aaaa-0000-0000-000000000010';
const PATIENT_ID_2 = '00000000-aaaa-0000-0000-000000000011';
const PATIENT_ID_3 = '00000000-aaaa-0000-0000-000000000012';

// ---------------------------------------------------------------------------
// Stateful shift store (simulates shift + claim persistence)
// ---------------------------------------------------------------------------

function createStatefulShiftStore() {
  const shifts = new Map<string, Record<string, any>>();
  const claims = new Map<string, Record<string, any>>();
  const auditEntries: Array<Record<string, any>> = [];
  let shiftIdCounter = 0;
  let claimIdCounter = 0;

  return {
    shifts,
    claims,
    auditEntries,

    // Core claim methods
    createClaim: vi.fn(async (data: any) => {
      const claimId = `00000000-cccc-0000-0000-${String(++claimIdCounter).padStart(12, '0')}`;
      const claim = {
        claimId,
        ...data,
        state: 'DRAFT',
        isClean: null,
        validationResult: null,
        validationTimestamp: null,
        referenceDataVersion: null,
        aiCoachSuggestions: null,
        duplicateAlert: null,
        flags: null,
        submittedBatchId: null,
        importBatchId: null,
        deletedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      claims.set(claimId, claim);
      return claim;
    }),
    findClaimById: vi.fn(async (claimId: string, physicianId: string) => {
      const c = claims.get(claimId);
      if (!c || c.physicianId !== physicianId || c.deletedAt) return undefined;
      return { ...c };
    }),
    updateClaim: vi.fn(async () => undefined as any),
    softDeleteClaim: vi.fn(async () => false),
    listClaims: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    countClaimsByState: vi.fn(async () => []),
    findClaimsApproachingDeadline: vi.fn(async () => []),
    transitionState: vi.fn(async () => ({})),
    classifyClaim: vi.fn(async () => ({})),
    updateValidationResult: vi.fn(async () => ({})),
    updateAiSuggestions: vi.fn(async () => ({})),
    updateDuplicateAlert: vi.fn(async () => ({})),
    updateFlags: vi.fn(async () => ({})),
    findClaimsForBatchAssembly: vi.fn(async () => []),
    bulkTransitionState: vi.fn(async () => []),

    // Import methods (stubs)
    createImportBatch: vi.fn(),
    findImportBatchById: vi.fn(),
    updateImportBatchStatus: vi.fn(),
    findDuplicateImportByHash: vi.fn(),
    listImportBatches: vi.fn(),

    // Template methods (stubs)
    createTemplate: vi.fn(),
    findTemplateById: vi.fn(),
    updateTemplate: vi.fn(),
    deleteTemplate: vi.fn(),
    listTemplates: vi.fn(),

    // Shift methods (stateful)
    createShift: vi.fn(async (data: any) => {
      const shiftId = `00000000-bbbb-0000-0000-${String(++shiftIdCounter).padStart(12, '0')}`;
      const shift = {
        shiftId,
        ...data,
        status: 'IN_PROGRESS',
        encounterCount: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      shifts.set(shiftId, shift);
      return shift;
    }),
    findShiftById: vi.fn(async (shiftId: string, physicianId: string) => {
      const shift = shifts.get(shiftId);
      if (!shift || shift.physicianId !== physicianId) return undefined;
      return { ...shift };
    }),
    updateShiftStatus: vi.fn(async (shiftId: string, physicianId: string, status: string) => {
      const shift = shifts.get(shiftId);
      if (!shift || shift.physicianId !== physicianId) return undefined;
      shift.status = status;
      shift.updatedAt = new Date();
      return { ...shift };
    }),
    updateShiftTimes: vi.fn(async () => ({})),
    incrementEncounterCount: vi.fn(async (shiftId: string, physicianId: string) => {
      const shift = shifts.get(shiftId);
      if (!shift || shift.physicianId !== physicianId) return;
      shift.encounterCount = (shift.encounterCount || 0) + 1;
      return { ...shift };
    }),
    listShifts: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    findClaimsByShift: vi.fn(async (shiftId: string, physicianId: string) => {
      return Array.from(claims.values()).filter(
        (c) => c.shiftId === shiftId && c.physicianId === physicianId && !c.deletedAt,
      );
    }),

    // Export methods (stubs)
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
    getClaimAuditHistory: vi.fn(async () => []),
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
let store: ReturnType<typeof createStatefulShiftStore>;
let mockProviderCheck: { isActive: ReturnType<typeof vi.fn>; getRegistrationDate: ReturnType<typeof vi.fn> };
let mockPatientCheck: { exists: ReturnType<typeof vi.fn> };
let mockFacilityCheck: { belongsToPhysician: ReturnType<typeof vi.fn> };
let mockAfterHoursCalculator: { calculatePremiums: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  store = createStatefulShiftStore();
  mockProviderCheck = {
    isActive: vi.fn(async () => true),
    getRegistrationDate: vi.fn(async () => '2020-01-01'),
  };
  mockPatientCheck = {
    exists: vi.fn(async () => true),
  };
  mockFacilityCheck = {
    belongsToPhysician: vi.fn(async () => true),
  };
  mockAfterHoursCalculator = {
    calculatePremiums: vi.fn(async () => []),
  };

  const serviceDeps: ClaimServiceDeps = {
    repo: store as any,
    providerCheck: mockProviderCheck,
    patientCheck: mockPatientCheck,
    facilityCheck: mockFacilityCheck,
    afterHoursPremiumCalculators: {
      AHCIP: mockAfterHoursCalculator,
    },
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

function authedPut(url: string, body?: Record<string, unknown>, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'PUT',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ED Shift Workflow Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // Full shift lifecycle: create -> encounters -> complete
  // =========================================================================

  describe('Create shift -> add encounters -> complete lifecycle', () => {
    let shiftId: string;

    beforeAll(() => {
      store.shifts.clear();
      store.claims.clear();
      store.auditEntries.length = 0;
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockPatientCheck.exists.mockResolvedValue(true);
      mockFacilityCheck.belongsToPhysician.mockResolvedValue(true);
    });

    it('Step 1: creates a new shift in IN_PROGRESS status', async () => {
      const res = await authedPost('/api/v1/shifts', {
        facility_id: FACILITY_ID,
        shift_date: '2026-02-01',
        start_time: '18:00:00',
        end_time: '06:00:00',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data.shiftId).toBeDefined();
      shiftId = body.data.shiftId;

      // Verify shift is IN_PROGRESS
      const shift = store.shifts.get(shiftId);
      expect(shift).toBeDefined();
      expect(shift!.status).toBe('IN_PROGRESS');
      expect(shift!.encounterCount).toBe(0);
    });

    it('Step 2: adds first encounter to shift', async () => {
      const res = await authedPost(`/api/v1/shifts/${shiftId}/encounters`, {
        patient_id: PATIENT_ID_1,
        date_of_service: '2026-02-01',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data.claimId).toBeDefined();

      // Verify encounter count incremented
      const shift = store.shifts.get(shiftId)!;
      expect(shift.encounterCount).toBe(1);

      // Verify claim linked to shift
      const claim = store.claims.get(body.data.claimId);
      expect(claim).toBeDefined();
      expect(claim!.shiftId).toBe(shiftId);
      expect(claim!.importSource).toBe('ED_SHIFT');
    });

    it('Step 3: adds second encounter to shift', async () => {
      const res = await authedPost(`/api/v1/shifts/${shiftId}/encounters`, {
        patient_id: PATIENT_ID_2,
        date_of_service: '2026-02-01',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(201);

      const shift = store.shifts.get(shiftId)!;
      expect(shift.encounterCount).toBe(2);
    });

    it('Step 4: adds third encounter to shift', async () => {
      const res = await authedPost(`/api/v1/shifts/${shiftId}/encounters`, {
        patient_id: PATIENT_ID_3,
        date_of_service: '2026-02-01',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(201);

      const shift = store.shifts.get(shiftId)!;
      expect(shift.encounterCount).toBe(3);
    });

    it('Step 5: completes shift and triggers after-hours calculation', async () => {
      const res = await authedPut(`/api/v1/shifts/${shiftId}/complete`);
      expect(res.statusCode).toBe(200);
      const body = res.json();

      // Verify shift completed
      expect(body.data.shift).toBeDefined();
      expect(body.data.claims).toBeDefined();
      expect(body.data.claims).toHaveLength(3);

      // Verify shift transitioned to COMPLETED
      const shift = store.shifts.get(shiftId)!;
      expect(shift.status).toBe('COMPLETED');

      // Verify after-hours premium calculator was called
      expect(mockAfterHoursCalculator.calculatePremiums).toHaveBeenCalledTimes(1);
      expect(mockAfterHoursCalculator.calculatePremiums).toHaveBeenCalledWith(
        expect.any(Array),
        '18:00:00',
        '06:00:00',
      );
    });

    it('Step 6: shift encounter count matches actual claims', async () => {
      // Fetch shift details via API
      const res = await authedGet(`/api/v1/shifts/${shiftId}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();

      expect(body.data.shift.encounterCount).toBe(3);
      expect(body.data.claims).toHaveLength(3);

      // Every claim should reference this shift
      body.data.claims.forEach((claim: any) => {
        expect(claim.shiftId).toBe(shiftId);
        expect(claim.importSource).toBe('ED_SHIFT');
      });
    });
  });

  // =========================================================================
  // Reject encounter on completed shift
  // =========================================================================

  describe('Reject encounter on completed shift', () => {
    let completedShiftId: string;

    beforeAll(async () => {
      store.shifts.clear();
      store.claims.clear();
      store.auditEntries.length = 0;
      mockProviderCheck.isActive.mockResolvedValue(true);
      mockPatientCheck.exists.mockResolvedValue(true);
      mockFacilityCheck.belongsToPhysician.mockResolvedValue(true);

      // Create and immediately complete a shift
      const createRes = await authedPost('/api/v1/shifts', {
        facility_id: FACILITY_ID,
        shift_date: '2026-02-10',
        start_time: '08:00:00',
        end_time: '16:00:00',
      });
      completedShiftId = createRes.json().data.shiftId;

      // Add one encounter before completing
      await authedPost(`/api/v1/shifts/${completedShiftId}/encounters`, {
        patient_id: PATIENT_ID_1,
        date_of_service: '2026-02-10',
        claim_type: 'AHCIP',
      });

      // Complete the shift
      await authedPut(`/api/v1/shifts/${completedShiftId}/complete`);
    });

    it('rejects adding an encounter to a completed shift with 422', async () => {
      const res = await authedPost(`/api/v1/shifts/${completedShiftId}/encounters`, {
        patient_id: PATIENT_ID_2,
        date_of_service: '2026-02-10',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(422);

      // Verify encounter count did not change
      const shift = store.shifts.get(completedShiftId)!;
      expect(shift.encounterCount).toBe(1);

      // Verify no additional claims were created for this shift
      const shiftClaims = Array.from(store.claims.values()).filter(
        (c) => c.shiftId === completedShiftId,
      );
      expect(shiftClaims).toHaveLength(1);
    });

    it('rejects completing an already completed shift with 422', async () => {
      const res = await authedPut(`/api/v1/shifts/${completedShiftId}/complete`);
      expect(res.statusCode).toBe(422);
    });
  });
});
