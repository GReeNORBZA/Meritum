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

const SHIFT_ID = '00000000-bbbb-0000-0000-000000000001';
const FACILITY_ID = '00000000-aaaa-0000-0000-000000000001';
const PATIENT_ID = '00000000-aaaa-0000-0000-000000000002';

function makeMockShift(overrides: Record<string, unknown> = {}) {
  return {
    shiftId: SHIFT_ID,
    physicianId: PHYSICIAN1_USER_ID,
    facilityId: FACILITY_ID,
    shiftDate: '2026-02-01',
    startTime: '18:00:00',
    endTime: '06:00:00',
    status: 'IN_PROGRESS',
    encounterCount: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
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
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock claim repository
// ---------------------------------------------------------------------------

function createMockClaimRepo() {
  return {
    createClaim: vi.fn(async (data: any) => ({
      claimId: crypto.randomUUID(),
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
      shiftId: null,
      importBatchId: null,
      deletedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findClaimById: vi.fn(async () => undefined as any),
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

    // Import methods
    createImportBatch: vi.fn(),
    findImportBatchById: vi.fn(),
    updateImportBatchStatus: vi.fn(),
    findDuplicateImportByHash: vi.fn(),
    listImportBatches: vi.fn(),

    // Template methods
    createTemplate: vi.fn(),
    findTemplateById: vi.fn(),
    updateTemplate: vi.fn(),
    deleteTemplate: vi.fn(),
    listTemplates: vi.fn(),

    // Shift methods
    createShift: vi.fn(async (data: any) => ({
      shiftId: SHIFT_ID,
      ...data,
      status: 'IN_PROGRESS',
      encounterCount: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findShiftById: vi.fn(async () => undefined as any),
    updateShiftStatus: vi.fn(async (_id: string, _pid: string, status: string) => ({
      ...makeMockShift(),
      status,
    })),
    updateShiftTimes: vi.fn(),
    incrementEncounterCount: vi.fn(async () => ({})),
    listShifts: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    findClaimsByShift: vi.fn(async () => []),

    // Export methods
    createExportRecord: vi.fn(),
    findExportById: vi.fn(),
    updateExportStatus: vi.fn(),

    // Audit
    appendClaimAudit: vi.fn(async () => ({})),
    getClaimAuditHistory: vi.fn(async () => []),
    getClaimAuditHistoryPaginated: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockClaimRepo>;
let mockProviderCheck: { isActive: ReturnType<typeof vi.fn>; getRegistrationDate: ReturnType<typeof vi.fn> };
let mockPatientCheck: { exists: ReturnType<typeof vi.fn> };
let mockFacilityCheck: { belongsToPhysician: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockClaimRepo();
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

  const serviceDeps: ClaimServiceDeps = {
    repo: mockRepo as any,
    providerCheck: mockProviderCheck,
    patientCheck: mockPatientCheck,
    facilityCheck: mockFacilityCheck,
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

function unauthedPut(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'PUT',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body ?? {},
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ED Shift Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mockProviderCheck.isActive.mockResolvedValue(true);
    mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
    mockPatientCheck.exists.mockResolvedValue(true);
    mockFacilityCheck.belongsToPhysician.mockResolvedValue(true);
  });

  // =========================================================================
  // POST /api/v1/shifts — Create Shift
  // =========================================================================

  describe('POST /api/v1/shifts', () => {
    it('creates shift with IN_PROGRESS status', async () => {
      const res = await authedPost('/api/v1/shifts', {
        facility_id: FACILITY_ID,
        shift_date: '2026-02-01',
        start_time: '18:00:00',
        end_time: '06:00:00',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.shiftId).toBe(SHIFT_ID);
      expect(mockRepo.createShift).toHaveBeenCalledTimes(1);
    });

    it('creates shift without optional times', async () => {
      const res = await authedPost('/api/v1/shifts', {
        facility_id: FACILITY_ID,
        shift_date: '2026-02-01',
      });
      expect(res.statusCode).toBe(201);
    });

    it('rejects invalid facility_id format', async () => {
      const res = await authedPost('/api/v1/shifts', {
        facility_id: 'not-a-uuid',
        shift_date: '2026-02-01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid shift_date format', async () => {
      const res = await authedPost('/api/v1/shifts', {
        facility_id: FACILITY_ID,
        shift_date: 'not-a-date',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid time format', async () => {
      const res = await authedPost('/api/v1/shifts', {
        facility_id: FACILITY_ID,
        shift_date: '2026-02-01',
        start_time: '25:00',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 404 when facility does not belong to physician', async () => {
      mockFacilityCheck.belongsToPhysician.mockResolvedValueOnce(false);

      const res = await authedPost('/api/v1/shifts', {
        facility_id: FACILITY_ID,
        shift_date: '2026-02-01',
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 422 when physician is not active', async () => {
      mockProviderCheck.isActive.mockResolvedValueOnce(false);

      const res = await authedPost('/api/v1/shifts', {
        facility_id: FACILITY_ID,
        shift_date: '2026-02-01',
      });
      expect(res.statusCode).toBe(422);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/shifts', {
        facility_id: FACILITY_ID,
        shift_date: '2026-02-01',
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/shifts/:id/encounters — Add Encounter
  // =========================================================================

  describe('POST /api/v1/shifts/:id/encounters', () => {
    it('adds encounter to shift', async () => {
      mockRepo.findShiftById.mockResolvedValueOnce(makeMockShift());

      const res = await authedPost(`/api/v1/shifts/${SHIFT_ID}/encounters`, {
        patient_id: PATIENT_ID,
        date_of_service: '2026-02-01',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data.claimId).toBeDefined();
      expect(mockRepo.createClaim).toHaveBeenCalledTimes(1);
      expect(mockRepo.incrementEncounterCount).toHaveBeenCalledWith(SHIFT_ID, PHYSICIAN1_USER_ID);
    });

    it('returns 404 when shift does not exist', async () => {
      mockRepo.findShiftById.mockResolvedValueOnce(undefined);

      const res = await authedPost(`/api/v1/shifts/${SHIFT_ID}/encounters`, {
        patient_id: PATIENT_ID,
        date_of_service: '2026-02-01',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(404);
    });

    it('rejects encounter on completed shift', async () => {
      mockRepo.findShiftById.mockResolvedValueOnce(
        makeMockShift({ status: 'COMPLETED' }),
      );

      const res = await authedPost(`/api/v1/shifts/${SHIFT_ID}/encounters`, {
        patient_id: PATIENT_ID,
        date_of_service: '2026-02-01',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(422);
    });

    it('rejects invalid claim_type', async () => {
      const res = await authedPost(`/api/v1/shifts/${SHIFT_ID}/encounters`, {
        patient_id: PATIENT_ID,
        date_of_service: '2026-02-01',
        claim_type: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/shifts/${SHIFT_ID}/encounters`, {
        patient_id: PATIENT_ID,
        date_of_service: '2026-02-01',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // PUT /api/v1/shifts/:id/complete — Complete Shift
  // =========================================================================

  describe('PUT /api/v1/shifts/:id/complete', () => {
    it('completes shift', async () => {
      mockRepo.findShiftById.mockResolvedValueOnce(makeMockShift());
      mockRepo.findClaimsByShift.mockResolvedValueOnce([]);

      const res = await authedPut(`/api/v1/shifts/${SHIFT_ID}/complete`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.shift).toBeDefined();
      expect(body.data.claims).toBeDefined();
      expect(mockRepo.updateShiftStatus).toHaveBeenCalledWith(
        SHIFT_ID,
        PHYSICIAN1_USER_ID,
        'COMPLETED',
      );
    });

    it('returns 404 for non-existent shift', async () => {
      mockRepo.findShiftById.mockResolvedValueOnce(undefined);

      const res = await authedPut(`/api/v1/shifts/${SHIFT_ID}/complete`);
      expect(res.statusCode).toBe(404);
    });

    it('rejects completing already completed shift', async () => {
      mockRepo.findShiftById.mockResolvedValueOnce(
        makeMockShift({ status: 'COMPLETED' }),
      );

      const res = await authedPut(`/api/v1/shifts/${SHIFT_ID}/complete`);
      expect(res.statusCode).toBe(422);
    });

    it('returns 400 for non-UUID id', async () => {
      const res = await authedPut('/api/v1/shifts/not-a-uuid/complete');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPut(`/api/v1/shifts/${SHIFT_ID}/complete`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/shifts/:id — Get Shift Details
  // =========================================================================

  describe('GET /api/v1/shifts/:id', () => {
    it('returns shift with linked claims', async () => {
      mockRepo.findShiftById.mockResolvedValueOnce(makeMockShift());
      mockRepo.findClaimsByShift.mockResolvedValueOnce([
        { claimId: crypto.randomUUID(), state: 'DRAFT' },
      ]);

      const res = await authedGet(`/api/v1/shifts/${SHIFT_ID}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.shift).toBeDefined();
      expect(body.data.shift.shiftId).toBe(SHIFT_ID);
      expect(body.data.claims).toHaveLength(1);
    });

    it('returns 404 for non-existent shift', async () => {
      mockRepo.findShiftById.mockResolvedValueOnce(undefined);

      const res = await authedGet(`/api/v1/shifts/${SHIFT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID id', async () => {
      const res = await authedGet('/api/v1/shifts/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/shifts/${SHIFT_ID}`);
      expect(res.statusCode).toBe(401);
    });
  });
});
