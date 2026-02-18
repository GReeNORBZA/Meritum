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

const PHYSICIAN2_USER_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_SESSION_TOKEN_HASH = hashToken(PHYSICIAN2_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Test claim data
// ---------------------------------------------------------------------------

const VALID_CLAIM = {
  claim_type: 'AHCIP' as const,
  patient_id: '00000000-aaaa-0000-0000-000000000001',
  date_of_service: '2026-01-15',
};

const CLAIM_ID_1 = '00000000-cccc-0000-0000-000000000001';
const CLAIM_ID_2 = '00000000-cccc-0000-0000-000000000002';
const SUGGESTION_ID_1 = '00000000-dddd-0000-0000-000000000001';

function makeMockClaim(overrides: Record<string, unknown> = {}) {
  return {
    claimId: CLAIM_ID_1,
    physicianId: PHYSICIAN1_USER_ID,
    patientId: '00000000-aaaa-0000-0000-000000000001',
    claimType: 'AHCIP',
    state: 'DRAFT',
    importSource: 'MANUAL',
    dateOfService: '2026-01-15',
    submissionDeadline: '2026-04-15',
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
    createdBy: PHYSICIAN1_USER_ID,
    updatedBy: PHYSICIAN1_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
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
    updateClaim: vi.fn(async (_id: string, _pid: string, data: any) => undefined as any),
    softDeleteClaim: vi.fn(async () => false),
    listClaims: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    countClaimsByState: vi.fn(async () => []),
    findClaimsApproachingDeadline: vi.fn(async () => []),
    transitionState: vi.fn(async (_id: string, _pid: string, _from: string, _to: string) =>
      makeMockClaim(),
    ),
    classifyClaim: vi.fn(async () => makeMockClaim()),
    updateValidationResult: vi.fn(async () => makeMockClaim()),
    updateAiSuggestions: vi.fn(async () => makeMockClaim()),
    updateDuplicateAlert: vi.fn(async () => makeMockClaim()),
    updateFlags: vi.fn(async () => makeMockClaim()),
    findClaimsForBatchAssembly: vi.fn(async () => []),
    bulkTransitionState: vi.fn(async () => []),
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

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockClaimRepo();
  mockProviderCheck = {
    isActive: vi.fn(async () => true),
    getRegistrationDate: vi.fn(async () => '2020-01-01'),
  };
  mockPatientCheck = {
    exists: vi.fn(async () => true),
  };

  const serviceDeps: ClaimServiceDeps = {
    repo: mockRepo as any,
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

function authedDelete(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'DELETE',
    url,
    headers: { cookie: `session=${token}` },
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Claim Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Reset defaults
    mockProviderCheck.isActive.mockResolvedValue(true);
    mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
    mockPatientCheck.exists.mockResolvedValue(true);
  });

  // =========================================================================
  // POST /api/v1/claims — Create
  // =========================================================================

  describe('POST /api/v1/claims', () => {
    it('creates draft claim and returns 201', async () => {
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.claimId).toBeDefined();
      expect(mockRepo.createClaim).toHaveBeenCalledTimes(1);
      expect(mockRepo.appendClaimAudit).toHaveBeenCalledTimes(1);
    });

    it('rejects request without required fields with 400', async () => {
      const res = await authedPost('/api/v1/claims', {
        claim_type: 'AHCIP',
        // missing patient_id and date_of_service
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid claim_type with 400', async () => {
      const res = await authedPost('/api/v1/claims', {
        ...VALID_CLAIM,
        claim_type: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid date_of_service format with 400', async () => {
      const res = await authedPost('/api/v1/claims', {
        ...VALID_CLAIM,
        date_of_service: 'not-a-date',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid patient_id UUID with 400', async () => {
      const res = await authedPost('/api/v1/claims', {
        ...VALID_CLAIM,
        patient_id: 'not-a-uuid',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/claims', VALID_CLAIM);
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('returns 422 when physician is not active', async () => {
      mockProviderCheck.isActive.mockResolvedValueOnce(false);
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      expect(res.statusCode).toBe(422);
    });

    it('returns 404 when patient not found', async () => {
      mockPatientCheck.exists.mockResolvedValueOnce(false);
      const res = await authedPost('/api/v1/claims', VALID_CLAIM);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // GET /api/v1/claims — List
  // =========================================================================

  describe('GET /api/v1/claims', () => {
    it('lists physician\'s claims with filtering', async () => {
      const claims = [makeMockClaim(), makeMockClaim({ claimId: CLAIM_ID_2 })];
      mockRepo.listClaims.mockResolvedValueOnce({
        data: claims,
        pagination: { total: 2, page: 1, pageSize: 25, hasMore: false },
      });

      const res = await authedGet('/api/v1/claims');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveLength(2);
      expect(body.pagination.total).toBe(2);
    });

    it('filters by state query parameter', async () => {
      mockRepo.listClaims.mockResolvedValueOnce({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
      });

      const res = await authedGet('/api/v1/claims?state=DRAFT');
      expect(res.statusCode).toBe(200);
      expect(mockRepo.listClaims).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        expect.objectContaining({ state: 'DRAFT' }),
      );
    });

    it('filters by claim_type query parameter', async () => {
      mockRepo.listClaims.mockResolvedValueOnce({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
      });

      const res = await authedGet('/api/v1/claims?claim_type=AHCIP');
      expect(res.statusCode).toBe(200);
      expect(mockRepo.listClaims).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        expect.objectContaining({ claimType: 'AHCIP' }),
      );
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/claims');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/claims/:id — Get by ID
  // =========================================================================

  describe('GET /api/v1/claims/:id', () => {
    it('returns claim for owning physician', async () => {
      const claim = makeMockClaim();
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedGet(`/api/v1/claims/${CLAIM_ID_1}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.claimId).toBe(CLAIM_ID_1);
    });

    it('returns 404 for different physician', async () => {
      mockRepo.findClaimById.mockResolvedValueOnce(undefined);

      const res = await authedGet(`/api/v1/claims/${CLAIM_ID_1}`, PHYSICIAN2_SESSION_TOKEN);
      expect(res.statusCode).toBe(404);
    });

    it('returns 404 for non-existent claim', async () => {
      mockRepo.findClaimById.mockResolvedValueOnce(undefined);

      const res = await authedGet('/api/v1/claims/00000000-0000-0000-0000-000000000099');
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID id parameter', async () => {
      const res = await authedGet('/api/v1/claims/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/claims/${CLAIM_ID_1}`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // PUT /api/v1/claims/:id — Update
  // =========================================================================

  describe('PUT /api/v1/claims/:id', () => {
    it('updates claim fields', async () => {
      const existing = makeMockClaim();
      mockRepo.findClaimById.mockResolvedValueOnce(existing);
      mockRepo.updateClaim.mockResolvedValueOnce({
        ...existing,
        dateOfService: '2026-02-01',
        updatedAt: new Date(),
      });

      const res = await authedPut(`/api/v1/claims/${CLAIM_ID_1}`, {
        date_of_service: '2026-02-01',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.dateOfService).toBe('2026-02-01');
    });

    it('returns 404 for non-existent claim', async () => {
      mockRepo.findClaimById.mockResolvedValueOnce(undefined);

      const res = await authedPut(`/api/v1/claims/${CLAIM_ID_1}`, {
        date_of_service: '2026-02-01',
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = app.inject({
        method: 'PUT',
        url: `/api/v1/claims/${CLAIM_ID_1}`,
        headers: { 'content-type': 'application/json' },
        payload: { date_of_service: '2026-02-01' },
      });
      expect((await res).statusCode).toBe(401);
    });
  });

  // =========================================================================
  // DELETE /api/v1/claims/:id — Soft Delete
  // =========================================================================

  describe('DELETE /api/v1/claims/:id', () => {
    it('soft-deletes draft claim', async () => {
      const existing = makeMockClaim({ state: 'DRAFT' });
      mockRepo.findClaimById.mockResolvedValueOnce(existing);
      mockRepo.softDeleteClaim.mockResolvedValueOnce(true);

      const res = await authedDelete(`/api/v1/claims/${CLAIM_ID_1}`);
      expect(res.statusCode).toBe(204);
      expect(mockRepo.softDeleteClaim).toHaveBeenCalledWith(CLAIM_ID_1, PHYSICIAN1_USER_ID);
    });

    it('returns 409 for non-draft claim', async () => {
      const existing = makeMockClaim({ state: 'VALIDATED' });
      mockRepo.findClaimById.mockResolvedValueOnce(existing);

      const res = await authedDelete(`/api/v1/claims/${CLAIM_ID_1}`);
      expect(res.statusCode).toBe(409);
      expect(res.json().error.code).toBe('CONFLICT');
    });

    it('returns 404 for non-existent claim', async () => {
      mockRepo.findClaimById.mockResolvedValueOnce(undefined);

      const res = await authedDelete(`/api/v1/claims/${CLAIM_ID_1}`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = app.inject({
        method: 'DELETE',
        url: `/api/v1/claims/${CLAIM_ID_1}`,
      });
      expect((await res).statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/claims/:id/validate
  // =========================================================================

  describe('POST /api/v1/claims/:id/validate', () => {
    it('returns validation result', async () => {
      const claim = makeMockClaim();
      mockRepo.findClaimById.mockResolvedValue(claim);
      mockRepo.listClaims.mockResolvedValue({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 100, hasMore: false },
      });

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/validate`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data).toHaveProperty('passed');
      expect(body.data).toHaveProperty('errors');
      expect(body.data).toHaveProperty('warnings');
    });

    it('returns 404 for non-existent claim', async () => {
      mockRepo.findClaimById.mockResolvedValueOnce(undefined);

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/validate`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/claims/${CLAIM_ID_1}/validate`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/claims/:id/queue
  // =========================================================================

  describe('POST /api/v1/claims/:id/queue', () => {
    it('queues validated claim', async () => {
      const claim = makeMockClaim({ state: 'VALIDATED' });
      mockRepo.findClaimById.mockResolvedValue(claim);
      mockRepo.listClaims.mockResolvedValue({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 100, hasMore: false },
      });

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/queue`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('isClean');
    });

    it('returns 409 for draft claim (wrong state)', async () => {
      const claim = makeMockClaim({ state: 'DRAFT' });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/queue`);
      expect(res.statusCode).toBe(409);
    });

    it('returns 404 for non-existent claim', async () => {
      mockRepo.findClaimById.mockResolvedValueOnce(undefined);

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/queue`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/claims/${CLAIM_ID_1}/queue`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/claims/:id/unqueue
  // =========================================================================

  describe('POST /api/v1/claims/:id/unqueue', () => {
    it('returns claim to validated', async () => {
      const claim = makeMockClaim({ state: 'QUEUED' });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/unqueue`);
      expect(res.statusCode).toBe(200);
      expect(mockRepo.transitionState).toHaveBeenCalledWith(
        CLAIM_ID_1,
        PHYSICIAN1_USER_ID,
        'QUEUED',
        'VALIDATED',
      );
    });

    it('returns 409 for non-queued claim', async () => {
      const claim = makeMockClaim({ state: 'DRAFT' });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/unqueue`);
      expect(res.statusCode).toBe(409);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/claims/${CLAIM_ID_1}/unqueue`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/claims/:id/write-off
  // =========================================================================

  describe('POST /api/v1/claims/:id/write-off', () => {
    it('transitions rejected to written_off', async () => {
      const claim = makeMockClaim({ state: 'REJECTED' });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/write-off`, {
        reason: 'Patient deceased, claim no longer valid',
      });
      expect(res.statusCode).toBe(200);
      expect(mockRepo.transitionState).toHaveBeenCalledWith(
        CLAIM_ID_1,
        PHYSICIAN1_USER_ID,
        'REJECTED',
        'WRITTEN_OFF',
      );
    });

    it('returns 409 for non-rejected claim', async () => {
      const claim = makeMockClaim({ state: 'DRAFT' });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/write-off`, {
        reason: 'Write off reason',
      });
      expect(res.statusCode).toBe(409);
    });

    it('returns 400 without reason', async () => {
      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/write-off`, {});
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/claims/${CLAIM_ID_1}/write-off`, {
        reason: 'test',
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/claims/:id/resubmit
  // =========================================================================

  describe('POST /api/v1/claims/:id/resubmit', () => {
    it('revalidates and requeues rejected claim', async () => {
      const claim = makeMockClaim({ state: 'REJECTED' });
      mockRepo.findClaimById.mockResolvedValue(claim);
      mockRepo.listClaims.mockResolvedValue({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 100, hasMore: false },
      });

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/resubmit`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.newState).toBe('QUEUED');
    });

    it('returns 409 for non-rejected claim', async () => {
      const claim = makeMockClaim({ state: 'DRAFT' });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedPost(`/api/v1/claims/${CLAIM_ID_1}/resubmit`);
      expect(res.statusCode).toBe(409);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/claims/${CLAIM_ID_1}/resubmit`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/claims/:id/suggestions — AI Coach
  // =========================================================================

  describe('GET /api/v1/claims/:id/suggestions', () => {
    it('returns AI suggestions', async () => {
      const claim = makeMockClaim({
        aiCoachSuggestions: {
          suggestions: [
            { id: SUGGESTION_ID_1, status: 'PENDING', field: 'dateOfService', suggestedValue: '2026-01-20', reason: 'More accurate' },
          ],
        },
      });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedGet(`/api/v1/claims/${CLAIM_ID_1}/suggestions`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.suggestions).toHaveLength(1);
      expect(body.data.suggestions[0].id).toBe(SUGGESTION_ID_1);
    });

    it('returns empty suggestions when none exist', async () => {
      const claim = makeMockClaim({ aiCoachSuggestions: null });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedGet(`/api/v1/claims/${CLAIM_ID_1}/suggestions`);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.suggestions).toHaveLength(0);
    });

    it('returns 404 for non-existent claim', async () => {
      mockRepo.findClaimById.mockResolvedValueOnce(undefined);

      const res = await authedGet(`/api/v1/claims/${CLAIM_ID_1}/suggestions`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/claims/${CLAIM_ID_1}/suggestions`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/claims/:id/suggestions/:sug_id/accept
  // =========================================================================

  describe('POST /api/v1/claims/:id/suggestions/:sug_id/accept', () => {
    it('applies suggestion', async () => {
      const claim = makeMockClaim({
        aiCoachSuggestions: {
          suggestions: [
            { id: SUGGESTION_ID_1, status: 'PENDING', field: 'dateOfService', suggestedValue: '2026-01-20' },
          ],
        },
      });
      mockRepo.findClaimById.mockResolvedValue(claim);
      mockRepo.listClaims.mockResolvedValue({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 100, hasMore: false },
      });

      const res = await authedPost(
        `/api/v1/claims/${CLAIM_ID_1}/suggestions/${SUGGESTION_ID_1}/accept`,
      );
      expect(res.statusCode).toBe(200);
      expect(mockRepo.updateAiSuggestions).toHaveBeenCalled();
      expect(mockRepo.appendClaimAudit).toHaveBeenCalled();
    });

    it('returns 404 for non-existent suggestion', async () => {
      const claim = makeMockClaim({ aiCoachSuggestions: { suggestions: [] } });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedPost(
        `/api/v1/claims/${CLAIM_ID_1}/suggestions/00000000-0000-0000-0000-000000000099/accept`,
      );
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(
        `/api/v1/claims/${CLAIM_ID_1}/suggestions/${SUGGESTION_ID_1}/accept`,
      );
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/claims/:id/suggestions/:sug_id/dismiss
  // =========================================================================

  describe('POST /api/v1/claims/:id/suggestions/:sug_id/dismiss', () => {
    it('dismisses suggestion with reason', async () => {
      const claim = makeMockClaim({
        aiCoachSuggestions: {
          suggestions: [
            { id: SUGGESTION_ID_1, status: 'PENDING', field: 'dateOfService', suggestedValue: '2026-01-20' },
          ],
        },
      });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedPost(
        `/api/v1/claims/${CLAIM_ID_1}/suggestions/${SUGGESTION_ID_1}/dismiss`,
        { reason: 'Not applicable' },
      );
      expect(res.statusCode).toBe(200);
      expect(mockRepo.updateAiSuggestions).toHaveBeenCalled();
    });

    it('dismisses suggestion without reason', async () => {
      const claim = makeMockClaim({
        aiCoachSuggestions: {
          suggestions: [
            { id: SUGGESTION_ID_1, status: 'PENDING', field: 'dateOfService', suggestedValue: '2026-01-20' },
          ],
        },
      });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedPost(
        `/api/v1/claims/${CLAIM_ID_1}/suggestions/${SUGGESTION_ID_1}/dismiss`,
        {},
      );
      expect(res.statusCode).toBe(200);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(
        `/api/v1/claims/${CLAIM_ID_1}/suggestions/${SUGGESTION_ID_1}/dismiss`,
        { reason: 'test' },
      );
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/claims/rejected
  // =========================================================================

  describe('GET /api/v1/claims/rejected', () => {
    it('lists rejected claims with enriched rejection codes', async () => {
      const rejectedClaim = makeMockClaim({
        state: 'REJECTED',
        validationResult: {
          errors: [{ check: 'S3_PATIENT_EXISTS', message: 'Patient not found', help_text: 'Verify patient' }],
          warnings: [],
          info: [],
          passed: false,
        },
      });
      mockRepo.listClaims.mockResolvedValueOnce({
        data: [rejectedClaim],
        pagination: { total: 1, page: 1, pageSize: 25, hasMore: false },
      });

      const res = await authedGet('/api/v1/claims/rejected');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveLength(1);
      expect(body.data[0].rejectionCodes).toBeDefined();
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/claims/rejected');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/claims/:id/rejection-details
  // =========================================================================

  describe('GET /api/v1/claims/:id/rejection-details', () => {
    it('returns rejection details for rejected claim', async () => {
      const claim = makeMockClaim({
        state: 'REJECTED',
        validationResult: {
          errors: [{ check: 'S3_PATIENT_EXISTS', message: 'Patient not found', help_text: 'Verify patient' }],
          warnings: [],
          info: [],
          passed: false,
        },
      });
      mockRepo.findClaimById.mockResolvedValueOnce(claim);

      const res = await authedGet(`/api/v1/claims/${CLAIM_ID_1}/rejection-details`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.claimId).toBe(CLAIM_ID_1);
      expect(body.data.rejectionCodes).toBeDefined();
      expect(body.data.resubmissionEligible).toBe(true);
    });

    it('returns 404 for non-existent claim', async () => {
      mockRepo.findClaimById.mockResolvedValueOnce(undefined);

      const res = await authedGet(`/api/v1/claims/${CLAIM_ID_1}/rejection-details`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/claims/${CLAIM_ID_1}/rejection-details`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/claims/:id/audit
  // =========================================================================

  describe('GET /api/v1/claims/:id/audit', () => {
    it('returns audit history for claim', async () => {
      const auditEntries = [
        { auditId: '1', claimId: CLAIM_ID_1, action: 'claim.created', createdAt: new Date() },
        { auditId: '2', claimId: CLAIM_ID_1, action: 'claim.validated', createdAt: new Date() },
      ];
      mockRepo.getClaimAuditHistory.mockResolvedValueOnce(auditEntries);

      const res = await authedGet(`/api/v1/claims/${CLAIM_ID_1}/audit`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveLength(2);
    });

    it('returns empty array for claim with no audit trail', async () => {
      mockRepo.getClaimAuditHistory.mockResolvedValueOnce([]);

      const res = await authedGet(`/api/v1/claims/${CLAIM_ID_1}/audit`);
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toHaveLength(0);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/claims/${CLAIM_ID_1}/audit`);
      expect(res.statusCode).toBe(401);
    });
  });
});
