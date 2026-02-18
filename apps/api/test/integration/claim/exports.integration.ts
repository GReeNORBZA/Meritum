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

const EXPORT_ID = '00000000-dddd-0000-0000-000000000001';

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
    createShift: vi.fn(),
    findShiftById: vi.fn(),
    updateShiftStatus: vi.fn(),
    updateShiftTimes: vi.fn(),
    incrementEncounterCount: vi.fn(),
    listShifts: vi.fn(),
    findClaimsByShift: vi.fn(),

    // Export methods
    createExportRecord: vi.fn(async (data: any) => ({
      exportId: EXPORT_ID,
      ...data,
      status: 'PENDING',
      filePath: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findExportById: vi.fn(async () => undefined as any),
    updateExportStatus: vi.fn(async () => ({})),

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

describe('Data Export & Submission Preferences Integration Tests', () => {
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
  });

  // =========================================================================
  // POST /api/v1/exports — Create Export
  // =========================================================================

  describe('POST /api/v1/exports', () => {
    it('creates export request', async () => {
      const res = await authedPost('/api/v1/exports', {
        date_from: '2026-01-01',
        date_to: '2026-01-31',
        format: 'CSV',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.exportId).toBe(EXPORT_ID);
      expect(mockRepo.createExportRecord).toHaveBeenCalledTimes(1);
    });

    it('creates export with optional claim_type filter', async () => {
      const res = await authedPost('/api/v1/exports', {
        date_from: '2026-01-01',
        date_to: '2026-01-31',
        claim_type: 'AHCIP',
        format: 'JSON',
      });
      expect(res.statusCode).toBe(201);
    });

    it('defaults format to CSV', async () => {
      const res = await authedPost('/api/v1/exports', {
        date_from: '2026-01-01',
        date_to: '2026-01-31',
      });
      expect(res.statusCode).toBe(201);
      expect(mockRepo.createExportRecord).toHaveBeenCalledWith(
        expect.objectContaining({ format: 'CSV' }),
      );
    });

    it('rejects invalid date_from', async () => {
      const res = await authedPost('/api/v1/exports', {
        date_from: 'not-a-date',
        date_to: '2026-01-31',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects missing date_to', async () => {
      const res = await authedPost('/api/v1/exports', {
        date_from: '2026-01-01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects date_from after date_to', async () => {
      const res = await authedPost('/api/v1/exports', {
        date_from: '2026-02-01',
        date_to: '2026-01-01',
      });
      expect(res.statusCode).toBe(422);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/exports', {
        date_from: '2026-01-01',
        date_to: '2026-01-31',
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/exports/:id — Get Export Status
  // =========================================================================

  describe('GET /api/v1/exports/:id', () => {
    it('returns status and download URL', async () => {
      mockRepo.findExportById.mockResolvedValueOnce({
        exportId: EXPORT_ID,
        physicianId: PHYSICIAN1_USER_ID,
        status: 'COMPLETED',
        filePath: `exports/${PHYSICIAN1_USER_ID}/${EXPORT_ID}.csv`,
        dateFrom: '2026-01-01',
        dateTo: '2026-01-31',
        format: 'CSV',
      });

      const res = await authedGet(`/api/v1/exports/${EXPORT_ID}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.exportId).toBe(EXPORT_ID);
      expect(body.data.status).toBe('COMPLETED');
      expect(body.data.filePath).toBeDefined();
    });

    it('returns pending status with no file path', async () => {
      mockRepo.findExportById.mockResolvedValueOnce({
        exportId: EXPORT_ID,
        physicianId: PHYSICIAN1_USER_ID,
        status: 'PENDING',
        filePath: null,
        dateFrom: '2026-01-01',
        dateTo: '2026-01-31',
        format: 'CSV',
      });

      const res = await authedGet(`/api/v1/exports/${EXPORT_ID}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.status).toBe('PENDING');
      expect(body.data.filePath).toBeNull();
    });

    it('returns 404 for non-existent export', async () => {
      mockRepo.findExportById.mockResolvedValueOnce(undefined);

      const res = await authedGet(`/api/v1/exports/${EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID id', async () => {
      const res = await authedGet('/api/v1/exports/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/exports/${EXPORT_ID}`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/submission-preferences — Get Preferences
  // =========================================================================

  describe('GET /api/v1/submission-preferences', () => {
    it('returns default submission preferences', async () => {
      const res = await authedGet('/api/v1/submission-preferences');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('ahcipMode');
      expect(body.data).toHaveProperty('wcbMode');
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/submission-preferences');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // PUT /api/v1/submission-preferences — Update Preferences
  // =========================================================================

  describe('PUT /api/v1/submission-preferences', () => {
    it('updates mode', async () => {
      const res = await authedPut('/api/v1/submission-preferences', {
        mode: 'AUTO_ALL',
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().data.success).toBe(true);
      expect(mockRepo.appendClaimAudit).toHaveBeenCalledTimes(1);
    });

    it('rejects invalid mode', async () => {
      const res = await authedPut('/api/v1/submission-preferences', {
        mode: 'INVALID_MODE',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects missing mode', async () => {
      const res = await authedPut('/api/v1/submission-preferences', {});
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPut('/api/v1/submission-preferences', {
        mode: 'AUTO_CLEAN',
      });
      expect(res.statusCode).toBe(401);
    });
  });
});
