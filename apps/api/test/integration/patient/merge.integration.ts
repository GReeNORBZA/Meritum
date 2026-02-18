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
import { patientRoutes } from '../../../src/domains/patient/patient.routes.js';
import { type PatientHandlerDeps } from '../../../src/domains/patient/patient.handlers.js';
import { type PatientServiceDeps } from '../../../src/domains/patient/patient.service.js';

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
// Test data
// ---------------------------------------------------------------------------

const PATIENT_SURVIVING_ID = '00000000-aaaa-0000-0000-000000000001';
const PATIENT_MERGED_ID = '00000000-aaaa-0000-0000-000000000002';
const PATIENT_OTHER_ID = '00000000-aaaa-0000-0000-000000000003';

function makeMockPatient(overrides: Record<string, unknown> = {}) {
  return {
    patientId: PATIENT_SURVIVING_ID,
    providerId: PHYSICIAN1_USER_ID,
    phn: '123456782',
    phnProvince: 'AB',
    firstName: 'John',
    middleName: null,
    lastName: 'Doe',
    dateOfBirth: '1985-03-15',
    gender: 'M',
    phone: null,
    email: null,
    addressLine1: null,
    addressLine2: null,
    city: null,
    province: null,
    postalCode: null,
    notes: null,
    lastVisitDate: null,
    isActive: true,
    createdBy: PHYSICIAN1_USER_ID,
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
// Mock patient repository
// ---------------------------------------------------------------------------

function createMockPatientRepo() {
  return {
    createPatient: vi.fn(async (data: any) => ({
      patientId: crypto.randomUUID(),
      ...data,
      isActive: true,
      lastVisitDate: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findPatientById: vi.fn(async () => undefined as any),
    findPatientByPhn: vi.fn(async () => undefined as any),
    updatePatient: vi.fn(async () => undefined as any),
    deactivatePatient: vi.fn(async () => undefined as any),
    reactivatePatient: vi.fn(async () => undefined as any),
    updateLastVisitDate: vi.fn(),
    searchByPhn: vi.fn(async () => undefined),
    searchByName: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    searchByDob: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    searchCombined: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    getRecentPatients: vi.fn(async () => []),
    createImportBatch: vi.fn(),
    findImportBatchById: vi.fn(),
    findImportByFileHash: vi.fn(),
    updateImportStatus: vi.fn(),
    listImportBatches: vi.fn(),
    bulkCreatePatients: vi.fn(),
    bulkUpsertPatients: vi.fn(),
    getMergePreview: vi.fn(async () => null),
    executeMerge: vi.fn(async () => null),
    listMergeHistory: vi.fn(),
    exportActivePatients: vi.fn(async () => []),
    countActivePatients: vi.fn(async () => 0),
    getPatientClaimContext: vi.fn(async () => null),
    validatePhnExists: vi.fn(async () => ({ valid: true, exists: false })),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockPatientRepo>;
let mockAuditRepo: { appendAuditLog: ReturnType<typeof vi.fn> };
let mockEvents: { emit: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockPatientRepo();
  mockAuditRepo = { appendAuditLog: vi.fn() };
  mockEvents = { emit: vi.fn() };

  const serviceDeps: PatientServiceDeps = {
    repo: mockRepo as any,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const handlerDeps: PatientHandlerDeps = { serviceDeps };

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

  // Register patient routes
  await testApp.register(patientRoutes, { deps: handlerDeps });

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

describe('Patient Merge Integration Tests', () => {
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
  // POST /api/v1/patients/merge/preview
  // =========================================================================

  describe('POST /api/v1/patients/merge/preview', () => {
    it('returns side-by-side comparison for two patients', async () => {
      const surviving = makeMockPatient({ patientId: PATIENT_SURVIVING_ID, firstName: 'John' });
      const merged = makeMockPatient({
        patientId: PATIENT_MERGED_ID,
        phn: '987654321',
        firstName: 'Jon',
        lastName: 'Doe',
      });

      mockRepo.getMergePreview.mockResolvedValueOnce({
        surviving,
        merged,
        claimsToTransfer: 3,
        fieldConflicts: {
          phn: { surviving: '123456782', merged: '987654321' },
          firstName: { surviving: 'John', merged: 'Jon' },
        },
      });

      const res = await authedPost('/api/v1/patients/merge/preview', {
        surviving_id: PATIENT_SURVIVING_ID,
        merged_id: PATIENT_MERGED_ID,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.surviving.patientId).toBe(PATIENT_SURVIVING_ID);
      expect(body.data.merged.patientId).toBe(PATIENT_MERGED_ID);
      expect(body.data.claimsToTransfer).toBe(3);
      expect(body.data.fieldConflicts).toBeDefined();
      expect(body.data.fieldConflicts.firstName).toEqual({
        surviving: 'John',
        merged: 'Jon',
      });
    });

    it('rejects cross-physician patients (returns 404)', async () => {
      // Repository returns null when one patient doesn't belong to physician
      mockRepo.getMergePreview.mockResolvedValueOnce(null);

      const res = await authedPost('/api/v1/patients/merge/preview', {
        surviving_id: PATIENT_SURVIVING_ID,
        merged_id: PATIENT_OTHER_ID,
      });

      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
    });

    it('rejects request with non-UUID ids', async () => {
      const res = await authedPost('/api/v1/patients/merge/preview', {
        surviving_id: 'not-a-uuid',
        merged_id: 'also-not-uuid',
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects request without body', async () => {
      const res = await authedPost('/api/v1/patients/merge/preview', {});

      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/patients/merge/preview', {
        surviving_id: PATIENT_SURVIVING_ID,
        merged_id: PATIENT_MERGED_ID,
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // POST /api/v1/patients/merge/execute
  // =========================================================================

  describe('POST /api/v1/patients/merge/execute', () => {
    it('transfers claims and soft-deletes merged patient', async () => {
      const mergeId = '00000000-bbbb-0000-0000-000000000001';

      mockRepo.executeMerge.mockResolvedValueOnce({
        mergeId,
        claimsTransferred: 5,
        fieldConflicts: {
          firstName: { surviving: 'John', merged: 'Jon' },
        },
      });

      const res = await authedPost('/api/v1/patients/merge/execute', {
        surviving_id: PATIENT_SURVIVING_ID,
        merged_id: PATIENT_MERGED_ID,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.mergeId).toBe(mergeId);
      expect(body.data.claimsTransferred).toBe(5);
      expect(body.data.fieldConflicts).toBeDefined();
    });

    it('returns 404 when patients not found or cross-physician', async () => {
      mockRepo.executeMerge.mockResolvedValueOnce(null);

      const res = await authedPost('/api/v1/patients/merge/execute', {
        surviving_id: PATIENT_SURVIVING_ID,
        merged_id: PATIENT_OTHER_ID,
      });

      expect(res.statusCode).toBe(404);
    });

    it('emits audit log on successful merge', async () => {
      const mergeId = '00000000-bbbb-0000-0000-000000000002';
      mockRepo.executeMerge.mockResolvedValueOnce({
        mergeId,
        claimsTransferred: 2,
        fieldConflicts: {},
      });

      await authedPost('/api/v1/patients/merge/execute', {
        surviving_id: PATIENT_SURVIVING_ID,
        merged_id: PATIENT_MERGED_ID,
      });

      expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'patient.merged',
          category: 'patient',
          resourceType: 'patient',
          resourceId: PATIENT_SURVIVING_ID,
        }),
      );
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/patients/merge/execute', {
        surviving_id: PATIENT_SURVIVING_ID,
        merged_id: PATIENT_MERGED_ID,
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('rejects request with non-UUID ids', async () => {
      const res = await authedPost('/api/v1/patients/merge/execute', {
        surviving_id: 'not-a-uuid',
        merged_id: PATIENT_MERGED_ID,
      });

      expect(res.statusCode).toBe(400);
    });
  });
});
