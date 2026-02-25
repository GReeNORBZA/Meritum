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
// Test patient data
// ---------------------------------------------------------------------------

const PATIENT_ID_1 = '00000000-aaaa-0000-0000-000000000001';

function makeMockPatient(overrides: Record<string, unknown> = {}) {
  return {
    patientId: PATIENT_ID_1,
    providerId: PHYSICIAN1_USER_ID,
    phn: '123456782',
    phnProvince: 'AB',
    firstName: 'Jon',
    middleName: null,
    lastName: 'Doe',
    dateOfBirth: '1990-01-01',
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
    findPatientById: vi.fn(async (_patientId: string, _physicianId: string) => undefined as any),
    findPatientByPhn: vi.fn(async (_physicianId: string, _phn: string) => undefined as any),
    updatePatient: vi.fn(async (_patientId: string, _physicianId: string, data: any) => undefined as any),
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
    getMergePreview: vi.fn(),
    executeMerge: vi.fn(),
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

function authedPatch(
  url: string,
  body: Record<string, unknown>,
  token = PHYSICIAN1_SESSION_TOKEN,
) {
  return app.inject({
    method: 'PATCH',
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

describe('Patient Correction Integration Tests (IMA S3.10)', () => {
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
  // PATCH /api/v1/patients/:id/correct
  // =========================================================================

  describe('PATCH /api/v1/patients/:id/correct', () => {
    it('updates patient and records correction audit', async () => {
      const existingPatient = makeMockPatient({ firstName: 'Jon' });
      mockRepo.findPatientById.mockResolvedValue(existingPatient);
      mockRepo.updatePatient.mockResolvedValue({
        ...existingPatient,
        firstName: 'John',
        updatedAt: new Date(),
      });

      const res = await authedPatch(`/api/v1/patients/${PATIENT_ID_1}/correct`, {
        correction_reason: 'Typo in first name',
        first_name: 'John',
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.firstName).toBe('John');

      // Verify the update was applied through the repository
      expect(mockRepo.updatePatient).toHaveBeenCalledWith(
        PATIENT_ID_1,
        PHYSICIAN1_USER_ID,
        expect.objectContaining({ firstName: 'John' }),
      );

      // Verify audit log was written
      expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'patient.correction_applied',
          resourceType: 'patient',
          resourceId: PATIENT_ID_1,
        }),
      );
    });

    it('correction audit entry contains field-level diff with old and new values', async () => {
      const existingPatient = makeMockPatient({
        firstName: 'Jon',
        dateOfBirth: '1990-01-01',
      });
      mockRepo.findPatientById.mockResolvedValue(existingPatient);
      mockRepo.updatePatient.mockResolvedValue({
        ...existingPatient,
        firstName: 'John',
        dateOfBirth: '1990-01-02',
        updatedAt: new Date(),
      });

      const res = await authedPatch(`/api/v1/patients/${PATIENT_ID_1}/correct`, {
        correction_reason: 'Name and DOB correction',
        first_name: 'John',
        date_of_birth: '1990-01-02',
      });

      expect(res.statusCode).toBe(200);

      // Verify audit log contains field-level diff
      const auditCall = mockAuditRepo.appendAuditLog.mock.calls[0][0];
      expect(auditCall.action).toBe('patient.correction_applied');
      expect(auditCall.detail).toBeDefined();
      expect(auditCall.detail.correction_reason).toBe('Name and DOB correction');
      expect(auditCall.detail.changes).toEqual(
        expect.arrayContaining([
          { field: 'firstName', old_value: 'Jon', new_value: 'John' },
          { field: 'dateOfBirth', old_value: '1990-01-01', new_value: '1990-01-02' },
        ]),
      );
    });

    it('correction_reason is required', async () => {
      const res = await authedPatch(`/api/v1/patients/${PATIENT_ID_1}/correct`, {
        first_name: 'John',
      });

      expect(res.statusCode).toBe(400);
    });

    it('at least one field besides correction_reason must be provided', async () => {
      const res = await authedPatch(`/api/v1/patients/${PATIENT_ID_1}/correct`, {
        correction_reason: 'Testing correction reason only',
      });

      expect(res.statusCode).toBe(400);
    });

    it('PHN is masked in correction audit detail', async () => {
      const existingPatient = makeMockPatient({ phn: '123456782' });
      mockRepo.findPatientById.mockResolvedValue(existingPatient);
      mockRepo.findPatientByPhn.mockResolvedValue(undefined);
      mockRepo.updatePatient.mockResolvedValue({
        ...existingPatient,
        phn: '111111118',
        updatedAt: new Date(),
      });

      const res = await authedPatch(`/api/v1/patients/${PATIENT_ID_1}/correct`, {
        correction_reason: 'Incorrect PHN recorded',
        phn: '111111118',
      });

      expect(res.statusCode).toBe(200);

      // Verify PHN is masked in audit log
      const auditCall = mockAuditRepo.appendAuditLog.mock.calls[0][0];
      const phnChange = auditCall.detail.changes.find(
        (c: any) => c.field === 'phn',
      );
      expect(phnChange).toBeDefined();
      // Old value should be masked (123******)
      expect(phnChange.old_value).toBe('123******');
      // New value should be masked
      expect(phnChange.new_value).toBe('111******');
      // Neither should contain the full PHN
      expect(phnChange.old_value).not.toBe('123456782');
      expect(phnChange.new_value).not.toBe('111111118');
    });

    it('returns 404 when correcting another physician\'s patient', async () => {
      // Patient not found for physician2 (tenant isolation)
      mockRepo.findPatientById.mockResolvedValue(undefined);

      const res = await authedPatch(
        `/api/v1/patients/${PATIENT_ID_1}/correct`,
        {
          correction_reason: 'Attempting cross-tenant correction',
          first_name: 'Hacked',
        },
        PHYSICIAN2_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
    });

    it('returns 401 without authentication', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/patients/${PATIENT_ID_1}/correct`,
        headers: { 'content-type': 'application/json' },
        payload: {
          correction_reason: 'Test',
          first_name: 'John',
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('does not modify patient when no fields actually changed', async () => {
      const existingPatient = makeMockPatient({ firstName: 'John' });
      mockRepo.findPatientById.mockResolvedValue(existingPatient);

      const res = await authedPatch(`/api/v1/patients/${PATIENT_ID_1}/correct`, {
        correction_reason: 'Correction with same values',
        first_name: 'John',
      });

      // Returns 200 with existing data (no update needed)
      expect(res.statusCode).toBe(200);
      expect(mockRepo.updatePatient).not.toHaveBeenCalled();
      // No audit log should be written for no-op corrections
      expect(mockAuditRepo.appendAuditLog).not.toHaveBeenCalled();
    });
  });
});
