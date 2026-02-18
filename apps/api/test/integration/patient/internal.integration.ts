import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);
process.env.INTERNAL_API_KEY = 'test-internal-api-key-for-patient-integration';

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
import { internalPatientRoutes } from '../../../src/domains/patient/patient.routes.js';
import { type InternalPatientHandlerDeps } from '../../../src/domains/patient/patient.handlers.js';
import { type PatientServiceDeps } from '../../../src/domains/patient/patient.service.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-1111-0000-0000-000000000001';
const PATIENT_ID = '00000000-aaaa-0000-0000-000000000001';
const UNKNOWN_PATIENT_ID = '00000000-aaaa-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const MOCK_CLAIM_CONTEXT = {
  patientId: PATIENT_ID,
  phn: '123456782',
  phnProvince: 'AB',
  firstName: 'John',
  lastName: 'Doe',
  dateOfBirth: '1985-03-15',
  gender: 'M',
};

// ---------------------------------------------------------------------------
// Mock patient repository
// ---------------------------------------------------------------------------

function createMockPatientRepo() {
  return {
    createPatient: vi.fn(),
    findPatientById: vi.fn(),
    findPatientByPhn: vi.fn(),
    updatePatient: vi.fn(),
    deactivatePatient: vi.fn(),
    reactivatePatient: vi.fn(),
    updateLastVisitDate: vi.fn(),
    searchByPhn: vi.fn(),
    searchByName: vi.fn(),
    searchByDob: vi.fn(),
    searchCombined: vi.fn(),
    getRecentPatients: vi.fn(),
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
    exportActivePatients: vi.fn(),
    countActivePatients: vi.fn(),
    getPatientClaimContext: vi.fn(async (patientId: string, physicianId: string) => {
      if (patientId === PATIENT_ID && physicianId === PHYSICIAN_ID) {
        return { ...MOCK_CLAIM_CONTEXT };
      }
      return null;
    }),
    validatePhnExists: vi.fn(async (physicianId: string, phn: string) => {
      if (physicianId === PHYSICIAN_ID && phn === '123456782') {
        return { valid: true, exists: true, patientId: PATIENT_ID };
      }
      return { valid: true, exists: false };
    }),
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

  const handlerDeps: InternalPatientHandlerDeps = {
    serviceDeps,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

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

  // Register internal patient routes (no auth plugin needed — API key auth)
  await testApp.register(internalPatientRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_API_KEY = 'test-internal-api-key-for-patient-integration';

function internalGet(url: string, apiKey?: string) {
  const headers: Record<string, string> = {};
  if (apiKey !== undefined) {
    headers['x-internal-api-key'] = apiKey;
  }
  return app.inject({
    method: 'GET',
    url,
    headers,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Internal Patient API Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Reset default mock implementations after clearAllMocks
    mockRepo.getPatientClaimContext.mockImplementation(async (patientId: string, physicianId: string) => {
      if (patientId === PATIENT_ID && physicianId === PHYSICIAN_ID) {
        return { ...MOCK_CLAIM_CONTEXT };
      }
      return null;
    });
    mockRepo.validatePhnExists.mockImplementation(async (physicianId: string, phn: string) => {
      if (physicianId === PHYSICIAN_ID && phn === '123456782') {
        return { valid: true, exists: true, patientId: PATIENT_ID };
      }
      return { valid: true, exists: false };
    });
  });

  // =========================================================================
  // Authentication: Internal API key enforcement
  // =========================================================================

  describe('Internal API key authentication', () => {
    it('rejects requests without X-Internal-API-Key header', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/${PATIENT_ID}/claim-context?physician_id=${PHYSICIAN_ID}`,
      );
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
      expect(res.json().error.code).toBe('UNAUTHORIZED');
    });

    it('rejects requests with invalid API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/${PATIENT_ID}/claim-context?physician_id=${PHYSICIAN_ID}`,
        'wrong-key',
      );
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('rejects requests with empty API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/${PATIENT_ID}/claim-context?physician_id=${PHYSICIAN_ID}`,
        '',
      );
      expect(res.statusCode).toBe(401);
    });

    it('accepts requests with valid API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/${PATIENT_ID}/claim-context?physician_id=${PHYSICIAN_ID}`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // GET /api/v1/internal/patients/:id/claim-context
  // =========================================================================

  describe('GET /api/v1/internal/patients/:id/claim-context', () => {
    it('returns minimal claim context for known patient', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/${PATIENT_ID}/claim-context?physician_id=${PHYSICIAN_ID}`,
        VALID_API_KEY,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.patientId).toBe(PATIENT_ID);
      expect(body.data.phn).toBe('123456782');
      expect(body.data.phnProvince).toBe('AB');
      expect(body.data.firstName).toBe('John');
      expect(body.data.lastName).toBe('Doe');
      expect(body.data.dateOfBirth).toBe('1985-03-15');
      expect(body.data.gender).toBe('M');
    });

    it('returns 404 for unknown patient', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/${UNKNOWN_PATIENT_ID}/claim-context?physician_id=${PHYSICIAN_ID}`,
        VALID_API_KEY,
      );

      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
      // Should not leak resource details
      expect(res.json().error.message).not.toContain(UNKNOWN_PATIENT_ID);
    });

    it('returns 400 for non-UUID patient id', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/not-a-uuid/claim-context?physician_id=${PHYSICIAN_ID}`,
        VALID_API_KEY,
      );

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 when physician_id query param is missing', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/${PATIENT_ID}/claim-context`,
        VALID_API_KEY,
      );

      expect(res.statusCode).toBe(400);
    });

    it('rejects request without internal API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/${PATIENT_ID}/claim-context?physician_id=${PHYSICIAN_ID}`,
      );

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/internal/patients/validate-phn/:phn
  // =========================================================================

  describe('GET /api/v1/internal/patients/validate-phn/:phn', () => {
    it('validates format and returns existence for known PHN', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/validate-phn/123456782?physician_id=${PHYSICIAN_ID}`,
        VALID_API_KEY,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.valid).toBe(true);
      expect(body.data.formatOk).toBe(true);
      expect(body.data.exists).toBe(true);
      expect(body.data.patientId).toBe(PATIENT_ID);
    });

    it('validates format and returns non-existence for unknown PHN', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/validate-phn/987654324?physician_id=${PHYSICIAN_ID}`,
        VALID_API_KEY,
      );

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.valid).toBe(true);
      expect(body.data.formatOk).toBe(true);
      expect(body.data.exists).toBe(false);
      expect(body.data.patientId).toBeUndefined();
    });

    it('returns 400 for invalid PHN format (non-numeric)', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/validate-phn/abc123456?physician_id=${PHYSICIAN_ID}`,
        VALID_API_KEY,
      );

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for wrong-length PHN', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/validate-phn/12345?physician_id=${PHYSICIAN_ID}`,
        VALID_API_KEY,
      );

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 when physician_id query param is missing', async () => {
      const res = await internalGet(
        '/api/v1/internal/patients/validate-phn/123456782',
        VALID_API_KEY,
      );

      expect(res.statusCode).toBe(400);
    });

    it('rejects request without internal API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/patients/validate-phn/123456782?physician_id=${PHYSICIAN_ID}`,
      );

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // UUID validation for all internal routes
  // =========================================================================

  describe('UUID parameter validation', () => {
    it('rejects non-UUID for claim-context', async () => {
      const res = await internalGet(
        '/api/v1/internal/patients/not-a-uuid/claim-context?physician_id=foo',
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(400);
    });
  });
});
