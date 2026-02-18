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

// ---------------------------------------------------------------------------
// Test patient data
// ---------------------------------------------------------------------------

function makeMockPatient(overrides: Record<string, unknown> = {}) {
  return {
    patientId: crypto.randomUUID(),
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
    lastVisitDate: '2026-01-15',
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
    createPatient: vi.fn(),
    findPatientById: vi.fn(async () => undefined),
    findPatientByPhn: vi.fn(async () => undefined),
    updatePatient: vi.fn(),
    deactivatePatient: vi.fn(),
    reactivatePatient: vi.fn(),
    updateLastVisitDate: vi.fn(),
    searchByPhn: vi.fn(async () => undefined),
    searchByName: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    searchByDob: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    searchCombined: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
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

function authedGet(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Patient Search Integration Tests', () => {
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
  // GET /api/v1/patients/search
  // =========================================================================

  describe('GET /api/v1/patients/search', () => {
    it('returns exact match for PHN search', async () => {
      const patient = makeMockPatient({ phn: '123456782' });
      mockRepo.searchByPhn.mockResolvedValueOnce(patient);

      const res = await authedGet('/api/v1/patients/search?phn=123456782');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.length).toBe(1);
      expect(body.data[0].phn).toBe('123456782');
    });

    it('returns name prefix results', async () => {
      const patients = [
        makeMockPatient({ firstName: 'Smith', lastName: 'Johnson' }),
        makeMockPatient({ firstName: 'John', lastName: 'Smith' }),
      ];
      mockRepo.searchByName.mockResolvedValueOnce({
        data: patients,
        pagination: { total: 2, page: 1, pageSize: 20, hasMore: false },
      });

      const res = await authedGet('/api/v1/patients/search?name=Sm');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.length).toBe(2);
    });

    it('returns empty results for unmatched search', async () => {
      mockRepo.searchByPhn.mockResolvedValueOnce(undefined);

      const res = await authedGet('/api/v1/patients/search?phn=999999999');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toEqual([]);
    });

    it('returns pagination metadata', async () => {
      const patients = Array.from({ length: 5 }, (_, i) =>
        makeMockPatient({ firstName: `Smith${i}` }),
      );
      mockRepo.searchByName.mockResolvedValueOnce({
        data: patients,
        pagination: { total: 25, page: 1, pageSize: 5, hasMore: true },
      });

      const res = await authedGet('/api/v1/patients/search?name=Smith&page_size=5');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.pagination).toBeDefined();
      expect(body.pagination.total).toBe(25);
      expect(body.pagination.hasMore).toBe(true);
    });

    it('rejects name search shorter than 2 characters', async () => {
      const res = await authedGet('/api/v1/patients/search?name=S');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/patients/search?phn=123456782');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('logs audit entry for search', async () => {
      mockRepo.searchByPhn.mockResolvedValueOnce(undefined);

      await authedGet('/api/v1/patients/search?phn=123456782');
      expect(mockAuditRepo.appendAuditLog).toHaveBeenCalled();
    });
  });

  // =========================================================================
  // GET /api/v1/patients/recent
  // =========================================================================

  describe('GET /api/v1/patients/recent', () => {
    it('returns last 20 patients by visit date', async () => {
      const patients = Array.from({ length: 5 }, (_, i) =>
        makeMockPatient({
          firstName: `Patient${i}`,
          lastVisitDate: `2026-01-${15 - i}`,
        }),
      );
      mockRepo.getRecentPatients.mockResolvedValueOnce(patients);

      const res = await authedGet('/api/v1/patients/recent');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.length).toBe(5);
      expect(mockRepo.getRecentPatients).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        20,
      );
    });

    it('respects custom limit parameter', async () => {
      mockRepo.getRecentPatients.mockResolvedValueOnce([]);

      const res = await authedGet('/api/v1/patients/recent?limit=5');
      expect(res.statusCode).toBe(200);
      expect(mockRepo.getRecentPatients).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        5,
      );
    });

    it('rejects limit > 50', async () => {
      const res = await authedGet('/api/v1/patients/recent?limit=100');
      expect(res.statusCode).toBe(400);
    });

    it('returns empty array when no recent patients', async () => {
      mockRepo.getRecentPatients.mockResolvedValueOnce([]);

      const res = await authedGet('/api/v1/patients/recent');
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toEqual([]);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/patients/recent');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });
});
