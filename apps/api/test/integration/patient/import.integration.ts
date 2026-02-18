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
import { ImportStatus } from '@meritum/shared/constants/patient.constants.js';

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

const IMPORT_ID_1 = '00000000-bbbb-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// CSV test data
// ---------------------------------------------------------------------------

const VALID_CSV = 'PHN,FirstName,LastName,DOB,Gender\n123456782,John,Doe,1985-03-15,M\n223456781,Jane,Smith,1990-06-20,F';

const VALID_CSV_WITH_DUPLICATE_PHN = 'PHN,FirstName,LastName,DOB,Gender\n123456782,John,Doe,1985-03-15,M\n123456782,Other,Person,1991-01-01,M';

const CSV_MISSING_REQUIRED = 'PHN,FirstName\n123456782,John';

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
    createImportBatch: vi.fn(async (data: any) => ({
      importId: IMPORT_ID_1,
      ...data,
      createdCount: 0,
      updatedCount: 0,
      skippedCount: 0,
      errorCount: 0,
      errorDetails: null,
      createdAt: new Date(),
    })),
    findImportBatchById: vi.fn(async (importId: string, physicianId: string) => {
      if (importId === IMPORT_ID_1 && physicianId === PHYSICIAN1_USER_ID) {
        return {
          importId: IMPORT_ID_1,
          physicianId: PHYSICIAN1_USER_ID,
          fileName: 'patients.csv',
          fileHash: 'abc123',
          totalRows: 2,
          status: ImportStatus.PENDING,
          createdCount: 0,
          updatedCount: 0,
          skippedCount: 0,
          errorCount: 0,
          errorDetails: null,
          createdBy: PHYSICIAN1_USER_ID,
          createdAt: new Date(),
        };
      }
      return undefined;
    }),
    findImportByFileHash: vi.fn(async () => undefined),
    updateImportStatus: vi.fn(async () => undefined),
    listImportBatches: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    bulkCreatePatients: vi.fn(async () => []),
    bulkUpsertPatients: vi.fn(async () => ({ created: 0, updated: 0 })),
    getMergePreview: vi.fn(async () => null),
    executeMerge: vi.fn(async () => null),
    listMergeHistory: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
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
// Multipart upload helper
// ---------------------------------------------------------------------------

function buildMultipartPayload(
  filename: string,
  content: string,
  contentType = 'text/csv',
): { body: string; boundary: string } {
  const boundary = '----FormBoundary' + randomBytes(8).toString('hex');
  const body = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="file"; filename="${filename}"`,
    `Content-Type: ${contentType}`,
    '',
    content,
    `--${boundary}--`,
  ].join('\r\n');

  return { body, boundary };
}

function authedUpload(
  filename: string,
  content: string,
  contentType = 'text/csv',
  token = PHYSICIAN1_SESSION_TOKEN,
) {
  const { body, boundary } = buildMultipartPayload(filename, content, contentType);
  return app.inject({
    method: 'POST',
    url: '/api/v1/patients/imports',
    headers: {
      cookie: `session=${token}`,
      'content-type': `multipart/form-data; boundary=${boundary}`,
    },
    payload: body,
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

function unauthedUpload(filename: string, content: string) {
  const { body, boundary } = buildMultipartPayload(filename, content);
  return app.inject({
    method: 'POST',
    url: '/api/v1/patients/imports',
    headers: {
      'content-type': `multipart/form-data; boundary=${boundary}`,
    },
    payload: body,
  });
}

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

function unauthedPut(url: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'PUT',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body,
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

describe('Patient CSV Import Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();

    // Reset default mock behavior for findImportBatchById
    mockRepo.findImportBatchById.mockImplementation(async (importId: string, physicianId: string) => {
      if (importId === IMPORT_ID_1 && physicianId === PHYSICIAN1_USER_ID) {
        return {
          importId: IMPORT_ID_1,
          physicianId: PHYSICIAN1_USER_ID,
          fileName: 'patients.csv',
          fileHash: 'abc123',
          totalRows: 2,
          status: ImportStatus.PENDING,
          createdCount: 0,
          updatedCount: 0,
          skippedCount: 0,
          errorCount: 0,
          errorDetails: null,
          createdBy: PHYSICIAN1_USER_ID,
          createdAt: new Date(),
        };
      }
      return undefined;
    });

    // Reset default mock for findImportByFileHash
    mockRepo.findImportByFileHash.mockResolvedValue(undefined);
  });

  // =========================================================================
  // POST /api/v1/patients/imports (upload)
  // =========================================================================

  describe('POST /api/v1/patients/imports', () => {
    it('uploads CSV and returns import_id', async () => {
      const res = await authedUpload('patients.csv', VALID_CSV);
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.importId).toBe(IMPORT_ID_1);
      expect(mockRepo.createImportBatch).toHaveBeenCalledTimes(1);
    });

    it('accepts .txt files', async () => {
      const res = await authedUpload('patients.txt', VALID_CSV, 'text/plain');
      expect(res.statusCode).toBe(201);
      expect(res.json().data.importId).toBe(IMPORT_ID_1);
    });

    it('rejects non-CSV file (e.g. .xlsx)', async () => {
      const res = await authedUpload('patients.xlsx', 'binary-content', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBeDefined();
    });

    it('rejects file exceeding 10MB', async () => {
      // Create a string larger than 10MB
      const largeContent = 'PHN,FirstName,LastName,DOB,Gender\n' + 'x'.repeat(11 * 1024 * 1024);
      const res = await authedUpload('large.csv', largeContent);
      // Should fail with 400 (file too large) or 413 (payload too large)
      expect([400, 413].includes(res.statusCode)).toBe(true);
    });

    it('rejects duplicate file upload (same hash)', async () => {
      mockRepo.findImportByFileHash.mockResolvedValueOnce({
        importId: 'existing-import',
        physicianId: PHYSICIAN1_USER_ID,
        fileName: 'patients.csv',
        fileHash: 'duplicate',
        totalRows: 2,
        status: ImportStatus.COMPLETED,
      });

      const res = await authedUpload('patients.csv', VALID_CSV);
      expect(res.statusCode).toBe(409);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedUpload('patients.csv', VALID_CSV);
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // GET /api/v1/patients/imports/:id/preview
  // =========================================================================

  describe('GET /api/v1/patients/imports/:id/preview', () => {
    it('returns column mapping and preview rows', async () => {
      // First upload to populate the cache
      await authedUpload('patients.csv', VALID_CSV);

      const res = await authedGet(`/api/v1/patients/imports/${IMPORT_ID_1}/preview`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.importId).toBe(IMPORT_ID_1);
      expect(body.data.headers).toBeDefined();
      expect(Array.isArray(body.data.headers)).toBe(true);
      expect(body.data.mapping).toBeDefined();
      expect(body.data.previewRows).toBeDefined();
      expect(Array.isArray(body.data.previewRows)).toBe(true);
      expect(body.data.totalRows).toBeGreaterThan(0);
    });

    it('returns 404 for non-existent import', async () => {
      const res = await authedGet('/api/v1/patients/imports/00000000-0000-0000-0000-000000000099/preview');
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID parameter', async () => {
      const res = await authedGet('/api/v1/patients/imports/not-a-uuid/preview');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/patients/imports/${IMPORT_ID_1}/preview`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // PUT /api/v1/patients/imports/:id/mapping
  // =========================================================================

  describe('PUT /api/v1/patients/imports/:id/mapping', () => {
    it('updates column mapping', async () => {
      // First upload to populate the cache
      await authedUpload('patients.csv', VALID_CSV);

      const mapping = {
        mapping: {
          phn: 'PHN',
          first_name: 'FirstName',
          last_name: 'LastName',
          date_of_birth: 'DOB',
          gender: 'Gender',
        },
      };

      const res = await authedPut(`/api/v1/patients/imports/${IMPORT_ID_1}/mapping`, mapping);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.success).toBe(true);
    });

    it('returns 404 for non-existent import', async () => {
      const res = await authedPut('/api/v1/patients/imports/00000000-0000-0000-0000-000000000099/mapping', {
        mapping: { phn: 'PHN' },
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for invalid body (missing mapping)', async () => {
      const res = await authedPut(`/api/v1/patients/imports/${IMPORT_ID_1}/mapping`, {});
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPut(`/api/v1/patients/imports/${IMPORT_ID_1}/mapping`, {
        mapping: { phn: 'PHN' },
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/patients/imports/:id/commit
  // =========================================================================

  describe('POST /api/v1/patients/imports/:id/commit', () => {
    it('processes all rows and returns result', async () => {
      // Upload first to populate cache
      await authedUpload('patients.csv', VALID_CSV);

      const res = await authedPost(`/api/v1/patients/imports/${IMPORT_ID_1}/commit`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.importId).toBe(IMPORT_ID_1);
      expect(body.data.status).toBe(ImportStatus.COMPLETED);
      expect(typeof body.data.created).toBe('number');
      expect(typeof body.data.updated).toBe('number');
      expect(typeof body.data.skipped).toBe('number');
      expect(typeof body.data.errors).toBe('number');
      expect(body.data.totalRows).toBeGreaterThan(0);
    });

    it('handles PHN duplicates correctly (skips within-file duplicates)', async () => {
      // Upload CSV with duplicate PHNs
      await authedUpload('dup.csv', VALID_CSV_WITH_DUPLICATE_PHN);

      const res = await authedPost(`/api/v1/patients/imports/${IMPORT_ID_1}/commit`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      // The second row with same PHN should be skipped
      expect(body.data.skipped).toBeGreaterThanOrEqual(1);
    });

    it('handles PHN duplicates correctly (updates existing patients)', async () => {
      // Upload CSV with a PHN that already exists in the physician's registry
      mockRepo.findPatientByPhn.mockImplementation(async (_physicianId: string, phn: string) => {
        if (phn === '123456782') {
          return {
            patientId: '00000000-aaaa-0000-0000-000000000001',
            providerId: PHYSICIAN1_USER_ID,
            phn: '123456782',
            phnProvince: 'AB',
            firstName: 'OldFirst',
            lastName: 'OldLast',
            dateOfBirth: '1985-03-15',
            gender: 'M',
            isActive: true,
          };
        }
        return undefined;
      });

      await authedUpload('existing.csv', VALID_CSV);

      const res = await authedPost(`/api/v1/patients/imports/${IMPORT_ID_1}/commit`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      // First row should be "updated" (existing PHN match), second row "created"
      expect(body.data.updated).toBeGreaterThanOrEqual(1);
    });

    it('returns 404 for non-existent import', async () => {
      const res = await authedPost('/api/v1/patients/imports/00000000-0000-0000-0000-000000000099/commit');
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/patients/imports/${IMPORT_ID_1}/commit`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/patients/imports/:id (status)
  // =========================================================================

  describe('GET /api/v1/patients/imports/:id', () => {
    it('returns status and counts', async () => {
      // Override mock to return a completed batch
      mockRepo.findImportBatchById.mockResolvedValueOnce({
        importId: IMPORT_ID_1,
        physicianId: PHYSICIAN1_USER_ID,
        fileName: 'patients.csv',
        fileHash: 'abc123',
        totalRows: 5,
        status: ImportStatus.COMPLETED,
        createdCount: 3,
        updatedCount: 1,
        skippedCount: 1,
        errorCount: 0,
        errorDetails: null,
        createdBy: PHYSICIAN1_USER_ID,
        createdAt: new Date(),
      });

      const res = await authedGet(`/api/v1/patients/imports/${IMPORT_ID_1}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.importId).toBe(IMPORT_ID_1);
      expect(body.data.status).toBe(ImportStatus.COMPLETED);
      expect(body.data.totalRows).toBe(5);
      expect(body.data.created).toBe(3);
      expect(body.data.updated).toBe(1);
      expect(body.data.skipped).toBe(1);
      expect(body.data.errors).toBe(0);
    });

    it('returns 404 for non-existent import', async () => {
      const res = await authedGet('/api/v1/patients/imports/00000000-0000-0000-0000-000000000099');
      expect(res.statusCode).toBe(404);
    });

    it('returns 404 for other physician\'s import', async () => {
      // Physician2 trying to access physician1's import
      const res = await authedGet(`/api/v1/patients/imports/${IMPORT_ID_1}`, PHYSICIAN2_SESSION_TOKEN);
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID parameter', async () => {
      const res = await authedGet('/api/v1/patients/imports/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/patients/imports/${IMPORT_ID_1}`);
      expect(res.statusCode).toBe(401);
    });
  });
});
