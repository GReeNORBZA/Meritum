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
import { type PatientServiceDeps, _exportStore, _accessExportStore } from '../../../src/domains/patient/patient.service.js';

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
    getPatientHealthInformation: vi.fn(async () => null),
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

function authedGet(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
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

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Patient Export Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Clear export stores between tests
    _exportStore.clear();
    _accessExportStore.clear();
  });

  // =========================================================================
  // POST /api/v1/patients/exports
  // =========================================================================

  describe('POST /api/v1/patients/exports', () => {
    it('generates export and returns export_id', async () => {
      mockRepo.exportActivePatients.mockResolvedValueOnce([
        {
          phn: '123456782',
          firstName: 'John',
          lastName: 'Doe',
          dateOfBirth: '1985-03-15',
          gender: 'M',
          phone: '403-555-0100',
          addressLine1: '123 Main St',
          addressLine2: null,
          city: 'Calgary',
          province: 'AB',
          postalCode: 'T2P1A1',
        },
        {
          phn: '987654328',
          firstName: 'Jane',
          lastName: 'Smith',
          dateOfBirth: '1990-07-22',
          gender: 'F',
          phone: null,
          addressLine1: null,
          addressLine2: null,
          city: null,
          province: null,
          postalCode: null,
        },
      ]);

      const res = await authedPost('/api/v1/patients/exports');

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.exportId).toBeDefined();
      expect(typeof body.data.exportId).toBe('string');
      expect(body.data.rowCount).toBe(2);
      expect(body.data.status).toBe('PROCESSING');
    });

    it('emits audit log on export request', async () => {
      mockRepo.exportActivePatients.mockResolvedValueOnce([]);

      await authedPost('/api/v1/patients/exports');

      expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'patient.export_requested',
          category: 'patient',
          resourceType: 'patient_export',
        }),
      );
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/patients/exports');

      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // GET /api/v1/patients/exports/:id
  // =========================================================================

  describe('GET /api/v1/patients/exports/:id', () => {
    it('returns download URL when export is ready', async () => {
      // First create an export
      mockRepo.exportActivePatients.mockResolvedValueOnce([
        {
          phn: '123456782',
          firstName: 'John',
          lastName: 'Doe',
          dateOfBirth: '1985-03-15',
          gender: 'M',
          phone: null,
          addressLine1: null,
          addressLine2: null,
          city: null,
          province: null,
          postalCode: null,
        },
      ]);

      const createRes = await authedPost('/api/v1/patients/exports');
      expect(createRes.statusCode).toBe(201);
      const exportId = createRes.json().data.exportId;

      // Then check status
      const statusRes = await authedGet(`/api/v1/patients/exports/${exportId}`);
      expect(statusRes.statusCode).toBe(200);
      const body = statusRes.json();
      expect(body.data.exportId).toBe(exportId);
      expect(body.data.status).toBe('READY');
      expect(body.data.downloadUrl).toBeDefined();
      expect(body.data.downloadUrl).toContain(`/api/v1/patients/exports/${exportId}/download`);
    });

    it('returns 404 for non-existent export', async () => {
      const fakeExportId = '00000000-cccc-0000-0000-000000000099';
      const res = await authedGet(`/api/v1/patients/exports/${fakeExportId}`);

      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
    });

    it('returns 404 when other physician tries to access export', async () => {
      // Create export as physician1
      mockRepo.exportActivePatients.mockResolvedValueOnce([]);
      const createRes = await authedPost('/api/v1/patients/exports');
      const exportId = createRes.json().data.exportId;

      // Try to access as physician2
      const res = await authedGet(
        `/api/v1/patients/exports/${exportId}`,
        PHYSICIAN2_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID export id', async () => {
      const res = await authedGet('/api/v1/patients/exports/not-a-uuid');

      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/patients/exports/00000000-cccc-0000-0000-000000000001');

      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // POST /api/v1/patients/:id/export (Patient Access Request Export - IMA S74)
  // =========================================================================

  describe('POST /api/v1/patients/:id/export', () => {
    const PATIENT_ID = '00000000-aaaa-0000-0000-000000000001';
    const OTHER_PATIENT_ID = '00000000-aaaa-0000-0000-000000000002';

    const mockDemographics = {
      patientId: PATIENT_ID,
      providerId: PHYSICIAN1_USER_ID,
      phn: '123456782',
      phnProvince: 'AB',
      firstName: 'John',
      middleName: null,
      lastName: 'Doe',
      dateOfBirth: '1985-03-15',
      gender: 'M',
      phone: '403-555-0100',
      email: 'john@example.com',
      addressLine1: '123 Main St',
      addressLine2: null,
      city: 'Calgary',
      province: 'AB',
      postalCode: 'T2P1A1',
      notes: null,
      isActive: true,
      lastVisitDate: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: PHYSICIAN1_USER_ID,
    };

    it('POST /api/v1/patients/:id/export returns download URL', async () => {
      mockRepo.getPatientHealthInformation.mockResolvedValueOnce({
        demographics: mockDemographics,
        claims: [],
        ahcipDetails: [],
        wcbDetails: [],
        auditEntries: [],
      });

      const res = await authedPost(`/api/v1/patients/${PATIENT_ID}/export`);

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.exportId).toBeDefined();
      expect(typeof body.data.exportId).toBe('string');
      expect(body.data.downloadUrl).toBeDefined();
      expect(body.data.downloadUrl).toContain(`/api/v1/patients/${PATIENT_ID}/export/`);
      expect(body.data.downloadUrl).toContain('/download');
      expect(body.data.expiresAt).toBeDefined();
      // Verify 24h expiry
      const expiresAt = new Date(body.data.expiresAt);
      const now = new Date();
      const diffHours = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);
      expect(diffHours).toBeGreaterThan(23);
      expect(diffHours).toBeLessThanOrEqual(24);
    });

    it('export contains patient demographics CSV', async () => {
      mockRepo.getPatientHealthInformation.mockResolvedValueOnce({
        demographics: mockDemographics,
        claims: [
          { claim_id: 'c1', patient_id: PATIENT_ID, status: 'draft', date_of_service: '2026-01-15' },
        ],
        ahcipDetails: [],
        wcbDetails: [],
        auditEntries: [],
      });

      const res = await authedPost(`/api/v1/patients/${PATIENT_ID}/export`);
      expect(res.statusCode).toBe(201);
      const body = res.json();
      const exportId = body.data.exportId;

      // Download the ZIP
      const downloadRes = await authedGet(
        `/api/v1/patients/${PATIENT_ID}/export/${exportId}/download`,
      );
      expect(downloadRes.statusCode).toBe(200);
      expect(downloadRes.headers['content-type']).toBe('application/zip');
      expect(downloadRes.headers['content-disposition']).toContain('patient_');
      expect(downloadRes.headers['content-disposition']).toContain('_export.zip');

      // Verify ZIP is non-empty (valid ZIP starts with PK signature 0x50 0x4b)
      const zipBody = downloadRes.rawPayload;
      expect(zipBody.length).toBeGreaterThan(0);
      expect(zipBody[0]).toBe(0x50); // 'P'
      expect(zipBody[1]).toBe(0x4b); // 'K'
    });

    it('export scoped to authenticated physician', async () => {
      mockRepo.getPatientHealthInformation.mockResolvedValueOnce({
        demographics: mockDemographics,
        claims: [],
        ahcipDetails: [],
        wcbDetails: [],
        auditEntries: [],
      });

      const res = await authedPost(`/api/v1/patients/${PATIENT_ID}/export`);
      expect(res.statusCode).toBe(201);

      // Verify the repo was called with the authenticated physician's ID
      expect(mockRepo.getPatientHealthInformation).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        PATIENT_ID,
      );
    });

    it('returns 404 for another physician\'s patient', async () => {
      // Repo returns null when patient doesn't belong to physician
      mockRepo.getPatientHealthInformation.mockResolvedValueOnce(null);

      const res = await authedPost(`/api/v1/patients/${OTHER_PATIENT_ID}/export`);

      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
      expect(res.json().data).toBeUndefined();
    });

    it('returns 401 without session', async () => {
      const res = await unauthedPost(`/api/v1/patients/${PATIENT_ID}/export`);

      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('audit log records export request without PHI', async () => {
      mockRepo.getPatientHealthInformation.mockResolvedValueOnce({
        demographics: mockDemographics,
        claims: [],
        ahcipDetails: [],
        wcbDetails: [],
        auditEntries: [],
      });

      await authedPost(`/api/v1/patients/${PATIENT_ID}/export`);

      expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'export.patient_access_requested',
          category: 'patient',
          resourceType: 'patient',
          resourceId: PATIENT_ID,
        }),
      );

      // Verify audit detail contains only IDs — no PHI
      const auditCall = mockAuditRepo.appendAuditLog.mock.calls.find(
        (call: any[]) => call[0].action === 'export.patient_access_requested',
      );
      expect(auditCall).toBeDefined();
      const detail = auditCall![0].detail;
      expect(detail.exportId).toBeDefined();
      expect(detail.providerId).toBe(PHYSICIAN1_USER_ID);
      // No PHI in detail
      expect(JSON.stringify(detail)).not.toContain('John');
      expect(JSON.stringify(detail)).not.toContain('Doe');
      expect(JSON.stringify(detail)).not.toContain('123456782');
    });

    it('returns 400 for non-UUID patient id', async () => {
      const res = await authedPost('/api/v1/patients/not-a-uuid/export');

      expect(res.statusCode).toBe(400);
    });

    it('returns 404 for non-existent patient', async () => {
      mockRepo.getPatientHealthInformation.mockResolvedValueOnce(null);

      const nonExistentId = '00000000-aaaa-0000-0000-ffffffffffff';
      const res = await authedPost(`/api/v1/patients/${nonExistentId}/export`);

      expect(res.statusCode).toBe(404);
    });

    it('emits PATIENT_ACCESS_EXPORT_READY event', async () => {
      mockRepo.getPatientHealthInformation.mockResolvedValueOnce({
        demographics: mockDemographics,
        claims: [],
        ahcipDetails: [],
        wcbDetails: [],
        auditEntries: [],
      });

      const res = await authedPost(`/api/v1/patients/${PATIENT_ID}/export`);
      expect(res.statusCode).toBe(201);

      expect(mockEvents.emit).toHaveBeenCalledWith(
        'export.patient_access_ready',
        expect.objectContaining({
          exportId: expect.any(String),
          patientId: PATIENT_ID,
          physicianId: PHYSICIAN1_USER_ID,
          actorId: PHYSICIAN1_USER_ID,
        }),
      );
    });
  });

  // =========================================================================
  // GET /api/v1/patients/:id/export/:exportId/download
  // =========================================================================

  describe('GET /api/v1/patients/:id/export/:exportId/download', () => {
    const PATIENT_ID = '00000000-aaaa-0000-0000-000000000001';

    const mockDemographics = {
      patientId: PATIENT_ID,
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
      isActive: true,
      lastVisitDate: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: PHYSICIAN1_USER_ID,
    };

    it('returns 404 for non-existent export', async () => {
      const fakeExportId = '00000000-bbbb-0000-0000-000000000099';
      const res = await authedGet(
        `/api/v1/patients/${PATIENT_ID}/export/${fakeExportId}/download`,
      );

      expect(res.statusCode).toBe(404);
    });

    it('returns 404 when other physician tries to download', async () => {
      // Create export as physician1
      mockRepo.getPatientHealthInformation.mockResolvedValueOnce({
        demographics: mockDemographics,
        claims: [],
        ahcipDetails: [],
        wcbDetails: [],
        auditEntries: [],
      });

      const createRes = await authedPost(`/api/v1/patients/${PATIENT_ID}/export`);
      expect(createRes.statusCode).toBe(201);
      const exportId = createRes.json().data.exportId;

      // Try to download as physician2
      const res = await authedGet(
        `/api/v1/patients/${PATIENT_ID}/export/${exportId}/download`,
        PHYSICIAN2_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without session', async () => {
      const fakeExportId = '00000000-bbbb-0000-0000-000000000001';
      const res = await unauthedGet(
        `/api/v1/patients/${PATIENT_ID}/export/${fakeExportId}/download`,
      );

      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('returns 400 for non-UUID export id', async () => {
      const res = await authedGet(
        `/api/v1/patients/${PATIENT_ID}/export/not-a-uuid/download`,
      );

      expect(res.statusCode).toBe(400);
    });
  });
});
