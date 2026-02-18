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
// Test data
// ---------------------------------------------------------------------------

const IMPORT_BATCH_ID = '00000000-eeee-0000-0000-000000000001';
const TEMPLATE_ID = '00000000-ffff-0000-0000-000000000001';

function makeMockImportBatch(overrides: Record<string, unknown> = {}) {
  return {
    importBatchId: IMPORT_BATCH_ID,
    physicianId: PHYSICIAN1_USER_ID,
    fileName: 'test.csv',
    fileHash: 'abc123hash',
    fieldMappingTemplateId: null,
    totalRows: 5,
    successCount: 0,
    errorCount: 0,
    status: 'PENDING',
    errorDetails: null,
    createdBy: PHYSICIAN1_USER_ID,
    createdAt: new Date(),
    ...overrides,
  };
}

function makeMockTemplate(overrides: Record<string, unknown> = {}) {
  return {
    templateId: TEMPLATE_ID,
    physicianId: PHYSICIAN1_USER_ID,
    name: 'Test Template',
    emrType: 'MedAccess',
    mappings: [
      { source_column: 'PatientID', target_field: 'patientId' },
      { source_column: 'DOS', target_field: 'dateOfService' },
      { source_column: 'Type', target_field: 'claimType' },
    ],
    delimiter: ',',
    hasHeaderRow: true,
    dateFormat: null,
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
// Mock claim repository
// ---------------------------------------------------------------------------

function createMockClaimRepo() {
  return {
    // Core claim methods (needed by service dependencies)
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
    createImportBatch: vi.fn(async (data: any) => ({
      importBatchId: IMPORT_BATCH_ID,
      ...data,
      createdAt: new Date(),
    })),
    findImportBatchById: vi.fn(async () => undefined as any),
    updateImportBatchStatus: vi.fn(async () => ({})),
    findDuplicateImportByHash: vi.fn(async () => null),
    listImportBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),

    // Template methods
    createTemplate: vi.fn(async (data: any) => ({
      templateId: TEMPLATE_ID,
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findTemplateById: vi.fn(async () => undefined as any),
    updateTemplate: vi.fn(async (_id: string, _pid: string, data: any) => ({
      templateId: TEMPLATE_ID,
      ...data,
      updatedAt: new Date(),
    })),
    deleteTemplate: vi.fn(async () => true),
    listTemplates: vi.fn(async () => []),

    // Shift methods
    createShift: vi.fn(),
    findShiftById: vi.fn(),
    updateShiftStatus: vi.fn(),
    updateShiftTimes: vi.fn(),
    incrementEncounterCount: vi.fn(),
    listShifts: vi.fn(),
    findClaimsByShift: vi.fn(),

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

describe('EMR Import Integration Tests', () => {
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
  // POST /api/v1/imports — Upload Import
  // =========================================================================

  describe('POST /api/v1/imports', () => {
    it('uploads file and returns import_batch_id', async () => {
      const res = await authedPost('/api/v1/imports', {});
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.importBatchId).toBe(IMPORT_BATCH_ID);
      expect(mockRepo.createImportBatch).toHaveBeenCalledTimes(1);
    });

    it('rejects duplicate file (same hash)', async () => {
      mockRepo.findDuplicateImportByHash.mockResolvedValueOnce(makeMockImportBatch());

      const res = await authedPost('/api/v1/imports', {});
      expect(res.statusCode).toBe(409);
      expect(res.json().error.code).toBe('CONFLICT');
    });

    it('uploads with optional template_id', async () => {
      mockRepo.findTemplateById.mockResolvedValueOnce(makeMockTemplate());

      const res = await authedPost('/api/v1/imports', {
        field_mapping_template_id: TEMPLATE_ID,
      });
      expect(res.statusCode).toBe(201);
    });

    it('returns 404 when template_id does not exist', async () => {
      mockRepo.findTemplateById.mockResolvedValueOnce(null);

      const res = await authedPost('/api/v1/imports', {
        field_mapping_template_id: TEMPLATE_ID,
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/imports', {});
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // GET /api/v1/imports/:id — Get Import Batch
  // =========================================================================

  describe('GET /api/v1/imports/:id', () => {
    it('returns import batch details', async () => {
      mockRepo.findImportBatchById.mockResolvedValueOnce(makeMockImportBatch());

      const res = await authedGet(`/api/v1/imports/${IMPORT_BATCH_ID}`);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.importBatchId).toBe(IMPORT_BATCH_ID);
    });

    it('returns 404 for non-existent import batch', async () => {
      mockRepo.findImportBatchById.mockResolvedValueOnce(undefined);

      const res = await authedGet(`/api/v1/imports/${IMPORT_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID id parameter', async () => {
      const res = await authedGet('/api/v1/imports/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/imports/${IMPORT_BATCH_ID}`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/imports/:id/preview — Preview Import
  // =========================================================================

  describe('GET /api/v1/imports/:id/preview', () => {
    it('returns mapped preview', async () => {
      mockRepo.findImportBatchById.mockResolvedValueOnce(
        makeMockImportBatch({ fieldMappingTemplateId: null }),
      );

      const res = await authedGet(`/api/v1/imports/${IMPORT_BATCH_ID}/preview`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('rows');
      expect(body.data).toHaveProperty('totalRows');
      expect(body.data).toHaveProperty('validRows');
      expect(body.data).toHaveProperty('errorRows');
    });

    it('returns 404 for non-existent import batch', async () => {
      mockRepo.findImportBatchById.mockResolvedValueOnce(undefined);

      const res = await authedGet(`/api/v1/imports/${IMPORT_BATCH_ID}/preview`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(`/api/v1/imports/${IMPORT_BATCH_ID}/preview`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/imports/:id/commit — Commit Import
  // =========================================================================

  describe('POST /api/v1/imports/:id/commit', () => {
    it('creates claims and returns counts', async () => {
      mockRepo.findImportBatchById.mockResolvedValue(
        makeMockImportBatch({ status: 'PENDING', fieldMappingTemplateId: null }),
      );

      const res = await authedPost(`/api/v1/imports/${IMPORT_BATCH_ID}/commit`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('successCount');
      expect(body.data).toHaveProperty('errorCount');
      expect(body.data).toHaveProperty('errorDetails');
    });

    it('rejects already processed batch', async () => {
      mockRepo.findImportBatchById.mockResolvedValueOnce(
        makeMockImportBatch({ status: 'COMPLETED' }),
      );

      const res = await authedPost(`/api/v1/imports/${IMPORT_BATCH_ID}/commit`);
      expect(res.statusCode).toBe(409);
    });

    it('returns 404 for non-existent import batch', async () => {
      mockRepo.findImportBatchById.mockResolvedValueOnce(undefined);

      const res = await authedPost(`/api/v1/imports/${IMPORT_BATCH_ID}/commit`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(`/api/v1/imports/${IMPORT_BATCH_ID}/commit`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Field Mapping Templates
  // =========================================================================

  describe('POST /api/v1/field-mapping-templates', () => {
    it('creates template', async () => {
      const res = await authedPost('/api/v1/field-mapping-templates', {
        name: 'My Template',
        mappings: [{ source_column: 'PatientID', target_field: 'patientId' }],
        has_header_row: true,
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.templateId).toBe(TEMPLATE_ID);
      expect(mockRepo.createTemplate).toHaveBeenCalledTimes(1);
    });

    it('rejects without required fields', async () => {
      const res = await authedPost('/api/v1/field-mapping-templates', {
        name: 'My Template',
        // missing mappings and has_header_row
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects empty mappings array', async () => {
      const res = await authedPost('/api/v1/field-mapping-templates', {
        name: 'My Template',
        mappings: [],
        has_header_row: true,
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/field-mapping-templates', {
        name: 'My Template',
        mappings: [{ source_column: 'PatientID', target_field: 'patientId' }],
        has_header_row: true,
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('GET /api/v1/field-mapping-templates', () => {
    it('lists physician\'s templates', async () => {
      mockRepo.listTemplates.mockResolvedValueOnce([
        makeMockTemplate(),
        makeMockTemplate({ templateId: crypto.randomUUID(), name: 'Template 2' }),
      ]);

      const res = await authedGet('/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toHaveLength(2);
    });

    it('returns empty array when no templates exist', async () => {
      mockRepo.listTemplates.mockResolvedValueOnce([]);

      const res = await authedGet('/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toHaveLength(0);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(401);
    });
  });

  describe('PUT /api/v1/field-mapping-templates/:id', () => {
    it('updates template', async () => {
      mockRepo.findTemplateById.mockResolvedValueOnce(makeMockTemplate());
      mockRepo.updateTemplate.mockResolvedValueOnce(
        makeMockTemplate({ name: 'Updated Template' }),
      );

      const res = await authedPut(`/api/v1/field-mapping-templates/${TEMPLATE_ID}`, {
        name: 'Updated Template',
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().data.name).toBe('Updated Template');
    });

    it('returns 404 for non-existent template', async () => {
      mockRepo.findTemplateById.mockResolvedValueOnce(undefined);

      const res = await authedPut(`/api/v1/field-mapping-templates/${TEMPLATE_ID}`, {
        name: 'Updated',
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = app.inject({
        method: 'PUT',
        url: `/api/v1/field-mapping-templates/${TEMPLATE_ID}`,
        headers: { 'content-type': 'application/json' },
        payload: { name: 'Updated' },
      });
      expect((await res).statusCode).toBe(401);
    });
  });

  describe('DELETE /api/v1/field-mapping-templates/:id', () => {
    it('deletes owned template', async () => {
      mockRepo.findTemplateById.mockResolvedValueOnce(makeMockTemplate());

      const res = await authedDelete(`/api/v1/field-mapping-templates/${TEMPLATE_ID}`);
      expect(res.statusCode).toBe(204);
      expect(mockRepo.deleteTemplate).toHaveBeenCalledWith(TEMPLATE_ID, PHYSICIAN1_USER_ID);
    });

    it('returns 404 for non-existent template', async () => {
      mockRepo.findTemplateById.mockResolvedValueOnce(undefined);

      const res = await authedDelete(`/api/v1/field-mapping-templates/${TEMPLATE_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = app.inject({
        method: 'DELETE',
        url: `/api/v1/field-mapping-templates/${TEMPLATE_ID}`,
      });
      expect((await res).statusCode).toBe(401);
    });
  });
});
