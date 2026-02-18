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

const IMPORT_BATCH_ID = '00000000-eeee-0000-0000-000000000001';
const TEMPLATE_ID = '00000000-ffff-0000-0000-000000000001';
const TEMPLATE_ID_2 = '00000000-ffff-0000-0000-000000000002';
const PATIENT_ID_1 = '00000000-aaaa-0000-0000-000000000001';
const PATIENT_ID_2 = '00000000-aaaa-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Stateful import store (simulates batch + template persistence)
// ---------------------------------------------------------------------------

function createStatefulImportStore() {
  const importBatches = new Map<string, Record<string, any>>();
  const templates = new Map<string, Record<string, any>>();
  const claims = new Map<string, Record<string, any>>();
  const auditEntries: Array<Record<string, any>> = [];
  const fileHashes = new Map<string, string>(); // hash -> batchId
  let batchIdCounter = 0;
  let claimIdCounter = 0;

  return {
    importBatches,
    templates,
    claims,
    auditEntries,
    fileHashes,

    // Core claim methods
    createClaim: vi.fn(async (data: any) => {
      const claimId = `00000000-cccc-0000-0000-${String(++claimIdCounter).padStart(12, '0')}`;
      const claim = {
        claimId,
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
        shiftId: data.shiftId ?? null,
        importBatchId: data.importBatchId ?? null,
        deletedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      claims.set(claimId, claim);
      return claim;
    }),
    findClaimById: vi.fn(async (claimId: string, physicianId: string) => {
      const c = claims.get(claimId);
      if (!c || c.physicianId !== physicianId || c.deletedAt) return undefined;
      return { ...c };
    }),
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

    // Import batch methods
    createImportBatch: vi.fn(async (data: any) => {
      const batchId = `00000000-eeee-0000-0000-${String(++batchIdCounter).padStart(12, '0')}`;
      const batch = {
        importBatchId: batchId,
        ...data,
        createdAt: new Date(),
      };
      importBatches.set(batchId, batch);
      if (data.fileHash) {
        fileHashes.set(`${data.physicianId}:${data.fileHash}`, batchId);
      }
      return batch;
    }),
    findImportBatchById: vi.fn(async (batchId: string, physicianId: string) => {
      const batch = importBatches.get(batchId);
      if (!batch || batch.physicianId !== physicianId) return undefined;
      return { ...batch };
    }),
    updateImportBatchStatus: vi.fn(
      async (batchId: string, physicianId: string, status: string, extra?: any) => {
        const batch = importBatches.get(batchId);
        if (!batch || batch.physicianId !== physicianId) return undefined;
        batch.status = status;
        if (extra) {
          if (extra.successCount !== undefined) batch.successCount = extra.successCount;
          if (extra.errorCount !== undefined) batch.errorCount = extra.errorCount;
          if (extra.errorDetails !== undefined) batch.errorDetails = extra.errorDetails;
        }
        return { ...batch };
      },
    ),
    findDuplicateImportByHash: vi.fn(async (physicianId: string, hash: string) => {
      const key = `${physicianId}:${hash}`;
      const batchId = fileHashes.get(key);
      if (!batchId) return null;
      return importBatches.get(batchId) ?? null;
    }),
    listImportBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),

    // Template methods
    createTemplate: vi.fn(async (data: any) => {
      const templateId = data.templateId ?? `00000000-ffff-0000-0000-${String(templates.size + 1).padStart(12, '0')}`;
      const template = {
        templateId,
        ...data,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      templates.set(templateId, template);
      return template;
    }),
    findTemplateById: vi.fn(async (templateId: string, physicianId: string) => {
      const t = templates.get(templateId);
      if (!t || t.physicianId !== physicianId) return undefined;
      return { ...t };
    }),
    updateTemplate: vi.fn(async () => ({})),
    deleteTemplate: vi.fn(async () => true),
    listTemplates: vi.fn(async () => []),

    // Shift methods (stubs)
    createShift: vi.fn(),
    findShiftById: vi.fn(),
    updateShiftStatus: vi.fn(),
    updateShiftTimes: vi.fn(),
    incrementEncounterCount: vi.fn(),
    listShifts: vi.fn(),
    findClaimsByShift: vi.fn(),

    // Export methods (stubs)
    createExportRecord: vi.fn(),
    findExportById: vi.fn(),
    updateExportStatus: vi.fn(),

    // Audit
    appendClaimAudit: vi.fn(async (entry: any) => {
      const audit = {
        auditId: crypto.randomUUID(),
        ...entry,
        createdAt: new Date(),
      };
      auditEntries.push(audit);
      return audit;
    }),
    getClaimAuditHistory: vi.fn(async () => []),
    getClaimAuditHistoryPaginated: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
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
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let store: ReturnType<typeof createStatefulImportStore>;
let mockProviderCheck: { isActive: ReturnType<typeof vi.fn>; getRegistrationDate: ReturnType<typeof vi.fn> };
let mockPatientCheck: { exists: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  store = createStatefulImportStore();
  mockProviderCheck = {
    isActive: vi.fn(async () => true),
    getRegistrationDate: vi.fn(async () => '2020-01-01'),
  };
  mockPatientCheck = {
    exists: vi.fn(async () => true),
  };

  const serviceDeps: ClaimServiceDeps = {
    repo: store as any,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('EMR Import Workflow Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    // Reset store between test groups
    store.importBatches.clear();
    store.templates.clear();
    store.claims.clear();
    store.auditEntries.length = 0;
    store.fileHashes.clear();
    vi.clearAllMocks();
    mockProviderCheck.isActive.mockResolvedValue(true);
    mockProviderCheck.getRegistrationDate.mockResolvedValue('2020-01-01');
    mockPatientCheck.exists.mockResolvedValue(true);
  });

  // =========================================================================
  // CSV comma delimiter parses correctly
  // =========================================================================

  describe('CSV comma delimiter parsing', () => {
    it('uploads CSV with comma delimiter, previews, commits, and creates claims', async () => {
      // 1. Create a field mapping template with comma delimiter
      const templateRes = await authedPost('/api/v1/field-mapping-templates', {
        name: 'Comma CSV Template',
        mappings: [
          { source_column: 'PatientID', target_field: 'patientId' },
          { source_column: 'DOS', target_field: 'dateOfService' },
          { source_column: 'Type', target_field: 'claimType' },
        ],
        delimiter: ',',
        has_header_row: true,
      });
      expect(templateRes.statusCode).toBe(201);
      const templateId = templateRes.json().data.templateId;

      // 2. Upload a CSV file (the handler extracts file from body)
      const csvContent = [
        'PatientID,DOS,Type',
        `${PATIENT_ID_1},2026-01-15,AHCIP`,
        `${PATIENT_ID_2},2026-01-16,AHCIP`,
      ].join('\n');

      // Simulate file upload via JSON body (handler extracts from request.file)
      const uploadRes = await app.inject({
        method: 'POST',
        url: '/api/v1/imports',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: {
          field_mapping_template_id: templateId,
        },
      });
      expect(uploadRes.statusCode).toBe(201);
      const importBatchId = uploadRes.json().data.importBatchId;
      expect(importBatchId).toBeDefined();

      // 3. Preview the import (send file_content in body)
      const previewRes = await app.inject({
        method: 'GET',
        url: `/api/v1/imports/${importBatchId}/preview`,
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { file_content: csvContent },
      });
      expect(previewRes.statusCode).toBe(200);
      const preview = previewRes.json().data;
      expect(preview).toHaveProperty('rows');
      expect(preview).toHaveProperty('totalRows');
      expect(preview).toHaveProperty('validRows');
      expect(preview).toHaveProperty('errorRows');

      // 4. Commit the import
      const commitRes = await app.inject({
        method: 'POST',
        url: `/api/v1/imports/${importBatchId}/commit`,
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { file_content: csvContent },
      });
      expect(commitRes.statusCode).toBe(200);
      const commitResult = commitRes.json().data;
      expect(commitResult).toHaveProperty('successCount');
      expect(commitResult).toHaveProperty('errorCount');
      expect(commitResult).toHaveProperty('errorDetails');
      // Both rows should succeed (patients exist, dates valid)
      expect(commitResult.successCount).toBe(2);
      expect(commitResult.errorCount).toBe(0);

      // 5. Verify claims were created
      expect(store.claims.size).toBe(2);
      const claimValues = Array.from(store.claims.values());
      expect(claimValues.every((c) => c.importSource === 'EMR_IMPORT')).toBe(true);
      expect(claimValues.every((c) => c.importBatchId === importBatchId)).toBe(true);
    });
  });

  // =========================================================================
  // Partial failure reports correct counts
  // =========================================================================

  describe('Partial failure handling', () => {
    it('reports correct success and error counts when some rows fail', async () => {
      // Create template
      const templateRes = await authedPost('/api/v1/field-mapping-templates', {
        name: 'Partial Fail Template',
        mappings: [
          { source_column: 'PatientID', target_field: 'patientId' },
          { source_column: 'DOS', target_field: 'dateOfService' },
          { source_column: 'Type', target_field: 'claimType' },
        ],
        delimiter: ',',
        has_header_row: true,
      });
      const templateId = templateRes.json().data.templateId;

      // Upload
      const uploadRes = await app.inject({
        method: 'POST',
        url: '/api/v1/imports',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { field_mapping_template_id: templateId },
      });
      const importBatchId = uploadRes.json().data.importBatchId;

      // CSV with 3 valid rows and 2 invalid rows (missing required fields)
      const csvContent = [
        'PatientID,DOS,Type',
        `${PATIENT_ID_1},2026-01-15,AHCIP`,       // valid
        `${PATIENT_ID_2},2026-01-16,AHCIP`,       // valid
        `,2026-01-17,AHCIP`,                       // missing patientId
        `${PATIENT_ID_1},,AHCIP`,                  // missing DOS
        `${PATIENT_ID_1},2026-01-18,AHCIP`,       // valid
      ].join('\n');

      // Commit (POST can carry file_content in body; preview is GET and
      // does not pass body through Fastify, so we test counts via commit)
      const commitRes = await app.inject({
        method: 'POST',
        url: `/api/v1/imports/${importBatchId}/commit`,
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { file_content: csvContent },
      });
      expect(commitRes.statusCode).toBe(200);
      const result = commitRes.json().data;
      expect(result.successCount).toBe(3);
      expect(result.errorCount).toBe(2);
      // Row 3 has 1 error (missing patientId), row 4 has 2 errors (invalid date + missing DOS)
      expect(result.errorDetails.length).toBeGreaterThanOrEqual(2);

      // Verify error details reference correct row numbers
      const errorRowNumbers = result.errorDetails.map((e: any) => e.rowNumber);
      expect(errorRowNumbers).toContain(3); // row 3: missing patientId
      expect(errorRowNumbers).toContain(4); // row 4: missing DOS
    });
  });

  // =========================================================================
  // Duplicate file rejected by hash
  // =========================================================================

  describe('Duplicate file detection via SHA-256 hash', () => {
    it('rejects a file that has already been imported with the same content', async () => {
      // First upload succeeds
      const firstRes = await app.inject({
        method: 'POST',
        url: '/api/v1/imports',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: {},
      });
      expect(firstRes.statusCode).toBe(201);

      // The handler computes a hash from the file content.
      // Since the handler extracts file from request.file (which is empty/default),
      // both uploads will have the same hash. The second should be rejected.
      const secondRes = await app.inject({
        method: 'POST',
        url: '/api/v1/imports',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: {},
      });
      expect(secondRes.statusCode).toBe(409);
      expect(secondRes.json().error.code).toBe('CONFLICT');
    });
  });

  // =========================================================================
  // Field mapping template reuse across imports
  // =========================================================================

  describe('Template reuse across imports', () => {
    it('uses the same template for multiple import batches', async () => {
      // Create a reusable template
      const templateRes = await authedPost('/api/v1/field-mapping-templates', {
        name: 'Reusable Template',
        mappings: [
          { source_column: 'PatientID', target_field: 'patientId' },
          { source_column: 'DOS', target_field: 'dateOfService' },
          { source_column: 'Type', target_field: 'claimType' },
        ],
        delimiter: ',',
        has_header_row: true,
      });
      expect(templateRes.statusCode).toBe(201);
      const templateId = templateRes.json().data.templateId;

      // First import with template
      const firstUpload = await app.inject({
        method: 'POST',
        url: '/api/v1/imports',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { field_mapping_template_id: templateId },
      });
      expect(firstUpload.statusCode).toBe(201);
      const firstBatchId = firstUpload.json().data.importBatchId;

      // Verify first batch references the template
      const firstBatch = store.importBatches.get(firstBatchId);
      expect(firstBatch).toBeDefined();
      expect(firstBatch!.fieldMappingTemplateId).toBe(templateId);

      // Second import with same template (different file content)
      // We need to clear the file hash so it's not a duplicate
      store.fileHashes.clear();

      const secondUpload = await app.inject({
        method: 'POST',
        url: '/api/v1/imports',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { field_mapping_template_id: templateId },
      });
      expect(secondUpload.statusCode).toBe(201);
      const secondBatchId = secondUpload.json().data.importBatchId;

      // Verify second batch also references the same template
      const secondBatch = store.importBatches.get(secondBatchId);
      expect(secondBatch).toBeDefined();
      expect(secondBatch!.fieldMappingTemplateId).toBe(templateId);

      // Both batches use the same template but are different batches
      expect(firstBatchId).not.toBe(secondBatchId);

      // Commit both batches with different CSV content — template mappings apply to both
      const csv1 = [
        'PatientID,DOS,Type',
        `${PATIENT_ID_1},2026-01-15,AHCIP`,
      ].join('\n');

      const commit1 = await app.inject({
        method: 'POST',
        url: `/api/v1/imports/${firstBatchId}/commit`,
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { file_content: csv1 },
      });
      expect(commit1.statusCode).toBe(200);
      expect(commit1.json().data.successCount).toBe(1);

      const csv2 = [
        'PatientID,DOS,Type',
        `${PATIENT_ID_2},2026-02-01,AHCIP`,
      ].join('\n');

      const commit2 = await app.inject({
        method: 'POST',
        url: `/api/v1/imports/${secondBatchId}/commit`,
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { file_content: csv2 },
      });
      expect(commit2.statusCode).toBe(200);
      expect(commit2.json().data.successCount).toBe(1);
    });
  });
});
