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
import { referenceRoutes } from '../../../src/domains/reference/reference.routes.js';
import { type ReferenceHandlerDeps } from '../../../src/domains/reference/reference.handlers.js';
import { type ReferenceServiceDeps } from '../../../src/domains/reference/reference.service.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000010';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000010';

const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Fixed test data IDs
// ---------------------------------------------------------------------------

const STAGING_ID = '00000000-bbbb-0000-0000-000000000001';
const HOLIDAY_ID = '00000000-dddd-0000-0000-000000000001';
const VERSION_ID = '00000000-aaaa-0000-0000-000000000001';
const RULES_VERSION_ID = '00000000-aaaa-0000-0000-000000000009';
const SOMB_VERSION_ID = '00000000-aaaa-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === ADMIN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: ADMIN_SESSION_ID,
            userId: ADMIN_USER_ID,
            tokenHash: ADMIN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: ADMIN_USER_ID,
            role: 'ADMIN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      if (tokenHash === PHYSICIAN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: PHYSICIAN_SESSION_ID,
            userId: PHYSICIAN_USER_ID,
            tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN_USER_ID,
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
// Mock reference data
// ---------------------------------------------------------------------------

const MOCK_STAGING_RECORD = {
  stagingId: STAGING_ID,
  dataSet: 'SOMB',
  uploadedBy: ADMIN_USER_ID,
  fileHash: 'abc123',
  recordCount: 2,
  stagedData: [
    { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.56', fee_type: 'fixed' },
    { hsc_code: '03.04B', description: 'Limited visit', base_fee: '22.13', fee_type: 'fixed' },
  ],
  status: 'diff_generated',
  validationResult: { valid: true, errors: [] },
  diffResult: {
    added: [],
    modified: [],
    deprecated: [],
    summary_stats: { added: 2, modified: 0, deprecated: 0 },
  },
  createdAt: new Date(),
  updatedAt: new Date(),
};

const MOCK_VERSION = {
  versionId: VERSION_ID,
  dataSet: 'SOMB',
  versionLabel: 'v2026.1',
  effectiveFrom: '2026-01-01',
  publishedBy: ADMIN_USER_ID,
  publishedAt: new Date(),
  isActive: true,
  sourceDocument: null,
  changeSummary: null,
  recordsAdded: 2,
  recordsModified: 0,
  recordsDeprecated: 0,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const MOCK_HOLIDAY = {
  holidayId: HOLIDAY_ID,
  date: '2026-12-25',
  name: 'Christmas Day',
  jurisdiction: 'both',
  affectsBillingPremiums: true,
  year: 2026,
};

const MOCK_RULE = {
  ruleId: 'VL001',
  ruleName: 'Max 3 office visits per day',
  description: 'Limits office visits to 3 per day',
  category: 'visit_limits',
  severity: 'error',
  ruleLogic: { max_per_day: 3, hsc_codes: ['03.04A', '03.04B'] },
  effectiveFrom: '2026-01-01',
  effectiveTo: null,
  versionId: RULES_VERSION_ID,
};

const MOCK_DIFF_RESULT = {
  added: [{ hsc_code: '03.04C', description: 'New code' }],
  modified: [],
  deprecated: [],
  summary_stats: { added: 1, modified: 0, deprecated: 0 },
};

// ---------------------------------------------------------------------------
// Mock reference repository
// ---------------------------------------------------------------------------

function createMockReferenceRepo() {
  return {
    // Version management
    findActiveVersion: vi.fn(async (dataSet: string) => {
      const versionMap: Record<string, any> = {
        SOMB: { versionId: SOMB_VERSION_ID, dataSet: 'SOMB', isActive: true, effectiveFrom: '2026-01-01' },
        GOVERNING_RULES: { versionId: RULES_VERSION_ID, dataSet: 'GOVERNING_RULES', isActive: true, effectiveFrom: '2026-01-01' },
      };
      return versionMap[dataSet];
    }),
    findVersionForDate: vi.fn(async (dataSet: string, _date: Date) => {
      return undefined;
    }),
    listVersions: vi.fn(async (_dataSet: string) => [MOCK_VERSION]),
    createVersion: vi.fn(async (data: any) => ({
      versionId: crypto.randomUUID(),
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),

    // Staging operations
    createStagingRecord: vi.fn(async (data: any) => ({
      stagingId: STAGING_ID,
      ...data,
      status: 'uploaded',
      validationResult: null,
      diffResult: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findStagingById: vi.fn(async (id: string) => {
      if (id === STAGING_ID) return MOCK_STAGING_RECORD;
      return undefined;
    }),
    updateStagingStatus: vi.fn(async (id: string, status: string, result?: any) => ({
      ...MOCK_STAGING_RECORD,
      status,
      ...(result?.validation_result !== undefined ? { validationResult: result.validation_result } : {}),
      ...(result?.diff_result !== undefined ? { diffResult: result.diff_result } : {}),
    })),
    deleteStagingRecord: vi.fn(async () => {}),
    listStagingByDataSet: vi.fn(async () => []),

    // Holiday operations
    createHoliday: vi.fn(async (data: any) => ({
      holidayId: crypto.randomUUID(),
      ...data,
    })),
    updateHoliday: vi.fn(async (id: string, data: any) => {
      if (id === HOLIDAY_ID) return { ...MOCK_HOLIDAY, ...data };
      return undefined;
    }),
    deleteHoliday: vi.fn(async () => {}),
    listHolidaysByYear: vi.fn(async () => [MOCK_HOLIDAY]),
    isHoliday: vi.fn(async () => ({ is_holiday: false })),

    // Rule operations
    findRuleById: vi.fn(async (ruleId: string, _versionId: string) => {
      if (ruleId === 'VL001') return MOCK_RULE;
      return undefined;
    }),

    // Bulk inserts (for publish)
    bulkInsertHscCodes: vi.fn(async () => {}),
    bulkInsertWcbCodes: vi.fn(async () => {}),
    bulkInsertModifiers: vi.fn(async () => {}),
    bulkInsertRules: vi.fn(async () => {}),
    bulkInsertDiCodes: vi.fn(async () => {}),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),

    // Search queries (stub for completeness — not used in admin tests)
    searchHscCodes: vi.fn(async () => []),
    findHscByCode: vi.fn(async () => undefined),
    listHscByVersion: vi.fn(async () => ({ data: [], total: 0 })),
    findModifiersForHsc: vi.fn(async () => []),
    searchDiCodes: vi.fn(async () => []),
    findDiByCode: vi.fn(async () => undefined),
    listAllModifiers: vi.fn(async () => []),
    findModifierByCode: vi.fn(async () => undefined),
    listFunctionalCentres: vi.fn(async () => []),
    findFunctionalCentre: vi.fn(async () => undefined),
    findExplanatoryCode: vi.fn(async () => undefined),
    findRrnpRate: vi.fn(async () => undefined),
    findPcpcmBasket: vi.fn(async () => undefined),
    findRulesForContext: vi.fn(async () => []),

    // For diff generation: list all active records for comparison
    listAllHscCodes: vi.fn(async () => []),
    listAllWcbCodes: vi.fn(async () => []),
    listAllDiCodes: vi.fn(async () => []),
    listAllGoverningRules: vi.fn(async () => []),
    listAllFunctionalCentres: vi.fn(async () => []),
    listAllRrnpCommunities: vi.fn(async () => []),
    listAllPcpcmBaskets: vi.fn(async () => []),
    listAllExplanatoryCodes: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockReferenceRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockReferenceRepo();

  const serviceDeps: ReferenceServiceDeps = {
    repo: mockRepo as any,
  };

  const handlerDeps: ReferenceHandlerDeps = {
    serviceDeps,
  };

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
  testApp.setErrorHandler((error, request, reply) => {
    // AppError instances
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: {
            code: (error as any).code,
            message: error.message,
          },
        });
      }
    }
    // Zod validation errors
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

  // Register reference routes (includes admin routes)
  await testApp.register(referenceRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function adminInject(method: string, url: string, payload?: unknown) {
  const opts: any = {
    method,
    url,
    headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
  };
  if (payload !== undefined) {
    opts.payload = payload;
    opts.headers['content-type'] = 'application/json';
  }
  return app.inject(opts);
}

function physicianInject(method: string, url: string, payload?: unknown) {
  const opts: any = {
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
  };
  if (payload !== undefined) {
    opts.payload = payload;
    opts.headers['content-type'] = 'application/json';
  }
  return app.inject(opts);
}

function unauthedInject(method: string, url: string, payload?: unknown) {
  const opts: any = { method, url };
  if (payload !== undefined) {
    opts.payload = payload;
    opts.headers = { 'content-type': 'application/json' };
  }
  return app.inject(opts);
}

function adminUpload(dataset: string, filename: string, content: string, contentType: string) {
  const boundary = '----FormBoundary' + randomBytes(8).toString('hex');
  const body = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="file"; filename="${filename}"`,
    `Content-Type: ${contentType}`,
    '',
    content,
    `--${boundary}--`,
  ].join('\r\n');

  return app.inject({
    method: 'POST',
    url: `/api/v1/admin/ref/${dataset}/upload`,
    headers: {
      cookie: `session=${ADMIN_SESSION_TOKEN}`,
      'content-type': `multipart/form-data; boundary=${boundary}`,
    },
    payload: body,
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Admin Routes', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Restore default findStagingById behavior
    mockRepo.findStagingById.mockImplementation(async (id: string) => {
      if (id === STAGING_ID) return MOCK_STAGING_RECORD;
      return undefined;
    });
  });

  // =========================================================================
  // File Upload
  // =========================================================================

  describe('POST /api/v1/admin/ref/:dataset/upload', () => {
    it('accepts CSV file upload', async () => {
      const csvContent = 'hsc_code,description,base_fee,fee_type\n03.04A,Office visit,38.56,fixed';

      const res = await adminUpload('SOMB', 'somb.csv', csvContent, 'text/csv');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.staging_id).toBe(STAGING_ID);
      expect(body.data.record_count).toBeGreaterThan(0);
    });

    it('accepts JSON file upload', async () => {
      const jsonContent = JSON.stringify([
        { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.56', fee_type: 'fixed' },
      ]);

      const res = await adminUpload('SOMB', 'somb.json', jsonContent, 'application/json');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.staging_id).toBe(STAGING_ID);
    });

    it('rejects invalid dataset name', async () => {
      const csvContent = 'hsc_code,description\n03.04A,Office visit';
      const res = await adminUpload('INVALID_DS', 'data.csv', csvContent, 'text/csv');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const boundary = '----FormBoundary' + randomBytes(8).toString('hex');
      const body = [
        `--${boundary}`,
        `Content-Disposition: form-data; name="file"; filename="data.csv"`,
        `Content-Type: text/csv`,
        '',
        'a,b\n1,2',
        `--${boundary}--`,
      ].join('\r\n');

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/SOMB/upload',
        headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
        payload: body,
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects non-admin (physician) users', async () => {
      const boundary = '----FormBoundary' + randomBytes(8).toString('hex');
      const body = [
        `--${boundary}`,
        `Content-Disposition: form-data; name="file"; filename="data.csv"`,
        `Content-Type: text/csv`,
        '',
        'a,b\n1,2',
        `--${boundary}--`,
      ].join('\r\n');

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/SOMB/upload',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Staging Diff
  // =========================================================================

  describe('GET /api/v1/admin/ref/:dataset/staging/:id/diff', () => {
    it('returns staging diff', async () => {
      const res = await adminInject('GET', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/diff`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('summary_stats');
    });

    it('returns 404 for unknown staging ID', async () => {
      const unknownId = '00000000-bbbb-0000-0000-000000999999';
      const res = await adminInject('GET', `/api/v1/admin/ref/SOMB/staging/${unknownId}/diff`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedInject('GET', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/diff`);
      expect(res.statusCode).toBe(401);
    });

    it('rejects non-admin users', async () => {
      const res = await physicianInject('GET', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/diff`);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Publish Version
  // =========================================================================

  describe('POST /api/v1/admin/ref/:dataset/staging/:id/publish', () => {
    it('creates live version from staged data', async () => {
      const res = await adminInject('POST', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`, {
        version_label: 'v2026.2',
        effective_from: '2026-07-01',
        source_document: 'SOMB Update July 2026',
        change_summary: 'Added new codes',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toHaveProperty('version_id');
    });

    it('returns 404 for unknown staging ID', async () => {
      const unknownId = '00000000-bbbb-0000-0000-000000999999';
      const res = await adminInject('POST', `/api/v1/admin/ref/SOMB/staging/${unknownId}/publish`, {
        version_label: 'v2026.2',
        effective_from: '2026-07-01',
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for missing required fields', async () => {
      const res = await adminInject('POST', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`, {});
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedInject('POST', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`, {
        version_label: 'v2026.2',
        effective_from: '2026-07-01',
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects non-admin users', async () => {
      const res = await physicianInject('POST', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`, {
        version_label: 'v2026.2',
        effective_from: '2026-07-01',
      });
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Discard Staging
  // =========================================================================

  describe('DELETE /api/v1/admin/ref/:dataset/staging/:id', () => {
    it('discards staged data', async () => {
      const res = await adminInject('DELETE', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.success).toBe(true);
    });

    it('returns 404 for unknown staging ID', async () => {
      const unknownId = '00000000-bbbb-0000-0000-000000999999';
      const res = await adminInject('DELETE', `/api/v1/admin/ref/SOMB/staging/${unknownId}`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedInject('DELETE', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`);
      expect(res.statusCode).toBe(401);
    });

    it('rejects non-admin users', async () => {
      const res = await physicianInject('DELETE', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // List Versions
  // =========================================================================

  describe('GET /api/v1/admin/ref/:dataset/versions', () => {
    it('returns version list for dataset', async () => {
      const res = await adminInject('GET', '/api/v1/admin/ref/SOMB/versions');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.versions).toBeInstanceOf(Array);
      expect(body.data.versions.length).toBeGreaterThan(0);
    });

    it('returns 400 for invalid dataset', async () => {
      const res = await adminInject('GET', '/api/v1/admin/ref/INVALID/versions');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedInject('GET', '/api/v1/admin/ref/SOMB/versions');
      expect(res.statusCode).toBe(401);
    });

    it('rejects non-admin users', async () => {
      const res = await physicianInject('GET', '/api/v1/admin/ref/SOMB/versions');
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Holiday Management
  // =========================================================================

  describe('POST /api/v1/admin/ref/holidays', () => {
    it('creates a holiday', async () => {
      const res = await adminInject('POST', '/api/v1/admin/ref/holidays', {
        date: '2026-12-25',
        name: 'Christmas Day',
        jurisdiction: 'both',
        affects_billing_premiums: true,
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toHaveProperty('holidayId');
      expect(body.data.name).toBe('Christmas Day');
    });

    it('returns 400 for missing required fields', async () => {
      const res = await adminInject('POST', '/api/v1/admin/ref/holidays', {
        date: '2026-12-25',
        // missing name and jurisdiction
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for invalid jurisdiction', async () => {
      const res = await adminInject('POST', '/api/v1/admin/ref/holidays', {
        date: '2026-12-25',
        name: 'Test',
        jurisdiction: 'invalid',
        affects_billing_premiums: true,
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedInject('POST', '/api/v1/admin/ref/holidays', {
        date: '2026-12-25',
        name: 'Christmas',
        jurisdiction: 'both',
        affects_billing_premiums: true,
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects non-admin users', async () => {
      const res = await physicianInject('POST', '/api/v1/admin/ref/holidays', {
        date: '2026-12-25',
        name: 'Christmas',
        jurisdiction: 'both',
        affects_billing_premiums: true,
      });
      expect(res.statusCode).toBe(403);
    });
  });

  describe('PUT /api/v1/admin/ref/holidays/:id', () => {
    it('updates a holiday', async () => {
      const res = await adminInject('PUT', `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`, {
        name: 'Christmas Day (Updated)',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.name).toBe('Christmas Day (Updated)');
    });

    it('returns 404 for unknown holiday', async () => {
      const unknownId = '00000000-dddd-0000-0000-000000999999';
      const res = await adminInject('PUT', `/api/v1/admin/ref/holidays/${unknownId}`, {
        name: 'Updated',
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID ID', async () => {
      const res = await adminInject('PUT', '/api/v1/admin/ref/holidays/not-a-uuid', {
        name: 'Updated',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedInject('PUT', `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`, { name: 'X' });
      expect(res.statusCode).toBe(401);
    });

    it('rejects non-admin users', async () => {
      const res = await physicianInject('PUT', `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`, { name: 'X' });
      expect(res.statusCode).toBe(403);
    });
  });

  describe('DELETE /api/v1/admin/ref/holidays/:id', () => {
    it('deletes a holiday', async () => {
      const res = await adminInject('DELETE', `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.success).toBe(true);
    });

    it('returns 400 for non-UUID ID', async () => {
      const res = await adminInject('DELETE', '/api/v1/admin/ref/holidays/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedInject('DELETE', `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`);
      expect(res.statusCode).toBe(401);
    });

    it('rejects non-admin users', async () => {
      const res = await physicianInject('DELETE', `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Dry-Run Rule
  // =========================================================================

  describe('POST /api/v1/admin/ref/rules/:rule_id/dry-run', () => {
    it('returns affected claims for rule change', async () => {
      const res = await adminInject('POST', '/api/v1/admin/ref/rules/VL001/dry-run', {
        updated_rule_logic: { max_per_day: 5, hsc_codes: ['03.04A'] },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('claims_affected');
      expect(body.data).toHaveProperty('sample_results');
      expect(body.data.claims_affected).toBe(0);
      expect(body.data.sample_results).toBeInstanceOf(Array);
    });

    it('returns 404 for unknown rule', async () => {
      const res = await adminInject('POST', '/api/v1/admin/ref/rules/ZZZZ/dry-run', {
        updated_rule_logic: { max_per_day: 5 },
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for missing body', async () => {
      const res = await adminInject('POST', '/api/v1/admin/ref/rules/VL001/dry-run');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedInject('POST', '/api/v1/admin/ref/rules/VL001/dry-run', {
        updated_rule_logic: { max_per_day: 5 },
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects non-admin users', async () => {
      const res = await physicianInject('POST', '/api/v1/admin/ref/rules/VL001/dry-run', {
        updated_rule_logic: { max_per_day: 5 },
      });
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // All admin routes reject non-admin users
  // =========================================================================

  describe('All admin routes reject non-admin (physician) users', () => {
    const adminRoutes: Array<[string, string, unknown?]> = [
      ['GET', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/diff`],
      ['POST', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`, {
        version_label: 'v1', effective_from: '2026-01-01',
      }],
      ['DELETE', `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`],
      ['GET', '/api/v1/admin/ref/SOMB/versions'],
      ['POST', '/api/v1/admin/ref/holidays', {
        date: '2026-01-01', name: 'Test', jurisdiction: 'both', affects_billing_premiums: true,
      }],
      ['PUT', `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`, { name: 'X' }],
      ['DELETE', `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`],
      ['POST', '/api/v1/admin/ref/rules/VL001/dry-run', {
        updated_rule_logic: { max_per_day: 5 },
      }],
    ];

    for (const [method, url, payload] of adminRoutes) {
      it(`${method} ${url} returns 403 for physician`, async () => {
        const res = await physicianInject(method, url, payload);
        expect(res.statusCode).toBe(403);
      });
    }
  });
});
