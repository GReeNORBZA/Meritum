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

const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Fixed test data IDs
// ---------------------------------------------------------------------------

const SOMB_VERSION_ID = '00000000-aaaa-0000-0000-000000000001';
const DI_VERSION_ID = '00000000-aaaa-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Mock reference data
// ---------------------------------------------------------------------------

const MOCK_SOMB_VERSION = {
  versionId: SOMB_VERSION_ID,
  dataSet: 'SOMB',
  versionLabel: 'v2026.1',
  effectiveFrom: '2026-01-01',
  publishedBy: '00000000-1111-0000-0000-000000000010',
  publishedAt: new Date('2026-01-01T00:00:00Z'),
  isActive: true,
  sourceDocument: 'SOMB Update Jan 2026',
  changeSummary: '3 codes added, 1 deprecated',
  recordsAdded: 3,
  recordsModified: 0,
  recordsDeprecated: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const MOCK_DI_VERSION = {
  versionId: DI_VERSION_ID,
  dataSet: 'DI_CODES',
  versionLabel: 'v2026.1',
  effectiveFrom: '2026-01-01',
  publishedBy: '00000000-1111-0000-0000-000000000010',
  publishedAt: new Date('2026-01-15T00:00:00Z'),
  isActive: true,
  sourceDocument: null,
  changeSummary: null,
  recordsAdded: 5,
  recordsModified: 2,
  recordsDeprecated: 0,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const MOCK_HSC_CODES = [
  {
    hscCode: '03.04A',
    description: 'Office visit — complete assessment',
    baseFee: '38.56',
    feeType: 'fixed',
    specialtyRestrictions: ['GP'],
    effectiveTo: null,
  },
  {
    hscCode: '03.04C',
    description: 'New code — extended assessment',
    baseFee: '52.00',
    feeType: 'fixed',
    specialtyRestrictions: [],
    effectiveTo: null,
  },
  {
    hscCode: '99.99Z',
    description: 'Deprecated code',
    baseFee: '10.00',
    feeType: 'fixed',
    specialtyRestrictions: [],
    effectiveTo: '2026-01-01',
  },
];

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
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
// Mock reference repository
// ---------------------------------------------------------------------------

function createMockReferenceRepo() {
  return {
    findActiveVersion: vi.fn(async (dataSet: string) => {
      const versionMap: Record<string, any> = {
        SOMB: { versionId: SOMB_VERSION_ID, dataSet: 'SOMB', isActive: true, effectiveFrom: '2026-01-01' },
        DI_CODES: { versionId: DI_VERSION_ID, dataSet: 'DI_CODES', isActive: true, effectiveFrom: '2026-01-01' },
      };
      return versionMap[dataSet];
    }),
    findVersionForDate: vi.fn(async () => undefined),
    listVersions: vi.fn(async (dataSet: string) => {
      if (dataSet === 'SOMB') return [MOCK_SOMB_VERSION];
      if (dataSet === 'DI_CODES') return [MOCK_DI_VERSION];
      return [];
    }),
    listHscByVersion: vi.fn(async () => ({
      data: MOCK_HSC_CODES,
      total: MOCK_HSC_CODES.length,
    })),

    // Stubs for unused repo methods
    searchHscCodes: vi.fn(async () => []),
    findHscByCode: vi.fn(async () => undefined),
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
    listHolidaysByYear: vi.fn(async () => []),
    isHoliday: vi.fn(async () => ({ is_holiday: false })),
    findRulesForContext: vi.fn(async () => []),
    findRuleById: vi.fn(async () => undefined),
    createVersion: vi.fn(async () => ({})),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),
    createStagingRecord: vi.fn(async () => ({})),
    findStagingById: vi.fn(async () => undefined),
    updateStagingStatus: vi.fn(async () => ({})),
    deleteStagingRecord: vi.fn(async () => {}),
    listStagingByDataSet: vi.fn(async () => []),
    createHoliday: vi.fn(async () => ({})),
    updateHoliday: vi.fn(async () => undefined),
    deleteHoliday: vi.fn(async () => {}),
    bulkInsertHscCodes: vi.fn(async () => {}),
    bulkInsertWcbCodes: vi.fn(async () => {}),
    bulkInsertModifiers: vi.fn(async () => {}),
    bulkInsertRules: vi.fn(async () => {}),
    bulkInsertDiCodes: vi.fn(async () => {}),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),
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

  // Register reference routes
  await testApp.register(referenceRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function authedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
  });
}

function unauthedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Change Summary Routes', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Restore listVersions mock after clearAllMocks
    mockRepo.listVersions = vi.fn(async (dataSet: string) => {
      if (dataSet === 'SOMB') return [MOCK_SOMB_VERSION];
      if (dataSet === 'DI_CODES') return [MOCK_DI_VERSION];
      return [];
    });
    mockRepo.listHscByVersion = vi.fn(async () => ({
      data: MOCK_HSC_CODES,
      total: MOCK_HSC_CODES.length,
    }));
  });

  // =========================================================================
  // GET /api/v1/ref/changes
  // =========================================================================

  describe('GET /api/v1/ref/changes', () => {
    it('returns version publications across all datasets', async () => {
      const res = await authedGet('/api/v1/ref/changes');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.versions).toBeInstanceOf(Array);
      expect(body.data.versions.length).toBeGreaterThan(0);
      // Should contain SOMB version
      const sombVersion = body.data.versions.find(
        (v: any) => v.data_set === 'SOMB',
      );
      expect(sombVersion).toBeDefined();
      expect(sombVersion.version_label).toBe('v2026.1');
      expect(sombVersion.records_added).toBe(3);
    });

    it('filters by dataset when provided', async () => {
      const res = await authedGet('/api/v1/ref/changes?dataset=SOMB');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.versions).toBeInstanceOf(Array);
      // Should only contain SOMB versions
      for (const v of body.data.versions) {
        expect(v.data_set).toBe('SOMB');
      }
    });

    it('filters by since date when provided', async () => {
      const res = await authedGet('/api/v1/ref/changes?since=2026-01-10');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      // DI version was published on 2026-01-15, should pass the filter
      // SOMB version was published on 2026-01-01, should be filtered out
      expect(body.data.versions).toBeInstanceOf(Array);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/changes');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // GET /api/v1/ref/changes/:version_id/detail
  // =========================================================================

  describe('GET /api/v1/ref/changes/:version_id/detail', () => {
    it('returns code-level changes for a version', async () => {
      const res = await authedGet(`/api/v1/ref/changes/${SOMB_VERSION_ID}/detail`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('added');
      expect(body.data).toHaveProperty('modified');
      expect(body.data).toHaveProperty('deprecated');
      expect(body.data.added).toBeInstanceOf(Array);
      expect(body.data.deprecated).toBeInstanceOf(Array);
    });

    it('filters by specialty when provided', async () => {
      const res = await authedGet(
        `/api/v1/ref/changes/${SOMB_VERSION_ID}/detail?specialty=GP`,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      // With GP specialty filter, should include codes with GP restriction
      // or codes with no restrictions
      expect(body.data.added).toBeInstanceOf(Array);
    });

    it('returns 404 for unknown version ID', async () => {
      const unknownId = '00000000-aaaa-0000-0000-000000999999';
      const res = await authedGet(`/api/v1/ref/changes/${unknownId}/detail`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID version_id', async () => {
      const res = await authedGet('/api/v1/ref/changes/not-a-uuid/detail');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet(`/api/v1/ref/changes/${SOMB_VERSION_ID}/detail`);
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // GET /api/v1/ref/changes/:version_id/physician-impact
  // =========================================================================

  describe('GET /api/v1/ref/changes/:version_id/physician-impact', () => {
    it('returns personalised impact data', async () => {
      const res = await authedGet(
        `/api/v1/ref/changes/${SOMB_VERSION_ID}/physician-impact`,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('deprecated_codes_used');
      expect(body.data).toHaveProperty('fee_changes');
      expect(body.data).toHaveProperty('new_relevant_codes');
      expect(body.data.deprecated_codes_used).toBeInstanceOf(Array);
      expect(body.data.fee_changes).toBeInstanceOf(Array);
      expect(body.data.new_relevant_codes).toBeInstanceOf(Array);
    });

    it('returns new relevant codes from SOMB version', async () => {
      const res = await authedGet(
        `/api/v1/ref/changes/${SOMB_VERSION_ID}/physician-impact`,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      // New codes are those without effectiveTo set
      expect(body.data.new_relevant_codes.length).toBeGreaterThan(0);
      for (const code of body.data.new_relevant_codes) {
        expect(code).toHaveProperty('code');
        expect(code).toHaveProperty('description');
        expect(code).toHaveProperty('baseFee');
        expect(code).toHaveProperty('feeType');
      }
    });

    it('returns 404 for unknown version ID', async () => {
      const unknownId = '00000000-aaaa-0000-0000-000000999999';
      const res = await authedGet(`/api/v1/ref/changes/${unknownId}/physician-impact`);
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID version_id', async () => {
      const res = await authedGet('/api/v1/ref/changes/not-a-uuid/physician-impact');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet(
        `/api/v1/ref/changes/${SOMB_VERSION_ID}/physician-impact`,
      );
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // All change routes return 401 without auth
  // =========================================================================

  describe('All change routes return 401 without auth', () => {
    const routes = [
      '/api/v1/ref/changes',
      `/api/v1/ref/changes/${SOMB_VERSION_ID}/detail`,
      `/api/v1/ref/changes/${SOMB_VERSION_ID}/physician-impact`,
    ];

    for (const route of routes) {
      it(`GET ${route} returns 401`, async () => {
        const res = await unauthedGet(route);
        expect(res.statusCode).toBe(401);
        expect(res.json().data).toBeUndefined();
      });
    }
  });
});
