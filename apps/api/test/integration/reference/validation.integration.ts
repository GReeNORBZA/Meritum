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
const MODIFIERS_VERSION_ID = '00000000-aaaa-0000-0000-000000000003';
const RULES_VERSION_ID = '00000000-aaaa-0000-0000-000000000009';
const FC_VERSION_ID = '00000000-aaaa-0000-0000-000000000004';

// ---------------------------------------------------------------------------
// Mock reference data
// ---------------------------------------------------------------------------

const MOCK_HSC_DETAIL = {
  hscCode: '03.04A',
  description: 'Office visit — complete assessment',
  baseFee: '38.56',
  feeType: 'fixed',
  helpText: 'Standard office visit for complete assessment',
  specialtyRestrictions: [],
  facilityRestrictions: [],
  modifierEligibility: ['CMGP', 'ANNT'],
  combinationGroup: null,
  surchargeEligible: true,
  pcpcmBasket: 'in_basket',
  requiresReferral: false,
  maxPerDay: null,
  maxPerVisit: null,
  effectiveTo: null,
};

const MOCK_RULE = {
  ruleId: 'VL001',
  ruleName: 'Max 3 office visits per day',
  ruleCategory: 'visit_limits',
  description: 'Limits office visits to 3 per day',
  severity: 'error',
  ruleLogic: { max_per_day: 3, hsc_codes: ['03.04A', '03.04B'] },
  errorMessage: 'Maximum 3 office visits per day exceeded',
  helpText: 'SOMB limits the number of office visits per day',
  sourceReference: 'SOMB Section 4.2.1',
  sourceUrl: null,
  versionId: RULES_VERSION_ID,
  effectiveFrom: '2026-01-01',
  effectiveTo: null,
};

const MOCK_MODIFIERS = [
  {
    modifierCode: 'CMGP',
    name: 'Comprehensive GP Care',
    description: 'Added to calls for comprehensive care',
    type: 'explicit',
    calculationMethod: 'percentage',
    calculationParams: { percentage: 15 },
    applicableHscFilter: { all: true },
    combinableWith: [],
    exclusiveWith: [],
    governingRuleReference: null,
    helpText: null,
    requiresTimeDocumentation: false,
    requiresFacility: false,
    versionId: MODIFIERS_VERSION_ID,
  },
];

const MOCK_FC = {
  code: 'FC001',
  name: 'Calgary General Hospital',
  facilityType: 'hospital_inpatient',
  locationCity: 'Calgary',
  locationRegion: 'Calgary Zone',
  active: true,
};

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
        MODIFIERS: { versionId: MODIFIERS_VERSION_ID, dataSet: 'MODIFIERS', isActive: true, effectiveFrom: '2026-01-01' },
        GOVERNING_RULES: { versionId: RULES_VERSION_ID, dataSet: 'GOVERNING_RULES', isActive: true, effectiveFrom: '2026-01-01' },
        FUNCTIONAL_CENTRES: { versionId: FC_VERSION_ID, dataSet: 'FUNCTIONAL_CENTRES', isActive: true, effectiveFrom: '2026-01-01' },
      };
      return versionMap[dataSet];
    }),
    findVersionForDate: vi.fn(async (dataSet: string, _date: Date) => {
      // Delegate to findActiveVersion for test simplification
      return undefined;
    }),
    findHscByCode: vi.fn(async (code: string, _versionId: string) => {
      if (code === '03.04A') return MOCK_HSC_DETAIL;
      return undefined;
    }),
    findRulesForContext: vi.fn(async () => [MOCK_RULE]),
    findModifiersForHsc: vi.fn(async () => MOCK_MODIFIERS),
    findFunctionalCentre: vi.fn(async (code: string, _versionId: string) => {
      if (code === 'FC001') return MOCK_FC;
      return undefined;
    }),
    findRuleById: vi.fn(async (ruleId: string, _versionId: string) => {
      if (ruleId === 'VL001') return MOCK_RULE;
      return undefined;
    }),

    // Stubs for unused repo methods (required by type)
    searchHscCodes: vi.fn(async () => []),
    listHscByVersion: vi.fn(async () => ({ data: [], total: 0 })),
    searchDiCodes: vi.fn(async () => []),
    findDiByCode: vi.fn(async () => undefined),
    listAllModifiers: vi.fn(async () => []),
    findModifierByCode: vi.fn(async () => undefined),
    listFunctionalCentres: vi.fn(async () => []),
    findExplanatoryCode: vi.fn(async () => undefined),
    findRrnpRate: vi.fn(async () => undefined),
    findPcpcmBasket: vi.fn(async () => undefined),
    listHolidaysByYear: vi.fn(async () => []),
    isHoliday: vi.fn(async () => ({ is_holiday: false })),
    listVersions: vi.fn(async () => []),
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

  // Fix findVersionForDate to delegate to findActiveVersion on the same instance
  mockRepo.findVersionForDate = vi.fn(async (dataSet: string, _date: Date) => {
    return mockRepo.findActiveVersion(dataSet);
  });

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

function authedPost(url: string, payload: unknown) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload,
  });
}

function unauthedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
  });
}

function unauthedPost(url: string, payload: unknown) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload,
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Internal Validation Routes', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Restore findVersionForDate delegation after clearAllMocks
    mockRepo.findVersionForDate = vi.fn(async (dataSet: string, _date: Date) => {
      return mockRepo.findActiveVersion(dataSet);
    });
  });

  // =========================================================================
  // GET /api/v1/ref/rules/validate-context
  // =========================================================================

  describe('GET /api/v1/ref/rules/validate-context', () => {
    it('returns applicable rules for claim context', async () => {
      const res = await authedGet(
        '/api/v1/ref/rules/validate-context?hsc=03.04A&date=2026-03-15',
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.hscDetails).toBeInstanceOf(Array);
      expect(body.data.hscDetails.length).toBe(1);
      expect(body.data.hscDetails[0].code).toBe('03.04A');
      expect(body.data.applicableRules).toBeInstanceOf(Array);
      expect(body.data.applicableRules.length).toBe(1);
      expect(body.data.applicableRules[0].ruleId).toBe('VL001');
      expect(body.data.modifierApplicability).toBeInstanceOf(Array);
      expect(body.data.versionInfo).toHaveProperty('somb');
      expect(body.data.versionInfo).toHaveProperty('modifiers');
      expect(body.data.versionInfo).toHaveProperty('governingRules');
    });

    it('includes facility validation when facility param provided', async () => {
      const res = await authedGet(
        '/api/v1/ref/rules/validate-context?hsc=03.04A&facility=FC001&date=2026-03-15',
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.facilityValidation.code).toBe('FC001');
      expect(body.data.facilityValidation.valid).toBe(true);
      expect(body.data.facilityValidation.facilityType).toBe('hospital_inpatient');
    });

    it('returns 400 for missing required hsc param', async () => {
      const res = await authedGet('/api/v1/ref/rules/validate-context?date=2026-03-15');
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for missing required date param', async () => {
      const res = await authedGet('/api/v1/ref/rules/validate-context?hsc=03.04A');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet(
        '/api/v1/ref/rules/validate-context?hsc=03.04A&date=2026-03-15',
      );
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // GET /api/v1/ref/rules/:rule_id
  // =========================================================================

  describe('GET /api/v1/ref/rules/:rule_id', () => {
    it('returns full rule with rule_logic', async () => {
      const res = await authedGet('/api/v1/ref/rules/VL001');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.ruleId).toBe('VL001');
      expect(body.data.ruleName).toBe('Max 3 office visits per day');
      expect(body.data.ruleLogic).toEqual({ max_per_day: 3, hsc_codes: ['03.04A', '03.04B'] });
      expect(body.data.severity).toBe('error');
      expect(body.data.helpText).toBe('SOMB limits the number of office visits per day');
    });

    it('accepts optional date query parameter', async () => {
      const res = await authedGet('/api/v1/ref/rules/VL001?date=2025-06-15');
      expect(res.statusCode).toBe(200);
      expect(mockRepo.findVersionForDate).toHaveBeenCalledWith(
        'GOVERNING_RULES',
        new Date('2025-06-15'),
      );
    });

    it('returns 404 for unknown rule ID', async () => {
      const res = await authedGet('/api/v1/ref/rules/ZZZZ');
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/rules/VL001');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // GET /api/v1/ref/somb/version
  // =========================================================================

  describe('GET /api/v1/ref/somb/version', () => {
    it('returns version for date', async () => {
      const res = await authedGet('/api/v1/ref/somb/version?date=2026-03-15');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.versionId).toBe(SOMB_VERSION_ID);
    });

    it('returns 400 for missing date param', async () => {
      const res = await authedGet('/api/v1/ref/somb/version');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/somb/version?date=2026-03-15');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // POST /api/v1/ref/rules/evaluate-batch
  // =========================================================================

  describe('POST /api/v1/ref/rules/evaluate-batch', () => {
    it('handles multiple claims and returns per-claim rules', async () => {
      const res = await authedPost('/api/v1/ref/rules/evaluate-batch', {
        claims: [
          {
            hscCodes: ['03.04A'],
            diCode: '401',
            dateOfService: '2026-03-15',
          },
          {
            hscCodes: ['03.04A', '03.04B'],
            facilityCode: 'FC001',
            dateOfService: '2026-03-16',
          },
        ],
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.results).toBeInstanceOf(Array);
      expect(body.data.results.length).toBe(2);
      expect(body.data.results[0].claimIndex).toBe(0);
      expect(body.data.results[0].applicableRules).toBeInstanceOf(Array);
      expect(body.data.results[1].claimIndex).toBe(1);
    });

    it('rejects batch with more than 500 claims', async () => {
      const claims = Array.from({ length: 501 }, (_, i) => ({
        hscCodes: ['03.04A'],
        dateOfService: '2026-03-15',
      }));
      const res = await authedPost('/api/v1/ref/rules/evaluate-batch', { claims });
      expect(res.statusCode).toBe(400);
    });

    it('rejects empty claims array', async () => {
      const res = await authedPost('/api/v1/ref/rules/evaluate-batch', {
        claims: [],
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for missing body', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/rules/evaluate-batch',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: {},
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedPost('/api/v1/ref/rules/evaluate-batch', {
        claims: [{ hscCodes: ['03.04A'], dateOfService: '2026-03-15' }],
      });
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // Route ordering: validate-context and evaluate-batch are not captured
  // by the :rule_id param route
  // =========================================================================

  describe('Route ordering', () => {
    it('validate-context is not treated as a :rule_id', async () => {
      const res = await authedGet(
        '/api/v1/ref/rules/validate-context?hsc=03.04A&date=2026-03-15',
      );
      expect(res.statusCode).toBe(200);
      // If this was captured by :rule_id, it would try to find a rule with ID "validate-context"
      // and return 404. Instead we get 200 because the validate-context route matched.
      expect(res.json().data).toHaveProperty('hscDetails');
    });

    it('evaluate-batch is not treated as a :rule_id', async () => {
      const res = await authedPost('/api/v1/ref/rules/evaluate-batch', {
        claims: [{ hscCodes: ['03.04A'], dateOfService: '2026-03-15' }],
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toHaveProperty('results');
    });
  });

  // =========================================================================
  // All validation routes return 401 without auth
  // =========================================================================

  describe('All validation routes return 401 without auth', () => {
    const routes = [
      '/api/v1/ref/rules/validate-context?hsc=03.04A&date=2026-03-15',
      '/api/v1/ref/rules/VL001',
      '/api/v1/ref/somb/version?date=2026-03-15',
    ];

    for (const route of routes) {
      it(`GET ${route} returns 401`, async () => {
        const res = await unauthedGet(route);
        expect(res.statusCode).toBe(401);
        expect(res.json().data).toBeUndefined();
      });
    }

    it('POST /api/v1/ref/rules/evaluate-batch returns 401', async () => {
      const res = await unauthedPost('/api/v1/ref/rules/evaluate-batch', {
        claims: [{ hscCodes: ['03.04A'], dateOfService: '2026-03-15' }],
      });
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });
});
