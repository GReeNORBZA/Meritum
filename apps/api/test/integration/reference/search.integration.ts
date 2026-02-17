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
const MODIFIERS_VERSION_ID = '00000000-aaaa-0000-0000-000000000003';
const FC_VERSION_ID = '00000000-aaaa-0000-0000-000000000004';
const EXPL_VERSION_ID = '00000000-aaaa-0000-0000-000000000005';
const RRNP_VERSION_ID = '00000000-aaaa-0000-0000-000000000006';
const PCPCM_VERSION_ID = '00000000-aaaa-0000-0000-000000000007';

const TEST_COMMUNITY_ID = '00000000-cccc-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock reference data
// ---------------------------------------------------------------------------

const MOCK_HSC_RESULTS = [
  {
    id: '1',
    hscCode: '03.04A',
    description: 'Office visit — complete assessment',
    baseFee: '38.56',
    feeType: 'fixed',
    helpText: 'Standard office visit for complete assessment',
    effectiveTo: null,
  },
  {
    id: '2',
    hscCode: '03.04B',
    description: 'Office visit — limited assessment',
    baseFee: '22.13',
    feeType: 'fixed',
    helpText: null,
    effectiveTo: null,
  },
];

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

const MOCK_DI_RESULTS = [
  {
    id: '1',
    diCode: '401',
    description: 'Essential hypertension',
    category: 'Circulatory',
    qualifiesSurcharge: true,
    qualifiesBcp: false,
    helpText: null,
  },
];

const MOCK_DI_DETAIL = {
  diCode: '401',
  description: 'Essential hypertension',
  category: 'Circulatory',
  subcategory: 'Hypertension',
  qualifiesSurcharge: true,
  qualifiesBcp: false,
  commonInSpecialty: ['GP', 'IM'],
  helpText: null,
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

const MOCK_MODIFIER_DETAIL = {
  ...MOCK_MODIFIERS[0],
};

const MOCK_FC_LIST = [
  {
    code: 'FC001',
    name: 'Calgary General Hospital',
    facilityType: 'hospital_inpatient',
    locationCity: 'Calgary',
    locationRegion: 'Calgary Zone',
    active: true,
  },
];

const MOCK_EXPL_CODE = {
  explCode: 'R001',
  description: 'Claim rejected — service not covered',
  severity: 'rejected',
  commonCause: 'Service code not eligible',
  suggestedAction: 'Review service code eligibility',
  helpText: 'This code indicates the service is not covered under AHCIP.',
};

const MOCK_RRNP_RATE = {
  communityName: 'Milk River',
  rrnpPercentage: '25.00',
};

const MOCK_PCPCM_BASKET = {
  hscCode: '03.04A',
  basket: 'in_basket',
  notes: null,
};

const MOCK_HOLIDAYS = [
  {
    holidayId: '00000000-dddd-0000-0000-000000000001',
    date: '2026-01-01',
    name: 'New Year\'s Day',
    jurisdiction: 'both',
    affectsBillingPremiums: true,
    year: 2026,
  },
  {
    holidayId: '00000000-dddd-0000-0000-000000000002',
    date: '2026-07-01',
    name: 'Canada Day',
    jurisdiction: 'federal',
    affectsBillingPremiums: true,
    year: 2026,
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
      const versionMap: Record<string, { versionId: string; dataSet: string; isActive: boolean; effectiveFrom: string }> = {
        SOMB: { versionId: SOMB_VERSION_ID, dataSet: 'SOMB', isActive: true, effectiveFrom: '2026-01-01' },
        DI_CODES: { versionId: DI_VERSION_ID, dataSet: 'DI_CODES', isActive: true, effectiveFrom: '2026-01-01' },
        MODIFIERS: { versionId: MODIFIERS_VERSION_ID, dataSet: 'MODIFIERS', isActive: true, effectiveFrom: '2026-01-01' },
        FUNCTIONAL_CENTRES: { versionId: FC_VERSION_ID, dataSet: 'FUNCTIONAL_CENTRES', isActive: true, effectiveFrom: '2026-01-01' },
        EXPLANATORY_CODES: { versionId: EXPL_VERSION_ID, dataSet: 'EXPLANATORY_CODES', isActive: true, effectiveFrom: '2026-01-01' },
        RRNP: { versionId: RRNP_VERSION_ID, dataSet: 'RRNP', isActive: true, effectiveFrom: '2026-01-01' },
        PCPCM: { versionId: PCPCM_VERSION_ID, dataSet: 'PCPCM', isActive: true, effectiveFrom: '2026-01-01' },
      };
      return versionMap[dataSet];
    }),
    findVersionForDate: vi.fn(async (dataSet: string, _date: Date) => {
      // Return the same version for any date (test simplification)
      const activeVersion = await createMockReferenceRepo().findActiveVersion(dataSet);
      return activeVersion;
    }),
    searchHscCodes: vi.fn(async () => MOCK_HSC_RESULTS),
    findHscByCode: vi.fn(async (code: string, _versionId: string) => {
      if (code === '03.04A') return MOCK_HSC_DETAIL;
      return undefined;
    }),
    listHscByVersion: vi.fn(async () => ({
      data: [MOCK_HSC_DETAIL],
      total: 1,
    })),
    findModifiersForHsc: vi.fn(async () => MOCK_MODIFIERS),
    searchDiCodes: vi.fn(async () => MOCK_DI_RESULTS),
    findDiByCode: vi.fn(async (code: string, _versionId: string) => {
      if (code === '401') return MOCK_DI_DETAIL;
      return undefined;
    }),
    listAllModifiers: vi.fn(async () => MOCK_MODIFIERS),
    findModifierByCode: vi.fn(async (code: string, _versionId: string) => {
      if (code === 'CMGP') return MOCK_MODIFIER_DETAIL;
      return undefined;
    }),
    listFunctionalCentres: vi.fn(async () => MOCK_FC_LIST),
    findFunctionalCentre: vi.fn(async () => MOCK_FC_LIST[0]),
    findExplanatoryCode: vi.fn(async (code: string, _versionId: string) => {
      if (code === 'R001') return MOCK_EXPL_CODE;
      return undefined;
    }),
    findRrnpRate: vi.fn(async (communityId: string, _versionId: string) => {
      if (communityId === TEST_COMMUNITY_ID) return MOCK_RRNP_RATE;
      return undefined;
    }),
    findPcpcmBasket: vi.fn(async (hscCode: string, _versionId: string) => {
      if (hscCode === '03.04A') return MOCK_PCPCM_BASKET;
      return undefined;
    }),
    listHolidaysByYear: vi.fn(async (year: number) => {
      if (year === 2026) return MOCK_HOLIDAYS;
      return [];
    }),
    isHoliday: vi.fn(async (date: Date) => {
      const dateStr = date.toISOString().split('T')[0];
      const holiday = MOCK_HOLIDAYS.find((h) => h.date === dateStr);
      if (holiday) {
        return { is_holiday: true, holiday_name: holiday.name };
      }
      return { is_holiday: false };
    }),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockReferenceRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockReferenceRepo();

  // Fix findVersionForDate to use the same repo instance
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

  // Register reference routes
  await testApp.register(referenceRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helper: make authenticated request
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

describe('Reference Data Search/Lookup Routes', () => {
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
  // HSC Search
  // =========================================================================

  describe('GET /api/v1/ref/hsc/search', () => {
    it('returns HSC results for keyword', async () => {
      const res = await authedGet('/api/v1/ref/hsc/search?q=office&limit=10');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.results).toBeInstanceOf(Array);
      expect(body.data.results.length).toBe(2);
      expect(body.data.results[0].code).toBe('03.04A');
      expect(body.data.results[0].description).toContain('Office visit');
    });

    it('returns version-appropriate results for date param', async () => {
      const res = await authedGet('/api/v1/ref/hsc/search?q=office&date=2025-06-15');
      expect(res.statusCode).toBe(200);
      expect(mockRepo.findVersionForDate).toHaveBeenCalledWith(
        'SOMB',
        new Date('2025-06-15'),
      );
    });

    it('returns 400 for missing query param', async () => {
      const res = await authedGet('/api/v1/ref/hsc/search');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/hsc/search?q=office');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // HSC Detail
  // =========================================================================

  describe('GET /api/v1/ref/hsc/:code', () => {
    it('returns full HSC detail', async () => {
      const res = await authedGet('/api/v1/ref/hsc/03.04A');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.code).toBe('03.04A');
      expect(body.data.baseFee).toBe('38.56');
      expect(body.data.applicableModifiers).toBeInstanceOf(Array);
    });

    it('returns 404 for unknown HSC code', async () => {
      const res = await authedGet('/api/v1/ref/hsc/99.99Z');
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/hsc/03.04A');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // HSC Favourites
  // =========================================================================

  describe('GET /api/v1/ref/hsc/favourites', () => {
    it('returns favourites list for authenticated user', async () => {
      const res = await authedGet('/api/v1/ref/hsc/favourites');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.favourites).toBeInstanceOf(Array);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/hsc/favourites');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // DI Search
  // =========================================================================

  describe('GET /api/v1/ref/di/search', () => {
    it('returns DI results with surcharge flags', async () => {
      const res = await authedGet('/api/v1/ref/di/search?q=hypertension');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.results).toBeInstanceOf(Array);
      expect(body.data.results.length).toBe(1);
      expect(body.data.results[0].code).toBe('401');
      expect(body.data.results[0].qualifiesSurcharge).toBe(true);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/di/search?q=hypertension');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // DI Detail
  // =========================================================================

  describe('GET /api/v1/ref/di/:code', () => {
    it('returns full DI detail', async () => {
      const res = await authedGet('/api/v1/ref/di/401');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.code).toBe('401');
      expect(body.data.qualifiesSurcharge).toBe(true);
    });

    it('returns 404 for unknown DI code', async () => {
      const res = await authedGet('/api/v1/ref/di/999');
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/di/401');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Modifiers
  // =========================================================================

  describe('GET /api/v1/ref/modifiers', () => {
    it('returns applicable modifiers for HSC', async () => {
      const res = await authedGet('/api/v1/ref/modifiers?hsc=03.04A');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.modifiers).toBeInstanceOf(Array);
      expect(body.data.modifiers.length).toBeGreaterThan(0);
    });

    it('returns all modifiers when no HSC specified', async () => {
      const res = await authedGet('/api/v1/ref/modifiers');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.modifiers).toBeInstanceOf(Array);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/modifiers');
      expect(res.statusCode).toBe(401);
    });
  });

  describe('GET /api/v1/ref/modifiers/:code', () => {
    it('returns modifier detail', async () => {
      const res = await authedGet('/api/v1/ref/modifiers/CMGP');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.modifierCode).toBe('CMGP');
    });

    it('returns 404 for unknown modifier', async () => {
      const res = await authedGet('/api/v1/ref/modifiers/ZZZZ');
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/modifiers/CMGP');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Functional Centres
  // =========================================================================

  describe('GET /api/v1/ref/functional-centres', () => {
    it('returns functional centres list', async () => {
      const res = await authedGet('/api/v1/ref/functional-centres');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.centres).toBeInstanceOf(Array);
      expect(body.data.centres.length).toBe(1);
      expect(body.data.centres[0].code).toBe('FC001');
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/functional-centres');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Explanatory Codes
  // =========================================================================

  describe('GET /api/v1/ref/explanatory-codes/:code', () => {
    it('returns explanatory code detail', async () => {
      const res = await authedGet('/api/v1/ref/explanatory-codes/R001');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.code).toBe('R001');
      expect(body.data.severity).toBe('rejected');
    });

    it('returns 404 for unknown code', async () => {
      const res = await authedGet('/api/v1/ref/explanatory-codes/ZZZZ');
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/explanatory-codes/R001');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // RRNP
  // =========================================================================

  describe('GET /api/v1/ref/rrnp/:community_id', () => {
    it('returns RRNP rate for community', async () => {
      const res = await authedGet(`/api/v1/ref/rrnp/${TEST_COMMUNITY_ID}`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.communityName).toBe('Milk River');
      expect(body.data.rrnpPercentage).toBe('25.00');
    });

    it('returns 404 for unknown community', async () => {
      const res = await authedGet('/api/v1/ref/rrnp/00000000-cccc-0000-0000-000999999999');
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID community_id', async () => {
      const res = await authedGet('/api/v1/ref/rrnp/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet(`/api/v1/ref/rrnp/${TEST_COMMUNITY_ID}`);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // PCPCM
  // =========================================================================

  describe('GET /api/v1/ref/pcpcm/:hsc_code', () => {
    it('returns basket classification', async () => {
      const res = await authedGet('/api/v1/ref/pcpcm/03.04A');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.basket).toBe('in_basket');
      expect(body.data.hscCode).toBe('03.04A');
    });

    it('returns 404 for unknown HSC code', async () => {
      const res = await authedGet('/api/v1/ref/pcpcm/99.99Z');
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/pcpcm/03.04A');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Holidays
  // =========================================================================

  describe('GET /api/v1/ref/holidays', () => {
    it('returns holidays for year', async () => {
      const res = await authedGet('/api/v1/ref/holidays?year=2026');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.holidays).toBeInstanceOf(Array);
      expect(body.data.holidays.length).toBe(2);
      expect(body.data.holidays[0].name).toBe("New Year's Day");
    });

    it('returns empty array for year with no holidays', async () => {
      const res = await authedGet('/api/v1/ref/holidays?year=2099');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.holidays).toEqual([]);
    });

    it('returns 400 for missing year', async () => {
      const res = await authedGet('/api/v1/ref/holidays');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/holidays?year=2026');
      expect(res.statusCode).toBe(401);
    });
  });

  describe('GET /api/v1/ref/holidays/check', () => {
    it('correctly identifies holiday', async () => {
      const res = await authedGet('/api/v1/ref/holidays/check?date=2026-01-01');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.is_holiday).toBe(true);
      expect(body.data.holiday_name).toBe("New Year's Day");
    });

    it('correctly identifies non-holiday', async () => {
      const res = await authedGet('/api/v1/ref/holidays/check?date=2026-03-15');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.is_holiday).toBe(false);
    });

    it('returns 400 for missing date', async () => {
      const res = await authedGet('/api/v1/ref/holidays/check');
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without auth', async () => {
      const res = await unauthedGet('/api/v1/ref/holidays/check?date=2026-01-01');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Auth enforcement across all routes
  // =========================================================================

  describe('All routes return 401 without auth', () => {
    const routes = [
      '/api/v1/ref/hsc/search?q=test',
      '/api/v1/ref/hsc/favourites',
      '/api/v1/ref/hsc/03.04A',
      '/api/v1/ref/di/search?q=test',
      '/api/v1/ref/di/401',
      '/api/v1/ref/modifiers',
      '/api/v1/ref/modifiers/CMGP',
      '/api/v1/ref/functional-centres',
      '/api/v1/ref/explanatory-codes/R001',
      `/api/v1/ref/rrnp/${TEST_COMMUNITY_ID}`,
      '/api/v1/ref/pcpcm/03.04A',
      '/api/v1/ref/holidays?year=2026',
      '/api/v1/ref/holidays/check?date=2026-01-01',
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
