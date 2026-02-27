import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
// ---------------------------------------------------------------------------

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(
      (email: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`,
    ),
    verify: vi.fn(({ token }: { token: string }) => token === '123456'),
  };
  return { authenticator: mockAuthenticator };
});

// ---------------------------------------------------------------------------
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { referenceRoutes } from '../../../src/domains/reference/reference.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test users -- two physicians + two admins
// ---------------------------------------------------------------------------

// Physician 1 -- "our" physician
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);
const PHYSICIAN1_USER_ID = 'aaaa1111-0000-0000-0000-000000000001';
const PHYSICIAN1_SESSION_ID = 'aaaa1111-0000-0000-0000-000000000011';

// Physician 2 -- "other" physician (attacker perspective)
const PHYSICIAN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_SESSION_TOKEN_HASH = hashToken(PHYSICIAN2_SESSION_TOKEN);
const PHYSICIAN2_USER_ID = 'aaaa1111-0000-0000-0000-000000000002';
const PHYSICIAN2_SESSION_ID = 'aaaa1111-0000-0000-0000-000000000012';

// Admin 1
const ADMIN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN1_SESSION_TOKEN_HASH = hashToken(ADMIN1_SESSION_TOKEN);
const ADMIN1_USER_ID = 'aaaa1111-0000-0000-0000-000000000091';
const ADMIN1_SESSION_ID = 'aaaa1111-0000-0000-0000-000000000191';

// Admin 2
const ADMIN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN2_SESSION_TOKEN_HASH = hashToken(ADMIN2_SESSION_TOKEN);
const ADMIN2_USER_ID = 'aaaa1111-0000-0000-0000-000000000092';
const ADMIN2_SESSION_ID = 'aaaa1111-0000-0000-0000-000000000192';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
  role: string;
  subscriptionStatus: string;
}

interface MockSession {
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}

let users: MockUser[] = [];
let sessions: MockSession[] = [];

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: '44444444-0000-0000-0000-000000000001' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Shared mock data -- global reference data (same for ALL physicians)
// ---------------------------------------------------------------------------

const SHARED_ICD_CROSSWALK_RESULTS = [
  {
    icd10Code: 'J06.9',
    icd10Description: 'Acute upper respiratory infection, unspecified',
    icd9Code: '465',
    icd9Description: 'Acute URI',
    matchQuality: 'EXACT',
    isPreferred: true,
    notes: null,
  },
  {
    icd10Code: 'J06.9',
    icd10Description: 'Acute upper respiratory infection, unspecified',
    icd9Code: '460',
    icd9Description: 'Acute nasopharyngitis',
    matchQuality: 'APPROXIMATE',
    isPreferred: false,
    notes: 'Less specific',
  },
];

const SHARED_PROVIDER_SEARCH_RESULTS = [
  {
    registryId: 'reg-1',
    cpsa: '12345',
    firstName: 'Jane',
    lastName: 'Smith',
    specialtyCode: 'GP',
    specialtyDescription: 'General Practice',
    city: 'Calgary',
    facilityName: 'Smith Clinic',
    phone: '403-555-1234',
    fax: '403-555-5678',
    isActive: true,
  },
];

const SHARED_PROVIDER_DETAIL = {
  registryId: 'reg-1',
  cpsa: '12345',
  firstName: 'Jane',
  lastName: 'Smith',
  specialtyCode: 'GP',
  specialtyDescription: 'General Practice',
  city: 'Calgary',
  facilityName: 'Smith Clinic',
  phone: '403-555-1234',
  fax: '403-555-5678',
  isActive: true,
};

const SHARED_GUIDANCE_LIST = [
  {
    guidanceId: 'guid-1',
    category: 'SOMB_INTERPRETATION',
    title: 'Complex Visit Billing',
    content: 'When billing for a complex office visit...',
    applicableHscCodes: ['03.04A', '03.05A'],
    applicableSpecialties: ['GP'],
    sourceReference: 'SOMB 2026 S4.2',
    sourceUrl: null,
    sortOrder: 1,
    isActive: true,
  },
];

const SHARED_GUIDANCE_DETAIL = {
  guidanceId: 'guid-1',
  category: 'SOMB_INTERPRETATION',
  title: 'Complex Visit Billing',
  content: 'When billing for a complex office visit...',
  applicableHscCodes: ['03.04A', '03.05A'],
  applicableSpecialties: ['GP'],
  sourceReference: 'SOMB 2026 S4.2',
  sourceUrl: null,
  sortOrder: 1,
  isActive: true,
};

const SHARED_PHN_FORMATS = [
  {
    formatId: 'fmt-ab',
    provinceCode: 'AB',
    provinceName: 'Alberta',
    formatPattern: '9999-99999',
    formatDescription: '9-digit numeric',
    examplePhn: '1234-56789',
    validationRegex: '^\\d{4}-?\\d{5}$',
    phnLength: 9,
    isReciprocal: false,
  },
  {
    formatId: 'fmt-bc',
    provinceCode: 'BC',
    provinceName: 'British Columbia',
    formatPattern: '9999 999 999',
    formatDescription: '10-digit starting with 9',
    examplePhn: '9876543210',
    validationRegex: '^9\\d{9}$',
    phnLength: 10,
    isReciprocal: true,
  },
];

const SHARED_RECIPROCAL_RULES = [
  {
    ruleId: 'rule-1',
    sourceProvince: 'BC',
    targetProvince: 'AB',
    billingMethod: 'RECIPROCAL',
    maxFeePercentage: '100',
    requiresPreApproval: false,
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    notes: null,
    isActive: true,
  },
];

const SHARED_ANESTHESIA_RULES = [
  {
    ruleId: 'anes-1',
    scenarioCode: 'GENERAL_ANESTHESIA',
    scenarioName: 'General Anesthesia',
    description: 'Standard general anesthesia procedure',
    baseUnits: 4,
    timeUnitMinutes: 15,
    calculationFormula: 'base_units + ceil(duration_min / 15)',
    modifierInteractions: { BMI_GT_40: 'add_2_units' },
    exampleCalculation: '4 + ceil(60/15) = 8 units',
    sortOrder: 1,
    isActive: true,
  },
];

const SHARED_ANESTHESIA_DETAIL = {
  ruleId: 'anes-1',
  scenarioCode: 'ANES01',
  scenarioName: 'General Anesthesia',
  description: 'Standard general anesthesia procedure',
  baseUnits: 4,
  timeUnitMinutes: 15,
  calculationFormula: 'base_units + ceil(duration_min / 15)',
  modifierInteractions: { BMI_GT_40: 'add_2_units' },
  exampleCalculation: '4 + ceil(60/15) = 8 units',
  sortOrder: 1,
  isActive: true,
};

const SHARED_BUNDLING_RULE = {
  ruleId: 'bund-1',
  codeA: '03.01A',
  codeB: '03.04J',
  relationship: 'BUNDLED',
  description: 'These codes are bundled',
  resolution: 'Bill the higher fee code only',
  overrideAllowed: true,
  sourceReference: 'SOMB 2026 S5.1',
  isActive: true,
};

const SHARED_BUNDLING_CONFLICTS = [
  {
    ruleId: 'bund-1',
    codeA: '03.01A',
    codeB: '03.04J',
    relationship: 'BUNDLED',
    description: 'These codes are bundled',
    resolution: 'Bill the higher fee code only',
    overrideAllowed: true,
    sourceReference: 'SOMB 2026 S5.1',
    isActive: true,
  },
];

const SHARED_JUSTIFICATION_TEMPLATES = [
  {
    templateId: 'tmpl-1',
    scenario: 'DUPLICATE_SERVICE',
    title: 'Medically Necessary Duplicate Service',
    templateText: 'Patient {patient_name} required a second {procedure} on {date} because {reason}.',
    placeholders: ['patient_name', 'procedure', 'date', 'reason'],
    sortOrder: 1,
    isActive: true,
  },
];

const SHARED_JUSTIFICATION_DETAIL = {
  templateId: 'tmpl-1',
  scenario: 'DUPLICATE_SERVICE',
  title: 'Medically Necessary Duplicate Service',
  templateText: 'Patient {patient_name} required a second {procedure} on {date} because {reason}.',
  placeholders: ['patient_name', 'procedure', 'date', 'reason'],
  sortOrder: 1,
  isActive: true,
};

// Version data used by ICD crosswalk resolution
const SHARED_VERSION = {
  versionId: 'dddd0000-0000-0000-0000-000000000001',
  dataSet: 'ICD_CROSSWALK',
  versionLabel: 'v2026.1',
  effectiveFrom: '2026-01-01',
  publishedAt: new Date('2026-01-01'),
  publishedBy: ADMIN1_USER_ID,
  recordsAdded: 5,
  recordsModified: 3,
  recordsDeprecated: 1,
  changeSummary: 'January 2026 ICD crosswalk update',
  isActive: true,
};

// Staging record -- shared between admins
const STAGING_ID = 'ssss0000-0000-0000-0000-000000000001';
const SHARED_STAGING_RECORD = {
  stagingId: STAGING_ID,
  dataSet: 'SOMB',
  uploadedBy: ADMIN1_USER_ID,
  status: 'diff_generated',
  fileHash: 'abc123',
  recordCount: 2,
  stagedData: [{ hsc_code: '03.01A', description: 'Updated', base_fee: '80.00', fee_type: 'fixed' }],
  diffResult: {
    added: [],
    modified: [{ hsc_code: '03.01A', _changes: [{ field: 'base_fee', old_value: '75.00', new_value: '80.00' }] }],
    deprecated: [],
    summary_stats: { added: 0, modified: 1, deprecated: 0 },
  },
  validationResult: { valid: true, errors: [] },
};

// ---------------------------------------------------------------------------
// Mock Reference Repository -- returns shared reference data
// ---------------------------------------------------------------------------

function createMockReferenceRepo() {
  return {
    // Version management
    findActiveVersion: vi.fn(async () => SHARED_VERSION),
    findVersionForDate: vi.fn(async () => SHARED_VERSION),
    findVersionByDate: vi.fn(async () => SHARED_VERSION),
    findVersionById: vi.fn(async () => SHARED_VERSION),
    listVersions: vi.fn(async () => [SHARED_VERSION]),
    createVersion: vi.fn(async () => SHARED_VERSION),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),
    // HSC (base reference -- not tested here but needed for route registration)
    searchHscCodes: vi.fn(async () => []),
    findHscByCode: vi.fn(async () => undefined),
    getHscByCode: vi.fn(async () => undefined),
    getHscCodesByVersion: vi.fn(async () => []),
    listHscByVersion: vi.fn(async () => []),
    bulkInsertHscCodes: vi.fn(async () => {}),
    // DI
    searchDiCodes: vi.fn(async () => []),
    findDiByCode: vi.fn(async () => undefined),
    getDiByCode: vi.fn(async () => undefined),
    getDiCodesByVersion: vi.fn(async () => []),
    bulkInsertDiCodes: vi.fn(async () => {}),
    // Modifiers
    findModifiersForHsc: vi.fn(async () => []),
    getModifiersForHsc: vi.fn(async () => []),
    findModifierByCode: vi.fn(async () => undefined),
    getModifierByCode: vi.fn(async () => undefined),
    listAllModifiers: vi.fn(async () => []),
    getModifiersByVersion: vi.fn(async () => []),
    bulkInsertModifiers: vi.fn(async () => {}),
    // Functional centres
    listFunctionalCentres: vi.fn(async () => []),
    findFunctionalCentre: vi.fn(async () => undefined),
    getFunctionalCentresByVersion: vi.fn(async () => []),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),
    // Explanatory codes
    findExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCodesByVersion: vi.fn(async () => []),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),
    // RRNP
    findRrnpRate: vi.fn(async () => undefined),
    getRrnpCommunity: vi.fn(async () => undefined),
    listRrnpCommunities: vi.fn(async () => []),
    getRrnpCommunitiesByVersion: vi.fn(async () => []),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),
    // PCPCM
    findPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasketsByVersion: vi.fn(async () => []),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),
    // Holidays
    listHolidaysByYear: vi.fn(async () => []),
    listHolidays: vi.fn(async () => []),
    isHoliday: vi.fn(async () => false),
    getHolidayById: vi.fn(async () => undefined),
    createHoliday: vi.fn(async () => ({})),
    updateHoliday: vi.fn(async () => ({})),
    deleteHoliday: vi.fn(async () => {}),
    // Governing rules
    findGoverningRules: vi.fn(async () => []),
    findRulesForContext: vi.fn(async () => []),
    findRuleById: vi.fn(async () => undefined),
    getGoverningRuleById: vi.fn(async () => undefined),
    getGoverningRulesByVersion: vi.fn(async () => []),
    listRulesByCategory: vi.fn(async () => []),
    bulkInsertGoverningRules: vi.fn(async () => {}),
    bulkInsertRules: vi.fn(async () => {}),
    // Staging
    createStagingRecord: vi.fn(async () => ({ stagingId: STAGING_ID })),
    createStagingEntry: vi.fn(async () => ({})),
    findStagingById: vi.fn(async () => SHARED_STAGING_RECORD),
    findStagingEntry: vi.fn(async () => SHARED_STAGING_RECORD),
    updateStagingStatus: vi.fn(async () => {}),
    deleteStagingRecord: vi.fn(async () => {}),
    deleteStagingEntry: vi.fn(async () => {}),
    listStagingByDataSet: vi.fn(async () => []),
    // Favourites / changes
    getHscFavourites: vi.fn(async () => []),
    findVersionByVersionId: vi.fn(async () => SHARED_VERSION),
    getChangeSummaries: vi.fn(async () => []),
    getChangeDetails: vi.fn(async () => []),
    // WCB
    searchWcbCodes: vi.fn(async () => []),
    findWcbByCode: vi.fn(async () => undefined),
    bulkInsertWcbCodes: vi.fn(async () => {}),
    // -----------------------------------------------------------------------
    // Extension repo methods -- return SHARED data regardless of caller
    // -----------------------------------------------------------------------
    getIcdCrosswalkByIcd10: vi.fn(async () => SHARED_ICD_CROSSWALK_RESULTS),
    searchIcdCrosswalk: vi.fn(async () => SHARED_ICD_CROSSWALK_RESULTS),
    bulkInsertIcdCrosswalk: vi.fn(async () => {}),
    searchProviderRegistry: vi.fn(async () => SHARED_PROVIDER_SEARCH_RESULTS),
    getProviderByCpsa: vi.fn(async () => SHARED_PROVIDER_DETAIL),
    bulkUpsertProviderRegistry: vi.fn(async () => {}),
    listBillingGuidance: vi.fn(async () => SHARED_GUIDANCE_LIST),
    searchBillingGuidance: vi.fn(async () => SHARED_GUIDANCE_LIST),
    getBillingGuidanceById: vi.fn(async () => SHARED_GUIDANCE_DETAIL),
    listProvincialPhnFormats: vi.fn(async () => SHARED_PHN_FORMATS),
    getReciprocalRules: vi.fn(async () => SHARED_RECIPROCAL_RULES),
    listAnesthesiaRules: vi.fn(async () => SHARED_ANESTHESIA_RULES),
    getAnesthesiaRuleByScenario: vi.fn(async () => SHARED_ANESTHESIA_DETAIL),
    getBundlingRuleForPair: vi.fn(async () => SHARED_BUNDLING_RULE),
    checkBundlingConflicts: vi.fn(async () => SHARED_BUNDLING_CONFLICTS),
    listJustificationTemplates: vi.fn(async () => SHARED_JUSTIFICATION_TEMPLATES),
    getJustificationTemplate: vi.fn(async () => SHARED_JUSTIFICATION_DETAIL),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockReferenceRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();
  mockRepo = createMockReferenceRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps = {
    serviceDeps: {
      repo: mockRepo,
      auditLog: createMockAuditRepo(),
      eventEmitter: createMockEvents(),
    },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(referenceRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers: Seed users and sessions
// ---------------------------------------------------------------------------

function seedAllUsers() {
  users = [];
  sessions = [];

  // Physician 1
  users.push({
    userId: PHYSICIAN1_USER_ID,
    email: 'physician1@example.com',
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: PHYSICIAN1_SESSION_ID,
    userId: PHYSICIAN1_USER_ID,
    tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Physician 2
  users.push({
    userId: PHYSICIAN2_USER_ID,
    email: 'physician2@example.com',
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: PHYSICIAN2_SESSION_ID,
    userId: PHYSICIAN2_USER_ID,
    tokenHash: PHYSICIAN2_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Admin 1
  users.push({
    userId: ADMIN1_USER_ID,
    email: 'admin1@meritum.ca',
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN1_SESSION_ID,
    userId: ADMIN1_USER_ID,
    tokenHash: ADMIN1_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Admin 2
  users.push({
    userId: ADMIN2_USER_ID,
    email: 'admin2@meritum.ca',
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN2_SESSION_ID,
    userId: ADMIN2_USER_ID,
    tokenHash: ADMIN2_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// Cookie helpers
function physician1Cookie(): string { return `session=${PHYSICIAN1_SESSION_TOKEN}`; }
function physician2Cookie(): string { return `session=${PHYSICIAN2_SESSION_TOKEN}`; }
function admin1Cookie(): string { return `session=${ADMIN1_SESSION_TOKEN}`; }
function admin2Cookie(): string { return `session=${ADMIN2_SESSION_TOKEN}`; }

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

describe('Reference Data Extensions Tenant Scoping (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedAllUsers();
    vi.clearAllMocks();
    // Re-assign default mock implementations after clearAllMocks
    mockRepo.findActiveVersion.mockResolvedValue(SHARED_VERSION);
    mockRepo.findVersionForDate.mockResolvedValue(SHARED_VERSION);
    mockRepo.findVersionByVersionId.mockResolvedValue(SHARED_VERSION);
    mockRepo.listVersions.mockResolvedValue([SHARED_VERSION]);
    mockRepo.getIcdCrosswalkByIcd10.mockResolvedValue(SHARED_ICD_CROSSWALK_RESULTS);
    mockRepo.searchIcdCrosswalk.mockResolvedValue(SHARED_ICD_CROSSWALK_RESULTS);
    mockRepo.searchProviderRegistry.mockResolvedValue(SHARED_PROVIDER_SEARCH_RESULTS);
    mockRepo.getProviderByCpsa.mockResolvedValue(SHARED_PROVIDER_DETAIL);
    mockRepo.listBillingGuidance.mockResolvedValue(SHARED_GUIDANCE_LIST);
    mockRepo.searchBillingGuidance.mockResolvedValue(SHARED_GUIDANCE_LIST);
    mockRepo.getBillingGuidanceById.mockResolvedValue(SHARED_GUIDANCE_DETAIL);
    mockRepo.listProvincialPhnFormats.mockResolvedValue(SHARED_PHN_FORMATS);
    mockRepo.getReciprocalRules.mockResolvedValue(SHARED_RECIPROCAL_RULES);
    mockRepo.listAnesthesiaRules.mockResolvedValue(SHARED_ANESTHESIA_RULES);
    mockRepo.getAnesthesiaRuleByScenario.mockResolvedValue(SHARED_ANESTHESIA_DETAIL);
    mockRepo.getBundlingRuleForPair.mockResolvedValue(SHARED_BUNDLING_RULE);
    mockRepo.checkBundlingConflicts.mockResolvedValue(SHARED_BUNDLING_CONFLICTS);
    mockRepo.listJustificationTemplates.mockResolvedValue(SHARED_JUSTIFICATION_TEMPLATES);
    mockRepo.getJustificationTemplate.mockResolvedValue(SHARED_JUSTIFICATION_DETAIL);
    mockRepo.findStagingById.mockResolvedValue(SHARED_STAGING_RECORD);
    mockRepo.findStagingEntry.mockResolvedValue(SHARED_STAGING_RECORD);
  });

  // =========================================================================
  // Shared reference data: both physicians see identical results
  // =========================================================================

  describe('Shared reference data: both physicians see identical results', () => {
    it('ICD crosswalk search returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=J06',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=J06',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('ICD crosswalk detail returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk/J06.9',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk/J06.9',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('provider registry search returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('provider registry detail returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/12345',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/12345',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('billing guidance list returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('billing guidance detail returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${DUMMY_UUID}`,
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${DUMMY_UUID}`,
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('provincial PHN formats returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('reciprocal billing rules returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/BC',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/BC',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('anesthesia rules list returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('anesthesia rule detail returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules/ANES01',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules/ANES01',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('anesthesia calculate returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physician1Cookie() },
        payload: { scenario_code: 'ANES01', time_minutes: 60 },
      });

      const res2 = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physician2Cookie() },
        payload: { scenario_code: 'ANES01', time_minutes: 60 },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('bundling pair lookup returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('bundling conflict check returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physician1Cookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      const res2 = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physician2Cookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('justification templates list returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('justification template detail returns identical results for physician1 and physician2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${DUMMY_UUID}`,
        headers: { cookie: physician1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${DUMMY_UUID}`,
        headers: { cookie: physician2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });
  });

  // =========================================================================
  // Query parameters cannot inject provider_id or cross-tenant context
  // =========================================================================

  describe('Query parameters cannot inject provider_id or cross-tenant context', () => {
    it('ICD crosswalk search ignores provider_id query parameter', async () => {
      const resNormal = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=J06',
        headers: { cookie: physician1Cookie() },
      });

      const resInjected = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/icd-crosswalk?q=J06&provider_id=${PHYSICIAN2_USER_ID}`,
        headers: { cookie: physician1Cookie() },
      });

      // Both should succeed or both should fail with same status
      // The provider_id param must be ignored (not cause different results)
      if (resNormal.statusCode < 400 && resInjected.statusCode < 400) {
        const bodyNormal = JSON.parse(resNormal.body);
        const bodyInjected = JSON.parse(resInjected.body);
        expect(bodyNormal.data).toEqual(bodyInjected.data);
      }
      // If injected param causes validation error, that is also acceptable
      // (strict schema rejects unknown params)
    });

    it('provider registry search ignores user_id query parameter', async () => {
      const resNormal = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physician1Cookie() },
      });

      const resInjected = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/providers/search?q=Smith&user_id=${PHYSICIAN2_USER_ID}`,
        headers: { cookie: physician1Cookie() },
      });

      if (resNormal.statusCode < 400 && resInjected.statusCode < 400) {
        const bodyNormal = JSON.parse(resNormal.body);
        const bodyInjected = JSON.parse(resInjected.body);
        expect(bodyNormal.data).toEqual(bodyInjected.data);
      }
    });

    it('billing guidance list ignores provider_id query parameter', async () => {
      const resNormal = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physician1Cookie() },
      });

      const resInjected = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance?provider_id=${PHYSICIAN2_USER_ID}`,
        headers: { cookie: physician1Cookie() },
      });

      if (resNormal.statusCode < 400 && resInjected.statusCode < 400) {
        const bodyNormal = JSON.parse(resNormal.body);
        const bodyInjected = JSON.parse(resInjected.body);
        expect(bodyNormal.data).toEqual(bodyInjected.data);
      }
    });

    it('anesthesia calculate ignores provider_id in request body', async () => {
      const resNormal = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physician1Cookie() },
        payload: { scenario_code: 'ANES01', time_minutes: 60 },
      });

      const resInjected = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physician1Cookie() },
        payload: { scenario_code: 'ANES01', time_minutes: 60, provider_id: PHYSICIAN2_USER_ID },
      });

      // Either both succeed with same data, or the injected one is rejected
      // by schema validation (unknown key). Either outcome is safe.
      if (resNormal.statusCode < 400 && resInjected.statusCode < 400) {
        const bodyNormal = JSON.parse(resNormal.body);
        const bodyInjected = JSON.parse(resInjected.body);
        expect(bodyNormal.data).toEqual(bodyInjected.data);
      }
    });

    it('bundling check ignores user_id in request body', async () => {
      const resNormal = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physician1Cookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      const resInjected = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physician1Cookie() },
        payload: { codes: ['03.01A', '03.04J'], user_id: PHYSICIAN2_USER_ID },
      });

      if (resNormal.statusCode < 400 && resInjected.statusCode < 400) {
        const bodyNormal = JSON.parse(resNormal.body);
        const bodyInjected = JSON.parse(resInjected.body);
        expect(bodyNormal.data).toEqual(bodyInjected.data);
      }
    });

    it('justification templates list ignores physician_id query parameter', async () => {
      const resNormal = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physician1Cookie() },
      });

      const resInjected = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates?physician_id=${PHYSICIAN2_USER_ID}`,
        headers: { cookie: physician1Cookie() },
      });

      if (resNormal.statusCode < 400 && resInjected.statusCode < 400) {
        const bodyNormal = JSON.parse(resNormal.body);
        const bodyInjected = JSON.parse(resInjected.body);
        expect(bodyNormal.data).toEqual(bodyInjected.data);
      }
    });
  });

  // =========================================================================
  // Admin endpoints are not influenced by physician context
  // =========================================================================

  describe('Admin endpoints are not influenced by physician context', () => {
    it('version list returns identical data for admin1 and admin2', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/ref/SOMB/versions',
        headers: { cookie: admin1Cookie() },
      });

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/ref/SOMB/versions',
        headers: { cookie: admin2Cookie() },
      });

      expect(res1.statusCode).toBeLessThan(400);
      expect(res2.statusCode).toBeLessThan(400);

      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.data).toEqual(body2.data);
    });

    it('staging diff created by admin1 is visible to admin2 (collaborative)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/diff`,
        headers: { cookie: admin2Cookie() },
      });

      // Admin2 should be able to see staging created by admin1
      // This is NOT a security violation -- admins collaborate on reference data
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(404);
    });

    it('staging record created by admin1 can be published by admin2', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`,
        headers: { cookie: admin2Cookie() },
        payload: {
          version_label: 'v2026.2',
          effective_from: '2026-03-01',
          change_summary: 'Published by admin2',
        },
      });

      // Admin2 should be able to publish admin1's staging
      expect(res.statusCode).not.toBe(403);
    });

    it('admin holiday creation is not scoped to a specific admin', async () => {
      const res1 = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: admin1Cookie() },
        payload: { name: 'Test Holiday', date: '2026-12-25', jurisdiction: 'provincial' },
      });

      const res2 = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: admin2Cookie() },
        payload: { name: 'Test Holiday', date: '2026-12-25', jurisdiction: 'provincial' },
      });

      // Both admins should be able to create holidays
      expect(res1.statusCode).not.toBe(403);
      expect(res2.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // No physician-identifying information in shared reference responses
  // =========================================================================

  describe('No physician-identifying information in shared reference responses', () => {
    it('ICD crosswalk response does not contain provider_id or userId', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=J06',
        headers: { cookie: physician1Cookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain('userId');
    });

    it('provider registry response does not contain calling physician user ID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physician1Cookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
    });

    it('billing guidance response does not contain physician-specific data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physician1Cookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain('provider_id');
    });

    it('anesthesia rules response does not contain physician-specific data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physician1Cookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain('provider_id');
    });

    it('bundling rules response does not contain physician-specific data', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physician1Cookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).toBeLessThan(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain('provider_id');
    });

    it('justification templates response does not contain physician-specific data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physician1Cookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain('provider_id');
    });

    it('provincial PHN formats response does not contain physician-specific data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physician1Cookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain('provider_id');
    });

    it('reciprocal rules response does not contain physician-specific data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/BC',
        headers: { cookie: physician1Cookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain('provider_id');
    });
  });
});
