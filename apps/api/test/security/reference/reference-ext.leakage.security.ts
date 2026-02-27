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
// Fixed test users/sessions
// ---------------------------------------------------------------------------

// Physician user (ACTIVE subscription)
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = 'eeee0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'eeee0000-0000-0000-0000-000000000011';

// Admin user
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_USER_ID = 'eeee0000-0000-0000-0000-000000000002';
const ADMIN_SESSION_ID = 'eeee0000-0000-0000-0000-000000000012';

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
// Version and staging data stores
// ---------------------------------------------------------------------------

const SOMB_VERSION_V1_ID = '11111111-1111-1111-1111-111111111111';
const SOMB_VERSION_V2_ID = '22222222-2222-2222-2222-222222222222';
const DI_VERSION_ID = '44444444-4444-4444-4444-444444444444';
const MODIFIERS_VERSION_ID = '55555555-5555-5555-5555-555555555555';
const RULES_VERSION_ID = '66666666-6666-6666-6666-666666666666';
const FC_VERSION_ID = '77777777-7777-7777-7777-777777777777';
const STAGING_ID = '88888888-8888-8888-8888-888888888888';
const EXPL_VERSION_ID = '99999999-9999-9999-9999-999999999999';

// Version store for all datasets
const versionStore: Record<string, Array<{
  versionId: string;
  dataSet: string;
  versionLabel: string;
  effectiveFrom: string;
  effectiveTo: string | null;
  isActive: boolean;
  publishedBy: string;
  publishedAt: Date;
  recordsAdded: number;
  recordsModified: number;
  recordsDeprecated: number;
  changeSummary: string | null;
  sourceDocument: string | null;
}>> = {};

// HSC code store
const hscStore: Array<{
  hscCode: string;
  versionId: string;
  description: string;
  baseFee: string | null;
  feeType: string;
  helpText: string | null;
  effectiveTo: string | null;
  specialtyRestrictions: string[];
  facilityRestrictions: string[];
  modifierEligibility: string[];
  combinationGroup: string | null;
  surchargeEligible: boolean;
  pcpcmBasket: string;
  maxPerDay: number | null;
  maxPerVisit: number | null;
  requiresReferral: boolean;
}> = [];

// DI code store
const diStore: Array<{
  diCode: string;
  versionId: string;
  description: string;
  category: string;
  subcategory: string | null;
  qualifiesSurcharge: boolean;
  qualifiesBcp: boolean;
  commonInSpecialty: string[];
  helpText: string | null;
}> = [];

// Staging store
const stagingStore: Array<{
  stagingId: string;
  dataSet: string;
  uploadedBy: string;
  fileHash: string;
  recordCount: number;
  stagedData: unknown[];
  status: string;
  validationResult: unknown;
  diffResult: unknown;
}> = [];

// Rules store
const rulesStore: Array<{
  ruleId: string;
  versionId: string;
  ruleName: string;
  ruleCategory: string;
  description: string;
  ruleLogic: Record<string, unknown>;
  severity: string;
  errorMessage: string;
  helpText: string | null;
  sourceReference: string | null;
  sourceUrl: string | null;
}> = [];

// Modifier store
const modifierStore: Array<{
  modifierCode: string;
  versionId: string;
  name: string;
  description: string;
  type: string;
  calculationMethod: string;
  calculationParams: Record<string, unknown>;
  helpText: string | null;
  combinableWith: string[];
  exclusiveWith: string[];
  governingRuleReference: string | null;
  requiresTimeDocumentation: boolean;
  requiresFacility: boolean;
  applicableHscFilter: unknown;
}> = [];

// Holiday store
const holidayStore: Array<{
  holidayId: string;
  date: string;
  name: string;
  jurisdiction: string;
  affectsBillingPremiums: boolean;
  year: number;
}> = [];

// FC store
const fcStore: Array<{
  code: string;
  versionId: string;
  name: string;
  facilityType: string;
  active: boolean;
}> = [];

// Explanatory code store
const explStore: Array<{
  explCode: string;
  versionId: string;
  description: string;
  severity: string;
  commonCause: string | null;
  suggestedAction: string | null;
  helpText: string | null;
}> = [];

// ---------------------------------------------------------------------------
// Stub reference repository with controlled data
// ---------------------------------------------------------------------------

function createStubReferenceRepo() {
  return {
    findActiveVersion: vi.fn(async (dataSet: string) => {
      const versions = versionStore[dataSet] ?? [];
      return versions.find((v) => v.isActive);
    }),
    findVersionForDate: vi.fn(async (dataSet: string, date: Date) => {
      const dateStr = date.toISOString().split('T')[0];
      const versions = versionStore[dataSet] ?? [];
      return versions.find(
        (v) =>
          v.effectiveFrom <= dateStr &&
          (v.effectiveTo === null || v.effectiveTo > dateStr),
      );
    }),
    findVersionById: vi.fn(async (versionId: string) => {
      for (const ds of Object.values(versionStore)) {
        const found = ds.find((v) => v.versionId === versionId);
        if (found) return found;
      }
      return undefined;
    }),
    listVersions: vi.fn(async (dataSet: string) => {
      return versionStore[dataSet] ?? [];
    }),
    createVersion: vi.fn(async (data: Record<string, unknown>) => {
      return { versionId: 'new-version-id', ...data };
    }),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),

    // HSC
    searchHscCodes: vi.fn(async (query: string, versionId: string, _filters: unknown, limit: number) => {
      return hscStore
        .filter((c) => c.versionId === versionId)
        .filter((c) => c.hscCode.includes(query) || c.description.toLowerCase().includes(query.toLowerCase()))
        .slice(0, limit);
    }),
    findHscByCode: vi.fn(async (hscCode: string, versionId: string) => {
      return hscStore.find((c) => c.hscCode === hscCode && c.versionId === versionId);
    }),
    listHscByVersion: vi.fn(async (versionId: string, pagination: { limit: number; offset: number }) => {
      const data = hscStore.filter((c) => c.versionId === versionId);
      return { data: data.slice(pagination.offset, pagination.offset + pagination.limit), total: data.length };
    }),
    findModifiersForHsc: vi.fn(async (_hscCode: string, versionId: string) => {
      return modifierStore.filter((m) => m.versionId === versionId);
    }),
    bulkInsertHscCodes: vi.fn(async () => {}),
    getHscByCode: vi.fn(async () => undefined),
    getHscCodesByVersion: vi.fn(async () => []),

    // DI
    searchDiCodes: vi.fn(async (query: string, versionId: string, _filters: unknown, limit: number) => {
      return diStore
        .filter((c) => c.versionId === versionId)
        .filter((c) => c.diCode.includes(query) || c.description.toLowerCase().includes(query.toLowerCase()))
        .slice(0, limit);
    }),
    findDiByCode: vi.fn(async (diCode: string, versionId: string) => {
      return diStore.find((c) => c.diCode === diCode && c.versionId === versionId);
    }),
    getDiByCode: vi.fn(async () => undefined),
    getDiCodesByVersion: vi.fn(async () => []),
    bulkInsertDiCodes: vi.fn(async () => {}),

    // Modifiers
    getModifierByCode: vi.fn(async () => undefined),
    findModifierByCode: vi.fn(async (code: string, versionId: string) => {
      return modifierStore.find((m) => m.modifierCode === code && m.versionId === versionId);
    }),
    listAllModifiers: vi.fn(async (versionId: string) => {
      return modifierStore.filter((m) => m.versionId === versionId);
    }),
    getModifiersForHsc: vi.fn(async () => []),
    getModifiersByVersion: vi.fn(async () => []),
    bulkInsertModifiers: vi.fn(async () => {}),

    // Functional centres
    listFunctionalCentres: vi.fn(async (versionId: string, _facilityType?: string) => {
      return fcStore.filter((f) => f.versionId === versionId);
    }),
    findFunctionalCentre: vi.fn(async (code: string, versionId: string) => {
      return fcStore.find((f) => f.code === code && f.versionId === versionId);
    }),
    getFunctionalCentresByVersion: vi.fn(async () => []),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),

    // Explanatory codes
    getExplanatoryCode: vi.fn(async () => undefined),
    findExplanatoryCode: vi.fn(async (code: string, versionId: string) => {
      return explStore.find((e) => e.explCode === code && e.versionId === versionId);
    }),
    getExplanatoryCodesByVersion: vi.fn(async () => []),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),

    // RRNP
    getRrnpCommunity: vi.fn(async () => undefined),
    findRrnpRate: vi.fn(async () => undefined),
    getRrnpCommunitiesByVersion: vi.fn(async () => []),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),

    // PCPCM
    getPcpcmBasket: vi.fn(async () => undefined),
    findPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasketsByVersion: vi.fn(async () => []),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),

    // Holidays
    listHolidaysByYear: vi.fn(async (year: number) => {
      return holidayStore.filter((h) => h.year === year);
    }),
    listHolidays: vi.fn(async () => holidayStore),
    isHoliday: vi.fn(async (date: Date) => {
      const dateStr = date.toISOString().split('T')[0];
      const found = holidayStore.find((h) => h.date === dateStr);
      return { is_holiday: !!found, holiday_name: found?.name };
    }),
    getHolidayById: vi.fn(async () => undefined),
    createHoliday: vi.fn(async (data: Record<string, unknown>) => ({
      holidayId: 'new-holiday-id',
      ...data,
    })),
    updateHoliday: vi.fn(async () => ({})),
    deleteHoliday: vi.fn(async () => {}),

    // Governing rules
    findGoverningRules: vi.fn(async () => []),
    findRulesForContext: vi.fn(async (_hscCodes: string[], _diCode: string | null, _facilityCode: string | null, versionId: string) => {
      return rulesStore.filter((r) => r.versionId === versionId);
    }),
    findRuleById: vi.fn(async (ruleId: string, versionId: string) => {
      return rulesStore.find((r) => r.ruleId === ruleId && r.versionId === versionId);
    }),
    getGoverningRuleById: vi.fn(async () => undefined),
    getGoverningRulesByVersion: vi.fn(async () => []),
    bulkInsertGoverningRules: vi.fn(async () => {}),
    bulkInsertRules: vi.fn(async () => {}),

    // Staging
    createStagingRecord: vi.fn(async (data: Record<string, unknown>) => {
      const entry = {
        stagingId: STAGING_ID,
        dataSet: data.dataSet as string,
        uploadedBy: data.uploadedBy as string,
        fileHash: data.fileHash as string,
        recordCount: data.recordCount as number,
        stagedData: data.stagedData as unknown[],
        status: 'uploaded',
        validationResult: null,
        diffResult: null,
      };
      stagingStore.push(entry);
      return entry;
    }),
    findStagingById: vi.fn(async (stagingId: string) => {
      return stagingStore.find((s) => s.stagingId === stagingId);
    }),
    findStagingEntry: vi.fn(async () => undefined),
    createStagingEntry: vi.fn(async () => ({})),
    updateStagingStatus: vi.fn(async (stagingId: string, status: string, extra?: Record<string, unknown>) => {
      const entry = stagingStore.find((s) => s.stagingId === stagingId);
      if (entry) {
        entry.status = status;
        if (extra?.validation_result) entry.validationResult = extra.validation_result;
        if (extra?.diff_result) entry.diffResult = extra.diff_result;
      }
    }),
    deleteStagingRecord: vi.fn(async (stagingId: string) => {
      const idx = stagingStore.findIndex((s) => s.stagingId === stagingId);
      if (idx >= 0) stagingStore.splice(idx, 1);
    }),
    deleteStagingEntry: vi.fn(async () => {}),
    listStagingByDataSet: vi.fn(async () => []),
    getHscFavourites: vi.fn(async () => []),
    findVersionByVersionId: vi.fn(async () => undefined),
    getChangeSummaries: vi.fn(async () => []),
    getChangeDetails: vi.fn(async () => []),

    // Extension repo methods
    getIcdCrosswalkByIcd10: vi.fn(async () => []),
    searchIcdCrosswalk: vi.fn(async () => []),
    bulkInsertIcdCrosswalk: vi.fn(async () => {}),
    searchProviderRegistry: vi.fn(async () => []),
    getProviderByCpsa: vi.fn(async () => undefined),
    bulkUpsertProviderRegistry: vi.fn(async () => {}),
    listBillingGuidance: vi.fn(async () => []),
    searchBillingGuidance: vi.fn(async () => []),
    getBillingGuidanceById: vi.fn(async () => undefined),
    listProvincialPhnFormats: vi.fn(async () => []),
    getReciprocalRules: vi.fn(async () => []),
    listAnesthesiaRules: vi.fn(async () => []),
    getAnesthesiaRuleByScenario: vi.fn(async () => undefined),
    getBundlingRuleForPair: vi.fn(async () => undefined),
    checkBundlingConflicts: vi.fn(async () => []),
    listJustificationTemplates: vi.fn(async () => []),
    getJustificationTemplate: vi.fn(async () => undefined),

    // WCB
    searchWcbCodes: vi.fn(async () => []),
    findWcbByCode: vi.fn(async () => undefined),
    bulkInsertWcbCodes: vi.fn(async () => {}),
    listRulesByCategory: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Test app builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;
let stubRepo: ReturnType<typeof createStubReferenceRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();
  stubRepo = createStubReferenceRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps = {
    serviceDeps: {
      repo: stubRepo,
      auditLog: { log: vi.fn(async () => {}) },
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
// Helpers
// ---------------------------------------------------------------------------

function physicianCookie(): string {
  return `session=${PHYSICIAN_SESSION_TOKEN}`;
}

function adminCookie(): string {
  return `session=${ADMIN_SESSION_TOKEN}`;
}

function seedUsers() {
  users = [];
  sessions = [];

  // Physician
  users.push({
    userId: PHYSICIAN_USER_ID,
    email: 'physician@example.com',
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: PHYSICIAN_SESSION_ID,
    userId: PHYSICIAN_USER_ID,
    tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Admin
  users.push({
    userId: ADMIN_USER_ID,
    email: 'admin@example.com',
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN_SESSION_ID,
    userId: ADMIN_USER_ID,
    tokenHash: ADMIN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function seedReferenceData() {
  // Clear stores
  for (const key of Object.keys(versionStore)) delete versionStore[key];
  hscStore.length = 0;
  diStore.length = 0;
  stagingStore.length = 0;
  rulesStore.length = 0;
  modifierStore.length = 0;
  holidayStore.length = 0;
  fcStore.length = 0;
  explStore.length = 0;

  // SOMB versions
  versionStore['SOMB'] = [
    {
      versionId: SOMB_VERSION_V1_ID,
      dataSet: 'SOMB',
      versionLabel: 'SOMB 2025-Q2',
      effectiveFrom: '2025-04-01',
      effectiveTo: '2025-10-01',
      isActive: false,
      publishedBy: ADMIN_USER_ID,
      publishedAt: new Date('2025-03-15'),
      recordsAdded: 10,
      recordsModified: 5,
      recordsDeprecated: 2,
      changeSummary: 'Q2 update',
      sourceDocument: null,
    },
    {
      versionId: SOMB_VERSION_V2_ID,
      dataSet: 'SOMB',
      versionLabel: 'SOMB 2025-Q4',
      effectiveFrom: '2025-10-01',
      effectiveTo: null,
      isActive: true,
      publishedBy: ADMIN_USER_ID,
      publishedAt: new Date('2025-09-20'),
      recordsAdded: 8,
      recordsModified: 3,
      recordsDeprecated: 1,
      changeSummary: 'Q4 update',
      sourceDocument: null,
    },
  ];

  // HSC codes in active version
  hscStore.push({
    hscCode: '03.01A',
    versionId: SOMB_VERSION_V2_ID,
    description: 'Office Visit - Complete Assessment',
    baseFee: '80.00',
    feeType: 'fixed',
    helpText: 'V2 version of office visit',
    effectiveTo: null,
    specialtyRestrictions: [],
    facilityRestrictions: [],
    modifierEligibility: [],
    combinationGroup: null,
    surchargeEligible: true,
    pcpcmBasket: 'in_basket',
    maxPerDay: 1,
    maxPerVisit: 1,
    requiresReferral: false,
  });

  // DI codes
  versionStore['DI_CODES'] = [{
    versionId: DI_VERSION_ID,
    dataSet: 'DI_CODES',
    versionLabel: 'DI 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 100,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  // Modifiers
  versionStore['MODIFIERS'] = [{
    versionId: MODIFIERS_VERSION_ID,
    dataSet: 'MODIFIERS',
    versionLabel: 'Modifiers 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 5,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  // Governing rules
  versionStore['GOVERNING_RULES'] = [{
    versionId: RULES_VERSION_ID,
    dataSet: 'GOVERNING_RULES',
    versionLabel: 'Rules 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 10,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  // Functional centres
  versionStore['FUNCTIONAL_CENTRES'] = [{
    versionId: FC_VERSION_ID,
    dataSet: 'FUNCTIONAL_CENTRES',
    versionLabel: 'FC 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 5,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  // Explanatory codes
  versionStore['EXPLANATORY_CODES'] = [{
    versionId: EXPL_VERSION_ID,
    dataSet: 'EXPLANATORY_CODES',
    versionLabel: 'ExplCodes 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 10,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  // Remaining datasets with empty version arrays
  for (const ds of ['WCB', 'RRNP', 'PCPCM']) {
    if (!versionStore[ds]) versionStore[ds] = [];
  }
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Extension — Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
    seedReferenceData();
    vi.clearAllMocks();
    // Re-bind all mock implementations after clearAllMocks
    rebindMocks();
  });

  function rebindMocks() {
    stubRepo.findActiveVersion.mockImplementation(async (dataSet: string) => {
      const versions = versionStore[dataSet] ?? [];
      return versions.find((v) => v.isActive);
    });
    stubRepo.findVersionForDate.mockImplementation(async (dataSet: string, date: Date) => {
      const dateStr = date.toISOString().split('T')[0];
      const versions = versionStore[dataSet] ?? [];
      return versions.find(
        (v) =>
          v.effectiveFrom <= dateStr &&
          (v.effectiveTo === null || v.effectiveTo > dateStr),
      );
    });
    stubRepo.listVersions.mockImplementation(async (dataSet: string) => {
      return versionStore[dataSet] ?? [];
    });
    stubRepo.searchHscCodes.mockImplementation(async (query: string, versionId: string, _filters: unknown, limit: number) => {
      return hscStore
        .filter((c) => c.versionId === versionId)
        .filter((c) => c.hscCode.includes(query) || c.description.toLowerCase().includes(query.toLowerCase()))
        .slice(0, limit);
    });
    stubRepo.findHscByCode.mockImplementation(async (hscCode: string, versionId: string) => {
      return hscStore.find((c) => c.hscCode === hscCode && c.versionId === versionId);
    });
    stubRepo.listHscByVersion.mockImplementation(async (versionId: string, pagination: { limit: number; offset: number }) => {
      const data = hscStore.filter((c) => c.versionId === versionId);
      return { data: data.slice(pagination.offset, pagination.offset + pagination.limit), total: data.length };
    });
    stubRepo.searchDiCodes.mockImplementation(async (query: string, versionId: string, _filters: unknown, limit: number) => {
      return diStore
        .filter((c) => c.versionId === versionId)
        .filter((c) => c.diCode.includes(query) || c.description.toLowerCase().includes(query.toLowerCase()))
        .slice(0, limit);
    });
    stubRepo.findDiByCode.mockImplementation(async (diCode: string, versionId: string) => {
      return diStore.find((c) => c.diCode === diCode && c.versionId === versionId);
    });
    stubRepo.findRulesForContext.mockImplementation(async (_hscCodes: string[], _diCode: string | null, _facilityCode: string | null, versionId: string) => {
      return rulesStore.filter((r) => r.versionId === versionId);
    });
    stubRepo.findRuleById.mockImplementation(async (ruleId: string, versionId: string) => {
      return rulesStore.find((r) => r.ruleId === ruleId && r.versionId === versionId);
    });
    stubRepo.findModifiersForHsc.mockImplementation(async (_hscCode: string, versionId: string) => {
      return modifierStore.filter((m) => m.versionId === versionId);
    });
    stubRepo.listAllModifiers.mockImplementation(async (versionId: string) => {
      return modifierStore.filter((m) => m.versionId === versionId);
    });
    stubRepo.findModifierByCode.mockImplementation(async (code: string, versionId: string) => {
      return modifierStore.find((m) => m.modifierCode === code && m.versionId === versionId);
    });
    stubRepo.listFunctionalCentres.mockImplementation(async (versionId: string) => {
      return fcStore.filter((f) => f.versionId === versionId);
    });
    stubRepo.findFunctionalCentre.mockImplementation(async (code: string, versionId: string) => {
      return fcStore.find((f) => f.code === code && f.versionId === versionId);
    });
    stubRepo.findExplanatoryCode.mockImplementation(async (code: string, versionId: string) => {
      return explStore.find((e) => e.explCode === code && e.versionId === versionId);
    });
    stubRepo.listHolidaysByYear.mockImplementation(async (year: number) => {
      return holidayStore.filter((h) => h.year === year);
    });
    stubRepo.isHoliday.mockImplementation(async (date: Date) => {
      const dateStr = date.toISOString().split('T')[0];
      const found = holidayStore.find((h) => h.date === dateStr);
      return { is_holiday: !!found, holiday_name: found?.name };
    });
    stubRepo.findStagingById.mockImplementation(async (stagingId: string) => {
      return stagingStore.find((s) => s.stagingId === stagingId);
    });
    stubRepo.createStagingRecord.mockImplementation(async (data: Record<string, unknown>) => {
      const entry = {
        stagingId: STAGING_ID,
        dataSet: data.dataSet as string,
        uploadedBy: data.uploadedBy as string,
        fileHash: data.fileHash as string,
        recordCount: data.recordCount as number,
        stagedData: data.stagedData as unknown[],
        status: 'uploaded',
        validationResult: null,
        diffResult: null,
      };
      stagingStore.push(entry);
      return entry;
    });
    stubRepo.updateStagingStatus.mockImplementation(async (stagingId: string, status: string, extra?: Record<string, unknown>) => {
      const entry = stagingStore.find((s) => s.stagingId === stagingId);
      if (entry) {
        entry.status = status;
        if (extra?.validation_result) entry.validationResult = extra.validation_result;
        if (extra?.diff_result) entry.diffResult = extra.diff_result;
      }
    });
    stubRepo.deleteStagingRecord.mockImplementation(async (stagingId: string) => {
      const idx = stagingStore.findIndex((s) => s.stagingId === stagingId);
      if (idx >= 0) stagingStore.splice(idx, 1);
    });
    // Extension rebindings — default returns already handle the typical cases,
    // but we rebind them here so they are fresh after vi.clearAllMocks().
    stubRepo.getIcdCrosswalkByIcd10.mockImplementation(async () => []);
    stubRepo.searchIcdCrosswalk.mockImplementation(async () => []);
    stubRepo.searchProviderRegistry.mockImplementation(async () => []);
    stubRepo.getProviderByCpsa.mockImplementation(async () => undefined);
    stubRepo.listBillingGuidance.mockImplementation(async () => []);
    stubRepo.searchBillingGuidance.mockImplementation(async () => []);
    stubRepo.getBillingGuidanceById.mockImplementation(async () => undefined);
    stubRepo.listProvincialPhnFormats.mockImplementation(async () => []);
    stubRepo.getReciprocalRules.mockImplementation(async () => []);
    stubRepo.listAnesthesiaRules.mockImplementation(async () => []);
    stubRepo.getAnesthesiaRuleByScenario.mockImplementation(async () => undefined);
    stubRepo.getBundlingRuleForPair.mockImplementation(async () => undefined);
    stubRepo.checkBundlingConflicts.mockImplementation(async () => []);
    stubRepo.listJustificationTemplates.mockImplementation(async () => []);
    stubRepo.getJustificationTemplate.mockImplementation(async () => undefined);
  }

  // =========================================================================
  // 1. Error response sanitisation for extension endpoints
  // =========================================================================

  describe('Error response sanitisation for extension endpoints', () => {
    it('GET /api/v1/ref/providers/NONEXIST returns 404 with generic message (not revealing cpsa)', async () => {
      stubRepo.getProviderByCpsa.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/NONEXIST',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.message).not.toContain('NONEXIST');
      expect(body.error.message).not.toContain('cpsa');
      expect(body.error.message).not.toContain('provider_registry');
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('GET /api/v1/ref/guidance/VALID_UUID returns 404 with generic message (not revealing ID)', async () => {
      const fakeUuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
      stubRepo.getBillingGuidanceById.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.message).not.toContain(fakeUuid);
      expect(body.error.message).not.toContain('billing_guidance');
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('GET /api/v1/ref/anesthesia-rules/NONEXIST returns 404 with generic message', async () => {
      stubRepo.getAnesthesiaRuleByScenario.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules/NONEXIST',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.message).not.toContain('NONEXIST');
      expect(body.error.message).not.toContain('anesthesia_rules');
      expect(body.error.message).not.toContain('scenario_code');
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('GET /api/v1/ref/justification-templates/VALID_UUID returns 404 with generic message', async () => {
      const fakeUuid = 'ffffffff-1111-2222-3333-444444444444';
      stubRepo.getJustificationTemplate.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.message).not.toContain(fakeUuid);
      expect(body.error.message).not.toContain('justification_templates');
      expect(body.error.message).not.toContain('template_id');
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('GET /api/v1/ref/bundling-rules/pair/XX.XXX/YY.YYY returns appropriate response with no leakage', async () => {
      stubRepo.getBundlingRuleForPair.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/bundling-rules/pair/XX.XXX/YY.YYY',
        headers: { cookie: physicianCookie() },
      });

      // The endpoint may return 200 (no rule found) or 404 — either is acceptable
      const body = JSON.parse(res.body);
      if (res.statusCode === 404) {
        expect(body.error).toBeDefined();
        expect(body.error.message).not.toContain('XX.XXX');
        expect(body.error.message).not.toContain('YY.YYY');
        expect(body.error.message).not.toContain('bundling_rules');
      }
      // In any case, no internal database details
      const rawBody = res.body;
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('staging_id');
      expect(rawBody).not.toContain('file_hash');
    });

    it('GET /api/v1/ref/reciprocal-rules/XX returns appropriate response with no leakage', async () => {
      stubRepo.getReciprocalRules.mockResolvedValueOnce([]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/XX',
        headers: { cookie: physicianCookie() },
      });

      // Province code "XX" is valid format (2 chars) — empty results or 200
      const rawBody = res.body;
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
      expect(rawBody).not.toContain('staging_id');
    });

    it('404 from ICD crosswalk detail does not reveal version or table info', async () => {
      stubRepo.findActiveVersion.mockResolvedValueOnce({ versionId: 'v1', dataSet: 'ICD_CROSSWALK', isActive: true } as any);
      stubRepo.getIcdCrosswalkByIcd10.mockResolvedValueOnce([]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk/Z99.FAKE',
        headers: { cookie: physicianCookie() },
      });

      const body = JSON.parse(res.body);
      if (res.statusCode === 404) {
        expect(body.error).toBeDefined();
        expect(body.error.message).not.toContain('Z99.FAKE');
        expect(body.error.message).not.toContain('v1');
      }
      // Whether 200 (empty results) or 404, no internal IDs leaked
      expect(res.body).not.toContain('version_id');
      expect(res.body).not.toContain('icd_crosswalk');
    });

    it('404 error shape is consistent: { error: { code, message } }', async () => {
      stubRepo.getProviderByCpsa.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/00000',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('404 from guidance detail has consistent error shape', async () => {
      const fakeUuid = 'bbbbbbbb-1111-2222-3333-444444444444';
      stubRepo.getBillingGuidanceById.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('404 from anesthesia rule detail has consistent error shape', async () => {
      stubRepo.getAnesthesiaRuleByScenario.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules/NOPE',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('404 responses do not contain session_id, user_id, or provider_id', async () => {
      const fakeUuid = 'cccccccc-1111-2222-3333-444444444444';
      stubRepo.getBillingGuidanceById.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain(PHYSICIAN_SESSION_ID);
    });

    it('404 from provider CPSA does not contain database column names', async () => {
      stubRepo.getProviderByCpsa.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/12345',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain('hsc_code');
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('registry_id');
      expect(rawBody).not.toContain('cpsa_number');
    });

    it('404 from justification template does not expose database column names', async () => {
      const fakeUuid = 'dddddddd-1111-2222-3333-444444444444';
      stubRepo.getJustificationTemplate.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain('template_id');
      expect(rawBody).not.toContain('scenario_code');
      expect(rawBody).not.toContain('template_text');
      expect(rawBody).not.toContain('hsc_code');
      expect(rawBody).not.toContain('version_id');
    });
  });

  // =========================================================================
  // 2. 500 errors on extension endpoints do not expose internals
  // =========================================================================

  describe('500 errors on extension endpoints do not expose internals', () => {
    it('searchIcdCrosswalk error returns 500 with only "Internal server error"', async () => {
      stubRepo.findActiveVersion.mockResolvedValueOnce({ versionId: 'v-test', dataSet: 'ICD_CROSSWALK', isActive: true } as any);
      stubRepo.searchIcdCrosswalk.mockRejectedValueOnce(
        new Error('relation "icd_crosswalk" does not exist at character 15'),
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('Internal server error');

      const rawBody = res.body;
      expect(rawBody).not.toContain('icd_crosswalk');
      expect(rawBody).not.toContain('relation');
      expect(rawBody).not.toContain('character 15');
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
    });

    it('getIcdCrosswalkByIcd10 error on detail endpoint returns 500 with no connection info', async () => {
      stubRepo.findActiveVersion.mockResolvedValueOnce({ versionId: 'v1', dataSet: 'ICD_CROSSWALK', isActive: true } as any);
      stubRepo.getIcdCrosswalkByIcd10.mockRejectedValueOnce(
        new Error('connection refused to pg-primary-0.internal:5432'),
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk/J06.9',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('Internal server error');

      const rawBody = res.body;
      expect(rawBody).not.toContain('connection refused');
      expect(rawBody).not.toContain('pg-primary');
      expect(rawBody).not.toContain('5432');
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
    });

    it('searchProviderRegistry error exposes no postgres/drizzle/connection details', async () => {
      stubRepo.searchProviderRegistry.mockRejectedValueOnce(
        new Error('relation "provider_registry" does not exist at character 22'),
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      expect(rawBody).not.toMatch(/postgres/i);
      expect(rawBody).not.toMatch(/drizzle/i);
      expect(rawBody).not.toContain('relation');
      expect(rawBody).not.toContain('provider_registry');
      expect(rawBody).not.toContain('character 22');
    });

    it('getProviderByCpsa error exposes no connection strings', async () => {
      stubRepo.getProviderByCpsa.mockRejectedValueOnce(
        new Error('ECONNREFUSED 10.0.0.5:5432'),
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/12345',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      expect(rawBody).not.toContain('10.0.0.5');
      expect(rawBody).not.toContain('5432');
      expect(rawBody).not.toContain('ECONNREFUSED');
    });

    it('listBillingGuidance error exposes no stack traces', async () => {
      stubRepo.listBillingGuidance.mockRejectedValueOnce(
        new Error('SELECT * FROM billing_guidance WHERE category = $1 -- syntax error'),
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      expect(rawBody).not.toContain('SELECT');
      expect(rawBody).not.toContain('billing_guidance');
      expect(rawBody).not.toContain('syntax error');
      expect(rawBody).not.toContain('$1');
      expect(rawBody).not.toContain('stack');
    });

    it('getBillingGuidanceById error returns only generic 500', async () => {
      const fakeUuid = 'aaaaaaaa-1111-2222-3333-444444444444';
      stubRepo.getBillingGuidanceById.mockRejectedValueOnce(
        new Error('column "guidance_id" of relation "billing_guidance" does not exist'),
      );

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('Internal server error');
      expect(res.body).not.toContain('guidance_id');
      expect(res.body).not.toContain('billing_guidance');
    });

    it('listAnesthesiaRules error exposes no IP addresses or ports', async () => {
      stubRepo.listAnesthesiaRules.mockRejectedValueOnce(
        new Error('TypeError at /app/node_modules/drizzle-orm/pg-core/index.js:42:15 ECONNRESET 192.168.1.100:5432'),
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('drizzle-orm');
      expect(rawBody).not.toContain('index.js');
      expect(rawBody).not.toContain('TypeError at');
      expect(rawBody).not.toContain('192.168.1.100');
      expect(rawBody).not.toContain('5432');
      expect(rawBody).not.toContain('ECONNRESET');
    });

    it('getAnesthesiaRuleByScenario error does not expose internal service names', async () => {
      stubRepo.getAnesthesiaRuleByScenario.mockRejectedValueOnce(
        new Error('ReferenceService.calculateAnesthesiaFee crashed in AnesthesiaRepository'),
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: { scenario_code: 'GEN', time_minutes: 60 },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      expect(rawBody).not.toContain('ReferenceService');
      expect(rawBody).not.toContain('AnesthesiaRepository');
      expect(rawBody).not.toContain('calculateAnesthesiaFee');
    });

    it('checkBundlingConflicts error returns only code + message in response', async () => {
      stubRepo.checkBundlingConflicts.mockRejectedValueOnce(
        new Error('FATAL: too many connections for role "meritum_app"'),
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.03A'] },
      });

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
      expect(body.error.message).toBe('Internal server error');
      expect(body.error).not.toHaveProperty('stack');
      expect(body.data).toBeUndefined();

      const rawBody = res.body;
      expect(rawBody).not.toContain('FATAL');
      expect(rawBody).not.toContain('meritum_app');
      expect(rawBody).not.toContain('too many connections');
    });

    it('getBundlingRuleForPair error does not leak session or user identifiers', async () => {
      stubRepo.getBundlingRuleForPair.mockRejectedValueOnce(new Error('deadlock detected'));

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/bundling-rules/pair/03.01A/03.03A',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('deadlock');
    });

    it('listProvincialPhnFormats error returns consistent 500 shape', async () => {
      stubRepo.listProvincialPhnFormats.mockRejectedValueOnce(new Error('unexpected'));

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
      expect(body.data).toBeUndefined();
    });

    it('getReciprocalRules error returns consistent 500 shape', async () => {
      stubRepo.getReciprocalRules.mockRejectedValueOnce(new Error('timeout'));

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/AB',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
      expect(body.data).toBeUndefined();
    });

    it('listJustificationTemplates error exposes no internals', async () => {
      stubRepo.listJustificationTemplates.mockRejectedValueOnce(
        new Error('ECONNRESET 10.0.1.50:5432'),
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      expect(rawBody).not.toContain('ECONNRESET');
      expect(rawBody).not.toContain('10.0.1.50');
      expect(rawBody).not.toContain('5432');
    });

    it('getJustificationTemplate error exposes no internals', async () => {
      const fakeUuid = 'aaaaaaaa-1111-2222-3333-444444444444';
      stubRepo.getJustificationTemplate.mockRejectedValueOnce(
        new Error('ECONNRESET 10.0.1.50:5432'),
      );

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      expect(rawBody).not.toContain('ECONNRESET');
      expect(rawBody).not.toContain('10.0.1.50');
      expect(rawBody).not.toContain('5432');
    });
  });

  // =========================================================================
  // 3. Extension endpoint validation errors do not expose DB column names
  // =========================================================================

  describe('Extension endpoint validation errors do not expose DB column names', () => {
    it('invalid q param on icd-crosswalk search does not expose table/column names', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('icd_crosswalk');
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('icd10_code');
      expect(rawBody).not.toContain('hsc_codes');
    });

    it('invalid body on anesthesia calculate does not expose internal field names', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('anesthesia_rules');
      expect(rawBody).not.toContain('base_units');
      expect(rawBody).not.toContain('time_unit_minutes');
      expect(rawBody).not.toContain('calculation_formula');
      expect(rawBody).not.toContain('staged_data');
      expect(rawBody).not.toContain('version_id');
    });

    it('invalid body on bundling check does not expose staging/version internals', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: 'not_an_array' },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('bundling_rules');
      expect(rawBody).not.toContain('staging_id');
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('file_hash');
      expect(rawBody).not.toContain('published_by');
    });

    it('invalid province code does not echo the code in error', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/INVALID_LONG_PROVINCE',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('INVALID_LONG_PROVINCE');
    });

    it('invalid UUID in guidance/:id does not echo the UUID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance/not-a-uuid-at-all',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('not-a-uuid-at-all');
    });

    it('empty provider search q does not expose internal column names', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('provider_registry');
      expect(rawBody).not.toContain('cpsa_number');
      expect(rawBody).not.toContain('registry_id');
    });

    it('invalid UUID in justification-templates/:id does not echo the UUID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates/not-a-uuid-either',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('not-a-uuid-either');
    });

    it('oversized bundling codes array validation error does not expose DB internals', async () => {
      const manyCodes = Array.from({ length: 11 }, (_, i) => `0${i}.01A`);
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: manyCodes },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('bundling_rules');
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('staging_id');
    });
  });

  // =========================================================================
  // 4. No server fingerprinting headers on extension endpoints
  // =========================================================================

  describe('No server fingerprinting headers on extension endpoints', () => {
    it('no X-Powered-By on successful ICD crosswalk search', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on successful provider registry search', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on successful guidance list', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on successful provincial PHN formats', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on successful anesthesia rules list', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on successful bundling check', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on successful justification templates list', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on successful reciprocal rules', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/AB',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on 404 extension responses', async () => {
      stubRepo.getProviderByCpsa.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/FAKE',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on 404 guidance response', async () => {
      const fakeUuid = 'eeeeeeee-1111-2222-3333-444444444444';
      stubRepo.getBillingGuidanceById.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on 404 anesthesia response', async () => {
      stubRepo.getAnesthesiaRuleByScenario.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules/NOPE',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on 404 justification template response', async () => {
      const fakeUuid = 'ffffffff-aaaa-bbbb-cccc-dddddddddddd';
      stubRepo.getJustificationTemplate.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on 500 extension responses', async () => {
      stubRepo.listProvincialPhnFormats.mockRejectedValueOnce(new Error('boom'));

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on 500 ICD crosswalk response', async () => {
      stubRepo.findActiveVersion.mockResolvedValueOnce({ versionId: 'v-test', dataSet: 'ICD_CROSSWALK', isActive: true } as any);
      stubRepo.searchIcdCrosswalk.mockRejectedValueOnce(new Error('boom'));

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=test',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By on 500 bundling response', async () => {
      stubRepo.checkBundlingConflicts.mockRejectedValueOnce(new Error('boom'));

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).toBe(500);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing version info on anesthesia calculate', async () => {
      stubRepo.getAnesthesiaRuleByScenario.mockResolvedValueOnce({
        ruleId: 'r1',
        scenarioCode: 'GEN',
        scenarioName: 'General',
        description: 'General anesthesia',
        baseUnits: 5,
        timeUnitMinutes: 15,
        calculationFormula: 'base + time',
        modifierInteractions: {},
        exampleCalculation: null,
        sortOrder: 1,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: { scenario_code: 'GEN', time_minutes: 60 },
      });

      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });

    it('no Server header revealing version info on guidance list', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physicianCookie() },
      });

      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });

    it('no Server header revealing version info on ICD crosswalk', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: physicianCookie() },
      });

      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });

    it('no Server header on bundling pair lookup', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J',
        headers: { cookie: physicianCookie() },
      });

      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });
  });

  // =========================================================================
  // 5. Extension responses use correct content type
  // =========================================================================

  describe('Extension responses use correct content type', () => {
    it('ICD crosswalk search response is application/json', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('ICD crosswalk detail response is application/json', async () => {
      stubRepo.findActiveVersion.mockResolvedValueOnce({ versionId: 'v1', dataSet: 'ICD_CROSSWALK', isActive: true } as any);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk/J09',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('provider registry search response is application/json', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('provider detail response is application/json', async () => {
      stubRepo.getProviderByCpsa.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/12345',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('guidance list response is application/json', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('guidance detail 404 response is application/json', async () => {
      const fakeUuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
      stubRepo.getBillingGuidanceById.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      // Must NOT be text/html
      expect(res.headers['content-type']).not.toMatch(/text\/html/);
    });

    it('provincial PHN formats response is application/json', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('reciprocal rules response is application/json', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/AB',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('anesthesia rules list response is application/json', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('anesthesia rule detail 404 response is application/json', async () => {
      stubRepo.getAnesthesiaRuleByScenario.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules/NOPE',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.headers['content-type']).not.toMatch(/text\/html/);
    });

    it('anesthesia calculate response is application/json', async () => {
      stubRepo.getAnesthesiaRuleByScenario.mockResolvedValueOnce({
        ruleId: 'r1',
        scenarioCode: 'GEN',
        scenarioName: 'General',
        description: 'General anesthesia',
        baseUnits: 5,
        timeUnitMinutes: 15,
        calculationFormula: 'base + time',
        modifierInteractions: {},
        exampleCalculation: null,
        sortOrder: 1,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: { scenario_code: 'GEN', time_minutes: 60 },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('bundling pair lookup response is application/json', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('bundling check response is application/json', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('justification templates list response is application/json', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('justification template detail 404 response is application/json', async () => {
      const fakeUuid = 'ffffffff-1111-2222-3333-444444444444';
      stubRepo.getJustificationTemplate.mockResolvedValueOnce(undefined);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.headers['content-type']).not.toMatch(/text\/html/);
    });

    it('500 error response is application/json (not text/html)', async () => {
      stubRepo.findActiveVersion.mockResolvedValueOnce({ versionId: 'v-test', dataSet: 'ICD_CROSSWALK', isActive: true } as any);
      stubRepo.searchIcdCrosswalk.mockRejectedValueOnce(new Error('db crash'));

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=test',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.headers['content-type']).not.toMatch(/text\/html/);
    });

    it('500 error on guidance is application/json', async () => {
      stubRepo.listBillingGuidance.mockRejectedValueOnce(new Error('boom'));

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.headers['content-type']).not.toMatch(/text\/html/);
    });

    it('500 error on bundling check is application/json', async () => {
      stubRepo.checkBundlingConflicts.mockRejectedValueOnce(new Error('boom'));

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).toBe(500);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.headers['content-type']).not.toMatch(/text\/html/);
    });

    it('validation error (400) on extension endpoint is application/json', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.headers['content-type']).not.toMatch(/text\/html/);
    });

    it('validation error on bundling check is application/json', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: [] },
      });

      expect(res.statusCode).toBe(400);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.headers['content-type']).not.toMatch(/text\/html/);
    });
  });

  // =========================================================================
  // 6. Extension responses do not leak internal metadata
  // =========================================================================

  describe('Extension responses do not leak internal metadata', () => {
    it('ICD crosswalk search results do not contain version_id or published_by', async () => {
      stubRepo.searchIcdCrosswalk.mockResolvedValueOnce([
        {
          icd10Code: 'J09',
          icd9Code: '487.0',
          description: 'Influenza due to identified novel influenza A virus',
          version_id: 'SHOULD_NOT_LEAK',
          published_by: 'SHOULD_NOT_LEAK',
        },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: physicianCookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('SHOULD_NOT_LEAK');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain('publishedBy');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
    });

    it('ICD crosswalk detail results do not contain staging metadata', async () => {
      stubRepo.findActiveVersion.mockResolvedValueOnce({ versionId: 'v1', dataSet: 'ICD_CROSSWALK', isActive: true } as any);
      stubRepo.getIcdCrosswalkByIcd10.mockResolvedValueOnce([
        {
          icd10Code: 'J09',
          icd9Code: '487.0',
          description: 'Influenza',
          staging_id: 'STAGING_LEAK',
          file_hash: 'HASH_LEAK',
        },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk/J09',
        headers: { cookie: physicianCookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('STAGING_LEAK');
      expect(rawBody).not.toContain('HASH_LEAK');
      expect(rawBody).not.toContain('staging_id');
      expect(rawBody).not.toContain('file_hash');
      expect(rawBody).not.toContain('fileHash');
    });

    it('provider registry results do not contain staging_id or file_hash', async () => {
      stubRepo.searchProviderRegistry.mockResolvedValueOnce([
        {
          cpsa: '12345',
          firstName: 'John',
          lastName: 'Smith',
          specialty: 'General Practice',
          staging_id: 'STAGING_SHOULD_NOT_APPEAR',
          file_hash: 'HASH_SHOULD_NOT_APPEAR',
        },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physicianCookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('STAGING_SHOULD_NOT_APPEAR');
      expect(rawBody).not.toContain('HASH_SHOULD_NOT_APPEAR');
      expect(rawBody).not.toContain('staging_id');
      expect(rawBody).not.toContain('stagingId');
      expect(rawBody).not.toContain('file_hash');
      expect(rawBody).not.toContain('fileHash');
    });

    it('provider detail does not contain staging metadata', async () => {
      stubRepo.getProviderByCpsa.mockResolvedValueOnce({
        cpsa: '12345',
        firstName: 'John',
        lastName: 'Smith',
        specialty: 'General Practice',
        staging_id: 'SECRET_STAGING',
        file_hash: 'SECRET_HASH',
        published_by: ADMIN_USER_ID,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/12345',
        headers: { cookie: physicianCookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('SECRET_STAGING');
      expect(rawBody).not.toContain('SECRET_HASH');
      expect(rawBody).not.toContain('staging_id');
      expect(rawBody).not.toContain('file_hash');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
    });

    it('guidance results do not contain internal IDs or admin metadata', async () => {
      stubRepo.listBillingGuidance.mockResolvedValueOnce([
        {
          id: 'bbbbbbbb-0000-0000-0000-000000000001',
          title: 'Billing for office visits',
          content: 'Use 03.01A for complete assessments.',
          category: 'general',
          internal_id: 'INTERNAL_SHOULD_NOT_APPEAR',
          admin_notes: 'ADMIN_NOTES_SHOULD_NOT_APPEAR',
          published_by: ADMIN_USER_ID,
        },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physicianCookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('INTERNAL_SHOULD_NOT_APPEAR');
      expect(rawBody).not.toContain('ADMIN_NOTES_SHOULD_NOT_APPEAR');
      expect(rawBody).not.toContain('internal_id');
      expect(rawBody).not.toContain('admin_notes');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
    });

    it('guidance detail does not contain admin metadata', async () => {
      stubRepo.getBillingGuidanceById.mockResolvedValueOnce({
        id: 'bbbbbbbb-0000-0000-0000-000000000001',
        title: 'Billing for office visits',
        content: 'Use 03.01A for complete assessments.',
        category: 'general',
        version_id: 'INTERNAL_VERSION',
        published_by: ADMIN_USER_ID,
        staging_id: 'STAGING_META',
      });

      const fakeUuid = 'bbbbbbbb-0000-0000-0000-000000000001';
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${fakeUuid}`,
        headers: { cookie: physicianCookie() },
      });

      if (res.statusCode === 200) {
        const rawBody = res.body;
        expect(rawBody).not.toContain('INTERNAL_VERSION');
        expect(rawBody).not.toContain('STAGING_META');
        expect(rawBody).not.toContain('published_by');
        expect(rawBody).not.toContain('publishedBy');
        expect(rawBody).not.toContain(ADMIN_USER_ID);
      }
    });

    it('anesthesia results do not contain staged_data', async () => {
      stubRepo.listAnesthesiaRules.mockResolvedValueOnce([
        {
          ruleId: 'r1',
          scenarioCode: 'GEN',
          scenarioName: 'General',
          description: 'General anesthesia',
          baseUnits: 5,
          timeUnitMinutes: 15,
          staged_data: { secret: 'SHOULD_NOT_APPEAR' },
          version_id: 'INTERNAL_VERSION_LEAK',
          published_by: ADMIN_USER_ID,
        },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physicianCookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('SHOULD_NOT_APPEAR');
      expect(rawBody).not.toContain('staged_data');
      expect(rawBody).not.toContain('stagedData');
      expect(rawBody).not.toContain('INTERNAL_VERSION_LEAK');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
    });

    it('anesthesia rule detail does not contain staging metadata', async () => {
      stubRepo.getAnesthesiaRuleByScenario.mockResolvedValueOnce({
        ruleId: 'r1',
        scenarioCode: 'GEN',
        scenarioName: 'General',
        description: 'General anesthesia',
        baseUnits: 5,
        timeUnitMinutes: 15,
        calculationFormula: 'base + time',
        modifierInteractions: {},
        exampleCalculation: null,
        sortOrder: 1,
        staged_data: { internal: true },
        file_hash: 'HASH_LEAK',
        version_id: 'VERSION_LEAK',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules/GEN',
        headers: { cookie: physicianCookie() },
      });

      if (res.statusCode === 200) {
        const rawBody = res.body;
        expect(rawBody).not.toContain('HASH_LEAK');
        expect(rawBody).not.toContain('VERSION_LEAK');
        expect(rawBody).not.toContain('staged_data');
        expect(rawBody).not.toContain('file_hash');
      }
    });

    it('bundling results do not contain staging metadata', async () => {
      stubRepo.checkBundlingConflicts.mockResolvedValueOnce([
        {
          codeA: '03.01A',
          codeB: '03.04J',
          conflict: true,
          resolution: 'Use higher-value code',
          staging_id: 'STAGING_LEAK_BUNDLING',
          version_id: 'VERSION_LEAK_BUNDLING',
          file_hash: 'HASH_LEAK_BUNDLING',
          published_by: ADMIN_USER_ID,
        },
      ]);

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('STAGING_LEAK_BUNDLING');
      expect(rawBody).not.toContain('VERSION_LEAK_BUNDLING');
      expect(rawBody).not.toContain('HASH_LEAK_BUNDLING');
      expect(rawBody).not.toContain('staging_id');
      expect(rawBody).not.toContain('file_hash');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
    });

    it('bundling pair lookup does not contain staging metadata', async () => {
      stubRepo.getBundlingRuleForPair.mockResolvedValueOnce({
        codeA: '03.01A',
        codeB: '03.04J',
        conflict: false,
        staging_id: 'STAGING_PAIR_LEAK',
        version_id: 'VERSION_PAIR_LEAK',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J',
        headers: { cookie: physicianCookie() },
      });

      if (res.statusCode === 200) {
        const rawBody = res.body;
        expect(rawBody).not.toContain('STAGING_PAIR_LEAK');
        expect(rawBody).not.toContain('VERSION_PAIR_LEAK');
        expect(rawBody).not.toContain('staging_id');
      }
    });

    it('justification templates list does not contain version_id or published_by', async () => {
      stubRepo.listJustificationTemplates.mockResolvedValueOnce([
        {
          id: 'cccccccc-0000-0000-0000-000000000001',
          name: 'Extended visit',
          templateText: 'Patient required extended assessment due to ...',
          version_id: 'VERSION_JUSTIFICATION_LEAK',
          published_by: ADMIN_USER_ID,
          staging_id: 'STAGING_JUSTIFICATION_LEAK',
        },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physicianCookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('VERSION_JUSTIFICATION_LEAK');
      expect(rawBody).not.toContain('STAGING_JUSTIFICATION_LEAK');
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('staging_id');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
    });

    it('justification template detail does not contain admin metadata', async () => {
      stubRepo.getJustificationTemplate.mockResolvedValueOnce({
        id: 'cccccccc-0000-0000-0000-000000000001',
        name: 'Extended visit',
        templateText: 'Patient required extended assessment due to ...',
        version_id: 'VERSION_DETAIL_LEAK',
        published_by: ADMIN_USER_ID,
        file_hash: 'FILE_HASH_LEAK',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates/cccccccc-0000-0000-0000-000000000001',
        headers: { cookie: physicianCookie() },
      });

      if (res.statusCode === 200) {
        const rawBody = res.body;
        expect(rawBody).not.toContain('VERSION_DETAIL_LEAK');
        expect(rawBody).not.toContain('FILE_HASH_LEAK');
        expect(rawBody).not.toContain('version_id');
        expect(rawBody).not.toContain('file_hash');
        expect(rawBody).not.toContain('published_by');
        expect(rawBody).not.toContain(ADMIN_USER_ID);
      }
    });

    it('provincial PHN formats results do not contain internal metadata', async () => {
      stubRepo.listProvincialPhnFormats.mockResolvedValueOnce([
        {
          province: 'AB',
          format: '9999-99999',
          version_id: 'PHN_VERSION_LEAK',
          published_by: ADMIN_USER_ID,
        },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physicianCookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('PHN_VERSION_LEAK');
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
    });

    it('reciprocal rules results do not contain internal metadata', async () => {
      stubRepo.getReciprocalRules.mockResolvedValueOnce([
        {
          province: 'AB',
          ruleName: 'Alberta reciprocal',
          version_id: 'RECIPROCAL_VERSION_LEAK',
          published_by: ADMIN_USER_ID,
          staging_id: 'RECIPROCAL_STAGING_LEAK',
        },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/AB',
        headers: { cookie: physicianCookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('RECIPROCAL_VERSION_LEAK');
      expect(rawBody).not.toContain('RECIPROCAL_STAGING_LEAK');
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('staging_id');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
    });

    it('anesthesia calculate response does not leak internal service metadata', async () => {
      stubRepo.getAnesthesiaRuleByScenario.mockResolvedValueOnce({
        ruleId: 'r1',
        scenarioCode: 'GEN',
        scenarioName: 'General',
        description: 'General anesthesia',
        baseUnits: 5,
        timeUnitMinutes: 15,
        calculationFormula: 'base + time',
        modifierInteractions: {},
        exampleCalculation: null,
        sortOrder: 1,
        _internalNote: 'DO_NOT_EXPOSE_THIS',
        version_id: 'CALC_VERSION_LEAK',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: { scenario_code: 'GEN', time_minutes: 60 },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('DO_NOT_EXPOSE_THIS');
      expect(rawBody).not.toContain('CALC_VERSION_LEAK');
      expect(rawBody).not.toContain('_internalNote');
    });
  });

  // =========================================================================
  // Sanity: test setup validates correctly
  // =========================================================================

  describe('Sanity: test setup validates correctly', () => {
    it('physician session authenticates successfully for ICD crosswalk search', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('physician session authenticates successfully for provider search', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('physician session authenticates successfully for guidance list', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('physician session authenticates successfully for provincial PHN formats', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('physician session authenticates successfully for anesthesia rules', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('physician session authenticates successfully for bundling check', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('physician session authenticates successfully for justification templates', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('admin session authenticates successfully for admin endpoints', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/ref/SOMB/versions',
        headers: { cookie: adminCookie() },
      });

      expect(res.statusCode).toBe(200);
    });
  });
});
